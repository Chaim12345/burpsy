// Package oob provides an out-of-band (OOB) interaction channel for scanner checks
// that can only be confirmed by observing a callback from the target — SSRF /
// out-of-band resource load, blind SQL injection, XXE with an external entity, and
// the three external-service-interaction issues (DNS / HTTP / SMTP).
//
// # Why this shells out instead of importing the library
//
// It drives the official `interactsh-client` binary (ProjectDiscovery, Interactsh
// v1.3.1) as a subprocess rather than importing `github.com/projectdiscovery/interactsh/pkg/client`.
// That package imports `pkg/server` and `pkg/storage`, so taking it as a dependency
// drags in a DNS server, an SMTP server, an LDAP server, an FTP server, certmagic/ACME,
// leveldb, buntdb and bbolt — roughly 100 modules into a project whose own go.mod is
// 3 direct plus 12 indirect. Shelling out to the official binary keeps the wire
// protocol upstream's problem (no hand-rolled RSA-OAEP or AES-CFB here) at the cost
// of one runtime prerequisite, which NewClient reports honestly when absent.
//
// The alternative of reimplementing the protocol was considered and rejected: the
// registration handshake and the AES-key-wrapped polling response are upstream's to
// change, and a silently-broken decrypt would look exactly like "no interactions",
// which is the one failure this package exists to make impossible to misread.
//
// # The honest-failure contract
//
// If the binary is missing, NewClient returns an error naming what it looked for. A
// caller MUST surface that as "no OOB channel available" and MUST NOT report a clean
// result. Zero interactions with a working channel and zero interactions with no
// channel at all are different facts, and conflating them turns an untested payload
// into an apparent absence of vulnerability. This is the same honest-counting rule
// the scanner's declined-check registry follows.
//
// # remote-address means different things per protocol
//
// For an `http` interaction, RemoteAddress is the real client IP — the host that
// fetched the payload URL, which is usually the target itself and is therefore
// attributable evidence. For a `dns` interaction it is the upstream *resolver*
// (observed in practice: Google and Cloudflare addresses), not the target. A DNS
// interaction proves the payload domain was resolved; it cannot prove which host
// resolved it. Any finding built on a DNS interaction must not claim otherwise.
package oob

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// binaryName is the official client's executable name, looked up on PATH when
// Options.BinaryPath is empty.
const binaryName = "interactsh-client"

// Interaction is one callback the Interactsh server recorded for our payload domain.
//
// Field names mirror the binary's own `-json` output exactly (verified against a live
// capture against oast.online), so this struct is the decode target and not a
// re-mapping — a rename upstream should fail loudly at unmarshal rather than silently
// zero a field.
type Interaction struct {
	// Protocol is "dns", "http", "smtp" or "ldap".
	Protocol string `json:"protocol"`
	// UniqueID is the lowercased correlation id. Correlate on this.
	UniqueID string `json:"unique-id"`
	// FullID carries DNS-0x20 randomised casing: the same interaction that reported
	// UniqueID "d9uonjrm27j35omjson0jo63uk6db5pzc" reported FullID
	// "d9UoNjrm27J35OMjson0Jo63Uk6dB5PZc", and sibling rows from the same lookup each
	// carried a different casing. NEVER compare this exactly; it is retained for
	// evidence display only.
	FullID string `json:"full-id"`
	// QType is the DNS query type ("A", "AAAA", ...) and is empty for non-DNS protocols.
	QType string `json:"q-type"`
	// RawRequest is the request as the interaction server saw it. For HTTP this carries
	// the full request line and headers, which is where a caller's marker will appear.
	RawRequest  string `json:"raw-request"`
	RawResponse string `json:"raw-response"`
	// RemoteAddress is the client IP for http/smtp/ldap, but the upstream RESOLVER for
	// dns. See the package doc comment: a dns interaction is not attributable.
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

// Options configures a Client. The zero value is usable: the binary is looked up on
// PATH, the default public OAST server pool is used, and registration is given 30s.
type Options struct {
	// BinaryPath overrides the PATH lookup for the interactsh-client executable.
	BinaryPath string
	// ServerURL pins a specific Interactsh server. Empty uses the client's own default
	// pool (oast.pro / oast.live / oast.fun / oast.me / oast.online), which is what the
	// public free instances are.
	ServerURL string
	// Timeout bounds how long NewClient waits for the client to announce its registered
	// payload domain. Zero means 30s.
	Timeout time.Duration
	// Disabled, when true, disables the OOB channel entirely — no client is started and
	// no addresses are handed out (burpsy-react-ui-8e3n).
	Disabled bool
}

// Client owns one running interactsh-client subprocess and the temp file it appends
// interactions to.
type Client struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	outPath string
	domain  string

	// stderrMu guards stderr, which a copier goroutine writes while NewClient's
	// registration poll reads it.
	stderrMu sync.Mutex
	stderr   bytes.Buffer

	closeOnce sync.Once
	closeErr  error
}

// domainRe matches the client's own startup announcement of the registered payload
// domain, e.g. "[INF] d9uonjrm27j35omjson0jo63uk6db5pzc.oast.online". The TLD is not
// pinned because the default pool spans several (oast.me, oast.online, oast.fun, ...)
// and which one a run lands on is upstream's choice.
var domainRe = regexp.MustCompile(`\[INF\]\s+([a-z0-9]+\.oast\.[a-z.]+?)\s*$`)

// ansiRe strips terminal colour codes before matching, since the client colourises its
// log lines when it believes it has a terminal.
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// NewClient starts an interactsh-client subprocess and blocks until it has announced a
// registered payload domain.
//
// A missing binary is reported as an error naming what was looked for, never as a
// client that yields no interactions — see the package doc comment on the honest-failure
// contract.
func NewClient(ctx context.Context, opts Options) (*Client, error) {
	// Disable flag (burpsy-react-ui-8e3n): when disabled, return a nil client that counts as
	// "not configured" everywhere else.
	if opts.Disabled {
		return nil, fmt.Errorf("out-of-band interaction channel is disabled")
	}

	bin := opts.BinaryPath
	if bin == "" {
		resolved, err := exec.LookPath(binaryName)
		if err != nil {
			return nil, fmt.Errorf("no out-of-band interaction channel: %q not found on PATH: %w", binaryName, err)
		}
		bin = resolved
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	outFile, err := os.CreateTemp("", "burpsy-oob-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("creating the interaction log: %w", err)
	}
	outPath := outFile.Name()
	// The subprocess opens and appends to this path itself; our handle is only needed to
	// reserve the name.
	_ = outFile.Close()

	args := []string{"-json", "-o", outPath}
	if opts.ServerURL != "" {
		args = append(args, "-server", opts.ServerURL)
	}

	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, bin, args...)

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("wiring the client's stderr: %w", err)
	}

	c := &Client{cmd: cmd, cancel: cancel, outPath: outPath}

	if err := cmd.Start(); err != nil {
		cancel()
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("starting %s: %w", bin, err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := stderrPipe.Read(buf)
			if n > 0 {
				c.stderrMu.Lock()
				// Cap the buffer so a long-lived client cannot grow it without bound; the
				// registration line arrives in the first few hundred bytes.
				if c.stderr.Len() < 64*1024 {
					c.stderr.Write(buf[:n])
				}
				c.stderrMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()

	deadline := time.Now().Add(timeout)
	for {
		if domain := c.scanDomain(); domain != "" {
			c.domain = domain
			return c, nil
		}
		if time.Now().After(deadline) {
			c.stderrMu.Lock()
			got := c.stderr.String()
			c.stderrMu.Unlock()
			_ = c.Close()
			return nil, fmt.Errorf("no out-of-band interaction channel: %s did not announce a payload domain within %s; its output was: %s",
				binaryName, timeout, strings.TrimSpace(got))
		}
		select {
		case <-runCtx.Done():
			_ = c.Close()
			return nil, fmt.Errorf("no out-of-band interaction channel: cancelled while waiting for %s to register: %w", binaryName, runCtx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// scanDomain looks for the registration announcement in whatever stderr holds so far.
func (c *Client) scanDomain() string {
	c.stderrMu.Lock()
	raw := c.stderr.String()
	c.stderrMu.Unlock()
	for _, line := range strings.Split(ansiRe.ReplaceAllString(raw, ""), "\n") {
		if m := domainRe.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			return m[1]
		}
	}
	return ""
}

// Domain is the registered payload domain a check embeds in its probe. Callers should
// prefix a per-probe marker onto it (e.g. "<marker>." + Domain()) so InteractionsFor can
// tell two concurrent checks' callbacks apart.
func (c *Client) Domain() string { return c.domain }

// Interactions returns every interaction recorded so far.
//
// A line that does not parse is skipped rather than returned as an error: the subprocess
// appends to this file while we read it, so observing a half-written trailing line is
// expected operation, not corruption. Treating it as an error would turn a routine race
// into a spurious "OOB channel broken".
func (c *Client) Interactions() ([]Interaction, error) {
	f, err := os.Open(c.outPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the interaction log: %w", err)
	}
	defer f.Close()

	var out []Interaction
	scanner := bufio.NewScanner(f)
	// Raw DNS request/response text makes individual records long; the default 64KiB
	// token limit is not enough for a verbose record.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var in Interaction
		if err := json.Unmarshal(line, &in); err != nil {
			continue
		}
		out = append(out, in)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return out, fmt.Errorf("scanning the interaction log: %w", err)
	}
	return out, nil
}

// InteractionsFor returns only the interactions whose raw request carries marker, so two
// checks polling the same client cannot read each other's callbacks. An empty marker
// returns everything.
func (c *Client) InteractionsFor(marker string) ([]Interaction, error) {
	all, err := c.Interactions()
	if err != nil {
		return nil, err
	}
	if marker == "" {
		return all, nil
	}
	var out []Interaction
	for _, in := range all {
		if strings.Contains(in.RawRequest, marker) {
			out = append(out, in)
		}
	}
	return out, nil
}

// Deduplicate collapses interactions that describe the same observable event.
//
// One DNS lookup of a payload domain legitimately produces several interactions — a
// live capture of a single nslookup yielded six, an A and an AAAA query from each of
// three upstream resolvers. A caller reading len(Interactions()) as "the number of times
// my payload fired" would over-report by that factor, so the fan-out is collapsed here
// on (protocol, query type, remote address) rather than left for each check to rediscover.
func Deduplicate(in []Interaction) []Interaction {
	seen := make(map[string]struct{}, len(in))
	var out []Interaction
	for _, i := range in {
		key := i.Protocol + "|" + i.QType + "|" + i.RemoteAddress
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, i)
	}
	return out
}

// Close terminates the subprocess and removes the interaction log. It is safe to call
// more than once.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.cmd != nil {
			// The kill we just requested surfaces here as an error; it is the expected
			// outcome of Close, not a failure to report.
			_ = c.cmd.Wait()
		}
		if c.outPath != "" {
			if err := os.Remove(c.outPath); err != nil && !os.IsNotExist(err) {
				c.closeErr = fmt.Errorf("removing the interaction log: %w", err)
			}
		}
	})
	return c.closeErr
}
