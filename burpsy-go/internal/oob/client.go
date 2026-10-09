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
	"path/filepath"
	"regexp"
	"sort"
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
	// StateDir, when set, makes the client's identity outlive this process: Burp's
	// restoreClient(SecretKey) / getSecretKey (burpsy-react-ui-d657). The interactsh session
	// (correlation id and keys) is kept in StateDir/session.yaml and resumed by the next client,
	// so a payload minted before a restart is still polled after it, and the interactions it
	// caused while burpsy was down are delivered on the first poll. Each run's interaction log is
	// kept beside it, and Interactions reads all of them, because interactsh-client truncates its
	// -o file and the previous run's log is the only record of what that run saw. Empty keeps the
	// old behaviour: a fresh identity per process and a temporary log removed on Close.
	StateDir string
}

// sessionFileName is the interactsh-client -sf file inside a StateDir.
const sessionFileName = "session.yaml"

// logPrefix names each run's interaction log inside a StateDir.
const logPrefix = "interactions-"

// Client owns one running interactsh-client subprocess and the temp file it appends
// interactions to.
type Client struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	outPath string
	domain  string
	// stateDir is Options.StateDir. When set, Close stops the subprocess gracefully so it saves
	// the session, and keeps the logs.
	stateDir string
	// resumed is true when this client took over a session a previous run saved.
	resumed bool

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

	if opts.StateDir == "" {
		outFile, err := os.CreateTemp("", "burpsy-oob-*.jsonl")
		if err != nil {
			return nil, fmt.Errorf("creating the interaction log: %w", err)
		}
		outPath := outFile.Name()
		// The subprocess opens and appends to this path itself; our handle is only needed to
		// reserve the name.
		_ = outFile.Close()
		c := &Client{outPath: outPath}
		if err := c.start(ctx, bin, opts.ServerURL, "", timeout); err != nil {
			_ = os.Remove(outPath)
			return nil, err
		}
		return c, nil
	}

	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating the collaborator state directory: %w", err)
	}
	session := filepath.Join(opts.StateDir, sessionFileName)
	_, statErr := os.Stat(session)
	c := &Client{stateDir: opts.StateDir, resumed: statErr == nil}
	c.outPath = c.newLogPath()
	if err := c.start(ctx, bin, opts.ServerURL, session, timeout); err != nil {
		return nil, err
	}
	if c.resumed {
		return c, nil
	}
	// interactsh-client writes the session file only when it exits cleanly. A burpsy that is killed
	// would then lose a session it had already handed payloads out from. So a brand-new session is
	// saved straight away: stop the client gracefully, which writes the file, and resume from it. That
	// costs one restart per new session and makes the identity survive a crash from the first payload on.
	if err := c.stop(true); err != nil {
		return nil, fmt.Errorf("saving the new collaborator session: %w", err)
	}
	if _, err := os.Stat(session); err != nil {
		return nil, fmt.Errorf("saving the new collaborator session: %s did not write %s on exit", binaryName, session)
	}
	c.resumed = true
	c.closeOnce = sync.Once{}
	c.outPath = c.newLogPath()
	if err := c.start(ctx, bin, opts.ServerURL, session, timeout); err != nil {
		return nil, err
	}
	return c, nil
}

// newLogPath names a fresh per-run interaction log in the state directory.
func (c *Client) newLogPath() string {
	return filepath.Join(c.stateDir, fmt.Sprintf("%s%d.jsonl", logPrefix, time.Now().UnixNano()))
}

// Resumed reports whether this client took over a saved session, so payloads minted before the
// last restart are still polled.
func (c *Client) Resumed() bool { return c.resumed }

// start launches the subprocess and blocks until it announces a payload domain.
func (c *Client) start(ctx context.Context, bin, serverURL, session string, timeout time.Duration) error {
	args := []string{"-json", "-o", c.outPath}
	if serverURL != "" {
		args = append(args, "-server", serverURL)
	}
	if session != "" {
		args = append(args, "-sf", session)
	}

	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, bin, args...)

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("wiring the client's stderr: %w", err)
	}

	c.stderrMu.Lock()
	c.stderr.Reset()
	c.stderrMu.Unlock()
	c.cmd, c.cancel = cmd, cancel

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("starting %s: %w", bin, err)
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
			return nil
		}
		if time.Now().After(deadline) {
			c.stderrMu.Lock()
			got := c.stderr.String()
			c.stderrMu.Unlock()
			_ = c.stop(false)
			return fmt.Errorf("no out-of-band interaction channel: %s did not announce a payload domain within %s; its output was: %s",
				binaryName, timeout, strings.TrimSpace(got))
		}
		select {
		case <-runCtx.Done():
			_ = c.stop(false)
			return fmt.Errorf("no out-of-band interaction channel: cancelled while waiting for %s to register: %w", binaryName, runCtx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// gracefulStopWait bounds how long a graceful stop waits for the client to save its session.
var gracefulStopWait = 5 * time.Second

// stop ends the subprocess. Graceful sends SIGINT first, which is what makes interactsh-client write
// its -sf session file, and only kills it if it has not exited within gracefulStopWait.
func (c *Client) stop(graceful bool) error {
	if c.cmd == nil {
		return nil
	}
	if graceful && c.cmd.Process != nil {
		done := make(chan struct{})
		go func() { _ = c.cmd.Wait(); close(done) }()
		if err := c.cmd.Process.Signal(os.Interrupt); err == nil {
			select {
			case <-done:
				c.cancel()
				c.cmd = nil
				return nil
			case <-time.After(gracefulStopWait):
			}
		}
		c.cancel()
		<-done
		c.cmd = nil
		return nil
	}
	c.cancel()
	// The kill we just requested surfaces here as an error; it is the expected outcome of a stop,
	// not a failure to report.
	_ = c.cmd.Wait()
	c.cmd = nil
	return nil
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
	if c.stateDir == "" {
		return readInteractionLog(c.outPath)
	}
	// Every run's log, oldest first. The previous runs' logs are the only record of what those runs
	// received, because each run's client truncates its own -o file.
	logs, err := filepath.Glob(filepath.Join(c.stateDir, logPrefix+"*.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("listing the interaction logs: %w", err)
	}
	sort.Strings(logs)
	var out []Interaction
	for _, path := range logs {
		got, err := readInteractionLog(path)
		out = append(out, got...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// readInteractionLog parses one JSONL interaction log.
func readInteractionLog(path string) ([]Interaction, error) {
	f, err := os.Open(path)
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
//
// The match ignores case. A DNS raw request carries the query name with DNS-0x20 randomised
// casing (the same reason FullID must never be compared exactly), so an exact match missed a
// lowercase marker in a lookup the resolver had re-cased — a real DNS callback read as none
// (burpsy-react-ui-ar8v). Hostnames are case-insensitive, so nothing legitimate is lost.
func (c *Client) InteractionsFor(marker string) ([]Interaction, error) {
	all, err := c.Interactions()
	if err != nil {
		return nil, err
	}
	return filterByMarker(all, marker), nil
}

// filterByMarker keeps the interactions whose raw request carries marker, ignoring case.
func filterByMarker(all []Interaction, marker string) []Interaction {
	if marker == "" {
		return all
	}
	want := strings.ToLower(marker)
	var out []Interaction
	for _, in := range all {
		if strings.Contains(strings.ToLower(in.RawRequest), want) {
			out = append(out, in)
		}
	}
	return out
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
		if c.stateDir != "" {
			// Gracefully, so the client saves the session the next run resumes, and the logs
			// stay: they are the record of what this identity has received.
			_ = c.stop(true)
			return
		}
		_ = c.stop(false)
		if c.outPath != "" {
			if err := os.Remove(c.outPath); err != nil && !os.IsNotExist(err) {
				c.closeErr = fmt.Errorf("removing the interaction log: %w", err)
			}
		}
	})
	return c.closeErr
}

// Forget closes the client and deletes its state directory: the saved session and every run's
// interaction log. It is the "discard" half of "Don't use Collaborator". Afterwards nothing can
// poll the payloads minted from this identity, which is what the operator chose.
func (c *Client) Forget() error {
	err := c.Close()
	if c.stateDir != "" {
		if rmErr := os.RemoveAll(c.stateDir); rmErr != nil && err == nil {
			err = fmt.Errorf("removing the collaborator state: %w", rmErr)
		}
	}
	return err
}

// StateDirFor is where a server's identity is kept under base: one directory per interaction
// server, so switching servers never resumes another server's session. "" stays "" (no
// persistence).
func StateDirFor(base, serverURL string) string {
	if base == "" {
		return ""
	}
	name := "public"
	if serverURL != "" {
		var b strings.Builder
		for _, r := range strings.ToLower(serverURL) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
				b.WriteRune(r)
			default:
				b.WriteByte('_')
			}
		}
		name = "server-" + b.String()
	}
	return filepath.Join(base, name)
}
