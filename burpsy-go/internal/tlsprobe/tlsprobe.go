// Package tlsprobe wraps the tlsx CLI for TLS certificate and cipher analysis.
//
// zcrypto was evaluated and rejected: its current release refuses SSLv3 client-side and
// will not negotiate RC4 or export-grade DH, which were the only capabilities it had over
// stdlib crypto/tls. tlsx reaches those through its openssl backend and additionally
// classifies cipher strength per TLS version.
package tlsprobe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/procgroup"
)

const (
	DefaultBinary  = "tlsx"
	DefaultTimeout = 30 * time.Second
	// Cipher enumeration tries each suite in turn; a single host took ~200s in testing.
	DefaultCipherEnumTimeout = 6 * time.Minute
	maxOutputBytes           = 8 << 20
)

// Outcome keeps "found nothing" separate from "could not look". Folding them together
// would let a missing binary or a timeout read as a clean TLS result.
type Outcome int

const (
	OutcomeNotInvoked Outcome = iota
	OutcomeUnavailable
	OutcomeFailed
	OutcomeCompleted
)

func (o Outcome) String() string {
	switch o {
	case OutcomeNotInvoked:
		return "not invoked"
	case OutcomeUnavailable:
		return "tlsx unavailable"
	case OutcomeFailed:
		return "tlsx failed"
	case OutcomeCompleted:
		return "completed"
	}
	return "unknown"
}

type CipherSet struct {
	Version string  `json:"version"`
	Ciphers Ciphers `json:"ciphers"`
}

type Ciphers struct {
	Weak     []string `json:"weak"`
	Insecure []string `json:"insecure"`
	Secure   []string `json:"secure"`
}

// Host is one tlsx JSONL record. Only the fields the scanner reads are mapped.
type Host struct {
	Host         string   `json:"host"`
	IP           string   `json:"ip"`
	Port         string   `json:"port"`
	ProbeStatus  bool     `json:"probe_status"`
	Error        string   `json:"error"`
	TLSVersion   string   `json:"tls_version"`
	Cipher       string   `json:"cipher"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	SubjectCN    string   `json:"subject_cn"`
	SubjectAN    []string `json:"subject_an"`
	IssuerCN     string   `json:"issuer_cn"`
	Serial       string   `json:"serial"`
	WildcardCert bool     `json:"wildcard_certificate"`

	Expired    bool `json:"expired"`
	SelfSigned bool `json:"self_signed"`
	Mismatched bool `json:"mismatched"`
	Revoked    bool `json:"revoked"`
	Untrusted  bool `json:"untrusted"`

	CipherEnum []CipherSet `json:"cipher_enum"`
	JARMHash   string      `json:"jarm_hash"`
	JA3Hash    string      `json:"ja3_hash"`
}

// HasCertificateDefect reports the discriminators the "TLS certificate" catalog row needs.
func (h Host) HasCertificateDefect() bool {
	return h.Expired || h.SelfSigned || h.Mismatched || h.Revoked || h.Untrusted
}

// WeakCiphers flattens weak and insecure suites across every enumerated version.
func (h Host) WeakCiphers() []string {
	var out []string
	for _, cs := range h.CipherEnum {
		for _, c := range cs.Ciphers.Weak {
			out = append(out, cs.Version+":"+c)
		}
		for _, c := range cs.Ciphers.Insecure {
			out = append(out, cs.Version+":"+c)
		}
	}
	return out
}

// DeprecatedProtocols lists negotiated versions below TLS 1.2.
func (h Host) DeprecatedProtocols() []string {
	var out []string
	for _, cs := range h.CipherEnum {
		switch cs.Version {
		case "ssl30", "tls10", "tls11":
			out = append(out, cs.Version)
		}
	}
	return out
}

type Result struct {
	Outcome Outcome
	Hosts   []Host
	// Err explains OutcomeUnavailable and OutcomeFailed. It is never set alongside
	// OutcomeCompleted.
	Err error
	// Command is the argv actually executed, for the provenance line a delegated check
	// must record.
	Command []string
	Version string
}

type Options struct {
	Binary string
	// EnumerateCiphers turns on per-suite enumeration. Slow; opt in per host.
	EnumerateCiphers bool
	ScanMode         string // ctls, ztls, openssl, auto
	MinVersion       string // ssl30, tls10, tls11, tls12, tls13
	Timeout          time.Duration
}

func (o Options) binary() string {
	if o.Binary != "" {
		return o.Binary
	}
	return DefaultBinary
}

func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	if o.EnumerateCiphers {
		return DefaultCipherEnumTimeout
	}
	return DefaultTimeout
}

func Available(binary string) bool {
	if binary == "" {
		binary = DefaultBinary
	}
	_, err := exec.LookPath(binary)
	return err == nil
}

// Probe runs tlsx against targets and returns parsed records.
//
// An empty target list is OutcomeNotInvoked rather than a completed empty scan: nothing
// was examined, and a caller must not report that as clean.
func Probe(ctx context.Context, targets []string, opts Options) Result {
	if len(targets) == 0 {
		return Result{Outcome: OutcomeNotInvoked, Err: errors.New("tlsprobe: no targets")}
	}
	bin := opts.binary()
	path, err := exec.LookPath(bin)
	if err != nil {
		return Result{Outcome: OutcomeUnavailable, Err: fmt.Errorf("tlsprobe: %q not on PATH: %w", bin, err)}
	}

	args := []string{
		"-u", strings.Join(targets, ","),
		"-j", "-silent", "-duc",
		"-ex", "-ss", "-mm", "-un", "-re",
		"-tv", "-cipher", "-wc", "-tps",
	}
	if opts.EnumerateCiphers {
		args = append(args, "-ce", "-ct", "all")
	}
	if opts.ScanMode != "" {
		args = append(args, "-sm", opts.ScanMode)
	}
	if opts.MinVersion != "" {
		args = append(args, "-min-version", opts.MinVersion)
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	cmd := exec.CommandContext(runCtx, path, args...)
	// The timeout bounds tlsx's whole process tree, not only tlsx itself
	// (burpsy-react-ui-9bzh).
	procgroup.Contain(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if stdout.Len() > maxOutputBytes {
		stdout.Truncate(maxOutputBytes)
	}
	hosts, parseErr := parseJSONL(stdout.Bytes())

	argv := append([]string{path}, args...)
	// A non-zero exit with usable records is still a result; tlsx exits non-zero when some
	// targets fail. Only refuse when nothing parsed.
	if len(hosts) == 0 {
		switch {
		case runErr != nil:
			return Result{Outcome: OutcomeFailed, Command: argv,
				Err: fmt.Errorf("tlsprobe: %w: %s", runErr, strings.TrimSpace(stderr.String()))}
		case parseErr != nil:
			return Result{Outcome: OutcomeFailed, Command: argv, Err: parseErr}
		}
	}
	return Result{Outcome: OutcomeCompleted, Hosts: hosts, Command: argv}
}

func parseJSONL(b []byte) ([]Host, error) {
	var hosts []Host
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var h Host
		if err := json.Unmarshal(line, &h); err != nil {
			return hosts, fmt.Errorf("tlsprobe: unparseable record: %w", err)
		}
		hosts = append(hosts, h)
	}
	if err := sc.Err(); err != nil {
		return hosts, fmt.Errorf("tlsprobe: reading output: %w", err)
	}
	return hosts, nil
}
