// Package extscan delegates a scan phase to an external security tool — `ffuf`
// for content discovery, `nuclei` for its community template corpus — and turns
// what comes back into the same report rows burpsy's own checks produce.
//
// # Two gates, both before exec
//
// A delegated tool dials the target itself. Nothing in this package can put an
// external process behind `sender.AuthorisedSender`, so the per-request byte
// gate that authorises every request burpsy constructs simply does not reach
// here. Two gates stand in for it, and both are checked before the binary is
// launched:
//
//   - The allowlist. A tool is named, never pathed: `Config.Tools` maps the
//     name an operator allowed onto the executable that implements it, and a
//     name absent from that map is refused. Same model as the scanner's
//     `run tool` runner, and the same reason — a loaded corpus, a config file
//     or a flag can only reach binaries the operator explicitly mapped.
//   - The scope. `Authorise` refuses a target the engagement scope does not
//     contain, and refuses just as loudly when scope *does* contain the base
//     but path-scoped rules mean burpsy cannot predict where the tool will go.
//     See Authorise for why a partially-in-scope host is a refusal rather than
//     a smaller scan.
//
// # Refusals are typed, never silent
//
// `Outcome` keeps "found nothing" apart from "could not look", the same
// distinction `tlsprobe` draws. A missing binary, an unauthorised target and a
// tool that ran and matched nothing are three different outcomes, because a
// report that renders them identically tells an operator the target is clean
// when nobody looked at it.
//
// # What a run is
//
// The binary is executed directly with arguments this package builds — no
// shell, so a target or wordlist path containing shell metacharacters is data
// and not injection. Output is captured to a bound and the run is bounded by a
// timeout. A non-zero exit is data: both tools exit non-zero in ordinary
// no-results conditions.
package extscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/procgroup"
)

// DefaultTimeout bounds one delegated run when the config names none. Both
// tools sweep a corpus or a wordlist and are slow by nature, so this is
// generous rather than snappy — the caller's own context is the real backstop.
const DefaultTimeout = 10 * time.Minute

// DefaultMaxOutputBytes caps captured stdout+stderr per run when the config
// names none. Large enough for a full nuclei JSONL stream, small enough that a
// misbehaving tool cannot balloon the process.
const DefaultMaxOutputBytes = 32 << 20 // 32 MiB

// ToolFFUF and ToolNuclei are the allowlist keys this package resolves. They
// are the names an operator writes, not paths.
const (
	ToolFFUF   = "ffuf"
	ToolNuclei = "nuclei"
)

// Config is the operator's allowlist and bounds for delegated scans.
type Config struct {
	// Tools maps an allowed tool name (ToolFFUF, ToolNuclei) to the executable
	// path that implements it. A name not present here is refused. A nil map
	// refuses everything, which is what "the operator configured nothing" must
	// mean — delegation is off until it is switched on.
	Tools map[string]string
	// Timeout bounds one run. Zero takes DefaultTimeout.
	Timeout time.Duration
	// MaxOutputBytes caps captured stdout+stderr per run. Zero takes
	// DefaultMaxOutputBytes.
	MaxOutputBytes int
}

func (c Config) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c Config) maxOutput() int {
	if c.MaxOutputBytes > 0 {
		return c.MaxOutputBytes
	}
	return DefaultMaxOutputBytes
}

// resolve returns the executable path an allowed tool name maps to.
//
// The allowlist decides, and PATH is consulted only to turn an allowed bare
// name into a path. An operator who wrote `nuclei=nuclei` gets PATH lookup; one
// who wrote an absolute path gets exactly that binary. A name absent from the
// map is refused before any of that — PATH cannot promote a tool onto the
// allowlist.
func (c Config) resolve(tool string) (string, error) {
	bin, ok := c.Tools[tool]
	if !ok {
		return "", fmt.Errorf("%w: %q is not in the configured allowlist", ErrNotAllowed, tool)
	}
	if bin == "" {
		return "", fmt.Errorf("%w: %q maps to an empty path", ErrNotAllowed, tool)
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("%w: %q maps to %q, which is not executable: %v", ErrUnavailable, tool, bin, err)
	}
	return path, nil
}

// Available reports whether a tool can be launched at all, without launching it:
// nil when the operator allowlisted the name and the binary it maps to is
// executable, ErrNotAllowed or ErrUnavailable otherwise.
//
// It exists so a caller can refuse *before* it registers work. A surface that
// only learned the tool was missing from a finished run would have to show an
// empty result and explain it afterwards, which is the shape this package spends
// its whole design avoiding. It is deliberately the same code path resolve takes,
// so the pre-flight answer and the run's answer cannot disagree — a second
// hand-rolled allowlist lookup at a call site is how they would.
func (c Config) Available(tool string) error {
	_, err := c.resolve(tool)
	return err
}

// The typed refusals. A caller distinguishes them with errors.Is; a report
// distinguishes them through Outcome. Both exist because "the operator did not
// allow this tool", "the binary is missing" and "this target is out of scope"
// are three different things to tell someone, and none of them is a finding.
var (
	// ErrNotAllowed means the tool name is not on the operator's allowlist.
	ErrNotAllowed = errors.New("extscan: tool not allowlisted")
	// ErrUnavailable means the allowlisted tool's binary could not be executed.
	ErrUnavailable = errors.New("extscan: tool unavailable")
	// ErrUnauthorised means the engagement scope does not authorise the target.
	ErrUnauthorised = errors.New("extscan: target not authorised by scope")
)

// Outcome keeps "found nothing" separate from "could not look". Folding them
// together would let a missing binary, a refused target or a timeout read as a
// clean result for a phase that never ran.
type Outcome int

const (
	// OutcomeNotInvoked: nothing was asked of the tool (no target).
	OutcomeNotInvoked Outcome = iota
	// OutcomeNotAllowed: the tool is not on the operator's allowlist.
	OutcomeNotAllowed
	// OutcomeUnauthorised: the engagement scope refused the target.
	OutcomeUnauthorised
	// OutcomeUnavailable: the allowlisted binary could not be executed.
	OutcomeUnavailable
	// OutcomeFailed: the tool ran and produced nothing usable.
	OutcomeFailed
	// OutcomeCompleted: the tool ran; its results, however many, are the result.
	OutcomeCompleted
)

func (o Outcome) String() string {
	switch o {
	case OutcomeNotInvoked:
		return "not invoked"
	case OutcomeNotAllowed:
		return "tool not allowlisted"
	case OutcomeUnauthorised:
		return "target not authorised by scope"
	case OutcomeUnavailable:
		return "tool unavailable"
	case OutcomeFailed:
		return "tool failed"
	case OutcomeCompleted:
		return "completed"
	}
	return "unknown"
}

// Looked reports whether this outcome means the tool actually examined the
// target. Only OutcomeCompleted does. A caller writing "no issues found" must
// gate on this, which is the whole reason the enum is not a bool.
func (o Outcome) Looked() bool { return o == OutcomeCompleted }

// ScopeAuthoriser is the engagement scope, narrowed to the one question this
// package asks. *core.Scope satisfies it; the interface keeps extscan free of a
// concrete core type, the same way sender.ScopeChecker does.
type ScopeAuthoriser interface {
	Contains(host string, port uint16, path string, isTLS bool) bool
}

// Target is a parsed, scope-authorised target. It exists as a distinct type so
// a runner cannot be handed a raw string that never passed Authorise — the only
// way to obtain one is through Authorise, which is the gate.
type Target struct {
	// URL is the target as the tool should receive it, normalised to an
	// explicit authority.
	URL    string
	Host   string
	Port   uint16
	Path   string
	IsTLS  bool
	scoped bool
}

// unauthorisedProbe is appended to a target's base path to ask scope a second
// question: would a path this tool might invent still be authorised? The value
// is deliberately one no wordlist and no nuclei template would produce on its
// own — it is a question to the scope rules, never a request on the wire.
const unauthorisedProbe = "burpsy-extscan-scope-probe"

// Authorise parses raw and refuses it unless the engagement scope authorises
// the whole subtree the tool may reach.
//
// # Why the whole subtree
//
// `ffuf` invents paths from a wordlist and `nuclei` requests whatever paths its
// templates name. Neither consults burpsy before dialling, so a path-scoped
// scope rule — `exclude(host, "/admin")` — cannot be enforced inside them: the
// request is already on the wire by the time this process could object.
//
// So scope is asked twice: about the base path, and about an invented path
// under it. Both must be authorised. A target whose base is in scope but whose
// invented paths are not is refused rather than scanned, because the honest
// alternatives are worse — running anyway would send requests the engagement
// excluded, and running "carefully" would be a claim this package cannot keep.
// An operator who wants the subtree scanned can widen the scope and say so.
func Authorise(scope ScopeAuthoriser, raw string) (Target, error) {
	if strings.TrimSpace(raw) == "" {
		return Target{}, fmt.Errorf("%w: no target given", ErrUnauthorised)
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Target{}, fmt.Errorf("%w: unusable target %q: %v", ErrUnauthorised, raw, err)
	}
	var isTLS bool
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		isTLS = true
	case "http":
		isTLS = false
	default:
		return Target{}, fmt.Errorf("%w: target %q names no http scheme", ErrUnauthorised, raw)
	}
	host := parsed.Hostname()
	if host == "" {
		return Target{}, fmt.Errorf("%w: target %q names no host", ErrUnauthorised, raw)
	}
	var port uint16
	if p := parsed.Port(); p != "" {
		n, cerr := strconv.ParseUint(p, 10, 16)
		if cerr != nil {
			return Target{}, fmt.Errorf("%w: target %q names an unusable port: %v", ErrUnauthorised, raw, cerr)
		}
		port = uint16(n)
	} else if isTLS {
		port = 443
	} else {
		port = 80
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	if scope == nil {
		return Target{}, fmt.Errorf("%w: no scope was supplied, and a delegated scan is not run unauthorised", ErrUnauthorised)
	}
	if !scope.Contains(host, port, path, isTLS) {
		return Target{}, fmt.Errorf("%w: %s", ErrUnauthorised, formatAuthority(host, port, isTLS)+path)
	}
	probe := strings.TrimSuffix(path, "/") + "/" + unauthorisedProbe
	if !scope.Contains(host, port, probe, isTLS) {
		return Target{}, fmt.Errorf("%w: scope authorises %s but not every path beneath it, and an "+
			"external tool chooses its own paths — widen the scope to cover the subtree, or scan it "+
			"with burpsy's own checks, which are gated per request",
			ErrUnauthorised, formatAuthority(host, port, isTLS)+path)
	}

	return Target{
		URL:    formatAuthority(host, port, isTLS) + path,
		Host:   host,
		Port:   port,
		Path:   path,
		IsTLS:  isTLS,
		scoped: true,
	}, nil
}

// Authorised reports whether this Target came from Authorise. A zero Target is
// not authorised, so a runner handed one refuses rather than scanning a target
// nobody checked.
func (t Target) Authorised() bool { return t.scoped }

// HostPort renders the authority the way a report row's Host column wants it.
func (t Target) HostPort() string {
	if (t.IsTLS && t.Port == 443) || (!t.IsTLS && t.Port == 80) {
		return t.Host
	}
	return t.Host + ":" + strconv.Itoa(int(t.Port))
}

func formatAuthority(host string, port uint16, isTLS bool) string {
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	if (isTLS && port == 443) || (!isTLS && port == 80) {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + strconv.Itoa(int(port))
}

// run executes one delegated tool and returns its captured output.
//
// The binary is invoked directly with args — never through a shell — so an
// argument carrying shell metacharacters is an argument. Exit status is
// returned rather than raised: both tools exit non-zero on ordinary
// no-results conditions, and only the caller knows whether its parse of the
// output makes that a failure.
func run(ctx context.Context, cfg Config, path string, args []string) (stdout, stderr []byte, exitCode int, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()

	cmd := exec.CommandContext(runCtx, path, args...)
	// The timeout bounds the tool's whole process tree: without a process
	// group a child the tool started keeps the pipes open and Run waits for it
	// (burpsy-react-ui-9bzh).
	procgroup.Contain(cmd)
	var out, errb cappedBuffer
	out.limit = cfg.maxOutput()
	errb.limit = cfg.maxOutput()
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := cmd.Run()

	if runCtx.Err() == context.DeadlineExceeded {
		return out.Bytes(), errb.Bytes(), -1, fmt.Errorf("timed out after %s", cfg.timeout())
	}
	// Stopped by the caller's context (the dashboard's stop button). The tool
	// was killed for it, so its partial output and signal exit are not a result.
	if err := runCtx.Err(); err != nil {
		return out.Bytes(), errb.Bytes(), -1, fmt.Errorf("stopped before it finished: %w", err)
	}
	if errors.Is(runErr, exec.ErrWaitDelay) {
		// The tool exited; a process it started held its output open past the
		// delay. Not a launch failure, and not a clean exit either.
		return out.Bytes(), errb.Bytes(), -1, fmt.Errorf("exited (status %d), but a process it started held its output open for more than %s; its captured stdout/stderr is incomplete",
			cmd.ProcessState.ExitCode(), procgroup.WaitDelay)
	}
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			// A launch failure is not an exit status; the tool never ran.
			return out.Bytes(), errb.Bytes(), -1, runErr
		}
	}
	return out.Bytes(), errb.Bytes(), cmd.ProcessState.ExitCode(), nil
}

// cappedBuffer is a bytes.Buffer that stops recording past limit, so a tool
// that spools without end cannot take the process with it.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.over {
		return len(p), nil
	}
	room := b.limit - b.buf.Len()
	if room <= 0 {
		b.over = true
		return len(p), nil
	}
	if len(p) > room {
		b.buf.Write(p[:room])
		b.over = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *cappedBuffer) Bytes() []byte { return b.buf.Bytes() }

// trimErr renders a tool's stderr for an error message without pasting a
// screenful into it.
func trimErr(stderr []byte) string {
	s := strings.TrimSpace(string(stderr))
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
