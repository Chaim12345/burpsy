// The scanner's tool runner: the allowlist-gated exec behind the bcheck
// `run tool` statement.
//
// # The gate is the allowlist
//
// A `run tool` statement names a tool — `sqlmap`, `jwt_tool` — never a path.
// This runner resolves that name through ToolRunnerConfig.Tools, the operator's
// allowlist, and refuses anything not on it. That is the whole safety model:
// a loaded .bcheck file can only execute binaries the operator explicitly
// mapped, with arguments the check supplies. An unknown name, a launch
// failure or a timeout is an error that abandons the check — the same
// refuse-don't-guess posture as the egress chokepoint for sends.
//
// # What a run is
//
// The binary is executed directly with the resolved args — no shell, so an
// arg that happens to contain shell metacharacters is data, not injection.
// stdout and stderr are captured up to a bound (MaxOutputBytes, default
// DefaultToolMaxOutputBytes) so a noisy tool cannot exhaust memory. The exit
// code is data, not an error: a tool that finds nothing exits non-zero, and
// the check compares `{<name>.exit_code}` against that.
package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// DefaultToolTimeout bounds one tool run when the config names none. External
// scanners are slow by nature; the audit's own wall-clock budget is the
// backstop, so this is generous rather than snappy.
const DefaultToolTimeout = 5 * time.Minute

// DefaultToolMaxOutputBytes caps captured stdout+stderr per run when the
// config names none. Enough for a tool's report, small enough that a
// misbehaving tool cannot balloon the process.
const DefaultToolMaxOutputBytes = 1 << 20 // 1 MiB

// ToolRunnerConfig is the operator's allowlist and bounds for `run tool`.
type ToolRunnerConfig struct {
	// Tools maps a tool name as written in a .bcheck file to the executable
	// path that implements it. A name not present here is refused.
	Tools map[string]string
	// Timeout bounds one run. Zero takes DefaultToolTimeout.
	Timeout time.Duration
	// MaxOutputBytes caps captured stdout+stderr per run. Zero takes
	// DefaultToolMaxOutputBytes.
	MaxOutputBytes int
}

// NewToolRunner builds the allowlist-gated runner from cfg.
func NewToolRunner(cfg ToolRunnerConfig) bcheck.ToolRunner {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultToolTimeout
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = DefaultToolMaxOutputBytes
	}
	return &execToolRunner{cfg: cfg}
}

type execToolRunner struct {
	cfg ToolRunnerConfig
}

// Run executes one `run tool`: resolve the name against the allowlist, run the
// mapped binary with the args directly (no shell), capture bounded output.
func (r *execToolRunner) Run(tool string, args []string) (bcheck.ToolResult, error) {
	bin, ok := r.cfg.Tools[tool]
	if !ok {
		return bcheck.ToolResult{}, fmt.Errorf("tool %q is not in the configured allowlist", tool)
	}
	// A configured name that maps to nothing is a configuration error, not a
	// request to run the empty string. Refused before exec gets a chance to.
	if bin == "" {
		return bcheck.ToolResult{}, fmt.Errorf("tool %q maps to an empty path", tool)
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr cappedBuffer
	stdout.limit = r.cfg.MaxOutputBytes
	stderr.limit = r.cfg.MaxOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return bcheck.ToolResult{}, fmt.Errorf("tool %q timed out after %s", tool, r.cfg.Timeout)
	}
	// A launch failure (binary missing, not executable) is an error: the check
	// cannot see the tool it asked for. A non-zero exit is data.
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return bcheck.ToolResult{}, fmt.Errorf("tool %q: %w", tool, runErr)
		}
	}
	return bcheck.ToolResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: cmd.ProcessState.ExitCode(),
	}, nil
}

// cappedBuffer is a bytes.Buffer that stops recording past limit. The
// runner's contract to the check is bounded output, so the check never sees a
// tool's full unbounded spool — and the process never holds it either.
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

func (b *cappedBuffer) String() string { return b.buf.String() }
