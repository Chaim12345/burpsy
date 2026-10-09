//go:build unix

package procgroup

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/procgroup/proctest"
)

// startContained starts script under a cancellable context, contained, and
// waits until it has written the pid of the child it started. The kill is
// driven by cancel rather than a short timeout so the test is deterministic: a
// timeout that fired before the script forked would leave nothing to check.
func startContained(t *testing.T, script string) (cmd *exec.Cmd, cancel context.CancelFunc, child int) {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	cmd = exec.CommandContext(ctx, "/bin/sh", "-c", script, "sh", pidFile)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	Contain(cmd)
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	return cmd, cancel, proctest.ChildPID(t, pidFile)
}

// TestContainedCancelKillsTheChildAndReturnsPromptly is the regression for
// burpsy-react-ui-9bzh: a shell that starts a long-lived child and waits on it.
// Uncontained, Wait blocks on the child's inherited stdout until it exits (30s
// here); contained, cancellation kills the group and Wait returns at once.
func TestContainedCancelKillsTheChildAndReturnsPromptly(t *testing.T) {
	cmd, cancel, child := startContained(t, `sleep 30 & echo $! > "$1"; wait`)
	defer syscall.Kill(child, syscall.SIGKILL)
	began := time.Now()
	cancel()
	err := cmd.Wait()
	took := time.Since(began)
	if err == nil {
		t.Fatal("Wait succeeded for a command its context killed")
	}
	if took > 2*time.Second {
		t.Fatalf("Wait took %s after cancel: the child held the call open", took)
	}
	t.Logf("Wait returned %s after cancel", took)
	if !proctest.WaitGone(child, 2*time.Second) {
		t.Fatalf("child %d is still running after the cancel: the group was not killed", child)
	}
}

// TestContainedCommandThatFinishesIsUnaffected pins that containment changes
// nothing for a command that exits on its own: exit status and output arrive
// as before.
func TestContainedCommandThatFinishesIsUnaffected(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c", "echo out; echo err >&2; exit 3")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	Contain(cmd)
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("Run error %v, want exit status 3", err)
	}
	if stdout.String() != "out\n" || stderr.String() != "err\n" {
		t.Fatalf("output %q / %q", stdout.String(), stderr.String())
	}
}

// TestContainedDescendantOutsideTheGroupCannotHoldTheCallOpen covers the
// WaitDelay backstop: a descendant that leaves the group (setsid) survives the
// group kill, but Run still returns within WaitDelay of the timeout.
func TestContainedDescendantOutsideTheGroupCannotHoldTheCallOpen(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		// util-linux ships setsid(1) on every Linux this is built on, so its
		// absence there is a broken environment, not a reason to pass quietly.
		if runtime.GOOS == "linux" {
			t.Fatalf("setsid(1) is not on PATH, so the WaitDelay backstop is unverified: %v", err)
		}
		t.Skip("setsid(1) is not installed on " + runtime.GOOS + "; the escape this test needs cannot be staged")
	}
	cmd, cancel, child := startContained(t, `setsid sleep 30 & echo $! > "$1"; wait`)
	defer syscall.Kill(child, syscall.SIGKILL)
	began := time.Now()
	cancel()
	_ = cmd.Wait()
	took := time.Since(began)
	if took > WaitDelay+2*time.Second {
		t.Fatalf("Wait took %s after cancel: WaitDelay did not bound a descendant outside the group", took)
	}
}
