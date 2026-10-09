//go:build unix

package extscan

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/procgroup/proctest"
)

// TestRunTimeoutBoundsTheToolsChildren pins burpsy-react-ui-9bzh for the
// delegated ffuf/nuclei runner: a tool that starts a child and waits on it must
// still come back at its timeout, with the child killed rather than orphaned
// holding the output pipes.
func TestRunTimeoutBoundsTheToolsChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cfg := Config{Timeout: 500 * time.Millisecond}
	began := time.Now()
	_, _, code, err := run(context.Background(), cfg, "/bin/sh", []string{"-c", `sleep 30 & echo $! > "$1"; wait`, "sh", pidFile})
	took := time.Since(began)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("run error %v, want a timeout", err)
	}
	if code != -1 {
		t.Errorf("exit code %d for a run that timed out, want -1", code)
	}
	if took > 2*time.Second {
		t.Errorf("run took %s for a 500ms timeout: a child of the tool held the call open", took)
	}
	child := proctest.ChildPID(t, pidFile)
	if !proctest.WaitGone(child, 2*time.Second) {
		syscall.Kill(child, syscall.SIGKILL)
		t.Errorf("the tool's child %d outlived the timeout", child)
	}
}

// A tool that exits on its own but leaves a child holding its stdout is not
// reported as a clean run: the capture is a prefix, and the call still returns
// within procgroup.WaitDelay rather than when the child does.
func TestRunReportsAChildThatHeldTheOutputOpen(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	began := time.Now()
	_, _, _, err := run(context.Background(), Config{Timeout: time.Minute}, "/bin/sh",
		[]string{"-c", `sleep 30 & echo $! > "$1"; exit 0`, "sh", pidFile})
	took := time.Since(began)
	child := proctest.ChildPID(t, pidFile)
	syscall.Kill(child, syscall.SIGKILL)
	if err == nil || !strings.Contains(err.Error(), "held its output open") {
		t.Fatalf("run error %v, want the held-output refusal", err)
	}
	if took > 5*time.Second {
		t.Errorf("run took %s: the lingering child held the call open", took)
	}
}

// A run stopped through its context is an error, not an exit status: the tool
// was killed for it, and what it had written so far is not a result. Its
// children die with it.
func TestRunStoppedByItsContextIsNotAResult(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	type ret struct {
		code int
		err  error
	}
	done := make(chan ret, 1)
	go func() {
		_, _, code, err := run(ctx, Config{Timeout: time.Minute}, "/bin/sh",
			[]string{"-c", `echo partial; sleep 30 & echo $! > "$1"; wait`, "sh", pidFile})
		done <- ret{code, err}
	}()
	child := proctest.ChildPID(t, pidFile)
	cancel()
	select {
	case r := <-done:
		if r.err == nil || !strings.Contains(r.err.Error(), "stopped") || r.code != -1 {
			t.Errorf("run returned (%d, %v), want a stopped error with code -1", r.code, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return within 2s of its context being cancelled")
	}
	if !proctest.WaitGone(child, 2*time.Second) {
		syscall.Kill(child, syscall.SIGKILL)
		t.Errorf("the tool's child %d outlived the stop", child)
	}
}
