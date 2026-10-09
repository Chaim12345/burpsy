//go:build unix

package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/procgroup/proctest"
)

// A tool that hangs is killed when its timeout expires; the run is an error,
// so the check cannot judge from a tool that never finished.
//
// The tool here is a wrapper that starts a child and waits on it, the shape
// that used to defeat the timeout (burpsy-react-ui-9bzh): killing only the
// shell left `sleep` holding stdout, and Run returned when sleep did — 5s for
// a 50ms timeout. The call must now return within a small multiple of the
// timeout, and the child must be dead, not orphaned.
func TestExecToolRunnerTimesOut(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	r := NewToolRunner(ToolRunnerConfig{
		Tools:   map[string]string{"sh": "/bin/sh"},
		Timeout: 500 * time.Millisecond,
	})
	began := time.Now()
	_, err := r.Run(context.Background(), "sh", []string{"-c", `sleep 30 & echo $! > "$1"; wait`, "sh", pidFile})
	took := time.Since(began)
	if err == nil {
		t.Fatal("Run succeeded for a tool that should have timed out")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q does not say timed out", err)
	}
	if took > 2*time.Second {
		t.Errorf("Run took %s for a 500ms timeout: a child of the tool held the call open", took)
	}
	child := proctest.ChildPID(t, pidFile)
	if !proctest.WaitGone(child, 2*time.Second) {
		syscall.Kill(child, syscall.SIGKILL)
		t.Errorf("the tool's child %d outlived the timeout: it was orphaned, not killed", child)
	}
}

// Cancelling the audit's context ends the tool's whole tree the same way the
// runner's own timeout does.
func TestExecToolRunnerCancelKillsTheToolsChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	r := NewToolRunner(ToolRunnerConfig{Tools: map[string]string{"sh": "/bin/sh"}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := r.Run(ctx, "sh", []string{"-c", `sleep 30 & echo $! > "$1"; wait`, "sh", pidFile})
		done <- err
	}()
	child := proctest.ChildPID(t, pidFile)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Run succeeded for a tool whose audit was cancelled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of its context being cancelled")
	}
	if !proctest.WaitGone(child, 2*time.Second) {
		syscall.Kill(child, syscall.SIGKILL)
		t.Errorf("the tool's child %d outlived the cancellation", child)
	}
}

// A tool that exits but leaves a child holding its stdout is refused rather
// than judged from a capture that is only a prefix, and the call returns within
// procgroup.WaitDelay instead of when the child exits.
func TestExecToolRunnerRefusesOutputAChildHeldOpen(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	r := NewToolRunner(ToolRunnerConfig{Tools: map[string]string{"sh": "/bin/sh"}})
	began := time.Now()
	_, err := r.Run(context.Background(), "sh", []string{"-c", `echo partial; sleep 30 & echo $! > "$1"; exit 0`, "sh", pidFile})
	took := time.Since(began)
	syscall.Kill(proctest.ChildPID(t, pidFile), syscall.SIGKILL)
	if err == nil || !strings.Contains(err.Error(), "held its output open") {
		t.Fatalf("Run error %v, want the held-output refusal", err)
	}
	if took > 5*time.Second {
		t.Errorf("Run took %s: the lingering child held the call open", took)
	}
}
