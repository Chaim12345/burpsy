package scanner

import (
	"context"
	"strings"
	"testing"
)

// The runner refuses a tool that is not on the allowlist — the whole gate.
func TestExecToolRunnerRefusesUnlistedTool(t *testing.T) {
	r := NewToolRunner(ToolRunnerConfig{Tools: map[string]string{"sqlmap": "/bin/true"}})
	_, err := r.Run(context.Background(), "jwt_tool", nil)
	if err == nil {
		t.Fatal("Run succeeded for a tool that is not allowlisted")
	}
	if !strings.Contains(err.Error(), "jwt_tool") {
		t.Errorf("error %q does not name the refused tool", err)
	}
}

// The runner executes the allowlisted binary with the resolved args, captures
// stdout, and reports the exit code as data.
func TestExecToolRunnerRunsAllowlistedTool(t *testing.T) {
	r := NewToolRunner(ToolRunnerConfig{Tools: map[string]string{"echo": "/bin/echo"}})
	res, err := r.Run(context.Background(), "echo", []string{"hello from the check"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(res.Stdout, "hello from the check") {
		t.Errorf("stdout = %q, want the echoed arg", res.Stdout)
	}
}

// A non-zero exit code is not an error — it is the tool's verdict, which the
// check compares against.
func TestExecToolRunnerNonZeroExitIsNotAnError(t *testing.T) {
	r := NewToolRunner(ToolRunnerConfig{Tools: map[string]string{"sh": "/bin/sh"}})
	res, err := r.Run(context.Background(), "sh", []string{"-c", "exit 3"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3", res.ExitCode)
	}
}

// A missing binary is a launch failure, which is an error: the check cannot
// see the tool it asked for.
func TestExecToolRunnerLaunchFailureIsAnError(t *testing.T) {
	r := NewToolRunner(ToolRunnerConfig{Tools: map[string]string{"ghost": "/nonexistent/binary"}})
	_, err := r.Run(context.Background(), "ghost", nil)
	if err == nil {
		t.Fatal("Run succeeded for a binary that does not exist")
	}
}

// Output is capped at the configured bound so a noisy tool cannot balloon the
// process — the check sees the bounded prefix.
func TestExecToolRunnerCapsOutput(t *testing.T) {
	r := NewToolRunner(ToolRunnerConfig{
		Tools:          map[string]string{"sh": "/bin/sh"},
		MaxOutputBytes: 16,
	})
	res, err := r.Run(context.Background(), "sh", []string{"-c", "printf 'abcdefghijklmnopqrstuvwxyz'"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Stdout) > 16 {
		t.Errorf("captured %d bytes, want capped at 16", len(res.Stdout))
	}
}
