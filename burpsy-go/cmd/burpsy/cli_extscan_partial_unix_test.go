//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/procgroup/proctest"
)

// burpsy-react-ui-b2wh at the one surface that reports a nuclei run: a run cut
// short with real hits prints and writes them, says it did not finish and why,
// and fails the command; a run that finished does none of that.

const cliFakeRecord = `{"template-id":"tpl-one","info":{"name":"One","severity":"high"},"type":"http","host":"127.0.0.1","port":"80","matched-at":"http://127.0.0.1/a"}`

func runFakeNucleiCLI(t *testing.T, tail string) (string, string, error) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "nuclei")
	script := "#!/bin/sh\nprintf '%s\\n' '" + cliFakeRecord + "'\n" + tail + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	ctx := &cliContext{
		scope:         core.NewScopeAllowEverything(),
		out:           &out,
		toolAllowlist: map[string]string{"nuclei": bin},
	}
	report := filepath.Join(dir, "report.json")
	err := cmdExtScan(ctx, []string{"nuclei", "-target", "http://127.0.0.1/", "-format", "json", "-out", report})
	doc, _ := os.ReadFile(report)
	return out.String(), string(doc), err
}

func TestExtscanCLIReportsACutShortNucleiRunAsPartial(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	// The tool exits, but a process it started holds stdout open past
	// procgroup.WaitDelay: the capture is incomplete.
	out, doc, err := runFakeNucleiCLI(t, "sleep 30 &\necho $! > '"+pidFile+"'\nexit 0")
	syscall.Kill(proctest.ChildPID(t, pidFile), syscall.SIGKILL)
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("command error = %v, want a failure saying the tool did not finish", err)
	}
	for _, want := range []string{"nuclei: partial (cut short)", "did not finish (incomplete output)", "1 template hit(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("console lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(doc, "One") || !strings.Contains(doc, "did not finish (incomplete output)") {
		t.Errorf("the written report lacks the hit or the partial note:\n%s", doc)
	}
}

func TestExtscanCLIReportsAFinishedNucleiRunAsCompleted(t *testing.T) {
	out, doc, err := runFakeNucleiCLI(t, "exit 0")
	if err != nil {
		t.Errorf("command error = %v for a finished run", err)
	}
	if !strings.Contains(out, "nuclei: completed") || strings.Contains(out, "did not finish") {
		t.Errorf("console for a finished run:\n%s", out)
	}
	if !strings.Contains(doc, "One") || strings.Contains(doc, "did not finish") {
		t.Errorf("report for a finished run:\n%s", doc)
	}
}
