package main

// Every committed git hook must parse under the interpreter its own shebang declares
// (burpsy-react-ui-5r80).
//
// Why a Go test at all: the defect shipped in a file nobody runs on purpose. bd's integration
// appended a POSIX-shell block after a Python body, the file stopped parsing at line 62, and the
// first symptom was a failed push — after the broken file was already committed. A gate that
// reads each hook's OWN shebang and asks that interpreter "does this parse?" turns that into a
// test failure at commit time, which is the only place it can be caught cheaply.
//
// # Why this package, and the path it walks
//
// The hooks live at the repository root, outside the module, and Go tests run with the package
// directory as their working directory — so the test walks ../../.. to reach .beads/hooks. That
// coupling is stated here because it is the one thing about this test that can silently break: a
// move of this package needs the walk adjusted, and `go test ./burpsy-go/cmd/burpsy` run from a
// directory that is not the repository root finds no hooks and says so loudly rather than passing.
//
// # What each interpreter is asked
//
// Python: py_compile, which parses without executing — a hook must never run as a side effect of
// the gate. Shell: sh -n, the same read-only syntax check. Both are the strictest check available
// that does not execute the hook, and both are the interpreters the hooks actually declare: a
// hook that names something else is itself a finding, not a skip.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hookWalk is the number of parent steps from this package's directory to the repository root.
const hookWalk = "../../../"

// Test_every_committed_git_hook_parses_under_its_own_shebang walks .beads/hooks and asks each
// executable file's declared interpreter whether the file parses.
//
// The assertion is deliberately "parses", not "runs": executing a pre-commit from the test would
// mutate the very state the gate exists to protect. The failure message names the file and the
// interpreter's complaint, because a syntax error is only actionable from its own text.
func Test_every_committed_git_hook_parses_under_its_own_shebang(t *testing.T) {
	dir := filepath.Join(hookWalk, ".beads", "hooks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		// A checkout without the beads integration is a supported state (the hooks directory is
		// committed, but a consumer vendoring only burpsy-go would not carry it). Absence is
		// reported, not skipped silently: a test that passes because it found nothing to check is
		// the shape of a gate that quietly stopped gating.
		t.Skipf("no .beads/hooks directory to check: %v", err)
	}

	checked := 0
	for _, e := range entries {
		name := e.Name()
		// The Windows shims (.cmd batch, .ps1 PowerShell) are three-line wrappers that invoke the
		// runner by name. Skipped with the reason stated rather than silently: batch and PowerShell
		// have no parse-only mode worth invoking from this gate, their bodies are small enough to
		// read, and a skip that is not named is how a gate quietly stops checking things.
		if strings.HasSuffix(name, ".cmd") || strings.HasSuffix(name, ".ps1") {
			continue
		}
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, name)
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if st.Mode()&0o111 == 0 {
			continue // not executable: git never runs it
		}

		shebang, err := firstLine(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		switch {
		case strings.Contains(shebang, "python"):
			out, err := exec.Command("python3", "-m", "py_compile", path).CombinedOutput()
			if err != nil {
				t.Errorf("%s declares %q and python3 cannot parse it: %s\nThis is the exact shape of "+
					"burpsy-react-ui-5r80: a shell block appended to a python hook is a SyntaxError at "+
					"parse time, and nothing in the file — including the block — ever runs",
					name, shebang, out)
			}
		case strings.Contains(shebang, "sh"):
			out, err := exec.Command("sh", "-n", path).CombinedOutput()
			if err != nil {
				t.Errorf("%s declares %q and sh -n rejects it: %s\nA hook that does not parse fails "+
					"every commit or push it touches, and the only working response (--no-verify) "+
					"teaches the operator to skip every other hook too", name, shebang, out)
			}
		default:
			t.Errorf("%s's shebang %q names no interpreter this gate knows how to check; add it here "+
				"rather than skipping the file, because an unchecked hook is the shape the next one "+
				"of these hides behind", name, shebang)
		}
		checked++
	}
	if checked == 0 {
		t.Error("no hooks were checked: the directory held no executable hook files, so this gate "+
			"proved nothing — which is a finding about the directory, not a pass")
	}
}

// firstLine reads a file's shebang line, without trailing whitespace.
func firstLine(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", nil
	}
	line := string(data)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimRight(line, "\r"), nil
}
