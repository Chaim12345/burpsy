package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The CLI's `scan` command must dispatch the loaded corpus's active checks, not
// just the passive set. Without this wiring `-bchecks DIR scan audit` audits
// with the built-in table only while the proxy keeps reporting corpus findings
// from the same directory — two surfaces, two different meanings of "a scan".
//
// The assertion compares against a no-corpus context rather than against zero,
// because the default ScanConfig ships with the built-in check table enabled:
// a non-zero count proves nothing about the wiring. What proves it is that the
// corpus context has *more* active checks than the plain one.
func TestCLIContextWiresTheLoadedCorpusIntoTheActiveScanner(t *testing.T) {
	dir := t.TempDir()
	// An M2-runnable check: `given request` with a send, no interaction server,
	// no insertion point. It must land in ActiveChecks, which is exactly what
	// newCLIContext hands to WithCorpusChecks.
	corpus := `metadata:
  language: v1-beta
  name: "cli wiring probe"
  description: "cli wiring probe"

given request then
  send request:
    appending queries: "p=1"
`
	if err := os.WriteFile(filepath.Join(dir, "active.bcheck"), []byte(corpus), 0o644); err != nil {
		t.Fatal(err)
	}

	plain, err := newCLIContext("", 1<<20, "*", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("newCLIContext (no corpus): %v", err)
	}
	wired, err := newCLIContext("", 1<<20, "*", "", "", dir, "", nil)
	if err != nil {
		t.Fatalf("newCLIContext (corpus): %v", err)
	}
	if wired.scanner.ActiveCheckCount() <= plain.scanner.ActiveCheckCount() {
		t.Fatalf("expected the corpus to add an active check to the CLI scanner: plain=%d wired=%d",
			plain.scanner.ActiveCheckCount(), wired.scanner.ActiveCheckCount())
	}
}
