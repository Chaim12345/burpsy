package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

// The CLI's `scan` command must dispatch the loaded corpus's active checks, not
// just the passive set. Without this wiring `-bchecks DIR scan audit` audits
// with the built-in table only while the proxy keeps reporting corpus findings
// from the same directory — two surfaces, two different meanings of "a scan".
//
// The corpus semantics the W1 wiring pins: the bundled corpus compiled into
// the binary is part of the default audit set (WithBundledCorpus switches
// check_corpus on), and an operator's -bchecks directory REPLACES that bundled
// set rather than adding to it (scanner.BundledCorpusForDir). So the plain
// context's count already includes the bundled checks, and the corpus context
// carries the plain count minus the bundled set plus the loaded directory's
// checks. That exact arithmetic is what proves the loaded corpus reached the
// active scanner: comparing against zero, or expecting *more* than the plain
// count, both pass with the loaded corpus silently dropped behind the bundled
// default.
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

	plain, err := newCLIContext("", 1<<20, "*", "", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("newCLIContext (no corpus): %v", err)
	}
	wired, err := newCLIContext("", 1<<20, "*", "", "", dir, "", "", nil)
	if err != nil {
		t.Fatalf("newCLIContext (corpus): %v", err)
	}
	bundled, err := scanner.BundledCorpusForDir("", nil)
	if err != nil {
		t.Fatalf("bundled corpus: %v", err)
	}
	want := plain.scanner.ActiveCheckCount() - len(bundled) + 1
	if got := wired.scanner.ActiveCheckCount(); got != want {
		t.Fatalf("corpus dir must replace the bundled set and land its own checks in the CLI scanner: plain=%d bundled=%d wired=%d want=%d",
			plain.scanner.ActiveCheckCount(), len(bundled), got, want)
	}
}
