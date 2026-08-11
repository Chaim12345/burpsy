package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// The published corpus is a PortSwigger fixture absent from most machines, so
// this recounts it only when it is present and otherwise skips — the same
// three-valued honesty as cmd/conform (a skipped check reports as skipped).
// The counts it guards are not absolute totals, which drift as the corpus
// repo grows; they are the invariants that used to be broken:
//
//  1. Every corpus check polling `<type> interactions` is classified
//     NeedsCollaborator (the classifier used to check a different parse shape
//     and answered false for all of them, silently dispatching blind checks
//     that probed nothing).
//  2. Collaborator checks survive load into ActiveChecks (they used to be
//     counted and dropped, which made the seam gate unreachable).
//  3. Attaching an interaction server to the ActiveScanner adds them to the
//     dispatch set; the nil-seam scanner keeps them out.
//
// The numbers are printed for the human reading the log, not asserted.
func TestCorpusCollaboratorChecksClassifyAndDispatch(t *testing.T) {
	const root = "/tmp/BChecks"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("corpus not present at %s; classification invariants unverified here", root)
	}
	logger := zap.NewNop()
	ps, err := LoadDir(root, nil, core.NewScope(), logger)
	if err != nil {
		t.Fatal(err)
	}
	rep := ps.Report()
	t.Logf("LoadReport summary: %s", rep.Summary())

	// 1. Cross-check the classification against textual ground truth: every
	// corpus file that polls `<type> interactions` must land in the
	// Collaborator bucket and nowhere else (the classifier used to check a
	// different parse shape and answered false for all of them).
	interactionFiles := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || filepath.Ext(p) != ".bcheck" {
			return nil
		}
		src, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(src), "interactions") {
			interactionFiles++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if interactionFiles == 0 {
		t.Skipf("no top-level corpus file mentions interactions; corpus layout may have changed at %s", root)
	}
	if rep.Collaborator != interactionFiles {
		t.Errorf("LoadReport.Collaborator=%d but %d corpus file(s) poll interactions — misclassification",
			rep.Collaborator, interactionFiles)
	}
	if rep.Collaborator == 0 {
		t.Fatal("corpus holds <type> interactions checks, but LoadReport.Collaborator is 0 — misclassification")
	}

	// 2. The collaborator checks reach the active scanner (counted *and* kept).
	nilScanner := NewActiveScanner(nil, logger).
		WithCorpusChecks(ps.ActiveChecks())
	withServer := NewActiveScanner(nil, logger).
		WithCorpusChecks(ps.ActiveChecks()).
		WithCollaborator(stubCollaborator{})
	plain, with := nilScanner.ActiveCheckCount(), withServer.ActiveCheckCount()
	t.Logf("active checks: nil seam=%d, with server=%d (delta = the collaborator set)", plain, with)
	if with <= plain {
		t.Fatalf("expected the interaction server to admit collaborator checks: nil=%d with=%d", plain, with)
	}
	if want := rep.Collaborator; with-plain != want {
		t.Fatalf("dispatch delta %d != LoadReport.Collaborator %d", with-plain, want)
	}
}

// stubCollaborator satisfies the seam without opening sockets; dispatch
// admission reads only the interface's presence.
type stubCollaborator struct{}

func (stubCollaborator) NewAddress() string { return "deadbeef.burpsy.test" }
func (stubCollaborator) Interactions([]string) (dns, http, smtp bool) {
	return false, false, false
}
