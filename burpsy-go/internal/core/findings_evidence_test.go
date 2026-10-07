package core

// Tests for Finding.Evidence (burpsy-react-ui-cx31).
//
// # Why the field exists
//
// A finding's Name and Description answer "what kind of thing happened". Nothing answered "which
// value", so an operator told that a credential leaked had to re-fetch the traffic by hand to find
// out which one — the exact work the tool exists to do. Evidence is that answer, redacted by the
// producer to whatever it must be, and these tests pin how it survives the trip into the store.
//
// The field was added after the fact: checks had been populating scanner.Finding.Evidence and
// coreNewFindingFor was dropping it on the way in, so every excerpt the engine ever produced died
// between the check and the store. That is why the merge rules below are stated explicitly — a
// field added late has no tests behind it by default, and merge is exactly where a late field is
// most likely to be quietly wrong.

import "testing"

// Evidence survives Add: the excerpt a producer supplied is the excerpt the store holds.
func TestEvidenceReachesTheStoredFinding(t *testing.T) {
	fs := NewFindingStore()
	id := fs.Add(NewFinding{
		Name:        "AWS secret access key exposed",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceFirm,
		Description: "a labelled AWS secret access key was found in the response body",
		Evidence:    "wJal...YKEY",
		Target:      FindingTarget{Host: "h", Path: "/config"},
	})

	got, err := fs.Get(id)
	if err != nil {
		t.Fatalf("finding %d is not in the store after Add: %v", id, err)
	}
	if got.Evidence != "wJal...YKEY" {
		t.Errorf("Evidence = %q after Add, want %q; the excerpt is the one thing that says WHICH "+
			"credential leaked, and losing it makes the finding unactionable", got.Evidence, "wJal...YKEY")
	}
}

// A finding with no excerpt is a normal finding, not a refusal. Empty must not be treated as a
// problem to report or a field to reject.
func TestAFindingWithNoEvidenceStoresCleanly(t *testing.T) {
	fs := NewFindingStore()
	id := fs.Add(NewFinding{
		Name:   "Cookie without HttpOnly",
		Target: FindingTarget{Host: "h", Path: "/login"},
	})
	got, err := fs.Get(id)
	if err != nil {
		t.Fatalf("finding %d is not in the store: %v", id, err)
	}
	if got.Evidence != "" {
		t.Errorf("Evidence = %q for a finding that supplied none, want empty", got.Evidence)
	}
}

// On a merge the FIRST observation's excerpt stands, so a finding's quoted text does not depend on
// scan order. This is the same rule Add's doc states for Description, and Evidence is text.
func TestAMergeKeepsTheFirstObservationsEvidence(t *testing.T) {
	fs := NewFindingStore()
	target := FindingTarget{Host: "h", Path: "/config"}
	fs.Add(NewFinding{Name: "leak", Evidence: "first-excerpt", Target: target})
	fs.Add(NewFinding{Name: "leak", Evidence: "second-excerpt", Target: target})

	for _, f := range fs.All() {
		if f.Name == "leak" {
			if f.Evidence != "first-excerpt" {
				t.Errorf("Evidence = %q after a merge, want the first observation's %q; a finding "+
					"whose quoted text changes with scan order is a finding nobody can re-read",
					f.Evidence, "first-excerpt")
			}
			return
		}
	}
	t.Fatal("no merged finding named 'leak'")
}

// The one exception, and it is directional on purpose: a first observation with no excerpt followed
// by one that has it must BACKFILL. Otherwise the common case loses everything — a check that only
// quotes when it has context (a longer match, a second occurrence) would leave the merged finding
// with no excerpt at all, which is precisely the finding an operator most needs to act on.
func TestAMergeBackfillsEvidenceWhenTheFirstObservationHadNone(t *testing.T) {
	fs := NewFindingStore()
	target := FindingTarget{Host: "h", Path: "/config"}
	fs.Add(NewFinding{Name: "leak", Evidence: "", Target: target})
	fs.Add(NewFinding{Name: "leak", Evidence: "later-excerpt", Target: target})

	for _, f := range fs.All() {
		if f.Name == "leak" {
			if f.Evidence != "later-excerpt" {
				t.Errorf("Evidence = %q after merging into an excerpt-less first observation, want "+
					"the later excerpt backfilled; an empty first observation must not permanently "+
					"strip the excerpt from the finding", f.Evidence)
			}
			return
		}
	}
	t.Fatal("no merged finding named 'leak'")
}

// The backfill must not run backwards. An observation with no excerpt arriving after one that has
// it must not CLEAR it — "nothing to quote this time" is not evidence that there is nothing to
// quote.
func TestAMergeDoesNotClearEvidenceOnAnExcerptlessObservation(t *testing.T) {
	fs := NewFindingStore()
	target := FindingTarget{Host: "h", Path: "/config"}
	fs.Add(NewFinding{Name: "leak", Evidence: "kept-excerpt", Target: target})
	fs.Add(NewFinding{Name: "leak", Evidence: "", Target: target})

	for _, f := range fs.All() {
		if f.Name == "leak" {
			if f.Evidence != "kept-excerpt" {
				t.Errorf("Evidence = %q after merging an excerpt-less observation, want %q; an "+
					"observation with nothing to quote is not evidence that there is nothing to quote",
					f.Evidence, "kept-excerpt")
			}
			return
		}
	}
	t.Fatal("no merged finding named 'leak'")
}
