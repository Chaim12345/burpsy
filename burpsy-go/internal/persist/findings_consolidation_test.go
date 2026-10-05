package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-oorl: a merged finding's count survives a restart, and a row written before the
// count existed (merged_count NULL) reads its merges back from its occurrences rather than as 0.
func TestFindingMergedCountRoundTripsAndLegacyRowsDeriveIt(t *testing.T) {
	st := newTestStore(t)
	fs := core.NewFindingStore()
	fs.SetPersistenceSink(st.SaveFinding)
	add := func(ex core.ExchangeID) {
		fs.Add(core.NewFinding{
			Name: "XSS", Severity: core.SeverityHigh,
			Target:      core.FindingTarget{Host: "app.test", Port: 80, Path: "/s"},
			Occurrences: []core.Occurrence{{ExchangeID: ex}},
		})
	}
	add(1)
	add(2)
	add(3)

	loaded, err := st.LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].MergedCount != 2 {
		t.Fatalf("loaded %d findings, merged_count %d; want 1 finding merged twice", len(loaded), loaded[0].MergedCount)
	}

	if _, err := st.db.Exec(`UPDATE findings SET merged_count = NULL`); err != nil {
		t.Fatal(err)
	}
	legacy, err := st.LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	if legacy[0].MergedCount != 2 {
		t.Errorf("a legacy row with 3 occurrences read merged_count %d, want 2", legacy[0].MergedCount)
	}
}

// The excerpt a check quoted survives a restart: a leaked-key finding must still say which key.
func TestFindingEvidenceRoundTrips(t *testing.T) {
	st := newTestStore(t)
	fs := core.NewFindingStore()
	fs.SetPersistenceSink(st.SaveFinding)
	fs.Add(core.NewFinding{Name: "Secret exposed: AWS access token", Severity: core.SeverityHigh,
		Target: core.FindingTarget{Host: "cdn.test", Port: 443, Path: "/app.js"}, Evidence: "AKIA...MPLQ"})
	loaded, err := st.LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Evidence != "AKIA...MPLQ" {
		t.Fatalf("evidence did not survive: %+v", loaded)
	}
}

// A finding filed under a producer's merge key (a leaked secret, a weak JWT key) is re-indexed under
// that key after a restore, so the next sighting of the same secret on another path merges into it
// rather than filing a second finding.
func TestARestoredFindingKeepsMergingUnderItsMergeKey(t *testing.T) {
	st := newTestStore(t)
	fs := core.NewFindingStore()
	fs.SetPersistenceSink(st.SaveFinding)
	add := func(fs *core.FindingStore, path string) uint64 {
		return fs.Add(core.NewFinding{Name: "Secret exposed: AWS access token", Severity: core.SeverityHigh,
			Target: core.FindingTarget{Host: "cdn.test", Port: 443, Path: path}, MergeKey: "aws-access-token:abc"})
	}
	first := add(fs, "/app.js")

	loaded, err := st.LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	restored := core.NewFindingStore()
	restored.Restore(loaded)
	if got := add(restored, "/other.js"); got != first || restored.Count() != 1 {
		t.Errorf("after a restore the same secret on another path filed finding %d (count %d), want a merge into %d",
			got, restored.Count(), first)
	}
}
