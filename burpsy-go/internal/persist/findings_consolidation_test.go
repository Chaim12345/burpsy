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
