package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The triage fields have to come back out of the database exactly as they went in, including the
// distinction between "no override" (nil) and an override that happens to equal the engine value.
func TestFindingTriageRoundTrip(t *testing.T) {
	st := newTestStore(t)
	fs := core.NewFindingStore()
	fs.SetPersistenceSink(st.SaveFinding)
	fs.SetDeleteSink(st.DeleteFinding)

	sev := core.SeverityLow
	id := fs.Add(core.NewFinding{
		Name:     "XSS",
		Severity: core.SeverityHigh,
		Target:   core.FindingTarget{Host: "app.test", Port: 80, Path: "/s"},
	})
	fs.Triage(id, func(f *core.Finding) {
		f.SeverityOverride = &sev
		f.FalsePositive = true
		f.Comment = "not reachable"
	})

	loaded, err := st.LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d findings, want 1", len(loaded))
	}
	f := loaded[0]
	if f.SeverityOverride == nil || *f.SeverityOverride != core.SeverityLow {
		t.Errorf("severity override did not survive: %+v", f)
	}
	if !f.FalsePositive {
		t.Error("false positive did not survive")
	}
	if f.Comment != "not reachable" {
		t.Errorf("comment did not survive: %q", f.Comment)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("engine severity changed: %v", f.Severity)
	}
}

// A finding with no triage state — the shape of every row written before this feature existed —
// must load as "no triage", not fail or invent values.
func TestLegacyFindingRowsLoadWithoutTriage(t *testing.T) {
	st := newTestStore(t)
	fs := core.NewFindingStore()
	fs.SetPersistenceSink(st.SaveFinding)
	fs.Add(core.NewFinding{Name: "plain", Severity: core.SeverityMedium})

	loaded, err := st.LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d findings, want 1", len(loaded))
	}
	f := loaded[0]
	if f.SeverityOverride != nil || f.ConfidenceOverride != nil || f.FalsePositive || f.Comment != "" {
		t.Errorf("unexpected triage state on a plain finding: %+v", f)
	}
}

// A finding deleted in the UI must not walk back in on the next restore — the delete sink is what
// stops the SQLite mirror resurrecting it.
func TestDeleteFindingRemovesRow(t *testing.T) {
	st := newTestStore(t)
	fs := core.NewFindingStore()
	fs.SetPersistenceSink(st.SaveFinding)
	fs.SetDeleteSink(st.DeleteFinding)

	id := fs.Add(core.NewFinding{Name: "gone", Severity: core.SeverityLow})
	loaded, err := st.LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("setup: loaded %d findings, want 1", len(loaded))
	}

	if !fs.Delete(id) {
		t.Fatal("Delete returned false")
	}
	loaded, err = st.LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 {
		t.Errorf("deleted finding still in database: %d rows", len(loaded))
	}
}
