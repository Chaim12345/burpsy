package core

import (
	"testing"
)

func low() *Severity       { s := SeverityLow; return &s }
func certain() *Confidence { c := ConfidenceCertain; return &c }

// An override changes what EffectiveSeverity reports without touching the engine's own verdict.
func TestEffectiveSeverityPrefersOverride(t *testing.T) {
	f := Finding{Severity: SeverityHigh, SeverityOverride: low()}
	if got := f.EffectiveSeverity(); got != SeverityLow {
		t.Errorf("EffectiveSeverity = %v, want Low", got)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("engine Severity mutated to %v, want High untouched", f.Severity)
	}
	f2 := Finding{Severity: SeverityHigh}
	if got := f2.EffectiveSeverity(); got != SeverityHigh {
		t.Errorf("no override: EffectiveSeverity = %v, want High", got)
	}
}

// Triage sets and clears overrides and other triage state in one locked step.
func TestTriageAppliesAndClears(t *testing.T) {
	fs := NewFindingStore()
	id := fs.Add(NewFinding{Name: "XSS", Severity: SeverityHigh, Confidence: ConfidenceFirm})

	ok := fs.Triage(id, func(f *Finding) {
		f.SeverityOverride = low()
		f.ConfidenceOverride = certain()
		f.FalsePositive = true
		f.Comment = "checked by hand"
	})
	if !ok {
		t.Fatal("Triage returned false for a live id")
	}
	f, err := fs.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if f.EffectiveSeverity() != SeverityLow || f.EffectiveConfidence() != ConfidenceCertain || !f.FalsePositive || f.Comment != "checked by hand" {
		t.Fatalf("triage state lost: %+v", f)
	}

	// Clearing restores the engine's verdict.
	fs.Triage(id, func(f *Finding) {
		f.SeverityOverride = nil
		f.ConfidenceOverride = nil
		f.FalsePositive = false
		f.Comment = ""
	})
	f, _ = fs.Get(id)
	if f.EffectiveSeverity() != SeverityHigh || f.EffectiveConfidence() != ConfidenceFirm || f.FalsePositive || f.Comment != "" {
		t.Errorf("clear did not restore engine values: %+v", f)
	}

	if fs.Triage(999, func(f *Finding) {}) {
		t.Error("Triage returned true for a missing id")
	}
}

// The reason overrides live through a merge: a re-audit that re-raises the same finding must not
// reset the operator's verdict to the engine's.
func TestMergeKeepsOperatorOverridesAndFalsePositive(t *testing.T) {
	fs := NewFindingStore()
	id := fs.Add(NewFinding{
		Name:     "SQLi",
		Severity: SeverityHigh,
		Target:   FindingTarget{Host: "app.test", Port: 80, Path: "/item"},
		Param:    "q",
	})
	fs.Triage(id, func(f *Finding) {
		f.SeverityOverride = low()
		f.FalsePositive = true
		f.Comment = "waf blocks this"
	})

	// The same finding is raised again by a second audit run; the engine still says High. The
	// merge is driven through Add, the path a real re-audit takes, rather than by calling a
	// locked helper directly.
	fs.Add(NewFinding{
		Name:     "SQLi",
		Severity: SeverityHigh,
		Target:   FindingTarget{Host: "app.test", Port: 80, Path: "/item"},
		Param:    "q",
	})
	if got := fs.Count(); got != 1 {
		t.Fatalf("re-audit produced %d findings, want a merge into the original one", got)
	}
	merged, err := fs.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if merged.SeverityOverride == nil || *merged.SeverityOverride != SeverityLow {
		t.Errorf("severity override lost in merge: %+v", merged)
	}
	if !merged.FalsePositive {
		t.Error("false positive lost in merge")
	}
	if merged.Comment != "waf blocks this" {
		t.Errorf("comment lost in merge: %q", merged.Comment)
	}
	if merged.Severity != SeverityHigh {
		t.Errorf("engine severity changed in merge to %v, want High", merged.Severity)
	}
}

func TestDeleteSinkFires(t *testing.T) {
	fs := NewFindingStore()
	deleted := []uint64{}
	fs.SetDeleteSink(func(id uint64) { deleted = append(deleted, id) })

	id := fs.Add(NewFinding{Name: "X", Severity: SeverityLow})
	if !fs.Delete(id) {
		t.Fatal("Delete returned false for a live id")
	}
	if len(deleted) != 1 || deleted[0] != id {
		t.Errorf("delete sink got %v, want [%d]", deleted, id)
	}

	// A delete of a missing id must not fire the sink: the mirror row it would refer to does not
	// exist either, and a spurious call is a lie about the past.
	if fs.Delete(4242) {
		t.Error("Delete returned true for a missing id")
	}
	if len(deleted) != 1 {
		t.Errorf("delete sink fired for a missing id: %v", deleted)
	}
}
