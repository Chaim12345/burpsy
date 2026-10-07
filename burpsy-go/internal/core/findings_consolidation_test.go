package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func consolidationFinding(sev Severity, desc string, task uint64) NewFinding {
	return NewFinding{
		Name: "Reflected XSS", Severity: sev, Confidence: ConfidenceFirm, Description: desc, TaskID: task,
		Target:      FindingTarget{Host: "t.test", Port: 443, TLS: true, Path: "/search"},
		Occurrences: []Occurrence{{ExchangeID: ExchangeID(task)}},
	}
}

// The zero value must keep merging: every producer in the tree builds a NewFinding without a word
// about consolidation, and a store with no policy installed is how every one of them runs.
func TestConsolidationDefaultKeepsMergingAndCounts(t *testing.T) {
	fs := NewFindingStore()
	a := fs.Add(consolidationFinding(SeverityLow, "first", 1))
	b := fs.Add(consolidationFinding(SeverityHigh, "second", 1))
	if a != b {
		t.Fatalf("default store filed a duplicate as a second finding (%d, %d)", a, b)
	}
	f := fs.All()[0]
	if f.MergedCount != 1 || f.Severity != SeverityHigh || f.Description != "first" {
		t.Errorf("merged finding = count %d sev %v desc %q; want 1, High, first", f.MergedCount, f.Severity, f.Description)
	}
	total, byTask := fs.ConsolidationTallies()
	if total.Collisions != 1 || total.Merged != 1 || byTask[1].Merged != 1 {
		t.Errorf("tallies = %+v / %+v", total, byTask)
	}
	if got := fs.Consolidation().Default; got != ConsolidateKeepExisting {
		t.Errorf("unset default reads as %q, want keep_existing", got)
	}
}

// keep_both files a second finding, and the index stays on the oldest so a later keep_existing
// observation lands where the first did.
func TestConsolidationKeepBothFilesASecondFindingAndKeepsTheOldestOwner(t *testing.T) {
	fs := NewFindingStore()
	first := fs.Add(consolidationFinding(SeverityLow, "first", 1))
	fs.SetConsolidation(ConsolidationPolicy{Default: ConsolidateKeepExisting, PerRow: map[string]ConsolidationAction{"Reflected XSS": ConsolidateKeepBoth}})
	second := fs.Add(consolidationFinding(SeverityLow, "second", 2))
	if second == first || len(fs.All()) != 2 {
		t.Fatalf("keep_both did not file a second finding: %d, %d, n=%d", first, second, len(fs.All()))
	}
	fs.SetConsolidation(ConsolidationPolicy{Default: ConsolidateKeepExisting})
	third := fs.Add(consolidationFinding(SeverityLow, "third", 3))
	if third != first {
		t.Errorf("after keep_both the next merge landed on %d, want the oldest %d", third, first)
	}
	total, byTask := fs.ConsolidationTallies()
	if total.KeptBoth != 1 || total.Merged != 1 || byTask[2].KeptBoth != 1 {
		t.Errorf("tallies = %+v / %+v", total, byTask)
	}
}

// keep_new replaces the content under the same id — severity included, which is what "keep new"
// means — but an operator's override and false-positive mark survive, and the triage note goes.
func TestConsolidationKeepNewReplacesContentButNotTheOperatorsTriage(t *testing.T) {
	fs := NewFindingStore()
	id := fs.Add(consolidationFinding(SeverityHigh, "old", 1))
	fs.SetTriage(id, &TriageNote{Verdict: "likely_true_positive"})
	fs.SetConsolidation(ConsolidationPolicy{Default: ConsolidateKeepNew})
	if got := fs.Add(consolidationFinding(SeverityLow, "new", 2)); got != id {
		t.Fatalf("keep_new minted a new id %d, want %d", got, id)
	}
	f := fs.All()[0]
	if f.Description != "new" || f.Severity != SeverityLow || f.TaskID != 2 || f.Triage != nil || len(f.Occurrences) != 1 {
		t.Errorf("replaced finding = %+v", f)
	}

	high := SeverityHigh
	fs.Triage(id, func(f *Finding) { f.SeverityOverride = &high })
	fs.Add(consolidationFinding(SeverityInformational, "newer", 3))
	if f := fs.All()[0]; f.Severity != SeverityLow || f.SeverityOverride == nil {
		t.Errorf("keep_new overwrote a severity the operator overrode: sev %v override %v", f.Severity, f.SeverityOverride)
	}
	if total, _ := fs.ConsolidationTallies(); total.Replaced != 2 {
		t.Errorf("replaced tally = %d, want 2", total.Replaced)
	}
}

// A setting that does not name an action reads as keep_existing, never keep_both — and the policy
// marshals its override map as {} rather than null.
func TestConsolidationPolicyFallsBackToMergingAndMarshalsAnEmptyMap(t *testing.T) {
	fs := NewFindingStore()
	fs.SetConsolidation(ConsolidationPolicy{Default: "bogus", PerRow: map[string]ConsolidationAction{"X": "nope", "Y": ConsolidateKeepBoth}})
	p := fs.Consolidation()
	if p.Default != ConsolidateKeepExisting || len(p.PerRow) != 1 || p.PerRow["Y"] != ConsolidateKeepBoth {
		t.Errorf("policy = %+v", p)
	}
	raw, _ := json.Marshal(NewFindingStore().Consolidation())
	if !strings.Contains(string(raw), `"per_row":{}`) {
		t.Errorf("empty policy marshals as %s", raw)
	}
	fs.Add(consolidationFinding(SeverityLow, "a", 1))
	fs.Add(consolidationFinding(SeverityLow, "b", 1))
	fs.Clear()
	if total, byTask := fs.ConsolidationTallies(); total.Collisions != 0 || len(byTask) != 0 {
		t.Errorf("Clear left tallies behind: %+v %+v", total, byTask)
	}
	if fs.Consolidation().PerRow["Y"] != ConsolidateKeepBoth {
		t.Error("Clear dropped the operator's policy")
	}
}
