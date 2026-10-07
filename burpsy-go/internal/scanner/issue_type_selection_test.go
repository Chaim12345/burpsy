package scanner

import (
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// burpsy-react-ui-kvmx: the three selected_issues-family keys were reported as unapplied because the
// engine had no per-issue selection. Burp's dispatch is a two-stage filter for exactly this — the
// family switches, then a per-check predicate over the selected issue types (Zwy6.java:36-75, and
// lambda$isEnabled$1 at :170-184) — so a run could not be narrowed past its families, and the
// ordinary workflow (fix a bug, re-audit for that one issue class) was unreachable.
//
// The rows were a false statement in an operator-facing table for a control that now works.

// probeChecksScanner is a scanner with every family switch on, so the ONLY thing that can narrow its
// check set is the per-issue selection. Built from the real registry rather than a synthetic table,
// because the test's claim is about what a real run dispatches.
func probeChecksScanner(t *testing.T) *ActiveScanner {
	t.Helper()
	cfg := &ScanConfig{
		MaxConcurrency: 1, Timeout: 5 * time.Second,
		CheckSqli: true, CheckXss: true, CheckPathTraversal: true, CheckSSRF: true,
		CheckXXE: true, CheckJwtWeak: true, CheckJSVulns: true,
		CheckPassiveAnalysis: true, CheckPassivePosture: true, CheckHeaders: true,
		CheckHostDiscovery: true, CheckExtendedCoverage: true, CheckReflectionProbes: true,
		CheckResponseDependence: true, CheckActiveInjection: true,
		CheckExtendedActive: true, CheckOutOfBand: true, CheckStored: true, CheckCorpus: true,
	}
	return NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithConfig(cfg)
}

// An empty selection is NO RESTRICTION, not "nothing selected" — the reading every optional field
// on this configuration uses, and the one that keeps a preset which never mentions selection
// behaving exactly as before.
func TestAnEmptyIssueTypeSelectionMeansNoRestriction(t *testing.T) {
	if !(ScanConfig{}).IsIssueTypeSelected(1) {
		t.Error("an empty selection excludes a type; a configuration that never mentions the key must " +
			"behave exactly as it did before the key existed")
	}
	if !(ScanConfig{IssueTypes: []uint32{}}).IsIssueTypeSelected(1) {
		t.Error("an explicitly empty slice excludes a type, which is not the same as unset here")
	}
}

// A selection that NAMES types admits exactly those.
func TestASelectionAdmitsExactlyTheTypesItNames(t *testing.T) {
	cfg := ScanConfig{IssueTypes: []uint32{0x0001, 0x0022}}
	for _, want := range []uint32{0x0001, 0x0022} {
		if !cfg.IsIssueTypeSelected(want) {
			t.Errorf("type %#04x was named by the selection and is not selected", want)
		}
	}
	for _, notWanted := range []uint32{0x0003, 0x0999} {
		if cfg.IsIssueTypeSelected(notWanted) {
			t.Errorf("type %#04x was NOT named by the selection and is selected anyway", notWanted)
		}
	}
}

// The narrowing itself, at the check-set level. This is the property that makes a run narrowable at
// all, and the one a test must read from the check set rather than from the predicate — a predicate
// that is right and never consulted selects nothing and every test of it passes.
func TestTheCheckSetIsNarrowedToTheSelectedIssueTypes(t *testing.T) {
	all := []activeCheck{
		{name: "sql-injection", typeIndex: 0x0001},
		{name: "path-traversal", typeIndex: 0x0022},
		{name: "xss-reflected", typeIndex: 0x0003},
		// A check with no catalogue entry — a synthesized corpus check. Not selectable, and not
		// kept when a selection is in force: a list that cannot name something must not silently
		// include it.
		{name: "corpus-synthesised"},
	}

	// No selection: everything, unchanged.
	if got := filterByIssueTypes(all, nil); len(got) != len(all) {
		t.Errorf("an empty selection narrowed the set to %d of %d; no selection means no restriction",
			len(got), len(all))
	}

	got := filterByIssueTypes(all, []uint32{0x0001, 0x0022})
	if len(got) != 2 {
		t.Fatalf("a two-type selection kept %d checks, want 2", len(got))
	}
	for _, c := range got {
		if c.typeIndex != 0x0001 && c.typeIndex != 0x0022 {
			t.Errorf("check %q (type %#04x) survived a selection that did not name it", c.name, c.typeIndex)
		}
	}
	// And the un-named, un-indexable one is EXCLUDED, not kept: it is the conservative direction,
	// because the operator asked for a set and a check they could not have chosen either way is
	// better reported as unselected than as selected.
	for _, c := range got {
		if c.name == "corpus-synthesised" {
			t.Error("a check with no catalogue entry survived a selection; a selection that cannot name " +
				"something must not silently keep it")
		}
	}
}

// The WIRING, read from the check set a scanner would actually dispatch.
//
// The two tests above call filterByIssueTypes directly, so they pass against an engine that
// computes the narrowed set and throws it away — which is exactly the mutation that leaves this
// feature looking delivered. This one goes through enabledChecks, which is the only function a run
// consults, so a selection that is not applied there is invisible to the others (burpsy-react-ui-kvmx).
func TestASelectionNarrowsTheCheckSetAScannerWouldDispatch(t *testing.T) {
	// Every family switch ON, so the selection is the only thing that can narrow the set.
	s := probeChecksScanner(t)
	before := s.enabledChecks()
	if len(before) < 2 {
		t.Skip("the probe scanner dispatches too few checks to tell a selection apart from the " +
			"family switches")
	}

	s.UpdateScanConfig(func(c *ScanConfig) {
		// One type that is definitely in the set, read back off the set itself rather than
		// hard-coded — a catalogue index that moved would otherwise make this test pass for the
		// wrong reason.
		c.IssueTypes = []uint32{before[0].typeIndex}
	})
	after := s.enabledChecks()
	if len(after) >= len(before) {
		t.Errorf("a selection of one type left %d of %d checks dispatchable; the narrowing is computed "+
			"and not applied, which is the shape of a control that looks delivered", len(after), len(before))
	}
	for _, c := range after {
		if c.typeIndex != before[0].typeIndex {
			t.Errorf("check %q (type %#04x) dispatched under a selection naming only %#04x",
				c.name, c.typeIndex, before[0].typeIndex)
		}
	}
	// And clearing it restores the whole set, which is the "no restriction" half again.
	s.UpdateScanConfig(func(c *ScanConfig) { c.IssueTypes = nil })
	if got := s.enabledChecks(); len(got) != len(before) {
		t.Errorf("clearing the selection left %d of %d checks; unset must mean no restriction",
			len(got), len(before))
	}
}

// The AUDIT path specifically, which is a different function from enabledChecks and takes the
// per-run configuration rather than the live one.
//
// A selection reaches a run through enabledChecksUnder, and a narrowing applied only in
// enabledChecks is computed and discarded for every real audit — which is every run a caller
// starts. This test starts one, and the mutation it exists for is the one that passes when the
// selection is honoured only where nothing looks.
func TestTheSelectionNarrowsTheCheckSetAnAuditWouldDispatch(t *testing.T) {
	s := probeChecksScanner(t)
	before := s.enabledChecksUnder(s.AuditConfig())
	if len(before) < 2 {
		t.Skip("the probe scanner dispatches too few checks to tell a selection apart from the " +
			"family switches")
	}
	// Only a selection: no family switch, no tier key. This is the configuration that has to narrow,
	// and it is the one a gate predicate written before the selection existed would route past.
	narrowed := s.enabledChecksUnder(AuditConfig{IssueTypes: []uint32{before[0].typeIndex}})
	if len(narrowed) >= len(before) {
		t.Errorf("a selection of one type left %d of %d checks dispatchable for an audit; the narrowing "+
			"is applied where the check set is LISTED and not where it is DISPATCHED, which is the shape "+
			"of a control that looks delivered", len(narrowed), len(before))
	}
}

// The coverage report needs the third state. A row that is runnable and suppressed is not covered
// for a run under this configuration, and a number that cannot say so overstates what the run would do.
func TestCoverageReportsARunnableCheckTheSelectionSuppresses(t *testing.T) {
	cfg := ScanConfig{IssueTypes: []uint32{0x0001}}
	rows := NativeCheckCoverageUnder(cfg)
	if len(rows) == 0 {
		t.Skip("the native registry is empty in this build")
	}
	var suppressed, runnable int
	for _, r := range rows {
		if r.Runnable {
			runnable++
		}
		if r.Suppressed {
			suppressed++
		}
		// The two are mutually exclusive, and a declined row is neither: it was never going to run.
		if r.Suppressed && !r.Runnable {
			t.Errorf("%q is declined AND reported as suppressed; that is two explanations for one absence",
				r.Name)
		}
	}
	if suppressed == 0 {
		t.Error("a selection of one type suppressed no runnable row; the coverage report cannot then " +
			"distinguish this run's coverage from a run with no selection at all")
	}
	if runnable == 0 {
		t.Fatal("no runnable rows in the native registry")
	}
}

// And with no selection, nothing is suppressed — a report that claimed otherwise would be describing
// a configuration nobody asked for.
func TestCoverageReportsNoSuppressionWithoutASelection(t *testing.T) {
	for _, r := range NativeCheckCoverageUnder(ScanConfig{}) {
		if r.Suppressed {
			t.Fatalf("%q is reported as suppressed with no selection in force; every runnable row is "+
				"selected when nothing is selected", r.Name)
		}
	}
}

// The three keys now apply, as partial: honoured as far as a boolean can be, and named as such rather
// than claimed or denied flat.
func TestTheThreeSelectionKeysNowApply(t *testing.T) {
	want := map[string]bool{
		"scan_only_selected_issues": true,
		"select_individual_issues":  true,
		"selected_issues":           true,
	}
	seen := map[string]bool{}
	for _, k := range BuiltInConfigKeys() {
		if _, tracked := want[k.Name]; !tracked {
			continue
		}
		seen[k.Name] = true
		if !k.Applies {
			t.Errorf("%s still reports as not applied (%q) while AuditConfig.IssueTypes narrows a run",
				k.Name, k.What)
		}
		if !k.Partial {
			t.Errorf("%s is marked applied in FULL; a boolean flag carries nothing beyond the presence "+
				"of a selection, so claiming full support for it is the mirror-image lie", k.Name)
		}
		if len(k.What) == 0 {
			t.Errorf("%s is partial with no description; the row is where the operator reads what the "+
				"reduced form cannot do", k.Name)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("no row for %s at all", name)
		}
	}
}
