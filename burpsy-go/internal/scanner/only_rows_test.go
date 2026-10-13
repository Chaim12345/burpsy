package scanner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// only_rows (only_rows.go): an audit restricted to named rows runs only the checks that can report
// them, sends nothing for the rest, and says which checks it did not run and why.

const onlyRowsXSS = "Cross-site scripting (reflected)"

// onlyRowsAudit audits one seeded vulnapp endpoint with the runtime corpus's (non-DOM) configuration
// narrowed to rows, through a scanner of its own over the target's store.
func onlyRowsAudit(t *testing.T, ct *checkTarget, path string, rows []string) (AuditOutcome, map[string]bool) {
	t.Helper()
	cfg := runtimeScanConfig()
	cfg.OnlyRows = rows
	scan := NewActiveScanner(ct.rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	o, fs := scan.AuditWithin(ctx, ct.rt.exchanges[path], scan.AuditConfig())
	if o.Error != "" {
		t.Fatalf("audit of %s refused: %s", path, o.Error)
	}
	got := map[string]bool{}
	for _, f := range fs {
		got[f.Name] = true
	}
	return o, got
}

func TestOnlyRowsRunsOnlyTheChecksThatCanReportTheListedRow(t *testing.T) {
	const path = "/search?q=seed"
	ct := vulnappTarget(t, runtimeScanConfig(), path)

	// The unfiltered audit: the endpoint is vulnerable to X (reflected XSS) and reports at least one
	// other row Y. Both directions of the test depend on that, so it is asserted, not assumed.
	full, fullRows := onlyRowsAudit(t, ct, path, nil)
	if !fullRows[onlyRowsXSS] {
		t.Fatalf("the unfiltered audit of %s did not report %q (got %v); the fixture no longer exercises X", path, onlyRowsXSS, fullRows)
	}
	var others []string
	for r := range fullRows {
		if r != onlyRowsXSS {
			others = append(others, r)
		}
	}
	if len(others) == 0 {
		t.Fatalf("the unfiltered audit of %s reported only %q; the test needs a second row Y to filter out", path, onlyRowsXSS)
	}
	if len(full.RowsNotSelected) != 0 || full.FindingsNotSelected != 0 {
		t.Fatalf("an empty only_rows skipped %d check(s) and dropped %d finding(s); empty must change nothing",
			len(full.RowsNotSelected), full.FindingsNotSelected)
	}

	only, onlyRows := onlyRowsAudit(t, ct, path, []string{onlyRowsXSS})
	if !onlyRows[onlyRowsXSS] {
		t.Fatalf("only_rows=[%q] did not report it (got %v)", onlyRowsXSS, onlyRows)
	}
	for r := range onlyRows {
		if r != onlyRowsXSS {
			t.Errorf("only_rows=[%q] reported %q", onlyRowsXSS, r)
		}
	}
	// The admission filter, measured by what went on the wire: the checks behind every other row sent
	// nothing, so the narrowed audit sends strictly fewer probes than the full one.
	if only.RequestsSent == 0 || only.RequestsSent >= full.RequestsSent {
		t.Fatalf("only_rows=[%q] sent %d probe(s), the unfiltered audit %d: the other rows' checks were not kept from sending",
			onlyRowsXSS, only.RequestsSent, full.RequestsSent)
	}
	// Every check behind each other row Y is listed as not selected, with its reason, and counted
	// Skipped — never as having run clean.
	skipped := map[string]string{}
	for _, s := range only.RowsNotSelected {
		skipped[s.Check] = s.Reason
	}
	for _, y := range others {
		var behind []string
		for _, c := range activeCheckSet {
			for _, r := range c.rows {
				if r == y {
					behind = append(behind, c.name)
				}
			}
		}
		if len(behind) == 0 {
			t.Errorf("row %q was reported but no check declares it; under a selection of it nothing could run", y)
		}
		for _, name := range behind {
			why, ok := skipped[name]
			if !ok {
				t.Errorf("check %q (row %q) is not listed as not selected", name, y)
				continue
			}
			if !strings.Contains(why, "only_rows") {
				t.Errorf("check %q is skipped without the only_rows reason: %q", name, why)
			}
		}
	}
	if _, ok := skipped[onlyRowsXSS]; ok {
		t.Errorf("the check for the listed row %q was itself skipped", onlyRowsXSS)
	}
	if only.Skipped < len(only.RowsNotSelected) {
		t.Errorf("Skipped=%d does not count the %d not-selected checks", only.Skipped, len(only.RowsNotSelected))
	}
	if only.Considered() != full.Considered() {
		t.Errorf("Considered()=%d under the selection, %d without it: the not-selected checks fell out of the partition",
			only.Considered(), full.Considered())
	}
	t.Logf("probes: %d unfiltered, %d with only_rows=[%q]; %d check(s) not selected", full.RequestsSent, only.RequestsSent, onlyRowsXSS, len(only.RowsNotSelected))
}

func TestOnlyRowsMarksEveryCheckThatCannotReportAListedRow(t *testing.T) {
	set := []activeCheck{
		{name: "A", rows: []string{"A", "A rider"}},
		{name: "B", rows: []string{"B"}},
		{name: "corpus check"}, // declares no row
	}
	if got := markRowSelection(set, nil); &got[0] != &set[0] {
		t.Fatal("an empty selection must return the set unchanged")
	}
	got := markRowSelection(set, []string{"A rider"})
	if got[0].rowSkip != "" {
		t.Errorf("A rides %q and must be admitted: %q", "A rider", got[0].rowSkip)
	}
	if !strings.Contains(got[1].rowSkip, "lists none of the rows") {
		t.Errorf("B must be skipped with the reason: %q", got[1].rowSkip)
	}
	if !strings.Contains(got[2].rowSkip, "declares no issue row") {
		t.Errorf("a check with no declared row must be skipped, saying so: %q", got[2].rowSkip)
	}
	if set[1].rowSkip != "" {
		t.Error("markRowSelection modified its input")
	}
}

func TestEveryRegisteredCheckDeclaresItsOwnRowAndItsRiders(t *testing.T) {
	riders := map[string][]string{}
	for _, r := range BurpsyNativeRows() {
		riders[r.Rides] = append(riders[r.Rides], r.Name)
	}
	for _, c := range activeCheckSet {
		if len(c.rows) == 0 || c.rows[0] != c.name {
			t.Errorf("check %q declares %v; its own row must come first", c.name, c.rows)
			continue
		}
		want := append(append([]string{}, riders[c.name]...), alsoReports[c.name]...)
		if strings.Join(c.rows[1:], "|") != strings.Join(want, "|") {
			t.Errorf("check %q declares %v beside its own row, BurpsyNativeRows and alsoReports say %v", c.name, c.rows[1:], want)
		}
	}
	registered := map[string]bool{}
	for _, c := range activeCheckSet {
		registered[c.name] = true
	}
	for check, rows := range alsoReports {
		if !registered[check] {
			t.Errorf("alsoReports names %q, which is not a registered check", check)
		}
		for _, r := range rows {
			if _, ok := ByName(r); !ok {
				t.Errorf("alsoReports[%q] names %q, which is not a catalogue row", check, r)
			}
		}
	}
}

func TestUnknownRowsNamesOnlyTheUnknown(t *testing.T) {
	got := UnknownRows([]string{onlyRowsXSS, "Nope", IssueLoginRateLimitMissing, "Nope", "Also nope"})
	if strings.Join(got, "|") != "Also nope|Nope" {
		t.Fatalf("UnknownRows = %v", got)
	}
	b, _ := json.Marshal(AuditOutcome{})
	if !strings.Contains(string(b), `"rows_not_selected":[]`) {
		t.Errorf("rows_not_selected must marshal as []: %s", b)
	}
}

// An admitted check that reports a row the selection does not list has that finding dropped and
// counted. "Broken access control" carries the login rate-limit row as a rider, so selecting the
// rider admits the check and reports it, while selecting only the check's own row drops it.
func TestOnlyRowsDropsAnAdmittedChecksUnlistedRows(t *testing.T) {
	const path = "/auth/login"
	ct := vulnappTarget(t, runtimeScanConfig(), path)

	_, rider := onlyRowsAudit(t, ct, path, []string{IssueLoginRateLimitMissing})
	if !rider[IssueLoginRateLimitMissing] {
		t.Fatalf("only_rows=[%q] did not report it (got %v); the fixture no longer exercises the rider", IssueLoginRateLimitMissing, rider)
	}
	o, own := onlyRowsAudit(t, ct, path, []string{"Broken access control"})
	if own[IssueLoginRateLimitMissing] {
		t.Errorf("only_rows=[Broken access control] reported the unlisted rider row %q", IssueLoginRateLimitMissing)
	}
	if o.FindingsNotSelected == 0 {
		t.Errorf("the rider finding was not counted as dropped: %s", o.Summary())
	}
	if o.RequestsSent == 0 {
		t.Error("the admitted check sent nothing")
	}
}

type onlyRowsSource struct{ rows []string }

func (s onlyRowsSource) AuditConfig() AuditConfig   { return DefaultAuditConfig() }
func (s onlyRowsSource) ConfigSnapshot() ScanConfig { return ScanConfig{OnlyRows: s.rows} }

// Capture-time passive scanning reports only the listed rows: the static-DOM row survives a selection
// of it, and the built-in passive finding outside it is dropped.
func TestOnlyRowsFiltersCaptureTimePassiveFindings(t *testing.T) {
	const dom = "Cross-site scripting (DOM-based)"
	const passive = "Cookie Missing HttpOnly Flag"
	if base := capturedNames(t, onlyRowsSource{}); !has(base, dom) || !has(base, passive) {
		t.Fatalf("control: an empty only_rows raised %v, want both", base)
	}
	got := capturedNames(t, onlyRowsSource{rows: []string{dom}})
	if strings.Join(got, "|") != dom {
		t.Fatalf("only_rows=[%q] at capture raised %v", dom, got)
	}
}
