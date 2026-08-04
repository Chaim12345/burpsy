package scanner

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// coverageWith builds a report by hand, so a projection can be tested against a known histogram
// rather than against whatever a live scan happened to produce.
func coverageWith(checks []CheckCoverage, skips map[ScanSkip]uint64) CoverageReport {
	out := CoverageReport{Checks: checks}
	for _, s := range ScanSkipAll {
		out.Skips = append(out.Skips, SkipCount{Reason: s.Explanation(), Count: skips[s]})
	}
	return out
}

// The distinction the whole feature is about, at the passive level: a check that ran and found nothing
// is not a check that never ran.
func TestCoverageBreakdownSeparatesRanCleanFromNeverRan(t *testing.T) {
	allClean := coverageWith([]CheckCoverage{
		{Name: "a", Ran: 50},
		{Name: "b", Ran: 50},
	}, nil)
	b := allClean.Breakdown()
	if b.Found != 0 {
		t.Errorf("found = %d, want 0", b.Found)
	}
	if !b.Complete() {
		t.Errorf("a set where every check ran clean reports incomplete (%+v); looked everywhere, found nothing is a complete answer", b)
	}

	oneNeverRan := coverageWith([]CheckCoverage{
		{Name: "a", Ran: 50},
		{Name: "b"},
	}, nil)
	b = oneNeverRan.Breakdown()
	if b.Skipped != 1 {
		t.Errorf("skipped = %d, want 1 for the check that was never dispatched", b.Skipped)
	}
	if b.Complete() {
		t.Error("a set with a never-dispatched check reports a complete count")
	}
}

// Erroring beats a clean run, exactly as CheckCoverage.State decides it: a check that errored once and
// ran cleanly ninety-nine times is not a trustworthy negative.
func TestCoverageBreakdownCountsAPartlyBrokenCheckAsErrored(t *testing.T) {
	b := coverageWith([]CheckCoverage{
		{Name: "flaky", Ran: 99, Findings: 2, Errored: 1, LastError: "invalid regex construct"},
	}, nil).Breakdown()
	if b.Errored != 1 {
		t.Errorf("errored = %d, want 1", b.Errored)
	}
	// The findings from a check that also errored are not counted as found: its verdict is not
	// evidence, which is the same call CoverageState makes.
	if b.Found != 0 {
		t.Errorf("found = %d, want 0 — a partly-broken check's findings are not a clean result", b.Found)
	}
	if b.Complete() {
		t.Error("a set with an errored check reports complete")
	}
}

// Policy refusals are gated; missing inputs are skipped. The two are different things to fix, and
// folding them together is how "the host is out of scope" starts reading like a bug.
func TestCoverageBreakdownGatesPolicyRefusalsAndSkipsMissingInputs(t *testing.T) {
	b := coverageWith([]CheckCoverage{{Name: "a", Ran: 1}}, map[ScanSkip]uint64{
		ScanSkipOutOfScope:       7,
		ScanSkipNoChecksLoaded:   1,
		ScanSkipResponseNotFound: 3,
		ScanSkipExchangeNotFound: 2,
	}).Breakdown()
	if b.Gated != 8 {
		t.Errorf("gated = %d, want 8 (7 out of scope + 1 no checks loaded)", b.Gated)
	}
	if b.Skipped != 5 {
		t.Errorf("skipped = %d, want 5 (3 missing responses + 2 missing exchanges)", b.Skipped)
	}
}

// Every non-zero bucket must be nameable, or the dashboard shows an unexplained gap.
func TestCoverageBreakdownReasonsExplainEveryCaveat(t *testing.T) {
	report := coverageWith([]CheckCoverage{
		{Name: "never"},
		{Name: "broken", Errored: 4, LastError: "unsupported lookbehind"},
	}, map[ScanSkip]uint64{ScanSkipOutOfScope: 2})

	b := report.Breakdown()
	reasons := report.BreakdownReasons()
	if b.Complete() {
		t.Fatal("test fixture is complete; nothing to explain")
	}
	if len(reasons) == 0 {
		t.Fatal("no reasons for a non-complete breakdown")
	}
	byBucket := map[dash.Bucket]uint64{}
	joined := ""
	for _, r := range reasons {
		byBucket[r.Bucket] += r.Count
		joined += r.Detail + "\n"
	}
	for _, bucket := range []dash.Bucket{dash.BucketSkipped, dash.BucketErrored, dash.BucketGated} {
		if byBucket[bucket] == 0 {
			t.Errorf("no reason explains the %s bucket; reasons were %+v", bucket, reasons)
		}
	}
	// The last error travels with the count: "4 checks errored" is not actionable on its own.
	if !strings.Contains(joined, "unsupported lookbehind") {
		t.Errorf("reasons do not carry the last observed error:\n%s", joined)
	}
}

// Skip counts are matched by reason rather than by position, so a report that arrived over the wire
// or from a reordered snapshot cannot have one reason's count attributed to another.
func TestCoverageBreakdownMatchesSkipReasonsByNameNotPosition(t *testing.T) {
	report := CoverageReport{
		Checks: []CheckCoverage{{Name: "a", Ran: 1}},
		// Deliberately reversed relative to ScanSkipAll.
		Skips: []SkipCount{
			{Reason: ScanSkipResponseNotFound.Explanation(), Count: 4},
			{Reason: ScanSkipOutOfScope.Explanation(), Count: 9},
		},
	}
	b := report.Breakdown()
	if b.Gated != 9 {
		t.Errorf("gated = %d, want 9 (the out-of-scope count, wherever it sat in the slice)", b.Gated)
	}
	if b.Skipped != 4 {
		t.Errorf("skipped = %d, want 4", b.Skipped)
	}
}

// ---- audit outcomes ----------------------------------------------------------------------------

// Scope collapse is work that ran, not work that was skipped. Counting it as a caveat would make the
// audit engine's largest saving look like a coverage regression — the argument ItemState.CompletedAudit
// already makes, held to here.
func TestAuditBreakdownDoesNotTreatScopeCollapseAsACaveat(t *testing.T) {
	o := AuditOutcome{State: ItemStateAudited, Ran: 4, Findings: 1, AlreadyCovered: 96}
	b := o.Breakdown()
	if b.Found != 1 {
		t.Errorf("found = %d, want 1", b.Found)
	}
	if !b.Complete() {
		t.Errorf("an item whose checks collapsed onto an earlier unit reports incomplete (%+v)", b)
	}
	for _, r := range o.BreakdownReasons() {
		if strings.Contains(r.Detail, "already") {
			t.Errorf("scope collapse is reported as a caveat: %+v", r)
		}
	}
}

// Every admission-side refusal is gated, and a bounded item is therefore never complete.
func TestAuditBreakdownGatesEveryAdmissionRefusal(t *testing.T) {
	o := AuditOutcome{
		State:              ItemStateBounded,
		Ran:                2,
		Findings:           1,
		NotRun:             3,
		RequestBudgetSpent: 4,
		UnitAbandoned:      5,
		ItemFailed:         6,
		SessionPaused:      7,
		RequestsRefused:    8,
		TimedOut:           true,
	}
	b := o.Breakdown()
	if b.Gated != 3+4+5+6+7+8 {
		t.Errorf("gated = %d, want 33 (every admission refusal plus the scope-refused probes)", b.Gated)
	}
	if b.Complete() {
		t.Error("a bounded item reports a complete count")
	}
	if len(o.BreakdownReasons()) == 0 {
		t.Error("no reasons for a bounded item")
	}
}

// A check with no implementation is skipped; a probe that could not be sent errored. Different things
// to fix, so they stay in different buckets.
func TestAuditBreakdownSeparatesUnimplementedFromUnsendable(t *testing.T) {
	b := AuditOutcome{State: ItemStateAudited, Ran: 1, Skipped: 2, SendFailures: 3, FindingsDropped: 1}.Breakdown()
	if b.Skipped != 2 {
		t.Errorf("skipped = %d, want 2 (the unimplemented checks)", b.Skipped)
	}
	if b.Errored != 4 {
		t.Errorf("errored = %d, want 4 (3 send failures + 1 finding dropped for want of a response)", b.Errored)
	}
}

// An item refused before any dispatch has every counter at zero, which would project to a complete,
// empty breakdown — "audited, clean" for a host that was never touched. That single case is the one
// the projection handles explicitly.
func TestAuditBreakdownOnAnItemRefusedBeforeDispatchIsGated(t *testing.T) {
	o := AuditOutcome{State: ItemStateOutOfScope, Error: "the host is outside the engagement scope"}
	b := o.Breakdown()
	if b.Complete() {
		t.Fatal("an item refused before any dispatch reports a complete count; that is 'never looked' reading as 'found nothing'")
	}
	if b.Gated != 1 {
		t.Errorf("gated = %d, want 1", b.Gated)
	}
	reasons := o.BreakdownReasons()
	if len(reasons) != 1 || !strings.Contains(reasons[0].Detail, "scope") {
		t.Errorf("reasons = %+v, want the refusal named", reasons)
	}
}

// ---- session outcomes ---------------------------------------------------------------------------

// A sweep over many exchanges must report one aggregated reason per cause, not one per item: 200
// identical lines is a histogram nobody reads.
func TestSessionBreakdownAggregatesIdenticalReasonsOnce(t *testing.T) {
	item := AuditOutcome{State: ItemStateBounded, Ran: 1, NotRun: 3}
	o := &SessionOutcome{
		Items: []ItemOutcome{
			{ExchangeID: 1, Outcome: item},
			{ExchangeID: 2, Outcome: item},
			{ExchangeID: 3, Outcome: item},
		},
		Findings: 5,
	}
	b := o.Breakdown()
	if b.Found != 5 {
		t.Errorf("found = %d, want the session's own total of 5", b.Found)
	}
	if b.Gated != 9 {
		t.Errorf("gated = %d, want 9 (3 items x 3 never attempted)", b.Gated)
	}
	reasons := o.BreakdownReasons()
	if len(reasons) != 1 {
		t.Fatalf("reasons = %+v, want one aggregated line", reasons)
	}
	if reasons[0].Count != 9 {
		t.Errorf("aggregated count = %d, want 9", reasons[0].Count)
	}
}

// The session-level flags are facts no individual item states. A run the failure breaker paused must
// say so, or "these items happened to be bounded" replaces "this host stopped answering".
func TestSessionBreakdownReasonsNameThePausedAndTimedOutFlags(t *testing.T) {
	o := &SessionOutcome{
		Items:       []ItemOutcome{{ExchangeID: 1, Outcome: AuditOutcome{State: ItemStatePaused, SessionPaused: 4}}},
		FailedItems: 2,
		Paused:      true,
		TimedOut:    true,
	}
	joined := ""
	for _, r := range o.BreakdownReasons() {
		joined += r.Detail + "\n"
	}
	for _, want := range []string{"failure breaker", "wall-clock budget"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reasons do not mention %q:\n%s", want, joined)
		}
	}
	if o.Breakdown().Complete() {
		t.Error("a paused, timed-out session reports a complete count")
	}
}

// A nil session projects to the empty breakdown rather than panicking: the audit paths hand back a
// pointer, and a nil one is a run that never started.
func TestSessionBreakdownOnNilIsEmpty(t *testing.T) {
	var o *SessionOutcome
	if b := o.Breakdown(); b != (dash.Breakdown{}) {
		t.Errorf("nil session breakdown = %+v, want the zero value", b)
	}
	if r := o.BreakdownReasons(); r != nil {
		t.Errorf("nil session reasons = %+v, want none", r)
	}
}

// ---- the shared admission ledger (AuditConfig.Ledger) -------------------------------------------

// A ledger supplied by the caller must survive across AuditSession calls, so a repeating caller keeps
// its scope collapse.
//
// This is the live sweep's problem, at the level it can be tested without a network: the sweep calls
// AuditSession every three seconds forever, and with a per-run ledger every `given host` and
// `given path` check re-dispatches on every tick for the life of the process.
func TestSuppliedLedgerSurvivesAcrossAuditSessions(t *testing.T) {
	shared := NewAuditLedger()
	if !shared.Admit("host:shop.test", 3) {
		t.Fatal("a fresh ledger refused a pair nothing had run")
	}
	if shared.Admit("host:shop.test", 3) {
		t.Error("the same (unit, check) pair was admitted twice by one ledger")
	}

	cfg := DefaultAuditConfig()
	cfg.Ledger = shared
	first := newAuditRun(cfg)
	second := newAuditRun(cfg)
	if first.ledger != shared || second.ledger != shared {
		t.Fatal("newAuditRun ignored the supplied ledger; every run would reset scope collapse")
	}
	// The pair admitted above is still refused by a *later* run — which is the whole property.
	if second.ledger.Admit("host:shop.test", 3) {
		t.Error("a later run re-admitted a pair an earlier one had already run; the ledger did not outlive the run")
	}
}

// With no ledger supplied — the default, and right for a one-shot audit — each run gets a fresh one, so
// a caller asking for these exchanges to be audited is not refused by something an earlier call did.
func TestUnsuppliedLedgerIsFreshPerRun(t *testing.T) {
	cfg := DefaultAuditConfig()
	if cfg.Ledger != nil {
		t.Fatal("DefaultAuditConfig ships a shared ledger; a one-shot audit must not inherit another run's collapse")
	}
	first := newAuditRun(cfg)
	first.ledger.Admit("host:shop.test", 3)
	second := newAuditRun(cfg)
	if second.ledger == first.ledger {
		t.Fatal("two runs shared a ledger with none supplied")
	}
	if !second.ledger.Admit("host:shop.test", 3) {
		t.Error("a fresh run refused work an unrelated earlier run had done")
	}
}

// AlreadyCovered is reported on its own, apart from NotAdmitted and apart from every caveat bucket,
// because scope collapse is work that ran. A caller sharing a ledger needs to be able to show the
// saving is happening rather than infer it from a request count.
func TestSessionAlreadyCoveredIsReportedButIsNotACaveat(t *testing.T) {
	o := &SessionOutcome{
		Items: []ItemOutcome{
			{ExchangeID: 1, Outcome: AuditOutcome{State: ItemStateAudited, Ran: 4, AlreadyCovered: 100}},
			{ExchangeID: 2, Outcome: AuditOutcome{State: ItemStateAudited, AlreadyCovered: 104}},
		},
		Findings: 1,
	}
	if got := o.AlreadyCovered(); got != 204 {
		t.Errorf("AlreadyCovered() = %d, want 204", got)
	}
	// NotAdmitted *does* count collapse, and that is correct for what it measures: the engine's own
	// admission accounting, where a refused pair is a pair that did not pass the gate. Breakdown
	// deliberately disagrees, because it measures something else — whether the operator's count is a
	// floor. Pinned here because the disagreement looks like a bug until you see both definitions, and
	// a future reader "fixing" one to match the other would break whichever requirement it served.
	if o.NotAdmitted() != 204 {
		t.Errorf("NotAdmitted() = %d, want 204: the engine counts a collapsed pair as one it did not admit", o.NotAdmitted())
	}
	b := o.Breakdown()
	if !b.Complete() {
		t.Errorf("a session whose saving was collapse reports incomplete (%+v); that would make the engine's largest saving look like a coverage regression", b)
	}
	var nilOutcome *SessionOutcome
	if nilOutcome.AlreadyCovered() != 0 {
		t.Error("AlreadyCovered on a nil session was not 0")
	}
}
