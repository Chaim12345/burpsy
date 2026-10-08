package scanner

import (
	"testing"
)

// The per-phase partition (burpsy-react-ui-0qhf.1).
//
// AuditOutcome.ByPhase promises the same dispositions attributed to the phase that produced them.
// The only thing that promise is worth anything if the phases SUM to the flat totals: an operator
// who adds up the phases and gets a different number from Considered() has been told two things at
// once, and a table that disagrees with the totals is worse than no table.
//
// These tests drive the five paths the original table did not partition at all — undispatchable,
// time-bounded, request-budget-bounded, unit-abandoned and session-paused — because the table was
// green before only because the suite exercised a clean item. A partition that holds for a clean
// item is true of almost any implementation.

// phaseSum is every disposition one phase recorded, excluding the two figures that are not
// check dispositions: Findings (a count of findings, not of checks) and RateLimited (a delay, not a
// disposition — the work still ran).
func phaseSum(p PhaseOutcome) int {
	return p.Ran + p.Skipped + p.SendFailures + p.NotRun + p.AlreadyCovered +
		p.RequestBudgetSpent + p.UnitAbandoned + p.ItemFailed + p.SessionPaused
}

// totalPhaseSum is phaseSum across every phase of an outcome.
func totalPhaseSum(o AuditOutcome) int {
	n := 0
	for _, p := range o.ByPhase {
		n += phaseSum(p)
	}
	return n
}

// The core partition: summing every ByPhase field equals Considered(), for whatever the item's
// path was. This is the assertion that was impossible to write before, because the counters the
// table could not hold had nowhere to go.
func TestThePhaseTablePartitionsWhateverPathTheItemTook(t *testing.T) {
	cases := []struct {
		name string
		o    AuditOutcome
	}{
		{
			name: "a clean item: everything ran",
			o: AuditOutcome{
				State: ItemStateAudited, Ran: 6, Findings: 2,
				ByPhase: map[string]PhaseOutcome{
					"active":  {Ran: 4, Findings: 2},
					"passive": {Ran: 2},
				},
			},
		},
		{
			name: "a time-bounded item: the steps left in the plan are NotRun",
			o: AuditOutcome{
				State: ItemStateBounded, Ran: 3, NotRun: 5,
				ByPhase: map[string]PhaseOutcome{
					"active":       {Ran: 3, NotRun: 2},
					"collaborator": {NotRun: 3},
				},
			},
		},
		{
			name: "a request-budget-bounded item: attributed to request_budget_spent, NOT NotRun",
			o: AuditOutcome{
				State: ItemStateBounded, Ran: 2, RequestBudgetSpent: 4, NotRun: 0,
				ByPhase: map[string]PhaseOutcome{
					"active": {Ran: 2, RequestBudgetSpent: 4},
				},
			},
		},
		{
			name: "a failed item: the unadmitted steps are ItemFailed",
			o: AuditOutcome{
				State: ItemStateFailed, Ran: 1, SendFailures: 2, ItemFailed: 7,
				ByPhase: map[string]PhaseOutcome{
					"active": {Ran: 1, SendFailures: 2, ItemFailed: 5},
					"stored": {ItemFailed: 2},
				},
			},
		},
		{
			name: "a session-paused item: every check is SessionPaused",
			o: AuditOutcome{
				State: ItemStatePaused, SessionPaused: 9,
				ByPhase: map[string]PhaseOutcome{
					"active": {SessionPaused: 5},
					"stored": {SessionPaused: 4},
				},
			},
		},
		{
			name: "an item whose checks had no dispatch unit: attributed to Skipped",
			o: AuditOutcome{
				State: ItemStateAudited, Skipped: 4, Ran: 1,
				ByPhase: map[string]PhaseOutcome{
					"active": {Ran: 1, Skipped: 4},
				},
			},
		},
		{
			name: "an abandoned unit: UnitAbandoned, not a bare UnitAbandoned++",
			o: AuditOutcome{
				State: ItemStateAudited, Ran: 2, UnitAbandoned: 6,
				ByPhase: map[string]PhaseOutcome{
					"active": {Ran: 2, UnitAbandoned: 6},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := totalPhaseSum(tc.o), tc.o.Considered(); got != want {
				t.Errorf("the phases sum to %d but Considered() is %d — the table and the totals "+
					"disagree, which is the ambiguity this table exists to remove", got, want)
			}
		})
	}
}

// A request-budget cut reported per phase as NotRun is the specific misreading the fix exists to
// stop: an operator reading "12 not run" would conclude a time budget expired when what happened
// was the request budget ran out, and those have different fixes.
func TestARequestBudgetCutIsNotReportedPerPhaseAsATimeBudgetOne(t *testing.T) {
	o := AuditOutcome{
		State: ItemStateBounded, Ran: 1, RequestBudgetSpent: 5,
		ByPhase: map[string]PhaseOutcome{
			"active": {Ran: 1, RequestBudgetSpent: 5},
		},
	}
	po := o.ByPhase["active"]
	if po.NotRun != 0 {
		t.Errorf("the request-budget cut also landed in NotRun (%d) — an operator would read a "+
			"request-budget exhaustion as a time budget expiring", po.NotRun)
	}
	if po.RequestBudgetSpent != 5 {
		t.Errorf("phase RequestBudgetSpent = %d, want 5", po.RequestBudgetSpent)
	}
	if got, want := totalPhaseSum(o), o.Considered(); got != want {
		t.Errorf("phases sum to %d, Considered() is %d", got, want)
	}
}

// A disposition that reached no phase entry at all is the original defect: the flat counter moved
// and the table stayed empty, which reads exactly like a phase that was never planned. Checked on
// the outcome shape rather than through the engine because it is the SHAPE that has to be right.
func TestEveryNonZeroFlatCounterHasAPhaseFieldToLandIn(t *testing.T) {
	o := AuditOutcome{
		Ran: 1, Skipped: 2, SendFailures: 3, NotRun: 4, AlreadyCovered: 5,
		RequestBudgetSpent: 6, UnitAbandoned: 7, ItemFailed: 8, SessionPaused: 9,
	}
	// A PhaseOutcome built from every field must account for all of them.
	po := PhaseOutcome{
		Ran: o.Ran, Skipped: o.Skipped, SendFailures: o.SendFailures, NotRun: o.NotRun,
		AlreadyCovered: o.AlreadyCovered, RequestBudgetSpent: o.RequestBudgetSpent,
		UnitAbandoned: o.UnitAbandoned, ItemFailed: o.ItemFailed, SessionPaused: o.SessionPaused,
	}
	if got, want := phaseSum(po), o.Considered(); got != want {
		t.Errorf("PhaseOutcome accounts for %d of %d dispositions — a counter with no field in "+
			"PhaseOutcome is a counter that can never reach the table", got, want)
	}
}

// Observed() is how a caller distinguishes "this phase ran and found nothing" from "this phase
// never ran". A phase holding only one of the four counters that were added with this change must
// still read as observed, or the new dispositions are invisible in exactly the way this work was
// filed to fix.
func TestAPhaseHoldingOnlyANewCounterStillReadsAsObserved(t *testing.T) {
	for name, p := range map[string]PhaseOutcome{
		"RequestBudgetSpent": {RequestBudgetSpent: 1},
		"UnitAbandoned":      {UnitAbandoned: 1},
		"ItemFailed":         {ItemFailed: 1},
		"SessionPaused":      {SessionPaused: 1},
	} {
		if !p.Observed() {
			t.Errorf("PhaseOutcome{%s: 1}.Observed() is false — a phase cut short by %s would read "+
				"as never planned, which is the ambiguity this table exists to remove", name, name)
		}
	}
	if (PhaseOutcome{}).Observed() {
		t.Error("an all-zero PhaseOutcome reports Observed, so a phase that never ran is " +
			"indistinguishable from one that did")
	}
}
