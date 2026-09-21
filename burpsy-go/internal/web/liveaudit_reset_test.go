package web

// The ledger reset's honest accounting (burpsy-react-ui-m9e0): a reset at the 20k-unit cap
// makes every already-covered collapse re-dispatch once more, and before this the cost was
// a single "resets" count hiding both the width and the payment. The tests pin:
//
//   - the reset records the dead ledger's WIDTH (its admitted count at the drop) — the
//     stated cost, visible before any re-dispatch happens;
//   - the re-walk's measurement: each pair the fresh ledger admits after a reset decrements
//     the remaining width, and the completion is observable (remaining returns to zero);
//   - the payment accumulates ACROSS resets (reAdmitted total), so a completed re-walk's
//     cost stays visible after "remaining" reads zero;
//   - no re-walk in progress: recordReAdmission is inert (no false completions, no counting).
import (
	"fmt"
	"testing"

	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

func TestALedgerResetRecordsItsReWalkWidth(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	la := s.liveAudit

	la.beginResetReWalk(18_000)
	remaining, admitted := la.ResetReWalk()
	if remaining != 18_000 {
		t.Fatalf("remaining = %d immediately after the reset, want the full width 18000 — the cost must be stated before any payment", remaining)
	}
	if admitted != 0 {
		t.Fatalf("admitted = %d before any re-admission, want 0", admitted)
	}
}

func TestTheReWalkCountsDownToCompletion(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	la := s.liveAudit
	la.beginResetReWalk(3)

	if done := la.recordReAdmission(); done {
		t.Fatal("the first of three re-admissions reported the re-walk done")
	}
	if _, admitted := la.ResetReWalk(); admitted != 1 {
		t.Fatalf("admitted = %d after one re-admission, want 1", admitted)
	}
	la.recordReAdmission()
	if done := la.recordReAdmission(); !done {
		t.Fatal("the third of three re-admissions did not complete the re-walk")
	}
	remaining, admitted := la.ResetReWalk()
	if remaining != 0 {
		t.Fatalf("remaining = %d after completion, want 0", remaining)
	}
	if admitted != 3 {
		t.Fatalf("admitted = %d after completion, want 3 — the completed re-walk's cost must stay visible", admitted)
	}
	// Past completion: further admissions are inert (no new re-walk began).
	if done := la.recordReAdmission(); done {
		t.Fatal("an admission past completion reported a second done — a stale width never completes twice")
	}
	_, admitted = la.ResetReWalk()
	if admitted != 3 {
		t.Fatalf("an inert admission moved the total: %d, want 3", admitted)
	}
}

func TestTheReWalkTotalAccumulatesAcrossResets(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	la := s.liveAudit
	la.beginResetReWalk(2)
	la.recordReAdmission()
	la.recordReAdmission() // first re-walk completes
	la.beginResetReWalk(1)
	la.recordReAdmission() // second completes
	_, admitted := la.ResetReWalk()
	if admitted != 3 {
		t.Fatalf("the cross-reset total = %d, want 3 — each reset's payment is part of the honest number", admitted)
	}
}

func TestNoReWalkInFlightMeansAdmissionsAreInert(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	la := s.liveAudit
	if done := la.recordReAdmission(); done {
		t.Fatal("an admission with no re-walk in progress reported done")
	}
	remaining, admitted := la.ResetReWalk()
	if remaining != 0 || admitted != 0 {
		t.Fatalf("remaining=%d admitted=%d, want 0/0 with no reset ever recorded", remaining, admitted)
	}
}

func TestTheAuditLedgerResetDrivesTheReWalkNumbers(t *testing.T) {
	// The end-to-end drive: a ledger past the cap resets through auditLedger, and the
	// re-walk's width is the DEAD ledger's admitted count — the number the event and the
	// pane will state.
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	run := &liveAuditRun{}
	// Grow the run's ledger past the cap with admits.
	ledger := scanner.NewAuditLedger()
	for i := 0; i <= liveAuditLedgerUnitCap; i++ {
		ledger.Admit(fmt.Sprintf("unit-%d", i), 0)
	}
	run.ledger = ledger

	log := dash.NewEventLog()
	run.auditLedger(s.liveAudit, log, nil)
	_ = log

	if got := s.liveAudit.LedgerResets(); got != 1 {
		t.Fatalf("ledgerResets = %d, want 1", got)
	}
	remaining, _ := s.liveAudit.ResetReWalk()
	if remaining != liveAuditLedgerUnitCap+1 {
		t.Fatalf("the re-walk width = %d, want the dead ledger's admitted count %d", remaining, liveAuditLedgerUnitCap+1)
	}
}
