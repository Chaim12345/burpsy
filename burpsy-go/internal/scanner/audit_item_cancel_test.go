package scanner

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// exiu item 1: the audit queue offered no way to stop one item. Burp's audit-item context menu has
// carried Cancel since running-scans/results/audit-items/index.html:102-115, and the only
// alternatives here were to wait for a slow or heavily-guarded URL to exhaust its own bounds, or to
// disable the enclosing live task — which stops every item, including the ones that were fine.

// itemFor reads one row out of the ledger the way any reader would, so the tests below do not depend
// on a private accessor that only they can see. nil when the ledger does not hold it.
func itemFor(l *AuditItemLedger, id core.ExchangeID) *AuditItem {
	// limit 0 means "everything", which is what a two-item ledger wants; Items walks the queue
	// newest-first, so this sees every row regardless of order.
	for _, row := range l.Items(0) {
		if row.ExchangeID == id {
			copied := row
			return &copied
		}
	}
	return nil
}

// A queued item cancels, and says so in the vocabulary rather than being relabelled.
func TestACancelledItemIsCancelledRatherThanBounded(t *testing.T) {
	l := NewAuditItemLedger(10)
	l.Enqueue(1, 5)

	ok, reason := l.Cancel(1)
	if !ok {
		t.Fatalf("Cancel refused a queued item: %s", reason)
	}
	row := itemFor(l, 1)
	if row == nil {
		t.Fatal("the cancelled item is not in the queue at all")
	}
	if row.State != ItemStateCancelled {
		t.Errorf("state = %v, want cancelled", row.State)
	}
	// The distinction this state exists for: bounded says the target was too expensive, cancelled
	// says a person stopped it, and an operator reading one as the other reaches the wrong
	// conclusion about what to do next.
	if row.BurpStatus != "CANCELLED" {
		t.Errorf("burp_status = %q, want CANCELLED; Burp has this constant and folding a cancel into "+
			"LIMIT_EXCEEDED would report a decision as a budget", row.BurpStatus)
	}
	if row.StatusLabel != "Cancelled" {
		t.Errorf("status_label = %q", row.StatusLabel)
	}
	if row.Note == "" {
		t.Error("a cancelled row has no note; the reason is the only thing distinguishing it from a row " +
			"that was merely never reached")
	}
}

// The gate the engine reads. A cancel that only changed the row's display would let the item be
// dispatched anyway, which is the shape of a control that appears to work and does not.
func TestACancelledItemIsRefusedAtTheGate(t *testing.T) {
	l := NewAuditItemLedger(10)
	l.Enqueue(1, 5)
	if l.Cancelled(1) {
		t.Fatal("a fresh queued item reports itself cancelled")
	}
	l.Cancel(1)
	if !l.Cancelled(1) {
		t.Error("the gate does not see the cancel; the item would still be dispatched")
	}
	// And a different item is unaffected — the whole point is stopping ONE.
	l.Enqueue(2, 5)
	if l.Cancelled(2) {
		t.Error("cancelling one item cancelled another")
	}
}

// Work already dispatched cannot be abandoned: the engine has no per-item context, so a cancel
// there would mean a half-sent request counted as complete. The refusal says which state the item
// is in, so the operator can tell a stale row from a live one.
func TestCancellingAnItemThatIsNoLongerQueuedIsRefusedWithItsState(t *testing.T) {
	l := NewAuditItemLedger(10)
	l.Enqueue(1, 5)
	l.Begin(1, nil, AuditConfig{}, 3, 6, nil, nil)

	ok, reason := l.Cancel(1)
	if ok {
		t.Fatal("an item already in flight was cancelled")
	}
	if reason == "" {
		t.Error("the refusal carries no reason; the operator cannot act on a bare failure")
	}
	// A REFUSED cancel must change nothing. Marking an in-flight item cancelled on a refusal would
	// make the gate stop an audit that is already running — the operator asked for something the
	// tool cannot do, and the answer would be a half-stopped item.
	if l.Cancelled(1) {
		t.Error("a refused cancel marked the item cancelled; the gate would now stop an audit that is " +
			"already in flight")
	}
	if row := itemFor(l, 1); row == nil || row.State != ItemStateAuditing {
		t.Errorf("a refused cancel changed the row's state; want auditing, got %+v", row)
	}
}

// "No such item" and "this one already finished" are different answers, and a stale row must be
// distinguishable from a live one.
func TestCancellingAnItemTheQueueDoesNotHoldIsRefusedDifferently(t *testing.T) {
	l := NewAuditItemLedger(10)
	l.Enqueue(1, 5)
	ok, reason := l.Cancel(999)
	if ok {
		t.Fatal("an item that was never queued was cancelled")
	}
	if reason == "" {
		t.Error("no reason given for a missing item")
	}
}

// And a finished item keeps the outcome it recorded. Relabelling it would erase the accounting.
func TestCancellingAFinishedItemLeavesItsOutcomeIntact(t *testing.T) {
	l := NewAuditItemLedger(10)
	l.Enqueue(1, 5)
	l.Begin(1, nil, AuditConfig{}, 3, 6, nil, nil)
	var o AuditOutcome
	o.State = ItemStateAudited
	o.Ran = 6
	l.Resolve(1, nil, o, AuditConfig{}, "")

	row := itemFor(l, 1)
	if row == nil || row.State != ItemStateAudited {
		t.Fatalf("precondition: row = %+v", row)
	}
	if ok, _ := l.Cancel(1); ok {
		t.Error("a finished item was cancelled")
	}
	after := itemFor(l, 1)
	if after == nil {
		t.Fatal("the item vanished from the queue on a refused cancel")
	}
	if after.State != ItemStateAudited || after.Outcome.Ran != 6 {
		t.Errorf("after a refused cancel the row is %v with Ran=%d; a refusal must change nothing",
			after.State, after.Outcome.Ran)
	}
}

// The new state is terminal — work is not outstanding on it — and it is NOT a completed audit, which
// is what makes "how much of this queue finished" keep counting only the work that finished.
func TestCancelledIsTerminalButIsNotACompletedAudit(t *testing.T) {
	if !ItemStateCancelled.IsTerminal() {
		t.Error("cancelled is not terminal; work is not outstanding on it")
	}
	if ItemStateCancelled.CompletedAudit() {
		t.Error("cancelled counts as a completed audit; a queue would report cancelled work as " +
			"finished, which is the claim this state was added to stop making")
	}
	// And it is in the histogram, so an operator sees the cancelled count rather than a row that
	// fell off the end of a known set of states.
	var found bool
	for _, s := range ItemStateAll {
		if s == ItemStateCancelled {
			found = true
		}
	}
	if !found {
		t.Error("ItemStateAll does not include cancelled, so the state histogram silently omits it")
	}
}

// A nil ledger is the "caller wants no queue" case, and it must not panic: a scanner configured
// without a queue has no rows to cancel, and that is not a crash.
func TestCancellingWithNoLedgerIsRefusedRatherThanPanicking(t *testing.T) {
	var l *AuditItemLedger
	if ok, reason := l.Cancel(1); ok {
		t.Error("a nil ledger cancelled an item")
	} else if reason == "" {
		t.Error("no reason given for a nil ledger")
	}
	if l.Cancelled(1) {
		t.Error("a nil ledger reports an item as cancelled")
	}
}
