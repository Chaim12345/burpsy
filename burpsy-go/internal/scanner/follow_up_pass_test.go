package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// burpsy-react-ui-5efx: Burp re-passes a FAILED audit item, bounded by
// scanner/error_handling/number_of_follow_up_passes (Zxdx.java:27,36; shipped default 1 at
// Zp0d.java:120-121) through a re-pass driver (Zeeu.java:119,239-241, Zfkz.java:57,69-81). burpsy
// reported the key unapplied and the dispatch loop BROKE on a failed item (audit_engine.go:1339), so
// a failure was final.
//
// A transient failure — a timeout, a 502 from a backend mid-restart, a dropped connection —
// permanently lost that item's coverage and was indistinguishable from a check that found nothing.
//
// Two steps were needed, in this order, and the order is the whole design: (1) the re-run NARROWING,
// so a pass does not re-send checks that already failed for a reason the response will not change;
// (2) the pass loop itself. Step 2 without step 1 multiplies traffic against a broken target by the
// number of passes, which is why burpsy's Admit — a single bit with no failure memory — was the gap.

// The narrowest possible proof that the loop runs at all: the config resolves, and a zero means "no
// passes", which is the operator's explicit choice rather than the default.
func TestFollowUpPassesResolvesWithTheDocumentedDefault(t *testing.T) {
	if got := (AuditConfig{}).followUpPasses(); got != DefaultFollowUpPasses {
		t.Errorf("unset FollowUpPasses resolved to %d, want the shipped default %d; an unset key that "+
			"resolves to 0 would read as \"no retries\" and quietly disable the feature",
			got, DefaultFollowUpPasses)
	}
	if DefaultFollowUpPasses != 1 {
		t.Errorf("DefaultFollowUpPasses = %d, want 1 (Zp0d.java:120-121 ships 1); a different default "+
			"changes the traffic every audit costs", DefaultFollowUpPasses)
	}
	// And zero is a real choice, not "unset".
	if got := (AuditConfig{FollowUpPasses: SomeUint32(0)}).followUpPasses(); got != 0 {
		t.Errorf("an explicit 0 resolved to %d; an operator who asked for no retries must get none", got)
	}
	if got := (AuditConfig{FollowUpPasses: SomeUint32(3)}).followUpPasses(); got != 3 {
		t.Errorf("an explicit 3 resolved to %d", got)
	}
}

// The narrowing: a check that already failed in a unit is not tried again, so a pass is bounded
// rather than a second full dispatch.
func TestTheBreakerRemembersWhichCheckFailedInWhichUnit(t *testing.T) {
	b := newItemBreaker(AuditConfig{ConsecutiveCheckFailuresToAbandonUnit: 2, ConsecutiveUnitFailuresToFailItem: 1})

	if b.AlreadyFailed("unit-a", "sqli") {
		t.Error("a fresh breaker reports a failure that never happened")
	}
	b.checkFailed("unit-a", "sqli")
	if !b.AlreadyFailed("unit-a", "sqli") {
		t.Error("the failure was not remembered; a follow-up pass would re-send a check whose failure " +
			"the response will not change")
	}
	// Scoped to the check, and to the unit: the same check in another unit is untried, and another
	// check in the same unit is untried.
	if b.AlreadyFailed("unit-a", "xss") {
		t.Error("a DIFFERENT check in the same unit reported as already failed")
	}
	if b.AlreadyFailed("unit-b", "sqli") {
		t.Error("the same check in a different dispatch unit reported as already failed; Burp's predicate " +
			"is per insertion point for the same reason")
	}
	// And the count Burp's predicate reads.
	if got := b.FailedCheckCount("unit-a"); got != 1 {
		t.Errorf("FailedCheckCount(unit-a) = %d, want 1", got)
	}
	if got := b.FailedCheckCount("unit-b"); got != 0 {
		t.Errorf("FailedCheckCount(unit-b) = %d, want 0", got)
	}
	// A repeated failure is still one check, not two.
	b.checkFailed("unit-a", "sqli")
	if got := b.FailedCheckCount("unit-a"); got != 1 {
		t.Errorf("FailedCheckCount = %d after a repeat, want 1; the predicate counts checks that failed, "+
			"not attempts", got)
	}
}

// A pass RESETS the consecutive counters so it is measured against the same thresholds, while
// KEEPING the memory — the memory is what narrows the pass, so clearing it would make every pass a
// full re-dispatch.
func TestAPassResetsTheThresholdsButKeepsTheMemory(t *testing.T) {
	b := newItemBreaker(AuditConfig{ConsecutiveCheckFailuresToAbandonUnit: 2, ConsecutiveUnitFailuresToFailItem: 2})
	// Two units abandoned back to back is what trips a failItemAfter of 2, which is the state a
	// follow-up pass is consulted in: the item is FAILED and the engine is deciding whether to retry.
	// unitFinished reports the item's failed STATE, so it returns false until the threshold trips --
	// that is the loop's own contract, and this test walks to the trip rather than assuming it.
	for _, unit := range []string{"unit-a", "unit-b"} {
		b.checkFailed(unit, "sqli")
		b.checkFailed(unit, "xss") // two failures in a row abandons the unit
		tripped := b.unitFinished(true)
		if unit == "unit-b" && !tripped {
			t.Fatalf("precondition: abandoning two units back to back should trip failItemAfter=2")
		}
	}
	if !b.failed() {
		t.Fatal("precondition: the item should be failed before beginPass is consulted")
	}
	b.beginPass()

	// The memory SURVIVES the pass -- that is the whole narrowing. Clearing it here would make every
	// pass a full re-dispatch and multiply the traffic against a target that is refusing, which is
	// precisely the hazard step 1 exists to remove.
	if !b.AlreadyFailed("unit-a", "sqli") {
		t.Error("a pass cleared the failure memory; every pass becomes a full re-dispatch and the " +
			"traffic multiplies against a target that is refusing")
	}
	if !b.AlreadyFailed("unit-b", "xss") {
		t.Error("a pass cleared the failure memory for the unit that tripped the breaker")
	}
	// The counters really did reset, or the second pass would inherit the count that stopped the first.
	if b.consecutiveCheckFailures != 0 || b.consecutiveUnitFailures != 0 {
		t.Errorf("a pass left the counters at check=%d unit=%d; a pass is measured against the same "+
			"thresholds rather than inheriting the count that stopped the last one",
			b.consecutiveCheckFailures, b.consecutiveUnitFailures)
	}
	// And the item is STILL failed after the pass. Clearing the flag would make the engine's verdict
	// depend on whether a retry happened rather than on whether the work succeeded, so a pass that
	// fixed nothing would report the item as merely bounded -- a claim this engine does not make.
	if !b.failed() {
		t.Error("beginPass cleared the item's failed flag; the item is still failed after a pass that " +
			"did not clear it, and reporting it as merely bounded would be a claim about work whose " +
			"outcome is unknown")
	}
}

// The key is honoured, so the row is no longer a false statement: a configuration carrying it
// produces a run configured for follow-up passes.
func TestTheFollowUpPassKeyNowApplies(t *testing.T) {
	for _, k := range BuiltInConfigKeys() {
		if k.Name != "number_of_follow_up_passes" {
			continue
		}
		if !k.Applies {
			t.Errorf("the row still reports the key as not applied (%q) while AuditConfig.FollowUpPasses "+
				"drives a real pass loop", k.What)
		}
		if k.Partial {
			t.Error("the row is marked partial; the control is honoured in full, through Burp's own shape " +
				"(a count), so there is nothing reduced about it")
		}
		preset, unapplied := BuiltInConfig{
			Name:           "retries",
			FollowUpPasses: SomeUint32(2),
		}.ApplyWithReport(AuditConfig{})
		if unapplied != nil {
			t.Errorf("a preset setting the key reports %v unapplied", unapplied)
		}
		if !preset.FollowUpPasses.Set || preset.FollowUpPasses.Value != 2 {
			t.Errorf("the preset applied %v, want the key set to 2", preset.FollowUpPasses)
		}
		if got := preset.followUpPasses(); got != 2 {
			t.Errorf("the applied config resolves to %d passes, want 2", got)
		}
		return
	}
	t.Fatal("no row for number_of_follow_up_passes")
}

// burpsy-react-ui-krf5: the follow-up pass must actually RE-DISPATCH. The old
// `goto dispatch` label sat AFTER the dispatch loop, so the jump skipped the loop
// entirely and went straight to the tail — which counted every step as failed a
// second time (ItemFailed += len(steps)) and reported FollowUpPasses = 0. The retry
// the feature exists for never ran.
//
// This drives an item through a failed pass with retries on: a dead target, a plan
// spanning TWO dispatch scopes (PerHost final checks + PerUrl injection checks), and
// the breaker wound tight. Pass 0 fails the first unit's check and abandons it; the
// retry must re-dispatch, skip the already-failed check, and try the next unit's check.
func TestAFollowUpPassReDispatchesAndDoesNotDoubleCount(t *testing.T) {
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, "127.0.0.1", deadTarget(t), "/search", "<html>seed</html>")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{
			MaxConcurrency: 1, Timeout: 10 * time.Second,
			// Two dispatch scopes: PerHost (final checks) before PerUrl (injection).
			// The PerHost check fails first, tripping the item breaker with the
			// PerUrl unit still untried — the state a retry exists for.
			CheckExtendedActive: true,
			CheckSqli:           true, CheckXss: true, CheckPathTraversal: true,
		})

	cfg := DefaultAuditConfig()
	cfg.FollowUpPasses = SomeUint32(1)
	// One failure abandons the unit; one abandoned unit fails the item — the tightest
	// breaker, so pass 0 stops after the first unit and the retry has something to do.
	cfg.ConsecutiveCheckFailuresToAbandonUnit = 1
	cfg.ConsecutiveUnitFailuresToFailItem = 1
	outcome, _ := scan.AuditWithin(context.Background(), id, cfg)

	// The retry RAN — the whole point of the fix. The old code reported 0 here.
	if outcome.FollowUpPasses != 1 {
		t.Errorf("FollowUpPasses = %d, want 1: a failed item with untried steps must be re-dispatched", outcome.FollowUpPasses)
	}
	// The partition identity: every enabled check is dispositioned exactly once.
	// The old code double-counted — the tail added len(steps) to ItemFailed after the
	// per-check counters had already accounted for them.
	if got, want := outcome.Considered(), scan.ActiveCheckCount(); got != want {
		t.Errorf("Considered() = %d, want %d (the enabled check set): a failed item still "+
			"accounts for its whole check set exactly once, with no double-count", got, want)
	}
	if outcome.State != ItemStateFailed {
		t.Errorf("state = %s, want failed", outcome.State.Label())
	}
}

// The narrowing's second defect (krf5): the old narrowing branch advanced pos a
// second time after the step-consumption point, so every already-failed check
// silently ate its successor's disposition. A re-pass must skip the failed check
// AND still dispatch the one after it.
func TestTheNarrowingDoesNotEatTheFollowingStep(t *testing.T) {
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, "127.0.0.1", deadTarget(t), "/search", "<html>seed</html>")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{
			MaxConcurrency: 1, Timeout: 10 * time.Second,
			CheckExtendedActive: true,
			CheckSqli:           true, CheckXss: true, CheckPathTraversal: true,
		})

	cfg := DefaultAuditConfig()
	cfg.FollowUpPasses = SomeUint32(1)
	cfg.ConsecutiveCheckFailuresToAbandonUnit = 1
	cfg.ConsecutiveUnitFailuresToFailItem = 1
	outcome, _ := scan.AuditWithin(context.Background(), id, cfg)

	// The retry re-dispatched and the previously-skipped check ran in it. The old
	// double pos++ would have left checks with no disposition at all.
	if outcome.FollowUpPasses != 1 {
		t.Errorf("FollowUpPasses = %d, want 1", outcome.FollowUpPasses)
	}
	if got, want := outcome.Considered(), scan.ActiveCheckCount(); got != want {
		t.Errorf("Considered() = %d, want %d: every check dispositioned exactly once", got, want)
	}
}
