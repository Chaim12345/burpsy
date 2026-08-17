package scanner

import (
	"context"
	"strings"
	"testing"
)

// The whole point of the deferred phase, asserted against the real engine.
//
// A stored row cannot fire during an audit: the canary is planted by the audit, and every response
// the scan holds predates it. So the audit must report the check as undecided rather than clean,
// and the finding must arrive from FinishScan after the re-fetch. Both halves are asserted here
// because either one alone can be satisfied dishonestly - a scan that never defers anything also
// never reports a false stored finding.
func TestAStoredRowIsUndecidedDuringTheAuditAndConfirmedAfterTheSecondLook(t *testing.T) {
	scan, _, ids := storedTarget(t)

	outcome, findings := scan.AuditWithin(context.Background(), ids["/comment?comment=hello"], scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit failed outright: %s", outcome.Error)
	}
	for _, f := range findings {
		if strings.Contains(f.Name, "stored") || strings.Contains(f.Name, "second order") {
			t.Fatalf("%q was reported during the audit; the canary was planted by this very audit, "+
				"so nothing could legitimately have seen it yet", f.Name)
		}
	}
	if outcome.Unmeasurable == 0 {
		t.Fatalf("audit reported %d undecided checks, want at least one: the stored rows planted "+
			"canaries and could not possibly have an answer, and silence there is the defect",
			outcome.Unmeasurable)
	}
	if scan.Pending().PendingCount() == 0 {
		t.Fatal("no claim was registered, so the planted canaries would never be looked for again")
	}

	deferred, completion := scan.FinishScan(context.Background())
	if completion.RefetchError != "" {
		t.Fatalf("the second look did not happen: %s", completion.RefetchError)
	}
	if completion.Refetch.Refetched == 0 {
		t.Fatalf("re-fetched nothing (%s), so the assertions below would be vacuous",
			completion.Refetch.Summary())
	}
	if len(deferred) == 0 {
		t.Fatalf("no stored finding after the second look. /comments renders every submitted "+
			"comment unescaped, so a canary planted in /comment must surface there.\nrefetch: %s\npending: %s",
			completion.Refetch.Summary(), completion.Pending)
	}
	for _, f := range deferred {
		if !strings.Contains(f.Description, "is rendered in exchange") {
			t.Errorf("%q does not name the exchange the value surfaced in; a stored finding that "+
				"cannot cite where it was seen is not reproducible", f.Name)
		}
	}
}

// A scan with no second look must not report the stored rows as clean.
func TestWithoutASecondLookTheStoredClaimsAreOutstandingRatherThanClean(t *testing.T) {
	scan, _, ids := storedTarget(t)
	if _, _ = scan.AuditWithin(context.Background(), ids["/comment?comment=hello"], scan.AuditConfig()); scan.Pending().PendingCount() == 0 {
		t.Fatal("nothing was deferred, so this test cannot distinguish the two states")
	}

	// Remove the capability the second look needs, exactly as a scan with no sender would.
	scan.sender = nil
	_, completion := scan.FinishScan(context.Background())
	if completion.RefetchError == "" {
		t.Error("FinishScan reported a successful second look with no sender configured")
	}
	if len(completion.Outstanding) == 0 {
		t.Fatal("no outstanding claims reported; the canaries were planted and never looked for, " +
			"which must appear in the report rather than reading as a clean stored result")
	}
	if !strings.Contains(completion.Pending, "outstanding") {
		t.Errorf("pending summary = %q, want it to name the unanswered claims", completion.Pending)
	}
}

// The sentinel the stored checks return has to be the inconclusive one, so the engine counts them
// as undecided rather than as failures that trip the breaker.
func TestADeferredStoredClaimIsCountedUndecidedNotFailed(t *testing.T) {
	scan, _, ids := storedTarget(t)
	outcome, _ := scan.AuditWithin(context.Background(), ids["/comment?comment=hello"], scan.AuditConfig())
	if outcome.SendFailures != 0 {
		t.Errorf("send failures = %d, want 0: deferring a claim is not a transport failure and "+
			"must not count towards the breaker", outcome.SendFailures)
	}
	if !strings.Contains(outcome.Summary(), "undecided") {
		t.Errorf("summary = %q, want the undecided checks named", outcome.Summary())
	}
}

// With an empty ledger there is nothing to wait for, so the honest answer is a clean one rather
// than an undecided claim nobody can ever settle.
func TestDeferringWithNothingPlantedReportsCleanRatherThanUndecided(t *testing.T) {
	scan, store, _ := storedTarget(t)
	ex := store.Exchanges()[0]
	if err := deferStoredClaim(&CheckContext{Scanner: scan, Exchange: ex},
		"Cross-site scripting (stored)", "high", contextAnywhere); err != nil {
		t.Fatalf("deferStoredClaim with an empty ledger returned %v, want nil: no canary was "+
			"planted, so there is no claim and nothing was suppressed", err)
	}
	if scan.Pending().PendingCount() != 0 {
		t.Error("a claim was registered with nothing planted; it could never settle and would be " +
			"reported outstanding forever")
	}
}
