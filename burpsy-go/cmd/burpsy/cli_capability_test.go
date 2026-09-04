package main

import "testing"

// ---- The capability handles: the shipping binary must wire what the engine can do ---------------
//
// The gap this test closes is the same class as the -dom one: the scanner grew five capability
// handles — stored-input ledger, provenance ledger, session coordinator, JS-library check, JWT
// weak-secret check — whose absence makes whole check families report "no X configured for this
// scan" while every test-built scanner demonstrated them working. main.go and cli.go wired only
// the browser provider (and, since the collaborator merge, the OOB provider), so the shipped
// binary ran stored, provenance, access-control, CSRF, JS-vulnerability and JWT rows that could
// never reach a verdict.
//
// The assertions go through the nil-safe Handle accessors rather than flags: the question is
// "did the constructor reach the scanner", and the accessor is the same answer a capability
// report would read.

func TestCLIContextWiresEveryCapabilityHandle(t *testing.T) {
	ctx, err := newCLIContext("", 1<<20, "*", "", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("newCLIContext: %v", err)
	}

	if ctx.scanner.StoredLedgerHandle() == nil {
		t.Error("no stored-input ledger: the 10 stored/second-order checks would all refuse for want of a ledger")
	}
	if ctx.scanner.ProvenanceLedgerHandle() == nil {
		t.Error("no provenance ledger: the final-report provenance rows would be missing from every audit")
	}
	if ctx.scanner.SessionCoordinatorHandle() == nil {
		t.Error("no session coordinator: access-control and CSRF rows would report a missing capability instead of comparing two anonymous requests")
	}
	if ctx.scanner.JsLibraryCheckHandle() == nil {
		t.Error("no JS-library check: the CheckJSVulns family would report a missing capability despite the vendored corpus")
	}
	if ctx.scanner.JwtWeakSecretCheckHandle() == nil {
		t.Error("no JWT weak-secret check: the CheckJwtWeak family would report a missing capability despite the bundled wordlist")
	}

	// The session coordinator must be the CLI's own instance, not a second one — the same law as
	// the single Scope handle: the session rules an operator edits on the Session page and the
	// comparisons the access-control and CSRF rows make have to be one rule set. A copy here would
	// let the page describe rules the scanner quietly stopped honouring.
	if ctx.scanner.SessionCoordinatorHandle() != ctx.sess {
		t.Error("the scanner did not share the CLI's session coordinator; session rules would govern one surface and not the other")
	}
}
