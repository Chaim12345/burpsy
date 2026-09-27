package scanner

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// The gate is per INSERTION POINT (Burp's Zfhb.java:81-83, which filters the
// per-insertion-point dispatch on the point's own effectiveness), so what these pin is the point
// count an enumeration returns under the key on and off — not the key-table row, which
// audit_config_keys_test.go already holds.

// gateRequest has three query parameters on one host, so a run that has already shown one of them
// inert can drop exactly that one and the enumeration still returns the other two.
const gateRequest = "GET /search?q=seed&b=1&c=2 HTTP/1.1\r\nHost: app.test\r\n\r\n"

// gateCheck is the check identity the prior is keyed by in these tests. The enumerator asks
// about opts.CheckName, so a test that records under any other name would be asking about a
// bucket nothing wrote to — which is exactly the mistake that made this gate look inert.
const gateCheck = "SQLInjection"

func gateOptions(effective func(string, bcheck.InsertionPoint) bool) bcheck.EnumerateOptions {
	return bcheck.EnumerateOptions{
		Max:            bcheck.DefaultMaxInsertionPoints,
		PointEffective: effective,
		CheckName:      gateCheck,
	}
}

func countQueryPoints(pts []bcheck.InsertionPoint) int {
	n := 0
	for _, p := range pts {
		if p.Kind == bcheck.IpQuery {
			n++
		}
	}
	return n
}

func declinedFor(declined []bcheck.Declined, what string) (bcheck.Declined, bool) {
	for _, d := range declined {
		if strings.HasPrefix(d.What, what) {
			return d, true
		}
	}
	return bcheck.Declined{}, false
}

// A point this run has probed with nothing found is dropped from the next dispatch. The other two
// points on the same request are untouched: the gate is per point, so a parameter that never
// answers cannot silence its siblings.
func TestTheEffectivenessGateDropsOneInertPointAndLeavesTheOthers(t *testing.T) {
	pe := newPointEffectiveness()
	inert := bcheck.InsertionPoint{Kind: bcheck.IpQuery, Name: "q"}

	// Two priors with nothing found — the minimum the gate needs before it will judge.
	pe.record(gateCheck, inert, "app.test", false)
	pe.record(gateCheck, inert, "app.test", false)

	pts, declined := bcheck.EnumerateWith([]byte(gateRequest), []string{"query"}, gateOptions(
		func(check string, p bcheck.InsertionPoint) bool { return pe.effective(check, p, "app.test") }))

	if got := countQueryPoints(pts); got != 2 {
		t.Fatalf("query points enumerated = %d, want 2 of 3: the gate must drop the one inert point "+
			"and leave its two siblings alone, because a parameter that never answers says nothing "+
			"about the parameters beside it", got)
	}
	if _, ok := declinedFor(declined, bcheck.DeclinedIneffectiveWhat); !ok {
		t.Errorf("no %q decline recorded; a gate that dropped a point silently would make the run's "+
			"point count unreadable, which is the whole reason the Declined type exists (got %v)",
			bcheck.DeclinedIneffectiveWhat, declined)
	}
}

// A point that answered something is never dropped, however many inert siblings it has: an
// effective parameter is evidence the target parses it, and dropping it would be a false negative.
func TestAPointThatAnsweredIsNeverDropped(t *testing.T) {
	pe := newPointEffectiveness()
	answered := bcheck.InsertionPoint{Kind: bcheck.IpQuery, Name: "q"}
	pe.record(gateCheck, answered, "app.test", true)
	pe.record(gateCheck, answered, "app.test", true)
	pe.record(gateCheck, answered, "app.test", true)

	pts, _ := bcheck.EnumerateWith([]byte(gateRequest), []string{"query"}, gateOptions(
		func(check string, p bcheck.InsertionPoint) bool { return pe.effective(check, p, "app.test") }))

	if got := countQueryPoints(pts); got != 3 {
		t.Fatalf("query points enumerated = %d, want all 3: a point that has answered must not be "+
			"dropped no matter how many priors it has — the gate only ever drops points it has "+
			"watched stay silent", got)
	}
}

// An unprobed point is always probed. A gate that dropped unjudged points would report a target
// as clean because the engine chose not to look, which is the false negative this project treats
// as the worse error.
func TestAnUnprobedPointIsStillProbed(t *testing.T) {
	pe := newPointEffectiveness()

	pts, declined := bcheck.EnumerateWith([]byte(gateRequest), []string{"query"}, gateOptions(
		func(check string, p bcheck.InsertionPoint) bool { return pe.effective(check, p, "app.test") }))

	if got := countQueryPoints(pts); got != 3 {
		t.Fatalf("query points enumerated = %d, want all 3: nothing has been probed yet, so the "+
			"gate has no standing to drop anything", got)
	}
	if len(declined) != 0 {
		t.Errorf("declined = %v, want none: no point was judged, so none may be reported as judged", declined)
	}
}

// A nil oracle skips nothing. This is what a context built outside a dispatched audit gets, and
// what the run installs when skip_ineffective_checks is set to zero.
func TestANilOracleSkipsNothing(t *testing.T) {
	pts, declined := bcheck.EnumerateWith([]byte(gateRequest), []string{"query"}, gateOptions(nil))
	if got := countQueryPoints(pts); got != 3 {
		t.Fatalf("query points enumerated = %d, want 3: a nil oracle means the caller cannot judge, "+
			"which is not the same as every point being ineffective", got)
	}
	if len(declined) != 0 {
		t.Errorf("declined = %v, want none with no oracle installed", declined)
	}
}

// The gate is keyed per host: the same parameter name on two hosts is two applications' handling,
// so one host's silence must not silence the other. Same reason the light-audit tier has the host
// in its key.
func TestTheGateIsKeyedPerHost(t *testing.T) {
	pe := newPointEffectiveness()
	p := bcheck.InsertionPoint{Kind: bcheck.IpQuery, Name: "q"}
	pe.record(gateCheck, p, "silent.test", false)
	pe.record(gateCheck, p, "silent.test", false)

	if pe.effective(gateCheck, p, "silent.test") {
		t.Error("a point with two silent priors on its own host must be judged ineffective")
	}
	if !pe.effective(gateCheck, p, "other.test") {
		t.Error("the same parameter on a different host must still be probed: the two are two " +
			"applications' handling, and one host's silence is not evidence about the other")
	}
}

// The key's own state: unset is Burp's shipped default (the gate is on), and set-and-zero turns
// it off. A gate that is on by default but silent when set would make the two spellings
// indistinguishable, which is the defect class every other OptUint32 here is written against.
func TestTheKeyIsOnUnlessExplicitlyZeroed(t *testing.T) {
	cfg := DefaultAuditConfig()
	if cfg.SkipIneffectiveChecks.Set {
		t.Fatal("SkipIneffectiveChecks is set in the default configuration; unset must mean Burp's " +
			"shipped default, which is the gate being on")
	}

	// The exact expression the dispatcher evaluates (audit_engine.go), kept here so the two
	// cannot drift: if one changes and the other does not, the key stops meaning what its row says.
	gateEnabled := func(c AuditConfig) bool { return !c.SkipIneffectiveChecks.Set || c.SkipIneffectiveChecks.Value != 0 }
	enabled := gateEnabled(cfg)
	if !enabled {
		t.Error("an unset key must leave the gate enabled — Burp ships it on")
	}
	// The dispatcher's own spelling: a set-and-zero is the operator saying "pay full price for
	// every point", and it must not read as unset.
	cfg.SkipIneffectiveChecks = SomeUint32(0)
	zeroed := cfg.SkipIneffectiveChecks.Set && cfg.SkipIneffectiveChecks.Value == 0
	if !zeroed || gateEnabled(cfg) {
		t.Error("a set-and-zero configuration must read as the gate off: the expression the " +
			"dispatcher uses no longer matches the one the key's contract states")
	}
	// And a non-zero set value is still on — the key is a boolean spelled as an integer, and
	// "set" alone must not be read as "off".
	if !gateEnabled(AuditConfig{SkipIneffectiveChecks: SomeUint32(1)}) {
		t.Error("a set-and-one configuration must read as the gate on")
	}
}

// The decline carries the count, because a truncation nobody can see is the silent false negative
// the Declined type exists to prevent.
func TestTheIneffectiveDeclineNamesItsCount(t *testing.T) {
	pe := newPointEffectiveness()
	for _, name := range []string{"q", "b", "c"} {
		p := bcheck.InsertionPoint{Kind: bcheck.IpQuery, Name: name}
		pe.record(gateCheck, p, "app.test", false)
		pe.record(gateCheck, p, "app.test", false)
	}
	_, declined := bcheck.EnumerateWith([]byte(gateRequest), []string{"query"}, gateOptions(
		func(check string, p bcheck.InsertionPoint) bool { return pe.effective(check, p, "app.test") }))
	d, ok := declinedFor(declined, bcheck.DeclinedIneffectiveWhat)
	if !ok {
		t.Fatalf("no ineffective decline in %v", declined)
	}
	if !strings.Contains(d.Reason, "3 point(s)") {
		t.Errorf("decline reason %q does not name the count; a run whose point count fell must be able "+
			"to say how many places it gave up and why", d.Reason)
	}
}

// The gate is a scanner behaviour, so the run's own accounting has to carry it: the outcome says
// how many probes were spent on points that answered nothing, which is the evidence the later
// drops are made of.
func TestTheLedgerCountsWhatItJudged(t *testing.T) {
	pe := newPointEffectiveness()
	if got := pe.Count(); got != 0 {
		t.Fatalf("fresh ledger count = %d, want 0", got)
	}
	p := bcheck.InsertionPoint{Kind: bcheck.IpQuery, Name: "q"}
	pe.record(gateCheck, p, "app.test", false)
	pe.record(gateCheck, p, "app.test", false)
	if got := pe.Count(); got != 2 {
		t.Fatalf("ledger count = %d, want 2 silent priors", got)
	}
	// A place that answers is RETIRED: its silent priors are cleared, not incremented, so a
	// parameter that has demonstrated it parses cannot re-serve the sentence the gate would
	// drop it on. Count is the total of silent priors across all places, so the answer drops
	// back to zero — which is the honest reading, because there is now nothing left to judge.
	pe.record(gateCheck, p, "app.test", true)
	if got := pe.Count(); got != 0 {
		t.Fatalf("ledger count = %d, want 0: a place that answered must be retired from the count, "+
			"or one answer would leave a stale prior behind for a parameter the target has been "+
			"shown to parse", got)
	}
	if !pe.effective(gateCheck, p, "app.test") {
		t.Error("a place that answered must read effective afterwards: retiring it from the count " +
			"must not also hand it straight back to the gate on its next dispatch")
	}
}
