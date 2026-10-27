package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"

	"go.uber.org/zap"
)

// W6: passive checks get dispatch units of their own, walked before every active unit, so a
// tripped active unit - or a failed item - cannot take findings that needed no requests down
// with it.

func TestPlanDispatchesPassiveUnitsAheadOfActiveOnes(t *testing.T) {
	ex := &core.Exchange{ID: 7, Host: "h.test", Port: 80, Method: "GET", Path: "/p?x=1"}
	noop := func(*ActiveScanner, context.Context, *core.Exchange) ([]*Finding, error) { return nil, nil }
	checks := []activeCheck{
		{name: "active-host", scope: DispatchScopePerHost, phase: PhaseActive, run: noop},
		{name: "active-url", scope: DispatchScopePerUrl, phase: PhaseActive, run: noop},
		{name: "passive-url", scope: DispatchScopePerUrl, phase: PhasePassive, passive: true, run: noop},
		{name: "passive-request", scope: DispatchScopePerRequest, phase: PhasePassive, passive: true, run: noop},
		{name: "active-request", scope: DispatchScopePerRequest, phase: PhaseActive, run: noop},
	}
	units, steps, undispatchable := plan(ex, checks)
	if undispatchable != 0 {
		t.Fatalf("undispatchable = %d, want 0", undispatchable)
	}
	if len(units) != 5 {
		t.Fatalf("units = %d, want 5: each scope splits into a passive and an active unit", len(units))
	}
	// Passive units first, in scope order; active units after, coarsest scope first.
	wantOrder := []struct {
		scope DispatchScope
		check string
	}{
		{DispatchScopePerUrl, "passive-url"},
		{DispatchScopePerRequest, "passive-request"},
		{DispatchScopePerHost, "active-host"},
		{DispatchScopePerUrl, "active-url"},
		{DispatchScopePerRequest, "active-request"},
	}
	if len(steps) != len(wantOrder) {
		t.Fatalf("steps = %d, want %d", len(steps), len(wantOrder))
	}
	for i, w := range wantOrder {
		if units[steps[i].unit].scope != w.scope || checks[steps[i].check].name != w.check {
			t.Errorf("step %d = (%s, %s), want (%s, %s)", i,
				units[steps[i].unit].scope.Label(), checks[steps[i].check].name, w.scope.Label(), w.check)
		}
	}
	// The passive unit's key is set apart from the active unit of the same scope, so failure
	// memory and per-unit counters never mix the two.
	activeUrlKey, _ := DispatchScopePerUrl.UnitKey(ex)
	if units[steps[0].unit].key != activeUrlKey+"|passive" {
		t.Errorf("passive per-url key = %q, want %q", units[steps[0].unit].key, activeUrlKey+"|passive")
	}
	if units[steps[3].unit].key != activeUrlKey {
		t.Errorf("active per-url key = %q, want %q", units[steps[3].unit].key, activeUrlKey)
	}
	// A passive check with no implementation is counted undispatchable exactly once.
	checks = append(checks, activeCheck{name: "passive-declined", scope: DispatchScopePerUrl, phase: PhasePassive, passive: true})
	_, _, undispatchable = plan(ex, checks)
	if undispatchable != 1 {
		t.Errorf("undispatchable = %d, want 1 for the one passive check with no implementation", undispatchable)
	}
}

func TestPassiveCheckFailuresDoNotPrimeTheUnitBreaker(t *testing.T) {
	b := newItemBreaker(DefaultAuditConfig())
	b.passiveCheckFailed("u", "p1")
	b.passiveCheckFailed("u", "p2")
	if !b.AlreadyFailed("u", "p1") || !b.AlreadyFailed("u", "p2") {
		t.Error("passive failures must be remembered so a follow-up pass does not re-run them blind")
	}
	if b.checkFailed("u", "a1") {
		t.Error("passive failures must not prime the consecutive count: one active failure is failure one")
	}
	if !b.checkFailed("u", "a2") {
		t.Error("the second consecutive ACTIVE failure abandons the unit")
	}
}

func TestPassiveFindingsSurviveWhenTheActiveUnitsTrip(t *testing.T) {
	store := core.NewTrafficStore()
	// h.test resolves nowhere: every active probe is a send failure, so the active units trip
	// their breakers. The passive checks need only the seeded exchange.
	id := seedAuditExchange(t, store, "h.test", 80, "/", "<html><body><form><input type=password></form></body></html>")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{
			MaxConcurrency:       1,
			Timeout:              5 * time.Second,
			CheckSqli:            true,
			CheckXss:             true,
			CheckPathTraversal:   true,
			CheckPassiveAnalysis: true,
			CheckPassivePosture:  true,
		})

	outcome, _ := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())

	po := outcome.ByPhase[PhasePassive.String()]
	if po.UnitAbandoned != 0 || po.ItemFailed != 0 {
		t.Errorf("passive phase: unit_abandoned=%d item_failed=%d, want both 0 - passive findings "+
			"needed no requests and must survive the active units' failure", po.UnitAbandoned, po.ItemFailed)
	}
	if po.Ran == 0 {
		t.Error("passive phase: ran = 0, want the passive checks to have run on the seeded exchange")
	}
	if outcome.UnitAbandoned == 0 {
		t.Error("active units did not abandon: the dead target should still trip the breakers - " +
			"the fix moves passive checks out of the blast radius, it does not defuse the breaker")
	}
	sum := 0
	for _, d := range outcome.Dispositions() {
		sum += d.Count
	}
	if sum != outcome.Considered() {
		t.Errorf("disposition histogram sums to %d, want the full check set %d", sum, outcome.Considered())
	}
	t.Logf("passive phase: ran=%d skipped=%d findings=%d; overall: unit_abandoned=%d send_failures=%d state=%s",
		po.Ran, po.Skipped, po.Findings, outcome.UnitAbandoned, outcome.SendFailures, outcome.State.Label())
}
