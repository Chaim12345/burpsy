package web

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/pool"
)

// Burp's resource-pool variations over the wire (burpsy-react-ui-nn0n).
//
// The schedule itself is the intruder package's (limit_variation_test.go asserts the exact gaps an
// attack takes). What is new here is the mapping: a percentage on the screen becoming the engine's
// fraction, the bounds the route puts on it, and the refusals reaching the operator with their
// reason intact instead of being clamped into something that would run.

func Test_an_inline_attack_carries_burps_delay_variations(t *testing.T) {
	s := newTestServer()
	rps := 10.0
	pct := 25.0
	inc := 50
	seed := uint64(7)
	limits, err := s.intruderLimits(intruderRunReq{
		RPS: &rps, DelayJitterPercent: &pct, DelayIncrementMS: &inc, DelaySeed: &seed,
	})
	if err != nil {
		t.Fatalf("a jittered, ramping pool was refused: %v", err)
	}
	v := limits.Variation()
	if v == nil {
		t.Fatal("the attack's limits carry no variation, so the engine would pace it flat")
	}
	if v.Jitter != 0.25 {
		t.Errorf("25%% on the wire became a jitter of %v, want 0.25", v.Jitter)
	}
	if v.IncrementMS != 50 {
		t.Errorf("the increment is %dms, want the 50 that was sent", v.IncrementMS)
	}
	if v.Seed != 7 {
		t.Errorf("the seed is %d, want 7 — a run that cannot be replayed cannot be checked", v.Seed)
	}
}

// The default is untouched: an attack that never mentions a variation gets none, and the engine's
// flat bucket is the code path it takes.
func Test_an_attack_that_asks_for_no_variation_has_none(t *testing.T) {
	s := newTestServer()
	rps := 10.0
	limits, err := s.intruderLimits(intruderRunReq{RPS: &rps})
	if err != nil {
		t.Fatalf("the plain inline form was refused: %v", err)
	}
	if limits.Variation() != nil {
		t.Fatalf("an attack that asked for nothing got the variation %+v", limits.Variation())
	}
}

func Test_a_variation_the_engine_cannot_honour_is_refused_with_its_reason(t *testing.T) {
	s := newTestServer()
	rps := 10.0
	hundred := 100.0
	negative := -5.0
	tooBig := intruderMaxDelayIncrementMS + 1
	negativeInc := -1
	seedOnly := uint64(3)
	for what, c := range map[string]struct {
		req  intruderRunReq
		says string
	}{
		"a variation of exactly 100%": {intruderRunReq{RPS: &rps, DelayJitterPercent: &hundred}, "below 100"},
		"a negative variation":        {intruderRunReq{RPS: &rps, DelayJitterPercent: &negative}, "at least 0"},
		"an increment past the bound": {intruderRunReq{RPS: &rps, DelayIncrementMS: &tooBig}, "delay_increment_ms"},
		"a negative increment":        {intruderRunReq{RPS: &rps, DelayIncrementMS: &negativeInc}, "delay_increment_ms"},
		"a seed and nothing to vary":  {intruderRunReq{RPS: &rps, DelaySeed: &seedOnly}, "nothing to vary"},
	} {
		got, err := s.intruderLimits(c.req)
		if err == nil {
			t.Errorf("%s was accepted, so the attack would run at a pace nobody chose", what)
			continue
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s was refused with %q, which does not say %q", what, err, c.says)
		}
		if got.Variation() != nil {
			t.Errorf("%s was refused but still produced a limit carrying a variation", what)
		}
	}
}

// A saved pool states how its delay behaves; an attack that names one and also sends a variation is
// two answers to the same question, and the refusal names both halves — the rule the rps,
// max_in_flight and auto_throttle trio already followed.
func Test_an_attack_cannot_name_a_pool_and_vary_its_delay(t *testing.T) {
	s := newTestServer()
	do(t, s, "POST", "/api/pools", pool.Pool{Name: "slow", MaxConcurrent: 1, DelayMs: 1000})
	name := "slow"
	pct := 20.0
	inc := 5
	seed := uint64(1)
	for what, req := range map[string]intruderRunReq{
		"delay_jitter_percent": {Pool: &name, DelayJitterPercent: &pct},
		"delay_increment_ms":   {Pool: &name, DelayIncrementMS: &inc},
		"delay_seed":           {Pool: &name, DelaySeed: &seed},
	} {
		if _, err := s.intruderLimits(req); err == nil {
			t.Errorf("an attack naming a pool and %s was accepted; one of the two would be dropped", what)
		}
	}
}

// The engine's own refusals are not re-implemented here, they are passed through: this is the one
// that only the engine can see, because the route always sets a rate and a pool with none can only
// arrive from a saved pool.
func Test_a_variation_on_a_pool_with_no_rate_cap_is_refused_by_the_engine(t *testing.T) {
	_, err := intruder.Unthrottled(4).WithVariation(&intruder.DelayVariation{Jitter: 0.5})
	if err == nil {
		t.Fatal("a variation on an uncapped pool was accepted; there is no interval for it to scale")
	}
	if !strings.Contains(err.Error(), "no rate cap to vary") {
		t.Errorf("the refusal is %q, which does not explain that there is no interval", err)
	}
}
