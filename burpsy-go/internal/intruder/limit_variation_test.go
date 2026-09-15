package intruder

import (
	"strings"
	"testing"
	"time"
)

// Burp's resource-pool variations (burpsy-react-ui-nn0n): "With random variations" and the
// per-request delay increment.
//
// # Why these tests drive reserve() with a clock they control
//
// The claim the feature makes is about the length of each gap between requests, and a test that
// measured that with a real clock on a loaded machine could only assert bounds loose enough to
// pass whatever the code did. reserve() is the whole schedule — Acquire is reserve plus a Sleep of
// exactly what it returned — so driving it with a synthetic now, advanced by the wait it just
// returned, is the timing an attack actually takes, measured exactly. TestAcquireSleepsTheSchedule
// below ties that back to the real clock so the two cannot drift apart.

const (
	ms  = time.Millisecond
	eps = time.Microsecond // the float arithmetic's slack; every assertion below is far tighter than one draw
)

// waits drives a limiter as a caller that waits exactly as long as it is told, and returns the gap
// before each grant. gap 0 is the first request's, which never waits.
func waits(l *RateLimiter, n int) []time.Duration {
	now := time.Now()
	out := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		w := l.reserve(now)
		out = append(out, w)
		now = now.Add(w)
	}
	return out
}

func varied(t *testing.T, rps float64, burst, inFlight int, v *DelayVariation) *RateLimiter {
	t.Helper()
	limit, err := NewRateLimit(&rps, burst, inFlight).WithVariation(v)
	if err != nil {
		t.Fatalf("WithVariation(%+v) refused a combination the test expects to be legal: %v", v, err)
	}
	return NewRateLimiter(&limit)
}

func mustEqual(t *testing.T, got, want []time.Duration, what string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d gaps, want %d", what, len(got), len(want))
	}
	for i := range want {
		if d := got[i] - want[i]; d > eps || d < -eps {
			t.Fatalf("%s: gap %d was %v, want %v (all: %v)", what, i, got[i], want[i], got)
		}
	}
}

// The regression the rest of this file is measured against: a pool with no variation is paced by
// the token bucket, and these are the exact gaps it produced before DelayVariation existed. If a
// variation ever leaks into the unvaried path this is the test that says so.
func TestWithNoVariationThePacingIsExactlyWhatItAlwaysWas(t *testing.T) {
	rps := 10.0
	strict := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 4})
	mustEqual(t, waits(strict, 5), []time.Duration{0, 100 * ms, 100 * ms, 100 * ms, 100 * ms}, "burst 1")

	// A burst spends its tokens first and then settles onto the same spacing.
	bursty := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 3, MaxInFlight: 4})
	mustEqual(t, waits(bursty, 6), []time.Duration{0, 0, 0, 100 * ms, 100 * ms, 100 * ms}, "burst 3")

	if strict.variation != nil || bursty.variation != nil {
		t.Fatal("a limiter built from a limit with no variation grew a schedule")
	}
}

// Burp's throttleIncrementMillis: gap 0 is the rate's own interval and every gap after it is one
// increment longer. Exact, because a ramp that is approximately right is a ramp nobody can predict
// the end of.
func TestAnIncrementRampsEveryGapByExactlyTheIncrement(t *testing.T) {
	l := varied(t, 10, 1, 4, &DelayVariation{IncrementMS: 50})
	mustEqual(t, waits(l, 5), []time.Duration{0, 100 * ms, 150 * ms, 200 * ms, 250 * ms}, "ramp")
}

// The exact delays seed 7 produces at 10/s with ±25%. Written as numbers rather than re-derived
// from a second generator in the test, so that a change to the seeding, the draw order or the
// interval arithmetic shows up as a diff instead of as two derivations agreeing with each other.
func TestASeededJitterProducesTheseExactDelays(t *testing.T) {
	l := varied(t, 10, 1, 4, &DelayVariation{Jitter: 0.25, Seed: 7})
	mustEqual(t, waits(l, 6), []time.Duration{
		0,
		76584707,
		123395653,
		93932296,
		101132419,
		106364598,
	}, "seed 7 at 10/s, ±25%")
}

// The two variations compose on one gap: the ramp moves the nominal interval, the jitter scales
// whatever the nominal is by that gap's own draw. Same seed as above, so the draws are the same
// numbers and every gap here is its counterpart above times (100+50k)/100.
func TestTheIncrementRampsTheIntervalTheJitterThenScales(t *testing.T) {
	l := varied(t, 10, 1, 4, &DelayVariation{Jitter: 0.25, IncrementMS: 50, Seed: 7})
	got := waits(l, 6)
	mustEqual(t, got, []time.Duration{
		0,
		76584707,
		185093480,
		187864592,
		252831048,
		319093795,
	}, "seed 7 at 10/s, ±25%, +50ms a request")

	flat := waits(varied(t, 10, 1, 4, &DelayVariation{Jitter: 0.25, Seed: 7}), 6)
	for k := 1; k < len(got); k++ {
		nominal := float64(100+50*(k-1)) / 100
		want := time.Duration(float64(flat[k]) * nominal)
		if d := got[k] - want; d > ms/10 || d < -ms/10 {
			t.Fatalf("gap %d was %v; the same draw on a nominal %g× the base should have made it %v",
				k, got[k], nominal, want)
		}
	}
}

// Every gap inside the fraction, in both directions, and the fraction actually used: a jitter that
// only ever slowed the attack down would pass a bounds check and be the wrong feature.
func TestEveryJitteredGapStaysInsideTheFractionAndUsesBothSidesOfIt(t *testing.T) {
	const (
		rps    = 20.0
		jitter = 0.4
		n      = 200
	)
	nominal := time.Duration(float64(time.Second) / rps)
	low, high := time.Duration(float64(nominal)*(1-jitter)), time.Duration(float64(nominal)*(1+jitter))
	got := waits(varied(t, rps, 1, 4, &DelayVariation{Jitter: jitter, Seed: 99}), n)
	var shorter, longer int
	for i, gap := range got[1:] {
		if gap < low-eps || gap > high+eps {
			t.Fatalf("gap %d was %v, outside the ±%g%% band [%v, %v] around %v", i, gap, jitter*100, low, high, nominal)
		}
		if gap < nominal {
			shorter++
		} else {
			longer++
		}
	}
	if shorter == 0 || longer == 0 {
		t.Fatalf("of %d gaps, %d were shorter than the %v nominal and %d longer; a variation moves both ways",
			n-1, shorter, nominal, longer)
	}
}

// Reproducible from the seed and from nothing else. This is what makes the exact-delay tests above
// evidence about an attack rather than about one lucky run.
func TestTheScheduleIsAFunctionOfTheSeed(t *testing.T) {
	first := waits(varied(t, 10, 1, 4, &DelayVariation{Jitter: 0.3, IncrementMS: 5, Seed: 4242}), 20)
	again := waits(varied(t, 10, 1, 4, &DelayVariation{Jitter: 0.3, IncrementMS: 5, Seed: 4242}), 20)
	mustEqual(t, again, first, "the same seed replayed")

	other := waits(varied(t, 10, 1, 4, &DelayVariation{Jitter: 0.3, IncrementMS: 5, Seed: 4243}), 20)
	same := 0
	for i := range other {
		if other[i] == first[i] {
			same++
		}
	}
	if same > 1 { // gap 0 is 0 in both: the first request never waits
		t.Fatalf("seeds 4242 and 4243 agreed on %d of %d gaps; the draws are not coming from the seed", same, len(first))
	}
}

// A run whose sends are slower than their gaps is spaced from when it actually came back, not
// from the slot it missed. The failure this pins is the other choice: schedule strictly from the
// last slot, and a caller that spent a second inside one slow send finds its next few slots
// already in the past and fires them off back to back — the burst a variation exists to avoid.
func TestALateCallerIsSpacedFromWhenItArrivedNotFromTheSlotItMissed(t *testing.T) {
	l := varied(t, 10, 1, 4, &DelayVariation{IncrementMS: 0, Jitter: 0.0000001})
	now := time.Now()
	l.reserve(now) // the first grant, which never waits
	// The caller comes back a whole second late, having spent it inside a slow send.
	now = now.Add(time.Second)
	late := l.reserve(now)
	if late < 100*ms-ms/10 || late > 100*ms+ms/10 {
		t.Fatalf("a caller a second past its slot waited %v, not its ~100ms interval", late)
	}
	now = now.Add(late)
	// And the gap after it is a full interval too: nothing was banked while the caller was away.
	if w := l.reserve(now); w < 100*ms-ms/10 || w > 100*ms+ms/10 {
		t.Fatalf("the gap after a late grant was %v, so the schedule was discharging a backlog", w)
	}
}

// Auto-throttling and a variation are different mechanisms and compose: the throttle sets the rate
// the nominal interval comes from, and the schedule varies that. The increment is an absolute
// number of milliseconds, Burp's throttleIncrementMillis, so it is added to the throttled interval
// rather than scaled with it.
func TestAVariationScalesTheThrottledIntervalNotTheConfiguredOne(t *testing.T) {
	rps := 10.0
	limit, err := NewRateLimit(&rps, 1, 4).
		WithAutoThrottle(&AutoThrottle{Statuses: []int{429}, After: 1, Factor: 2, RecoverAfter: 10}).
		WithVariation(&DelayVariation{IncrementMS: 50})
	if err != nil {
		t.Fatal(err)
	}
	l := NewRateLimiter(&limit)
	now := time.Now()
	now = now.Add(l.reserve(now)) // the first grant, no gap in front of it
	first := l.reserve(now)
	now = now.Add(first)
	if d := first - 100*ms; d > eps || d < -eps {
		t.Fatalf("the first gap was %v, want the unthrottled 100ms interval", first)
	}

	status := 429
	l.Observe(&status)
	if !l.IsThrottled() {
		t.Fatal("one listed status with After:1 did not engage the throttle")
	}
	// Half the rate is a 200ms interval, and the ramp is on its second gap: 200 + 50.
	throttled := l.reserve(now)
	if d := throttled - 250*ms; d > eps || d < -eps {
		t.Fatalf("the first throttled gap was %v, want the halved 200ms interval plus one 50ms increment", throttled)
	}
}

// Acquire is reserve plus a sleep of exactly what it returned, so the schedule the tests above
// measure is the time an attack really spends. Bounds, not exact values: this one is on the real
// clock, and a machine can always be slower than it promised, never faster.
func TestAcquireSleepsTheSchedule(t *testing.T) {
	l := varied(t, 20, 1, 4, &DelayVariation{IncrementMS: 25})
	start := time.Now()
	for i := 0; i < 4; i++ {
		l.Acquire().Release()
	}
	// 50 + 75 + 100 = 225ms of scheduled gaps.
	if elapsed := time.Since(start); elapsed < 225*ms {
		t.Fatalf("four requests on a 50ms interval ramping 25ms took %v, inside the 225ms the schedule demands", elapsed)
	}
}

// The refusals. Every one of these is a combination that has no honest behaviour, so it is an
// error with a reason rather than a value quietly moved to the nearest one that works.
func TestAMeaninglessVariationIsRefusedWithAReason(t *testing.T) {
	rps := 10.0
	none := 0.0
	cases := []struct {
		name  string
		limit RateLimit
		v     *DelayVariation
		says  string
	}{
		{"a negative jitter", NewRateLimit(&rps, 1, 4), &DelayVariation{Jitter: -0.1}, "negative"},
		{"a jitter of exactly 1", NewRateLimit(&rps, 1, 4), &DelayVariation{Jitter: 1}, "zero or negative gap"},
		{"a jitter above 1", NewRateLimit(&rps, 1, 4), &DelayVariation{Jitter: 1.5}, "zero or negative gap"},
		{"a negative increment", NewRateLimit(&rps, 1, 4), &DelayVariation{IncrementMS: -1}, "shortens every gap"},
		{"neither setting", NewRateLimit(&rps, 1, 4), &DelayVariation{Seed: 9}, "nothing to vary"},
		{"no rate cap at all", Unthrottled(4), &DelayVariation{Jitter: 0.5}, "no rate cap to vary"},
		{"a rate cap of zero", NewRateLimit(&none, 1, 4), &DelayVariation{Jitter: 0.5}, "no rate cap to vary"},
		{"a burst", NewRateLimit(&rps, 3, 4), &DelayVariation{Jitter: 0.5}, "two answers"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.limit.WithVariation(c.v)
			if err == nil {
				t.Fatalf("%+v was accepted", c.v)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Fatalf("the refusal says %q, which does not explain %q", err.Error(), c.says)
			}
			if got.Variation() != nil || got.PerSecond != nil {
				t.Fatalf("a refused variation still returned a usable limit: %+v", got)
			}
		})
	}
}

// Accepted, attached, and removable — and a limit that never asked for one is untouched.
func TestAVariationIsCarriedByTheLimitAndCanBeTakenOffAgain(t *testing.T) {
	rps := 10.0
	plain := NewRateLimit(&rps, 1, 4)
	if plain.Variation() != nil {
		t.Fatal("a fresh limit already had a variation")
	}
	if err := plain.ValidateVariation(); err != nil {
		t.Fatalf("a limit with no variation was refused: %v", err)
	}
	v := &DelayVariation{Jitter: 0.2, IncrementMS: 10, Seed: 3}
	with, err := plain.WithVariation(v)
	if err != nil {
		t.Fatal(err)
	}
	if with.Variation() != v {
		t.Fatalf("the limit carries %+v, not the variation it was given", with.Variation())
	}
	if plain.Variation() != nil {
		t.Fatal("WithVariation mutated the limit it was called on")
	}
	off, err := with.WithVariation(nil)
	if err != nil || off.Variation() != nil {
		t.Fatalf("nil did not remove the variation: %+v, %v", off.Variation(), err)
	}
	if NewRateLimiter(&off).variation != nil {
		t.Fatal("a limiter built from a cleared limit still scheduled")
	}
}
