package intruder

import (
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sortDur(d []time.Duration) { sort.Slice(d, func(i, j int) bool { return d[i] < d[j] }) }

// Ports burpsy-intruder::limit's test suite (limit.rs:373-734). Timing-sensitive tests
// assert bounds rather than exact timings, and none of them has an upper bound that a
// loaded machine could trip by being slow.

func ptr(i int) *int { return &i }

func TestSerialAcquiresCannotExceedTheConfiguredRate(t *testing.T) {
	rps := 100.0
	n := 21
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 8})
	t0 := time.Now()
	for i := 0; i < n; i++ {
		l.Acquire().Release()
	}
	elapsed := time.Since(t0)
	floor := time.Duration(float64(n-1) / rps * float64(time.Second))
	if elapsed < floor {
		t.Fatalf("%d requests at %g/s took %v, faster than the %v floor", n, rps, elapsed, floor)
	}
}

func TestConcurrentAcquiresAreSpacedNotReleasedTogether(t *testing.T) {
	rps := 50.0
	n := 20
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: n})
	t0 := time.Now()
	var mu sync.Mutex
	var grants []time.Duration
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := l.Acquire()
			mu.Lock()
			grants = append(grants, time.Since(t0))
			mu.Unlock()
			p.Release()
		}()
	}
	wg.Wait()
	sortDur(grants)
	floor := time.Duration(float64(n-1) / rps * float64(time.Second))
	if grants[n-1] < floor {
		t.Fatalf("last of %d concurrent grants landed at %v, inside the %v floor", n, grants[n-1], floor)
	}
	if grants[0] >= 100*time.Millisecond {
		t.Fatalf("the burst token did not make the first grant free: %v", grants[0])
	}
}

func TestNoWindowHoldsMoreGrantsThanTheBucketAllows(t *testing.T) {
	rps := 50.0
	burst := 3
	n := 30
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: burst, MaxInFlight: 8})
	t0 := time.Now()
	at := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		l.Acquire().Release()
		at = append(at, time.Since(t0).Seconds())
	}
	window := 0.2
	allowed := float64(burst) + rps*window
	for i, start := range at {
		count := 0
		for _, tm := range at[i:] {
			if tm-start <= window {
				count++
			} else {
				break
			}
		}
		if float64(count) > allowed {
			t.Fatalf("%d grants inside a %gs window starting at %gs; burst %d + %g/s allows at most %g",
				count, window, start, burst, rps, allowed)
		}
	}
}

func TestInFlightIsCappedEvenWithNoRateCap(t *testing.T) {
	capN := 4
	l := NewRateLimiter(&RateLimit{PerSecond: nil, Burst: 1, MaxInFlight: capN})
	var live, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := l.Acquire()
			now := live.Add(1)
			for {
				old := peak.Load()
				if now <= old || peak.CompareAndSwap(old, now) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			live.Add(-1)
			p.Release()
		}()
	}
	wg.Wait()
	if peak.Load() != int64(capN) {
		t.Fatalf("concurrency peaked at %d, outside the %d-slot cap", peak.Load(), capN)
	}
}

func TestAnAbsurdlySmallRateSaturatesInsteadOfPanicking(t *testing.T) {
	// 1.0 / 1e-300 is 1e300 seconds — unrepresentable. The wait must clamp to the
	// ceiling rather than panic (Rust's Duration::from_secs_f64 panics) or overflow.
	rate := 1e-300
	l := NewRateLimiter(&RateLimit{PerSecond: &rate, Burst: 1, MaxInFlight: 4})
	first := l.Acquire() // free: the burst token
	first.Release()
	wait := l.reserve(time.Now())
	if wait != MAX_WAIT {
		t.Fatalf("an unrepresentable wait must clamp to the ceiling, got %v", wait)
	}
}

func TestANormalRateIsUnaffectedByTheClamp(t *testing.T) {
	rps := 10.0
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 4})
	if wait := l.reserve(time.Now()); wait != 0 {
		t.Fatalf("the burst token must be free, got a %v wait", wait)
	}
	wait := l.reserve(time.Now())
	if wait <= 90*time.Millisecond || wait >= 110*time.Millisecond {
		t.Fatalf("expected ~100ms, got %v", wait)
	}
}

func TestAnUnsetRateStillLeavesConcurrencyBounded(t *testing.T) {
	l := NewRateLimiter(&RateLimit{PerSecond: nil, Burst: 1, MaxInFlight: 3})
	if wait := l.reserve(time.Now()); wait != 0 {
		t.Fatalf("no rate cap must never impose a wait")
	}
	if got := l.AvailableSlots(); got != 3 {
		t.Fatalf("available slots = %d, want 3", got)
	}
}

// ---- the auto-throttle ---------------------------------------------------------------------
//
// The highest-risk addition: it touches the one code path every request goes through, so the
// first thing established is the *absence* of an effect when it is not configured.

func TestWithNoAutoThrottleConfiguredNothingObservesAndNothingChanges(t *testing.T) {
	rps := 10.0
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 4})
	for i := 0; i < 100; i++ {
		l.Observe(ptr(429))
	}
	if l.IsThrottled() {
		t.Fatal("an unconfigured limiter became throttled")
	}
	if l.AutoThrottleEngaged() != 0 {
		t.Fatal("an unconfigured limiter engaged the throttle")
	}
	if wait := l.reserve(time.Now()); wait != 0 {
		t.Fatalf("the burst token is still free, got a %v wait", wait)
	}
	wait := l.reserve(time.Now())
	if wait <= 90*time.Millisecond || wait >= 110*time.Millisecond {
		t.Fatalf("an unconfigured limiter changed its arithmetic: %v", wait)
	}
}

func TestARunOfListedStatusesHalvesTheRateAndAShorterRunDoesNot(t *testing.T) {
	cfg := AutoThrottle{Statuses: []int{429}, After: 3, Factor: 2.0, RecoverAfter: 10}
	rps := 10.0
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 4, AutoThrottle: &cfg})

	l.Observe(ptr(429))
	l.Observe(ptr(429))
	if l.IsThrottled() {
		t.Fatal("two responses must not trip it")
	}
	_ = l.reserve(time.Now()) // spend the burst token
	normal := l.reserve(time.Now())
	if normal <= 90*time.Millisecond || normal >= 110*time.Millisecond {
		t.Fatalf("expected the unthrottled ~100ms, got %v", normal)
	}

	l.Observe(ptr(429))
	l.Observe(ptr(429))
	l.Observe(ptr(429))
	if !l.IsThrottled() {
		t.Fatal("three back-to-back must trip it")
	}
	if l.AutoThrottleEngaged() != 1 {
		t.Fatalf("engaged = %d, want 1", l.AutoThrottleEngaged())
	}
	slowed := l.reserve(time.Now())
	if slowed <= normal {
		t.Fatalf("the throttled wait %v is not longer than the normal %v", slowed, normal)
	}
}

func TestANonListedStatusResetsTheRun(t *testing.T) {
	rps := 10.0
	cfg := AutoThrottle{Statuses: []int{429, 503}, After: 3, Factor: 2.0, RecoverAfter: 10}
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 4, AutoThrottle: &cfg})
	l.Observe(ptr(429))
	l.Observe(ptr(503))
	l.Observe(ptr(200))
	l.Observe(ptr(429))
	l.Observe(ptr(429))
	if l.IsThrottled() {
		t.Fatal("the 200 should have reset the run, leaving only two")
	}
	l.Observe(ptr(429))
	if !l.IsThrottled() {
		t.Fatal("and three after the reset should trip it")
	}
}

func TestTheReducedRateLastsExactlyRecoverAfterGrantsAndThenRecovers(t *testing.T) {
	rps := 10.0
	cfg := AutoThrottle{Statuses: []int{429}, After: 1, Factor: 4.0, RecoverAfter: 5}
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 4, AutoThrottle: &cfg})
	l.Observe(ptr(429))
	if !l.IsThrottled() {
		t.Fatal("after=1 must engage immediately")
	}
	for i := 0; i < 5; i++ {
		if !l.IsThrottled() {
			t.Fatalf("recovered early, after %d grants", i)
		}
		l.reserve(time.Now())
	}
	if l.IsThrottled() {
		t.Fatal("5 grants should have used the window up")
	}
	// The next wait is priced at the operator's rate, not the reduced one. The five
	// throttled grants drove the bucket to -4 tokens; this grant takes it to -5. Paying
	// that debt at 10/s is 500ms, and at the reduced 2.5/s it would be 2s.
	wait := l.reserve(time.Now())
	if wait <= 450*time.Millisecond || wait >= 550*time.Millisecond {
		t.Fatalf("expected the 5-token debt priced at 10/s (~500ms); %v is the reduced rate still in force", wait)
	}
}

func TestASendWithNoStatusNeitherTripsNorResetsTheThrottle(t *testing.T) {
	rps := 10.0
	cfg := AutoThrottle{Statuses: []int{429}, After: 2, Factor: 2.0, RecoverAfter: 5}
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 4, AutoThrottle: &cfg})
	l.Observe(ptr(429))
	l.Observe(nil)
	if l.IsThrottled() {
		t.Fatal("an error must not trip it on its own")
	}
	l.Observe(ptr(429))
	if !l.IsThrottled() {
		t.Fatal("and must not have reset the run either")
	}
}

func TestAnAbsurdFactorCannotStallTheAttackAndAnInvertedOneCannotSpeedItUp(t *testing.T) {
	rps := 20.0
	slow := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 4,
		AutoThrottle: &AutoThrottle{Statuses: []int{429}, After: 1, Factor: 1e9, RecoverAfter: 100}})
	slow.Observe(ptr(429))
	if wait := slow.reserve(time.Now()); wait > 100*time.Second {
		t.Fatalf("the floor did not hold: %v", wait)
	}

	fastRps := 10.0
	fast := NewRateLimiter(&RateLimit{PerSecond: &fastRps, Burst: 1, MaxInFlight: 4,
		AutoThrottle: &AutoThrottle{Statuses: []int{429}, After: 1, Factor: 0.1, RecoverAfter: 100}})
	fast.Observe(ptr(429))
	_ = fast.reserve(time.Now()) // spend the burst
	if wait := fast.reserve(time.Now()); wait <= 90*time.Millisecond {
		t.Fatalf("an auto-throttle made the attack faster: %v", wait)
	}
}

func TestAnAutoThrottleOverAnUncappedRateIsInertAndSaysSoByNeverWaiting(t *testing.T) {
	l := NewRateLimiter(&RateLimit{PerSecond: nil, Burst: 1, MaxInFlight: 4,
		AutoThrottle: &AutoThrottle{Statuses: []int{429}, After: 1, Factor: 100.0, RecoverAfter: 100}})
	l.Observe(ptr(429))
	if l.AutoThrottleEngaged() != 1 {
		t.Fatal("it still engaged")
	}
	if wait := l.reserve(time.Now()); wait != 0 {
		t.Fatalf("but with no rate cap there is no wait to lengthen, got %v", wait)
	}
}

func TestAPoolNameIsCarriedThroughAndChangesNothingElse(t *testing.T) {
	rps := 10.0
	l := NewRateLimiter(&RateLimit{PerSecond: &rps, Burst: 1, MaxInFlight: 7, Name: "slow"})
	if got := l.PoolName(); got != "slow" {
		t.Fatalf("pool name = %q, want slow", got)
	}
	if got := l.AvailableSlots(); got != 7 {
		t.Fatalf("available slots = %d, want 7", got)
	}
	if wait := l.reserve(time.Now()); wait != 0 {
		t.Fatalf("unexpected wait %v", wait)
	}
}
