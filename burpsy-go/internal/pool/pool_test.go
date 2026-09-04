package pool

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The one thing a named pool must actually do: bound concurrency.
//
// Everything else in this package is bookkeeping around this. ROADMAP.md's reason for a limiter is
// that unbounded parallelism DoSes the target, so a pool that saves "max 2 concurrent requests" and
// then admits 8 at once is worse than no pool at all — it reports a bound the target is not getting.
// This drives real goroutines through the real limiter rather than asserting on the RateLimit value,
// because a value that *says* MaxInFlight 2 is exactly what a broken wiring would also produce.
func Test_a_named_pool_bounds_concurrency_to_what_was_saved(t *testing.T) {
	reg := New()
	// No delay: this test is about the in-flight ceiling alone, and a rate cap would make it a test of
	// the token bucket's timing instead. Throttle off for the same reason — Validate refuses a
	// throttle with no delay, which is itself the point of Test_automatic_throttling_needs_a_delay.
	if err := reg.Add(Pool{Name: "two at a time", MaxConcurrent: 2}); err != nil {
		t.Fatalf("saving the pool: %v", err)
	}
	limiter, err := reg.Limiter("two at a time")
	if err != nil {
		t.Fatalf("resolving the pool: %v", err)
	}

	var live, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := limiter.Pace(context.Background())
			if err != nil {
				t.Errorf("Pace returned %v; nothing here cancels", err)
				return
			}
			defer release()
			now := live.Add(1)
			// A high-water mark rather than a sampled count: the failure this guards against is a
			// momentary excess, and a check of the instantaneous value could miss it.
			for {
				was := peak.Load()
				if now <= was || peak.CompareAndSwap(was, now) {
					break
				}
			}
			// Long enough that sixteen unbounded goroutines would overlap. Not a synchronisation
			// mechanism — the assertion is on the peak, which is monotonic, so a slow scheduler makes
			// this test weaker rather than flaky.
			time.Sleep(2 * time.Millisecond)
			live.Add(-1)
		}()
	}
	wg.Wait()

	if got := peak.Load(); got > 2 {
		t.Errorf("%d requests were in flight at once under a pool whose saved ceiling is 2.\n"+
			"The pool resolved to a limiter that is not enforcing MaxInFlight, which means every tool "+
			"running under it is sending more traffic than the operator authorised.", got)
	}
	if peak.Load() == 0 {
		t.Error("no request was ever in flight, so this test proved nothing about the ceiling")
	}
}

// Two runs under one pool contend for that pool's slots, rather than getting a full allowance each.
//
// This is the difference between a named pool and the inline limits that came before it. If the
// registry handed out a fresh limiter per resolution, two audits under a pool of two would send four
// at once and each would be individually "within limits" — the bound would be per caller, which is
// not what a shared object means.
func Test_two_runs_under_one_pool_share_its_slots(t *testing.T) {
	reg := New()
	if err := reg.Add(Pool{Name: "shared", MaxConcurrent: 1}); err != nil {
		t.Fatalf("saving the pool: %v", err)
	}
	first, err := reg.Limiter("shared")
	if err != nil {
		t.Fatalf("first resolution: %v", err)
	}
	second, err := reg.Limiter("shared")
	if err != nil {
		t.Fatalf("second resolution: %v", err)
	}
	if first != second {
		t.Fatal("two resolutions of one pool name returned two limiters, so two tools under this pool " +
			"would each get its whole allowance and together exceed it")
	}

	// And the shared limiter really is exclusive: with the one slot held, a second Pace must not
	// proceed. Proven by cancellation rather than by a timeout, so there is no sleep deciding the
	// verdict — if the slot were free, Pace would return before the context is even consulted.
	release, err := first.Pace(context.Background())
	if err != nil {
		t.Fatalf("taking the only slot: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := second.Pace(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("a second Pace on a full pool of 1 returned %v, want context.Canceled: the slot the "+
			"first caller holds was not exclusive", err)
	}
	release()
	// Released means reusable, which is the other half of the contract: a limiter that never gave a
	// slot back would look like a working bound and be a deadlock.
	if _, err := second.Pace(context.Background()); err != nil {
		t.Errorf("after the slot was released, Pace returned %v; the release did not free it", err)
	}
}

// An edited pool means the next run gets the new bounds, not the ones a cached limiter was built
// from. Work already in flight keeps its limiter, which is the documented and deliberate half.
func Test_editing_a_pool_replaces_its_limiter(t *testing.T) {
	reg := New()
	if err := reg.Add(Pool{Name: "p", MaxConcurrent: 1}); err != nil {
		t.Fatalf("saving: %v", err)
	}
	before, err := reg.Limiter("p")
	if err != nil {
		t.Fatalf("first resolution: %v", err)
	}
	if err := reg.Update("p", Pool{Name: "p", MaxConcurrent: 4}); err != nil {
		t.Fatalf("editing: %v", err)
	}
	after, err := reg.Limiter("p")
	if err != nil {
		t.Fatalf("resolution after the edit: %v", err)
	}
	if before == after {
		t.Fatal("the pool's limiter survived an edit to its bounds, so the saved ceiling and the " +
			"enforced one have diverged: the panel would show 4 and the target would get 1")
	}
	// A rename must stop the old name resolving, or a tool referencing it would keep running under a
	// pool the operator believes they renamed.
	if err := reg.Update("p", Pool{Name: "q", MaxConcurrent: 4}); err != nil {
		t.Fatalf("renaming: %v", err)
	}
	if _, err := reg.Limiter("p"); !errors.Is(err, ErrNoSuchPool) {
		t.Errorf("the old name still resolves after a rename (%v), so a stale reference would run "+
			"under bounds nobody can see", err)
	}
}

// A name nothing holds is an error, never a limiter with default bounds.
//
// This is the failure the package docs single out: a tool that quietly fell back would run unbounded
// traffic while the operator believed a pool was in force.
func Test_an_unsaved_pool_name_is_refused_rather_than_defaulted(t *testing.T) {
	reg := New()
	if _, err := reg.Limiter("never saved"); !errors.Is(err, ErrNoSuchPool) {
		t.Errorf("resolving an unsaved name returned %v, want ErrNoSuchPool", err)
	}
	if _, err := reg.Limit("never saved"); !errors.Is(err, ErrNoSuchPool) {
		t.Errorf("Limit on an unsaved name returned %v, want ErrNoSuchPool", err)
	}
}

// The delay-to-factor translation is exact, which is what makes it a translation rather than an
// approximation. See Throttle's derivation: raising a delay of D by I divides the rate by (D+I)/D.
func Test_the_throttle_increment_becomes_an_exact_rate_divisor(t *testing.T) {
	p := Pool{Name: "p", MaxConcurrent: 1, DelayMs: 100, Throttle: &Throttle{IncrementMs: 100}}
	rps, capped := p.RequestsPerSecond()
	if !capped || rps != 10 {
		t.Fatalf("a 100ms delay is %v requests a second (capped=%v), want 10", rps, capped)
	}
	factor, on := p.ThrottleFactor()
	if !on || factor != 2 {
		t.Fatalf("raising a 100ms delay by 100ms is a factor of %v, want exactly 2", factor)
	}
	limit := p.Limit()
	if limit.AutoThrottle == nil {
		t.Fatal("a pool with a throttle resolved to a limit with none")
	}
	// The defaults are the intruder's own, so a pool that leaves them unset behaves as an intruder
	// attack with auto-throttling on already did.
	if limit.AutoThrottle.After != DefaultThrottleAfter ||
		limit.AutoThrottle.RecoverAfter != DefaultThrottleRecoverAfter {
		t.Errorf("unset throttle parameters resolved to after=%d recover=%d, want %d and %d",
			limit.AutoThrottle.After, limit.AutoThrottle.RecoverAfter,
			DefaultThrottleAfter, DefaultThrottleRecoverAfter)
	}
	if limit.Burst != 1 {
		t.Errorf("burst is %d; a delay between requests means strict spacing, and a burst above 1 "+
			"would let requests go out back-to-back after an idle moment", limit.Burst)
	}
}

// Automatic throttling with no delay is refused rather than reinterpreted. There is no multiple of
// zero larger than zero, so the alternative would be this package inventing a rate.
func Test_automatic_throttling_needs_a_delay(t *testing.T) {
	err := Pool{Name: "p", MaxConcurrent: 1, DelayMs: 0, Throttle: &Throttle{IncrementMs: 50}}.Validate()
	if err == nil {
		t.Fatal("a throttle with no delay to increase was accepted; it cannot do anything, so saving " +
			"it as on would show the operator a safeguard that does nothing")
	}
}

// A pool with no delay is a real configuration — "concurrency only" — and is not the same as a pool
// with a rate of zero. The two-value return is what keeps them apart.
func Test_no_delay_means_no_rate_cap_not_a_rate_of_zero(t *testing.T) {
	p := Pool{Name: "p", MaxConcurrent: 4}
	if rps, capped := p.RequestsPerSecond(); capped {
		t.Errorf("a pool with no delay reported a rate cap of %v", rps)
	}
	if p.Limit().PerSecond != nil {
		t.Error("a pool with no delay resolved to a limit with a rate cap, which would impose a bound " +
			"the operator explicitly did not set")
	}
}

// Validation runs on load, not only on save, so a pool written before a check existed is refused
// with its reason instead of being installed as an exception to the rule — and the refusals are
// returned rather than logged and dropped.
func Test_restore_reports_what_it_refused(t *testing.T) {
	reg := New()
	refused := reg.Restore([]Pool{
		{Name: "good", MaxConcurrent: 2, DelayMs: 50},
		{Name: "", MaxConcurrent: 2},     // no name: nothing could reference it
		{Name: "bad", MaxConcurrent: 0},  // would deadlock rather than throttle
		{Name: "GOOD", MaxConcurrent: 1}, // duplicate of "good", case-insensitively
	})
	if len(refused) != 3 {
		t.Errorf("Restore refused %d pools, want 3: %v", len(refused), refused)
	}
	if reg.Len() != 1 {
		t.Errorf("%d pools were restored, want 1 — the rest were malformed and must not be installed",
			reg.Len())
	}
	if _, err := reg.Get("good"); err != nil {
		t.Errorf("the one valid pool was not restored: %v", err)
	}
}

// Order is preserved across a restore, because a list that reshuffles itself on every restart is a
// list nobody can navigate.
func Test_restore_keeps_the_operators_order(t *testing.T) {
	reg := New()
	reg.Restore([]Pool{{Name: "third", MaxConcurrent: 1}, {Name: "first", MaxConcurrent: 1}})
	got := reg.List()
	if len(got) != 2 || got[0].Name != "third" || got[1].Name != "first" {
		t.Errorf("restored order is %v, want the order it was given (third, first)", got)
	}
}

// A name differing only in case is the same pool. Two pools called "Default" and "default" would be
// a trap: an operator naming one would get the other's bounds.
func Test_pool_names_are_case_insensitive(t *testing.T) {
	reg := New()
	if err := reg.Add(Pool{Name: "Out Of Hours", MaxConcurrent: 1}); err != nil {
		t.Fatalf("saving: %v", err)
	}
	if err := reg.Add(Pool{Name: "out of hours", MaxConcurrent: 9}); !errors.Is(err, ErrDuplicateName) {
		t.Errorf("a name differing only in case was accepted as a second pool (%v)", err)
	}
	p, err := reg.Get("OUT OF HOURS")
	if err != nil {
		t.Fatalf("looking up a differently-cased name: %v", err)
	}
	if p.Name != "Out Of Hours" {
		t.Errorf("the stored name is %q; the operator's own capitalisation should be kept", p.Name)
	}
}

// Every tool path that accepts a pool name states which of the pool's bounds it honours. The table is
// data precisely so this can be checked — a tool added without an entry fails here rather than
// leaving an operator to infer it from behaviour.
func Test_every_tool_states_which_pool_bounds_it_honours(t *testing.T) {
	rows := Support()
	if len(rows) == 0 {
		t.Fatal("no tool path declares its pool support")
	}
	seen := map[string]bool{}
	for _, h := range rows {
		if h.Tool == "" || h.Route == "" {
			t.Errorf("a support row names no tool or no route: %+v", h)
		}
		if seen[h.Route] {
			t.Errorf("route %q has two support rows, so which one describes it is undecidable", h.Route)
		}
		seen[h.Route] = true
		// The invariant that makes the table honest: a row that falls short of any bound must say why.
		// Without this, "not honoured" and "nobody filled this in" are the same value.
		if !h.Complete() && h.Detail == "" {
			t.Errorf("%s does not honour every pool bound and gives no detail; an operator reading this "+
				"would see a bound quietly not applying with no reason given", h.Tool)
		}
		if h.Complete() && h.Detail != "" {
			t.Errorf("%s honours every bound but carries a detail (%q); a caveat on a path with no "+
				"exception reads as an exception", h.Tool, h.Detail)
		}
	}
	// The count an honest surface leads with. Stated here so a tool silently gaining or losing an
	// exception is a deliberate edit to this number.
	if got := len(Unhonoured()); got != 1 {
		t.Errorf("%d tool paths cannot honour every pool bound, and this test expects 1 (the crawler, "+
			"whose loop is sequential). If a path was added or fixed, change this number and say why.", got)
	}
}

// The default a New dialog opens on is the intruder's own long-standing default, so the first pool an
// operator saves is not more aggressive than what the tools already did.
func Test_the_default_pool_is_valid_and_not_more_aggressive_than_the_status_quo(t *testing.T) {
	p := DefaultPool("first")
	if err := p.Validate(); err != nil {
		t.Fatalf("the default a New dialog offers does not validate: %v", err)
	}
	rps, capped := p.RequestsPerSecond()
	if !capped || rps != 20 {
		t.Errorf("the default pool runs at %v requests a second (capped=%v), want 20 — the intruder's "+
			"own default", rps, capped)
	}
	if p.Throttle == nil {
		t.Error("the default pool has automatic throttling off; nobody should discover that their " +
			"default was 'as fast as the network allows' from the target's incident channel")
	}
}

// The pacer bounds a send only when the context says which pool the work is under, and never invents
// a bound when it does not.
func Test_the_context_pacer_paces_only_what_names_a_pool(t *testing.T) {
	reg := New()
	if err := reg.Add(Pool{Name: "p", MaxConcurrent: 1}); err != nil {
		t.Fatalf("saving: %v", err)
	}
	limiter, err := reg.Limiter("p")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	// No pool in the context: unpaced, which is how every audit ran before pools existed. The release
	// must still be callable — Pacer's contract is that success always returns something safe.
	release, err := (ContextPacer{}).Pace(context.Background())
	if err != nil {
		t.Fatalf("an unpaced send returned %v", err)
	}
	if release == nil {
		t.Fatal("an unpaced send returned a nil release, which every call site would then have to guard")
	}
	release()

	// A pool in the context: the pacer takes that pool's slot, so a second call with the slot held and
	// a cancelled context must be refused rather than admitted.
	ctx := WithLimiter(context.Background(), limiter)
	held, err := (ContextPacer{}).Pace(ctx)
	if err != nil {
		t.Fatalf("the first paced send returned %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (ContextPacer{}).Pace(cancelled); !errors.Is(err, context.Canceled) {
		t.Errorf("a paced send on a full pool of 1 returned %v, want context.Canceled: the pacer is "+
			"not actually taking the pool's slot", err)
	}
	held()
}
