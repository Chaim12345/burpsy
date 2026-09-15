package intruder

// Rate limiting and in-flight bounds for attacks, ported from burpsy-intruder::limit.
//
// # Why this is a correctness feature
//
// An attack tool that ignores rate limits is not "fast", it is broken. Firing unbounded
// parallel requests at an authorised target gets the operator's source blocked, fills the
// target's database with junk, or takes the service down. So the limiter is not a politeness
// knob bolted onto the engine; the engine cannot send a request without going through it.
//
// # Two independent bounds
//
//   - requests per second: a token bucket, which bounds throughput over time;
//   - max in flight: a semaphore, which bounds concurrency and therefore how many sockets and
//     how much spliced-request memory exist at once.
//
// They are not redundant. A rate cap alone still permits 500 simultaneous slow requests once a
// second's worth of tokens accumulates; a concurrency cap alone still permits thousands of
// requests per second if the target answers quickly.
//
// # The bound the bucket guarantees
//
// Tokens accrue at per_second and are capped at burst, and every grant costs exactly one token.
// Therefore in any window of length T the limiter grants at most burst + per_second*T requests.
// That is the property the tests measure, not an approximation of it.
//
// # Resource pools: a name, and a reaction to the target
//
// RateLimit.Name is an identifier the caller sets and gets back in the report. It does not make
// two attacks share a bucket, and this package keeps no registry of pools: an attack gets one
// RateLimiter, and cross-attack state belongs to whichever layer owns the attacks.
//
// internal/pool is that layer. It owns names, lifetimes and persistence, and resolves a saved pool
// to exactly one RateLimit — so a *named* pool is a resolution step in front of this type, never a
// second limiter beside it. Nothing was moved down here to make that work: this file still has no
// map from name to anything.
//
// AutoThrottle reacts to the target. N consecutive responses with a status the operator listed
// (429 and 503 by default) divide the rate for the next M grants, then it recovers. This is the
// reason a limiter needs Observe: a token bucket that only ever hears about sends cannot notice
// that the target has started refusing them. It is opt-in for exactly that reason: with no
// AutoThrottle configured, every code path here behaves as it did before it existed.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

// MIN_THROTTLED_RPS is the floor on the rate an AutoThrottle may reduce to.
//
// A factor of 1e9 would otherwise turn a 20/s attack into one request every 578 days, which is
// indistinguishable from a hang.
const MIN_THROTTLED_RPS = 0.01

// MAX_WAIT is the ceiling on a single computed wait.
//
// An hour is already far past the point where an operator would conclude the attack has stalled,
// so clamping here loses nothing real and keeps the arithmetic total.
const MAX_WAIT = time.Hour

// RateLimit holds operator-controlled bounds on how hard an attack is allowed to hit the target.
type RateLimit struct {
	// PerSecond is the requests per second. nil removes the rate cap; MaxInFlight still applies.
	// A pointer rather than a sentinel because "no rate cap" must be a decision someone typed, not
	// a value that arises from a zero or an unset field.
	PerSecond *float64
	// Burst is how many requests may go out back-to-back after an idle period. 1 means strict
	// spacing. Treated as 1 when zero.
	Burst int
	// MaxInFlight is the maximum requests in flight at once. Treated as 1 when zero.
	MaxInFlight int
	// Name is the operator's name for this pool, echoed back in AttackReport.Pool. An identifier,
	// not a handle: nothing here looks it up, and two attacks naming the same pool still get
	// independent buckets.
	Name string
	// AutoThrottle cuts the rate when the target starts saying no. nil is the default and changes
	// nothing.
	AutoThrottle *AutoThrottle
	// variation is the delay schedule, unexported so the only way to set one is WithVariation,
	// which refuses the combinations this limiter cannot honour and hands the refusal back as an
	// error. A settable field would have to be checked by NewRateLimiter, which cannot return an
	// error and would therefore have to either panic or quietly pace the attack at a rate nobody
	// chose. Copying a RateLimit copies the pointer, which is what every caller that passes one
	// around by value already expects of AutoThrottle.
	variation *DelayVariation
}

// DelayVariation is Burp's "With random variations" and its per-request delay increment: the two
// ways a resource pool's spacing stops being a constant.
//
// # Why an attack wants a delay that is not flat
//
// A constant rate is a signature. A lockout counter that a flat 20/s trips at request N trips at
// request N on every run, and inter-arrival times that never move are what a defender's graph is
// looking at when it decides this is a tool rather than a person. Burp offers the two variations
// for that reason and they answer different questions: the jitter hides the shape of the traffic,
// the increment backs the whole attack off as it goes, so a run that starts inside the target's
// budget stays inside it as the window fills.
//
// # What it does to the limiter
//
// A variation REPLACES the token bucket's spacing with an explicit schedule. The k-th gap between
// requests (k from 0, so gap 0 is the one after the first request) is
//
//	interval_k = (1/rps + k*IncrementMS) * (1 + Jitter*u_k),   u_k uniform in [-1, 1)
//
// and the grant after gap k is released interval_k after the previous grant was scheduled.
//
// The bucket is bypassed rather than layered under this, because the two cannot both hold: the
// bucket's guarantee is that no gap is ever shorter than 1/rps, and half of what jitter means is
// gaps shorter than that. Taking the larger of the two waits would keep the guarantee and throw
// away the feature — every downward draw eaten, leaving a variation that only ever slows the
// attack down. So with a variation configured the rate the operator typed is the rate the gaps are
// drawn around rather than a per-window ceiling, which is what asking for variation says.
//
// One consequence worth stating: a gap is counted from when the caller comes back for its next
// grant, which is after the previous request finished, so the realised rate is the nominal one
// minus however long each request took. That is Burp's own "delay between requests" and not a
// drift — but it does mean a varied pool on a slow target runs a little under its nominal rate,
// where the bucket would have refilled through the wait and held it. Measured live at 10/s on the
// fixture: a flat pool's gaps were 100.7/101.0/99.1/101.0/99.0ms, and the same pool with a 50ms
// increment 102.7/153.3/203.0/256.7/304.7ms.
//
// With no variation — the nil default, and every caller that has ever existed — not one line of
// this runs and the bucket is exactly what it was.
//
// # Seeded, because a timing claim has to be checkable
//
// u_k comes from a PCG generator seeded with Seed, so the schedule is a function of the seed and
// the grant order and nothing else. The same seed replays the same delays, which is what lets a
// test assert the delays an attack actually took rather than assert that some randomness happened.
type DelayVariation struct {
	// Jitter is the fraction of the nominal interval a gap may vary by, up or down: 0.25 is
	// Burp's ±25%. Must be below 1 — at 1 a draw of -1 is a zero interval and above it a
	// negative one, and neither is a delay anything can wait for.
	Jitter float64 `json:"jitter"`
	// IncrementMS is Burp's throttleIncrementMillis: every gap is this many milliseconds longer
	// than the one before it. Must not be negative. A ramp that shortens each gap reaches zero
	// and then goes negative, and the request that follows a negative delay is not a slower
	// attack, it is an unbounded one.
	IncrementMS int `json:"increment_ms"`
	// Seed seeds the jitter. 0 is a seed like any other, not "unseeded": an operator who never
	// names one still gets a schedule that can be replayed, and one who wants a different shape
	// of traffic per run names a different seed.
	Seed uint64 `json:"seed"`
}

// variationSeedStream is the second half of the PCG state. PCG takes two 64-bit words and a seed
// of (0, 0) is a legal but degenerate state, so the operator's seed is paired with a fixed
// non-zero constant rather than with a zero.
const variationSeedStream uint64 = 0x9e3779b97f4a7c15

// Variation is the delay schedule this limit carries, or nil for the flat spacing every pool had
// before. Read-only by design — see RateLimit.variation.
func (l RateLimit) Variation() *DelayVariation { return l.variation }

// WithVariation attaches Burp's delay variations, or refuses them with a reason. nil removes one.
//
// It returns an error rather than clamping because every one of the refused combinations is a
// request for something this limiter cannot do, and the operator's next move depends on which:
// a jitter of 1.5 is not "as much jitter as possible", and a variation on an uncapped rate is not
// "a little variation on nothing".
func (l RateLimit) WithVariation(v *DelayVariation) (RateLimit, error) {
	l.variation = v
	if err := l.ValidateVariation(); err != nil {
		return RateLimit{}, err
	}
	return l, nil
}

// ValidateVariation reports why this limit's variation cannot be honoured, or nil. Always nil when
// no variation is set.
func (l RateLimit) ValidateVariation() error {
	v := l.variation
	if v == nil {
		return nil
	}
	switch {
	case math.IsNaN(v.Jitter) || math.IsInf(v.Jitter, 0):
		return fmt.Errorf("delay variation: a jitter of %v is not a number", v.Jitter)
	case v.Jitter < 0:
		return fmt.Errorf("delay variation: a jitter of %v is negative; it is the fraction of the interval a gap may move either way, so 0 is a fixed delay and 0.25 is Burp's ±25%%", v.Jitter)
	case v.Jitter >= 1:
		return fmt.Errorf("delay variation: a jitter of %v is 1 or more, so a downward draw would schedule a zero or negative gap; the largest variation that is still a delay is just under 1", v.Jitter)
	case v.IncrementMS < 0:
		return fmt.Errorf("delay variation: an increment of %dms shortens every gap until the interval reaches zero and then goes negative; Burp's increment only increases the delay", v.IncrementMS)
	case v.Jitter == 0 && v.IncrementMS == 0:
		return errors.New("delay variation: neither a jitter nor an increment was given, so there is nothing to vary; leave the variation off for a fixed delay")
	case l.PerSecond == nil || *l.PerSecond <= 0:
		return errors.New("delay variation: there is no rate cap to vary; a variation scales the interval between requests, and a pool with no rate has no interval")
	case l.Burst > 1:
		return fmt.Errorf("delay variation: a burst of %d and a varying delay are two answers to when the next request may go — the burst says several at once, the schedule spaces every one of them; set burst to 1 to vary the delay", l.Burst)
	}
	return nil
}

// NewRateLimit builds a limit with the two independent bounds. Use Unthrottled for
// concurrency only.
func NewRateLimit(perSecond *float64, burst, maxInFlight int) RateLimit {
	return RateLimit{PerSecond: perSecond, Burst: burst, MaxInFlight: maxInFlight}
}

// Unthrottled is concurrency only, no rate cap. Named so it reads as a decision at the call site.
func Unthrottled(maxInFlight int) RateLimit {
	return RateLimit{PerSecond: nil, Burst: 1, MaxInFlight: maxInFlight}
}

// Named labels this pool. See RateLimit.Name for what the label does and does not do.
func (l RateLimit) Named(name string) RateLimit {
	l.Name = name
	return l
}

// WithAutoThrottle attaches a reaction to the target. nil means none.
func (l RateLimit) WithAutoThrottle(cfg *AutoThrottle) RateLimit {
	l.AutoThrottle = cfg
	return l
}

// DefaultRateLimit is deliberately timid. An operator who wants 200 rps on an engagement that
// authorises it can say so; nobody should discover their default was "as fast as the network
// allows" from the target's incident channel.
func DefaultRateLimit() RateLimit {
	per := 20.0
	return RateLimit{PerSecond: &per, Burst: 1, MaxInFlight: 10}
}

// AutoThrottle backs off when the target starts refusing requests.
//
// Consecutive: a single 503 on a busy target is noise, and reacting to it would make the rate
// jitter for no reason. A run of them is the target telling you something. Any non-listed status
// resets the run, so one good response ends it.
//
// Grants, not seconds: the thing being recovered from is a rate, and "slower for the next N
// requests" is a bound the operator can reason about against the size of their attack.
type AutoThrottle struct {
	// Statuses are the statuses that mean "slow down".
	Statuses []int `json:"statuses"`
	// After is how many consecutive listed responses precede a rate cut. Zero is treated as one.
	After int `json:"after"`
	// Factor is what the rate is divided by while throttled. Values below 1 would raise the rate,
	// which is never what an operator means here, so they are clamped to 1 (no change).
	Factor float64 `json:"factor"`
	// RecoverAfter is how many grants the reduced rate lasts for before it recovers.
	RecoverAfter int `json:"recover_after"`
}

// DefaultAutoThrottle: 429 is the status that exists to say this; 503 is what a target says when
// it is the truth rather than a policy. Three in a row, at half rate, for fifty requests.
func DefaultAutoThrottle() *AutoThrottle {
	return &AutoThrottle{Statuses: []int{429, 503}, After: 3, Factor: 2.0, RecoverAfter: 50}
}

// Permit is a held in-flight slot. Release returns it; holding it *is* being in flight.
type Permit struct {
	limiter  *RateLimiter
	released bool
}

// Release returns the in-flight slot to the pool. Idempotent.
func (p *Permit) Release() {
	if p == nil || p.released {
		return
	}
	p.released = true
	<-p.limiter.slots
}

// RateLimiter is the gate every request must pass through.
type RateLimiter struct {
	perSecond float64
	burst     float64
	mu        sync.Mutex
	tokens    float64
	last      time.Time
	slots     chan struct{}
	name      string
	auto      *autoState
	// variation is the delay schedule, nil for the flat bucket. Guarded by mu, the bucket's own
	// lock, because it is read and advanced only inside reserve — which already holds it — so a
	// varied pool grows no second lock and no lock order to get wrong.
	variation *variationState
}

// variationState is the running delay schedule: where the next grant is due, how many gaps have
// been scheduled (the ramp's index and the jitter's draw index, which are the same number), and
// the seeded generator the draws come from.
type variationState struct {
	jitter  float64
	inc     time.Duration
	rnd     *rand.Rand
	gaps    int
	started bool
	nextAt  time.Time
}

// autoState is the auto-throttle's running state. Its own lock, so an attack with no auto-throttle
// configured never touches it — auto is nil and every path short-circuits before this exists.
type autoState struct {
	mu          sync.Mutex
	cfg         AutoThrottle
	consecutive int
	remaining   int
	engaged     int
}

// NewRateLimiter builds a limiter from a limit. A burst of 0 would mean even the very first
// request waits, which is never what anyone means; and 0 in-flight slots would deadlock rather
// than throttle, so both are raised to 1.
func NewRateLimiter(limit *RateLimit) *RateLimiter {
	burst := float64(limit.Burst)
	if burst < 1 {
		burst = 1
	}
	slots := limit.MaxInFlight
	if slots < 1 {
		slots = 1
	}
	var per float64
	if limit.PerSecond != nil {
		per = *limit.PerSecond
		if per < 0 {
			per = 0
		}
	}
	l := &RateLimiter{
		perSecond: per,
		burst:     burst,
		tokens:    burst,
		last:      time.Now(),
		slots:     make(chan struct{}, slots),
		name:      limit.Name,
	}
	if limit.AutoThrottle != nil {
		l.auto = &autoState{cfg: *limit.AutoThrottle}
	}
	// No validation here, and none needed: RateLimit.variation is unexported and WithVariation is
	// the only thing that sets it, so anything that reaches this line was refused or accepted
	// already.
	if v := limit.variation; v != nil {
		l.variation = &variationState{
			jitter: v.Jitter,
			inc:    time.Duration(v.IncrementMS) * time.Millisecond,
			rnd:    rand.New(rand.NewPCG(v.Seed, v.Seed^variationSeedStream)),
		}
	}
	return l
}

// Acquire waits until this request may be sent. Holding the returned Permit is being in flight.
//
// The in-flight slot is taken first and the rate token last, so the token is spent as close as
// possible to the actual send. Spending it earlier would let budget accrue while a caller is
// stuck waiting for a socket, and the attack would then burst to catch up.
func (l *RateLimiter) Acquire() *Permit {
	l.slots <- struct{}{}
	if wait := l.reserve(time.Now()); wait > 0 {
		time.Sleep(wait)
	}
	return &Permit{limiter: l}
}

// Pace is Acquire for a caller that has a context, returning the release function rather than a
// Permit. It is the shape sender.Pacer requires, so a limiter can be handed to an AuthorisedSender
// and bound every send that leaves through it — which is how a *named* resource pool reaches the
// audit path, where there is no driver loop of the intruder's shape to put an Acquire in.
//
// Two departures from Acquire, both because a context exists here and did not there:
//
//   - the in-flight slot is waited for on a select, so a caller queued behind a full pool is
//     released by cancellation instead of waiting for a slot that may never come;
//   - the rate wait is a timer, not a Sleep, for the same reason. A pool with a large delay between
//     requests would otherwise make a cancelled audit sit out its whole spacing before noticing —
//     one request's delay per queued worker, which on a wide pool is the difference between stopping
//     and appearing to hang.
//
// The slot is returned before returning the error, so a cancellation between taking the slot and
// finishing the wait does not leak it. The returned release is never nil on success and is
// idempotent, matching Permit.Release.
func (l *RateLimiter) Pace(ctx context.Context) (func(), error) {
	select {
	case l.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	permit := &Permit{limiter: l}
	if wait := l.reserve(time.Now()); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			permit.Release()
			return nil, ctx.Err()
		}
	}
	return permit.Release, nil
}

// reserve charges one request to the bucket and returns how long the caller must wait to spend it.
//
// Reservation, not polling: a caller that finds the bucket empty still takes its token and drives
// the balance negative, so the next caller queues behind it with a longer deadline. Without that,
// N concurrent waiters would all wake on the same refill and the burst would be N, not burst.
// A rate with no cap never imposes a wait.
func (l *RateLimiter) reserve(now time.Time) time.Duration {
	if l.perSecond <= 0 {
		return 0
	}
	// Consulted before the bucket lock is taken, so the two mutexes are never held at once and
	// there is no lock order to get wrong. Observe only ever takes the auto lock.
	rps := l.chargeThrottle(l.perSecond)
	// A varied pool is paced by its schedule instead of by the bucket — see DelayVariation for why
	// the two cannot both hold. The throttled rate is what the schedule's nominal interval is
	// derived from, so the two features compose: a target that says 429 doubles the interval, and
	// the jitter and the ramp then apply to the doubled one.
	if l.variation != nil {
		return l.reserveVaried(now, rps)
	}
	l.mu.Lock()
	elapsed := now.Sub(l.last).Seconds()
	l.last = now
	l.tokens = math.Min(l.tokens+elapsed*rps, l.burst) - 1.0
	if l.tokens >= 0 {
		l.mu.Unlock()
		return 0
	}
	// Clamp to the ceiling: a very small rps makes -tokens/rps arbitrarily large, and an
	// unrepresentable wait must saturate, not panic or overflow.
	wait := -l.tokens / rps
	l.mu.Unlock()
	if wait >= MAX_WAIT.Seconds() {
		return MAX_WAIT
	}
	return time.Duration(wait * float64(time.Second))
}

// reserveVaried is reserve for a pool with a delay schedule: it books this grant into the schedule
// and returns how long the caller must wait for its slot.
//
// Scheduled from the later of the last slot and now, so a run whose sends take longer than their
// gap does not accumulate a debt and then discharge it as a burst — the thing a variation exists
// to avoid. A caller that waits exactly the returned duration therefore sees gap k land exactly
// interval_k after gap k-1, which is the property the tests assert.
func (l *RateLimiter) reserveVaried(now time.Time, rps float64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := l.variation
	if !v.started {
		// The first grant has no gap in front of it — the same "the first request does not wait"
		// the burst token gives an unvaried pool — and it draws no jitter, so draw k is gap k.
		v.started = true
		v.nextAt = now
		return 0
	}
	interval := 1/rps + float64(v.gaps)*v.inc.Seconds()
	if v.jitter > 0 {
		// Float64 is [0, 1), so u is [-1, 1) and the interval stays positive for any jitter the
		// validation allowed.
		interval *= 1 + v.jitter*(2*v.rnd.Float64()-1)
	}
	v.gaps++
	gap := time.Duration(interval * float64(time.Second))
	// The same ceiling the bucket clamps to, applied to the interval rather than to the wait: a
	// ramp that has run long enough to pass an hour a request must not push the schedule further
	// and further into a future the attack will never reach.
	if gap > MAX_WAIT {
		gap = MAX_WAIT
	}
	from := v.nextAt
	if from.Before(now) {
		from = now
	}
	v.nextAt = from.Add(gap)
	wait := v.nextAt.Sub(now)
	if wait <= 0 {
		return 0
	}
	return wait
}

// chargeThrottle returns the rate this grant is charged at, spending one grant of any active
// throttle. It returns rps untouched — with no lock taken and no state read — when no AutoThrottle
// was configured. That is the guarantee that makes this safe to put in the path every attack uses.
func (l *RateLimiter) chargeThrottle(rps float64) float64 {
	if l.auto == nil {
		return rps
	}
	st := l.auto
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.remaining == 0 {
		return rps
	}
	st.remaining--
	factor := st.cfg.Factor
	if factor < 1 {
		factor = 1
	}
	reduced := rps / factor
	if reduced < MIN_THROTTLED_RPS {
		reduced = MIN_THROTTLED_RPS
	}
	return reduced
}

// Observe tells the limiter what the target answered. A no-op when no AutoThrottle is configured,
// and a no-op for a send that produced no status at all: a connection error is not the target
// asking to be treated more gently, and treating it as one would make an unreachable host look like
// a rate limit. It does not reset the run either, for the same reason: a transport failure is
// silence, not a "no".
func (l *RateLimiter) Observe(status *int) {
	if l.auto == nil || status == nil {
		return
	}
	st := l.auto
	st.mu.Lock()
	defer st.mu.Unlock()
	listed := false
	for _, s := range st.cfg.Statuses {
		if s == *status {
			listed = true
			break
		}
	}
	if listed {
		st.consecutive++
		after := st.cfg.After
		if after < 1 {
			after = 1
		}
		if st.consecutive >= after {
			st.consecutive = 0
			// Re-arm rather than extend: a target still refusing after the window keeps the reduced
			// rate, and the engagement count says how often that happened.
			st.remaining = st.cfg.RecoverAfter
			st.engaged++
		}
	} else {
		st.consecutive = 0
	}
}

// AutoThrottleEngaged reports how many times the auto-throttle engaged. Always 0 when none was
// configured.
func (l *RateLimiter) AutoThrottleEngaged() int {
	if l.auto == nil {
		return 0
	}
	l.auto.mu.Lock()
	defer l.auto.mu.Unlock()
	return l.auto.engaged
}

// IsThrottled is true while the reduced rate is in force.
func (l *RateLimiter) IsThrottled() bool {
	if l.auto == nil {
		return false
	}
	l.auto.mu.Lock()
	defer l.auto.mu.Unlock()
	return l.auto.remaining > 0
}

// PoolName returns the operator's name for this pool, if they gave one.
func (l *RateLimiter) PoolName() string { return l.name }

// AvailableSlots reports slots currently free. Exposed so callers can report progress, not to make
// decisions with.
func (l *RateLimiter) AvailableSlots() int { return cap(l.slots) - len(l.slots) }
