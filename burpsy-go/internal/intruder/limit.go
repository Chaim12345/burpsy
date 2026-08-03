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
// AutoThrottle reacts to the target. N consecutive responses with a status the operator listed
// (429 and 503 by default) divide the rate for the next M grants, then it recovers. This is the
// reason a limiter needs Observe: a token bucket that only ever hears about sends cannot notice
// that the target has started refusing them. It is opt-in for exactly that reason: with no
// AutoThrottle configured, every code path here behaves as it did before it existed.

import (
	"math"
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
