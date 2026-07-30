//! Rate limiting and in-flight bounds for attacks.
//!
//! # Why this is a correctness feature
//!
//! An attack tool that ignores rate limits is not "fast", it is broken. Firing unbounded parallel
//! requests at an authorised target gets the operator's source blocked, fills the target's database
//! with junk, or takes the service down — and on a real engagement that turns a valid test into an
//! incident. So the limiter is not a politeness knob bolted onto the engine; the engine cannot send
//! a request without going through it.
//!
//! Burp reaches the same conclusion, and enforces it: its resource-pool validator
//! (`burp.Zuwo.Zz`, teardown of 2026.7.1) rejects a pool configured with
//! `NEITHER_THROTTLING_NOR_CONCURRENCY_LIMIT_SELECTED`. You are not allowed to save "unbounded".
//!
//! # Two independent bounds
//!
//! * **requests per second** — a token bucket, which bounds *throughput* over time;
//! * **max in flight** — a semaphore, which bounds *concurrency* and therefore how many sockets and
//!   how much spliced-request memory exist at once.
//!
//! They are not redundant. A rate cap alone still permits 500 simultaneous slow requests once a
//! second's worth of tokens accumulates; a concurrency cap alone still permits thousands of requests
//! per second if the target answers quickly. Burp exposes exactly this pair —
//! `ResourcePoolConfiguration{concurrentRequestLimit, throttleDurationMillis, …}` (`burp.Zgao`).
//!
//! # Rate, not inter-request delay
//!
//! Burp's throttle is a *delay between requests* in milliseconds. That is a weaker bound than it
//! looks: with a concurrency limit of N, N workers each sleeping D ms produce `N/D` requests per
//! millisecond, so the aggregate rate rises with concurrency and the operator's mental model of
//! "one request every D ms" is wrong. A token bucket shared by all workers bounds the aggregate
//! directly, which is the number that matters to the target, and it stays correct when
//! `max_in_flight` changes.
//!
//! # The bound the bucket guarantees
//!
//! Tokens accrue at `per_second` and are capped at `burst`, and every grant costs exactly one token.
//! Therefore **in any window of length `T` the limiter grants at most `burst + per_second * T`
//! requests** — that is the property [`RateLimiter`]'s tests measure, not an approximation of it.
//!
//! # Resource pools: a name, and a reaction to the target
//!
//! Burp's unit of rate limiting is a named *resource pool* that several attacks can share
//! (`ResourcePoolConfiguration{name, concurrentRequestLimit, throttleDurationMillis, …}`,
//! `burp.Zgao`). Two parts of that are here and one deliberately is not:
//!
//! * [`RateLimit::name`] is an identifier the caller sets and gets back in the report. It does **not**
//!   make two attacks share a bucket, and this crate does not keep a registry of pools: an attack
//!   gets one [`RateLimiter`], and cross-attack state belongs to whichever layer owns the attacks
//!   (the web layer or the CLI), not to the thing that bounds a single one.
//! * [`AutoThrottle`] reacts to the target. N consecutive responses with a status the operator listed
//!   — 429 and 503 by default — divide the rate for the next M grants, then it recovers.
//!
//! The second one is the reason a limiter needs [`RateLimiter::observe`]: a token bucket that only
//! ever hears about *sends* cannot notice that the target has started refusing them. Burp's own
//! throttle is static, so this is a step past it, and it is opt-in for exactly that reason —
//! **with no [`AutoThrottle`] configured, every code path here behaves as it did before it existed.**

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Operator-controlled bounds on how hard an attack is allowed to hit the target.
///
/// No longer `Copy`, because [`RateLimit::name`] owns a `String`. Cheap to clone and cloned once per
/// attack, so the cost is a name's worth of bytes against a limiter that lives for the whole run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Requests per second. `None` removes the rate cap; `max_in_flight` still applies.
    ///
    /// `Option` rather than a sentinel because "no rate cap" must be a decision someone typed, not
    /// a value that arises from a zero or an unset field.
    pub per_second: Option<f64>,
    /// How many requests may go out back-to-back after an idle period. 1 means strict spacing.
    pub burst: u32,
    /// Maximum requests in flight at once.
    pub max_in_flight: usize,
    /// The operator's name for this pool, echoed back in [`crate::AttackReport::pool`].
    ///
    /// An identifier, not a handle: nothing here looks it up, and two attacks naming the same pool
    /// still get independent buckets. It exists so the layer above can offer "reuse my slow pool"
    /// without this crate growing a global registry — see the module note.
    #[serde(default)]
    pub name: Option<String>,
    /// Cut the rate when the target starts saying no. `None` is the default and changes nothing.
    #[serde(default)]
    pub auto_throttle: Option<AutoThrottle>,
}

impl Default for RateLimit {
    /// Deliberately timid. An operator who wants 200 rps on an engagement that authorises it can say
    /// so; nobody should discover their default was "as fast as the network allows" from the target's
    /// incident channel.
    fn default() -> Self {
        Self {
            per_second: Some(20.0),
            burst: 1,
            max_in_flight: 10,
            name: None,
            auto_throttle: None,
        }
    }
}

impl RateLimit {
    pub fn new(per_second: Option<f64>, burst: u32, max_in_flight: usize) -> Self {
        Self {
            per_second,
            burst,
            max_in_flight,
            name: None,
            auto_throttle: None,
        }
    }

    /// Concurrency only, no rate cap. Named so it reads as a decision at the call site.
    pub fn unthrottled(max_in_flight: usize) -> Self {
        Self {
            per_second: None,
            burst: 1,
            max_in_flight,
            name: None,
            auto_throttle: None,
        }
    }

    /// Label this pool. See [`RateLimit::name`] for what the label does and does not do.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_auto_throttle(mut self, cfg: AutoThrottle) -> Self {
        self.auto_throttle = Some(cfg);
        self
    }
}

/// Back off when the target starts refusing requests.
///
/// # Why consecutive, and why a grant count rather than a duration
///
/// *Consecutive*: a single 503 on a busy target is noise, and reacting to it would make the rate
/// jitter for no reason. A run of them is the target telling you something. Any non-listed status
/// resets the run, so one good response ends it.
///
/// *Grants, not seconds*: the thing being recovered from is a rate, and "slower for the next 50
/// requests" is a bound the operator can reason about against the size of their attack. A duration
/// would interact with the rate it is modifying — halve a 2/s attack for 30 seconds and you have
/// slowed 30 requests; halve a 200/s attack for 30 seconds and you have slowed 3 000.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoThrottle {
    /// Statuses that mean "slow down".
    pub statuses: Vec<u16>,
    /// Consecutive listed responses before the rate is cut. Zero is treated as one.
    pub after: u32,
    /// What the rate is divided by while throttled. Values below 1 would *raise* the rate, which is
    /// never what an operator means here, so they are clamped to 1 (no change).
    pub factor: f64,
    /// How many grants the reduced rate lasts for before it recovers.
    pub recover_after: u32,
}

impl Default for AutoThrottle {
    /// 429 is the status that exists to say this; 503 is what a target says when it is the truth
    /// rather than a policy. Three in a row, at half rate, for fifty requests.
    fn default() -> Self {
        Self {
            statuses: vec![429, 503],
            after: 3,
            factor: 2.0,
            recover_after: 50,
        }
    }
}

/// Floor on the rate an [`AutoThrottle`] may reduce to.
///
/// A factor of `1e9` would otherwise turn a 20/s attack into one request every 578 days, which is
/// indistinguishable from a hang. Matches the web edge's own minimum rate.
const MIN_THROTTLED_RPS: f64 = 0.01;

/// Ceiling on a single computed wait.
///
/// An hour is already far past the point where an operator would conclude the attack has stalled,
/// so clamping here loses nothing real and keeps the arithmetic total.
const MAX_WAIT: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct Bucket {
    /// May go negative: see [`RateLimiter::reserve`].
    tokens: f64,
    last: Instant,
}

/// The auto-throttle's running state. Its own lock, so an attack with no auto-throttle configured
/// never touches it — `auto` is `None` and every path short-circuits before this exists.
#[derive(Debug)]
struct AutoState {
    /// Listed statuses seen back-to-back. Reset by any other status.
    consecutive: u32,
    /// Grants left at the reduced rate. 0 means not throttled.
    remaining: u32,
    /// How many times the throttle engaged. Reported, because a rate the operator did not choose
    /// must not be invisible.
    engaged: usize,
}

#[derive(Debug)]
struct Auto {
    cfg: AutoThrottle,
    state: parking_lot::Mutex<AutoState>,
}

/// Gate every request must pass through.
#[derive(Debug)]
pub struct RateLimiter {
    per_second: Option<f64>,
    burst: f64,
    bucket: parking_lot::Mutex<Bucket>,
    slots: Arc<Semaphore>,
    name: Option<String>,
    auto: Option<Auto>,
}

impl RateLimiter {
    /// Takes the limit by reference: [`RateLimit`] stopped being `Copy` when it grew a name, and a
    /// caller that holds its config for the report should not have to clone it to build a limiter.
    pub fn new(limit: &RateLimit) -> Arc<Self> {
        // A burst of 0 would mean even the very first request waits, which is never what anyone
        // means; and 0 in-flight slots would deadlock rather than throttle.
        let burst = f64::from(limit.burst.max(1));
        let slots = limit.max_in_flight.max(1);
        Arc::new(Self {
            per_second: limit.per_second.filter(|r| *r > 0.0),
            burst,
            bucket: parking_lot::Mutex::new(Bucket {
                // Start full: the first `burst` requests are free, which is what `burst` means and
                // what the `(n - burst) / rps` bound in the tests is derived from.
                tokens: burst,
                last: Instant::now(),
            }),
            slots: Arc::new(Semaphore::new(slots)),
            name: limit.name.clone(),
            auto: limit.auto_throttle.as_ref().map(|cfg| Auto {
                cfg: cfg.clone(),
                state: parking_lot::Mutex::new(AutoState {
                    consecutive: 0,
                    remaining: 0,
                    engaged: 0,
                }),
            }),
        })
    }

    /// Wait until this request may be sent. Holding the returned permit *is* being in flight.
    ///
    /// The in-flight slot is taken first and the rate token last, so the token is spent as close as
    /// possible to the actual send. Spending it earlier would let budget accrue while a caller is
    /// stuck waiting for a socket, and the attack would then burst to catch up.
    pub async fn acquire(&self) -> OwnedSemaphorePermit {
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            // The semaphore is private to this limiter and is never closed.
            .expect("in-flight semaphore closed");
        if let Some(wait) = self.reserve(Instant::now()) {
            tokio::time::sleep(wait).await;
        }
        permit
    }

    /// Charge one request to the bucket and return how long the caller must wait to spend it.
    ///
    /// Reservation, not polling: a caller that finds the bucket empty still takes its token and
    /// drives the balance negative, so the next caller queues *behind* it with a longer deadline.
    /// Without that, N concurrent waiters would all wake on the same refill and the burst would be
    /// N, not `burst`.
    fn reserve(&self, now: Instant) -> Option<Duration> {
        let rps = self.per_second?;
        // Consulted *before* the bucket lock is taken, so the two mutexes are never held at once and
        // there is no lock order to get wrong. `observe` only ever takes the auto lock.
        let rps = self.charge_throttle(rps);
        let mut b = self.bucket.lock();
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + elapsed * rps).min(self.burst) - 1.0;
        if b.tokens >= 0.0 {
            return None;
        }
        // `try_from_secs_f64`, not `from_secs_f64`: the latter PANICS on a value too large to
        // represent, and `-tokens / rps` gets there easily for a very small rps — 1.0 / 1e-300 is
        // 1e300 seconds. That input was reachable from the HTTP edge, which capped rps only from
        // above. The edge now has a floor too, but a limiter that panics on a legal `f64` is a
        // sharp edge regardless of who is holding it, so it saturates here instead.
        Some(
            Duration::try_from_secs_f64(-b.tokens / rps)
                .unwrap_or(MAX_WAIT)
                .min(MAX_WAIT),
        )
    }

    /// The rate this grant is charged at, spending one grant of any active throttle.
    ///
    /// Returns `rps` untouched — with no lock taken and no state read — when no [`AutoThrottle`] was
    /// configured. That is the guarantee that makes this change safe to put in the path every attack
    /// uses: an attack that did not ask for auto-throttling cannot be affected by it.
    fn charge_throttle(&self, rps: f64) -> f64 {
        let Some(auto) = &self.auto else { return rps };
        let mut st = auto.state.lock();
        if st.remaining == 0 {
            return rps;
        }
        st.remaining -= 1;
        (rps / auto.cfg.factor.max(1.0)).max(MIN_THROTTLED_RPS)
    }

    /// Tell the limiter what the target answered.
    ///
    /// Called once per response by [`crate::run`]. A no-op — one `Option` check — when no
    /// [`AutoThrottle`] was configured, and a no-op for a send that produced no status at all: a
    /// connection error is not the target asking to be treated more gently, and treating it as one
    /// would make an unreachable host look like a rate limit. It does not reset the run either, for
    /// the same reason: a transport failure is silence, not a "no".
    pub fn observe(&self, status: Option<u16>) {
        let Some(auto) = &self.auto else { return };
        let Some(code) = status else { return };
        let mut st = auto.state.lock();
        if auto.cfg.statuses.contains(&code) {
            st.consecutive += 1;
            if st.consecutive >= auto.cfg.after.max(1) {
                st.consecutive = 0;
                // Re-arm rather than extend: a target still refusing after the window keeps the
                // reduced rate, and the engagement count says how often that happened.
                st.remaining = auto.cfg.recover_after;
                st.engaged += 1;
            }
        } else {
            st.consecutive = 0;
        }
    }

    /// How many times the auto-throttle engaged. Always 0 when none was configured.
    pub fn auto_throttle_engaged(&self) -> usize {
        self.auto
            .as_ref()
            .map(|a| a.state.lock().engaged)
            .unwrap_or(0)
    }

    /// True while the reduced rate is in force.
    pub fn is_throttled(&self) -> bool {
        self.auto
            .as_ref()
            .map(|a| a.state.lock().remaining > 0)
            .unwrap_or(false)
    }

    /// The operator's name for this pool, if they gave one.
    pub fn pool_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Slots currently free. Exposed so callers can report progress, not to make decisions with.
    pub fn available_slots(&self) -> usize {
        self.slots.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The bound is `elapsed >= (n - burst) / rps`, derived directly from the bucket starting full.
    /// `sleep` never returns early, so a loaded machine can only push the measurement further above
    /// the floor — the assertion has no upper bound to flake against.
    #[tokio::test]
    async fn serial_acquires_cannot_exceed_the_configured_rate() {
        let rps = 100.0;
        let n = 21;
        let l = RateLimiter::new(&RateLimit::new(Some(rps), 1, 8));
        let t0 = Instant::now();
        for _ in 0..n {
            let _p = l.acquire().await;
        }
        let elapsed = t0.elapsed();
        let floor = Duration::from_secs_f64((f64::from(n) - 1.0) / rps);
        assert!(
            elapsed >= floor,
            "21 requests at 100rps took {elapsed:?}, which is faster than the {floor:?} the bucket allows"
        );
    }

    /// The reservation model is what makes the bound hold when callers arrive together: 20 tasks
    /// that all ask at once must still be spaced, not released in one clump.
    #[tokio::test]
    async fn concurrent_acquires_are_spaced_not_released_together() {
        let rps = 50.0;
        let n = 20;
        let l = RateLimiter::new(&RateLimit::new(Some(rps), 1, n));
        let t0 = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..n {
            let l = l.clone();
            set.spawn(async move {
                let _p = l.acquire().await;
                t0.elapsed()
            });
        }
        let mut grants: Vec<Duration> = Vec::new();
        while let Some(r) = set.join_next().await {
            grants.push(r.unwrap());
        }
        grants.sort();
        let floor = Duration::from_secs_f64((n as f64 - 1.0) / rps);
        assert!(
            grants[n - 1] >= floor,
            "last of {n} concurrent grants landed at {:?}, inside the {floor:?} floor",
            grants[n - 1]
        );
        // And the first one is free, because burst is 1. Loose upper bound on purpose: this is
        // task-spawn latency, and the property it guards is already carried by the floor above —
        // a first grant that had queued behind the other 19 would land near 380ms, not near 100.
        assert!(
            grants[0] < Duration::from_millis(100),
            "the burst token did not make the first grant free: {:?}",
            grants[0]
        );
    }

    /// No window of length T may contain more than `burst + rps*T` grants. Stated exactly, no fudge.
    #[tokio::test]
    async fn no_window_holds_more_grants_than_the_bucket_allows() {
        let rps = 50.0;
        let burst = 3u32;
        let n = 30usize;
        let l = RateLimiter::new(&RateLimit::new(Some(rps), burst, 8));
        let t0 = Instant::now();
        let mut at = Vec::with_capacity(n);
        for _ in 0..n {
            let _p = l.acquire().await;
            at.push(t0.elapsed().as_secs_f64());
        }
        let window = 0.2_f64;
        let allowed = f64::from(burst) + rps * window;
        for (i, start) in at.iter().enumerate() {
            let count = at[i..].iter().take_while(|t| **t - start <= window).count();
            assert!(
                count as f64 <= allowed,
                "{count} grants inside a {window}s window starting at {start}s; \
                 burst {burst} + {rps}/s allows at most {allowed}"
            );
        }
    }

    #[tokio::test]
    async fn in_flight_is_capped_even_with_no_rate_cap() {
        let cap = 4;
        let l = RateLimiter::new(&RateLimit::unthrottled(cap));
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..40 {
            let (l, live, peak) = (l.clone(), live.clone(), peak.clone());
            set.spawn(async move {
                let _p = l.acquire().await;
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
        while set.join_next().await.is_some() {}
        assert_eq!(
            peak.load(Ordering::SeqCst),
            cap,
            "concurrency peaked outside the {cap}-slot cap"
        );
    }

    #[tokio::test]
    async fn an_absurdly_small_rate_saturates_instead_of_panicking() {
        // `Duration::from_secs_f64` PANICS on a value it cannot represent, and 1.0 / 1e-300 is
        // 1e300 seconds. This exact input was reachable over HTTP, because the edge capped rps only
        // from above. The edge has a floor now, but the limiter must not be a landmine for any
        // caller holding a legal f64.
        let l = RateLimiter::new(&RateLimit::new(Some(1e-300), 1, 4));
        let _first = l.acquire().await; // free: the burst token
        // The second computes a wait. It must clamp, not panic — and must not actually sleep for
        // an hour inside a test, so we only check that reserve() produced a finite bounded value.
        let wait = l
            .reserve(Instant::now())
            .expect("a spent bucket must ask for a wait");
        assert_eq!(
            wait, MAX_WAIT,
            "an unrepresentable wait must clamp to the ceiling"
        );
    }

    #[test]
    fn a_normal_rate_is_unaffected_by_the_clamp() {
        // Guard against over-correcting: the clamp must not distort ordinary waits.
        let l = RateLimiter::new(&RateLimit::new(Some(10.0), 1, 4));
        assert!(
            l.reserve(Instant::now()).is_none(),
            "the burst token is free"
        );
        let wait = l.reserve(Instant::now()).expect("second must wait");
        // 1 token at 10/s == 100ms, give or take the nanoseconds this took to run.
        assert!(
            wait > Duration::from_millis(90) && wait < Duration::from_millis(110),
            "expected ~100ms, got {wait:?}"
        );
    }

    #[test]
    fn an_unset_rate_still_leaves_concurrency_bounded() {
        let l = RateLimiter::new(&RateLimit::unthrottled(3));
        assert!(
            l.reserve(Instant::now()).is_none(),
            "no rate cap must never impose a wait"
        );
        assert_eq!(l.available_slots(), 3);
    }

    // ---- the auto-throttle ------------------------------------------------------------------
    //
    // This is the highest-risk addition in the crate: it touches the one code path every attack's
    // every request goes through. So the first thing these tests establish is the *absence* of an
    // effect when it is not configured, and only then what it does when it is.

    /// The guarantee that makes the rest of this safe. An attack that did not ask for auto-throttling
    /// must compute exactly the waits it computed before this feature existed.
    #[test]
    fn with_no_auto_throttle_configured_nothing_observes_and_nothing_changes() {
        let l = RateLimiter::new(&RateLimit::new(Some(10.0), 1, 4));
        // Enough 429s to trip any configuration, before and between the measurements.
        for _ in 0..100 {
            l.observe(Some(429));
        }
        assert!(!l.is_throttled());
        assert_eq!(l.auto_throttle_engaged(), 0);
        assert!(
            l.reserve(Instant::now()).is_none(),
            "the burst token is still free"
        );
        let wait = l.reserve(Instant::now()).expect("second must wait");
        // Unchanged from `a_normal_rate_is_unaffected_by_the_clamp`: 1 token at 10/s is 100ms.
        assert!(
            wait > Duration::from_millis(90) && wait < Duration::from_millis(110),
            "an unconfigured limiter changed its arithmetic: {wait:?}"
        );
    }

    #[test]
    fn a_run_of_listed_statuses_halves_the_rate_and_a_shorter_run_does_not() {
        let cfg = AutoThrottle {
            statuses: vec![429],
            after: 3,
            factor: 2.0,
            recover_after: 10,
        };
        let l = RateLimiter::new(&RateLimit::new(Some(10.0), 1, 4).with_auto_throttle(cfg));

        // Two is not a run.
        l.observe(Some(429));
        l.observe(Some(429));
        assert!(!l.is_throttled(), "two responses must not trip it");
        let _free = l.reserve(Instant::now()); // spend the burst token
        let normal = l.reserve(Instant::now()).expect("must wait");
        assert!(
            normal > Duration::from_millis(90) && normal < Duration::from_millis(110),
            "expected the unthrottled ~100ms, got {normal:?}"
        );

        // The third makes it a run.
        l.observe(Some(429));
        l.observe(Some(429));
        l.observe(Some(429));
        assert!(l.is_throttled());
        assert_eq!(l.auto_throttle_engaged(), 1);
        let slowed = l.reserve(Instant::now()).expect("must wait");
        assert!(
            slowed > normal,
            "the throttled wait {slowed:?} is not longer than the normal {normal:?}"
        );
    }

    /// One good response ends the run: a lone 503 on a busy target is noise, not a signal.
    #[test]
    fn a_non_listed_status_resets_the_run() {
        let l = RateLimiter::new(
            &RateLimit::new(Some(10.0), 1, 4).with_auto_throttle(AutoThrottle {
                statuses: vec![429, 503],
                after: 3,
                factor: 2.0,
                recover_after: 10,
            }),
        );
        l.observe(Some(429));
        l.observe(Some(503));
        l.observe(Some(200));
        l.observe(Some(429));
        l.observe(Some(429));
        assert!(
            !l.is_throttled(),
            "the 200 should have reset the run, leaving only two"
        );
        l.observe(Some(429));
        assert!(l.is_throttled(), "and three after the reset should trip it");
    }

    #[test]
    fn the_reduced_rate_lasts_exactly_recover_after_grants_and_then_recovers() {
        let l = RateLimiter::new(
            &RateLimit::new(Some(10.0), 1, 4).with_auto_throttle(AutoThrottle {
                statuses: vec![429],
                after: 1,
                factor: 4.0,
                recover_after: 5,
            }),
        );
        l.observe(Some(429));
        assert!(l.is_throttled());
        for i in 0..5 {
            assert!(l.is_throttled(), "recovered early, after {i} grants");
            l.reserve(Instant::now());
        }
        assert!(!l.is_throttled(), "5 grants should have used the window up");
        // And the next wait is priced at the operator's rate, not the reduced one.
        //
        // Read carefully, because the number is not "one token at 10/s". Nothing sleeps here, so the
        // five throttled grants drove the bucket to -4 tokens; this grant takes it to -5. Paying that
        // debt at the operator's 10/s is 500ms, and at the reduced 2.5/s it would be 2s. That gap is
        // the assertion — it is the only measurement that distinguishes "recovered" from "still
        // throttled", since both waits are long.
        let wait = l.reserve(Instant::now()).expect("a spent bucket must wait");
        assert!(
            wait > Duration::from_millis(450) && wait < Duration::from_millis(550),
            "expected the 5-token debt priced at 10/s (~500ms); {wait:?} is the reduced rate still \
             in force"
        );
    }

    /// A transport failure is silence, not the target asking to be treated gently. Counting it as a
    /// "slow down" would make an unreachable host indistinguishable from a rate limit.
    #[test]
    fn a_send_with_no_status_neither_trips_nor_resets_the_throttle() {
        let l = RateLimiter::new(
            &RateLimit::new(Some(10.0), 1, 4).with_auto_throttle(AutoThrottle {
                statuses: vec![429],
                after: 2,
                factor: 2.0,
                recover_after: 5,
            }),
        );
        l.observe(Some(429));
        l.observe(None);
        assert!(!l.is_throttled(), "an error must not trip it on its own");
        l.observe(Some(429));
        assert!(l.is_throttled(), "and must not have reset the run either");
    }

    /// A factor of 1e9 against a 20/s rate is one request every 578 days, which an operator would
    /// read as a hang rather than a throttle.
    #[test]
    fn an_absurd_factor_cannot_stall_the_attack_and_an_inverted_one_cannot_speed_it_up() {
        let slow = RateLimiter::new(
            &RateLimit::new(Some(20.0), 1, 4).with_auto_throttle(AutoThrottle {
                statuses: vec![429],
                after: 1,
                factor: 1e9,
                recover_after: 100,
            }),
        );
        slow.observe(Some(429));
        let wait = slow.reserve(Instant::now());
        // The floor is 0.01/s, so one token costs at most 100 seconds — bounded, and nowhere near
        // the hour-long ceiling a 1e9 divisor would otherwise reach for.
        assert!(
            wait.unwrap_or_default() <= Duration::from_secs(100),
            "the floor did not hold: {wait:?}"
        );

        // A factor below 1 would divide by less than one and *raise* the rate. Clamped.
        let fast = RateLimiter::new(
            &RateLimit::new(Some(10.0), 1, 4).with_auto_throttle(AutoThrottle {
                statuses: vec![429],
                after: 1,
                factor: 0.1,
                recover_after: 100,
            }),
        );
        fast.observe(Some(429));
        let _burst = fast.reserve(Instant::now());
        let wait = fast.reserve(Instant::now()).expect("must wait");
        assert!(
            wait > Duration::from_millis(90),
            "an auto-throttle made the attack faster: {wait:?}"
        );
    }

    /// With no rate to reduce there is nothing to halve. Stated as a test rather than left for
    /// someone to discover: `unthrottled` plus an auto-throttle is inert, not a bug.
    #[test]
    fn an_auto_throttle_over_an_uncapped_rate_is_inert_and_says_so_by_never_waiting() {
        let l = RateLimiter::new(
            &RateLimit::unthrottled(4).with_auto_throttle(AutoThrottle {
                statuses: vec![429],
                after: 1,
                factor: 100.0,
                recover_after: 100,
            }),
        );
        l.observe(Some(429));
        assert_eq!(l.auto_throttle_engaged(), 1, "it still engaged");
        assert!(
            l.reserve(Instant::now()).is_none(),
            "but with no rate cap there is no wait to lengthen"
        );
    }

    #[test]
    fn a_pool_name_is_carried_through_and_changes_nothing_else() {
        let l = RateLimiter::new(&RateLimit::new(Some(10.0), 1, 7).named("slow"));
        assert_eq!(l.pool_name(), Some("slow"));
        assert_eq!(l.available_slots(), 7);
        assert!(l.reserve(Instant::now()).is_none());
    }
}
