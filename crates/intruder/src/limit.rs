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

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Operator-controlled bounds on how hard an attack is allowed to hit the target.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
        }
    }
}

impl RateLimit {
    pub fn new(per_second: Option<f64>, burst: u32, max_in_flight: usize) -> Self {
        Self {
            per_second,
            burst,
            max_in_flight,
        }
    }

    /// Concurrency only, no rate cap. Named so it reads as a decision at the call site.
    pub fn unthrottled(max_in_flight: usize) -> Self {
        Self {
            per_second: None,
            burst: 1,
            max_in_flight,
        }
    }
}

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

/// Gate every request must pass through.
#[derive(Debug)]
pub struct RateLimiter {
    per_second: Option<f64>,
    burst: f64,
    bucket: parking_lot::Mutex<Bucket>,
    slots: Arc<Semaphore>,
}

impl RateLimiter {
    pub fn new(limit: RateLimit) -> Arc<Self> {
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
        let l = RateLimiter::new(RateLimit::new(Some(rps), 1, 8));
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
        let l = RateLimiter::new(RateLimit::new(Some(rps), 1, n));
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
        let l = RateLimiter::new(RateLimit::new(Some(rps), burst, 8));
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
        let l = RateLimiter::new(RateLimit::unthrottled(cap));
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
        let l = RateLimiter::new(RateLimit::new(Some(1e-300), 1, 4));
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
        let l = RateLimiter::new(RateLimit::new(Some(10.0), 1, 4));
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
        let l = RateLimiter::new(RateLimit::unthrottled(3));
        assert!(
            l.reserve(Instant::now()).is_none(),
            "no rate cap must never impose a wait"
        );
        assert_eq!(l.available_slots(), 3);
    }
}
