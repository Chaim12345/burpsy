//! Running an attack: bounded concurrency, and a summary instead of a pile of bodies.
//!
//! # What an operator actually gets back
//!
//! A cluster bomb produces 100,000 responses. Handing back 100,000 response bodies is useless twice
//! over — nobody reads them, and holding them is the exact memory failure this project exists to
//! avoid. What distinguishes an interesting response from the other 99,999 is almost always the
//! triple **(status, length, did the payload come back)**, so that triple is the key, and the report
//! is a bucket per distinct triple with a count.
//!
//! Two consequences fall out of that:
//!
//! * **Results hold ordinals, not payloads.** [`crate::AttackPlan`] derives request `i` from `i`, so
//!   a bucket recording `first_ordinal` can regenerate the exact payload combination that produced
//!   it. A result row is therefore a fixed ~40 bytes no matter how many positions the attack used.
//! * **Only one response per bucket is stored.** Recording all 100k into the traffic store would
//!   reintroduce the same problem one layer down, so the recorder fires for the *first* response in
//!   each bucket. The operator keeps one openable exemplar per distinct behaviour, and resident
//!   bytes scale with distinct behaviours rather than with requests sent.
//!
//! Reflection is the fixed case of what Burp exposes as configurable grep-match
//! (`matchgrep.dogrep`, `matchgrep.casesensitive`, `matchgrep.excludeheaders`,
//! `matchgrep.simplepattern` — `burp.Zru_`). Here it is one question, asked of every attack: did
//! this payload come back? Arbitrary grep patterns are a separate feature, not part of the key.
//!
//! # Grep-match and grep-extract, and why they stayed out of the key
//!
//! [`Grep`] adds the configurable version: an operator regex tested against each response, and a
//! second one whose first capture group is pulled out. They are computed per response and reported per
//! attempt — but the bucket key is still `(status, length, reflected)`, exactly as the paragraph above
//! says it is, because a grep result is a *question the operator asked*, not a property of how the
//! target behaved. Keying on it would silently double the bucket count for every attack that turned a
//! pattern on, and the same 200 responses would collapse differently depending on what was being
//! searched for.
//!
//! That leaves a bucket covering responses that disagree about the grep, which is handled by counting
//! rather than by picking one: [`ResultBucket::grep_matches`] is how many of the bucket's responses
//! matched, so `grep_matches == count` and `grep_matches == 0` are distinguishable from a mixture. The
//! extracted *value* cannot be counted that way, so [`ResultBucket::grep_extract`] is documented as
//! the exemplar's and the per-attempt rows carry the rest.
//!
//! # Concurrency
//!
//! Every send passes through [`RateLimiter`]. The driver loop takes a permit *before* it splices the
//! request, so the number of spliced request copies alive at once is `max_in_flight`, not the length
//! of the plan; completed tasks are drained on every iteration so the `JoinSet` cannot accumulate
//! finished work either.

use crate::limit::{RateLimit, RateLimiter};
use crate::plan::{Assignment, AttackKind, AttackPlan};
use crate::{InsertionPoint, apply_all};
use bytes::Bytes;
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What one send produced. `status` comes from the sender because the sender already parsed it.
#[derive(Debug, Clone)]
pub struct Sent {
    pub raw: Bytes,
    pub duration: Duration,
    pub status: Option<u16>,
}

/// A send in progress. Boxed so the engine holds one sender for the whole attack instead of being
/// generic over the network stack — the web layer plugs in the repeater, tests plug in a closure.
pub type SendFuture = Pin<Box<dyn Future<Output = Result<Sent, String>> + Send>>;

/// Sends raw request bytes and returns the response.
pub type SendFn = Arc<dyn Fn(Vec<u8>) -> SendFuture + Send + Sync>;

/// Stores a response and returns its message id. Called once per distinct result bucket.
pub type RecordFn = Arc<dyn Fn(Bytes) -> u64 + Send + Sync>;

/// Everything an attack needs that is not "how do I reach the network".
pub struct Attack<'a> {
    /// The base request. Never mutated; each attempt splices a copy.
    pub base: &'a Bytes,
    /// The selected positions, in the order the plan's `point` indices refer to.
    pub points: &'a [InsertionPoint],
    /// Payload sets, in the order the plan's `set` indices refer to.
    pub sets: &'a [Vec<Bytes>],
    pub plan: &'a AttackPlan,
    pub limits: RateLimit,
    /// How many per-request rows to keep. Beyond this only bucket counts survive.
    pub detail_limit: usize,
    /// How many distinct result buckets to keep before giving up on further distinctions.
    pub max_buckets: usize,
    /// Refuses a spliced request before it goes out. `Err(reason)` means do not send.
    ///
    /// The engine has no concept of engagement scope and should not grow one — but it is the only
    /// place that sees the request a payload actually produced. A caller checked the *target* the
    /// operator named; a payload spliced into a path position can move the request somewhere else
    /// entirely. So the caller supplies the predicate and the engine guarantees nothing bypasses
    /// it. Refusals are counted as errors, never dropped silently.
    pub guard: Option<Guard>,
    /// Operator regexes tested against each response. Empty by default and free when empty.
    pub grep: Grep,
}

/// Decides whether a spliced request may be sent. See [`Attack::guard`].
pub type Guard = Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

/// Longest grep-extract this will report.
///
/// A capture group can match a whole response body, and a report is not a place to put 200 KB of it
/// once per attempt. Burp bounds the same thing (its grep-extract has a maximum capture length,
/// default 100 characters); this is more generous and still bounded. A capture longer than this is
/// cut — the field's doc says so, so a truncated value is never presented as a whole one.
pub const MAX_EXTRACT: usize = 256;

/// Grep-match and grep-extract: two optional regexes, applied to every response.
///
/// `Arc`-wrapped rather than held by value because each spawned send needs its own handle and the
/// compiled program is the expensive part. Cloning the `Arc` is a refcount bump; cloning a `Regex`
/// is not guaranteed to be.
#[derive(Clone, Default)]
pub struct Grep {
    /// Does the response match? Answered as a boolean per attempt.
    pub match_re: Option<Arc<regex::bytes::Regex>>,
    /// The first capture group of the first match, or the whole match when the pattern has no
    /// groups — which is what an operator who wrote a pattern with no parentheses means.
    pub extract_re: Option<Arc<regex::bytes::Regex>>,
}

impl std::fmt::Debug for Grep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grep")
            .field("match_re", &self.match_re.as_ref().map(|r| r.as_str()))
            .field("extract_re", &self.extract_re.as_ref().map(|r| r.as_str()))
            .finish()
    }
}

impl Grep {
    pub fn is_empty(&self) -> bool {
        self.match_re.is_none() && self.extract_re.is_none()
    }

    /// Run both patterns over one response.
    fn run(&self, raw: &[u8]) -> (Option<bool>, Option<String>) {
        let matched = self.match_re.as_ref().map(|re| re.is_match(raw));
        let extracted = self.extract_re.as_ref().and_then(|re| {
            let caps = re.captures(raw)?;
            // Group 1 when there is one, else group 0 — the whole match. `get(0)` always exists on a
            // successful capture, so the `?` here can only fail for a pattern whose group 1 did not
            // participate in the match, which is a real "nothing extracted".
            let m = if re.captures_len() > 1 {
                caps.get(1)?
            } else {
                caps.get(0)?
            };
            let bytes = m.as_bytes();
            Some(String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_EXTRACT)]).into_owned())
        });
        (matched, extracted)
    }
}

impl<'a> Attack<'a> {
    /// Defaults sized for a UI: enough rows to render a small attack, enough buckets that a real
    /// target's response variety fits without truncation.
    pub fn new(
        base: &'a Bytes,
        points: &'a [InsertionPoint],
        sets: &'a [Vec<Bytes>],
        plan: &'a AttackPlan,
    ) -> Self {
        Self {
            base,
            points,
            sets,
            plan,
            limits: RateLimit::default(),
            detail_limit: 500,
            max_buckets: 2_000,
            guard: None,
            grep: Grep::default(),
        }
    }

    /// Attach the predicate every spliced request must satisfy before it is sent.
    pub fn with_guard(mut self, g: Guard) -> Self {
        self.guard = Some(g);
        self
    }

    pub fn with_limits(mut self, limits: RateLimit) -> Self {
        self.limits = limits;
        self
    }

    /// Attach the operator's grep-match and grep-extract patterns.
    pub fn with_grep(mut self, grep: Grep) -> Self {
        self.grep = grep;
        self
    }
}

/// Responses that behave the same, counted once.
#[derive(Debug, Clone, Serialize)]
pub struct ResultBucket {
    pub status: Option<u16>,
    pub response_len: usize,
    /// A payload from this request appeared verbatim in the response.
    pub reflected: bool,
    pub count: usize,
    /// Plan ordinal of the first request that landed here — replay it to recover the payloads.
    pub first_ordinal: usize,
    /// Stored response for `first_ordinal`, when a recorder was supplied. One exemplar per bucket.
    pub example_response_id: Option<u64>,
    /// How many of this bucket's `count` responses matched [`Grep::match_re`]. Always 0 when no
    /// grep-match pattern was supplied.
    ///
    /// A count rather than a boolean because the grep is deliberately not part of the bucket key, so a
    /// bucket can hold responses that disagree — `grep_matches == count` and `grep_matches == 0` are
    /// the unanimous cases and anything between is a mixture the operator can see.
    pub grep_matches: usize,
    /// The **exemplar's** grep-extract, i.e. the value pulled from the response at `first_ordinal`.
    ///
    /// A single value cannot stand for a whole bucket, and this one does not pretend to: the
    /// per-attempt rows carry each response's own extraction.
    pub grep_extract: Option<String>,
}

/// Sends that never produced a response, grouped by message.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBucket {
    pub error: String,
    pub count: usize,
    /// `None` when the failure was a panicking task, whose ordinal cannot be recovered. Reporting
    /// a made-up ordinal would send the operator to replay the wrong request.
    pub first_ordinal: Option<usize>,
}

/// One request's outcome. Carries no bytes: `ordinal` regenerates the payloads through the plan.
#[derive(Debug, Clone, Serialize)]
pub struct Attempt {
    pub ordinal: usize,
    pub status: Option<u16>,
    pub response_len: usize,
    pub duration_ms: u64,
    pub reflected: bool,
    /// Set only when this attempt was the exemplar stored for its bucket.
    pub response_id: Option<u64>,
    pub error: Option<String>,
    /// Did this response match [`Grep::match_re`]? `None` when no pattern was supplied — which is a
    /// different fact from `Some(false)`, and the reason this is not a bare `bool`.
    pub grep_matched: Option<bool>,
    /// What [`Grep::extract_re`] pulled out of this response, capped at [`MAX_EXTRACT`] bytes.
    pub grep_extract: Option<String>,
}

/// The answer to "what happened".
#[derive(Debug, Clone, Serialize)]
pub struct AttackReport {
    pub kind: AttackKind,
    /// Requests the mode describes with no bound applied.
    pub combinations: u64,
    /// False when `combinations` saturated and is a lower bound.
    pub combinations_exact: bool,
    /// The bound that was in force.
    pub max_requests: usize,
    /// True when the bound cut the attack short. Reported, never silent.
    pub truncated: bool,
    pub planned: usize,
    pub sent: usize,
    pub failed: usize,
    pub elapsed_ms: u64,
    /// Rarest first: with 100k responses the interesting one is the bucket with a count of 1.
    pub buckets: Vec<ResultBucket>,
    /// True when `max_buckets` was hit; `unbucketed` responses were then only counted.
    pub buckets_truncated: bool,
    pub unbucketed: usize,
    pub errors: Vec<ErrorBucket>,
    /// Per-request rows for the first `detail_limit` ordinals, in plan order.
    pub attempts: Vec<Attempt>,
    /// The rule behind that cut. Reported for the same reason `max_requests` is: a consumer seeing
    /// 200,000 sent next to 500 rows can infer a bound was applied but not what it was.
    pub detail_limit: usize,
    /// Responses that matched [`Grep::match_re`], across the whole attack.
    ///
    /// Not the sum of [`ResultBucket::grep_matches`]: once `max_buckets` is hit further responses are
    /// only counted, and their grep results would otherwise be lost with them.
    pub grep_matched: usize,
    /// The operator's name for the resource pool these bounds came from, echoed back.
    pub pool: Option<String>,
    /// How many times the [`crate::AutoThrottle`] cut the rate. Always 0 when none was configured.
    ///
    /// Reported for the same reason `truncated` is: an attack that ran at a rate the operator did not
    /// choose, and cannot see, looks like a target that got slower.
    pub auto_throttle_engaged: usize,
}

/// What a spawned send hands back to the driver.
struct Outcome {
    ordinal: usize,
    result: Result<Hit, String>,
}

struct Hit {
    status: Option<u16>,
    len: usize,
    duration_ms: u64,
    reflected: bool,
    grep_matched: Option<bool>,
    grep_extract: Option<String>,
    /// Kept only until the driver decides whether this response is a bucket exemplar.
    raw: Bytes,
}

/// Run the attack to completion.
pub async fn run(a: Attack<'_>, sender: SendFn, record: Option<RecordFn>) -> AttackReport {
    let started = Instant::now();
    let limiter = RateLimiter::new(&a.limits);
    let mut collector = Collector::new(&a, record);
    let mut tasks: tokio::task::JoinSet<Outcome> = tokio::task::JoinSet::new();
    let mut asg = Assignment::default();
    let mut places: Vec<(&InsertionPoint, &[u8])> = Vec::new();

    for i in 0..a.plan.len() {
        if !a.plan.fill(i, &mut asg) {
            break;
        }
        places.clear();
        let mut payloads: Vec<Bytes> = Vec::with_capacity(asg.slots.len());
        for s in &asg.slots {
            let (Some(point), Some(payload)) = (
                a.points.get(s.point),
                a.sets.get(s.set).and_then(|set| set.get(s.payload)),
            ) else {
                continue;
            };
            places.push((point, payload.as_ref()));
            payloads.push(payload.clone());
        }

        // Permit first, splice second: the spliced request is the one unavoidable copy of the body,
        // so it must not exist until this attempt is cleared to go out.
        let permit = limiter.acquire().await;
        let bytes = apply_all(a.base, &places);
        // Between splice and send: this is the first moment the real request exists, and the last
        // moment before it leaves. A refusal costs the rate token that was just spent, which is
        // correct — a refused attempt still occupied a slot in the operator's budget.
        if let Some(g) = &a.guard
            && let Err(why) = g(&bytes)
        {
            drop(permit);
            collector.absorb(Ok(Outcome {
                ordinal: i,
                result: Err(why),
            }));
            continue;
        }
        let sender = sender.clone();
        let grep = a.grep.clone();
        let feedback = limiter.clone();
        tasks.spawn(async move {
            let result = sender(bytes).await.map(|sent| {
                // Tell the limiter what came back before the permit is released, so a target that
                // started refusing has already cut the rate by the time the next request asks for a
                // token. A no-op unless an `AutoThrottle` was configured.
                feedback.observe(sent.status);
                // Scan in the worker, not the driver: with 100 in flight this is the only part of
                // response handling that costs real CPU, and the greps belong here for the same
                // reason reflection does.
                let reflected = payloads.iter().any(|p| contains(&sent.raw, p));
                let (grep_matched, grep_extract) = grep.run(&sent.raw);
                Hit {
                    status: sent.status,
                    len: sent.raw.len(),
                    duration_ms: sent.duration.as_millis() as u64,
                    reflected,
                    grep_matched,
                    grep_extract,
                    raw: sent.raw,
                }
            });
            drop(permit);
            Outcome { ordinal: i, result }
        });

        // Drain whatever finished while we were waiting, so the JoinSet holds in-flight work only.
        while let Some(done) = tasks.try_join_next() {
            collector.absorb(done);
        }
    }

    while let Some(done) = tasks.join_next().await {
        collector.absorb(done);
    }

    collector.finish(&a, &limiter, started.elapsed())
}

/// Folds outcomes into buckets as they arrive, holding no response bodies.
struct Collector {
    record: Option<RecordFn>,
    index: HashMap<(Option<u16>, usize, bool), usize>,
    buckets: Vec<ResultBucket>,
    error_index: HashMap<String, usize>,
    errors: Vec<ErrorBucket>,
    attempts: Vec<Attempt>,
    detail_limit: usize,
    max_buckets: usize,
    sent: usize,
    failed: usize,
    unbucketed: usize,
    grep_matched: usize,
}

impl Collector {
    fn new(a: &Attack<'_>, record: Option<RecordFn>) -> Self {
        Self {
            record,
            index: HashMap::new(),
            buckets: Vec::new(),
            error_index: HashMap::new(),
            errors: Vec::new(),
            attempts: Vec::new(),
            detail_limit: a.detail_limit,
            max_buckets: a.max_buckets.max(1),
            sent: 0,
            failed: 0,
            unbucketed: 0,
            grep_matched: 0,
        }
    }

    fn absorb(&mut self, done: Result<Outcome, tokio::task::JoinError>) {
        let out = match done {
            Ok(o) => o,
            // A panicking send task is a bug, but losing the whole attack over it is worse: count
            // it and keep going, the same as any other failed request.
            Err(e) => {
                self.failed += 1;
                self.note_error(None, format!("send task failed: {e}"));
                return;
            }
        };
        match out.result {
            Ok(hit) => {
                self.sent += 1;
                // Counted before bucketing, so a response past `max_buckets` still contributes: the
                // report's total must not depend on how varied the target's behaviour was.
                if hit.grep_matched == Some(true) {
                    self.grep_matched += 1;
                }
                // Not part of the key, on purpose — see the module header.
                let key = (hit.status, hit.len, hit.reflected);
                let mut response_id = None;
                match self.index.get(&key) {
                    Some(&i) => {
                        self.buckets[i].count += 1;
                        if hit.grep_matched == Some(true) {
                            self.buckets[i].grep_matches += 1;
                        }
                    }
                    None if self.buckets.len() < self.max_buckets => {
                        // First of its kind: this is the one response worth keeping.
                        response_id = self.record.as_ref().map(|r| r(hit.raw.clone()));
                        self.index.insert(key, self.buckets.len());
                        self.buckets.push(ResultBucket {
                            status: hit.status,
                            response_len: hit.len,
                            reflected: hit.reflected,
                            count: 1,
                            first_ordinal: out.ordinal,
                            example_response_id: response_id,
                            grep_matches: usize::from(hit.grep_matched == Some(true)),
                            grep_extract: hit.grep_extract.clone(),
                        });
                    }
                    None => self.unbucketed += 1,
                }
                if out.ordinal < self.detail_limit {
                    self.attempts.push(Attempt {
                        ordinal: out.ordinal,
                        status: hit.status,
                        response_len: hit.len,
                        duration_ms: hit.duration_ms,
                        reflected: hit.reflected,
                        response_id,
                        error: None,
                        grep_matched: hit.grep_matched,
                        grep_extract: hit.grep_extract,
                    });
                }
            }
            Err(e) => {
                self.failed += 1;
                if out.ordinal < self.detail_limit {
                    self.attempts.push(Attempt {
                        ordinal: out.ordinal,
                        status: None,
                        response_len: 0,
                        duration_ms: 0,
                        reflected: false,
                        response_id: None,
                        error: Some(e.clone()),
                        // There was no response, so there is nothing the grep could have been asked
                        // about. `None` says that; `Some(false)` would claim the pattern was tested
                        // and absent.
                        grep_matched: None,
                        grep_extract: None,
                    });
                }
                self.note_error(Some(out.ordinal), e);
            }
        }
    }

    fn note_error(&mut self, ordinal: Option<usize>, message: String) {
        match self.error_index.get(&message) {
            Some(&i) => self.errors[i].count += 1,
            // Distinct error texts are bounded the same way buckets are: "connection refused"
            // repeated 99,997 times is one line, not 99,997.
            None if self.errors.len() < self.max_buckets => {
                self.error_index.insert(message.clone(), self.errors.len());
                self.errors.push(ErrorBucket {
                    error: message,
                    count: 1,
                    first_ordinal: ordinal,
                });
            }
            None => {}
        }
    }

    fn finish(
        mut self,
        a: &Attack<'_>,
        limiter: &RateLimiter,
        elapsed: Duration,
    ) -> AttackReport {
        // Rarest first, then by ordinal so the output is stable across runs.
        self.buckets.sort_by_key(|b| (b.count, b.first_ordinal));
        self.errors
            .sort_by_key(|e| (e.count, e.first_ordinal.unwrap_or(usize::MAX)));
        // Results arrive as they complete; the operator reads them in plan order.
        self.attempts.sort_by_key(|x| x.ordinal);
        AttackReport {
            kind: a.plan.kind(),
            combinations: a.plan.combinations(),
            combinations_exact: a.plan.combinations_exact(),
            max_requests: a.plan.max_requests(),
            truncated: a.plan.truncated(),
            planned: a.plan.len(),
            sent: self.sent,
            failed: self.failed,
            elapsed_ms: elapsed.as_millis() as u64,
            buckets: self.buckets,
            buckets_truncated: self.unbucketed > 0,
            unbucketed: self.unbucketed,
            errors: self.errors,
            attempts: self.attempts,
            detail_limit: self.detail_limit,
            grep_matched: self.grep_matched,
            pool: limiter.pool_name().map(str::to_string),
            auto_throttle_engaged: limiter.auto_throttle_engaged(),
        }
    }
}

/// Did `needle` come back verbatim? Searches the whole response, headers included: a payload
/// reflected into `Location` or `Set-Cookie` matters as much as one in the body.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::AttackKind;
    use crate::{PointConfig, find_points};
    use burpsy_core::{Direction, TrafficStore};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn request(raw: &'static [u8]) -> (Bytes, Vec<InsertionPoint>) {
        let s = TrafficStore::new();
        let id = s.put(Bytes::from_static(raw), Direction::Request);
        let m = s.get(id).unwrap();
        let pts = find_points(&m, &PointConfig::default());
        (m.raw.clone(), pts)
    }

    fn sets(v: &[&[&str]]) -> Vec<Vec<Bytes>> {
        v.iter()
            .map(|s| {
                s.iter()
                    .map(|p| Bytes::from(p.as_bytes().to_vec()))
                    .collect()
            })
            .collect()
    }

    /// A sender that answers instantly and records every request it was given.
    fn recording_sender(seen: Arc<Mutex<Vec<Vec<u8>>>>, body: &'static str) -> SendFn {
        Arc::new(move |bytes: Vec<u8>| {
            let seen = seen.clone();
            Box::pin(async move {
                seen.lock().unwrap().push(bytes);
                Ok(Sent {
                    raw: Bytes::from_static(body.as_bytes()),
                    duration: Duration::from_millis(1),
                    status: Some(200),
                })
            })
        })
    }

    // ---- the guard ---------------------------------------------------------------------
    //
    // The attack this defends against: the operator's scope excludes /admin, the host-level check
    // authorises the host anyway, and a payload spliced into a path position then rewrites the
    // request onto the excluded path. Nothing upstream ever sees that request.

    #[tokio::test]
    async fn a_payload_that_rewrites_the_path_out_of_scope_is_never_sent() {
        // A filename position, which is exactly what lets a payload move the path.
        let s = TrafficStore::new();
        let id = s.put(
            Bytes::from_static(b"GET /search HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
            Direction::Request,
        );
        let m = s.get(id).unwrap();
        let points = find_points(&m, &PointConfig::all());
        let sel: Vec<InsertionPoint> = points
            .iter()
            .filter(|p| p.kind == crate::PointKind::UrlPathFilename)
            .cloned()
            .collect();
        assert_eq!(sel.len(), 1, "expected one filename position in /search");

        let payloads = sets(&[&["products", "admin", "help"]]);
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[3], 1_000);
        let seen = Arc::new(Mutex::new(Vec::new()));

        // Stand-in for the real scope predicate: /admin is excluded.
        let guard: Guard = Arc::new(|raw: &[u8]| {
            let path = burpsy_core::scope::request_path(raw).unwrap_or("");
            if path.starts_with("/admin") {
                Err(format!("refused: {path} is out of scope"))
            } else {
                Ok(())
            }
        });

        let a = Attack::new(&m.raw, &sel, &payloads, &plan)
            .with_limits(RateLimit::unthrottled(4))
            .with_guard(guard);
        let r = run(
            a,
            recording_sender(seen.clone(), "HTTP/1.1 200 OK\r\n\r\nok"),
            None,
        )
        .await;

        let sent: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|b| {
                String::from_utf8_lossy(b)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert!(
            !sent.iter().any(|l| l.contains("/admin")),
            "an out-of-scope request reached the sender: {sent:?}"
        );
        assert_eq!(r.sent, 2, "the two in-scope payloads must still go");
        assert_eq!(
            r.failed, 1,
            "and the refused one must be counted, not dropped silently"
        );
    }

    #[tokio::test]
    async fn a_refusal_is_reported_with_its_reason() {
        // A refusal the operator cannot see is indistinguishable from a target that said nothing.
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads = sets(&[&["x"]]);
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[1], 10);
        let seen = Arc::new(Mutex::new(Vec::new()));

        let guard: Guard = Arc::new(|_: &[u8]| Err("refused: out of scope".into()));
        let a = Attack::new(&base, &sel, &payloads, &plan)
            .with_limits(RateLimit::unthrottled(2))
            .with_guard(guard);
        let r = run(
            a,
            recording_sender(seen.clone(), "HTTP/1.1 200 OK\r\n\r\nok"),
            None,
        )
        .await;

        assert_eq!(r.sent, 0);
        assert_eq!(r.failed, 1);
        assert!(
            seen.lock().unwrap().is_empty(),
            "nothing may reach the sender"
        );
        assert!(
            r.errors.iter().any(|e| e.error.contains("out of scope")),
            "the reason must survive into the report: {:?}",
            r.errors
        );
    }

    #[tokio::test]
    async fn pitchfork_sends_one_request_per_lockstep_pair() {
        let (base, points) = request(b"GET /?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone(), points[1].clone()];
        let payloads = sets(&[&["u1", "u2", "u3"], &["p1", "p2"]]);
        let plan = AttackPlan::new(AttackKind::Pitchfork, 2, &[3, 2], 1_000);
        let seen = Arc::new(Mutex::new(Vec::new()));

        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::unthrottled(4));
        let r = run(
            a,
            recording_sender(seen.clone(), "HTTP/1.1 200 OK\r\n\r\nok"),
            None,
        )
        .await;

        assert_eq!(r.sent, 2, "the 2-entry set ends the attack");
        let mut got: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|b| {
                String::from_utf8_lossy(b)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                "GET /?a=u1&b=p1 HTTP/1.1".to_string(),
                "GET /?a=u2&b=p2 HTTP/1.1".to_string()
            ],
            "pitchfork must pair set members by index, not cross them"
        );
    }

    #[tokio::test]
    async fn cluster_bomb_sends_every_combination() {
        let (base, points) = request(b"GET /?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone(), points[1].clone()];
        let payloads = sets(&[&["x", "y"], &["1", "2", "3"]]);
        let plan = AttackPlan::new(AttackKind::ClusterBomb, 2, &[2, 3], 1_000);
        let seen = Arc::new(Mutex::new(Vec::new()));

        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::unthrottled(4));
        let r = run(
            a,
            recording_sender(seen.clone(), "HTTP/1.1 200 OK\r\n\r\nok"),
            None,
        )
        .await;

        assert_eq!(r.sent, 6);
        assert_eq!(r.combinations, 6);
        assert!(!r.truncated);
        let mut got: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|b| {
                String::from_utf8_lossy(b)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                "GET /?a=x&b=1 HTTP/1.1",
                "GET /?a=x&b=2 HTTP/1.1",
                "GET /?a=x&b=3 HTTP/1.1",
                "GET /?a=y&b=1 HTTP/1.1",
                "GET /?a=y&b=2 HTTP/1.1",
                "GET /?a=y&b=3 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn battering_ram_puts_the_same_payload_everywhere_at_once() {
        let (base, points) = request(b"GET /?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone(), points[1].clone()];
        let payloads = sets(&[&["ZZ", "QQ"]]);
        let plan = AttackPlan::new(AttackKind::BatteringRam, 2, &[2], 1_000);
        let seen = Arc::new(Mutex::new(Vec::new()));

        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::unthrottled(4));
        let r = run(
            a,
            recording_sender(seen.clone(), "HTTP/1.1 200 OK\r\n\r\nok"),
            None,
        )
        .await;

        assert_eq!(r.sent, 2, "one request per payload, both positions filled");
        let mut got: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|b| {
                String::from_utf8_lossy(b)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec!["GET /?a=QQ&b=QQ HTTP/1.1", "GET /?a=ZZ&b=ZZ HTTP/1.1"]
        );
    }

    /// The output an operator reads: three distinct behaviours out of 30 responses, rarest first,
    /// with one stored exemplar each rather than 30 bodies.
    #[tokio::test]
    async fn results_collapse_to_buckets_keyed_on_status_length_and_reflection() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let words: Vec<String> = (0..30).map(|i| format!("w{i:02}")).collect();
        let payloads: Vec<Vec<Bytes>> = vec![
            words
                .iter()
                .map(|w| Bytes::from(w.clone().into_bytes()))
                .collect(),
        ];
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[30], 1_000);

        let stored = Arc::new(AtomicUsize::new(0));
        let counter = stored.clone();
        let record: RecordFn = Arc::new(move |_raw| counter.fetch_add(1, Ordering::SeqCst) as u64);

        // w00 is echoed back; w01 gets a 500; everything else is an identical 200.
        let sender: SendFn = Arc::new(|bytes: Vec<u8>| {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            Box::pin(async move {
                let raw = if text.contains("a=w00") {
                    Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nw00")
                } else if text.contains("a=w01") {
                    Bytes::from_static(b"HTTP/1.1 500 Err\r\nContent-Length: 2\r\n\r\nno")
                } else {
                    Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                };
                let status = if text.contains("a=w01") { 500 } else { 200 };
                Ok(Sent {
                    raw,
                    duration: Duration::from_millis(1),
                    status: Some(status),
                })
            })
        });

        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::unthrottled(8));
        let r = run(a, sender, Some(record)).await;

        assert_eq!(r.sent, 30);
        assert_eq!(r.buckets.len(), 3, "30 responses, 3 distinct behaviours");
        assert!(!r.buckets_truncated);

        // Rarest first: the reflected one and the 500 come before the 28-strong baseline.
        assert_eq!(r.buckets[0].count, 1);
        assert_eq!(r.buckets[1].count, 1);
        assert_eq!(r.buckets[2].count, 28);
        assert_eq!(r.buckets[2].status, Some(200));

        let reflected: Vec<&ResultBucket> = r.buckets.iter().filter(|b| b.reflected).collect();
        assert_eq!(reflected.len(), 1, "only w00 came back in its response");
        assert_eq!(
            reflected[0].first_ordinal, 0,
            "and it was the first payload"
        );

        let five_hundred: Vec<&ResultBucket> =
            r.buckets.iter().filter(|b| b.status == Some(500)).collect();
        assert_eq!(five_hundred.len(), 1);
        assert_eq!(five_hundred[0].first_ordinal, 1);

        assert_eq!(
            stored.load(Ordering::SeqCst),
            3,
            "30 responses must cost 3 stored bodies, one exemplar per bucket"
        );
    }

    #[tokio::test]
    async fn a_bounded_cluster_bomb_reports_what_it_did_not_send() {
        let (base, points) = request(b"GET /?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone(), points[1].clone()];
        let big: Vec<Bytes> = (0..100).map(|i| Bytes::from(format!("p{i}"))).collect();
        let payloads = vec![big.clone(), big];
        let plan = AttackPlan::new(AttackKind::ClusterBomb, 2, &[100, 100], 25);
        let seen = Arc::new(Mutex::new(Vec::new()));

        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::unthrottled(8));
        let r = run(
            a,
            recording_sender(seen.clone(), "HTTP/1.1 200 OK\r\n\r\nok"),
            None,
        )
        .await;

        assert_eq!(r.combinations, 10_000, "the operator is told the real size");
        assert_eq!(r.max_requests, 25);
        assert!(r.truncated, "and that the bound bit");
        assert_eq!(r.planned, 25);
        assert_eq!(r.sent, 25);
        assert_eq!(
            seen.lock().unwrap().len(),
            25,
            "no request beyond the bound went out"
        );
    }

    #[tokio::test]
    async fn failures_are_grouped_and_do_not_stop_the_attack() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads = sets(&[&["a", "b", "c", "d"]]);
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[4], 100);

        let sender: SendFn = Arc::new(|bytes: Vec<u8>| {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            Box::pin(async move {
                if text.contains("a=b") || text.contains("a=c") {
                    Err("connect 127.0.0.1:1: connection refused".to_string())
                } else {
                    Ok(Sent {
                        raw: Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n"),
                        duration: Duration::from_millis(1),
                        status: Some(200),
                    })
                }
            })
        });

        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::unthrottled(4));
        let r = run(a, sender, None).await;

        assert_eq!(r.sent, 2);
        assert_eq!(r.failed, 2);
        assert_eq!(r.errors.len(), 1, "one message, two occurrences");
        assert_eq!(r.errors[0].count, 2);
        assert_eq!(
            r.errors[0].first_ordinal,
            Some(1),
            "and a replayable ordinal"
        );
        assert_eq!(r.attempts.len(), 4, "every attempt still has a row");
        assert_eq!(
            r.attempts[1].error.as_deref(),
            Some("connect 127.0.0.1:1: connection refused")
        );
        assert!(r.attempts[0].error.is_none());
    }

    // ---- measured against a real socket ---------------------------------------------------
    //
    // The rate limiter is only a correctness feature if it holds when requests really go out over
    // TCP with real scheduling jitter, so these two tests measure arrivals at the far end rather
    // than trusting the bucket arithmetic.

    struct Probe {
        addr: std::net::SocketAddr,
        arrivals: Arc<Mutex<Vec<Instant>>>,
        peak: Arc<AtomicUsize>,
    }

    /// A server that timestamps every connection, tracks peak concurrency, and optionally holds
    /// each request open for `delay` before answering.
    async fn probe_server(delay: Duration) -> Probe {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (a, l, p) = (arrivals.clone(), live.clone(), peak.clone());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (a, l, p) = (a.clone(), l.clone(), p.clone());
                tokio::spawn(async move {
                    a.lock().unwrap().push(Instant::now());
                    let now = l.fetch_add(1, Ordering::SeqCst) + 1;
                    p.fetch_max(now, Ordering::SeqCst);
                    let mut buf = [0u8; 8192];
                    let _ = sock.read(&mut buf).await;
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                    let _ = sock.shutdown().await;
                    l.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Probe {
            addr,
            arrivals,
            peak,
        }
    }

    /// One connection per request, closed by the server. Deliberately not the repeater: this crate
    /// must not know about the network stack, and the test proves the seam works.
    fn tcp_sender(addr: std::net::SocketAddr) -> SendFn {
        Arc::new(move |bytes: Vec<u8>| {
            Box::pin(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let started = Instant::now();
                let mut s = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(|e| e.to_string())?;
                s.write_all(&bytes).await.map_err(|e| e.to_string())?;
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
                Ok(Sent {
                    raw: Bytes::from(buf),
                    duration: started.elapsed(),
                    status: Some(200),
                })
            })
        })
    }

    /// Measured at the target: no window of length T received more than `burst + rps*T` requests,
    /// and the whole attack could not finish before `(n - burst) / rps`.
    #[tokio::test]
    async fn the_target_never_receives_more_than_the_configured_rate() {
        let rps = 50.0;
        let burst = 1u32;
        let n = 40usize;
        let probe = probe_server(Duration::ZERO).await;

        let (base, points) =
            request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads: Vec<Vec<Bytes>> =
            vec![(0..n).map(|i| Bytes::from(format!("p{i}"))).collect()];
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[n], 1_000);

        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::new(
            Some(rps),
            burst,
            8,
        ));
        let t0 = Instant::now();
        let r = run(a, tcp_sender(probe.addr), None).await;
        let elapsed = t0.elapsed();

        assert_eq!(
            r.sent, n,
            "every request must have actually gone out: {r:?}"
        );

        let floor = Duration::from_secs_f64((n as f64 - f64::from(burst)) / rps);
        assert!(
            elapsed >= floor,
            "{n} requests at {rps}/s finished in {elapsed:?}, faster than the {floor:?} floor"
        );

        let at = probe.arrivals.lock().unwrap().clone();
        assert_eq!(at.len(), n, "the server did not see every request");
        let window = Duration::from_millis(500);
        // The bucket's clock and these arrival timestamps are both wall-clock, and when the whole
        // workspace suite runs at once the two drift by tens of milliseconds. A request the limiter
        // admitted legitimately just outside the window can then be *timestamped* just inside it —
        // a measurement artefact, not a limiter that let an extra request through. Observed as a
        // 27th arrival against an ideal allowance of 26.
        //
        // The allowance is that drift expressed in requests; it is not slack in the bound under
        // test. The bound itself is the `floor` assertion above, which requires the attack to take
        // at least (n - burst)/rps and which no amount of jitter can satisfy if the limiter is
        // absent — and an unlimited run would put all 40 arrivals in one window, far past even the
        // widened allowance.
        let jitter = Duration::from_millis(60);
        let allowed = f64::from(burst) + rps * (window + jitter).as_secs_f64();
        for (i, start) in at.iter().enumerate() {
            let count = at[i..]
                .iter()
                .take_while(|t| **t - *start <= window)
                .count();
            assert!(
                count as f64 <= allowed,
                "{count} requests arrived within {window:?}; burst {burst} + {rps}/s allows {allowed}"
            );
        }
    }

    /// The other half: the limiter must bound the attack without serialising it. With a slow target
    /// and eight slots, wall time is a fraction of the sequential cost — and the target never sees a
    /// ninth concurrent request.
    #[tokio::test]
    async fn requests_run_concurrently_up_to_the_in_flight_cap() {
        let per_request = Duration::from_millis(60);
        let slots = 8;
        let n = 32usize;
        let probe = probe_server(per_request).await;

        let (base, points) =
            request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads: Vec<Vec<Bytes>> =
            vec![(0..n).map(|i| Bytes::from(format!("p{i}"))).collect()];
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[n], 1_000);

        let a =
            Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::unthrottled(slots));
        let t0 = Instant::now();
        let r = run(a, tcp_sender(probe.addr), None).await;
        let elapsed = t0.elapsed();

        assert_eq!(r.sent, n);
        assert!(
            probe.peak.load(Ordering::SeqCst) <= slots,
            "the target saw {} concurrent requests against a cap of {slots}",
            probe.peak.load(Ordering::SeqCst)
        );
        let sequential = per_request * n as u32;
        assert!(
            elapsed < sequential / 2,
            "{n} requests over {slots} slots took {elapsed:?}; sequential would be {sequential:?}, \
             so this did not run concurrently"
        );
    }

    // ---- grep-match and grep-extract -------------------------------------------------------

    fn re(p: &str) -> Arc<regex::bytes::Regex> {
        Arc::new(regex::bytes::Regex::new(p).unwrap())
    }

    /// A sender whose response depends on the payload, so a grep has something to disagree about.
    fn varying_sender() -> SendFn {
        Arc::new(|bytes: Vec<u8>| {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            Box::pin(async move {
                // Same status and same length for every payload, so the bucket key cannot tell them
                // apart — which is the point of the test below.
                let raw = if text.contains("a=admin") {
                    Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nrole=ADMIN.")
                } else {
                    Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nrole=user..")
                };
                Ok(Sent {
                    raw,
                    duration: Duration::from_millis(1),
                    status: Some(200),
                })
            })
        })
    }

    #[tokio::test]
    async fn grep_match_flags_the_responses_that_match_and_leaves_the_rest_alone() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads = sets(&[&["guest", "admin", "other"]]);
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[3], 100);

        let a = Attack::new(&base, &sel, &payloads, &plan)
            .with_limits(RateLimit::unthrottled(4))
            .with_grep(Grep {
                match_re: Some(re("ADMIN")),
                extract_re: None,
            });
        let r = run(a, varying_sender(), None).await;

        assert_eq!(r.sent, 3);
        assert_eq!(r.grep_matched, 1, "only the admin payload's response matched");
        let matched: Vec<usize> = r
            .attempts
            .iter()
            .filter(|x| x.grep_matched == Some(true))
            .map(|x| x.ordinal)
            .collect();
        assert_eq!(matched, vec![1], "the second payload is `admin`");
        assert!(
            r.attempts
                .iter()
                .all(|x| x.grep_matched.is_some() && x.grep_extract.is_none()),
            "every row was asked the match question and none the extract one"
        );
    }

    /// The engine's own doc says arbitrary grep patterns are not part of the bucket key. This is that
    /// claim as a test: three responses that agree on `(status, length, reflected)` collapse into one
    /// bucket even though the grep disagrees, and the disagreement survives as a count.
    #[tokio::test]
    async fn a_grep_result_does_not_split_a_bucket_it_is_counted_inside_it() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads = sets(&[&["guest", "admin", "other"]]);
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[3], 100);

        let a = Attack::new(&base, &sel, &payloads, &plan)
            .with_limits(RateLimit::unthrottled(4))
            .with_grep(Grep {
                match_re: Some(re("ADMIN")),
                extract_re: None,
            });
        let r = run(a, varying_sender(), None).await;

        assert_eq!(
            r.buckets.len(),
            1,
            "the grep must not have become part of the key: {:?}",
            r.buckets
        );
        assert_eq!(r.buckets[0].count, 3);
        assert_eq!(
            r.buckets[0].grep_matches, 1,
            "1 of 3 matched, and a mixture must be visible as one"
        );
    }

    #[tokio::test]
    async fn grep_extract_returns_the_first_capture_group_or_the_whole_match() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads = sets(&[&["guest", "admin"]]);
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[2], 100);

        // With a group: just the value.
        let a = Attack::new(&base, &sel, &payloads, &plan)
            .with_limits(RateLimit::unthrottled(4))
            .with_grep(Grep {
                match_re: None,
                extract_re: Some(re("role=([A-Za-z]+)")),
            });
        let r = run(a, varying_sender(), None).await;
        let got: Vec<Option<String>> = r.attempts.iter().map(|x| x.grep_extract.clone()).collect();
        assert_eq!(
            got,
            vec![Some("user".to_string()), Some("ADMIN".to_string())]
        );
        assert_eq!(
            r.buckets[0].grep_extract.as_deref(),
            Some("user"),
            "the bucket carries its exemplar's value, which is ordinal 0's"
        );

        // Without a group: the whole match, because a pattern with no parentheses still means
        // something and returning nothing would be a silent failure.
        let a = Attack::new(&base, &sel, &payloads, &plan)
            .with_limits(RateLimit::unthrottled(4))
            .with_grep(Grep {
                match_re: None,
                extract_re: Some(re("role=[A-Za-z]+")),
            });
        let r = run(a, varying_sender(), None).await;
        assert_eq!(r.attempts[1].grep_extract.as_deref(), Some("role=ADMIN"));
    }

    #[tokio::test]
    async fn an_extraction_longer_than_the_cap_is_cut_to_it() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads = sets(&[&["x"]]);
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[1], 10);

        // A body far longer than MAX_EXTRACT, and a pattern that matches all of it.
        let big = Bytes::from(format!(
            "HTTP/1.1 200 OK\r\n\r\n{}",
            "z".repeat(MAX_EXTRACT * 3)
        ));
        let sender: SendFn = Arc::new(move |_| {
            let raw = big.clone();
            Box::pin(async move {
                Ok(Sent {
                    raw,
                    duration: Duration::from_millis(1),
                    status: Some(200),
                })
            })
        });

        let a = Attack::new(&base, &sel, &payloads, &plan)
            .with_limits(RateLimit::unthrottled(2))
            .with_grep(Grep {
                match_re: None,
                extract_re: Some(re("z+")),
            });
        let r = run(a, sender, None).await;
        assert_eq!(
            r.attempts[0].grep_extract.as_ref().map(|s| s.len()),
            Some(MAX_EXTRACT),
            "a whole-body capture must not land in the report"
        );
    }

    /// The no-change guarantee: an attack that configures no grep must produce the report it produced
    /// before greps existed, with the two new fields saying "not asked" rather than "no".
    #[tokio::test]
    async fn an_attack_with_no_grep_reports_no_grep_results_at_all() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads = sets(&[&["guest", "admin"]]);
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[2], 100);

        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::unthrottled(4));
        let r = run(a, varying_sender(), None).await;

        assert_eq!(r.grep_matched, 0);
        assert!(
            r.attempts
                .iter()
                .all(|x| x.grep_matched.is_none() && x.grep_extract.is_none()),
            "an unasked question must not be answered"
        );
        assert!(r.buckets.iter().all(|b| b.grep_matches == 0));
        assert_eq!(r.pool, None);
        assert_eq!(r.auto_throttle_engaged, 0);
    }

    // ---- resource pools ---------------------------------------------------------------------

    /// The auto-throttle end to end: a target that answers 429 makes the engine cut its own rate, and
    /// the report says so rather than leaving the operator to infer it from the elapsed time.
    #[tokio::test]
    async fn a_target_answering_429_makes_the_engine_slow_itself_down_and_report_it() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads: Vec<Vec<Bytes>> =
            vec![(0..12).map(|i| Bytes::from(format!("p{i}"))).collect()];
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[12], 100);

        let sender: SendFn = Arc::new(|_| {
            Box::pin(async move {
                Ok(Sent {
                    raw: Bytes::from_static(b"HTTP/1.1 429 Too Many\r\n\r\n"),
                    duration: Duration::from_millis(1),
                    status: Some(429),
                })
            })
        });

        // One slot, so responses are observed strictly before the next request asks for a token.
        let limits = RateLimit::new(Some(200.0), 1, 1)
            .named("cautious")
            .with_auto_throttle(crate::AutoThrottle {
                statuses: vec![429],
                after: 2,
                factor: 4.0,
                recover_after: 100,
            });
        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(limits);
        let r = run(a, sender, None).await;

        assert_eq!(r.sent, 12, "throttling must not lose requests");
        assert!(
            r.auto_throttle_engaged >= 1,
            "twelve 429s should have engaged the throttle at least once"
        );
        assert_eq!(
            r.pool.as_deref(),
            Some("cautious"),
            "the pool name must come back for the operator to reuse"
        );
    }

    /// The other half, and the more important one: the same attack against a healthy target must be
    /// untouched by an auto-throttle it never triggers.
    #[tokio::test]
    async fn an_auto_throttle_that_never_triggers_changes_nothing_about_the_attack() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads = sets(&[&["a", "b", "c", "d"]]);
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[4], 100);

        let limits = RateLimit::unthrottled(4).with_auto_throttle(crate::AutoThrottle::default());
        let a = Attack::new(&base, &sel, &payloads, &plan).with_limits(limits);
        let r = run(
            a,
            recording_sender(Arc::new(Mutex::new(Vec::new())), "HTTP/1.1 200 OK\r\n\r\nok"),
            None,
        )
        .await;

        assert_eq!(r.sent, 4);
        assert_eq!(r.failed, 0);
        assert_eq!(
            r.auto_throttle_engaged, 0,
            "a healthy target must not have tripped it"
        );
    }

    #[tokio::test]
    async fn detail_rows_are_capped_but_bucket_counts_are_not() {
        let (base, points) = request(b"GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n");
        let sel = vec![points[0].clone()];
        let payloads: Vec<Vec<Bytes>> =
            vec![(0..200).map(|i| Bytes::from(format!("p{i}"))).collect()];
        let plan = AttackPlan::new(AttackKind::Sniper, 1, &[200], 1_000);

        let mut a =
            Attack::new(&base, &sel, &payloads, &plan).with_limits(RateLimit::unthrottled(16));
        a.detail_limit = 10;
        let r = run(
            a,
            recording_sender(Arc::new(Mutex::new(Vec::new())), "HTTP/1.1 204 No\r\n\r\n"),
            None,
        )
        .await;

        assert_eq!(r.sent, 200);
        assert_eq!(r.attempts.len(), 10, "detail is bounded");
        assert_eq!(
            r.detail_limit, 10,
            "and the bound is stated, not left to be inferred"
        );
        assert_eq!(
            r.attempts.iter().map(|x| x.ordinal).collect::<Vec<_>>(),
            (0..10).collect::<Vec<_>>(),
            "and kept in plan order"
        );
        assert_eq!(
            r.buckets.iter().map(|b| b.count).sum::<usize>(),
            200,
            "counts are not"
        );
    }
}
