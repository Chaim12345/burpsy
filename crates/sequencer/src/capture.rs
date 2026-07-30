//! Live capture: send one request template repeatedly and pull a token out of each response.
//!
//! # The one way out
//!
//! Every request here leaves through [`burpsy_sender::AuthorisedSender::send_async`], which is the
//! workspace's single authorising path to a socket. This module names no transport, holds no
//! client, and its `tokio` dependency is narrowed to `time` so that `sleep` is the only runtime
//! feature it can reach — see `Cargo.toml` and `crates/sender/AGENTS.md`. The scope decision is
//! made inside the sender against the actual outbound bytes, once per request, so a template
//! aimed somewhere the engagement does not cover is refused rather than sent.
//!
//! # Extraction is the mirror of Intruder's insertion
//!
//! `burpsy_intruder`'s insertion point is a [`burpsy_core::Span`] plus a kind: it says *where in a
//! request* a payload goes. [`Extractor`] is the same idea pointed the other way — where in a
//! *response* a token is — and it is deliberately the same two mechanisms an operator already has
//! elsewhere: a byte-offset span, or a pattern. Nothing is copied but the token itself.
//!
//! # Why this is bounded, and bounded twice
//!
//! A token capture is a loop that sends real traffic to someone else's server, so an unbounded one
//! is an outage with a progress bar. [`CaptureConfig::count`] is capped at [`MAX_TOKENS`] the way
//! `burpsy_intruder::AttackPlan` caps a combination count — the request states a bound, the bound
//! is enforced, and the report says what it was. The second bound is
//! [`MAX_CONSECUTIVE_FAILURES`]: an extractor that matches nothing would otherwise spend the whole
//! budget discovering that fact one request at a time.

use burpsy_core::{Direction, parse};
use burpsy_sender::{AuthorisedSender, Target};
use bytes::Bytes;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// Tokens captured when the operator does not choose a number.
///
/// 100 is the conventional floor for this kind of analysis and the point below which a per-position
/// character distribution has too few samples to say anything: with fewer tokens than the alphabet
/// is wide, every position is capped at `log2(tokens)` bits whatever the generator does. It is a
/// starting point, not a sufficient sample — a single FIPS block needs 20,000 bits, which is 1,250
/// tokens of 16 bits.
pub const DEFAULT_TOKENS: usize = 100;

/// Hard ceiling on one capture session.
///
/// Ours, not quoted from anywhere, and picked for a reason worth stating: at a typical 128-bit
/// token this is ~2.5 million bits, or ~128 whole FIPS blocks, well past where another block changes
/// a verdict. It also bounds the traffic one API call can produce, which is the property that
/// actually matters when the target belongs to someone else.
pub const MAX_TOKENS: usize = 20_000;

/// Consecutive extraction or transport failures before a capture gives up.
///
/// A misconfigured extractor is the common case here, and it fails identically every time. Ten is
/// enough to ride out a flaky target and few enough that a wrong regex costs ten requests instead
/// of twenty thousand.
pub const MAX_CONSECUTIVE_FAILURES: usize = 10;

/// Which part of the response an [`Extractor`] addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsePart {
    /// The whole response, status line and headers included. Offsets in a `Span` are usually meant
    /// this way, because that is what the operator counted them from.
    Whole,
    /// The status line and headers, without the body. Where a `Set-Cookie` session id lives.
    Headers,
    /// The body only. Where a CSRF token in a form or a JSON field lives.
    Body,
}

impl ResponsePart {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponsePart::Whole => "whole",
            ResponsePart::Headers => "headers",
            ResponsePart::Body => "body",
        }
    }

    /// The slice this part addresses.
    ///
    /// A response that will not parse yields the whole thing for [`ResponsePart::Whole`] and nothing
    /// for the other two. Guessing where a body starts in a message we could not read would be
    /// worse than admitting we do not know: the token would come out of the wrong bytes and the
    /// analysis would silently describe something else.
    pub fn slice<'a>(&self, raw: &'a [u8]) -> Option<&'a [u8]> {
        match self {
            ResponsePart::Whole => Some(raw),
            ResponsePart::Headers | ResponsePart::Body => {
                let shape = parse(raw, Direction::Response).ok()?;
                let body = shape.body;
                let start = body.offset.min(raw.len());
                match self {
                    ResponsePart::Body => Some(&raw[start..body.end().min(raw.len())]),
                    _ => Some(&raw[..start]),
                }
            }
        }
    }
}

/// Where in a response the token is.
#[derive(Debug, Clone)]
pub enum Extractor {
    /// A byte-offset span into `part`. The mirror of an insertion point's `Span`.
    Span {
        part: ResponsePart,
        offset: usize,
        len: usize,
    },
    /// The first match of `pattern` against `part`. Capture group 1 when the pattern has one, so
    /// `sid=([0-9a-f]+)` yields the token without the `sid=`; otherwise the whole match.
    Pattern {
        part: ResponsePart,
        pattern: regex::bytes::Regex,
    },
}

impl Extractor {
    /// Compile a pattern extractor.
    ///
    /// `regex::bytes` rather than `regex`, because a response body is bytes and may not be UTF-8 —
    /// requiring valid UTF-8 here would refuse to capture from a gzip or a binary payload for a
    /// reason that has nothing to do with the token.
    pub fn pattern(part: ResponsePart, pattern: &str) -> Result<Self, regex::Error> {
        Ok(Extractor::Pattern {
            part,
            pattern: regex::bytes::Regex::new(pattern)?,
        })
    }

    pub fn part(&self) -> ResponsePart {
        match self {
            Extractor::Span { part, .. } | Extractor::Pattern { part, .. } => *part,
        }
    }

    /// Pull the token out of one response, or say why not.
    ///
    /// An empty match is an error rather than an empty token: a zero-length token is not a sample,
    /// and letting it into the set would drag every statistic towards a value nothing produced.
    pub fn extract(&self, raw: &[u8]) -> Result<Bytes, String> {
        let part = self.part();
        let slice = part.slice(raw).ok_or_else(|| {
            format!(
                "response did not parse, so its {} is unknown",
                part.as_str()
            )
        })?;
        let found = match self {
            Extractor::Span { offset, len, .. } => {
                let end = offset.checked_add(*len).unwrap_or(usize::MAX);
                if end > slice.len() {
                    return Err(format!(
                        "span {offset}..{end} runs past the {} ({} bytes)",
                        part.as_str(),
                        slice.len()
                    ));
                }
                &slice[*offset..end]
            }
            Extractor::Pattern { pattern, .. } => {
                let caps = pattern.captures(slice).ok_or_else(|| {
                    format!(
                        "pattern did not match the {} of the response",
                        part.as_str()
                    )
                })?;
                // Group 1 when the pattern declares one, else group 0. `get` rather than indexing:
                // an optional group that did not participate must read as "no token", not panic.
                let group = if pattern.captures_len() > 1 { 1 } else { 0 };
                caps.get(group)
                    .ok_or_else(|| {
                        format!("capture group {group} did not participate in the match")
                    })?
                    .as_bytes()
            }
        };
        if found.is_empty() {
            return Err("extracted a zero-length token".to_string());
        }
        Ok(Bytes::copy_from_slice(found))
    }
}

/// One live-capture job.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub target: Target,
    /// The request template, exactly as it should go on the wire.
    pub raw: Bytes,
    /// Tokens wanted. Clamped to `1..=`[`MAX_TOKENS`] by [`CaptureConfig::new`].
    pub count: usize,
    pub extract: Extractor,
    /// Wait between requests. Serial by construction — see [`capture`].
    pub delay: Duration,
}

impl CaptureConfig {
    /// Clamp the requested count into the allowed range at construction, so no later code has to
    /// remember to. Returns the config and whether the bound bit.
    pub fn new(
        target: Target,
        raw: Bytes,
        count: Option<usize>,
        extract: Extractor,
        delay: Duration,
    ) -> (Self, bool) {
        let wanted = count.unwrap_or(DEFAULT_TOKENS);
        let clamped = wanted.clamp(1, MAX_TOKENS);
        (
            Self {
                target,
                raw,
                count: clamped,
                extract,
                delay,
            },
            clamped != wanted,
        )
    }
}

/// Live progress, shared between the capture loop and whatever is watching it.
///
/// The web layer polls this while the capture runs, and stops it through the same handle. Atomics
/// rather than a lock for the same reason `AuthorisedSender`'s counters are atomics: this is read
/// from a different task than it is written from, and a `Cell` here would not be `Sync`.
#[derive(Debug, Default)]
pub struct CaptureProgress {
    captured: AtomicUsize,
    attempted: AtomicUsize,
    stop: AtomicBool,
}

impl CaptureProgress {
    pub fn captured(&self) -> usize {
        self.captured.load(Ordering::Relaxed)
    }

    pub fn attempted(&self) -> usize {
        self.attempted.load(Ordering::Relaxed)
    }

    /// Ask the capture to finish early. It stops before its next request, keeping what it has —
    /// tokens already captured are real samples and throwing them away would be worse than
    /// analysing fewer.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

/// Why a capture ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureEnd {
    /// Every requested token was captured.
    Complete,
    /// The operator stopped it.
    Stopped,
    /// [`MAX_CONSECUTIVE_FAILURES`] in a row.
    GaveUp,
    /// Scope refused the request. Nothing further was attempted, and nothing reached a socket.
    Refused,
}

/// What a capture produced.
#[derive(Debug, Clone)]
pub struct CaptureOutcome {
    pub tokens: Vec<Bytes>,
    pub attempted: usize,
    pub ended: CaptureEnd,
    /// Distinct failure messages with how often each happened. Deduplicated because a bad extractor
    /// produces the identical message every time and a list of ten thousand copies is not a report.
    pub failures: Vec<(String, usize)>,
    /// Straight off the sender's own counters, so "did anything actually go out" is answered by the
    /// chokepoint rather than by this loop's bookkeeping.
    pub sent: u32,
    pub refused: u32,
}

impl CaptureOutcome {
    /// Total failures across every distinct message.
    pub fn failure_count(&self) -> usize {
        self.failures.iter().map(|(_, n)| n).sum()
    }
}

/// Send the template `cfg.count` times and collect a token from each response.
///
/// Serial, one request at a time, and that is a decision rather than a simplification: tokens are
/// usually issued against session state, and overlapping requests let the server interleave them so
/// the order captured is not the order generated. A run-order artefact in a randomness analysis
/// would be indistinguishable from a weak generator, which is the one mistake this whole feature
/// exists to avoid making.
pub async fn capture(
    sender: &AuthorisedSender,
    cfg: &CaptureConfig,
    progress: &CaptureProgress,
) -> CaptureOutcome {
    let mut tokens = Vec::with_capacity(cfg.count);
    let mut failures: Vec<(String, usize)> = Vec::new();
    let mut consecutive = 0usize;
    let mut attempted = 0usize;
    let mut ended = CaptureEnd::Complete;

    /// Deduplicate as we go. A bad extractor produces the identical message every attempt, and a
    /// list of ten thousand copies of it is noise rather than a record.
    fn note(failures: &mut Vec<(String, usize)>, why: String) {
        match failures.iter_mut().find(|(m, _)| *m == why) {
            Some((_, n)) => *n += 1,
            None => failures.push((why, 1)),
        }
    }

    while tokens.len() < cfg.count {
        if progress.stopping() {
            ended = CaptureEnd::Stopped;
            break;
        }
        if attempted > 0 && !cfg.delay.is_zero() {
            tokio::time::sleep(cfg.delay).await;
        }
        attempted += 1;
        progress.attempted.store(attempted, Ordering::Relaxed);

        match sender.send_async(&cfg.target, &cfg.raw).await {
            Ok(response) => match cfg.extract.extract(&response.raw_response) {
                Ok(token) => {
                    tokens.push(token);
                    progress.captured.store(tokens.len(), Ordering::Relaxed);
                    consecutive = 0;
                    continue;
                }
                Err(why) => note(&mut failures, why),
            },
            Err(e) if e.is_refused() => {
                // Scope said no. Retrying cannot change that, and the remaining budget would be
                // spent proving it, so stop here and say which it was.
                note(&mut failures, e.to_string());
                ended = CaptureEnd::Refused;
                break;
            }
            Err(e) => note(&mut failures, e.to_string()),
        }
        consecutive += 1;
        if consecutive >= MAX_CONSECUTIVE_FAILURES {
            ended = CaptureEnd::GaveUp;
            break;
        }
    }

    CaptureOutcome {
        tokens,
        attempted,
        ended,
        failures,
        sent: sender.sent(),
        refused: sender.refused(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{Scope, ScopeRule, SharedScope};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const BODY_TOKEN: &[u8] = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=a1b2c3d4\r\nContent-Length: 26\r\n\r\n<input name=csrf value=9f8e>";

    fn scope_of(host: &str) -> SharedScope {
        let mut s = Scope::new();
        s.add(ScopeRule::include(host));
        SharedScope::new(s)
    }

    // ---- extraction, without a network ------------------------------------------------------

    #[test]
    fn a_pattern_against_the_headers_finds_a_session_cookie() {
        let e = Extractor::pattern(ResponsePart::Headers, "sid=([0-9a-f]+)").unwrap();
        assert_eq!(&e.extract(BODY_TOKEN).unwrap()[..], b"a1b2c3d4");
    }

    #[test]
    fn a_pattern_against_the_body_finds_a_csrf_token_and_not_the_cookie() {
        let e = Extractor::pattern(ResponsePart::Body, "value=([0-9a-f]+)").unwrap();
        assert_eq!(&e.extract(BODY_TOKEN).unwrap()[..], b"9f8e");
        // The same pattern aimed at the headers must fail rather than reach into the body.
        let headers = Extractor::pattern(ResponsePart::Headers, "value=([0-9a-f]+)").unwrap();
        assert!(headers.extract(BODY_TOKEN).is_err());
    }

    /// A pattern with no capture group yields the whole match, so the simple case needs no groups.
    #[test]
    fn a_pattern_with_no_group_yields_the_whole_match() {
        let e = Extractor::pattern(ResponsePart::Whole, "[0-9a-f]{8}").unwrap();
        assert_eq!(&e.extract(BODY_TOKEN).unwrap()[..], b"a1b2c3d4");
    }

    #[test]
    fn a_span_is_taken_from_the_part_it_names() {
        // "9f8e" sits at offset 22 of the body.
        let body = ResponsePart::Body.slice(BODY_TOKEN).unwrap();
        let offset = body.windows(4).position(|w| w == b"9f8e").unwrap();
        let e = Extractor::Span {
            part: ResponsePart::Body,
            offset,
            len: 4,
        };
        assert_eq!(&e.extract(BODY_TOKEN).unwrap()[..], b"9f8e");
    }

    #[test]
    fn a_span_past_the_end_is_refused_rather_than_silently_shortened() {
        let e = Extractor::Span {
            part: ResponsePart::Body,
            offset: 20,
            len: 9_999,
        };
        let err = e.extract(BODY_TOKEN).expect_err("must not truncate");
        assert!(err.contains("runs past"), "{err}");
    }

    #[test]
    fn a_zero_length_match_is_an_error_not_an_empty_token() {
        let e = Extractor::pattern(ResponsePart::Whole, "x*").unwrap();
        let err = e.extract(BODY_TOKEN).expect_err("empty is not a sample");
        assert!(err.contains("zero-length"), "{err}");
    }

    /// Refuse-by-default on unparseable input, the convention from the root `AGENTS.md`: a response
    /// whose framing cannot be read has no known body, and guessing one would pull the token out of
    /// the wrong bytes.
    ///
    /// The exact boundary is `burpsy_core::parse`'s, which is deliberately tolerant — an unterminated
    /// buffer is treated as all head with an empty body rather than rejected, because that is the
    /// traffic you most want to inspect. So there are two distinct outcomes here, and both are
    /// honest: a start line that will not parse at all yields *no* body, while a merely unterminated
    /// response yields an *empty* one. Neither invents bytes to match against.
    #[test]
    fn an_unparseable_response_has_no_body_rather_than_a_guessed_one() {
        // No space in the start line, so `parse` cannot split it and returns an error.
        let unparseable = b"notAStartLine\r\n\r\nsid=deadbeef";
        assert!(ResponsePart::Body.slice(unparseable).is_none());
        assert!(ResponsePart::Headers.slice(unparseable).is_none());
        assert_eq!(
            ResponsePart::Whole.slice(unparseable),
            Some(&unparseable[..]),
            "the whole thing is always knowable"
        );
        let body = Extractor::pattern(ResponsePart::Body, "sid=([a-f0-9]+)").unwrap();
        let err = body.extract(unparseable).expect_err("no body, no token");
        assert!(err.contains("did not parse"), "{err}");
        // And the token is emphatically not fished out of the raw bytes as a fallback.
        assert!(!err.contains("deadbeef"), "{err}");

        // Unterminated but parseable: the tolerant path. Head is everything, body is empty, so a body
        // extractor finds nothing rather than reading the headers by accident.
        let unterminated = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=cafe";
        assert_eq!(ResponsePart::Body.slice(unterminated), Some(&b""[..]));
        assert_eq!(
            ResponsePart::Headers.slice(unterminated),
            Some(&unterminated[..])
        );
        let err = body
            .extract(unterminated)
            .expect_err("empty body has no token");
        assert!(err.contains("did not match"), "{err}");
        let headers = Extractor::pattern(ResponsePart::Headers, "sid=([a-f0-9]+)").unwrap();
        assert_eq!(&headers.extract(unterminated).unwrap()[..], b"cafe");
    }

    #[test]
    fn a_bad_pattern_is_a_compile_error_the_caller_can_report() {
        assert!(Extractor::pattern(ResponsePart::Whole, "([unclosed").is_err());
    }

    // ---- bounds --------------------------------------------------------------------------------

    #[test]
    fn the_count_is_clamped_at_construction_and_the_clamp_is_reported() {
        let t = Target {
            host: "h".into(),
            port: 80,
            tls: false,
        };
        let e = Extractor::pattern(ResponsePart::Whole, "x").unwrap();
        let (cfg, clamped) = CaptureConfig::new(
            t.clone(),
            Bytes::new(),
            Some(MAX_TOKENS + 1),
            e.clone(),
            Duration::ZERO,
        );
        assert_eq!(cfg.count, MAX_TOKENS);
        assert!(clamped, "a silently reduced bound is a lie about what ran");

        let (cfg, clamped) =
            CaptureConfig::new(t.clone(), Bytes::new(), None, e.clone(), Duration::ZERO);
        assert_eq!(cfg.count, DEFAULT_TOKENS);
        assert!(!clamped);

        let (cfg, clamped) = CaptureConfig::new(t, Bytes::new(), Some(0), e, Duration::ZERO);
        assert_eq!(cfg.count, 1, "zero tokens is not a capture");
        assert!(clamped);
    }

    // ---- the loop, against a real local listener ---------------------------------------------

    /// A server that hands out a fresh 8-hex-digit token per request, from a counter so the test can
    /// predict every value.
    async fn token_server() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut n: u32 = 0;
            while let Ok((mut sock, _)) = listener.accept().await {
                n += 1;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let body = format!("sid={:08x}", n.wrapping_mul(2_654_435_761));
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        port
    }

    fn config_for(port: u16, count: usize, pattern: &str) -> CaptureConfig {
        let (cfg, _) = CaptureConfig::new(
            Target {
                host: "127.0.0.1".into(),
                port,
                tls: false,
            },
            Bytes::from_static(
                b"GET /token HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            ),
            Some(count),
            Extractor::pattern(ResponsePart::Body, pattern).unwrap(),
            Duration::ZERO,
        );
        cfg
    }

    #[tokio::test]
    async fn a_capture_collects_the_requested_number_of_tokens_through_the_chokepoint() {
        let port = token_server().await;
        let sender = AuthorisedSender::asynchronous(scope_of("127.0.0.1"), Duration::from_secs(5));
        let cfg = config_for(port, 5, "sid=([0-9a-f]+)");
        let progress = CaptureProgress::default();

        let out = capture(&sender, &cfg, &progress).await;
        assert_eq!(out.ended, CaptureEnd::Complete);
        assert_eq!(out.tokens.len(), 5, "failures: {:?}", out.failures);
        assert_eq!(out.attempted, 5);
        assert_eq!(out.failure_count(), 0);
        assert_eq!(out.sent, 5, "the sender's own counter is the witness");
        assert_eq!(out.refused, 0);
        assert_eq!(progress.captured(), 5);
        assert!(out.tokens.iter().all(|t| t.len() == 8));
        // Distinct tokens, so the capture is not re-reading one response.
        let distinct: std::collections::HashSet<&[u8]> =
            out.tokens.iter().map(|t| &t[..]).collect();
        assert_eq!(distinct.len(), 5);
    }

    /// The property the whole crate is built around: an out-of-scope template captures nothing and
    /// sends nothing. The refusal comes from the sender, not from a check written here.
    #[tokio::test]
    async fn an_out_of_scope_template_captures_nothing_and_reaches_no_socket() {
        let port = token_server().await;
        let sender =
            AuthorisedSender::asynchronous(scope_of("authorised.test"), Duration::from_secs(5));
        let cfg = config_for(port, 50, "sid=([0-9a-f]+)");

        let out = capture(&sender, &cfg, &CaptureProgress::default()).await;
        assert_eq!(out.ended, CaptureEnd::Refused);
        assert!(out.tokens.is_empty());
        assert_eq!(out.sent, 0, "nothing may leave for an unauthorised target");
        assert_eq!(out.refused, 1);
        assert_eq!(
            out.attempted, 1,
            "one refusal is enough; the rest of the budget must not be spent proving it again"
        );
        assert!(
            out.failures.iter().any(|(m, _)| m.contains("out of scope")),
            "the reason must survive to the report: {:?}",
            out.failures
        );
    }

    /// A wrong extractor must cost ten requests, not the whole budget.
    #[tokio::test]
    async fn an_extractor_that_never_matches_gives_up_after_the_consecutive_failure_bound() {
        let port = token_server().await;
        let sender = AuthorisedSender::asynchronous(scope_of("127.0.0.1"), Duration::from_secs(5));
        let cfg = config_for(port, 5_000, "this-is-not-in-the-response");

        let out = capture(&sender, &cfg, &CaptureProgress::default()).await;
        assert_eq!(out.ended, CaptureEnd::GaveUp);
        assert!(out.tokens.is_empty());
        assert_eq!(out.attempted, MAX_CONSECUTIVE_FAILURES);
        assert_eq!(
            out.failures.len(),
            1,
            "one distinct message, counted, not ten copies"
        );
        assert_eq!(out.failures[0].1, MAX_CONSECUTIVE_FAILURES);
    }

    #[tokio::test]
    async fn a_stopped_capture_keeps_what_it_already_had() {
        let port = token_server().await;
        let sender = AuthorisedSender::asynchronous(scope_of("127.0.0.1"), Duration::from_secs(5));
        let cfg = config_for(port, 5_000, "sid=([0-9a-f]+)");
        let progress = Arc::new(CaptureProgress::default());

        let watcher = {
            let progress = Arc::clone(&progress);
            tokio::spawn(async move {
                while progress.captured() < 3 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                progress.request_stop();
            })
        };
        let out = capture(&sender, &cfg, &progress).await;
        watcher.await.unwrap();

        assert_eq!(out.ended, CaptureEnd::Stopped);
        assert!(
            out.tokens.len() >= 3,
            "tokens already captured are real samples: got {}",
            out.tokens.len()
        );
        assert!(out.tokens.len() < 5_000);
    }
}
