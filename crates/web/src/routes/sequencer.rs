//! Sequencer: statistical randomness analysis of session tokens.
//!
//! Two token sources, and they are deliberately very different shapes over HTTP.
//!
//! **Paste** is one synchronous call. `POST /api/sequencer/analyse` takes text or an array, runs
//! [`burpsy_sequencer::analyse`], and returns the report. No network, no state, no polling — the
//! analysis of even 20,000 tokens is a handful of milliseconds of counting, so making the simple
//! path asynchronous would add a state machine to buy nothing. This is the default path.
//!
//! **Live capture** is start/poll/stop, because it cannot be anything else. Capturing 500 tokens at
//! a deliberately timid rate is minutes of real traffic to someone else's server. A single blocking
//! endpoint would hold one HTTP request open for all of it — browsers and intermediaries time such
//! a request out, an operator gets no progress and no way to stop it, and a disconnect would either
//! orphan the loop or lose the tokens. So a capture is a background task with a handle.
//!
//! # Why the capture state is an `Extension` and not a sixth `AppState` field
//!
//! `AppState`'s `Option` fields — `audit`, `export`, `intercept`, `session`, `live_audit` — are
//! `Option`, and threaded through the `router_*`/`serve_*` ladder, for one reason each: every one of
//! them holds something only the binary can build. A scanner hook, a CA, an interceptor, a login
//! macro. `None` there means "this process was not started with that", which is a real distinction
//! those routes have to report rather than paper over.
//!
//! This state holds none of that. A capture needs the request template the operator typed, the
//! `scope` `AppState` already carries, and the sender it builds itself. So an `Option` would encode
//! a state that cannot occur and every handler would carry a `None` branch that can never be taken,
//! and an eleventh ladder parameter plus a `router_sequencer`/`serve_sequencer` pair would be
//! ceremony with no caller to justify it.
//!
//! Instead the state rides an `Extension` layer applied by this module's own [`routes`], which is
//! exactly what `routes::tools::ToolState` does and for the same reason. It also keeps the promise
//! `routes/AGENTS.md` makes about this layout — adding a tool means adding a *file* — since it means
//! this feature lands without touching `AppState`, the constructor ladder, or the seven existing
//! `AppState { .. }` literals in other modules' tests.
//!
//! # Bounds
//!
//! Three, because this endpoint's job is to generate traffic and every one of them has been a real
//! bug in something:
//!
//! * tokens per capture — [`burpsy_sequencer::MAX_TOKENS`], clamped in the crate and reported back;
//! * concurrent captures — [`MAX_RUNNING`], so two operators cannot quietly triple the request rate;
//! * retained sessions — [`MAX_SESSIONS`], so a long-lived process does not accumulate reports.
//!
//! # These requests are not written to history, on purpose
//!
//! A capture sends the *same* request several hundred times. Recording each one would bury the
//! history it was mixed into and add nothing an operator could use — the interesting artefact is the
//! token set, not five hundred identical exchanges. What is reported instead is a full account: the
//! target, the template, how many were attempted, and the `sent`/`refused` counters read straight
//! off the [`AuthorisedSender`] rather than off this module's own bookkeeping. Nothing about the
//! traffic is hidden; it is summarised where a per-request log would be noise.

use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use burpsy_sender::{AuthorisedSender, parse_target};
use burpsy_sequencer::{
    CaptureConfig, CaptureEnd, CaptureProgress, Encoding, Extractor, ResponsePart, SequencerReport,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Captures allowed to run at once. Each one is a request loop against a live target; two is enough
/// to compare a login token against a CSRF token, and a third would mean the rate the operator chose
/// is not the rate the target sees.
pub const MAX_RUNNING: usize = 2;

/// Finished sessions kept for polling. Beyond this the oldest finished one is dropped, so a process
/// left running for a week does not hold every report it ever produced.
pub const MAX_SESSIONS: usize = 8;

/// Requests per second when the operator does not choose. Slower than Intruder's default on purpose:
/// a capture is long-running by nature, nothing about it is improved by going fast, and the token
/// issuer is often the most fragile endpoint an application has.
const DEFAULT_RPS: f64 = 5.0;

/// Floor on the operator-supplied rate, and the reason is arithmetic rather than politeness: an `rps`
/// of 1e-300 passes `> 0.0` and then asks for a 1e300-second sleep, which is not a representable
/// `Duration`. Same floor and same reasoning as `intruder_run`'s.
const MIN_RPS: f64 = 0.01;

/// Ceiling on the rate. Not a rate limiter for the target's benefit alone — above this the sleep
/// between requests stops being the thing that paces the loop.
const MAX_RPS: f64 = 200.0;

// ---- state ------------------------------------------------------------------------------------

/// A capture that has finished, and everything worth knowing about how it went.
struct Finished {
    ended: CaptureEnd,
    attempted: usize,
    sent: u32,
    refused: u32,
    failures: Vec<(String, usize)>,
    /// `None` when the capture produced no tokens at all — there is nothing to analyse, and an
    /// empty report would read as a result.
    report: Option<SequencerReport>,
}

struct Session {
    id: u64,
    target: String,
    wanted: usize,
    /// True when the requested count was clamped to the crate's ceiling. Reported, never silent.
    clamped: bool,
    progress: Arc<CaptureProgress>,
    outcome: parking_lot::Mutex<Option<Finished>>,
}

impl Session {
    fn running(&self) -> bool {
        self.outcome.lock().is_none()
    }
}

/// Live-capture sessions. See the module header for why this rides an `Extension` rather than
/// `AppState`.
#[derive(Default)]
pub struct SequencerState {
    sessions: parking_lot::Mutex<Vec<Arc<Session>>>,
    next_id: AtomicU64,
}

impl SequencerState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn get(&self, id: u64) -> Option<Arc<Session>> {
        self.sessions
            .lock()
            .iter()
            .find(|s| s.id == id)
            .map(Arc::clone)
    }

    /// Register a session, evicting the oldest finished one if the retention cap is reached.
    ///
    /// Returns `Err` when the concurrency cap is already met — refusing is the right answer, because
    /// silently queueing would mean the capture the operator started is not the capture that is
    /// running.
    fn admit(&self, session: Arc<Session>) -> Result<(), String> {
        let mut sessions = self.sessions.lock();
        let running = sessions.iter().filter(|s| s.running()).count();
        if running >= MAX_RUNNING {
            return Err(format!(
                "{running} capture(s) already running and the limit is {MAX_RUNNING}; stop one first"
            ));
        }
        while sessions.len() >= MAX_SESSIONS {
            match sessions.iter().position(|s| !s.running()) {
                Some(i) => {
                    sessions.remove(i);
                }
                // Cannot happen while MAX_RUNNING < MAX_SESSIONS, but dropping a *running* capture's
                // handle would orphan a live request loop, so the cap yields rather than risk it.
                None => break,
            }
        }
        sessions.push(session);
        Ok(())
    }
}

pub fn routes() -> Router<AppState> {
    routes_with(SequencerState::new())
}

/// The same routes, over state the caller keeps a handle to. Mirrors `tools::routes_with`, and
/// exists for the same reason: a test that wants to inspect the sessions needs the handle.
pub fn routes_with(state: Arc<SequencerState>) -> Router<AppState> {
    Router::new()
        .route("/api/sequencer/analyse", post(analyse))
        .route(
            "/api/sequencer/capture",
            get(list_captures).post(start_capture),
        )
        .route("/api/sequencer/capture/{id}", get(poll_capture))
        .route("/api/sequencer/capture/{id}/stop", post(stop_capture))
        .layer(Extension(state))
}

// ---- paste mode -------------------------------------------------------------------------------

#[derive(Deserialize)]
struct AnalyseReq {
    /// One token per line. The form the UI's textarea posts.
    #[serde(default)]
    text: Option<String>,
    /// Pre-split tokens, for a caller that already has them.
    #[serde(default)]
    tokens: Option<Vec<String>>,
    /// `hex` | `base64` | `raw`. Absent means detect, which is almost always right.
    #[serde(default)]
    encoding: Option<String>,
}

fn parse_encoding(name: &str) -> Result<Encoding, String> {
    match name {
        "hex" => Ok(Encoding::Hex),
        "base64" => Ok(Encoding::Base64),
        "raw" => Ok(Encoding::Raw),
        other => Err(format!(
            "unknown encoding {other:?}: expected hex, base64 or raw"
        )),
    }
}

/// `POST /api/sequencer/analyse` — analyse a token list the operator supplied directly.
///
/// Takes no state at all, which is the point: pasted text is not traffic, so there is no scope
/// decision to make and nothing to record. There is a test that this works for a host wholly outside
/// scope, because gating it would be a check that protects nothing.
async fn analyse(Json(req): Json<AnalyseReq>) -> impl IntoResponse {
    let tokens = match (req.tokens, req.text) {
        (Some(list), _) => list
            .into_iter()
            .map(|t| bytes::Bytes::from(t.into_bytes()))
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>(),
        (None, Some(text)) => burpsy_sequencer::tokens_from_text(&text),
        (None, None) => {
            return (
                StatusCode::BAD_REQUEST,
                "no tokens: pass text (one per line) or tokens",
            )
                .into_response();
        }
    };
    let encoding = match req.encoding.as_deref().map(parse_encoding) {
        Some(Err(why)) => return (StatusCode::BAD_REQUEST, why).into_response(),
        Some(Ok(e)) => Some(e),
        None => None,
    };
    // An empty paste is answered rather than refused: the report says "no tokens were supplied", and
    // that is more useful to whoever pasted the wrong buffer than a 400 with no analysis in it.
    Json(burpsy_sequencer::analyse_as(&tokens, encoding)).into_response()
}

// ---- live capture -----------------------------------------------------------------------------

#[derive(Deserialize)]
struct ExtractReq {
    /// `whole` | `headers` | `body`. Absent means the whole response.
    #[serde(default)]
    part: Option<String>,
    /// A regex. Capture group 1 when the pattern has one, else the whole match.
    #[serde(default)]
    pattern: Option<String>,
    /// A byte offset into `part`, paired with `len`.
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    len: Option<usize>,
}

impl ExtractReq {
    /// Exactly one of the two mechanisms, refusing rather than guessing when it is ambiguous. A
    /// request that supplies both means the operator believes something about this endpoint that is
    /// not true, and picking one for them would capture the wrong bytes for a whole session.
    fn build(self) -> Result<Extractor, String> {
        let part = match self.part.as_deref() {
            None | Some("whole") => ResponsePart::Whole,
            Some("headers") => ResponsePart::Headers,
            Some("body") => ResponsePart::Body,
            Some(other) => {
                return Err(format!(
                    "unknown part {other:?}: expected whole, headers or body"
                ));
            }
        };
        match (self.pattern, self.offset, self.len) {
            (Some(pattern), None, None) => Extractor::pattern(part, &pattern)
                .map_err(|e| format!("bad extraction pattern: {e}")),
            (None, Some(offset), Some(len)) => {
                if len == 0 {
                    return Err("a zero-length span extracts no token".to_string());
                }
                Ok(Extractor::Span { part, offset, len })
            }
            (None, Some(_), None) | (None, None, Some(_)) => {
                Err("a span extractor needs both offset and len".to_string())
            }
            (Some(_), _, _) => Err("pass either pattern or offset+len, not both".to_string()),
            (None, None, None) => {
                Err("no extraction point: pass pattern, or offset and len".to_string())
            }
        }
    }
}

#[derive(Deserialize)]
struct StartReq {
    target: String,
    /// The request template, exactly as it should go on the wire. Bare LF is normalised to CRLF the
    /// same way the repeater does it, because a textarea produces LF.
    raw: String,
    #[serde(default)]
    count: Option<usize>,
    extract: ExtractReq,
    #[serde(default)]
    rps: Option<f64>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    /// Forces the bit-level encoding for the analysis that runs when the capture ends.
    #[serde(default)]
    encoding: Option<String>,
}

#[derive(Serialize)]
struct FailureView {
    message: String,
    count: usize,
}

#[derive(Serialize)]
struct CaptureView {
    id: u64,
    target: String,
    wanted: usize,
    captured: usize,
    attempted: usize,
    /// `running` | `finished`.
    state: &'static str,
    /// True when `count` was clamped to the crate's ceiling.
    clamped: bool,
    /// Set once finished: `complete` | `stopped` | `gave_up` | `refused`.
    ended: Option<CaptureEnd>,
    /// Straight off the sender's counters, so "did anything leave" is answered by the chokepoint.
    sent: Option<u32>,
    refused: Option<u32>,
    failures: Vec<FailureView>,
    /// Present once finished, and `null` when the capture produced no tokens.
    report: Option<SequencerReport>,
}

fn view(session: &Session) -> CaptureView {
    let outcome = session.outcome.lock();
    match outcome.as_ref() {
        None => CaptureView {
            id: session.id,
            target: session.target.clone(),
            wanted: session.wanted,
            captured: session.progress.captured(),
            attempted: session.progress.attempted(),
            state: "running",
            clamped: session.clamped,
            ended: None,
            sent: None,
            refused: None,
            failures: Vec::new(),
            report: None,
        },
        Some(done) => CaptureView {
            id: session.id,
            target: session.target.clone(),
            wanted: session.wanted,
            captured: session.progress.captured(),
            attempted: done.attempted,
            state: "finished",
            clamped: session.clamped,
            ended: Some(done.ended),
            sent: Some(done.sent),
            refused: Some(done.refused),
            failures: done
                .failures
                .iter()
                .map(|(message, count)| FailureView {
                    message: message.clone(),
                    count: *count,
                })
                .collect(),
            report: done.report.clone(),
        },
    }
}

/// `POST /api/sequencer/capture` — start capturing tokens from a live target.
async fn start_capture(
    State(s): State<AppState>,
    Extension(sequencer): Extension<Arc<SequencerState>>,
    Json(req): Json<StartReq>,
) -> impl IntoResponse {
    let target = match parse_target(&req.target) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad target: {e}")).into_response(),
    };
    let extract = match req.extract.build() {
        Ok(e) => e,
        Err(why) => return (StatusCode::BAD_REQUEST, why).into_response(),
    };
    let encoding = match req.encoding.as_deref().map(parse_encoding) {
        Some(Err(why)) => return (StatusCode::BAD_REQUEST, why).into_response(),
        Some(Ok(e)) => Some(e),
        None => None,
    };
    let rps = match req.rps {
        None => DEFAULT_RPS,
        Some(r) if r >= MIN_RPS => r.min(MAX_RPS),
        Some(r) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("rps must be at least {MIN_RPS}, got {r}"),
            )
                .into_response();
        }
    };
    let raw = req.raw.replace("\r\n", "\n").replace('\n', "\r\n");
    if raw.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "the request template is empty").into_response();
    }

    // Checked up front so an out-of-scope target is a 403 rather than a session that exists only to
    // report a refusal. This is the host-level question; the binding check is inside the sender and
    // judges the actual outbound bytes on every single request whether or not this one ran.
    if !s
        .scope
        .may_contain_host(&target.host, target.port, target.tls)
    {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "refused: {}",
                s.scope.explain(&target.host, target.port, "/", target.tls)
            ),
        )
            .into_response();
    }

    let (cfg, clamped) = CaptureConfig::new(
        target,
        bytes::Bytes::from(raw.into_bytes()),
        req.count,
        extract,
        Duration::from_secs_f64(1.0 / rps),
    );
    let progress = Arc::new(CaptureProgress::default());
    let session = Arc::new(Session {
        id: sequencer.next_id.fetch_add(1, Ordering::Relaxed),
        target: req.target.clone(),
        wanted: cfg.count,
        clamped,
        progress: Arc::clone(&progress),
        outcome: parking_lot::Mutex::new(None),
    });
    if let Err(why) = sequencer.admit(Arc::clone(&session)) {
        return (StatusCode::TOO_MANY_REQUESTS, why).into_response();
    }

    let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(15_000));
    let sender = AuthorisedSender::asynchronous(s.scope.clone(), timeout);
    let task_session = Arc::clone(&session);
    tokio::spawn(async move {
        let outcome = burpsy_sequencer::capture(&sender, &cfg, &progress).await;
        // No tokens means no analysis. An `analyse(&[])` report would have a shape and a grade and
        // would read as a result, when the only fact available is that nothing was captured.
        let report = (!outcome.tokens.is_empty())
            .then(|| burpsy_sequencer::analyse_as(&outcome.tokens, encoding));
        *task_session.outcome.lock() = Some(Finished {
            ended: outcome.ended,
            attempted: outcome.attempted,
            sent: outcome.sent,
            refused: outcome.refused,
            failures: outcome.failures,
            report,
        });
    });

    (StatusCode::ACCEPTED, Json(view(&session))).into_response()
}

/// `GET /api/sequencer/capture/{id}` — progress while running, the report once finished.
async fn poll_capture(
    Extension(sequencer): Extension<Arc<SequencerState>>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match sequencer.get(id) {
        Some(session) => Json(view(&session)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            format!("no capture {id}: it never existed, or it aged out of the last {MAX_SESSIONS}"),
        )
            .into_response(),
    }
}

/// `GET /api/sequencer/capture` — every retained session, oldest first.
async fn list_captures(Extension(sequencer): Extension<Arc<SequencerState>>) -> impl IntoResponse {
    // Cloned out from under the lock: `view` takes the per-session lock, and holding the list lock
    // across that would order the two locks one way here and risk the other way elsewhere.
    let sessions = sequencer.sessions.lock().clone();
    Json(sessions.iter().map(|x| view(x)).collect::<Vec<_>>())
}

/// `POST /api/sequencer/capture/{id}/stop` — finish early, keeping the tokens already captured.
async fn stop_capture(
    Extension(sequencer): Extension<Arc<SequencerState>>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match sequencer.get(id) {
        Some(session) => {
            session.progress.request_stop();
            Json(view(&session)).into_response()
        }
        None => (StatusCode::NOT_FOUND, format!("no capture {id}")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{Scope, ScopeRule, TrafficStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn state(scope: Scope) -> AppState {
        AppState {
            store: TrafficStore::new(),
            ca_pem: None,
            scope: scope.into(),
            findings: None,
            audit: None,
            export: None,
            intercept: None,
            session: None,
            tool_log: None,
            live_audit: None,
        }
    }

    async fn serve(st: AppState) -> String {
        let app = routes().with_state(st);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await });
        format!("127.0.0.1:{}", addr.port())
    }

    async fn call(addr: &str, method: &str, path: &str, body: &str) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    }

    /// A server handing out a fresh token per request, so a capture has something to collect.
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

    // ---- paste mode ---------------------------------------------------------------------------

    #[tokio::test]
    async fn a_pasted_token_list_is_analysed_in_one_call() {
        let addr = serve(state(Scope::allow_everything())).await;
        let text = (0..400u32)
            .map(|i| format!("{:08x}", i.wrapping_mul(2_654_435_761)))
            .collect::<Vec<_>>()
            .join("\\n");
        let (status, body) = call(
            &addr,
            "POST",
            "/api/sequencer/analyse",
            &format!("{{\"text\":\"{text}\"}}"),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["tokens"], 400);
        assert_eq!(v["encoding"], "hex");
        assert_eq!(v["characters"]["alphabet_size"], 16);
        assert_eq!(v["characters"]["positions"].as_array().unwrap().len(), 8);
        // 400 x 32 bits = 12,800 — short of a block, so there must be no verdict rather than a bad one.
        assert_eq!(v["bits"]["bits"], 12_800);
        assert_eq!(v["grade"], "insufficient");
        assert!(v["fips"]["tests"].is_null());
        assert_eq!(v["fips"]["bits_untested"], 12_800);
    }

    /// Paste mode must never touch the network. A capture is the only thing here that sends, and it
    /// is a different endpoint with a different scope check.
    #[tokio::test]
    async fn paste_mode_analyses_tokens_for_a_host_that_is_wholly_out_of_scope() {
        let mut scope = Scope::new();
        scope.add(ScopeRule::include("authorised.test"));
        let addr = serve(state(scope)).await;
        let (status, body) = call(
            &addr,
            "POST",
            "/api/sequencer/analyse",
            r#"{"text":"abcd\nefab\n1234"}"#,
        )
        .await;
        assert_eq!(
            status, 200,
            "pasted text is not traffic and needs no authorisation: {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["tokens"], 3);
    }

    #[tokio::test]
    async fn an_empty_paste_gets_a_report_that_says_so_rather_than_an_error() {
        let addr = serve(state(Scope::allow_everything())).await;
        let (status, body) = call(
            &addr,
            "POST",
            "/api/sequencer/analyse",
            r#"{"text":"  \n\n"}"#,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["tokens"], 0);
        assert_eq!(v["grade"], "insufficient");
        assert!(
            v["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w.as_str().unwrap().contains("no tokens")),
            "{body}"
        );
    }

    #[tokio::test]
    async fn a_paste_with_neither_text_nor_tokens_is_refused() {
        let addr = serve(state(Scope::allow_everything())).await;
        let (status, _) = call(&addr, "POST", "/api/sequencer/analyse", "{}").await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn an_unknown_encoding_is_named_rather_than_ignored() {
        let addr = serve(state(Scope::allow_everything())).await;
        let (status, body) = call(
            &addr,
            "POST",
            "/api/sequencer/analyse",
            r#"{"text":"ab\ncd","encoding":"rot13"}"#,
        )
        .await;
        assert_eq!(status, 400);
        assert!(body.contains("rot13"), "{body}");
    }

    // ---- live capture -------------------------------------------------------------------------

    /// The whole start/poll cycle against a real listener, ending in a report.
    #[tokio::test]
    async fn a_live_capture_starts_polls_and_finishes_with_a_report() {
        let tgt = token_server().await;
        let addr = serve(state(Scope::allow_everything())).await;
        let body = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}",
                 "raw":"GET /t HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                 "count":12,"rps":200,
                 "extract":{{"part":"body","pattern":"sid=([0-9a-f]+)"}}}}"#
        );
        let (status, out) = call(&addr, "POST", "/api/sequencer/capture", &body).await;
        assert_eq!(
            status, 202,
            "a background job must be accepted, not 200: {out}"
        );
        let started: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(started["state"], "running");
        assert_eq!(started["wanted"], 12);
        assert_eq!(started["clamped"], false);
        let id = started["id"].as_u64().unwrap();

        let mut finished = serde_json::Value::Null;
        for _ in 0..200 {
            let (status, out) =
                call(&addr, "GET", &format!("/api/sequencer/capture/{id}"), "").await;
            assert_eq!(status, 200, "{out}");
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            if v["state"] == "finished" {
                finished = v;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!finished.is_null(), "the capture never finished");
        assert_eq!(finished["ended"], "complete");
        assert_eq!(finished["captured"], 12);
        assert_eq!(finished["sent"], 12, "the sender's own counter");
        assert_eq!(finished["refused"], 0);
        assert_eq!(finished["failures"].as_array().unwrap().len(), 0);
        assert_eq!(finished["report"]["tokens"], 12);
        assert_eq!(finished["report"]["encoding"], "hex");
        // Far too few tokens for a FIPS block, and the report must say that rather than grade them.
        assert_eq!(finished["report"]["grade"], "insufficient");
    }

    /// The one bug in this tool with consequences outside it. An out-of-scope capture must be refused
    /// before a session exists, let alone a request.
    #[tokio::test]
    async fn a_capture_aimed_outside_scope_is_refused_before_anything_is_sent() {
        let tgt = token_server().await;
        let mut scope = Scope::new();
        scope.add(ScopeRule::include("authorised.test"));
        let addr = serve(state(scope)).await;
        let body = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}",
                 "raw":"GET /t HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n","count":50,
                 "extract":{{"pattern":"sid=([0-9a-f]+)"}}}}"#
        );
        let (status, out) = call(&addr, "POST", "/api/sequencer/capture", &body).await;
        assert_eq!(status, 403, "{out}");
        assert!(out.contains("out of scope"), "{out}");
        // And no session was created, so nothing is left implying a capture happened.
        let (status, out) = call(&addr, "GET", "/api/sequencer/capture", "").await;
        assert_eq!(status, 200);
        assert_eq!(out.trim(), "[]", "{out}");
    }

    #[tokio::test]
    async fn a_stopped_capture_reports_that_it_was_stopped_and_keeps_its_tokens() {
        let tgt = token_server().await;
        let addr = serve(state(Scope::allow_everything())).await;
        let body = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}",
                 "raw":"GET /t HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                 "count":5000,"rps":200,
                 "extract":{{"part":"body","pattern":"sid=([0-9a-f]+)"}}}}"#
        );
        let (_, out) = call(&addr, "POST", "/api/sequencer/capture", &body).await;
        let id = serde_json::from_str::<serde_json::Value>(&out).unwrap()["id"]
            .as_u64()
            .unwrap();

        // Let it get going, then stop it.
        for _ in 0..200 {
            let (_, out) = call(&addr, "GET", &format!("/api/sequencer/capture/{id}"), "").await;
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            if v["captured"].as_u64().unwrap_or(0) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (status, out) = call(
            &addr,
            "POST",
            &format!("/api/sequencer/capture/{id}/stop"),
            "",
        )
        .await;
        assert_eq!(status, 200, "{out}");

        let mut finished = serde_json::Value::Null;
        for _ in 0..200 {
            let (_, out) = call(&addr, "GET", &format!("/api/sequencer/capture/{id}"), "").await;
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            if v["state"] == "finished" {
                finished = v;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(finished["ended"], "stopped", "{finished}");
        let captured = finished["captured"].as_u64().unwrap();
        assert!((2..5_000).contains(&captured), "kept {captured} tokens");
        assert_eq!(
            finished["report"]["tokens"], captured,
            "the partial sample is still analysed rather than discarded"
        );
    }

    #[tokio::test]
    async fn an_ambiguous_or_incomplete_extractor_is_refused_with_a_reason() {
        let addr = serve(state(Scope::allow_everything())).await;
        let template = r#""target":"http://127.0.0.1:9","raw":"GET / HTTP/1.1\r\nHost: h\r\n\r\n""#;
        let cases: [(&str, &str); 6] = [
            ("both mechanisms", r#"{"pattern":"x","offset":1,"len":2}"#),
            ("offset with no len", r#"{"offset":1}"#),
            ("len with no offset", r#"{"len":2}"#),
            ("neither", "{}"),
            ("a zero-length span", r#"{"offset":0,"len":0}"#),
            ("an uncompilable pattern", r#"{"pattern":"([unclosed"}"#),
        ];
        for (what, extract) in cases {
            let (status, out) = call(
                &addr,
                "POST",
                "/api/sequencer/capture",
                &format!("{{{template},\"extract\":{extract}}}"),
            )
            .await;
            assert_eq!(status, 400, "{what} was accepted: {out}");
        }
        // And an unknown part is named rather than defaulted.
        let (status, out) = call(
            &addr,
            "POST",
            "/api/sequencer/capture",
            &format!("{{{template},\"extract\":{{\"part\":\"trailer\",\"pattern\":\"x\"}}}}"),
        )
        .await;
        assert_eq!(status, 400);
        assert!(out.contains("trailer"), "{out}");
    }

    #[tokio::test]
    async fn an_over_large_count_is_clamped_and_the_clamp_is_visible() {
        let tgt = token_server().await;
        let addr = serve(state(Scope::allow_everything())).await;
        let body = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}",
                 "raw":"GET /t HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                 "count":999999,"rps":200,
                 "extract":{{"part":"body","pattern":"sid=([0-9a-f]+)"}}}}"#
        );
        let (status, out) = call(&addr, "POST", "/api/sequencer/capture", &body).await;
        assert_eq!(status, 202, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["wanted"], burpsy_sequencer::MAX_TOKENS);
        assert_eq!(
            v["clamped"], true,
            "a silently reduced bound is a lie about what ran"
        );
        let id = v["id"].as_u64().unwrap();
        call(
            &addr,
            "POST",
            &format!("/api/sequencer/capture/{id}/stop"),
            "",
        )
        .await;
    }

    #[tokio::test]
    async fn a_third_concurrent_capture_is_refused_rather_than_quietly_queued() {
        let tgt = token_server().await;
        let addr = serve(state(Scope::allow_everything())).await;
        let body = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}",
                 "raw":"GET /t HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                 "count":5000,"rps":0.5,
                 "extract":{{"part":"body","pattern":"sid=([0-9a-f]+)"}}}}"#
        );
        let mut ids = Vec::new();
        for _ in 0..MAX_RUNNING {
            let (status, out) = call(&addr, "POST", "/api/sequencer/capture", &body).await;
            assert_eq!(status, 202, "{out}");
            ids.push(
                serde_json::from_str::<serde_json::Value>(&out).unwrap()["id"]
                    .as_u64()
                    .unwrap(),
            );
        }
        let (status, out) = call(&addr, "POST", "/api/sequencer/capture", &body).await;
        assert_eq!(status, 429, "{out}");
        assert!(out.contains("already running"), "{out}");
        for id in ids {
            call(
                &addr,
                "POST",
                &format!("/api/sequencer/capture/{id}/stop"),
                "",
            )
            .await;
        }
    }

    #[tokio::test]
    async fn polling_a_capture_that_does_not_exist_says_so() {
        let addr = serve(state(Scope::allow_everything())).await;
        let (status, out) = call(&addr, "GET", "/api/sequencer/capture/99", "").await;
        assert_eq!(status, 404);
        assert!(out.contains("99"), "{out}");
        let (status, _) = call(&addr, "POST", "/api/sequencer/capture/99/stop", "").await;
        assert_eq!(status, 404);
    }

    /// An extractor that matches nothing must cost the failure bound, not the whole token budget,
    /// and the report must name the reason once with a count rather than a thousand times.
    #[tokio::test]
    async fn a_capture_whose_extractor_never_matches_gives_up_and_says_why() {
        let tgt = token_server().await;
        let addr = serve(state(Scope::allow_everything())).await;
        let body = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}",
                 "raw":"GET /t HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                 "count":5000,"rps":200,
                 "extract":{{"part":"body","pattern":"csrf=([0-9a-f]+)"}}}}"#
        );
        let (_, out) = call(&addr, "POST", "/api/sequencer/capture", &body).await;
        let id = serde_json::from_str::<serde_json::Value>(&out).unwrap()["id"]
            .as_u64()
            .unwrap();

        let mut finished = serde_json::Value::Null;
        for _ in 0..200 {
            let (_, out) = call(&addr, "GET", &format!("/api/sequencer/capture/{id}"), "").await;
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            if v["state"] == "finished" {
                finished = v;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(finished["ended"], "gave_up", "{finished}");
        assert_eq!(finished["captured"], 0);
        assert!(
            finished["report"].is_null(),
            "no tokens means no report, not an empty one: {finished}"
        );
        let failures = finished["failures"].as_array().unwrap();
        assert_eq!(failures.len(), 1, "one distinct message: {finished}");
        assert!(
            failures[0]["message"]
                .as_str()
                .unwrap()
                .contains("did not match"),
            "{finished}"
        );
        assert!(failures[0]["count"].as_u64().unwrap() >= 2);
    }
}
