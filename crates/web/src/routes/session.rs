//! `ReloginCoordinator`'s production home behind the web API — SESSION-01..04 made reachable.
//!
//! # Why the coordinator is held directly, not behind a hook
//!
//! `audit`/`export` take a closure ([`crate::AuditHook`], [`crate::routes::report::ExportHook`])
//! because `burpsy-web` must not depend on `burpsy-scanner` — the dependency edge runs the other
//! way. There is no equivalent boundary here: `burpsy-web` already depends on both
//! `burpsy-session` and `burpsy-sender` (see [`crate::session_sender`]), so this module holds a
//! [`ReloginCoordinator`] and an [`AuthorisedMacroSender`] directly, the same way `intercept.rs`
//! holds an `Interceptor`.
//!
//! # Why `POST /api/session/login` takes a `probe`
//!
//! [`ReloginCoordinator::handle_response`] evaluates a response the caller hands it, and — if
//! recovery runs — resends the *same* request it was given. There is nothing here to fabricate
//! that response from, and reusing a login-macro step as the "original" request would replay a
//! login step against the live target for no reason. So the operator's "log in again" button
//! names the request whose session it wants valid (`probe`), this module sends it once through
//! the same [`AuthorisedMacroSender`] the macro uses — so scope is enforced on it too — and only
//! then hands the real response to the coordinator. `AlreadyValid` is honest this way: it means
//! the probe you asked about was already fine, not a response nobody actually saw.

use crate::AppState;
use crate::session_sender::AuthorisedMacroSender;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use burpsy_session::{
    DEFAULT_MAX_LOGIN_ATTEMPTS, Macro, MacroResponse, MacroStep, RecoveryOutcome,
    ReloginCoordinator, SessionValidity, ValidityRule,
};
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

/// Shared state for the login-macro feature: the configured [`ReloginCoordinator`] behind a lock
/// so `PUT /api/session/macro` can replace it at runtime, plus the sender that drives it.
///
/// Owned here rather than in [`AppState`] directly, the same way `intercept::InterceptState` is —
/// so this feature can evolve its own storage without touching the shared struct.
pub struct SessionState {
    configured: RwLock<Option<Arc<Configured>>>,
    sender: AuthorisedMacroSender,
}

impl SessionState {
    pub fn new(sender: AuthorisedMacroSender) -> Arc<Self> {
        Arc::new(Self {
            configured: RwLock::new(None),
            sender,
        })
    }
}

/// One configured macro: the coordinator that runs it, and the view `GET /api/session/macro`
/// reports back. Kept together so a reader of `configured` never sees the two disagree.
struct Configured {
    coordinator: ReloginCoordinator,
    view: MacroView,
}

/// One recorded macro step, as the operator submits and reads it back over the API.
///
/// `body` is UTF-8 text rather than raw bytes: a login macro's body is almost always a form or
/// JSON payload an operator can read and edit as a string, and taking arbitrary bytes here would
/// force every caller of this JSON API to base64-encode an ordinary login form just to submit it.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct StepDto {
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: String,
}

impl From<StepDto> for MacroStep {
    fn from(d: StepDto) -> Self {
        MacroStep {
            method: d.method,
            url: d.url,
            headers: d.headers,
            body: Bytes::from(d.body.into_bytes()),
        }
    }
}

/// Mirrors [`ValidityRule`] one-to-one, as its own type: this crate's wire format is free to grow
/// (defaults, docs, renames) without `burpsy-session`'s enum having to carry serde derives it
/// otherwise has no use for.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuleDto {
    StatusIs(u16),
    BodyContains(String),
    BodyNotContains(String),
    HeaderPresent(String),
    HeaderAbsent(String),
    RedirectsTo(String),
    All(Vec<RuleDto>),
    Any(Vec<RuleDto>),
    Not(Box<RuleDto>),
}

impl From<RuleDto> for ValidityRule {
    fn from(d: RuleDto) -> Self {
        match d {
            RuleDto::StatusIs(code) => ValidityRule::StatusIs(code),
            RuleDto::BodyContains(s) => ValidityRule::BodyContains(s),
            RuleDto::BodyNotContains(s) => ValidityRule::BodyNotContains(s),
            RuleDto::HeaderPresent(s) => ValidityRule::HeaderPresent(s),
            RuleDto::HeaderAbsent(s) => ValidityRule::HeaderAbsent(s),
            RuleDto::RedirectsTo(s) => ValidityRule::RedirectsTo(s),
            RuleDto::All(v) => ValidityRule::All(v.into_iter().map(Into::into).collect()),
            RuleDto::Any(v) => ValidityRule::Any(v.into_iter().map(Into::into).collect()),
            RuleDto::Not(r) => ValidityRule::Not(Box::new((*r).into())),
        }
    }
}

/// What `GET /api/session/macro` reports back — exactly what was submitted (with the resolved
/// `max_attempts`), not a re-derivation from the coordinator, which keeps no public accessors for
/// its own configuration.
#[derive(Debug, Clone, Serialize)]
struct MacroView {
    steps: Vec<StepDto>,
    rule: RuleDto,
    max_attempts: u32,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/session/macro", get(get_macro).put(put_macro))
        .route("/api/session/login", post(login))
        .route("/api/session/cookies", get(cookies))
}

/// Same shape as `/api/intercept` and `/api/issues`: a feature not wired into this process says so
/// in a `200`, rather than a `404` that looks like a typo in the route.
fn feature_unwired() -> axum::response::Response {
    Json(json!({
        "configured": false,
        "wired": false,
        "hint": "session re-login is not attached to this process",
    }))
    .into_response()
}

/// The feature is wired, but no macro has been submitted yet.
fn macro_not_configured() -> axum::response::Response {
    Json(json!({
        "configured": false,
        "wired": true,
        "hint": "PUT /api/session/macro to define the login steps, validity rule, and retry bound",
    }))
    .into_response()
}

fn bad_request(msg: impl Into<String>) -> axum::response::Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.into()}))).into_response()
}

#[derive(Debug, Deserialize)]
struct PutMacroReq {
    steps: Vec<StepDto>,
    rule: RuleDto,
    #[serde(default)]
    max_attempts: Option<u32>,
}

/// `PUT /api/session/macro` — define the login macro, the validity rule, and the retry bound.
///
/// Rejected rather than coerced: an empty macro, an empty step method, an unparsable step URL, or
/// a stated `max_attempts` of `0` are operator mistakes this crate can catch immediately, rather
/// than surfacing later as "the button does nothing" or, worse, as a confusing `MacroFailed` at
/// login time (`step.url` is parsed with the same `parse_target` the sender itself will apply).
async fn put_macro(State(s): State<AppState>, Json(req): Json<PutMacroReq>) -> impl IntoResponse {
    let Some(session) = s.session.as_ref() else {
        return feature_unwired();
    };
    if req.steps.is_empty() {
        return bad_request("macro must have at least one step");
    }
    for (index, step) in req.steps.iter().enumerate() {
        if step.method.trim().is_empty() {
            return bad_request(format!("step {index} has an empty method"));
        }
        // Caught here rather than left to surface as a confusing `MacroFailed`/`probe_failed` at
        // login time: `MacroStep::url` must be a full `scheme://host[:port]/path`, and
        // `parse_target` is the same parser the sender itself will apply to it.
        if let Err(e) = burpsy_sender::parse_target(&step.url) {
            return bad_request(format!("step {index} has an invalid url {:?}: {e}", step.url));
        }
    }
    let max_attempts = match req.max_attempts {
        Some(0) => {
            return bad_request(format!(
                "max_attempts must be at least 1; omit it for the default of {DEFAULT_MAX_LOGIN_ATTEMPTS}"
            ));
        }
        Some(n) => n,
        None => DEFAULT_MAX_LOGIN_ATTEMPTS,
    };
    let steps: Vec<MacroStep> = req.steps.iter().cloned().map(Into::into).collect();
    let rule: ValidityRule = req.rule.clone().into();
    let coordinator = ReloginCoordinator::new(Macro { steps }, rule, max_attempts);
    let view = MacroView {
        steps: req.steps,
        rule: req.rule,
        max_attempts,
    };
    *session.configured.write() = Some(Arc::new(Configured {
        coordinator,
        view: view.clone(),
    }));
    Json(json!({
        "configured": true,
        "steps": view.steps,
        "rule": view.rule,
        "max_attempts": view.max_attempts,
    }))
    .into_response()
}

/// `GET /api/session/macro` — read back what is configured, or say plainly that nothing is.
async fn get_macro(State(s): State<AppState>) -> impl IntoResponse {
    let Some(session) = s.session.as_ref() else {
        return feature_unwired();
    };
    let guard = session.configured.read();
    match guard.as_ref() {
        Some(c) => Json(json!({
            "configured": true,
            "steps": c.view.steps,
            "rule": c.view.rule,
            "max_attempts": c.view.max_attempts,
        }))
        .into_response(),
        None => macro_not_configured(),
    }
}

#[derive(Debug, Deserialize)]
struct LoginReq {
    /// The request whose session should end up valid — see the module docs for why this is not
    /// synthesised from the macro itself.
    probe: StepDto,
}

/// `POST /api/session/login` — the operator's "log in again" button: send `probe`, evaluate it
/// against the configured validity rule, and recover if it fails.
///
/// Offloaded to a blocking thread: both the probe and the macro itself send real HTTP requests
/// through the blocking [`burpsy_sender::AuthorisedSender`], and `handle_response` can additionally
/// park on another caller's in-flight login (`ReloginCoordinator`'s single-flight collapsing) —
/// running any of that on a runtime worker would stall every other request the same way
/// `run_audit` would without the same treatment.
async fn login(State(s): State<AppState>, Json(req): Json<LoginReq>) -> impl IntoResponse {
    let Some(session) = s.session.clone() else {
        return feature_unwired();
    };
    // Cloned out and the lock dropped before any network call: holding a `parking_lot` guard
    // across `spawn_blocking` would not compile (the guard is not `Send`) and would in any case
    // block `PUT /api/session/macro` for the whole login attempt.
    let configured = session.configured.read().clone();
    let Some(configured) = configured else {
        return macro_not_configured();
    };
    let probe: MacroStep = req.probe.into();
    let session = session.clone();
    match tokio::task::spawn_blocking(move || run_login(&session, &configured, probe)).await {
        Ok(resp) => resp,
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "login task panicked"})),
        )
            .into_response(),
    }
}

fn run_login(
    session: &SessionState,
    configured: &Configured,
    probe: MacroStep,
) -> axum::response::Response {
    // The chokepoint (HARD-03): `session.sender` is an `AuthorisedMacroSender` over
    // `AuthorisedSender`, so a probe or macro step aimed outside scope is refused here, not
    // rechecked — see `crate::session_sender`.
    //
    // `send_with_jar` (not a bare `session.sender.send`) so the probe carries whatever cookie the
    // jar already holds for its host and absorbs any `Set-Cookie` the probe's own response sets —
    // otherwise a probe sent outside the jar would look permanently logged-out (no session cookie
    // ever attached) and `AlreadyValid` would be unreachable in practice.
    let response = match configured
        .coordinator
        .send_with_jar(&session.sender, &probe)
    {
        Ok(r) => r,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"outcome": "probe_failed", "error": error})),
            )
                .into_response();
        }
    };
    outcome_response(configured.coordinator.handle_response(&session.sender, &probe, response))
}

/// Faithful `RecoveryOutcome` -> HTTP mapping. Every variant carries its own `outcome` tag rather
/// than collapsing into ok/error, per the coordinator's own docs on why a caller must be able to
/// tell "this is working" from "this has quietly stopped trying". `502` is used only for the two
/// variants where a request could not be sent at all (`MacroFailed`, `RetryFailed`); every variant
/// that ran to a definite conclusion — including `GaveUp` — is a `200` whose body states which.
fn outcome_response(outcome: RecoveryOutcome) -> axum::response::Response {
    match outcome {
        RecoveryOutcome::AlreadyValid => Json(json!({"outcome": "already_valid"})).into_response(),
        RecoveryOutcome::Recovered {
            login_attempts,
            response,
        } => Json(json!({
            "outcome": "recovered",
            "login_attempts": login_attempts,
            "response": response_view(&response),
        }))
        .into_response(),
        RecoveryOutcome::StillInvalidAfterRelogin {
            login_attempts,
            validity,
            response,
        } => Json(json!({
            "outcome": "still_invalid_after_relogin",
            "login_attempts": login_attempts,
            "validity": validity_view(&validity),
            "response": response_view(&response),
        }))
        .into_response(),
        RecoveryOutcome::GaveUp { attempts } => Json(json!({
            "outcome": "gave_up",
            "attempts": attempts,
        }))
        .into_response(),
        RecoveryOutcome::MacroFailed { attempt, failure } => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "outcome": "macro_failed",
                "attempt": attempt,
                "step_index": failure.step_index,
                "error": failure.error,
            })),
        )
            .into_response(),
        RecoveryOutcome::RetryFailed {
            login_attempts,
            error,
        } => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "outcome": "retry_failed",
                "login_attempts": login_attempts,
                "error": error,
            })),
        )
            .into_response(),
    }
}

fn response_view(r: &MacroResponse) -> serde_json::Value {
    json!({
        "status": r.status,
        "headers": r.headers,
        // `None` (never captured) is kept distinct from `Some("")` (a real empty body) — the same
        // distinction `MacroResponse::body` itself exists to preserve.
        "body": r.body.as_ref().map(|b| String::from_utf8_lossy(b).into_owned()),
    })
}

fn validity_view(v: &SessionValidity) -> serde_json::Value {
    match v {
        SessionValidity::Valid => json!("valid"),
        SessionValidity::Invalid => json!("invalid"),
        SessionValidity::Indeterminate(reason) => json!({"indeterminate": reason}),
    }
}

/// `GET /api/session/cookies` — the shared jar's current contents: SESSION-03's "one jar across
/// tools" made visible to an operator.
async fn cookies(State(s): State<AppState>) -> impl IntoResponse {
    let Some(session) = s.session.as_ref() else {
        return feature_unwired();
    };
    let guard = session.configured.read();
    let Some(configured) = guard.as_ref() else {
        return macro_not_configured();
    };
    let jar = configured.coordinator.shared_jar();
    let snapshot = jar.lock().snapshot();
    Json(json!({
        "configured": true,
        "cookies": snapshot
            .into_iter()
            .map(|(host, pairs)| json!({
                "host": host,
                "cookies": pairs
                    .into_iter()
                    .map(|(name, value)| json!({"name": name, "value": value}))
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{Scope, TrafficStore};
    use burpsy_sender::{AuthorisedSender, NetSender};
    use serde_json::Value;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn state_without_session() -> AppState {
        AppState {
            store: TrafficStore::new(),
            ca_pem: None,
            scope: Arc::new(Scope::allow_everything()),
            findings: None,
            audit: None,
            export: None,
            intercept: None,
            session: None,
        }
    }

    fn state_with_session() -> AppState {
        let sender = Arc::new(AuthorisedSender::blocking(
            Arc::new(Scope::allow_everything()),
            NetSender::default(),
        ));
        let session = SessionState::new(AuthorisedMacroSender::new(sender));
        AppState {
            session: Some(session),
            ..state_without_session()
        }
    }

    async fn body_json(response: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Serve the session routes and return `host:port` to reach them, following
    /// `routes::intercept`'s dependency-free test pattern — this crate carries no HTTP client
    /// dev-dependency, so a real request is a raw `TcpStream`, not a library call.
    async fn serve(st: AppState) -> String {
        let app = routes().with_state(st);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await });
        format!("127.0.0.1:{}", addr.port())
    }

    async fn call(addr: &str, method: &str, path: &str, body: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let raw = String::from_utf8_lossy(&buf).into_owned();
        let status = raw
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        (status, body.to_string())
    }

    #[tokio::test]
    async fn configuring_a_macro_then_reading_it_back_returns_the_same_shape() {
        let addr = serve(state_with_session()).await;

        let put_body = json!({
            "steps": [{"method": "POST", "url": "http://target.test/login", "body": "user=a&pass=b"}],
            "rule": {"status_is": 200},
        })
        .to_string();
        let (status, body) = call(&addr, "PUT", "/api/session/macro", &put_body).await;
        assert_eq!(status, 200, "{body}");
        let put_response: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(put_response["configured"], true);
        assert_eq!(put_response["max_attempts"], DEFAULT_MAX_LOGIN_ATTEMPTS);

        let (status, body) = call(&addr, "GET", "/api/session/macro", "").await;
        assert_eq!(status, 200, "{body}");
        let get_response: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            get_response, put_response,
            "reading the macro back must match what was configured"
        );
    }

    #[tokio::test]
    async fn login_with_no_macro_configured_reports_not_configured() {
        let response = login(
            State(state_with_session()),
            Json(LoginReq {
                probe: StepDto {
                    method: "GET".to_string(),
                    url: "http://target.test/whoami".to_string(),
                    headers: vec![],
                    body: String::new(),
                },
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["configured"], false);
        assert_eq!(body["wired"], true);
    }

    /// End-to-end against a loopback listener, following `session_sender.rs`'s pattern: a fake
    /// origin server that answers a two-step macro (login form, then its "logged in" follow-through)
    /// and the retried probe as authenticated.
    #[tokio::test]
    async fn a_two_step_macro_recovers_an_invalid_probe() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // 1: probe -> logged-out. 2: macro step 1 (submit creds) -> redirect + Set-Cookie.
            // 3: macro step 2 (follow-through) -> 200, satisfies the rule so the macro succeeds.
            // 4: retried probe -> 200, now valid.
            let responses = [
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: session=abc123\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ];
            for resp in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).unwrap();
                stream.write_all(resp.as_bytes()).unwrap();
            }
        });

        let sender = Arc::new(AuthorisedSender::blocking(
            Arc::new(Scope::allow_everything()),
            NetSender::default(),
        ));
        let session = SessionState::new(AuthorisedMacroSender::new(sender));
        let login_url = format!("http://{target_addr}/login");
        let home_url = format!("http://{target_addr}/home");
        let probe_url = format!("http://{target_addr}/whoami");
        *session.configured.write() = Some(Arc::new(Configured {
            coordinator: ReloginCoordinator::new(
                Macro {
                    steps: vec![
                        MacroStep {
                            method: "POST".to_string(),
                            url: login_url,
                            headers: vec![],
                            body: Bytes::from_static(b"user=a&pass=b"),
                        },
                        MacroStep {
                            method: "GET".to_string(),
                            url: home_url,
                            headers: vec![],
                            body: Bytes::new(),
                        },
                    ],
                },
                ValidityRule::StatusIs(200),
                DEFAULT_MAX_LOGIN_ATTEMPTS,
            ),
            view: MacroView {
                steps: vec![],
                rule: RuleDto::StatusIs(200),
                max_attempts: DEFAULT_MAX_LOGIN_ATTEMPTS,
            },
        }));

        let response = login(
            State(AppState {
                session: Some(session),
                ..state_without_session()
            }),
            Json(LoginReq {
                probe: StepDto {
                    method: "GET".to_string(),
                    url: probe_url,
                    headers: vec![],
                    body: String::new(),
                },
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(
            body["outcome"], "recovered",
            "a 401 probe followed by a successful macro and a 200 retry must report `recovered`, got {body:?}"
        );
        assert_eq!(body["login_attempts"], 1);
    }
}
