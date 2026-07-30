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
//! # The API is a rule list, and the coordinator is not rebuilt per edit
//!
//! Session handling is a list of independently-scoped rules, so this is a REST resource:
//! `GET/POST /api/session/rules` and `PUT/DELETE /api/session/rules/{id}`. One `ReloginCoordinator`
//! lives for the whole process and mutates its own list, rather than being replaced whenever a rule
//! changes — it owns the shared cookie jar, and rebuilding it would silently log the operator out of
//! every host each time they renamed a rule.
//!
//! Rules are read back from the coordinator (`ReloginCoordinator::rules`), not echoed from what was
//! submitted, because the two can genuinely differ: `POST /api/session/rules/{id}/update-macro`
//! rewrites a rule's recorded steps server-side. A read-back that replayed the submitted document
//! would keep showing the stale macro the operator had just replaced.
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
//!
//! The rule that owns the probe is resolved *before* the probe is sent, so a probe no rule covers
//! costs the target nothing: there would be no macro to run with whatever came back.

use crate::AppState;
use crate::session_sender::AuthorisedMacroSender;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use burpsy_core::Scope;
use burpsy_session::{
    DEFAULT_MAX_LOGIN_ATTEMPTS, ExtractFrom, ExtractHow, Extraction, Macro, MacroItem,
    MacroResponse, MacroStep, RecoveryOutcome, ReloginCoordinator, SessionRuleSpec, SessionValidity,
    UpdateMacroOutcome, ValidityRule,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

/// Shared state for the session-handling feature: the one [`ReloginCoordinator`] that holds the rule
/// list and the cookie jar, plus the sender that drives it.
///
/// Owned here rather than in [`AppState`] directly, the same way `intercept::InterceptState` is —
/// so this feature can evolve its own storage without touching the shared struct. No lock around the
/// coordinator: it locks its own rule list, which is what lets a rule be edited while a login for
/// another rule is in flight.
pub struct SessionState {
    coordinator: ReloginCoordinator,
    sender: AuthorisedMacroSender,
}

impl SessionState {
    pub fn new(sender: AuthorisedMacroSender) -> Arc<Self> {
        Arc::new(Self {
            coordinator: ReloginCoordinator::new(),
            sender,
        })
    }
}

/// One recorded macro step, as the operator submits and reads it back over the API.
///
/// `body` is UTF-8 text rather than raw bytes: a login macro's body is almost always a form or
/// JSON payload an operator can read and edit as a string, and taking arbitrary bytes here would
/// force every caller of this JSON API to base64-encode an ordinary login form just to submit it.
/// Read-back is therefore lossy for a body that is not UTF-8 — the macro itself keeps the real bytes.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct StepDto {
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: String,
    /// Values to lift out of *this* step's response for a later step's `{{name}}`. Empty is the
    /// common case, so it is defaulted rather than required.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extract: Vec<ExtractionDto>,
}

impl From<StepDto> for MacroItem {
    fn from(d: StepDto) -> Self {
        MacroItem {
            step: MacroStep {
                method: d.method,
                url: d.url,
                headers: d.headers,
                body: Bytes::from(d.body.into_bytes()),
            },
            extract: d.extract.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<&MacroItem> for StepDto {
    fn from(i: &MacroItem) -> Self {
        StepDto {
            method: i.step.method.clone(),
            url: i.step.url.clone(),
            headers: i.step.headers.clone(),
            body: String::from_utf8_lossy(&i.step.body).into_owned(),
            extract: i.extract.iter().map(Into::into).collect(),
        }
    }
}

/// Mirrors [`Extraction`] on the wire. Same reasoning as [`RuleDto`]: the wire format is this
/// crate's to grow, and `burpsy-session` carries no serde derives for it.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct ExtractionDto {
    name: String,
    #[serde(default)]
    from: FromDto,
    how: HowDto,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FromDto {
    #[default]
    Body,
    Header(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HowDto {
    /// `group` defaults to 1: a pattern written to extract something almost always wraps it in the
    /// one capture group, and group 0 (the whole match) has to be asked for deliberately.
    Regex {
        pattern: String,
        #[serde(default = "first_group")]
        group: usize,
    },
    JsonPath(String),
    Whole,
}

fn first_group() -> usize {
    1
}

impl From<ExtractionDto> for Extraction {
    fn from(d: ExtractionDto) -> Self {
        Extraction {
            name: d.name,
            from: match d.from {
                FromDto::Body => ExtractFrom::Body,
                FromDto::Header(h) => ExtractFrom::Header(h),
            },
            how: match d.how {
                HowDto::Regex { pattern, group } => ExtractHow::Regex { pattern, group },
                HowDto::JsonPath(p) => ExtractHow::JsonPath(p),
                HowDto::Whole => ExtractHow::Whole,
            },
        }
    }
}

impl From<&Extraction> for ExtractionDto {
    fn from(e: &Extraction) -> Self {
        ExtractionDto {
            name: e.name.clone(),
            from: match &e.from {
                ExtractFrom::Body => FromDto::Body,
                ExtractFrom::Header(h) => FromDto::Header(h.clone()),
            },
            how: match &e.how {
                ExtractHow::Regex { pattern, group } => HowDto::Regex {
                    pattern: pattern.clone(),
                    group: *group,
                },
                ExtractHow::JsonPath(p) => HowDto::JsonPath(p.clone()),
                ExtractHow::Whole => HowDto::Whole,
            },
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

impl From<&ValidityRule> for RuleDto {
    fn from(r: &ValidityRule) -> Self {
        match r {
            ValidityRule::StatusIs(code) => RuleDto::StatusIs(*code),
            ValidityRule::BodyContains(s) => RuleDto::BodyContains(s.clone()),
            ValidityRule::BodyNotContains(s) => RuleDto::BodyNotContains(s.clone()),
            ValidityRule::HeaderPresent(s) => RuleDto::HeaderPresent(s.clone()),
            ValidityRule::HeaderAbsent(s) => RuleDto::HeaderAbsent(s.clone()),
            ValidityRule::RedirectsTo(s) => RuleDto::RedirectsTo(s.clone()),
            ValidityRule::All(v) => RuleDto::All(v.iter().map(Into::into).collect()),
            ValidityRule::Any(v) => RuleDto::Any(v.iter().map(Into::into).collect()),
            ValidityRule::Not(r) => RuleDto::Not(Box::new(r.as_ref().into())),
        }
    }
}

fn enabled_by_default() -> bool {
    true
}

/// One session-handling rule, as submitted. `id` is absent on the way in and present on the way out.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct SessionRuleDto {
    /// Assigned by the coordinator; ignored if a caller sends one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    name: String,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    /// Which targets this rule handles. Absent applies everywhere; an *empty* scope is refused —
    /// see [`create_rule`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<Scope>,
    steps: Vec<StepDto>,
    /// What this rule treats as a valid session.
    validity: RuleDto,
    /// Absent means the crate's default of [`DEFAULT_MAX_LOGIN_ATTEMPTS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_attempts: Option<u32>,
}

impl SessionRuleDto {
    fn into_spec(self) -> SessionRuleSpec {
        SessionRuleSpec {
            name: self.name,
            enabled: self.enabled,
            scope: self.scope,
            login_macro: Macro {
                items: self.steps.into_iter().map(Into::into).collect(),
            },
            validity: self.validity.into(),
            max_attempts: self.max_attempts.unwrap_or(DEFAULT_MAX_LOGIN_ATTEMPTS),
        }
    }

    fn of(id: u64, spec: &SessionRuleSpec) -> Self {
        Self {
            id: Some(id),
            name: spec.name.clone(),
            enabled: spec.enabled,
            scope: spec.scope.clone(),
            steps: spec.login_macro.items.iter().map(Into::into).collect(),
            validity: (&spec.validity).into(),
            max_attempts: Some(spec.max_attempts),
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/session/rules", get(list_rules).post(create_rule))
        .route(
            "/api/session/rules/{id}",
            put(replace_rule).delete(delete_rule),
        )
        .route("/api/session/rules/{id}/update-macro", post(update_macro))
        .route("/api/session/login", post(login))
        .route("/api/session/cookies", get(cookies))
}

/// Same shape as `/api/intercept` and `/api/issues`: a feature not wired into this process says so
/// in a `200`, rather than a `404` that looks like a typo in the route.
fn feature_unwired() -> axum::response::Response {
    Json(json!({
        "wired": false,
        "rules": [],
        "hint": "session re-login is not attached to this process",
    }))
    .into_response()
}

fn bad_request(msg: impl Into<String>) -> axum::response::Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.into()}))).into_response()
}

fn no_such_rule(id: u64) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": format!("no session rule {id}")})),
    )
        .into_response()
}

/// One rule as the coordinator currently holds it — the read-back after a write, which is not the
/// same document as the one submitted: defaults are resolved, and `update-macro` can have rewritten
/// the steps since.
fn rule_view(session: &SessionState, id: u64) -> Option<SessionRuleDto> {
    session
        .coordinator
        .rules()
        .iter()
        .find(|(existing, _)| *existing == id)
        .map(|(existing, spec)| SessionRuleDto::of(*existing, spec))
}

/// `GET /api/session/rules` — the whole list, in the order the coordinator consults it.
///
/// An empty list is not an error and not a special case: it is what "nothing configured" looks like,
/// and `POST /api/session/login` reports `no_rule_applies` for every probe until one is added.
async fn list_rules(State(s): State<AppState>) -> impl IntoResponse {
    let Some(session) = s.session.as_ref() else {
        return feature_unwired();
    };
    let rules: Vec<SessionRuleDto> = session
        .coordinator
        .rules()
        .iter()
        .map(|(id, spec)| SessionRuleDto::of(*id, spec))
        .collect();
    Json(json!({"wired": true, "rules": rules})).into_response()
}

/// `POST /api/session/rules` — add one rule, returning the id to address it by.
///
/// Rejected rather than coerced: an empty macro, a step URL with no readable host, an empty scope
/// (which would match nothing, so the rule would silently never fire), a `max_attempts` of `0`, an
/// extraction whose pattern does not compile, or a step referring to a `{{value}}` no earlier step
/// extracts. Every one of those is an operator mistake that would otherwise surface as "the button
/// does nothing" or as a confusing `macro_failed` mid-login.
///
/// None of those checks are written here. `SessionRule::new` refuses all of them and its message —
/// which names the rule and the step — is what a `400` carries, so each check lives in exactly one
/// place. A duplicate here would be one more thing to forget when the rule model grows, the same
/// reasoning `../../AGENTS.md` gives for not hand-writing a scope check in a handler.
async fn create_rule(
    State(s): State<AppState>,
    Json(req): Json<SessionRuleDto>,
) -> impl IntoResponse {
    let Some(session) = s.session.as_ref() else {
        return feature_unwired();
    };
    match session.coordinator.add_rule(req.into_spec()) {
        Ok(id) => (
            StatusCode::CREATED,
            Json(json!({"rule": rule_view(session, id)})),
        )
            .into_response(),
        Err(e) => bad_request(e.to_string()),
    }
}

/// `PUT /api/session/rules/{id}` — replace one rule, keeping its position in the list.
async fn replace_rule(
    State(s): State<AppState>,
    Path(id): Path<u64>,
    Json(req): Json<SessionRuleDto>,
) -> impl IntoResponse {
    let Some(session) = s.session.as_ref() else {
        return feature_unwired();
    };
    match session.coordinator.replace_rule(id, req.into_spec()) {
        Ok(true) => Json(json!({"rule": rule_view(session, id)})).into_response(),
        Ok(false) => no_such_rule(id),
        Err(e) => bad_request(e.to_string()),
    }
}

/// `DELETE /api/session/rules/{id}`.
async fn delete_rule(State(s): State<AppState>, Path(id): Path<u64>) -> impl IntoResponse {
    let Some(session) = s.session.as_ref() else {
        return feature_unwired();
    };
    if session.coordinator.remove_rule(id) {
        Json(json!({"removed": id})).into_response()
    } else {
        no_such_rule(id)
    }
}

/// `POST /api/session/rules/{id}/update-macro` — Burp's "update macro": promote the requests the
/// rule's last *successful* login actually sent to being its recorded steps.
///
/// `409` for "nothing observed" rather than `400`: the request is well-formed and the rule exists;
/// what is missing is a successful login to copy from, which the operator fixes by pressing "log in
/// again" and not by editing the request.
async fn update_macro(State(s): State<AppState>, Path(id): Path<u64>) -> impl IntoResponse {
    let Some(session) = s.session.as_ref() else {
        return feature_unwired();
    };
    match session.coordinator.update_macro(id) {
        UpdateMacroOutcome::Updated { steps } => Json(json!({
            "updated": true,
            "steps": steps.iter().map(|step| StepDto::from(&MacroItem::new(step.clone()))).collect::<Vec<_>>(),
        }))
        .into_response(),
        UpdateMacroOutcome::NoSuchRule => no_such_rule(id),
        UpdateMacroOutcome::NothingObserved => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "this rule has not completed a login yet, so there is nothing observed to \
                          promote; run POST /api/session/login against a request it covers first",
            })),
        )
            .into_response(),
        UpdateMacroOutcome::Invalid(e) => bad_request(e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct LoginReq {
    /// The request whose session should end up valid — see the module docs for why this is not
    /// synthesised from the macro itself.
    probe: StepDto,
}

/// `POST /api/session/login` — the operator's "log in again" button: find the rule that owns
/// `probe`, send it, evaluate it against that rule's validity rule, and recover if it fails.
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
    let probe: MacroStep = MacroItem::from(req.probe).step;
    match tokio::task::spawn_blocking(move || run_login(&session, probe)).await {
        Ok(resp) => resp,
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "login task panicked"})),
        )
            .into_response(),
    }
}

fn run_login(session: &SessionState, probe: MacroStep) -> axum::response::Response {
    // Resolved before anything is sent: with no rule for this target there is no macro to run with
    // whatever comes back, so sending the probe would cost the target a request to no purpose.
    let Some((rule_id, rule_name)) = session.coordinator.matching_rule(&probe.url) else {
        return Json(json!({
            "outcome": "no_rule_applies",
            "url": probe.url,
            "rules": session.coordinator.rules().len(),
            "hint": "no enabled rule's scope covers this url; add one, widen its scope, or enable it",
        }))
        .into_response();
    };
    // The chokepoint (HARD-03): `session.sender` is an `AuthorisedMacroSender` over
    // `AuthorisedSender`, so a probe or macro step aimed outside scope is refused here, not
    // rechecked — see `crate::session_sender`. A rule's own scope selects *which login* applies and
    // authorises nothing.
    //
    // `send_with_jar` (not a bare `session.sender.send`) so the probe carries whatever cookie the
    // jar already holds for its host and absorbs any `Set-Cookie` the probe's own response sets —
    // otherwise a probe sent outside the jar would look permanently logged-out (no session cookie
    // ever attached) and `AlreadyValid` would be unreachable in practice.
    let response = match session.coordinator.send_with_jar(&session.sender, &probe) {
        Ok(r) => r,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "outcome": "probe_failed",
                    "rule_id": rule_id,
                    "rule": rule_name,
                    "error": error,
                })),
            )
                .into_response();
        }
    };
    let outcome = session
        .coordinator
        .handle_response(&session.sender, &probe, response);
    outcome_response(rule_id, &rule_name, outcome)
}

/// Faithful `RecoveryOutcome` -> HTTP mapping, labelled with the rule that produced it. Every
/// variant carries its own `outcome` tag rather than collapsing into ok/error, per the coordinator's
/// own docs on why a caller must be able to tell "this is working" from "this has quietly stopped
/// trying". `502` is used only for the two variants where a request could not be sent at all
/// (`MacroFailed`, `RetryFailed`); every variant that ran to a definite conclusion — including
/// `GaveUp` — is a `200` whose body states which.
fn outcome_response(
    rule_id: u64,
    rule_name: &str,
    outcome: RecoveryOutcome,
) -> axum::response::Response {
    let (status, mut body) = outcome_body(outcome);
    if let Some(map) = body.as_object_mut() {
        map.insert("rule_id".to_string(), json!(rule_id));
        map.insert("rule".to_string(), json!(rule_name));
    }
    (status, Json(body)).into_response()
}

fn outcome_body(outcome: RecoveryOutcome) -> (StatusCode, serde_json::Value) {
    match outcome {
        // Unreachable from `run_login`, which resolves the rule before sending — kept faithful
        // rather than `unreachable!()` so a future caller that skips that step is answered honestly.
        RecoveryOutcome::NoRuleApplies { url } => (
            StatusCode::OK,
            json!({"outcome": "no_rule_applies", "url": url}),
        ),
        RecoveryOutcome::AlreadyValid => (StatusCode::OK, json!({"outcome": "already_valid"})),
        RecoveryOutcome::Recovered {
            login_attempts,
            response,
        } => (
            StatusCode::OK,
            json!({
                "outcome": "recovered",
                "login_attempts": login_attempts,
                "response": response_view(&response),
            }),
        ),
        RecoveryOutcome::StillInvalidAfterRelogin {
            login_attempts,
            validity,
            response,
        } => (
            StatusCode::OK,
            json!({
                "outcome": "still_invalid_after_relogin",
                "login_attempts": login_attempts,
                "validity": validity_view(&validity),
                "response": response_view(&response),
            }),
        ),
        RecoveryOutcome::GaveUp { attempts } => (
            StatusCode::OK,
            json!({"outcome": "gave_up", "attempts": attempts}),
        ),
        RecoveryOutcome::MacroFailed { attempt, failure } => (
            StatusCode::BAD_GATEWAY,
            json!({
                "outcome": "macro_failed",
                "attempt": attempt,
                "step_index": failure.step_index,
                "error": failure.error,
            }),
        ),
        RecoveryOutcome::RetryFailed {
            login_attempts,
            error,
        } => (
            StatusCode::BAD_GATEWAY,
            json!({
                "outcome": "retry_failed",
                "login_attempts": login_attempts,
                "error": error,
            }),
        ),
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
///
/// The jar belongs to the coordinator, not to any one rule, so this answers even with an empty rule
/// list — a jar that has absorbed cookies from a probe is worth seeing before any rule exists.
async fn cookies(State(s): State<AppState>) -> impl IntoResponse {
    let Some(session) = s.session.as_ref() else {
        return feature_unwired();
    };
    let jar = session.coordinator.shared_jar();
    let snapshot = jar.lock().snapshot();
    Json(json!({
        "wired": true,
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
    use burpsy_core::{ScopeRule, SharedScope, TrafficStore};
    use burpsy_sender::{AuthorisedSender, NetSender};
    use serde_json::Value;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn state_without_session() -> AppState {
        AppState {
            store: TrafficStore::new(),
            ca_pem: None,
            scope: SharedScope::allow_everything(),
            findings: None,
            audit: None,
            export: None,
            intercept: None,
            session: None,
            tool_log: None,
            live_audit: None,
        }
    }

    fn session_state() -> Arc<SessionState> {
        let sender = Arc::new(AuthorisedSender::blocking(
            SharedScope::allow_everything(),
            NetSender::default(),
        ));
        SessionState::new(AuthorisedMacroSender::new(sender))
    }

    fn state_with_session() -> AppState {
        AppState {
            session: Some(session_state()),
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

    fn one_rule_body() -> String {
        json!({
            "name": "admin login",
            "scope": {"rules": [{"kind": "Include", "host": "target.test", "port": null,
                                 "path_prefix": null, "tls": null}]},
            "steps": [{"method": "POST", "url": "http://target.test/login", "body": "user=a&pass=b"}],
            "validity": {"status_is": 200},
        })
        .to_string()
    }

    #[tokio::test]
    async fn creating_a_rule_then_listing_it_returns_the_same_shape() {
        let addr = serve(state_with_session()).await;

        let (status, body) = call(&addr, "GET", "/api/session/rules", "").await;
        assert_eq!(status, 200, "{body}");
        let empty: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(empty["wired"], true);
        assert_eq!(
            empty["rules"].as_array().map(|r| r.len()),
            Some(0),
            "an empty list is what 'nothing configured' looks like, not an error"
        );

        let (status, body) = call(&addr, "POST", "/api/session/rules", &one_rule_body()).await;
        assert_eq!(status, 201, "{body}");
        let created: Value = serde_json::from_str(&body).unwrap();
        let rule = &created["rule"];
        assert_eq!(rule["name"], "admin login");
        assert_eq!(rule["enabled"], true);
        assert_eq!(rule["max_attempts"], DEFAULT_MAX_LOGIN_ATTEMPTS);
        assert!(rule["id"].as_u64().is_some(), "the id must come back: {rule}");

        let (status, body) = call(&addr, "GET", "/api/session/rules", "").await;
        assert_eq!(status, 200, "{body}");
        let listed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            listed["rules"][0], *rule,
            "reading a rule back must match what was created"
        );
    }

    #[tokio::test]
    async fn a_rule_can_be_replaced_and_deleted_by_id_and_an_unknown_id_is_a_404() {
        let addr = serve(state_with_session()).await;
        let (_, body) = call(&addr, "POST", "/api/session/rules", &one_rule_body()).await;
        let id = serde_json::from_str::<Value>(&body).unwrap()["rule"]["id"]
            .as_u64()
            .expect("id");

        let renamed = json!({
            "name": "renamed",
            "enabled": false,
            "steps": [{"method": "GET", "url": "http://target.test/login"}],
            "validity": {"status_is": 204},
            "max_attempts": 5,
        })
        .to_string();
        let (status, body) = call(
            &addr,
            "PUT",
            &format!("/api/session/rules/{id}"),
            &renamed,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let updated: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(updated["rule"]["name"], "renamed");
        assert_eq!(updated["rule"]["enabled"], false);
        assert_eq!(updated["rule"]["max_attempts"], 5);
        assert_eq!(
            updated["rule"]["id"].as_u64(),
            Some(id),
            "a replacement keeps its id, so the list does not silently reorder"
        );
        assert!(
            updated["rule"]["scope"].is_null(),
            "the replacement stated no scope, so it now applies everywhere: {}",
            updated["rule"]
        );

        let (status, _) = call(&addr, "PUT", "/api/session/rules/9999", &renamed).await;
        assert_eq!(status, 404);
        let (status, _) = call(&addr, "DELETE", "/api/session/rules/9999", "").await;
        assert_eq!(status, 404);

        let (status, _) = call(&addr, "DELETE", &format!("/api/session/rules/{id}"), "").await;
        assert_eq!(status, 200);
        let (_, body) = call(&addr, "GET", "/api/session/rules", "").await;
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["rules"]
                .as_array()
                .map(|r| r.len()),
            Some(0)
        );
    }

    #[tokio::test]
    async fn the_mistakes_that_would_silently_do_nothing_are_refused_with_400() {
        let addr = serve(state_with_session()).await;
        let cases = [
            // An empty scope matches nothing, so the rule would never fire.
            (
                json!({"name": "r", "scope": {"rules": []},
                       "steps": [{"method": "GET", "url": "http://t.test/login"}],
                       "validity": {"status_is": 200}}),
                "matches nothing",
            ),
            (
                json!({"name": "r", "steps": [], "validity": {"status_is": 200}}),
                "no steps",
            ),
            (
                json!({"name": "r", "max_attempts": 0,
                       "steps": [{"method": "GET", "url": "http://t.test/login"}],
                       "validity": {"status_is": 200}}),
                "at least 1",
            ),
            (
                json!({"name": "  ", "steps": [{"method": "GET", "url": "http://t.test/login"}],
                       "validity": {"status_is": 200}}),
                "needs a name",
            ),
            // `burpsy_sender::parse_target` reads a typed-in sentence as a host with an odd name;
            // `burpsy-session`'s stricter parser refuses it, so a rule scoped to an impossible host
            // is never created.
            (
                json!({"name": "r", "steps": [{"method": "GET", "url": "not a url at all"}],
                       "validity": {"status_is": 200}}),
                "no host in its url",
            ),
            (
                json!({"name": "r", "steps": [{"method": "  ", "url": "http://t.test/login"}],
                       "validity": {"status_is": 200}}),
                "empty method",
            ),
            // An extraction whose pattern cannot compile, caught before any login runs.
            (
                json!({"name": "r", "validity": {"status_is": 200}, "steps": [
                    {"method": "GET", "url": "http://t.test/login",
                     "extract": [{"name": "csrf", "how": {"regex": {"pattern": "([unclosed"}}}]}
                ]}),
                "unusable pattern",
            ),
            // A step naming a value nothing produces.
            (
                json!({"name": "r", "validity": {"status_is": 200}, "steps": [
                    {"method": "GET", "url": "http://t.test/login?t={{csrf}}"}
                ]}),
                "no earlier step extracts",
            ),
        ];
        for (body, expected) in cases {
            let (status, resp) = call(&addr, "POST", "/api/session/rules", &body.to_string()).await;
            assert_eq!(status, 400, "{body} -> {resp}");
            assert!(
                resp.contains(expected),
                "expected {expected:?} in the refusal, got {resp}"
            );
        }
        let (_, body) = call(&addr, "GET", "/api/session/rules", "").await;
        assert!(
            body.contains(r#""rules":[]"#),
            "nothing refused may have been stored: {body}"
        );
    }

    #[tokio::test]
    async fn an_extraction_round_trips_through_the_api_unchanged() {
        let addr = serve(state_with_session()).await;
        let body = json!({
            "name": "csrf login",
            "validity": {"status_is": 200},
            "steps": [
                {"method": "GET", "url": "http://t.test/form", "extract": [
                    {"name": "csrf", "from": "body",
                     "how": {"regex": {"pattern": "value=\"([^\"]+)\"", "group": 1}}},
                    {"name": "sid", "from": {"header": "Set-Cookie"},
                     "how": {"regex": {"pattern": "session=([^;]+)", "group": 1}}},
                    {"name": "token", "from": {"header": "X-Token"}, "how": "whole"},
                    {"name": "bearer", "how": {"json_path": "data.access"}}
                ]},
                {"method": "POST", "url": "http://t.test/login?t={{csrf}}",
                 "headers": [["X-CSRF", "{{csrf}}"]], "body": "u=a&s={{sid}}&b={{bearer}}&k={{token}}"}
            ],
        });
        let (status, resp) = call(&addr, "POST", "/api/session/rules", &body.to_string()).await;
        assert_eq!(status, 201, "{resp}");
        let created: Value = serde_json::from_str(&resp).unwrap();
        let steps = &created["rule"]["steps"];
        assert_eq!(
            steps[0]["extract"],
            json!([
                {"name": "csrf", "from": "body",
                 "how": {"regex": {"pattern": "value=\"([^\"]+)\"", "group": 1}}},
                {"name": "sid", "from": {"header": "Set-Cookie"},
                 "how": {"regex": {"pattern": "session=([^;]+)", "group": 1}}},
                {"name": "token", "from": {"header": "X-Token"}, "how": "whole"},
                // Submitted with no `from` at all: the resolved default comes back stated, the same
                // way `max_attempts` does, so a reader never has to know what the default was.
                {"name": "bearer", "from": "body", "how": {"json_path": "data.access"}}
            ]),
            "got {}",
            steps[0]["extract"]
        );
        assert_eq!(
            steps[1]["body"], "u=a&s={{sid}}&b={{bearer}}&k={{token}}",
            "the placeholders must survive the round trip, not be resolved on the way in"
        );
        assert!(
            steps[1].get("extract").is_none(),
            "a step that extracts nothing does not carry an empty list: {}",
            steps[1]
        );
    }

    #[tokio::test]
    async fn login_with_no_rules_reports_that_no_rule_applies_and_sends_nothing() {
        let response = login(
            State(state_with_session()),
            Json(LoginReq {
                probe: StepDto {
                    method: "GET".to_string(),
                    // Unroutable on purpose: if this ever reaches the network the assertion below
                    // would be reporting a send, and there is nothing here that should send.
                    url: "http://127.0.0.1:1/whoami".to_string(),
                    headers: vec![],
                    body: String::new(),
                    extract: vec![],
                },
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["outcome"], "no_rule_applies");
        assert_eq!(body["rules"], 0);
    }

    #[tokio::test]
    async fn a_probe_outside_every_rules_scope_is_not_logged_in_with_another_rules_macro() {
        let session = session_state();
        let mut scope = Scope::new();
        scope.add(ScopeRule::include("staging.test"));
        session
            .coordinator
            .add_rule(
                SessionRuleSpec::new(
                    "staging only",
                    Macro::of_steps(vec![MacroStep {
                        method: "POST".to_string(),
                        url: "http://staging.test/login".to_string(),
                        headers: vec![],
                        body: Bytes::new(),
                    }]),
                    ValidityRule::StatusIs(200),
                )
                .with_scope(scope),
            )
            .expect("valid rule");

        let response = login(
            State(AppState {
                session: Some(session),
                ..state_without_session()
            }),
            Json(LoginReq {
                probe: StepDto {
                    method: "GET".to_string(),
                    url: "http://127.0.0.1:1/whoami".to_string(),
                    headers: vec![],
                    body: String::new(),
                    extract: vec![],
                },
            }),
        )
        .await
        .into_response();
        let body = body_json(response).await;
        assert_eq!(
            body["outcome"], "no_rule_applies",
            "a target no rule covers must not borrow another rule's login: {body:?}"
        );
    }

    /// End-to-end against a loopback listener, following `session_sender.rs`'s pattern: a fake
    /// origin server that answers a two-step macro whose second step has to echo a token scraped out
    /// of the first step's response, and the retried probe as authenticated.
    ///
    /// Then "update macro": the run is promoted to the rule's recorded steps, and the token it
    /// happened to extract must come back as `{{csrf}}` rather than baked in.
    #[tokio::test]
    async fn a_macro_with_parameter_extraction_recovers_a_probe_and_can_be_promoted() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // 1: probe -> logged-out. 2: macro step 1 (the form) -> the CSRF token to echo.
            // 3: macro step 2 (submit creds + token) -> 200 + Set-Cookie, satisfies the rule.
            // 4: retried probe -> 200, now valid.
            let responses = [
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 44\r\nConnection: close\r\n\r\n\
                 <input name=\"csrf\" value=\"tok-9f3a\"><br>x",
                "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ];
            let mut seen = Vec::new();
            for resp in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                seen.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                stream.write_all(resp.as_bytes()).unwrap();
            }
            seen
        });

        let session = session_state();
        let id = session
            .coordinator
            .add_rule(SessionRuleSpec::new(
                "csrf login",
                Macro {
                    items: vec![
                        MacroItem::new(MacroStep {
                            method: "GET".to_string(),
                            url: format!("http://{target_addr}/form"),
                            headers: vec![],
                            body: Bytes::new(),
                        })
                        .extracting(Extraction::regex(
                            "csrf",
                            r#"name="csrf" value="([^"]+)""#,
                            1,
                        )),
                        MacroItem::new(MacroStep {
                            method: "POST".to_string(),
                            url: format!("http://{target_addr}/login"),
                            headers: vec![("X-CSRF".to_string(), "{{csrf}}".to_string())],
                            body: Bytes::from_static(b"user=a&pass=b&csrf={{csrf}}"),
                        }),
                    ],
                },
                ValidityRule::StatusIs(200),
            ))
            .expect("valid rule");

        let state = AppState {
            session: Some(session.clone()),
            ..state_without_session()
        };
        let response = login(
            State(state.clone()),
            Json(LoginReq {
                probe: StepDto {
                    method: "GET".to_string(),
                    url: format!("http://{target_addr}/whoami"),
                    headers: vec![],
                    body: String::new(),
                    extract: vec![],
                },
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(
            body["outcome"], "recovered",
            "a 401 probe, a macro that scrapes a token and echoes it, then a 200 retry must report \
             `recovered`, got {body:?}"
        );
        assert_eq!(body["login_attempts"], 1);
        assert_eq!(body["rule"], "csrf login");
        assert_eq!(body["rule_id"], id);

        // The jar absorbed the login's cookie, and it is visible without any rule being asked.
        let jar = cookies(State(state.clone())).await.into_response();
        let jar = body_json(jar).await;
        assert!(
            jar["cookies"][0]["cookies"][0]["value"] == "abc123",
            "the login's cookie must be in the shared jar: {jar:?}"
        );

        // "Update macro": promote what actually worked, with the token re-tokenised.
        let promoted = update_macro(State(state.clone()), Path(id)).await.into_response();
        assert_eq!(promoted.status(), StatusCode::OK);
        let promoted = body_json(promoted).await;
        assert_eq!(promoted["updated"], true);
        assert_eq!(
            promoted["steps"][1]["body"], "user=a&pass=b&csrf={{csrf}}",
            "promoting a run must not bake in the one-time token it used: {promoted:?}"
        );
        let listed = list_rules(State(state)).await.into_response();
        let listed = body_json(listed).await;
        assert_eq!(
            listed["rules"][0]["steps"][0]["extract"][0]["name"], "csrf",
            "the extraction survives the promotion: {listed:?}"
        );
    }

    #[tokio::test]
    async fn update_macro_before_any_successful_login_is_a_409_not_a_silent_no_op() {
        let addr = serve(state_with_session()).await;
        let (_, body) = call(&addr, "POST", "/api/session/rules", &one_rule_body()).await;
        let id = serde_json::from_str::<Value>(&body).unwrap()["rule"]["id"]
            .as_u64()
            .expect("id");
        let (status, body) = call(
            &addr,
            "POST",
            &format!("/api/session/rules/{id}/update-macro"),
            "",
        )
        .await;
        assert_eq!(status, 409, "{body}");
        assert!(body.contains("nothing observed"), "{body}");

        let (status, _) = call(
            &addr,
            "POST",
            "/api/session/rules/9999/update-macro",
            "",
        )
        .await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn every_endpoint_says_plainly_when_the_feature_is_not_wired_into_this_process() {
        let addr = serve(state_without_session()).await;
        // The two body-taking endpoints get a *valid* body: axum deserialises before a handler runs,
        // so a malformed one would be answered with a 422 about the body rather than with the
        // feature's own answer, and this asserts the answer.
        for (method, path, body) in [
            ("GET", "/api/session/rules", ""),
            ("POST", "/api/session/rules", one_rule_body().as_str()),
            ("PUT", "/api/session/rules/1", one_rule_body().as_str()),
            ("DELETE", "/api/session/rules/1", ""),
            ("POST", "/api/session/rules/1/update-macro", ""),
            ("GET", "/api/session/cookies", ""),
        ] {
            let (status, resp) = call(&addr, method, path, body).await;
            assert_eq!(status, 200, "{method} {path} -> {resp}");
            assert!(
                resp.contains(r#""wired":false"#),
                "{method} {path} -> {resp}"
            );
        }
    }
}
