//! burpsy-web — JSON API and a single-page UI for testing.
//!
//! Browser-based rather than a native GUI, for the reason Caido gets right: the perceived slowness
//! of Burp is largely Swing, and a web front end also makes the tool usable headless or over SSH.
//!
//! The API deliberately returns *index* rows for history (`Exchange`, which holds `MsgId`s and
//! lengths) and only fetches message bytes when a specific message is opened. Listing 100k
//! exchanges therefore never touches a single body.

use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use burpsy_core::{Direction, Exchange, MsgId, RuleKind, ScopeRule, SharedScope, TrafficStore};
use burpsy_intruder::{
    Assignment, Attack, AttackKind, AttackPlan, AttackReport, AutoThrottle, Chain, DropReason, Grep,
    InsertionPoint, PayloadSet, PayloadSource, PointConfig, RateLimit, RecordFn, RuleSpec, SendFn,
    Sent, find_points,
};
use burpsy_sender::{AuthorisedSender, parse_target};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

pub mod routes;
pub mod session_sender;
pub mod ui;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<TrafficStore>,
    /// CA certificate in PEM, served at `/ca.crt` when interception is enabled.
    pub ca_pem: Option<Arc<String>>,
    /// Authorised targets. Attack endpoints refuse anything outside this.
    ///
    /// A handle, not a snapshot: `POST /api/scope/rules` edits it while the process runs, and the
    /// proxy's capture gate and the sender's authorisation gate must see that edit too. See
    /// `burpsy_core::SharedScope`.
    pub scope: SharedScope,
    /// Findings produced by the passive scanner, if one is running.
    pub findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    /// Runs the active checks against one exchange, returning a JSON summary.
    ///
    /// A closure rather than a scanner handle so this crate needs no dependency on the scanner or
    /// the sender: the binary owns that wiring, and the web layer only needs "given an exchange id,
    /// audit it".
    pub audit: Option<AuditHook>,
    /// Renders a findings-and-coverage report in one format.
    ///
    /// Same shape and the same reason as `audit`: reporting needs the scanner's coverage model, and
    /// this crate must not depend on the scanner. See `routes::report`.
    pub export: Option<routes::report::ExportHook>,
    /// Held-request state, when interception is enabled.
    pub intercept: Option<Arc<routes::intercept::InterceptState>>,
    /// The login-macro re-login feature's state, when this process has one wired.
    ///
    /// Absent means the feature is not configured for this process — same convention as `audit`,
    /// `export`, and `intercept` above: the routes must say so, not act as if there were an
    /// unconfigured macro to run.
    pub session: Option<Arc<routes::session::SessionState>>,
    /// The unified Repeater/Intruder/Scanner/BCheck activity log — see `burpsy_tools::logger`.
    ///
    /// `Some` and shared with the same `ToolState` `routes::tools` serves from, so this crate's
    /// own `repeater_send`/`intruder_run` write to the exact log `GET /api/tools/log` reads back,
    /// rather than each keeping its own. Absent means the caller built a router without one (only
    /// tests do this) — `repeater_send`/`intruder_run` simply skip logging in that case.
    pub tool_log: Option<Arc<burpsy_tools::logger::ToolLog>>,
    /// The opt-in "live active audit" background sweep's state, when this process has one wired.
    /// Same convention as `intercept`/`session`: absent means the feature does not exist for this
    /// process, not that it exists and is merely off.
    pub live_audit: Option<Arc<routes::liveaudit::LiveAuditState>>,
}

/// Audits one exchange by id and returns a JSON summary. Blocking — callers must offload it.
pub type AuditHook = Arc<dyn Fn(u64) -> serde_json::Value + Send + Sync>;

pub fn router(store: Arc<TrafficStore>) -> Router {
    router_with_ca(store, None)
}

pub fn router_with_ca(store: Arc<TrafficStore>, ca_pem: Option<String>) -> Router {
    router_full(store, ca_pem, SharedScope::allow_everything())
}

pub fn router_full(store: Arc<TrafficStore>, ca_pem: Option<String>, scope: impl Into<SharedScope>) -> Router {
    router_all(store, ca_pem, scope, None)
}

pub fn router_all(
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
) -> Router {
    router_audit(store, ca_pem, scope, findings, None)
}

pub fn router_audit(
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
) -> Router {
    router_export(store, ca_pem, scope, findings, audit, None)
}

pub fn router_export(
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
    export: Option<routes::report::ExportHook>,
) -> Router {
    router_session(store, ca_pem, scope, findings, audit, export, None)
}

#[allow(clippy::too_many_arguments)]
pub fn router_session(
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
    export: Option<routes::report::ExportHook>,
    session: Option<Arc<routes::session::SessionState>>,
) -> Router {
    router_intercept(store, ca_pem, scope, findings, audit, export, session, None)
}

#[allow(clippy::too_many_arguments)]
pub fn router_intercept(
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
    export: Option<routes::report::ExportHook>,
    session: Option<Arc<routes::session::SessionState>>,
    intercept: Option<Arc<routes::intercept::InterceptState>>,
) -> Router {
    router_activity(
        store, ca_pem, scope, findings, audit, export, session, intercept, None, None,
    )
}

/// The full router. Every other constructor above defaults one more argument into this one.
#[allow(clippy::too_many_arguments)]
pub fn router_activity(
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
    export: Option<routes::report::ExportHook>,
    session: Option<Arc<routes::session::SessionState>>,
    intercept: Option<Arc<routes::intercept::InterceptState>>,
    tool_log: Option<Arc<burpsy_tools::logger::ToolLog>>,
    live_audit: Option<Arc<routes::liveaudit::LiveAuditState>>,
) -> Router {
    // The same log this crate's own repeater/intruder handlers write to, handed to `routes::tools`
    // so `GET /api/tools/log` reads it back — one log, not two. `unwrap_or_default` only matters to
    // the shorter constructors above, which pass `None`: a fresh, unshared log rather than a router
    // that fails to build.
    let tool_state = Arc::new(routes::tools::ToolState {
        log: tool_log.clone().unwrap_or_default(),
        ..Default::default()
    });
    Router::new()
        .route("/ca.crt", get(ca_cert))
        .merge(ui::routes())
        .route("/api/stats", get(stats))
        .route("/api/history", get(history))
        .route("/api/message/{id}", get(message))
        .route("/api/exchange/{id}", get(exchange))
        .route("/api/repeater/send", post(repeater_send))
        .route("/api/intruder/points", post(intruder_points))
        .route("/api/intruder/run", post(intruder_run))
        .route("/api/scope", get(get_scope))
        .route("/api/scope/rules", post(add_scope_rule))
        .route("/api/scope/rules/{id}", delete(remove_scope_rule))
        .route("/api/issues", get(get_issues))
        .route("/api/audit/{id}", post(run_audit))
        .merge(routes::all(tool_state))
        .with_state(AppState {
            store,
            ca_pem: ca_pem.map(Arc::new),
            scope: scope.into(),
            findings,
            audit,
            export,
            intercept,
            session,
            tool_log,
            live_audit,
        })
}

pub async fn serve(bind: &str, store: Arc<TrafficStore>) -> Result<()> {
    serve_with_ca(bind, store, None).await
}

pub async fn serve_with_ca(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
) -> Result<()> {
    serve_full(bind, store, ca_pem, SharedScope::allow_everything()).await
}

pub async fn serve_full(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
) -> Result<()> {
    serve_all(bind, store, ca_pem, scope, None).await
}

pub async fn serve_all(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
) -> Result<()> {
    serve_audit(bind, store, ca_pem, scope, findings, None).await
}

pub async fn serve_audit(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
) -> Result<()> {
    serve_export(bind, store, ca_pem, scope, findings, audit, None).await
}

pub async fn serve_export(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
    export: Option<routes::report::ExportHook>,
) -> Result<()> {
    serve_session(bind, store, ca_pem, scope, findings, audit, export, None).await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_session(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
    export: Option<routes::report::ExportHook>,
    session: Option<Arc<routes::session::SessionState>>,
) -> Result<()> {
    serve_intercept(bind, store, ca_pem, scope, findings, audit, export, session, None).await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_intercept(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
    export: Option<routes::report::ExportHook>,
    session: Option<Arc<routes::session::SessionState>>,
    intercept: Option<Arc<routes::intercept::InterceptState>>,
) -> Result<()> {
    serve_activity(
        bind, store, ca_pem, scope, findings, audit, export, session, intercept, None, None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_activity(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: impl Into<SharedScope>,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
    export: Option<routes::report::ExportHook>,
    session: Option<Arc<routes::session::SessionState>>,
    intercept: Option<Arc<routes::intercept::InterceptState>>,
    tool_log: Option<Arc<burpsy_tools::logger::ToolLog>>,
    live_audit: Option<Arc<routes::liveaudit::LiveAuditState>>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind web ui on {bind}"))?;
    tracing::info!("web ui on http://{bind}");
    axum::serve(
        listener,
        router_activity(
            store, ca_pem, scope, findings, audit, export, session, intercept, tool_log,
            live_audit,
        ),
    )
    .await
    .context("serve")?;
    Ok(())
}

/// Serve the CA so a browser can install it. Content type is the one Windows/Chrome expect for a
/// DER-or-PEM certificate download; `Content-Disposition` makes it save as a file rather than render.
async fn ca_cert(State(s): State<AppState>) -> impl IntoResponse {
    match s.ca_pem {
        Some(pem) => (
            StatusCode::OK,
            [
                ("content-type", "application/x-x509-ca-cert"),
                (
                    "content-disposition",
                    "attachment; filename=\"burpsy-ca.crt\"",
                ),
            ],
            pem.as_str().to_owned(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "TLS interception is disabled; start burpsy with --intercept-tls",
        )
            .into_response(),
    }
}

/// Current scope, so the UI can show what is authorised.
async fn get_scope(State(s): State<AppState>) -> impl IntoResponse {
    Json(scope_body(&s.scope))
}

/// The one shape every scope endpoint answers with, so a mutation's response *is* the new state and
/// the UI never has to reconcile a partial update against a re-fetch.
fn scope_body(scope: &SharedScope) -> serde_json::Value {
    let g = scope.read();
    serde_json::json!({
        "allow_all": g.allow_all,
        "rules": g.rules,
        "empty": g.is_empty(),
    })
}

/// One rule to add. Mirrors `ScopeRule`'s own fields; `host` is the only required one.
#[derive(Deserialize)]
struct NewScopeRule {
    /// `"include"` or `"exclude"`.
    kind: String,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    path_prefix: Option<String>,
    #[serde(default)]
    tls: Option<bool>,
}

/// `POST /api/scope/rules` — authorise (or exclude) a host while the tool is running.
///
/// # Why this is allowed to exist
///
/// Scope was immutable at runtime, on the argument that widening authorisation is the privileged
/// operation in Burp's *agentic* tool registry. That argument is about an autonomous agent granting
/// itself new authorisation. This endpoint is the opposite actor: an operator clicking "add to scope"
/// on a row in their own UI, which is what Burp's site-map right-click has always done. See
/// `burpsy_core::scope`'s module docs for the full reasoning.
///
/// What is kept from that concern is that widening is never *incidental*. Nothing else in this process
/// calls this. It is reached only by an explicit request, the UI puts a confirmation in front of it
/// naming what changes, and the effect is logged at `info` so a session's authorisation history is
/// readable afterwards rather than inferred from what got captured.
///
/// The host pattern is validated rather than stored as typed, because a pattern the matcher cannot act
/// on fails *open* on an `exclude` rule — see `burpsy_core::scope::validate_host_pattern`.
async fn add_scope_rule(
    State(s): State<AppState>,
    Json(req): Json<NewScopeRule>,
) -> impl IntoResponse {
    let kind = match req.kind.to_ascii_lowercase().as_str() {
        "include" => RuleKind::Include,
        "exclude" => RuleKind::Exclude,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("kind must be \"include\" or \"exclude\", got {other:?}"),
            )
                .into_response();
        }
    };
    if let Err(why) = burpsy_core::scope::validate_host_pattern(&req.host) {
        return (StatusCode::BAD_REQUEST, why).into_response();
    }
    // A path prefix that does not start with `/` cannot match any request path, and on an exclude that
    // is the fail-open shape again: a rule that reads as protecting `admin` and holds back nothing.
    if let Some(p) = &req.path_prefix
        && !p.is_empty()
        && !p.starts_with('/')
    {
        return (
            StatusCode::BAD_REQUEST,
            format!("path prefix {p:?} must start with `/` or it will match no request"),
        )
            .into_response();
    }

    let mut rule = match kind {
        RuleKind::Include => ScopeRule::include(req.host.trim()),
        RuleKind::Exclude => ScopeRule::exclude(req.host.trim()),
    };
    rule.port = req.port;
    rule.tls = req.tls;
    rule.path_prefix = req.path_prefix.filter(|p| !p.is_empty());

    let id = s.scope.add_rule(rule.clone());
    // At `info`, not `debug`: this is the line that answers "what was this session authorised to
    // touch, and from when" after the fact.
    tracing::info!(
        rule_id = id,
        kind = ?kind,
        host = %req.host.trim(),
        "scope rule added by operator; capture and attack authorisation change from here on"
    );
    let mut body = scope_body(&s.scope);
    body["added"] = serde_json::json!({ "id": id });
    (StatusCode::CREATED, Json(body)).into_response()
}

/// `DELETE /api/scope/rules/{id}` — drop a rule by the id `GET /api/scope` reported for it.
///
/// By id and not by list position, because removal is the direction that can widen without looking
/// like it: taking away an `exclude` authorises everything it was holding back. Rule order is
/// load-bearing (last match wins), so positions shift on every edit, and an index from a stale view
/// would delete the neighbouring rule — which is exactly how a caller aiming at an include ends up
/// deleting the exclude beside it. An unknown id is a 404 rather than a silent success, so a UI acting
/// on stale state finds out instead of reporting a removal that did not happen.
async fn remove_scope_rule(State(s): State<AppState>, Path(id): Path<u64>) -> impl IntoResponse {
    let Some(removed) = s.scope.remove_rule(id) else {
        return (
            StatusCode::NOT_FOUND,
            format!("no scope rule with id {id}; re-read GET /api/scope"),
        )
            .into_response();
    };
    tracing::info!(
        rule_id = id,
        kind = ?removed.kind,
        host = removed.host.as_deref().unwrap_or("any host"),
        widens = removed.kind == RuleKind::Exclude,
        "scope rule removed by operator"
    );
    let mut body = scope_body(&s.scope);
    body["removed"] = serde_json::to_value(&removed).unwrap_or(serde_json::Value::Null);
    Json(body).into_response()
}

/// Deduplicated findings, most severe first.
/// `POST /api/audit/{id}` — actively scan one captured exchange.
///
/// Offloaded to a blocking thread because the evaluator is synchronous and each check may open
/// several connections; running it on a runtime worker would stall every other request.
async fn run_audit(
    State(s): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> impl IntoResponse {
    let Some(hook) = s.audit.clone() else {
        return Json(serde_json::json!({
            "enabled": false,
            "reason": "no check set loaded; start with --bchecks",
        }))
        .into_response();
    };
    match tokio::task::spawn_blocking(move || hook(id)).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            Json(serde_json::json!({ "error": format!("audit task failed: {e}") })).into_response()
        }
    }
}

async fn get_issues(State(s): State<AppState>) -> impl IntoResponse {
    match &s.findings {
        Some(f) => {
            let g = f.read();
            Json(serde_json::json!({
                "enabled": true,
                "counts": { "high": g.severity_counts()[0], "medium": g.severity_counts()[1],
                            "low": g.severity_counts()[2], "info": g.severity_counts()[3] },
                "findings": g.all(),
            }))
            .into_response()
        }
        None => Json(serde_json::json!({
            "enabled": false,
            "hint": "start burpsy with --bchecks <dir> to enable passive scanning",
            "findings": [],
        }))
        .into_response(),
    }
}

// ---- API -----------------------------------------------------------------------------------

#[derive(Serialize)]
struct Stats {
    exchanges: usize,
    messages: usize,
    stored_bytes: usize,
}

async fn stats(State(s): State<AppState>) -> Json<Stats> {
    let (exchanges, messages, stored_bytes) = s.store.counts();
    Json(Stats {
        exchanges,
        messages,
        stored_bytes,
    })
}

#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    200
}

async fn history(State(s): State<AppState>, Query(p): Query<Page>) -> Json<Vec<Exchange>> {
    Json(s.store.exchanges(p.offset, p.limit.min(2000)))
}

async fn exchange(State(s): State<AppState>, Path(id): Path<u64>) -> impl IntoResponse {
    match s.store.exchange(id) {
        Some(e) => Json(e).into_response(),
        None => (StatusCode::NOT_FOUND, "no such exchange").into_response(),
    }
}

#[derive(Serialize)]
struct MessageView {
    id: u64,
    len: usize,
    text: String,
}

async fn message(State(s): State<AppState>, Path(id): Path<u64>) -> impl IntoResponse {
    match s.store.get(MsgId(id)) {
        Some(m) => Json(MessageView {
            id,
            len: m.raw.len(),
            text: String::from_utf8_lossy(&m.raw).into_owned(),
        })
        .into_response(),
        None => (StatusCode::NOT_FOUND, "no such message").into_response(),
    }
}

#[derive(Deserialize)]
struct SendReq {
    target: String,
    raw: String,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}
fn default_timeout_ms() -> u64 {
    15_000
}

#[derive(Serialize)]
struct SendResp {
    status: Option<u16>,
    duration_ms: u64,
    response: String,
    request_msg_id: u64,
    response_msg_id: u64,
    exchange_id: u64,
}

async fn repeater_send(State(s): State<AppState>, Json(req): Json<SendReq>) -> impl IntoResponse {
    let target = match parse_target(&req.target) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad target: {e}")).into_response(),
    };
    let raw = req.raw.replace("\r\n", "\n").replace('\n', "\r\n");
    let sender =
        AuthorisedSender::asynchronous(s.scope.clone(), Duration::from_millis(req.timeout_ms));
    // Asked up front only so an out-of-scope request never reaches history. The binding check is
    // inside the send below and runs whether or not this one did — it judges the bytes themselves
    // rather than the target line, because the operator types the request here and a host-level test
    // would happily pass a request aimed at an excluded path.
    if let Err(why) = sender.check_scope(&target, raw.as_bytes()) {
        return (StatusCode::FORBIDDEN, why).into_response();
    }
    let req_id = s
        .store
        .put(raw.clone().into_bytes().into(), Direction::Request);
    let ex_id = s.store.add_exchange(Exchange {
        related: Vec::new(),
        protocol: burpsy_core::Protocol::Http1,
        id: 0,
        request: req_id,
        response: None,
        host: target.host.clone(),
        port: target.port,
        tls: target.tls,
        method: first_token(&raw),
        path: second_token(&raw),
        status: None,
        response_len: 0,
        started_ms: 0,
        duration_ms: 0,
        notes: Some("repeater".into()),
    });
    let log_id = s.tool_log.as_ref().map(|log| {
        log.started(burpsy_tools::logger::Started {
            tool: burpsy_tools::logger::Tool::Repeater,
            host: target.host.clone(),
            port: target.port,
            tls: target.tls,
            method: first_token(&raw),
            path: second_token(&raw),
            request: req_id,
            started_ms: now_ms(),
            exchange: Some(ex_id),
            note: None,
        })
    });

    match sender.send_async(&target, raw.as_bytes()).await {
        Ok(r) => {
            let len = r.raw_response.len();
            let dur = r.duration.as_millis() as u64;
            let resp_id = s.store.put(r.raw_response.clone(), Direction::Response);
            s.store
                .set_response(ex_id, resp_id, r.status.unwrap_or(0), len, dur);
            if let (Some(log), Some(id)) = (&s.tool_log, log_id) {
                log.finished(id, resp_id, r.status, len, dur);
            }
            Json(SendResp {
                status: r.status,
                duration_ms: dur,
                response: String::from_utf8_lossy(&r.raw_response).into_owned(),
                request_msg_id: req_id.0,
                response_msg_id: resp_id.0,
                exchange_id: ex_id,
            })
            .into_response()
        }
        Err(e) => {
            if let (Some(log), Some(id)) = (&s.tool_log, log_id) {
                log.failed(id, e.to_string(), 0);
            }
            (StatusCode::BAD_GATEWAY, format!("send failed: {e}")).into_response()
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct PointsReq {
    msg_id: u64,
    #[serde(default)]
    all: bool,
}

#[derive(Serialize)]
struct PointView {
    index: usize,
    kind: &'static str,
    label: String,
    offset: usize,
    len: usize,
    current: String,
}

async fn intruder_points(
    State(s): State<AppState>,
    Json(req): Json<PointsReq>,
) -> impl IntoResponse {
    let Some(m) = s.store.get(MsgId(req.msg_id)) else {
        return (StatusCode::NOT_FOUND, "no such message").into_response();
    };
    let cfg = if req.all {
        PointConfig::all()
    } else {
        PointConfig::default()
    };
    let pts = find_points(&m, &cfg);
    let out: Vec<PointView> = pts
        .iter()
        .enumerate()
        .map(|(i, p)| PointView {
            index: i,
            kind: p.kind.as_str(),
            label: p.label.clone(),
            offset: p.span.offset,
            len: p.span.len,
            current: m.text(p.span),
        })
        .collect();
    Json(out).into_response()
}

#[derive(Deserialize)]
struct RunReq {
    msg_id: u64,
    target: String,
    #[serde(default)]
    all: bool,
    /// Single-position form. Equivalent to `points: [n]`.
    #[serde(default)]
    point_index: Option<usize>,
    /// Single payload set. Equivalent to `payload_sets: [[…]]`.
    #[serde(default)]
    payloads: Option<Vec<String>>,
    /// `sniper` | `battering_ram` | `pitchfork` | `cluster_bomb`. Absent means sniper.
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    points: Option<Vec<usize>>,
    /// One set per position for the multi-set modes; exactly one for sniper and battering ram.
    #[serde(default)]
    payload_sets: Option<Vec<Vec<String>>>,
    /// Generated payload sets — numbers, dates, brute forcer, custom iterator, null. One per
    /// position, in the same shape and with the same count rules as `payload_sets`, which it
    /// replaces; a `{"type":"list"}` source is a literal set, so the two are never both needed.
    #[serde(default)]
    payload_sources: Option<Vec<PayloadSource>>,
    /// The payload-processing chain, applied in order to every payload of every set.
    ///
    /// One chain for all sets, where Burp keeps a chain per set. That is a simplification and worth
    /// naming as one: the rules an operator actually chains (encode, prefix, hash) are almost always
    /// the same across the positions of one attack, and a per-set chain is an additive change to this
    /// field's type if that stops being true.
    #[serde(default)]
    payload_rules: Option<Vec<RuleSpec>>,
    /// Cap on the payloads one generator may produce. Reported back per set, never silently applied.
    #[serde(default)]
    max_payloads: Option<usize>,
    /// Flag each response that matches this regex. Compiled here, so a bad pattern is a 400.
    #[serde(default)]
    grep_match: Option<String>,
    /// Pull the first capture group out of each response. The whole match when the pattern has no
    /// groups.
    #[serde(default)]
    grep_extract: Option<String>,
    /// The operator's name for the resource pool these bounds describe. Echoed back in the report;
    /// it does not make two attacks share a limiter — see `burpsy_intruder::RateLimit::name`.
    #[serde(default)]
    pool: Option<String>,
    /// Cut the rate when the target starts answering with the listed statuses. Absent leaves the
    /// limiter behaving exactly as it did before this existed.
    #[serde(default)]
    auto_throttle: Option<AutoThrottle>,
    /// Requests per second. Defaults to a deliberately timid rate; cannot be disabled here.
    #[serde(default)]
    rps: Option<f64>,
    #[serde(default)]
    max_in_flight: Option<usize>,
    /// Ceiling on requests actually sent. Reported back, never silently applied.
    #[serde(default)]
    max_requests: Option<usize>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Serialize)]
struct AttemptView {
    payload: String,
    status: Option<u16>,
    len: usize,
    duration_ms: u64,
    error: Option<String>,
    /// `null` when no `grep_match` was asked for, which is not the same fact as `false`.
    grep_matched: Option<bool>,
    grep_extract: Option<String>,
}

/// What one payload set cost and what it left out. The counting half of generators and rules: a set
/// that was capped or whose rules dropped half the payloads must not look like a set that was typed.
#[derive(Serialize)]
struct PayloadSetView {
    kind: &'static str,
    /// Payloads that will actually be sent, after the cap and after any rule dropped some.
    count: usize,
    /// Payloads the source describes with no cap applied.
    total: u64,
    /// False when `total` saturated and is a floor rather than a count.
    total_exact: bool,
    truncated: bool,
    max_count: usize,
    /// Payloads a processing rule dropped before sending.
    skipped: usize,
    /// Why, grouped: distinct reasons with counts.
    dropped: Vec<DropReason>,
}

/// Payloads behind a bucket, resolved from its ordinal.
#[derive(Serialize)]
struct BucketExample {
    first_ordinal: usize,
    payloads: Vec<String>,
}

#[derive(Serialize)]
struct RunView {
    report: AttackReport,
    /// One entry per bucket, in bucket order: the exact payload combination that produced it.
    /// Results hold ordinals, so this is the resolution step the operator would otherwise do by
    /// hand.
    examples: Vec<BucketExample>,
    /// One entry per payload set, in position order.
    payload_sets: Vec<PayloadSetView>,
}

/// Rate an operator gets if they do not choose one. Slow enough to be safe on a fragile target.
const DEFAULT_RPS: f64 = 20.0;
/// Floor on the operator-supplied rate. Below this the wait between requests stops being a rate and
/// starts being an arithmetic hazard — see the `rps` validation in `intruder_run`.
const MIN_RPS: f64 = 0.01;
/// Burp's own ceiling on a resource pool's concurrent-request limit (`burp.Zuwo`, 1..=999).
const MAX_IN_FLIGHT_CEILING: usize = 999;
/// Payloads one generator may produce when the caller names no cap of its own.
const DEFAULT_MAX_PAYLOADS: usize = 10_000;
/// Ceiling on a compiled grep pattern's program size.
///
/// An operator-supplied regex arrives over HTTP, and `regex` will happily build a multi-megabyte DFA
/// for a pattern like `(a|b){100}`. 1 MiB is far past any grep an operator writes and keeps a typo
/// from becoming a memory spike in a process holding an attack's worth of traffic.
const GREP_SIZE_LIMIT: usize = 1 << 20;
/// Most statuses an auto-throttle may list. Every response tests this list, and a pool that reacts to
/// three hundred distinct statuses is not a configuration anyone means.
const MAX_THROTTLE_STATUSES: usize = 32;

/// Run an attack: sniper, battering ram, pitchfork or cluster bomb.
///
/// # Two response shapes, and why
///
/// A request that names no `mode` and no `payload_sets` is the single-position sniper form the
/// bundled UI posts, and it gets back the flat array of per-attempt rows that UI renders. Anything
/// else gets the full [`AttackReport`]: with a cluster bomb, a row per request is not an answer, and
/// the bucketed summary is.
///
/// Both shapes come off the same engine — the legacy array is a projection of the report — so there
/// is one execution path, one rate limiter, and one place scope is enforced.
async fn intruder_run(State(s): State<AppState>, Json(req): Json<RunReq>) -> impl IntoResponse {
    let Some(m) = s.store.get(MsgId(req.msg_id)) else {
        return (StatusCode::NOT_FOUND, "no such message").into_response();
    };
    let target = match parse_target(&req.target) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad target: {e}")).into_response(),
    };
    // Two layers, because one cannot do this job. Here we only know the host: the paths this attack
    // will actually request do not exist yet, and a payload spliced into a path position invents
    // them. So this refuses a host that is wholly out of scope, and every spliced request is judged
    // again on its own bytes by the guard below. Attacking something outside the engagement is the
    // one bug in this tool with consequences outside the tool.
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
    // The flat-array shape is for the bundled UI's one-position form only. Naming a generator is as
    // clear a statement that the operator wants the full report as naming a mode is.
    let legacy = req.mode.is_none() && req.payload_sets.is_none() && req.payload_sources.is_none();
    let kind = match req.mode.as_deref() {
        None => AttackKind::Sniper,
        Some(name) => match AttackKind::parse(name) {
            Some(k) => k,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "unknown mode {name:?}: expected sniper, battering_ram, pitchfork or cluster_bomb"
                    ),
                )
                    .into_response();
            }
        },
    };

    let cfg = if req.all {
        PointConfig::all()
    } else {
        PointConfig::default()
    };
    let discovered: Vec<InsertionPoint> = find_points(&m, &cfg);

    let wanted: Vec<usize> = match (&req.points, req.point_index) {
        (Some(p), _) => p.clone(),
        (None, Some(i)) => vec![i],
        (None, None) => {
            return (
                StatusCode::BAD_REQUEST,
                "no insertion point selected: pass point_index or points",
            )
                .into_response();
        }
    };
    let mut seen = std::collections::HashSet::new();
    for i in &wanted {
        if *i >= discovered.len() {
            return (
                StatusCode::BAD_REQUEST,
                format!("point {i} out of range: {} points found", discovered.len()),
            )
                .into_response();
        }
        // Two payloads aimed at one position would overlap, and the splice would drop one of them.
        // Better to say so than to send a request the operator did not ask for.
        if !seen.insert(*i) {
            return (
                StatusCode::BAD_REQUEST,
                format!("insertion point {i} selected twice"),
            )
                .into_response();
        }
    }
    // Burp's rule, and a sound one: "This attack type requires between 2 and 20 payload positions"
    // (`burp.Zb33`). One position makes these modes meaningless; twenty is where a cluster bomb
    // stops being an attack and becomes an outage.
    if matches!(kind, AttackKind::Pitchfork | AttackKind::ClusterBomb)
        && !(2..=20).contains(&wanted.len())
    {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "{} requires between 2 and 20 payload positions, got {}",
                kind.as_str(),
                wanted.len()
            ),
        )
            .into_response();
    }
    let selected: Vec<InsertionPoint> = wanted.iter().map(|i| discovered[*i].clone()).collect();

    // A literal list is a `PayloadSource` variant, so the three request shapes collapse to one type
    // here and everything downstream — count checks, resolution, processing — happens once.
    let sources: Vec<PayloadSource> = match (req.payload_sources, req.payload_sets, req.payloads) {
        (Some(s), _, _) => s,
        (None, Some(sets), _) => sets
            .into_iter()
            .map(|items| PayloadSource::List { items })
            .collect(),
        (None, None, Some(p)) => vec![PayloadSource::List { items: p }],
        (None, None, None) => {
            return (
                StatusCode::BAD_REQUEST,
                "no payloads: pass payloads, payload_sets or payload_sources",
            )
                .into_response();
        }
    };
    let need = match kind {
        AttackKind::Sniper | AttackKind::BatteringRam => 1,
        AttackKind::Pitchfork | AttackKind::ClusterBomb => selected.len(),
    };
    if sources.len() != need {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "{} needs exactly {need} payload set(s), got {}",
                kind.as_str(),
                sources.len()
            ),
        )
            .into_response();
    }

    // Compiled once, before any payload is generated: an unparseable pattern is one error here rather
    // than N identical drops inside the attack.
    let chain = match Chain::new(req.payload_rules.as_deref().unwrap_or(&[])) {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("payload rule: {e}")).into_response();
        }
    };
    let payload_cap = req
        .max_payloads
        .unwrap_or(DEFAULT_MAX_PAYLOADS)
        .clamp(1, burpsy_intruder::payload::MAX_PAYLOADS);
    let mut resolved: Vec<PayloadSet> = Vec::with_capacity(sources.len());
    for (i, src) in sources.iter().enumerate() {
        // Generate, then process, then done — all of it before the plan is built, so `plan.len()` is
        // the number of requests and a payload a rule dropped never occupies an ordinal.
        let mut set = match src.resolve(payload_cap) {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("payload set {i} ({}): {e}", src.as_str()),
                )
                    .into_response();
            }
        };
        chain.run(&mut set);
        resolved.push(set);
    }
    // Built before `resolved` is consumed, because these are the numbers that say what the caller
    // asked for versus what the caps and rules left.
    let set_views: Vec<PayloadSetView> = sources
        .iter()
        .zip(&resolved)
        .map(|(src, set)| PayloadSetView {
            kind: src.as_str(),
            count: set.len(),
            total: set.total,
            total_exact: set.total_exact,
            truncated: set.truncated,
            max_count: set.max_count,
            skipped: set.skipped,
            dropped: set.dropped.clone(),
        })
        .collect();
    let sets: Vec<Vec<bytes::Bytes>> = resolved.into_iter().map(|s| s.items).collect();

    let grep = match build_grep(req.grep_match.as_deref(), req.grep_extract.as_deref()) {
        Ok(g) => g,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    if let Some(t) = &req.auto_throttle
        && t.statuses.len() > MAX_THROTTLE_STATUSES
    {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "auto_throttle lists {} statuses, more than the {MAX_THROTTLE_STATUSES} allowed",
                t.statuses.len()
            ),
        )
            .into_response();
    }

    // Bounded at BOTH ends. The ceiling is obvious; the floor is not, and its absence was a real
    // defect: `rps` of 1e-300 passed `> 0.0`, and the limiter then computed a 1e300-second wait,
    // which is not a representable `Duration`. A rate below one request per two minutes is not a
    // rate anyone means, so it is rejected with a message rather than silently clamped.
    let rps = match req.rps {
        None => DEFAULT_RPS,
        Some(r) if r >= MIN_RPS => r.min(1_000.0),
        Some(r) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("rps must be at least {MIN_RPS}, got {r}"),
            )
                .into_response();
        }
    };
    // There is deliberately no way to turn the rate cap off over HTTP.
    let mut limits = RateLimit::new(
        Some(rps),
        1,
        req.max_in_flight
            .unwrap_or(10)
            .clamp(1, MAX_IN_FLIGHT_CEILING),
    );
    if let Some(name) = req.pool {
        limits = limits.named(name);
    }
    if let Some(t) = req.auto_throttle {
        limits = limits.with_auto_throttle(t);
    }
    // The legacy form keeps its original 500-request cap so a fat paste cannot become an accidental
    // DoS; the new form's bound is the operator's, and comes back in the report either way.
    let bound = if legacy {
        500
    } else {
        req.max_requests.unwrap_or(5_000).clamp(1, 200_000)
    };

    let set_lens: Vec<usize> = sets.iter().map(|s| s.len()).collect();
    let plan = AttackPlan::new(kind, selected.len(), &set_lens, bound);

    let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(15_000));
    let addr = Arc::new(target);
    // One authorising sender for the whole attack. The scope decision still happens once per spliced
    // request — which is what matters, because a payload landing in a `UrlPathFolder` or
    // `UrlPathFilename` position rewrites the path, so the request that goes out may address
    // something a host-level check never saw — but it now happens *inside* the sender rather than in
    // an `Option`al guard the caller had to remember to attach.
    let authorised = Arc::new(AuthorisedSender::asynchronous(s.scope.clone(), timeout));
    let sender: SendFn = {
        let authorised = Arc::clone(&authorised);
        Arc::new(move |raw: Vec<u8>| {
            let addr = addr.clone();
            let authorised = Arc::clone(&authorised);
            Box::pin(async move {
                match authorised.send_async(&addr, &raw).await {
                    Ok(r) => Ok(Sent {
                        raw: r.raw_response,
                        duration: r.duration,
                        status: r.status,
                    }),
                    Err(e) => Err(e.to_string()),
                }
            })
        })
    };
    let store = s.store.clone();
    let record: RecordFn = Arc::new(move |raw| store.put(raw, Direction::Response).0);

    let attack = Attack::new(&m.raw, &selected, &sets, &plan)
        .with_limits(limits)
        .with_grep(grep);
    let report = burpsy_intruder::run(attack, sender, Some(record)).await;

    let mut buf = Assignment::default();
    if legacy {
        let rows: Vec<AttemptView> = report
            .attempts
            .iter()
            .map(|a| AttemptView {
                payload: payloads_at(&plan, &sets, a.ordinal, &mut buf)
                    .into_iter()
                    .next()
                    .unwrap_or_default(),
                status: a.status,
                len: a.response_len,
                duration_ms: a.duration_ms,
                error: a.error.clone(),
                grep_matched: a.grep_matched,
                grep_extract: a.grep_extract.clone(),
            })
            .collect();
        return Json(rows).into_response();
    }

    let examples: Vec<BucketExample> = report
        .buckets
        .iter()
        .map(|b| BucketExample {
            first_ordinal: b.first_ordinal,
            payloads: payloads_at(&plan, &sets, b.first_ordinal, &mut buf),
        })
        .collect();
    Json(RunView {
        report,
        examples,
        payload_sets: set_views,
    })
    .into_response()
}

/// Compile the operator's grep patterns, bounded.
///
/// Both patterns go through `regex::bytes`, not `regex`: a response body is bytes and a target that
/// answers with a Latin-1 page or a gzip stream must still be greppable. A `str` regex would refuse
/// to run against it at all.
fn build_grep(match_re: Option<&str>, extract_re: Option<&str>) -> Result<Grep, String> {
    let compile = |p: &str, what: &str| -> Result<Arc<regex::bytes::Regex>, String> {
        regex::bytes::RegexBuilder::new(p)
            .size_limit(GREP_SIZE_LIMIT)
            .build()
            .map(Arc::new)
            .map_err(|e| format!("bad {what} pattern: {e}"))
    };
    Ok(Grep {
        match_re: match_re
            .filter(|p| !p.is_empty())
            .map(|p| compile(p, "grep_match"))
            .transpose()?,
        extract_re: extract_re
            .filter(|p| !p.is_empty())
            .map(|p| compile(p, "grep_extract"))
            .transpose()?,
    })
}

/// Recover the payload combination behind a plan ordinal.
///
/// This is why results can hold an ordinal and nothing else: the plan is a pure function of the
/// index, so the payloads are always one cheap call away.
fn payloads_at(
    plan: &AttackPlan,
    sets: &[Vec<bytes::Bytes>],
    ordinal: usize,
    buf: &mut Assignment,
) -> Vec<String> {
    if !plan.fill(ordinal, buf) {
        return Vec::new();
    }
    buf.slots
        .iter()
        .filter_map(|slot| sets.get(slot.set).and_then(|set| set.get(slot.payload)))
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect()
}

fn first_token(raw: &str) -> String {
    raw.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}
fn second_token(raw: &str) -> String {
    raw.split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stats_and_history_serve() {
        let store = TrafficStore::new();
        let app = router(store.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let base = format!("http://{addr}");
        let body = reqwest_get(&format!("{base}/api/stats")).await;
        assert!(body.contains("\"exchanges\":0"), "{body}");

        // Store a request and confirm it appears.
        let id = store.put(
            bytes::Bytes::from_static(b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n"),
            Direction::Request,
        );
        store.add_exchange(Exchange {
            related: Vec::new(),
            protocol: burpsy_core::Protocol::Http1,
            id: 0,
            request: id,
            response: None,
            host: "t".into(),
            port: 80,
            tls: false,
            method: "GET".into(),
            path: "/x".into(),
            status: None,
            response_len: 0,
            started_ms: 0,
            duration_ms: 0,
            notes: None,
        });
        let body = reqwest_get(&format!("{base}/api/history")).await;
        assert!(body.contains("\"path\":\"/x\""), "{body}");

        let body = reqwest_get(&format!("{base}/api/message/0")).await;
        assert!(body.contains("GET /x HTTP/1.1"), "{body}");
    }

    #[tokio::test]
    async fn repeater_send_writes_into_the_shared_tool_log() {
        let tgt = echo_target().await;
        let store = TrafficStore::new();
        let tool_log = Arc::new(burpsy_tools::logger::ToolLog::new());
        let app = router_activity(
            store,
            None,
            burpsy_core::Scope::allow_everything(),
            None,
            None,
            None,
            None,
            None,
            Some(tool_log.clone()),
            None,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base = format!("http://{addr}");

        let body = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}","raw":"GET /probe HTTP/1.1\r\nHost: t\r\n\r\n"}}"#
        );
        let (status, resp) = post_json(&format!("{base}/api/repeater/send"), &body).await;
        assert_eq!(status, 200, "{resp}");

        assert_eq!(tool_log.len(), 1, "the send must be recorded exactly once");
        let log_body = reqwest_get(&format!("{base}/api/tools/log")).await;
        assert!(log_body.contains("\"repeater\":1"), "{log_body}");
        assert!(log_body.contains("/probe"), "{log_body}");
    }

    // ---- intruder API -----------------------------------------------------------------------

    /// Minimal POST so tests need no HTTP client dependency.
    async fn post_json(url: &str, body: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rest = url.trim_start_matches("http://");
        let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
        let mut s = tokio::net::TcpStream::connect(hostport).await.unwrap();
        let req = format!(
            "POST /{path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\n\
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

    /// A target that echoes the request line back, so payloads reflect.
    async fn echo_target() -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let body = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string();
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

    // ---- scope API --------------------------------------------------------------------------
    //
    // These are about one property: an operator's edit reaches the code that *authorises traffic*,
    // not just the code that displays rules. Scope was immutable at runtime, so every subsystem held
    // its own `Arc<Scope>` copy; a half-migrated version of this feature would pass a test that only
    // re-read `GET /api/scope` while the repeater kept refusing the host the operator just added.
    // So the assertions are made through `/api/repeater/send`, which is a real authorisation decision
    // taken by an `AuthorisedSender` built after the edit from the same shared handle.

    /// A one-shot request with any method, so DELETE is reachable without an HTTP client dependency.
    async fn request(method: &str, url: &str, body: Option<&str>) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rest = url.trim_start_matches("http://");
        let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
        let mut s = tokio::net::TcpStream::connect(hostport).await.unwrap();
        let head = match body {
            Some(b) => format!(
                "{method} /{path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{b}",
                b.len()
            ),
            None => format!(
                "{method} /{path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n"
            ),
        };
        s.write_all(head.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let out = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, out)
    }

    /// The API with a scope that authorises nothing yet — the state an operator edits their way out of.
    async fn scope_api() -> String {
        let app = router_full(TrafficStore::new(), None, burpsy_core::Scope::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap_or_else(|e| panic!("not json: {e}: {s}"))
    }

    #[tokio::test]
    async fn adding_a_rule_authorises_the_host_on_the_attack_path_without_a_restart() {
        let tgt = echo_target().await;
        let base = scope_api().await;
        let send = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}","raw":"GET / HTTP/1.1\r\nHost: t\r\n\r\n"}}"#
        );

        // Nothing is in scope, so the chokepoint refuses before any socket is opened.
        let (status, why) = post_json(&format!("{base}/api/repeater/send"), &send).await;
        assert_eq!(status, 403, "an empty scope must authorise nothing: {why}");

        let (status, out) = post_json(
            &format!("{base}/api/scope/rules"),
            r#"{"kind":"include","host":"127.0.0.1"}"#,
        )
        .await;
        assert_eq!(status, 201, "{out}");
        let v = json(&out);
        assert_eq!(v["empty"], false);
        assert_eq!(v["rules"].as_array().unwrap().len(), 1);
        assert_eq!(v["rules"][0]["host"], "127.0.0.1");
        let id = v["added"]["id"]
            .as_u64()
            .expect("the new rule must be addressable");
        assert!(id > 0);

        // The same handle the sender reads. This is the assertion that fails on a half-migration.
        let (status, out) = post_json(&format!("{base}/api/repeater/send"), &send).await;
        assert_eq!(
            status, 200,
            "the edit must reach the authorisation gate: {out}"
        );

        // And GET agrees with what the mutation returned, so the UI need not reconcile the two.
        let (_, got) = request("GET", &format!("{base}/api/scope"), None).await;
        assert_eq!(json(&got)["rules"], v["rules"]);
    }

    #[tokio::test]
    async fn removing_a_rule_narrows_the_attack_path_again() {
        let tgt = echo_target().await;
        let base = scope_api().await;
        let send = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}","raw":"GET / HTTP/1.1\r\nHost: t\r\n\r\n"}}"#
        );
        let (_, out) = post_json(
            &format!("{base}/api/scope/rules"),
            r#"{"kind":"include","host":"127.0.0.1"}"#,
        )
        .await;
        let id = json(&out)["added"]["id"].as_u64().unwrap();
        let (status, _) = post_json(&format!("{base}/api/repeater/send"), &send).await;
        assert_eq!(status, 200);

        let (status, out) = request("DELETE", &format!("{base}/api/scope/rules/{id}"), None).await;
        assert_eq!(status, 200, "{out}");
        let v = json(&out);
        assert_eq!(v["removed"]["id"], id);
        assert_eq!(v["empty"], true);
        assert!(v["rules"].as_array().unwrap().is_empty());

        let (status, why) = post_json(&format!("{base}/api/repeater/send"), &send).await;
        assert_eq!(
            status, 403,
            "the narrowing must bind immediately too: {why}"
        );
    }

    #[tokio::test]
    async fn a_path_scoped_exclude_added_at_runtime_refuses_that_path_and_nothing_else() {
        // The two-layer model has to keep working for rules that did not exist at startup.
        let tgt = echo_target().await;
        let base = scope_api().await;
        let rules = format!("{base}/api/scope/rules");
        post_json(&rules, r#"{"kind":"include","host":"127.0.0.1"}"#).await;
        let (status, out) = post_json(
            &rules,
            r#"{"kind":"exclude","host":"127.0.0.1","path_prefix":"/admin"}"#,
        )
        .await;
        assert_eq!(status, 201, "{out}");

        let ok = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}","raw":"GET /search HTTP/1.1\r\nHost: t\r\n\r\n"}}"#
        );
        let bad = format!(
            r#"{{"target":"http://127.0.0.1:{tgt}","raw":"GET /admin/x HTTP/1.1\r\nHost: t\r\n\r\n"}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/repeater/send"), &ok).await;
        assert_eq!(status, 200, "{out}");
        let (status, why) = post_json(&format!("{base}/api/repeater/send"), &bad).await;
        assert_eq!(status, 403, "the runtime exclude must bind to the path");
        assert!(
            why.contains("/admin/x"),
            "the refusal must name the path: {why}"
        );
    }

    #[tokio::test]
    async fn a_host_pattern_the_matcher_cannot_act_on_is_refused_rather_than_stored() {
        // The fail-open case: an exclude with an unmatched wildcard sits in the rule list looking as
        // though it protects something. Better a 400 than a rule that silently holds nothing back.
        let base = scope_api().await;
        let rules = format!("{base}/api/scope/rules");
        for bad in [
            r#"{"kind":"exclude","host":"a*.test"}"#,
            r#"{"kind":"exclude","host":"*.*.test"}"#,
            r#"{"kind":"include","host":""}"#,
            r#"{"kind":"include","host":"http://h.test/a"}"#,
            r#"{"kind":"include","host":"h.test","path_prefix":"admin"}"#,
            r#"{"kind":"sometimes","host":"h.test"}"#,
        ] {
            let (status, why) = post_json(&rules, bad).await;
            assert_eq!(status, 400, "{bad} should have been refused, got {why}");
        }
        let (_, out) = request("GET", &format!("{base}/api/scope"), None).await;
        assert!(
            json(&out)["rules"].as_array().unwrap().is_empty(),
            "a refused rule must not land in the scope: {out}"
        );
        // A leading wildcard is the one form that IS supported, so it must still go in.
        let (status, _) = post_json(&rules, r#"{"kind":"include","host":"*.ok.test"}"#).await;
        assert_eq!(status, 201);
    }

    #[tokio::test]
    async fn removing_an_unknown_rule_id_is_a_404_not_a_silent_success() {
        // A UI acting on stale ids has to find out. Reporting success for a removal that did not
        // happen would leave an operator believing a host was excluded when it was not.
        let base = scope_api().await;
        let (status, why) = request("DELETE", &format!("{base}/api/scope/rules/999"), None).await;
        assert_eq!(status, 404, "{why}");
        assert!(why.contains("999"), "{why}");

        let (_, out) = post_json(
            &format!("{base}/api/scope/rules"),
            r#"{"kind":"include","host":"h.test"}"#,
        )
        .await;
        let id = json(&out)["added"]["id"].as_u64().unwrap();
        let (status, _) = request("DELETE", &format!("{base}/api/scope/rules/{id}"), None).await;
        assert_eq!(status, 200);
        let (status, _) = request("DELETE", &format!("{base}/api/scope/rules/{id}"), None).await;
        assert_eq!(status, 404, "an id must not be removable twice");
    }

    /// The API with the given scope, plus a stored two-parameter request to attack.
    async fn intruder_api(scope: burpsy_core::Scope) -> (String, u64) {
        let store = TrafficStore::new();
        let id = store.put(
            bytes::Bytes::from_static(b"GET /login?user=a&pass=b HTTP/1.1\r\nHost: t.test\r\n\r\n"),
            Direction::Request,
        );
        let app = router_full(store, None, scope);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), id.0)
    }

    /// The bundled UI posts `point_index` + `payloads` and renders `res.map(...)` over the reply.
    /// That contract predates the attack engine and must survive it.
    #[tokio::test]
    async fn the_legacy_sniper_form_still_returns_the_row_array_the_ui_renders() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","point_index":0,
                "payloads":["AAA","BBB","'"]}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        assert!(
            out.starts_with('['),
            "the legacy reply must stay a flat array: {out}"
        );
        let rows: serde_json::Value = serde_json::from_str(&out).unwrap();
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["payload"], "AAA");
        assert_eq!(rows[2]["payload"], "'");
        assert_eq!(rows[0]["status"], 200);
        assert!(rows[0]["len"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn cluster_bomb_reports_every_combination_and_resolves_its_buckets() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        // Payload lengths chosen so no two combinations sum to the same request length; the target
        // echoes the request line, so each combination lands in a bucket of its own.
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"cluster_bomb",
                "points":[0,1],
                "payload_sets":[["u","uu","uuu"],["pppppppppp","pppppppppppppppppppp"]],
                "rps":200}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["report"]["kind"], "cluster_bomb");
        assert_eq!(v["report"]["combinations"], 6);
        assert_eq!(v["report"]["sent"], 6);
        assert_eq!(v["report"]["truncated"], false);

        let buckets = v["report"]["buckets"].as_array().unwrap();
        assert_eq!(buckets.len(), 6, "six distinct response lengths: {out}");
        assert!(buckets.iter().all(|b| b["reflected"] == true), "{out}");
        // One stored exemplar per bucket, not one per request.
        assert_eq!(
            buckets
                .iter()
                .filter(|b| !b["example_response_id"].is_null())
                .count(),
            6
        );

        // Ordinals resolve back to the exact combination that produced each bucket.
        let examples = v["examples"].as_array().unwrap();
        assert_eq!(examples.len(), 6);
        let mut combos: Vec<String> = examples
            .iter()
            .map(|e| {
                e["payloads"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| p.as_str().unwrap())
                    .collect::<Vec<_>>()
                    .join("+")
            })
            .collect();
        combos.sort();
        assert_eq!(
            combos,
            vec![
                "u+pppppppppp",
                "u+pppppppppppppppppppp",
                "uu+pppppppppp",
                "uu+pppppppppppppppppppp",
                "uuu+pppppppppp",
                "uuu+pppppppppppppppppppp",
            ]
        );
    }

    #[tokio::test]
    async fn a_bounded_cluster_bomb_says_so_instead_of_quietly_truncating() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        let sets: Vec<String> = (0..20).map(|i| format!("\"p{i}\"")).collect();
        let set = sets.join(",");
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"cluster_bomb",
                "points":[0,1],"payload_sets":[[{set}],[{set}]],"max_requests":5,"rps":200}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["report"]["combinations"], 400,
            "the real size is reported"
        );
        assert_eq!(v["report"]["max_requests"], 5);
        assert_eq!(
            v["report"]["truncated"], true,
            "and so is the fact it was cut"
        );
        assert_eq!(v["report"]["sent"], 5);
    }

    #[tokio::test]
    async fn pitchfork_pairs_sets_in_lockstep_through_the_api() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        // Distinct lengths again, so the two lockstep pairs land in separate buckets and the
        // combination behind each is visible. A crossed pairing would show up as u+pppp or uuuu+p.
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"pitchfork",
                "points":[0,1],"payload_sets":[["u","uuuu"],["p","pppppppp"]],"rps":200}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["report"]["sent"], 2, "the shortest set ends it: {out}");
        let mut combos: Vec<String> = v["examples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                e["payloads"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| p.as_str().unwrap())
                    .collect::<Vec<_>>()
                    .join("+")
            })
            .collect();
        combos.sort();
        assert_eq!(combos, vec!["u+p", "uuuu+pppppppp"], "sets must not cross");
    }

    // ---- generators, processing rules, grep and pools -------------------------------------------

    /// A generator is only useful if the operator can see what it produced *and* what it left out.
    /// 1..=200 capped at 10 must report both numbers, not just the ten it sent.
    #[tokio::test]
    async fn a_numbers_generator_produces_payloads_and_reports_the_cap_it_hit() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"sniper","points":[0],
                "payload_sources":[{{"type":"numbers","from":1,"to":200,"step":1,"pad_to":4}}],
                "max_payloads":10,"rps":200}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["report"]["sent"], 10);

        let sets = v["payload_sets"].as_array().unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0]["kind"], "numbers");
        assert_eq!(sets[0]["count"], 10, "the cap is what got sent");
        assert_eq!(sets[0]["total"], 200, "and the operator is told the real size");
        assert_eq!(sets[0]["truncated"], true);

        // Zero-padded, and the payloads resolve back through the ordinals like any other set.
        let payloads: Vec<String> = v["examples"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["payloads"][0].as_str().map(str::to_string))
            .collect();
        assert!(
            payloads.iter().all(|p| p.len() == 4 && p.starts_with("000")),
            "expected 4-digit zero-padded numbers, got {payloads:?}"
        );
    }

    /// The chain runs before the plan is built, so a skipped payload is a shorter set rather than a
    /// hole: `sent` is the surviving count and the drop is accounted for, not merely missing.
    #[tokio::test]
    async fn a_processing_chain_transforms_payloads_and_accounts_for_the_ones_it_dropped() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        // Distinct payload lengths, as in the pitchfork test above: the target echoes the request
        // line, so two same-length payloads would collapse into one bucket and `examples` would have
        // one entry for both.
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"sniper","points":[0],
                "payload_sources":[{{"type":"list","items":["admin","superuser","42"]}}],
                "payload_rules":[
                    {{"rule":"skip_if_matches","pattern":"^[0-9]+$"}},
                    {{"rule":"add_prefix","text":"x-"}},
                    {{"rule":"uppercase"}}
                ],
                "rps":200}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();

        assert_eq!(v["report"]["sent"], 2, "the numeric payload was dropped");
        let set = &v["payload_sets"][0];
        assert_eq!(set["count"], 2);
        assert_eq!(set["skipped"], 1);
        assert_eq!(set["dropped"][0]["count"], 1);

        let mut payloads: Vec<String> = v["examples"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["payloads"][0].as_str().map(str::to_string))
            .collect();
        payloads.sort();
        assert_eq!(
            payloads,
            vec!["X-ADMIN", "X-SUPERUSER"],
            "rules must apply in order: prefix, then case"
        );
    }

    #[tokio::test]
    async fn grep_match_and_grep_extract_come_back_per_attempt_and_per_bucket() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        // The target echoes the request line, so the payload is in the response and a grep can find
        // it. `user=(\w+)` extracts whichever payload landed in the first position.
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"sniper","points":[0],
                "payload_sets":[["needle","haystack"]],
                "grep_match":"needle","grep_extract":"user=(\\w+)","rps":200}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["report"]["sent"], 2);
        assert_eq!(
            v["report"]["grep_matched"], 1,
            "exactly one response held the needle: {out}"
        );

        let attempts = v["report"]["attempts"].as_array().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0]["grep_matched"], true);
        assert_eq!(attempts[0]["grep_extract"], "needle");
        assert_eq!(attempts[1]["grep_matched"], false);
        assert_eq!(attempts[1]["grep_extract"], "haystack");
        // The two responses differ in length, so each gets its own bucket and the counts are 1 and 0.
        let matched: Vec<u64> = v["report"]["buckets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["grep_matches"].as_u64().unwrap())
            .collect();
        assert_eq!(matched.iter().sum::<u64>(), 1, "{out}");
    }

    /// A pattern the operator mistyped must be one 400 at the edge, not a per-response failure that
    /// makes an attack look like it ran clean.
    #[tokio::test]
    async fn a_bad_grep_pattern_or_payload_rule_is_refused_before_anything_is_sent() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        let cases = [
            format!(
                r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"sniper","points":[0],
                    "payload_sets":[["x"]],"grep_match":"([unclosed"}}"#
            ),
            format!(
                r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"sniper","points":[0],
                    "payload_sets":[["x"]],"payload_rules":[{{"rule":"encode","layer":"rot13"}}]}}"#
            ),
            format!(
                r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"sniper","points":[0],
                    "payload_sources":[{{"type":"numbers","from":1,"to":9,"step":0}}]}}"#
            ),
        ];
        for body in cases {
            let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
            assert_eq!(status, 400, "should have been refused: {body} -> {out}");
        }
    }

    /// The pool name is an identifier the caller passes and gets back, which is the whole contract —
    /// so the test is that it survives the round trip, and that an unconfigured throttle stays at 0.
    #[tokio::test]
    async fn a_named_pool_comes_back_in_the_report_and_an_unset_throttle_never_engages() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"sniper","points":[0],
                "payload_sets":[["a","b"]],"pool":"fragile-staging","rps":200}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["report"]["pool"], "fragile-staging");
        assert_eq!(v["report"]["auto_throttle_engaged"], 0);
    }

    /// An auto-throttle config must be accepted and reported, and against a healthy target must leave
    /// the attack alone. The engine's own tests cover it engaging; this covers the API not breaking
    /// the default path.
    #[tokio::test]
    async fn an_auto_throttle_is_accepted_and_leaves_a_healthy_attack_untouched() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"sniper","points":[0],
                "payload_sets":[["a","b","c"]],"rps":200,
                "auto_throttle":{{"statuses":[429,503],"after":2,"factor":2.0,"recover_after":10}}}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["report"]["sent"], 3);
        assert_eq!(v["report"]["failed"], 0);
        assert_eq!(
            v["report"]["auto_throttle_engaged"], 0,
            "a target answering 200 must not have tripped it"
        );
    }

    /// Every request shape that predates generators must still work byte for byte, because the UI is
    /// built against them and one of them is the flat-array legacy form.
    #[tokio::test]
    async fn the_pre_generator_request_shapes_are_untouched_by_the_new_fields() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;

        // Legacy: no mode, no sets -> flat array, and the two new per-row fields say "not asked".
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","point_index":0,
                "payloads":["AAA","BBB"]}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        assert!(out.starts_with('['), "still a flat array: {out}");
        let rows: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(rows[0]["payload"], "AAA");
        assert!(
            rows[0]["grep_matched"].is_null(),
            "an unasked grep must be null, not false: {out}"
        );

        // `payload_sets` still resolves to a report, and now also describes the sets it was given.
        let body = format!(
            r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"sniper","points":[0],
                "payload_sets":[["a","bb"]],"rps":200}}"#
        );
        let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
        assert_eq!(status, 200, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["report"]["sent"], 2);
        assert_eq!(v["payload_sets"][0]["kind"], "list");
        assert_eq!(v["payload_sets"][0]["truncated"], false);
        assert_eq!(v["payload_sets"][0]["skipped"], 0);
    }

    /// Scope is the one thing here with consequences outside the tool. Every mode must hit it, and
    /// it must be checked before a single request is planned.
    #[tokio::test]
    async fn every_attack_mode_refuses_a_target_outside_scope() {
        let tgt = echo_target().await;
        let mut scope = burpsy_core::Scope::new();
        scope.add(burpsy_core::ScopeRule::include("authorised.test"));
        let (base, msg) = intruder_api(scope).await;

        let cases = [
            format!(
                r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","point_index":0,"payloads":["x"]}}"#
            ),
            format!(
                r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"cluster_bomb",
                    "points":[0,1],"payload_sets":[["x"],["y"]]}}"#
            ),
            format!(
                r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"pitchfork",
                    "points":[0,1],"payload_sets":[["x"],["y"]]}}"#
            ),
            format!(
                r#"{{"msg_id":{msg},"target":"http://127.0.0.1:{tgt}","mode":"battering_ram",
                    "points":[0,1],"payload_sets":[["x"]]}}"#
            ),
        ];
        for body in cases {
            let (status, out) = post_json(&format!("{base}/api/intruder/run"), &body).await;
            assert_eq!(status, 403, "out-of-scope target was accepted: {out}");
            assert!(out.contains("out of scope"), "{out}");
        }
    }

    #[tokio::test]
    async fn malformed_attack_requests_are_rejected_not_guessed_at() {
        let tgt = echo_target().await;
        let (base, msg) = intruder_api(burpsy_core::Scope::allow_everything()).await;
        let url = format!("{base}/api/intruder/run");
        let target = format!("http://127.0.0.1:{tgt}");

        let cases: [(&str, String); 5] = [
            (
                "unknown mode",
                format!(
                    r#"{{"msg_id":{msg},"target":"{target}","mode":"shotgun","points":[0],"payload_sets":[["x"]]}}"#
                ),
            ),
            (
                "one position for a multi-set mode",
                format!(
                    r#"{{"msg_id":{msg},"target":"{target}","mode":"cluster_bomb","points":[0],"payload_sets":[["x"]]}}"#
                ),
            ),
            (
                "set count not matching position count",
                format!(
                    r#"{{"msg_id":{msg},"target":"{target}","mode":"pitchfork","points":[0,1],"payload_sets":[["x"]]}}"#
                ),
            ),
            (
                "the same position twice",
                format!(
                    r#"{{"msg_id":{msg},"target":"{target}","mode":"pitchfork","points":[0,0],"payload_sets":[["x"],["y"]]}}"#
                ),
            ),
            (
                "a zero rate",
                format!(
                    r#"{{"msg_id":{msg},"target":"{target}","mode":"sniper","points":[0],"payload_sets":[["x"]],"rps":0}}"#
                ),
            ),
        ];
        for (what, body) in cases {
            let (status, out) = post_json(&url, &body).await;
            assert_eq!(status, 400, "{what} was accepted: {out}");
        }
    }

    /// Minimal GET so tests need no HTTP client dependency.
    async fn reqwest_get(url: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rest = url.trim_start_matches("http://");
        let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
        let mut s = tokio::net::TcpStream::connect(hostport).await.unwrap();
        let req = format!("GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }
}
