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
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use burpsy_core::{Direction, Exchange, MsgId, Scope, TrafficStore};
use burpsy_intruder::{
    Assignment, Attack, AttackKind, AttackPlan, AttackReport, InsertionPoint, PointConfig,
    RateLimit, RecordFn, SendFn, Sent, find_points,
};
use burpsy_sender::{AuthorisedSender, parse_target};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

pub mod routes;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<TrafficStore>,
    /// CA certificate in PEM, served at `/ca.crt` when interception is enabled.
    pub ca_pem: Option<Arc<String>>,
    /// Authorised targets. Attack endpoints refuse anything outside this.
    pub scope: Arc<Scope>,
    /// Findings produced by the passive scanner, if one is running.
    pub findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    /// Runs the active checks against one exchange, returning a JSON summary.
    ///
    /// A closure rather than a scanner handle so this crate needs no dependency on the scanner or
    /// the sender: the binary owns that wiring, and the web layer only needs "given an exchange id,
    /// audit it".
    pub audit: Option<AuditHook>,
    /// Held-request state, when interception is enabled.
    pub intercept: Option<Arc<routes::intercept::InterceptState>>,
}

/// Audits one exchange by id and returns a JSON summary. Blocking — callers must offload it.
pub type AuditHook = Arc<dyn Fn(u64) -> serde_json::Value + Send + Sync>;

pub fn router(store: Arc<TrafficStore>) -> Router {
    router_with_ca(store, None)
}

pub fn router_with_ca(store: Arc<TrafficStore>, ca_pem: Option<String>) -> Router {
    router_full(store, ca_pem, Scope::allow_everything())
}

pub fn router_full(store: Arc<TrafficStore>, ca_pem: Option<String>, scope: Scope) -> Router {
    router_all(store, ca_pem, scope, None)
}

pub fn router_all(
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: Scope,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
) -> Router {
    router_audit(store, ca_pem, scope, findings, None)
}

pub fn router_audit(
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: Scope,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
) -> Router {
    Router::new()
        .route("/ca.crt", get(ca_cert))
        .route("/", get(index))
        .route("/api/stats", get(stats))
        .route("/api/history", get(history))
        .route("/api/message/{id}", get(message))
        .route("/api/exchange/{id}", get(exchange))
        .route("/api/repeater/send", post(repeater_send))
        .route("/api/intruder/points", post(intruder_points))
        .route("/api/intruder/run", post(intruder_run))
        .route("/api/scope", get(get_scope))
        .route("/api/issues", get(get_issues))
        .route("/api/audit/{id}", post(run_audit))
        .merge(routes::all())
        .with_state(AppState {
            store,
            ca_pem: ca_pem.map(Arc::new),
            scope: Arc::new(scope),
            findings,
            audit,
            intercept: None,
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
    serve_full(bind, store, ca_pem, Scope::allow_everything()).await
}

pub async fn serve_full(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: Scope,
) -> Result<()> {
    serve_all(bind, store, ca_pem, scope, None).await
}

pub async fn serve_all(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: Scope,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
) -> Result<()> {
    serve_audit(bind, store, ca_pem, scope, findings, None).await
}

pub async fn serve_audit(
    bind: &str,
    store: Arc<TrafficStore>,
    ca_pem: Option<String>,
    scope: Scope,
    findings: Option<Arc<parking_lot::RwLock<burpsy_core::FindingStore>>>,
    audit: Option<AuditHook>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind web ui on {bind}"))?;
    tracing::info!("web ui on http://{bind}");
    axum::serve(
        listener,
        router_audit(store, ca_pem, scope, findings, audit),
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
    Json(serde_json::json!({
        "allow_all": s.scope.allow_all,
        "rules": s.scope.rules,
        "empty": s.scope.is_empty(),
    }))
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

    match sender.send_async(&target, raw.as_bytes()).await {
        Ok(r) => {
            let len = r.raw_response.len();
            let resp_id = s.store.put(r.raw_response.clone(), Direction::Response);
            s.store.set_response(
                ex_id,
                resp_id,
                r.status.unwrap_or(0),
                len,
                r.duration.as_millis() as u64,
            );
            Json(SendResp {
                status: r.status,
                duration_ms: r.duration.as_millis() as u64,
                response: String::from_utf8_lossy(&r.raw_response).into_owned(),
                request_msg_id: req_id.0,
                response_msg_id: resp_id.0,
                exchange_id: ex_id,
            })
            .into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("send failed: {e}")).into_response(),
    }
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
}

/// Rate an operator gets if they do not choose one. Slow enough to be safe on a fragile target.
const DEFAULT_RPS: f64 = 20.0;
/// Floor on the operator-supplied rate. Below this the wait between requests stops being a rate and
/// starts being an arithmetic hazard — see the `rps` validation in `intruder_run`.
const MIN_RPS: f64 = 0.01;
/// Burp's own ceiling on a resource pool's concurrent-request limit (`burp.Zuwo`, 1..=999).
const MAX_IN_FLIGHT_CEILING: usize = 999;

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
    let legacy = req.mode.is_none() && req.payload_sets.is_none();
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

    let raw_sets: Vec<Vec<String>> = match (req.payload_sets, req.payloads) {
        (Some(sets), _) => sets,
        (None, Some(p)) => vec![p],
        (None, None) => {
            return (
                StatusCode::BAD_REQUEST,
                "no payloads: pass payloads or payload_sets",
            )
                .into_response();
        }
    };
    let need = match kind {
        AttackKind::Sniper | AttackKind::BatteringRam => 1,
        AttackKind::Pitchfork | AttackKind::ClusterBomb => selected.len(),
    };
    if raw_sets.len() != need {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "{} needs exactly {need} payload set(s), got {}",
                kind.as_str(),
                raw_sets.len()
            ),
        )
            .into_response();
    }
    let sets: Vec<Vec<bytes::Bytes>> = raw_sets
        .iter()
        .map(|set| {
            set.iter()
                .map(|p| bytes::Bytes::from(p.clone().into_bytes()))
                .collect()
        })
        .collect();

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
    let limits = RateLimit::new(
        Some(rps),
        1,
        req.max_in_flight
            .unwrap_or(10)
            .clamp(1, MAX_IN_FLIGHT_CEILING),
    );
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

    let attack = Attack::new(&m.raw, &selected, &sets, &plan).with_limits(limits);
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
    Json(RunView { report, examples }).into_response()
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

// ---- UI ------------------------------------------------------------------------------------

async fn index() -> Html<&'static str> {
    Html(UI)
}

const UI: &str = r#"<!doctype html>
<meta charset="utf-8"><title>burpsy</title>
<style>
:root{--bg:#12141a;--fg:#e6e6e6;--dim:#8a8f98;--acc:#ff7a45;--pan:#1a1d25;--brd:#2a2f3a}
*{box-sizing:border-box}
body{margin:0;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--bg);color:var(--fg)}
header{padding:8px 14px;border-bottom:1px solid var(--brd);display:flex;gap:16px;align-items:center}
h1{font-size:14px;margin:0;color:var(--acc);letter-spacing:.5px}
nav button{background:none;border:1px solid var(--brd);color:var(--dim);padding:4px 12px;cursor:pointer;font:inherit}
nav button.on{color:var(--fg);border-color:var(--acc)}
#stats{margin-left:auto;color:var(--dim);font-size:12px}
main{padding:12px 14px}
section{display:none}section.on{display:block}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:3px 8px;border-bottom:1px solid var(--brd);white-space:nowrap;
      overflow:hidden;text-overflow:ellipsis;max-width:380px}
th{color:var(--dim);font-weight:400}
tr:hover td{background:#20242e;cursor:pointer}
textarea{width:100%;background:#0e1015;color:var(--fg);border:1px solid var(--brd);
         font:inherit;padding:8px;min-height:220px}
input{background:#0e1015;color:var(--fg);border:1px solid var(--brd);font:inherit;padding:5px 8px}
button.go{background:var(--acc);border:none;color:#111;padding:6px 16px;cursor:pointer;font:inherit;font-weight:700}
.row{display:flex;gap:10px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}
pre{background:#0e1015;border:1px solid var(--brd);padding:8px;overflow:auto;max-height:60vh;margin:0}
.s2{color:#7ac07a}.s3{color:#7aa7c0}.s4{color:#c9c07a}.s5{color:#c07a7a}.err{color:#c07a7a}
</style>
<header>
  <h1>burpsy</h1>
  <nav>
    <button class="on" data-t="history">History</button>
    <button data-t="repeater">Repeater</button>
    <button data-t="intruder">Intruder</button>
  </nav>
  <div id="stats"></div>
</header>
<main>
  <section id="history" class="on">
    <div class="row"><button class="go" onclick="loadHist()">Refresh</button>
      <span id="hnote" style="color:var(--dim)"></span></div>
    <table><thead><tr><th>#</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th>
      <th>Len</th><th>ms</th><th>TLS</th></tr></thead><tbody id="hbody"></tbody></table>
    <div class="two" style="margin-top:10px">
      <div><b style="color:var(--dim)">Request</b><pre id="vreq">select a row</pre></div>
      <div><b style="color:var(--dim)">Response</b><pre id="vres"></pre></div>
    </div>
  </section>

  <section id="repeater">
    <div class="row">
      <input id="rtarget" placeholder="http://host:port or https://host" style="width:340px">
      <button class="go" onclick="doSend()">Send</button>
      <span id="rmeta" style="color:var(--dim)"></span>
    </div>
    <div class="two">
      <textarea id="rraw" spellcheck="false">GET / HTTP/1.1
Host: example.com
User-Agent: burpsy
Connection: close

</textarea>
      <pre id="rres"></pre>
    </div>
  </section>

  <section id="intruder">
    <div class="row">
      <input id="imsg" placeholder="request msg id" style="width:130px">
      <input id="itarget" placeholder="http://host:port" style="width:280px">
      <label style="color:var(--dim)"><input type="checkbox" id="iall"> all point types</label>
      <button class="go" onclick="loadPoints()">Find points</button>
    </div>
    <table><thead><tr><th>#</th><th>Kind</th><th>Label</th><th>Offset</th><th>Len</th>
      <th>Current value</th></tr></thead><tbody id="ibody"></tbody></table>
    <div class="row" style="margin-top:10px">
      <input id="ipoint" placeholder="point #" style="width:90px">
      <input id="ipayloads" placeholder="payloads, comma separated" style="width:460px"
             value="'
,&quot;,../../etc/passwd,{{7*7}},&lt;script&gt;">
      <button class="go" onclick="runAttack()">Attack</button>
      <span id="imeta" style="color:var(--dim)"></span>
    </div>
    <table><thead><tr><th>Payload</th><th>Status</th><th>Len</th><th>ms</th><th>Error</th></tr>
      </thead><tbody id="rbody"></tbody></table>
  </section>
</main>
<script>
const $=s=>document.querySelector(s), esc=s=>(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('section').forEach(s=>s.classList.toggle('on',s.id===b.dataset.t));
});
const sc=s=>s?`<span class="s${String(s)[0]}">${s}</span>`:'-';
async function stats(){try{const s=await (await fetch('/api/stats')).json();
  $('#stats').textContent=`${s.exchanges} exchanges · ${s.messages} msgs · ${(s.stored_bytes/1048576).toFixed(2)} MB stored`;}catch(e){}}
async function loadHist(){
  const rows=await (await fetch('/api/history?limit=300')).json();
  $('#hbody').innerHTML=rows.map(r=>`<tr onclick="openEx(${r.id},${r.request},${r.response})">
    <td>${r.id}</td><td>${esc(r.method)}</td><td>${esc(r.host)}:${r.port}</td>
    <td>${esc(r.path)}</td><td>${sc(r.status)}</td><td>${r.response_len}</td>
    <td>${r.duration_ms}</td><td>${r.tls?'yes':''}</td></tr>`).join('');
  $('#hnote').textContent=rows.length?'':'no traffic yet — set your browser proxy to this host:8080';
  stats();
}
async function openEx(id,req,res){
  $('#vreq').textContent='loading…';$('#vres').textContent='';
  const a=await (await fetch('/api/message/'+req)).json();
  $('#vreq').textContent=a.text;
  if(res!==null&&res!==undefined){const b=await (await fetch('/api/message/'+res)).json();
    $('#vres').textContent=b.text;}
}
async function doSend(){
  $('#rres').textContent='sending…';
  const r=await fetch('/api/repeater/send',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({target:$('#rtarget').value,raw:$('#rraw').value})});
  if(!r.ok){$('#rres').innerHTML='<span class="err">'+esc(await r.text())+'</span>';return;}
  const d=await r.json();
  $('#rmeta').innerHTML=`${sc(d.status)} · ${d.duration_ms} ms · req msg ${d.request_msg_id}`;
  $('#rres').textContent=d.response; stats();
}
async function loadPoints(){
  const r=await fetch('/api/intruder/points',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({msg_id:+$('#imsg').value,all:$('#iall').checked})});
  if(!r.ok){$('#ibody').innerHTML='<tr><td colspan=6 class="err">'+esc(await r.text())+'</td></tr>';return;}
  const pts=await r.json();
  $('#ibody').innerHTML=pts.map(p=>`<tr onclick="$('#ipoint').value=${p.index}">
    <td>${p.index}</td><td>${p.kind}</td><td>${esc(p.label)}</td><td>${p.offset}</td>
    <td>${p.len}</td><td>${esc(p.current)}</td></tr>`).join('')
    ||'<tr><td colspan=6 style="color:var(--dim)">no insertion points found</td></tr>';
}
async function runAttack(){
  $('#imeta').textContent='running…';
  const payloads=$('#ipayloads').value.split(',');
  const r=await fetch('/api/intruder/run',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({msg_id:+$('#imsg').value,target:$('#itarget').value,
      point_index:+$('#ipoint').value,payloads,all:$('#iall').checked})});
  if(!r.ok){$('#imeta').innerHTML='<span class="err">'+esc(await r.text())+'</span>';return;}
  const res=await r.json();
  $('#imeta').textContent=res.length+' attempts';
  $('#rbody').innerHTML=res.map(a=>`<tr><td>${esc(a.payload)}</td><td>${sc(a.status)}</td>
    <td>${a.len}</td><td>${a.duration_ms}</td><td class="err">${esc(a.error||'')}</td></tr>`).join('');
  stats();
}
loadHist(); setInterval(stats,4000);
</script>
"#;

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
