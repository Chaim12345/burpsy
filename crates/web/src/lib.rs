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
use burpsy_intruder::{AttackKind, InsertionPoint, PointConfig, apply, find_points};
use burpsy_repeater::{Target, send};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

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
        .with_state(AppState {
            store,
            ca_pem: ca_pem.map(Arc::new),
            scope: Arc::new(scope),
            findings,
            audit,
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
    axum::serve(listener, router_audit(store, ca_pem, scope, findings, audit))
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
                ("content-disposition", "attachment; filename=\"burpsy-ca.crt\""),
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
        Err(e) => Json(serde_json::json!({ "error": format!("audit task failed: {e}") }))
            .into_response(),
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
    Json(Stats { exchanges, messages, stored_bytes })
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

async fn repeater_send(
    State(s): State<AppState>,
    Json(req): Json<SendReq>,
) -> impl IntoResponse {
    let target = match Target::parse(&req.target) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad target: {e}")).into_response(),
    };
    // Refuse before a single byte leaves the box: scope is the record of what we may attack.
    if !s.scope.contains_host(&target.host, target.port, target.tls) {
        return (
            StatusCode::FORBIDDEN,
            format!("refused: {}", s.scope.explain(&target.host, target.port, "/", target.tls)),
        )
            .into_response();
    }
    let raw = req.raw.replace("\r\n", "\n").replace('\n', "\r\n");
    let req_id = s.store.put(raw.clone().into_bytes().into(), Direction::Request);
    let ex_id = s.store.add_exchange(Exchange {
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

    match send(&target, raw.as_bytes(), Duration::from_millis(req.timeout_ms)).await {
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
    let cfg = if req.all { PointConfig::all() } else { PointConfig::default() };
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
    point_index: usize,
    payloads: Vec<String>,
    #[serde(default)]
    all: bool,
}

#[derive(Serialize)]
struct AttemptView {
    payload: String,
    status: Option<u16>,
    len: usize,
    duration_ms: u64,
    error: Option<String>,
}

/// Run a sniper attack over one insertion point.
///
/// Sequential on purpose for this first cut: concurrency here needs a rate limiter and a resource
/// pool (Burp's `resourcePoolSelectionConfig`), and firing unbounded parallel requests at a target
/// is how you take it down rather than test it.
async fn intruder_run(State(s): State<AppState>, Json(req): Json<RunReq>) -> impl IntoResponse {
    let Some(m) = s.store.get(MsgId(req.msg_id)) else {
        return (StatusCode::NOT_FOUND, "no such message").into_response();
    };
    let target = match Target::parse(&req.target) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad target: {e}")).into_response(),
    };
    if !s.scope.contains_host(&target.host, target.port, target.tls) {
        return (
            StatusCode::FORBIDDEN,
            format!("refused: {}", s.scope.explain(&target.host, target.port, "/", target.tls)),
        )
            .into_response();
    }
    let cfg = if req.all { PointConfig::all() } else { PointConfig::default() };
    let pts: Vec<InsertionPoint> = find_points(&m, &cfg);
    let Some(point) = pts.get(req.point_index) else {
        return (StatusCode::BAD_REQUEST, "point_index out of range").into_response();
    };

    // Cap so a fat paste cannot become an accidental DoS.
    let payloads: Vec<String> = req.payloads.into_iter().take(500).collect();
    let mut out = Vec::with_capacity(payloads.len());
    for p in payloads {
        let bytes = apply(&m.raw, point, p.as_bytes());
        match send(&target, &bytes, Duration::from_secs(15)).await {
            Ok(r) => {
                let len = r.raw_response.len();
                s.store.put(r.raw_response, Direction::Response);
                out.push(AttemptView {
                    payload: p,
                    status: r.status,
                    len,
                    duration_ms: r.duration.as_millis() as u64,
                    error: None,
                });
            }
            Err(e) => out.push(AttemptView {
                payload: p,
                status: None,
                len: 0,
                duration_ms: 0,
                error: Some(e.to_string()),
            }),
        }
    }
    let _ = AttackKind::Sniper;
    Json(out).into_response()
}

fn first_token(raw: &str) -> String {
    raw.split_whitespace().next().unwrap_or_default().to_string()
}
fn second_token(raw: &str) -> String {
    raw.split_whitespace().nth(1).unwrap_or_default().to_string()
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
