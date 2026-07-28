//! Decoder, Comparer, Logger, Organizer, match-and-replace.
//!
//! # Why the tools own their state instead of joining `AppState`
//!
//! `AppState` is shared by every feature, so adding a field to it serialises development the same
//! way a shared route table does — the exact problem `routes/mod.rs` was split to avoid. These
//! endpoints therefore carry their state as a request [`Extension`] attached to their own subtree.
//! `AppState` is still extracted where a handler needs the message store, so nothing is lost.
//!
//! [`routes_with`] exists so the binary can hold the same [`ToolState`] the HTTP layer serves —
//! that is the hook Repeater, Intruder and the scanner need in order to write to the tool log, and
//! the proxy needs in order to read the match-and-replace rules.
//!
//! # What is deliberately not here
//!
//! Nothing in this file sends traffic. Compare, decode and rule-test are pure functions over bytes
//! the caller already has, so none of them can reach the network and none of them need a scope
//! check. `POST /api/tools/log` records a request that some other component already sent.

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use burpsy_core::{Direction, MsgId};
use burpsy_tools::comparer::{self, Granularity, Op};
use burpsy_tools::decoder::{self, Layer, SmartOptions};
use burpsy_tools::logger::{Started, Tool, ToolLog};
use burpsy_tools::matchreplace::{Ctx, RuleSet, RuleSetSpec};
use burpsy_tools::organizer::{Highlight, Organizer};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Everything the tool endpoints own.
#[derive(Debug, Default)]
pub struct ToolState {
    pub log: ToolLog,
    pub organizer: Organizer,
    /// Swapped wholesale on `PUT /api/tools/rules`, so the proxy's read side never sees a
    /// half-applied rule list.
    pub rules: RwLock<RuleSet>,
}

pub fn routes() -> Router<AppState> {
    routes_with(Arc::new(ToolState::default()))
}

/// The same routes, over state the caller keeps a handle to.
pub fn routes_with(state: Arc<ToolState>) -> Router<AppState> {
    Router::new()
        .route("/api/tools/decode", post(decode))
        .route("/api/tools/encode", post(encode))
        .route("/api/tools/compare", post(compare))
        .route(
            "/api/tools/log",
            get(log_list).post(log_record).delete(log_clear),
        )
        .route("/api/tools/organizer", get(org_list).post(org_add))
        .route(
            "/api/tools/organizer/{id}",
            post(org_update).delete(org_remove),
        )
        .route("/api/tools/rules", get(rules_get).put(rules_put))
        .route("/api/tools/rules/test", post(rules_test))
        .layer(Extension(state))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Bytes as JSON. Lossy text plus the facts needed to know whether to trust it — a decoded gzip
/// response can be a PNG, and silently handing back replacement characters would be a lie.
///
/// `truncated` is the other half of that standard. A decompression stopped by the inflate cap, or
/// broken mid-stream, yields real bytes that are nonetheless only a prefix; returning them with an
/// unqualified 200 let an operator read 40 recovered bytes, conclude the string they wanted was
/// absent, and move on when it sat in the 3 960 that never decompressed.
#[derive(Serialize)]
struct BytesView {
    text: String,
    len: usize,
    utf8: bool,
    truncated: bool,
}

impl BytesView {
    /// For bytes that are complete by construction — anything that did not go through a decoder.
    fn new(b: &[u8]) -> Self {
        Self::partial(b, false)
    }

    /// For bytes whose completeness the caller had to determine.
    fn partial(b: &[u8], truncated: bool) -> Self {
        Self {
            text: String::from_utf8_lossy(b).into_owned(),
            len: b.len(),
            utf8: std::str::from_utf8(b).is_ok(),
            truncated,
        }
    }
}

/// Resolve either a stored message or literal text.
fn source(
    s: &AppState,
    msg_id: Option<u64>,
    text: Option<&str>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    match msg_id {
        Some(id) => s
            .store
            .get(MsgId(id))
            .map(|m| m.raw.to_vec())
            .ok_or((StatusCode::NOT_FOUND, format!("no message {id}"))),
        None => Ok(text.unwrap_or_default().as_bytes().to_vec()),
    }
}

// ---- decoder ---------------------------------------------------------------------------------

#[derive(Deserialize)]
struct DecodeReq {
    #[serde(default)]
    input: String,
    #[serde(default)]
    msg_id: Option<u64>,
    /// A layer name, or absent/`"smart"` to let the decoder work it out.
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    guess_alphabets: bool,
    #[serde(default = "default_passes")]
    max_passes: usize,
}
fn default_passes() -> usize {
    4
}

#[derive(Serialize)]
struct RunView {
    layer: Option<&'static str>,
    confidence: Option<&'static str>,
    why: &'static str,
    input_offset: usize,
    input_len: usize,
    output_offset: usize,
    output_len: usize,
    truncated: bool,
}

async fn decode(State(s): State<AppState>, Json(req): Json<DecodeReq>) -> impl IntoResponse {
    let input = match source(&s, req.msg_id, Some(&req.input)) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let name = req
        .encoding
        .as_deref()
        .unwrap_or("smart")
        .trim()
        .to_string();

    if name.is_empty() || name.eq_ignore_ascii_case("smart") {
        let opts = SmartOptions {
            max_passes: req.max_passes.clamp(1, 16),
            guess_alphabets: req.guess_alphabets,
        };
        let r = decoder::smart_decode(&input, &opts);
        let passes: Vec<serde_json::Value> = r
            .passes
            .iter()
            .map(|p| {
                serde_json::json!({
                    "output": BytesView::partial(&p.output, p.truncated()),
                    "runs": p.runs.iter().map(|run| RunView {
                        layer: run.layer.map(Layer::as_str),
                        confidence: run.confidence.map(|c| match c {
                            decoder::Confidence::Definite => "definite",
                            decoder::Confidence::Likely => "likely",
                        }),
                        why: run.why,
                        input_offset: run.input.offset,
                        input_len: run.input.len,
                        output_offset: run.output.offset,
                        output_len: run.output.len,
                        truncated: run.truncated,
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();
        return Json(serde_json::json!({
            "mode": "smart",
            "layers": r.layers().iter().map(|l| l.as_str()).collect::<Vec<_>>(),
            "output": BytesView::partial(&r.output, r.truncated()),
            // Every intermediate, so a guess the operator disagrees with can be backed out of.
            "passes": passes,
        }))
        .into_response();
    }

    let Some(layer) = Layer::parse(&name) else {
        return (
            StatusCode::BAD_REQUEST,
            format!("unknown encoding {name:?}"),
        )
            .into_response();
    };
    match decoder::decode(layer, &input) {
        Ok((out, truncated)) => Json(serde_json::json!({
            "mode": "explicit",
            "layers": [layer.as_str()],
            "output": BytesView::partial(&out, truncated),
        }))
        .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct EncodeReq {
    #[serde(default)]
    input: String,
    #[serde(default)]
    msg_id: Option<u64>,
    encoding: String,
}

async fn encode(State(s): State<AppState>, Json(req): Json<EncodeReq>) -> impl IntoResponse {
    let input = match source(&s, req.msg_id, Some(&req.input)) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let Some(layer) = Layer::parse(&req.encoding) else {
        return (
            StatusCode::BAD_REQUEST,
            format!("unknown encoding {:?}", req.encoding),
        )
            .into_response();
    };
    match decoder::encode(layer, &input) {
        Ok(out) => Json(serde_json::json!({
            "encoding": layer.as_str(),
            "output": BytesView::new(&out),
        }))
        .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// ---- comparer --------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct Side {
    #[serde(default)]
    msg_id: Option<u64>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct CompareReq {
    #[serde(default)]
    a: Side,
    #[serde(default)]
    b: Side,
    /// `"byte"` or `"word"`.
    #[serde(default)]
    granularity: Option<String>,
}

/// Cap on ops returned. A diff of two unrelated bodies can have tens of thousands; the browser
/// cannot render them and the counts already say how big the change is.
const MAX_OPS: usize = 2000;

/// Cap on how much of a changed region is inlined per op.
const PREVIEW: usize = 240;

#[derive(Serialize)]
struct OpView {
    kind: &'static str,
    a_offset: usize,
    a_len: usize,
    b_offset: usize,
    b_len: usize,
    /// The changed bytes, truncated. Absent for equal regions, which the client already has.
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

async fn compare(State(s): State<AppState>, Json(req): Json<CompareReq>) -> impl IntoResponse {
    let a = match source(&s, req.a.msg_id, req.a.text.as_deref()) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let b = match source(&s, req.b.msg_id, req.b.text.as_deref()) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let granularity = match req.granularity.as_deref().unwrap_or("word") {
        g if g.eq_ignore_ascii_case("byte") => Granularity::Byte,
        g if g.eq_ignore_ascii_case("word") => Granularity::Word,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("granularity must be \"byte\" or \"word\", not {other:?}"),
            )
                .into_response();
        }
    };

    let d = comparer::diff(&a, &b, granularity);
    let preview = |buf: &[u8], off: usize, len: usize| {
        let end = (off + len.min(PREVIEW)).min(buf.len());
        Some(String::from_utf8_lossy(&buf[off.min(buf.len())..end]).into_owned())
    };
    let ops: Vec<OpView> = d
        .ops
        .iter()
        .take(MAX_OPS)
        .map(|op| match *op {
            Op::Equal { a: sa, b: sb } => OpView {
                kind: "equal",
                a_offset: sa.offset,
                a_len: sa.len,
                b_offset: sb.offset,
                b_len: sb.len,
                text: None,
            },
            Op::Delete { a: sa } => OpView {
                kind: "delete",
                a_offset: sa.offset,
                a_len: sa.len,
                b_offset: 0,
                b_len: 0,
                text: preview(&a, sa.offset, sa.len),
            },
            Op::Insert { b: sb } => OpView {
                kind: "insert",
                a_offset: 0,
                a_len: 0,
                b_offset: sb.offset,
                b_len: sb.len,
                text: preview(&b, sb.offset, sb.len),
            },
        })
        .collect();

    Json(serde_json::json!({
        "granularity": if granularity == Granularity::Byte { "byte" } else { "word" },
        "a_len": a.len(),
        "b_len": b.len(),
        "identical": d.is_identical(),
        "equal_tokens": d.equal_tokens,
        "deleted_tokens": d.deleted_tokens,
        "inserted_tokens": d.inserted_tokens,
        // The edit script hit its budget: the differing region is reported wholesale.
        "truncated": d.truncated,
        "ops_omitted": d.ops.len().saturating_sub(ops.len()),
        "ops": ops,
    }))
    .into_response()
}

// ---- logger ----------------------------------------------------------------------------------

#[derive(Deserialize)]
struct LogQuery {
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    200
}

async fn log_list(
    Extension(t): Extension<Arc<ToolState>>,
    Query(q): Query<LogQuery>,
) -> impl IntoResponse {
    let limit = q.limit.min(2000);
    let entries = match q.tool.as_deref() {
        None | Some("") | Some("all") => t.log.entries(q.offset, limit),
        Some(name) => match Tool::parse(name) {
            Some(tool) => t.log.by_tool(tool, q.offset, limit),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("unknown tool {name:?}; proxy traffic is in /api/history, not here"),
                )
                    .into_response();
            }
        },
    };
    let counts = t.log.counts();
    Json(serde_json::json!({
        "total": t.log.len(),
        "dropped": t.log.dropped(),
        "counts": {
            "repeater": counts[0], "intruder": counts[1],
            "scanner": counts[2], "bcheck": counts[3],
        },
        "entries": entries,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct LogReq {
    tool: String,
    host: String,
    port: u16,
    #[serde(default)]
    tls: bool,
    method: String,
    path: String,
    request_msg_id: u64,
    #[serde(default)]
    response_msg_id: Option<u64>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    response_len: usize,
    #[serde(default)]
    duration_ms: u64,
    #[serde(default)]
    exchange: Option<u64>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

async fn log_record(
    Extension(t): Extension<Arc<ToolState>>,
    Json(req): Json<LogReq>,
) -> impl IntoResponse {
    let Some(tool) = Tool::parse(&req.tool) else {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "unknown tool {:?}; this log is for burpsy's own traffic, and proxy history lives \
                 in /api/history",
                req.tool
            ),
        )
            .into_response();
    };
    let id = t.log.started(Started {
        tool,
        host: req.host,
        port: req.port,
        tls: req.tls,
        method: req.method,
        path: req.path,
        request: MsgId(req.request_msg_id),
        started_ms: now_ms().saturating_sub(req.duration_ms),
        exchange: req.exchange,
        note: req.note,
    });
    match (req.error, req.response_msg_id) {
        (Some(e), _) => t.log.failed(id, e, req.duration_ms),
        (None, Some(r)) => {
            t.log
                .finished(id, MsgId(r), req.status, req.response_len, req.duration_ms)
        }
        (None, None) => {}
    }
    (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response()
}

async fn log_clear(Extension(t): Extension<Arc<ToolState>>) -> impl IntoResponse {
    t.log.clear();
    Json(serde_json::json!({ "cleared": true, "total": t.log.len() }))
}

// ---- organizer -------------------------------------------------------------------------------

async fn org_list(Extension(t): Extension<Arc<ToolState>>) -> impl IntoResponse {
    Json(serde_json::json!({ "items": t.organizer.all() }))
}

#[derive(Deserialize)]
struct OrgAddReq {
    exchange: u64,
    #[serde(default)]
    title: String,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    highlight: Option<String>,
}

async fn org_add(
    State(s): State<AppState>,
    Extension(t): Extension<Arc<ToolState>>,
    Json(req): Json<OrgAddReq>,
) -> impl IntoResponse {
    // Refuse to save a reference to something that is not there: a shortlist of dangling ids is
    // worse than an error at the moment the operator clicked save.
    let Some(ex) = s.store.exchange(req.exchange) else {
        return (
            StatusCode::NOT_FOUND,
            format!("no exchange {}", req.exchange),
        )
            .into_response();
    };
    let title = if req.title.is_empty() {
        format!("{} {}", ex.method, ex.path)
    } else {
        req.title
    };
    let id = t.organizer.add(req.exchange, title, now_ms());
    if let Some(n) = req.note {
        t.organizer.set_note(id, n);
    }
    if let Some(h) = req.highlight {
        t.organizer.set_highlight(id, Highlight::parse(&h));
    }
    (
        StatusCode::CREATED,
        Json(t.organizer.get(id).expect("just added")),
    )
        .into_response()
}

#[derive(Deserialize)]
struct OrgUpdateReq {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    highlight: Option<String>,
}

async fn org_update(
    Extension(t): Extension<Arc<ToolState>>,
    Path(id): Path<u64>,
    Json(req): Json<OrgUpdateReq>,
) -> impl IntoResponse {
    if t.organizer.get(id).is_none() {
        return (StatusCode::NOT_FOUND, format!("no organizer item {id}")).into_response();
    }
    if let Some(v) = req.title {
        t.organizer.set_title(id, v);
    }
    if let Some(v) = req.note {
        t.organizer.set_note(id, v);
    }
    if let Some(v) = req.highlight {
        t.organizer.set_highlight(id, Highlight::parse(&v));
    }
    Json(t.organizer.get(id).expect("checked above")).into_response()
}

async fn org_remove(
    Extension(t): Extension<Arc<ToolState>>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    if t.organizer.remove(id) {
        Json(serde_json::json!({ "removed": id })).into_response()
    } else {
        (StatusCode::NOT_FOUND, format!("no organizer item {id}")).into_response()
    }
}

// ---- match and replace -----------------------------------------------------------------------

async fn rules_get(Extension(t): Extension<Arc<ToolState>>) -> impl IntoResponse {
    let g = t.rules.read();
    Json(serde_json::json!({
        "affects_requests": g.affects(Direction::Request),
        "affects_responses": g.affects(Direction::Response),
        "config": g.spec(),
    }))
}

/// Replace the whole rule set. Every regex is compiled here, once; a bad pattern is a 400 rather
/// than a per-request failure on the proxy hot path.
async fn rules_put(
    Extension(t): Extension<Arc<ToolState>>,
    Json(spec): Json<RuleSetSpec>,
) -> impl IntoResponse {
    match RuleSet::compile(spec) {
        Ok(set) => {
            let n = set.rules().len();
            *t.rules.write() = set;
            Json(serde_json::json!({ "compiled": n })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct RuleTestReq {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    msg_id: Option<u64>,
    /// `"request"` or `"response"`.
    #[serde(default)]
    direction: Option<String>,
    #[serde(default = "localhost")]
    host: String,
    #[serde(default = "port80")]
    port: u16,
    #[serde(default = "root_path")]
    path: String,
    #[serde(default)]
    tls: bool,
}
fn localhost() -> String {
    "localhost".into()
}
fn port80() -> u16 {
    80
}
fn root_path() -> String {
    "/".into()
}

/// Dry-run the rule set against one message. Burp's rule dialog has the same button, and for the
/// same reason: a rule you cannot try before enabling is a rule you enable and then debug in
/// production traffic.
async fn rules_test(
    State(s): State<AppState>,
    Extension(t): Extension<Arc<ToolState>>,
    Json(req): Json<RuleTestReq>,
) -> impl IntoResponse {
    let raw = match source(&s, req.msg_id, req.text.as_deref()) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let direction = match req.direction.as_deref().unwrap_or("request") {
        d if d.eq_ignore_ascii_case("request") => Direction::Request,
        d if d.eq_ignore_ascii_case("response") => Direction::Response,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("direction must be \"request\" or \"response\", not {other:?}"),
            )
                .into_response();
        }
    };
    let ctx = Ctx {
        host: &req.host,
        port: req.port,
        path: &req.path,
        tls: req.tls,
    };
    let out = t.rules.read().apply(direction, &ctx, &raw);
    Json(serde_json::json!({
        "changed": out.is_some(),
        "output": BytesView::new(out.as_deref().unwrap_or(&raw)),
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{Exchange, Scope, TrafficStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Stand the real router up on a real socket. Anything less would not prove the `Extension`
    /// layer survives `routes::all()` and `with_state`, which is a run-time property, not a
    /// compile-time one.
    async fn serve() -> (String, Arc<TrafficStore>) {
        let store = TrafficStore::new();
        let state = AppState {
            store: store.clone(),
            ca_pem: None,
            scope: Arc::new(Scope::allow_everything()),
            findings: None,
            audit: None,
            export: None,
            intercept: None,
        };
        let app = Router::new().merge(crate::routes::all()).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr.to_string(), store)
    }

    /// Minimal HTTP/1.1 client so the tests need no dependency, matching `lib.rs`.
    async fn call(addr: &str, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
        if let Some(b) = body {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        if let Some(b) = body {
            req.push_str(b);
        }
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
            .map(|(_, b)| b)
            .unwrap_or("")
            .to_string();
        (status, body)
    }

    async fn post(addr: &str, path: &str, body: &str) -> (u16, String) {
        call(addr, "POST", path, Some(body)).await
    }

    #[tokio::test]
    async fn the_decoder_endpoints_are_reachable_and_round_trip() {
        let (addr, _) = serve().await;

        let (code, body) = post(&addr, "/api/tools/decode", r#"{"input":"a%20b&c=%3C"}"#).await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains(r#""mode":"smart""#), "{body}");
        assert!(body.contains(r#"a b&c=<"#), "{body}");
        // Two separate escape runs with plain text between them, so two regions fired — not one
        // whole-input guess. That is the per-position scan showing through the API.
        assert!(body.contains(r#""layers":["url","url"]"#), "{body}");
        assert_eq!(
            body.matches(r#""layer":null"#).count(),
            2,
            "plain regions kept: {body}"
        );
        // The ladder is exposed, which is the recoverability contract.
        assert!(body.contains("\"passes\""), "{body}");
        assert!(body.contains("\"why\""), "{body}");

        let (code, body) = post(
            &addr,
            "/api/tools/encode",
            r#"{"input":"a b","encoding":"url"}"#,
        )
        .await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("a%20b"), "{body}");

        // Base64 is not guessed unless asked, and is when asked.
        let (_, body) = post(
            &addr,
            "/api/tools/decode",
            r#"{"input":"SGVsbG8sIHdvcmxk"}"#,
        )
        .await;
        assert!(body.contains(r#""layers":[]"#), "{body}");
        let (_, body) = post(
            &addr,
            "/api/tools/decode",
            r#"{"input":"SGVsbG8sIHdvcmxk","guess_alphabets":true}"#,
        )
        .await;
        assert!(body.contains("Hello, world"), "{body}");

        let (code, body) = post(
            &addr,
            "/api/tools/decode",
            r#"{"input":"x","encoding":"rot13"}"#,
        )
        .await;
        assert_eq!(code, 400, "{body}");
    }

    #[tokio::test]
    async fn the_decode_endpoint_reports_truncated_for_a_broken_deflate_body() {
        // QA finding 4's route-level half: `truncated` is threaded from `decoder::decode` into
        // `BytesView`, but nothing asserted it actually reaches the wire. A body cut deep enough
        // to break mid-stream, decoded explicitly as `deflate`, must come back with
        // `"truncated":true` rather than a clean 200 that looks whole.
        let (addr, store) = serve().await;
        let body = b"the quick brown fox jumps over the lazy dog, repeatedly, for good measure. "
            .repeat(200);
        let full = decoder::encode(Layer::Deflate, &body).unwrap();
        let cut = full.len() * 2 / 3;
        let msg = store.put(
            bytes::Bytes::copy_from_slice(&full[..cut]),
            Direction::Response,
        );
        let (code, resp) = post(
            &addr,
            "/api/tools/decode",
            &format!(r#"{{"msg_id":{},"encoding":"deflate"}}"#, msg.0),
        )
        .await;
        assert_eq!(code, 200, "{resp}");
        assert!(resp.contains(r#""truncated":true"#), "{resp}");

        // A whole body decodes with `truncated` explicitly `false`, not merely absent — the
        // client cannot distinguish "complete" from "field missing" otherwise.
        let msg_whole = store.put(bytes::Bytes::copy_from_slice(&full), Direction::Response);
        let (code, resp) = post(
            &addr,
            "/api/tools/decode",
            &format!(r#"{{"msg_id":{},"encoding":"deflate"}}"#, msg_whole.0),
        )
        .await;
        assert_eq!(code, 200, "{resp}");
        assert!(resp.contains(r#""truncated":false"#), "{resp}");
    }

    #[tokio::test]
    async fn the_comparer_endpoint_reports_a_single_word_change() {
        let (addr, _) = serve().await;
        let (code, body) = post(
            &addr,
            "/api/tools/compare",
            r#"{"a":{"text":"the quick brown fox"},"b":{"text":"the quick red fox"}}"#,
        )
        .await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains(r#""deleted_tokens":1"#), "{body}");
        assert!(body.contains(r#""inserted_tokens":1"#), "{body}");
        assert!(body.contains(r#""identical":false"#), "{body}");
        assert!(body.contains("brown") && body.contains("red"), "{body}");
    }

    #[tokio::test]
    async fn the_comparer_reads_stored_messages_by_id() {
        let (addr, store) = serve().await;
        let a = store.put(
            bytes::Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\nid=aaa"),
            Direction::Response,
        );
        let b = store.put(
            bytes::Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\nid=bbb"),
            Direction::Response,
        );
        let (code, body) = post(
            &addr,
            "/api/tools/compare",
            &format!(
                r#"{{"a":{{"msg_id":{}}},"b":{{"msg_id":{}}},"granularity":"byte"}}"#,
                a.0, b.0
            ),
        )
        .await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains(r#""deleted_tokens":3"#), "{body}");
        assert!(body.contains(r#""granularity":"byte""#), "{body}");

        let (code, body) = post(
            &addr,
            "/api/tools/compare",
            r#"{"a":{"msg_id":999},"b":{"text":"x"}}"#,
        )
        .await;
        assert_eq!(code, 404, "{body}");
    }

    #[tokio::test]
    async fn the_tool_log_records_reads_back_and_refuses_proxy_traffic() {
        let (addr, _) = serve().await;
        let (code, body) = post(
            &addr,
            "/api/tools/log",
            r#"{"tool":"repeater","host":"t.test","port":443,"tls":true,"method":"POST",
                "path":"/login","request_msg_id":1,"response_msg_id":2,"status":302,
                "response_len":99,"duration_ms":12}"#,
        )
        .await;
        assert_eq!(code, 201, "{body}");

        let (code, body) = call(&addr, "GET", "/api/tools/log", None).await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains(r#""path":"/login""#), "{body}");
        assert!(body.contains(r#""status":302"#), "{body}");
        assert!(body.contains(r#""repeater":1"#), "{body}");

        let (code, body) = call(&addr, "GET", "/api/tools/log?tool=intruder", None).await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains(r#""entries":[]"#), "{body}");

        // The whole point of a separate log: browser traffic cannot be filed here.
        let (code, body) = call(&addr, "GET", "/api/tools/log?tool=proxy", None).await;
        assert_eq!(code, 400, "{body}");
        assert!(body.contains("/api/history"), "{body}");

        let (code, _) = call(&addr, "DELETE", "/api/tools/log", None).await;
        assert_eq!(code, 200);
        let (_, body) = call(&addr, "GET", "/api/tools/log", None).await;
        assert!(body.contains(r#""total":0"#), "{body}");
    }

    #[tokio::test]
    async fn the_organizer_saves_annotates_and_removes_a_real_exchange() {
        let (addr, store) = serve().await;
        let req = store.put(
            bytes::Bytes::from_static(b"GET /admin HTTP/1.1\r\nHost: t\r\n\r\n"),
            Direction::Request,
        );
        let ex = store.add_exchange(Exchange {
            related: Vec::new(),
            protocol: burpsy_core::Protocol::Http1,
            id: 0,
            request: req,
            response: None,
            host: "t".into(),
            port: 80,
            tls: false,
            method: "GET".into(),
            path: "/admin".into(),
            status: None,
            response_len: 0,
            started_ms: 0,
            duration_ms: 0,
            notes: None,
        });

        let (code, body) = post(
            &addr,
            "/api/tools/organizer",
            &format!(r#"{{"exchange":{ex}}}"#),
        )
        .await;
        assert_eq!(code, 201, "{body}");
        assert!(
            body.contains(r#""title":"GET /admin""#),
            "title defaulted: {body}"
        );
        let id: u64 = body
            .split(r#""id":"#)
            .nth(1)
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse().ok())
            .unwrap();

        let (code, body) = post(
            &addr,
            &format!("/api/tools/organizer/{id}"),
            r#"{"note":"auth bypass candidate","highlight":"red"}"#,
        )
        .await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("auth bypass candidate"), "{body}");
        assert!(body.contains(r#""highlight":"red""#), "{body}");

        let (_, body) = call(&addr, "GET", "/api/tools/organizer", None).await;
        assert!(body.contains("auth bypass candidate"), "{body}");

        // A dangling reference is refused at save time.
        let (code, _) = post(&addr, "/api/tools/organizer", r#"{"exchange":9999}"#).await;
        assert_eq!(code, 404);

        let (code, _) = call(&addr, "DELETE", &format!("/api/tools/organizer/{id}"), None).await;
        assert_eq!(code, 200);
        let (_, body) = call(&addr, "GET", "/api/tools/organizer", None).await;
        assert!(body.contains(r#""items":[]"#), "{body}");
    }

    #[tokio::test]
    async fn match_and_replace_rules_compile_at_put_time_and_can_be_dry_run() {
        let (addr, _) = serve().await;

        // A bad pattern never reaches the hot path.
        let (code, body) = call(
            &addr,
            "PUT",
            "/api/tools/rules",
            Some(r#"{"rules":[{"rule_type":"request_header","string_match":"([bad"}]}"#),
        )
        .await;
        assert_eq!(code, 400, "{body}");

        let (code, body) = call(
            &addr,
            "PUT",
            "/api/tools/rules",
            Some(
                r#"{"rules":[
                    {"rule_type":"request_header","string_match":"^User-Agent.*$",
                     "string_replace":"User-Agent: burpsy","comment":"Emulate burpsy"},
                    {"category":"literal","rule_type":"request_header",
                     "string_replace":"X-Probe: 1"}
                ]}"#,
            ),
        )
        .await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains(r#""compiled":2"#), "{body}");

        let (code, body) = call(&addr, "GET", "/api/tools/rules", None).await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains(r#""affects_requests":true"#), "{body}");
        assert!(body.contains(r#""affects_responses":false"#), "{body}");
        assert!(body.contains("Emulate burpsy"), "{body}");

        let (code, body) = post(
            &addr,
            "/api/tools/rules/test",
            r#"{"text":"GET / HTTP/1.1\r\nHost: t\r\nUser-Agent: curl/8\r\n\r\n"}"#,
        )
        .await;
        assert_eq!(code, 200, "{body}");
        assert!(body.contains(r#""changed":true"#), "{body}");
        assert!(body.contains("User-Agent: burpsy"), "{body}");
        assert!(body.contains("X-Probe: 1"), "{body}");

        // A response is untouched by request-only rules.
        let (_, body) = post(
            &addr,
            "/api/tools/rules/test",
            r#"{"text":"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n","direction":"response"}"#,
        )
        .await;
        assert!(body.contains(r#""changed":false"#), "{body}");
    }
}
