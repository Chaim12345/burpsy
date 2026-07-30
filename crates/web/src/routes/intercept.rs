//! Interception: hold, edit, forward, drop — and the condition lists that decide what gets held.
//!
//! The queue itself lives in `burpsy_proxy::intercept` — it has to, because the thing being held is
//! a proxy connection task, and so does condition matching, because it runs on that task. This module
//! is only the HTTP surface over both, so the API layer carries no interception logic of its own
//! beyond one decision: whether to recompute `Content-Length` on an edited message.
//!
//! # Why editing defaults to fixing `Content-Length`
//!
//! An operator who adds a word to a JSON body and forwards it will otherwise send a request whose
//! declared length no longer matches its body: the origin either truncates the body at the stale
//! length or blocks waiting for bytes that never arrive. Both look like the tool broke. So a forward
//! with new bytes re-derives the length through `burpsy_core::edit::RequestEdit`, which is the same
//! path Repeater and the BCheck sender use, and `fix_content_length: false` turns it off for the
//! case where the malformed framing *is* the test.
//!
//! An edited **response** needs the same fix for the same reason, aimed at the browser instead of the
//! origin, but it cannot use the same code: `RequestEdit` parses a request line and re-emits one, so
//! feeding it a status line loses the response. [`fix_response_length`] does the narrower thing
//! instead — see its own docs for why narrower is right here.
//!
//! # The rule lists are replaced whole, and compiled here
//!
//! `PUT` takes an entire list rather than offering per-rule edits. Ordering and "does anything match"
//! are properties of the list, not of a rule, so an operator reasoning about a half-applied list is
//! reasoning about something that never ran. Every pattern compiles inside the `PUT`, which is what
//! makes a bad regex a `400` here rather than a failure on the proxy's hot path later.

use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use burpsy_core::Direction;
use burpsy_core::edit::RequestEdit;
use burpsy_proxy::intercept::{InterceptRules, InterceptRulesSpec, Interceptor};
use bytes::Bytes;
use serde::Deserialize;
use std::sync::Arc;

/// Shared state for held requests. Owned here rather than in `AppState` so the interception
/// feature can evolve its own storage without touching the shared struct.
#[derive(Debug)]
pub struct InterceptState {
    /// The same `Arc` the proxy holds. Nothing else connects an operator's decision to the
    /// connection task parked on it.
    pub interceptor: Arc<Interceptor>,
}

impl InterceptState {
    pub fn new(interceptor: Arc<Interceptor>) -> Arc<Self> {
        Arc::new(Self { interceptor })
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/intercept", get(status))
        .route("/api/intercept/enable", post(enable))
        .route(
            "/api/intercept/rules/requests",
            get(request_rules_get).put(request_rules_put),
        )
        .route(
            "/api/intercept/rules/responses",
            get(response_rules_get).put(response_rules_put),
        )
        // No ambiguity with `rules/{requests,responses}` above: the last segment differs, so `{id}`
        // is never asked to swallow the literal `rules`.
        .route("/api/intercept/{id}/forward", post(forward))
        .route("/api/intercept/{id}/drop", post(drop_held))
}

/// Same shape as `/api/issues` and `/api/audit/{id}`: a feature that is not wired up says so in a
/// 200 rather than looking like a broken endpoint.
fn unwired() -> axum::response::Response {
    Json(serde_json::json!({
        "enabled": false,
        "wired": false,
        "hint": "interception is not attached to this proxy; \
                 build the proxy with ProxyConfig::with_interceptor and share the same Arc",
        "held": [],
    }))
    .into_response()
}

/// `GET /api/intercept` — is interception on, and what is waiting.
///
/// The two `holds_every_…` flags are here rather than left to the rule endpoints because the
/// combination is what an operator actually needs to see: "interception is on" and "nothing is being
/// held" are both true at once whenever a list is inactive or every rule in it is unchecked, and that
/// pairing is otherwise indistinguishable from a broken proxy.
async fn status(State(s): State<AppState>) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    let held = st.interceptor.list();
    let on = st.interceptor.is_enabled();
    let (req, resp) = (
        st.interceptor.request_rules(),
        st.interceptor.response_rules(),
    );
    Json(serde_json::json!({
        "enabled": on,
        "wired": true,
        "pending": held.len(),
        "held": held,
        "holds_every_request": on && req.is_unconditional(),
        "holds_every_response": on && resp.is_unconditional(),
        "request_rules_active": req.is_active(),
        "response_rules_active": resp.is_active(),
    }))
    .into_response()
}

/// `GET /api/intercept/rules/requests` — the request condition list, in order.
async fn request_rules_get(State(s): State<AppState>) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    rules_body(&st.interceptor.request_rules())
}

/// `GET /api/intercept/rules/responses` — the response condition list, in order.
async fn response_rules_get(State(s): State<AppState>) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    rules_body(&st.interceptor.response_rules())
}

/// `PUT /api/intercept/rules/requests` — replace the request condition list.
async fn request_rules_put(
    State(s): State<AppState>,
    Json(spec): Json<InterceptRulesSpec>,
) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    match InterceptRules::compile(spec) {
        Ok(rules) => {
            let body = rules_body(&rules);
            st.interceptor.set_request_rules(rules);
            body
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// `PUT /api/intercept/rules/responses` — replace the response condition list.
///
/// This is how response interception is switched on at all: the list ships inactive, because burpsy
/// has never held a response and turning the master switch on must not silently start.
async fn response_rules_put(
    State(s): State<AppState>,
    Json(spec): Json<InterceptRulesSpec>,
) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    match InterceptRules::compile(spec) {
        Ok(rules) => {
            let body = rules_body(&rules);
            st.interceptor.set_response_rules(rules);
            body
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// One shape for both the `GET` and the `PUT` answer, so a client can read back what it just wrote
/// without a second request.
///
/// `unconditional` is reported rather than left to be inferred: a list of five rules with every box
/// unchecked looks selective and holds everything, and that is exactly the state an operator needs
/// told rather than left to work out.
fn rules_body(rules: &InterceptRules) -> axum::response::Response {
    Json(serde_json::json!({
        "active": rules.is_active(),
        "unconditional": rules.is_unconditional(),
        "count": rules.rules().len(),
        "rules": rules.rules(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct Enable {
    enabled: bool,
}

/// `POST /api/intercept/enable` — turn holding on or off.
///
/// Reports how many requests were released, because switching interception off is also the
/// operator's escape hatch when they have queued more than they meant to.
async fn enable(State(s): State<AppState>, Json(req): Json<Enable>) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    let released = st.interceptor.set_enabled(req.enabled);
    Json(serde_json::json!({
        "enabled": st.interceptor.is_enabled(),
        "released": released,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct Forward {
    /// Replacement bytes. Absent means forward exactly what was captured.
    #[serde(default)]
    raw: Option<String>,
    #[serde(default = "yes")]
    fix_content_length: bool,
}
fn yes() -> bool {
    true
}

/// `POST /api/intercept/{id}/forward` — release one held message, optionally rewritten.
async fn forward(
    State(s): State<AppState>,
    Path(id): Path<u64>,
    body: Option<Json<Forward>>,
) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    let Json(req) = body.unwrap_or_default();
    // Read while the entry is still held: `forward` below removes it, and a response edited as a
    // request loses its status line.
    let direction = st.interceptor.direction_of(id);
    let edited = req.raw.map(|raw| {
        // A textarea gives back bare LFs; HTTP wants CRLF. Normalise the same way Repeater does.
        let raw = raw.replace("\r\n", "\n").replace('\n', "\r\n");
        if !req.fix_content_length {
            return Bytes::from(raw.into_bytes());
        }
        if direction == Some(Direction::Response) {
            return Bytes::from(fix_response_length(raw.as_bytes()));
        }
        if let Ok(r) = RequestEdit::from_raw(raw.as_bytes()) {
            return Bytes::from(r.to_raw());
        }
        // Unparsable after an edit is the operator's business, not ours to repair: send it as-is.
        Bytes::from(raw.into_bytes())
    });

    let sent_bytes = edited.as_ref().map(|b| b.len());
    if st.interceptor.forward(id, edited) {
        Json(serde_json::json!({ "forwarded": true, "id": id, "sent_bytes": sent_bytes }))
            .into_response()
    } else {
        gone(id)
    }
}

#[derive(Deserialize, Default)]
struct DropReq {
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /api/intercept/{id}/drop` — refuse to forward. The client gets a 403, not a dead socket.
async fn drop_held(
    State(s): State<AppState>,
    Path(id): Path<u64>,
    body: Option<Json<DropReq>>,
) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    let Json(req) = body.unwrap_or_default();
    let reason = req
        .reason
        .unwrap_or_else(|| "dropped from the intercept queue".to_string());
    if st.interceptor.drop_request(id, reason.clone()) {
        Json(serde_json::json!({ "dropped": true, "id": id, "reason": reason })).into_response()
    } else {
        gone(id)
    }
}

/// Recompute an edited response's `Content-Length`.
///
/// Deliberately narrower than a reparse-and-re-emit: it rewrites the one header the edit invalidated
/// and leaves every other byte where the operator put it. `RequestEdit` cannot be reused — it parses
/// a request line and emits a request line, so a status line does not survive the trip — and a
/// response-shaped equivalent that normalised header order and casing would silently undo edits an
/// operator made on purpose.
///
/// Three cases are left alone rather than "fixed":
///
/// * **`Transfer-Encoding: chunked`.** Those body bytes carry their own framing. A `Content-Length`
///   beside it is the CL/TE ambiguity, which is a thing to test, not a thing to add by accident.
/// * **No header block at all.** Nothing to anchor the rewrite on; send what was written.
/// * **An empty body with no existing length header.** A `204`, a `304` and a `HEAD` answer are
///   correct without one, and inventing `Content-Length: 0` changes how the client frames the reply.
///
/// A response carrying two length headers keeps the first and loses the rest, because that is what
/// having *a* correct length means. When the duplication is the test, `fix_content_length: false` is
/// the switch that says so.
fn fix_response_length(raw: &[u8]) -> Vec<u8> {
    // Interim `1xx` heads are complete at their own terminator, so anchoring on the *first* one would
    // write the length into a `103 Early Hints` and declare the real response to be its body. They are
    // bytes the client receives, so they are kept — just not written into.
    let interim = burpsy_proxy::final_response_start(raw);
    let (prefix, raw) = raw.split_at(interim);
    let Some(i) = find(raw, b"\r\n\r\n") else {
        return [prefix, raw].concat();
    };
    let (head, body) = (&raw[..i], &raw[i + 4..]);
    let lower = head.to_ascii_lowercase();
    if let Some(te) = find(&lower, b"transfer-encoding:") {
        let line_end = lower[te..]
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .unwrap_or(lower.len() - te);
        if find(&lower[te..te + line_end], b"chunked").is_some() {
            return [prefix, raw].concat();
        }
    }

    let mut out = Vec::with_capacity(prefix.len() + raw.len() + 24);
    out.extend_from_slice(prefix);
    let mut written = false;
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.to_ascii_lowercase().starts_with(b"content-length:") {
            if written {
                continue;
            }
            written = true;
            out.extend_from_slice(format!("Content-Length: {}", body.len()).as_bytes());
        } else {
            out.extend_from_slice(line);
        }
        out.extend_from_slice(b"\r\n");
    }
    if !written && !body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A held message that is no longer held — already resolved, or its client hung up. Saying so beats
/// a silent success, which would leave the operator believing they forwarded something.
fn gone(id: u64) -> axum::response::Response {
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "forwarded": false,
            "dropped": false,
            "id": id,
            "reason": "no such held request: it was already resolved, or its client disconnected",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{SharedScope, TrafficStore};
    use burpsy_proxy::{HeldMeta, Verdict};
    use std::time::Duration;

    fn state(interceptor: Arc<Interceptor>) -> AppState {
        AppState {
            store: TrafficStore::new(),
            ca_pem: None,
            scope: SharedScope::allow_everything(),
            findings: None,
            audit: None,
            export: None,
            intercept: Some(InterceptState::new(interceptor)),
            session: None,
            tool_log: None,
            live_audit: None,
        }
    }

    /// Serve the interception routes and return where to reach them.
    async fn serve(st: AppState) -> String {
        let app = routes().with_state(st);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await });
        format!("127.0.0.1:{}", addr.port())
    }

    async fn call(addr: &str, method: &str, path: &str, body: &str) -> String {
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
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn meta() -> HeldMeta {
        HeldMeta {
            host: "a.test".into(),
            port: 80,
            tls: false,
            method: "POST".into(),
            path: "/submit".into(),
        }
    }

    async fn wait_for_pending(ic: &Interceptor, n: usize) {
        for _ in 0..3000 {
            if ic.pending() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("timed out waiting for {n} held request(s)");
    }

    #[tokio::test]
    async fn an_unwired_interceptor_reports_itself_instead_of_erroring() {
        let mut st = state(Interceptor::new());
        st.intercept = None;
        let addr = serve(st).await;
        let body = call(&addr, "GET", "/api/intercept", "").await;
        assert!(
            body.starts_with("HTTP/1.1 200"),
            "must not 404 or 500: {body}"
        );
        assert!(body.contains("\"enabled\":false"), "{body}");
        assert!(body.contains("\"wired\":false"), "{body}");
    }

    #[tokio::test]
    async fn the_queue_is_visible_over_http_and_a_forward_releases_it() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        let held = {
            let ic = ic.clone();
            tokio::spawn(async move {
                ic.hold(
                    meta(),
                    Bytes::from_static(b"POST /submit HTTP/1.1\r\nHost: a.test\r\n\r\n"),
                )
                .await
            })
        };
        wait_for_pending(&ic, 1).await;

        let body = call(&addr, "GET", "/api/intercept", "").await;
        assert!(body.contains("\"pending\":1"), "{body}");
        assert!(body.contains("\"path\":\"/submit\""), "{body}");

        let id = ic.list()[0].id;
        let body = call(&addr, "POST", &format!("/api/intercept/{id}/forward"), "{}").await;
        assert!(body.contains("\"forwarded\":true"), "{body}");
        assert!(matches!(held.await.unwrap(), Verdict::Forward(_)));
    }

    #[tokio::test]
    async fn an_edited_body_gets_a_content_length_that_matches_it() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        let held = {
            let ic = ic.clone();
            tokio::spawn(async move {
                ic.hold(
                    meta(),
                    Bytes::from_static(
                        b"POST /submit HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nhi",
                    ),
                )
                .await
            })
        };
        wait_for_pending(&ic, 1).await;
        let id = ic.list()[0].id;

        // The operator lengthens the body and leaves the stale Content-Length in place.
        let edited = "POST /submit HTTP/1.1\\nHost: a.test\\nContent-Length: 2\\n\\nhi there world";
        let body = call(
            &addr,
            "POST",
            &format!("/api/intercept/{id}/forward"),
            &format!("{{\"raw\":\"{edited}\"}}"),
        )
        .await;
        assert!(body.contains("\"forwarded\":true"), "{body}");

        match held.await.unwrap() {
            Verdict::Forward(b) => {
                let s = String::from_utf8_lossy(&b);
                assert!(
                    s.contains("Content-Length: 14"),
                    "stale length not fixed: {s:?}"
                );
                assert!(s.ends_with("hi there world"), "{s:?}");
            }
            Verdict::Drop(r) => panic!("expected forward, got drop: {r}"),
        }
    }

    #[tokio::test]
    async fn opting_out_of_the_length_fix_sends_the_bytes_as_written() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"x")).await })
        };
        wait_for_pending(&ic, 1).await;
        let id = ic.list()[0].id;

        let edited = "POST /submit HTTP/1.1\\nHost: a.test\\nContent-Length: 2\\n\\nhi there world";
        call(
            &addr,
            "POST",
            &format!("/api/intercept/{id}/forward"),
            &format!("{{\"raw\":\"{edited}\",\"fix_content_length\":false}}"),
        )
        .await;

        match held.await.unwrap() {
            Verdict::Forward(b) => {
                let s = String::from_utf8_lossy(&b);
                assert!(
                    s.contains("Content-Length: 2"),
                    "deliberately broken framing must survive: {s:?}"
                );
            }
            Verdict::Drop(r) => panic!("expected forward, got drop: {r}"),
        }
    }

    #[tokio::test]
    async fn dropping_carries_the_reason_and_resolving_a_stale_id_reports_404() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"x")).await })
        };
        wait_for_pending(&ic, 1).await;
        let id = ic.list()[0].id;

        let body = call(
            &addr,
            "POST",
            &format!("/api/intercept/{id}/drop"),
            "{\"reason\":\"not authorised\"}",
        )
        .await;
        assert!(body.contains("\"dropped\":true"), "{body}");
        match held.await.unwrap() {
            Verdict::Drop(r) => assert_eq!(r, "not authorised"),
            Verdict::Forward(_) => panic!("expected drop"),
        }

        // The same id a second time is gone, and the API says so rather than claiming success.
        let body = call(&addr, "POST", &format!("/api/intercept/{id}/forward"), "{}").await;
        assert!(body.starts_with("HTTP/1.1 404"), "{body}");
        assert!(body.contains("\"forwarded\":false"), "{body}");
    }

    // ---- condition lists ----------------------------------------------------------------------

    #[tokio::test]
    async fn the_default_lists_are_reported_as_blanket_requests_and_inactive_responses() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        let body = call(&addr, "GET", "/api/intercept/rules/requests", "").await;
        assert!(body.contains("\"active\":true"), "{body}");
        assert!(body.contains("\"unconditional\":true"), "{body}");
        assert!(body.contains("\"count\":0"), "{body}");

        let body = call(&addr, "GET", "/api/intercept/rules/responses", "").await;
        assert!(
            body.contains("\"active\":false"),
            "responses must ship off: {body}"
        );
        assert!(body.contains("\"unconditional\":false"), "{body}");

        // The combination is what the status endpoint has to make legible.
        let body = call(&addr, "GET", "/api/intercept", "").await;
        assert!(body.contains("\"holds_every_request\":true"), "{body}");
        assert!(body.contains("\"holds_every_response\":false"), "{body}");
    }

    #[tokio::test]
    async fn a_put_rule_list_is_read_back_and_narrows_what_gets_held() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        let body = call(
            &addr,
            "PUT",
            "/api/intercept/rules/requests",
            "{\"active\":true,\"rules\":[{\"field\":\"host\",\"string_match\":\"^only\\\\.example$\"}]}",
        )
        .await;
        assert!(body.contains("\"count\":1"), "{body}");
        assert!(
            body.contains("\"unconditional\":false"),
            "one enabled rule means the list is selective: {body}"
        );

        let body = call(&addr, "GET", "/api/intercept/rules/requests", "").await;
        assert!(body.contains("\"field\":\"host\""), "{body}");
        assert!(body.contains("\"enabled\":true"), "{body}");
        assert!(body.contains("\"category\":\"regex\""), "{body}");

        // `meta()` is a.test, which the rule does not name, so nothing is held any more.
        let v = ic.hold(meta(), Bytes::from_static(b"REQ")).await;
        assert!(matches!(v, Verdict::Forward(_)), "should not have held");
        assert_eq!(ic.pending(), 0);
    }

    #[tokio::test]
    async fn a_bad_pattern_is_a_400_and_leaves_the_running_list_alone() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        let body = call(
            &addr,
            "PUT",
            "/api/intercept/rules/requests",
            "{\"rules\":[{\"field\":\"path\",\"string_match\":\"(unclosed\"}]}",
        )
        .await;
        assert!(body.starts_with("HTTP/1.1 400"), "{body}");
        assert!(body.contains("intercept rule"), "{body}");
        assert!(
            ic.request_rules().is_unconditional(),
            "a rejected PUT must not half-apply"
        );
    }

    #[tokio::test]
    async fn a_put_that_omits_active_cannot_switch_blanket_response_holding_on_by_accident() {
        // `{"rules": []}` is what a client sends when the last response rule is deleted. If `active`
        // defaulted to true, that would mean "hold every response" — quietly undoing, from outside,
        // the inactive-by-default guarantee that stops the master switch holding responses at all.
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        for body in ["{}", "{\"rules\":[]}"] {
            let out = call(&addr, "PUT", "/api/intercept/rules/responses", body).await;
            assert!(out.contains("\"active\":false"), "{body} -> {out}");
            assert!(out.contains("\"unconditional\":false"), "{body} -> {out}");
        }
        let resp = Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        assert!(matches!(
            ic.hold_response(meta(), resp).await,
            Verdict::Forward(_)
        ));
        assert_eq!(ic.pending(), 0);

        // Blanket stays reachable, but only by saying so out loud.
        let out = call(
            &addr,
            "PUT",
            "/api/intercept/rules/responses",
            "{\"active\":true,\"rules\":[]}",
        )
        .await;
        assert!(out.contains("\"unconditional\":true"), "{out}");
    }

    #[tokio::test]
    async fn unchecking_the_last_condition_holds_nothing_rather_than_everything() {
        // The other half of the same hazard: a list with rows in it is never blanket, however many of
        // those rows are unchecked. Otherwise unticking one box starts holding every response.
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        let out = call(
            &addr,
            "PUT",
            "/api/intercept/rules/responses",
            "{\"active\":true,\"rules\":[{\"field\":\"status_code\",\"string_match\":\"^2..$\",\"enabled\":false}]}",
        )
        .await;
        assert!(out.contains("\"count\":1"), "{out}");
        assert!(
            out.contains("\"unconditional\":false"),
            "rows present means never blanket: {out}"
        );

        let resp = Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        assert!(matches!(
            ic.hold_response(meta(), resp).await,
            Verdict::Forward(_)
        ));
        assert_eq!(ic.pending(), 0);
    }

    #[tokio::test]
    async fn switching_the_response_list_on_over_http_is_what_starts_holding_responses() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        // Off by default: the master switch alone holds no response.
        let resp = Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        assert!(matches!(
            ic.hold_response(meta(), resp.clone()).await,
            Verdict::Forward(_)
        ));

        let body = call(
            &addr,
            "PUT",
            "/api/intercept/rules/responses",
            "{\"active\":true,\"rules\":[{\"field\":\"status_code\",\"string_match\":\"^2..$\"}]}",
        )
        .await;
        assert!(body.contains("\"active\":true"), "{body}");
        assert!(body.contains("\"count\":1"), "{body}");

        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold_response(meta(), resp).await })
        };
        wait_for_pending(&ic, 1).await;

        let body = call(&addr, "GET", "/api/intercept", "").await;
        assert!(body.contains("\"direction\":\"response\""), "{body}");
        assert!(body.contains("\"status\":200"), "{body}");

        let id = ic.list()[0].id;
        let edited = "HTTP/1.1 200 OK\\nContent-Length: 2\\n\\nhi there world";
        let body = call(
            &addr,
            "POST",
            &format!("/api/intercept/{id}/forward"),
            &format!("{{\"raw\":\"{edited}\"}}"),
        )
        .await;
        assert!(body.contains("\"forwarded\":true"), "{body}");

        match held.await.unwrap() {
            Verdict::Forward(b) => {
                let s = String::from_utf8_lossy(&b);
                assert!(
                    s.starts_with("HTTP/1.1 200 OK"),
                    "the status line must survive an edit: {s:?}"
                );
                assert!(
                    s.contains("Content-Length: 14"),
                    "a response edit needs its length fixed too: {s:?}"
                );
                assert!(s.ends_with("hi there world"), "{s:?}");
            }
            Verdict::Drop(r) => panic!("expected forward, got drop: {r}"),
        }
    }

    #[test]
    fn the_response_length_fix_touches_the_length_and_nothing_else() {
        let out = String::from_utf8(fix_response_length(
            b"HTTP/1.1 200 OK\r\nx-odd-Casing: kept\r\nContent-Length: 2\r\n\r\nhi there",
        ))
        .unwrap();
        assert_eq!(
            out,
            "HTTP/1.1 200 OK\r\nx-odd-Casing: kept\r\nContent-Length: 8\r\n\r\nhi there",
            "header order and casing are the operator's, not ours"
        );

        // Absent length, non-empty body: add one, because a browser needs to know where to stop.
        let out = String::from_utf8(fix_response_length(
            b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody",
        ))
        .unwrap();
        assert!(out.contains("Content-Length: 4"), "{out:?}");

        // Absent length, empty body: leave it alone. A 304 is correct without one.
        let out =
            String::from_utf8(fix_response_length(b"HTTP/1.1 304 Not Modified\r\nX: y\r\n\r\n"))
                .unwrap();
        assert!(!out.contains("Content-Length"), "{out:?}");

        // Chunked: the body carries its own framing, and adding a length beside it is the CL/TE
        // ambiguity rather than a repair.
        let chunked: &[u8] =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n";
        assert_eq!(fix_response_length(chunked), chunked.to_vec());

        // Two lengths collapse to one correct one.
        let out = String::from_utf8(fix_response_length(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 9\r\n\r\nhi",
        ))
        .unwrap();
        assert_eq!(out.matches("Content-Length").count(), 1, "{out:?}");
        assert!(out.contains("Content-Length: 2"), "{out:?}");

        // An interim 1xx head is kept and never written into: anchoring on the first `\r\n\r\n` would
        // put the length in the 103's headers and declare the real response to be its body.
        let out = String::from_utf8(fix_response_length(
            b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n\
              HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nhello",
        ))
        .unwrap();
        assert!(out.starts_with("HTTP/1.1 103 Early Hints"), "{out:?}");
        assert_eq!(out.matches("Content-Length").count(), 1, "{out:?}");
        assert!(out.contains("Content-Length: 5"), "{out:?}");
        assert!(out.ends_with("hello"), "{out:?}");
    }

    #[tokio::test]
    async fn an_edited_response_can_keep_its_deliberately_broken_framing() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        ic.set_response_rules(InterceptRules::unconditional());
        let addr = serve(state(ic.clone())).await;

        let held = {
            let ic = ic.clone();
            tokio::spawn(async move {
                ic.hold_response(meta(), Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n"))
                    .await
            })
        };
        wait_for_pending(&ic, 1).await;
        let id = ic.list()[0].id;

        let edited = "HTTP/1.1 200 OK\\nContent-Length: 2\\n\\nhi there world";
        call(
            &addr,
            "POST",
            &format!("/api/intercept/{id}/forward"),
            &format!("{{\"raw\":\"{edited}\",\"fix_content_length\":false}}"),
        )
        .await;

        match held.await.unwrap() {
            Verdict::Forward(b) => {
                let s = String::from_utf8_lossy(&b);
                assert!(
                    s.contains("Content-Length: 2"),
                    "a response smuggling probe must survive: {s:?}"
                );
            }
            Verdict::Drop(r) => panic!("expected forward, got drop: {r}"),
        }
    }

    #[tokio::test]
    async fn the_rule_endpoints_report_an_unwired_interceptor_like_every_other_endpoint() {
        let mut st = state(Interceptor::new());
        st.intercept = None;
        let addr = serve(st).await;
        for path in [
            "/api/intercept/rules/requests",
            "/api/intercept/rules/responses",
        ] {
            let body = call(&addr, "GET", path, "").await;
            assert!(body.starts_with("HTTP/1.1 200"), "{path}: {body}");
            assert!(body.contains("\"wired\":false"), "{path}: {body}");
        }
    }

    #[tokio::test]
    async fn switching_interception_off_over_http_releases_the_queue() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let addr = serve(state(ic.clone())).await;

        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"x")).await })
        };
        wait_for_pending(&ic, 1).await;

        let body = call(
            &addr,
            "POST",
            "/api/intercept/enable",
            "{\"enabled\":false}",
        )
        .await;
        assert!(body.contains("\"released\":1"), "{body}");
        assert!(body.contains("\"enabled\":false"), "{body}");
        assert!(matches!(held.await.unwrap(), Verdict::Forward(_)));
    }
}
