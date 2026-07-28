//! Request interception: hold, edit, forward, drop.
//!
//! The queue itself lives in `burpsy_proxy::intercept` — it has to, because the thing being held is
//! a proxy connection task. This module is only the HTTP surface over it, so the API layer carries
//! no interception logic of its own beyond one decision: whether to recompute `Content-Length` on
//! an edited request.
//!
//! # Why editing defaults to fixing `Content-Length`
//!
//! An operator who adds a word to a JSON body and forwards it will otherwise send a request whose
//! declared length no longer matches its body: the origin either truncates the body at the stale
//! length or blocks waiting for bytes that never arrive. Both look like the tool broke. So a forward
//! with new bytes re-derives the length through `burpsy_core::edit::RequestEdit`, which is the same
//! path Repeater and the BCheck sender use, and `fix_content_length: false` turns it off for the
//! case where the malformed framing *is* the test.

use crate::AppState;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use burpsy_core::edit::RequestEdit;
use burpsy_proxy::intercept::Interceptor;
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
async fn status(State(s): State<AppState>) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    let held = st.interceptor.list();
    Json(serde_json::json!({
        "enabled": st.interceptor.is_enabled(),
        "wired": true,
        "pending": held.len(),
        "held": held,
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

/// `POST /api/intercept/{id}/forward` — release one held request, optionally rewritten.
async fn forward(
    State(s): State<AppState>,
    Path(id): Path<u64>,
    body: Option<Json<Forward>>,
) -> impl IntoResponse {
    let Some(st) = s.intercept.as_ref() else {
        return unwired();
    };
    let Json(req) = body.unwrap_or_default();
    let edited = req.raw.map(|raw| {
        // A textarea gives back bare LFs; HTTP wants CRLF. Normalise the same way Repeater does.
        let raw = raw.replace("\r\n", "\n").replace('\n', "\r\n");
        if req.fix_content_length
            && let Ok(r) = RequestEdit::from_raw(raw.as_bytes())
        {
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

/// A held request that is no longer held — already resolved, or its client hung up. Saying so beats
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
    use burpsy_core::{Scope, TrafficStore};
    use burpsy_proxy::{HeldMeta, Verdict};
    use std::time::Duration;

    fn state(interceptor: Arc<Interceptor>) -> AppState {
        AppState {
            store: TrafficStore::new(),
            ca_pem: None,
            scope: Arc::new(Scope::allow_everything()),
            findings: None,
            audit: None,
            export: None,
            intercept: Some(InterceptState::new(interceptor)),
            session: None,
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
