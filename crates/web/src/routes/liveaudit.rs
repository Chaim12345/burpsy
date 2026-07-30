//! Live active audit: an opt-in, off-by-default background sweep that actively audits new
//! in-scope traffic as it's captured. This module is only the HTTP surface — read status, flip
//! the switch — the sweep itself runs in `crates/cli/src/main.rs`, which is the one place that
//! already holds both the scanner and the store.
//!
//! # Why off by default, and why a switch rather than always-on
//!
//! `POST /api/audit/{id}` exists precisely because active scanning sends real traffic to the
//! target and "must be a deliberate act rather than a side effect of browsing through the proxy"
//! (see `lib.rs::run_audit`). A background sweep that audited everything automatically the
//! moment `--bchecks` was passed would quietly reverse that invariant. So this stays off until
//! the operator flips it on — flipping the switch *is* the deliberate act, the same shape as
//! `Interceptor` (attached but disabled by default) and passive scanning itself (opt-in via
//! `--bchecks` in the first place).

use crate::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct LiveAuditState {
    enabled: AtomicBool,
    swept: AtomicU64,
    findings: AtomicU64,
}

impl LiveAuditState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    /// Record the outcome of one sweep tick, so the operator can see the sweep is doing
    /// something without having to open the report.
    pub fn record(&self, swept: u64, findings: u64) {
        self.swept.fetch_add(swept, Ordering::Relaxed);
        self.findings.fetch_add(findings, Ordering::Relaxed);
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/scanner/live", get(status).post(enable))
}

/// Same shape as `/api/intercept` and `/api/issues`: a feature not wired into this process says
/// so in a 200, rather than a 404 that looks like a typo in the route.
fn unwired() -> axum::response::Response {
    Json(serde_json::json!({
        "wired": false,
        "enabled": false,
        "hint": "live active audit needs a loaded check set; start with --bchecks",
    }))
    .into_response()
}

fn view(la: &LiveAuditState) -> serde_json::Value {
    serde_json::json!({
        "wired": true,
        "enabled": la.is_enabled(),
        "swept": la.swept.load(Ordering::Relaxed),
        "findings": la.findings.load(Ordering::Relaxed),
    })
}

async fn status(State(s): State<AppState>) -> impl IntoResponse {
    match s.live_audit.as_ref() {
        Some(la) => Json(view(la)).into_response(),
        None => unwired(),
    }
}

#[derive(Deserialize)]
struct EnableReq {
    enabled: bool,
}

async fn enable(State(s): State<AppState>, Json(req): Json<EnableReq>) -> impl IntoResponse {
    match s.live_audit.as_ref() {
        Some(la) => {
            la.set_enabled(req.enabled);
            Json(view(la)).into_response()
        }
        None => unwired(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{SharedScope, TrafficStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn state(live_audit: Option<Arc<LiveAuditState>>) -> AppState {
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
            live_audit,
        }
    }

    async fn serve(st: AppState) -> String {
        let app = routes().with_state(st);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await });
        format!("127.0.0.1:{}", addr.port())
    }

    async fn call(addr: &str, method: &str, body: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "{method} /api/scanner/live HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn an_unwired_process_reports_itself_instead_of_404ing() {
        let addr = serve(state(None)).await;
        let body = call(&addr, "GET", "").await;
        assert!(body.starts_with("HTTP/1.1 200"), "{body}");
        assert!(body.contains("\"wired\":false"), "{body}");
    }

    #[tokio::test]
    async fn it_is_off_by_default_and_the_switch_flips_it() {
        let la = LiveAuditState::new();
        let addr = serve(state(Some(la.clone()))).await;

        let body = call(&addr, "GET", "").await;
        assert!(body.contains("\"enabled\":false"), "{body}");

        let body = call(&addr, "POST", "{\"enabled\":true}").await;
        assert!(body.contains("\"enabled\":true"), "{body}");
        assert!(la.is_enabled());

        let body = call(&addr, "POST", "{\"enabled\":false}").await;
        assert!(body.contains("\"enabled\":false"), "{body}");
    }

    #[tokio::test]
    async fn recorded_sweeps_accumulate_and_are_visible_over_http() {
        let la = LiveAuditState::new();
        la.record(5, 1);
        la.record(3, 0);
        let addr = serve(state(Some(la))).await;
        let body = call(&addr, "GET", "").await;
        assert!(body.contains("\"swept\":8"), "{body}");
        assert!(body.contains("\"findings\":1"), "{body}");
    }
}
