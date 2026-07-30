//! A runnable proxy with the interception API attached, for `e2e-intercept.sh`.
//!
//! # Why this exists instead of using the `burpsy` binary
//!
//! `burpsy_web::router_audit` builds its own `AppState` with `intercept: None`, so the shipped
//! binary cannot reach the hold queue yet — wiring it means editing `crates/web/src/lib.rs` and
//! `crates/cli/src/main.rs`, which belong to other work in flight. `AppState`'s fields are public,
//! so this example assembles the router itself: the real `routes::intercept::routes()`, over a real
//! `Interceptor`, shared with a real proxy. The end-to-end script therefore drives exactly the
//! endpoints the UI will call, against exactly the proxy code that ships.
//!
//! Two extra endpoints under `/e2e/` exist only so the script can assert on things the interception
//! API does not expose: what landed in the traffic store, and how many TCP connections a run of
//! probes actually opened.

use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;
use burpsy_bcheck::eval::{Sender, Target};
use burpsy_core::{Scope, ScopeRule, SharedScope, TrafficStore};
use burpsy_proxy::{Interceptor, ProxyConfig};
use burpsy_sender::NetSender;
use burpsy_web::AppState;
use burpsy_web::routes::intercept::InterceptState;
use serde::Deserialize;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut proxy_bind = "127.0.0.1:18580".to_string();
    let mut web_bind = "127.0.0.1:18581".to_string();
    let mut scope = Scope::new();
    let mut scope_set = false;
    let mut start_on = true;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--proxy" => proxy_bind = args.next().unwrap_or(proxy_bind),
            "--web" => web_bind = args.next().unwrap_or(web_bind),
            "--scope-include" => {
                if let Some(h) = args.next() {
                    scope.add(ScopeRule::include(h));
                    scope_set = true;
                }
            }
            "--intercept-off" => start_on = false,
            other => anyhow::bail!("unknown argument {other:?}"),
        }
    }
    // One shared scope for both halves. Two copies would let the API report rules the proxy was
    // not capturing by — see `SharedScope`'s docs.
    let scope = SharedScope::new(if scope_set {
        scope
    } else {
        Scope::allow_everything()
    });

    let store = TrafficStore::new();
    let interceptor = Interceptor::new();
    interceptor.set_enabled(start_on);

    let cfg = ProxyConfig::new(store.clone())
        .with_scope(scope.clone())
        .with_interceptor(interceptor.clone());

    let state = AppState {
        store: store.clone(),
        ca_pem: None,
        scope,
        findings: None,
        audit: None,
        export: None,
        intercept: Some(InterceptState::new(interceptor)),
        session: None,
        tool_log: None,
        live_audit: None,
    };

    let app = Router::new()
        .merge(burpsy_web::routes::intercept::routes())
        .route("/e2e/history", get(history))
        .route("/e2e/probe", get(probe))
        .with_state(state);

    let web = tokio::net::TcpListener::bind(&web_bind).await?;
    let proxy = tokio::net::TcpListener::bind(&proxy_bind).await?;
    tracing::info!(
        "intercept e2e: proxy {proxy_bind}, api http://{web_bind} (intercept on: {start_on})"
    );

    tokio::select! {
        r = burpsy_proxy::serve(proxy, cfg) => r?,
        r = async { axum::serve(web, app).await } => r?,
    }
    Ok(())
}

/// Everything in the store, including the raw request text — so the script can assert that the
/// bytes recorded are the bytes that were sent.
async fn history(State(s): State<AppState>) -> axum::Json<serde_json::Value> {
    let rows: Vec<serde_json::Value> = s
        .store
        .exchanges(0, 500)
        .into_iter()
        .map(|e| {
            let req = s
                .store
                .get(e.request)
                .map(|m| String::from_utf8_lossy(&m.raw).into_owned())
                .unwrap_or_default();
            serde_json::json!({
                "id": e.id,
                "method": e.method,
                "host": e.host,
                "port": e.port,
                "tls": e.tls,
                "path": e.path,
                "status": e.status,
                "notes": e.notes,
                "request": req,
            })
        })
        .collect();
    axum::Json(serde_json::json!({ "count": rows.len(), "exchanges": rows }))
}

#[derive(Deserialize)]
struct ProbeArgs {
    host: String,
    port: u16,
    #[serde(default = "three")]
    n: usize,
    /// Send `Connection: close` on every probe, exercising the escape hatch.
    #[serde(default)]
    force_close: bool,
    /// Turn the pool off entirely.
    #[serde(default)]
    no_reuse: bool,
}
fn three() -> usize {
    3
}

/// Fire N active-scan-style probes through the real [`NetSender`], so the script can compare the
/// number of probes against the number of TCP connections the origin accepted.
async fn probe(Query(a): Query<ProbeArgs>) -> axum::Json<serde_json::Value> {
    let out = tokio::task::spawn_blocking(move || {
        let sender = if a.no_reuse {
            NetSender::without_reuse()
        } else {
            NetSender::default()
        };
        let target = Target {
            host: a.host.clone(),
            port: a.port,
            tls: false,
        };
        let raw = if a.force_close {
            format!(
                "GET /probe HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
                a.host, a.port
            )
        } else {
            format!("GET /probe HTTP/1.1\r\nHost: {}:{}\r\n\r\n", a.host, a.port)
        };
        let mut ok = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for _ in 0..a.n.min(50) {
            match sender.send(&target, raw.as_bytes()) {
                Ok(_) => ok += 1,
                Err(e) => errors.push(e),
            }
        }
        serde_json::json!({
            "probes": a.n,
            "ok": ok,
            "errors": errors,
            "pooled_after": sender.pooled_connections(),
        })
    })
    .await
    .unwrap_or_else(|e| serde_json::json!({ "error": format!("probe task failed: {e}") }));
    axum::Json(out)
}
