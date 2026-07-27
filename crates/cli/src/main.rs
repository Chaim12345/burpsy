//! burpsy — a memory-frugal HTTP testing proxy with a web UI.
//!
//! Runs the intercepting proxy and the web UI over one shared [`TrafficStore`], so traffic captured
//! by the proxy is immediately available to Repeater and Intruder without copying bodies between
//! subsystems.

use anyhow::{Context, Result};
use burpsy_core::TrafficStore;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut proxy_bind = "127.0.0.1:8080".to_string();
    let mut web_bind = "127.0.0.1:8081".to_string();
    let mut policy = burpsy_proxy::TlsPolicy::new();
    let mut intercept = false;
    let mut ca_dir = burpsy_proxy::default_ca_dir();
    let mut scope = burpsy_core::Scope::new();
    let mut scope_set = false;
    let mut bchecks_dir: Option<std::path::PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--proxy" => proxy_bind = args.next().unwrap_or(proxy_bind),
            "--web" => web_bind = args.next().unwrap_or(web_bind),
            "--tls-passthrough" => {
                if let Some(pat) = args.next() {
                    policy.add_passthrough(pat);
                }
            }
            "--tls-passthrough-port" => {
                if let Some(p) = args.next().and_then(|v| v.parse::<u16>().ok()) {
                    policy.passthrough_ports.push(p);
                }
            }
            "--tls-defaults" => policy = burpsy_proxy::TlsPolicy::with_common_defaults(),
            "--intercept-tls" => intercept = true,
            "--bchecks" => bchecks_dir = args.next().map(std::path::PathBuf::from),
            "--scope-include" => {
                if let Some(h) = args.next() {
                    scope.add(burpsy_core::ScopeRule::include(h));
                    scope_set = true;
                }
            }
            "--scope-exclude" => {
                if let Some(h) = args.next() {
                    scope.add(burpsy_core::ScopeRule::exclude(h));
                    scope_set = true;
                }
            }
            "--ca-dir" => ca_dir = args.next().map(std::path::PathBuf::from).unwrap_or(ca_dir),
            "-h" | "--help" => {
                println!(
                    "burpsy {}\n\n\
                     USAGE:\n  burpsy [--proxy HOST:PORT] [--web HOST:PORT]\n         \
                     [--tls-passthrough PATTERN]... [--tls-passthrough-port PORT]... [--tls-defaults]\n\n\
                     DEFAULTS:\n  --proxy 127.0.0.1:8080   intercepting proxy\n  \
                     --web   127.0.0.1:8081   web UI\n\n\
                     TLS:\n  \
                     HTTPS CONNECT is currently tunnelled and recorded but NOT decrypted;\n  \
                     interception is in progress. The passthrough policy is already enforced and\n  \
                     annotated in history, so hosts you never want intercepted can be set now:\n\n  \
                     --tls-passthrough '*.apple.com'    exempt a host pattern (one leading *. allowed)\n  \
                     --tls-passthrough-port 8883        exempt a whole port (non-HTTP TLS services)\n  \
                     --tls-defaults                     preload common pinned hosts\n\n  \
                     Passthrough exists because MITM breaks certificate-pinned clients, TLS\n  \
                     client-auth, and non-HTTP-over-TLS outright. IP-literal CONNECTs are always\n  \
                     passed through (no SNI hostname to sign for).\n\n\
                     SCANNING:\n  \
                     --bchecks DIR    load PortSwigger BCheck files and passively scan responses\n  \
                     Only `given response` checks run today (105 of the 264 published checks);\n  \
                     active and Collaborator-dependent ones are counted and reported, not hidden.\n\n\
                     SCOPE:\n  \
                     --scope-include HOST / --scope-exclude HOST   (repeatable)\n  \
                     Gates what is stored AND refuses out-of-scope repeater/intruder targets.\n  \
                     With no --scope-* flags everything is in scope.\n\n\
                     Point your browser's HTTP proxy at the proxy address, then open the web UI.",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            other => {
                eprintln!("unknown argument {other:?}; try --help");
                std::process::exit(2);
            }
        }
    }

    let store: Arc<TrafficStore> = TrafficStore::new();

    // Load (or first-run generate) the CA only when interception is requested, so a plain HTTP
    // session never writes key material to disk it does not need.
    // No --scope-* flags means allow everything: narrowing capture must be a deliberate act,
    // not a surprise on first run.
    let scope = if scope_set {
        tracing::info!(
            "scope: {} rule(s) — capture and attacks limited to them",
            scope.rules.len()
        );
        scope
    } else {
        burpsy_core::Scope::allow_everything()
    };
    let mut cfg = burpsy_proxy::ProxyConfig::new(store.clone())
        .with_tls_policy(policy)
        .with_scope(scope.clone());

    // Passive scanning is opt-in via --bchecks. Load once at startup and REPORT the split, so
    // coverage is a stated number rather than an implied one.
    let mut findings = None;
    let mut audit_hook: Option<burpsy_web::AuditHook> = None;
    if let Some(dir) = &bchecks_dir {
        let sc = std::sync::Arc::new(burpsy_scanner::PassiveScanner::load_dir(
            dir,
            std::sync::Arc::new(scope.clone()),
        ));
        tracing::info!("bchecks from {}: {}", dir.display(), sc.report().summary());
        for (f, e) in sc.report().errors.iter().take(5) {
            tracing::warn!("unparsable bcheck {f}: {e}");
        }
        findings = Some(sc.findings());
        // Active scanning is operator-triggered via POST /api/audit/{id}, never automatic: it sends
        // traffic to the target, so it must be a deliberate act rather than a side effect of
        // browsing through the proxy.
        audit_hook = Some({
            let sc = sc.clone();
            let store = store.clone();
            std::sync::Arc::new(move |id: u64| {
                let sender = burpsy_proxy::sender::NetSender::default();
                let o = sc.audit(&store, id, &sender);
                serde_json::json!({
                    "enabled": true,
                    "exchange": id,
                    "active_checks": sc.active_loaded(),
                    "outcome": o,
                })
            }) as burpsy_web::AuditHook
        });
        cfg = cfg.with_scanner(sc);
    }
    let mut ca_pem: Option<String> = None;
    if intercept {
        let ca = burpsy_proxy::load_or_generate_ca(&ca_dir)
            .with_context(|| format!("loading CA from {}", ca_dir.display()))?;
        ca_pem = Some(ca.cert_pem.clone());
        cfg = cfg.with_tls_engine(Arc::new(burpsy_proxy::TlsEngine::new(ca)));
        tracing::info!(
            "TLS interception ENABLED (CA in {}) — install http://{}/ca.crt in your trust store",
            ca_dir.display(),
            web_bind
        );
    } else {
        tracing::info!(
            "TLS interception disabled — HTTPS will be tunnelled blind (--intercept-tls to enable)"
        );
    }

    let p = {
        let bind = proxy_bind.clone();
        tokio::spawn(async move { burpsy_proxy::run_with(&bind, cfg).await })
    };
    let w = {
        let store = store.clone();
        let bind = web_bind.clone();
        tokio::spawn(async move {
            burpsy_web::serve_audit(&bind, store, ca_pem, scope, findings, audit_hook).await
        })
    };

    tracing::info!("burpsy up — proxy {proxy_bind}, ui http://{web_bind}");

    // Exit as soon as either half fails, rather than silently running degraded.
    tokio::select! {
        r = p => match r { Ok(Err(e)) => tracing::error!("proxy stopped: {e}"), Err(e) => tracing::error!("proxy task: {e}"), _ => {} },
        r = w => match r { Ok(Err(e)) => tracing::error!("web ui stopped: {e}"), Err(e) => tracing::error!("web task: {e}"), _ => {} },
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    Ok(())
}
