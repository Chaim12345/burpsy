//! burpsy — a memory-frugal HTTP testing proxy with a web UI.
//!
//! Runs the intercepting proxy and the web UI over one shared [`TrafficStore`], so traffic captured
//! by the proxy is immediately available to Repeater and Intruder without copying bodies between
//! subsystems.

use anyhow::{Context, Result};
use burpsy_core::TrafficStore;
use std::sync::Arc;

/// `burpsy store verify DIR` — check a capture directory against its own checksums.
///
/// Separate from the serving path on purpose: it takes no ports, starts no proxy, and only reads.
/// Exits non-zero when any segment reports a fault, so it is usable as a check in a script rather
/// than something whose output a human has to read.
fn store_subcommand(mut args: impl Iterator<Item = String>) -> Result<()> {
    let verb = args.next().unwrap_or_default();
    if verb != "verify" {
        eprintln!("usage: burpsy store verify DIR\n\nUnknown store subcommand {verb:?}.",);
        std::process::exit(2);
    }
    let Some(dir) = args.next() else {
        eprintln!("usage: burpsy store verify DIR");
        std::process::exit(2);
    };
    let dir = std::path::PathBuf::from(dir);

    let report = burpsy_core::verify_capture_dir(&dir)
        .with_context(|| format!("verifying capture directory {}", dir.display()))?;

    if report.is_empty() {
        println!("{}: no sealed segments to check", dir.display());
        return Ok(());
    }

    // One line per segment, naming the fault where there is one. A bare "ok"/"corrupt" would leave
    // an operator no better off than a crash — the whole point of this command is that a verdict
    // says which record went wrong and where.
    let mut checked = 0usize;
    let mut faults = 0usize;
    for verdict in &report {
        let name = verdict
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| verdict.path.display().to_string());
        checked += verdict.checked;
        match &verdict.fault {
            None => println!("ok    {name}  {} records", verdict.checked),
            Some(fault) => {
                faults += 1;
                println!(
                    "FAULT {name}  {} records read, then: {fault}",
                    verdict.checked
                );
            }
        }
    }

    println!(
        "\nchecked {checked} record(s) across {} segment(s), {faults} with faults",
        report.len()
    );
    if faults > 0 {
        // Non-zero exit: a corrupt capture must fail a script, not merely print something.
        std::process::exit(1);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Subcommands are checked before the logging subscriber and before flag parsing: `store verify`
    // is a read-only offline check, and log lines on stdout would corrupt its report.
    let mut raw = std::env::args().skip(1);
    if matches!(raw.next().as_deref(), Some("store")) {
        // `raw` is now positioned just past "store".
        return store_subcommand(raw);
    }

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
    let mut capture_dir: Option<std::path::PathBuf> = None;
    let mut segment_target = burpsy_core::DEFAULT_SEGMENT_TARGET_BYTES;

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
            "--capture-dir" => capture_dir = args.next().map(std::path::PathBuf::from),
            "--segment-bytes" => {
                if let Some(n) = args.next() {
                    match n.parse::<usize>() {
                        Ok(n) if n > 0 => segment_target = n,
                        _ => {
                            eprintln!("--segment-bytes needs a positive byte count, got {n:?}");
                            std::process::exit(2);
                        }
                    }
                }
            }
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
                     CAPTURE TO DISK:\n  \
                     --capture-dir DIR       append traffic to sealed segments under DIR\n  \
                     --segment-bytes N       segment rotation target (default 64 MiB)\n  \
                     Without --capture-dir everything stays in RAM. With it, only one active\n  \
                     segment is resident, so a multi-GB capture is bounded by disk instead. DIR\n  \
                     must be empty or absent: there is no startup-recovery path yet, so reusing a\n  \
                     directory that already holds a capture is refused rather than overwriting it.\n  \
                     The size is a target, not a cap — a single message larger than it gets its own\n  \
                     segment rather than being truncated or dropped.\n\n\
                     SUBCOMMANDS:\n  \
                     burpsy store verify DIR   re-read every sealed segment and check each record\n  \
                     against the checksum written with it. Names the failing record and its byte\n  \
                     offset; exits non-zero if anything failed. Detects accidental corruption\n  \
                     (torn writes, truncation, bit rot) — it is not a tamper-evidence check.\n\n\
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

    // With no --capture-dir the store stays entirely in RAM, which is the historical behaviour and
    // is fine for a short session. With one, payloads append into sealed segments and only a
    // location per message stays resident, so a long capture is bounded by disk instead.
    let store: Arc<TrafficStore> = match &capture_dir {
        Some(dir) => {
            let store = TrafficStore::with_capture_dir(dir, segment_target)
                .with_context(|| format!("opening capture directory {}", dir.display()))?;
            tracing::info!(
                dir = %dir.display(),
                segment_bytes = segment_target,
                "capturing to disk; verify later with: burpsy store verify {}",
                dir.display()
            );
            store
        }
        None => TrafficStore::new(),
    };

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
    let mut export_hook: Option<burpsy_web::routes::report::ExportHook> = None;
    // Every audit this process ran, retained so a report can state what the active set actually did.
    // Without it `audit()`'s outcome is serialised to the HTTP response and dropped, and the report
    // would have to say "no audit was run" for a session in which the operator audited fifty
    // exchanges — a coverage claim that is wrong in the safe direction, but still wrong.
    let audits: Arc<std::sync::Mutex<Vec<burpsy_scanner::SessionOutcome>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
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
            let scope = std::sync::Arc::new(scope.clone());
            let audits = audits.clone();
            std::sync::Arc::new(move |id: u64| {
                // The chokepoint, not a bare transport: an active audit constructs requests, so it
                // is exactly the traffic HARD-03 exists to authorise.
                let sender = burpsy_sender::AuthorisedSender::blocking(
                    scope.clone(),
                    burpsy_sender::NetSender::default(),
                );
                let o = sc.audit(&store, id, &sender);
                // Retained before the response is built, so an outcome is never reported to the
                // operator and then missing from the report.
                if let Ok(mut log) = audits.lock() {
                    log.push(burpsy_scanner::report::single_audit(id, o.clone()));
                }
                serde_json::json!({
                    "enabled": true,
                    "exchange": id,
                    "active_checks": sc.active_loaded(),
                    "outcome": o,
                })
            }) as burpsy_web::AuditHook
        });
        export_hook = Some({
            let sc = sc.clone();
            let scope = std::sync::Arc::new(scope.clone());
            let audits = audits.clone();
            std::sync::Arc::new(move |fmt: burpsy_web::routes::report::ExportFormat| {
                use burpsy_scanner::report;
                let findings = sc.findings().read().all();
                // A poisoned lock means some audit thread panicked. Refused rather than reported as
                // an empty audit log: a report that silently claims no audit ran is the exact defect
                // the coverage model exists to prevent.
                let retained = audits
                    .lock()
                    .map_err(|_| "the retained audit log is poisoned; restart to report".to_owned())?
                    .clone();
                let passive = sc.coverage();
                let r = report::Report::from_facts(report::RunFacts {
                    scope: &scope,
                    load: sc.report(),
                    passive: &passive,
                    audits: &retained,
                    findings: &findings,
                    generated_unix_ms: report::now_unix_ms(),
                });
                let bytes = match fmt {
                    burpsy_web::routes::report::ExportFormat::Html => report::html::to_html(&r),
                    burpsy_web::routes::report::ExportFormat::Json => report::json::to_json(&r),
                    burpsy_web::routes::report::ExportFormat::Sarif => report::sarif::to_sarif(&r),
                }
                .into_bytes();
                Ok(burpsy_web::routes::report::Export {
                    format: fmt,
                    bytes,
                })
            }) as burpsy_web::routes::report::ExportHook
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
            burpsy_web::serve_export(
                &bind,
                store,
                ca_pem,
                scope,
                findings,
                audit_hook,
                export_hook,
            )
            .await
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
