//! burpsy-proxy — intercepting HTTP proxy.
//!
//! # Current scope, stated plainly
//!
//! * **Plain HTTP** — fully proxied. Request and response are captured into the
//!   [`TrafficStore`] and an [`Exchange`] indexes them.
//! * **HTTPS (`CONNECT`)** — tunnelled bidirectionally and *recorded* with `tls: true`, but the
//!   ciphertext is not decrypted. TLS interception needs a generated CA, per-host leaf signing and
//!   the user installing that CA in their trust store — a separate chunk, deliberately not faked.
//!
//! So today: full visibility on HTTP, connection-level visibility on HTTPS. A tunnel is recorded
//! rather than silently dropped, so history never lies about what happened — and a `CONNECT` that
//! never reaches its origin is recorded too, with the reason, because "unreachable" and "never
//! visited" must not both look like an empty history.
//!
//! # Request interception
//!
//! Optional and off by default. When a hold queue is attached (see [`ProxyConfig::with_interceptor`]
//! and the [`intercept`] module), an in-scope request is parked before it is forwarded so an
//! operator can rewrite or refuse it. Out-of-scope traffic is never held, and holding one request
//! parks only its own connection task.
//!
//! # Memory
//!
//! Bodies are read once, converted to `Bytes`, handed to the store. Nothing upstream keeps a second
//! copy — the [`Exchange`] carries `MsgId`s only.

use anyhow::{Context, Result};
use burpsy_core::{Direction, Exchange, TrafficStore};
use bytes::Bytes;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod intercept;
pub mod sender;
pub mod tls;
pub mod tls_policy;
pub use intercept::{HeldMeta, HeldView, Interceptor, Verdict};
pub use tls::{CertAuthority, TlsEngine, default_ca_dir, load_or_generate_ca};
pub use tls_policy::{TlsAction, TlsPolicy};

/// Everything a connection handler needs.
#[derive(Clone)]
pub struct ProxyConfig {
    pub store: Arc<TrafficStore>,
    pub tls: Arc<TlsPolicy>,
    /// When present, `CONNECT` to a non-passthrough host is intercepted rather than tunnelled.
    pub engine: Option<Arc<TlsEngine>>,
    /// Gates what gets STORED. Out-of-scope traffic is still forwarded — otherwise pointing a
    /// browser at the proxy would break every site outside the engagement — it just is not kept.
    pub scope: Arc<burpsy_core::Scope>,
    /// Passive scanner. Runs on a spawned task so scan cost never adds proxy latency.
    pub scanner: Option<Arc<burpsy_scanner::PassiveScanner>>,
    /// Hold queue for operator review. `None` means the feature is not wired up at all, which is
    /// cheaper than a wired-but-disabled queue and impossible to switch on by accident.
    pub intercept: Option<Arc<intercept::Interceptor>>,
}

impl ProxyConfig {
    pub fn new(store: Arc<TrafficStore>) -> Self {
        Self {
            store,
            tls: Arc::new(TlsPolicy::new()),
            engine: None,
            // Default: allow everything. Scope narrows capture; it must not silently swallow
            // traffic on a fresh run before the operator has configured anything.
            scope: Arc::new(burpsy_core::Scope::allow_everything()),
            scanner: None,
            intercept: None,
        }
    }

    pub fn with_scanner(mut self, s: Arc<burpsy_scanner::PassiveScanner>) -> Self {
        self.scanner = Some(s);
        self
    }

    pub fn with_scope(mut self, sc: burpsy_core::Scope) -> Self {
        self.scope = Arc::new(sc);
        self
    }

    pub fn with_tls_policy(mut self, p: TlsPolicy) -> Self {
        self.tls = Arc::new(p);
        self
    }

    /// Enable TLS interception with a loaded CA.
    pub fn with_tls_engine(mut self, e: Arc<TlsEngine>) -> Self {
        self.engine = Some(e);
        self
    }

    /// Attach a hold queue. Share the same `Arc` with the API layer — that is the only link between
    /// the operator's decisions and the connection tasks waiting on them.
    pub fn with_interceptor(mut self, i: Arc<intercept::Interceptor>) -> Self {
        self.intercept = Some(i);
        self
    }
}

/// Run the proxy until cancelled. Each connection gets its own task.
pub async fn run(bind: &str, store: Arc<TrafficStore>) -> Result<()> {
    run_with(bind, ProxyConfig::new(store)).await
}

/// Run with an explicit config (TLS policy etc.).
pub async fn run_with(bind: &str, cfg: ProxyConfig) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind proxy on {bind}"))?;
    tracing::info!(
        "proxy listening on {bind} ({} passthrough pattern(s))",
        cfg.tls.passthrough.len()
    );
    serve(listener, cfg).await
}

/// Accept loop over a listener the caller already bound.
///
/// Split out from [`run_with`] so a test can bind port 0, learn the port, and still drive the real
/// accept path — asserting proxy behaviour against a hardcoded port is how test suites start
/// colliding with each other.
pub async fn serve(listener: TcpListener, cfg: ProxyConfig) -> Result<()> {
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                continue;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, cfg).await {
                tracing::debug!("connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, cfg: ProxyConfig) -> Result<()> {
    client.set_nodelay(true).ok();
    let head = read_head(&mut client).await?;
    if head.is_empty() {
        return Ok(());
    }

    let line_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    let start_line = String::from_utf8_lossy(&head[..line_end]).to_string();
    let mut parts = start_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        return tunnel(client, &target, cfg).await;
    }
    forward_http(client, head, &method, &target, cfg).await
}

/// Read until end of headers, then the body if `Content-Length` says so.
async fn read_head(s: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = vec![0u8; 8192];
    loop {
        let n = s.read(&mut chunk).await.context("read request")?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(head_end) = find(&buf, b"\r\n\r\n") {
            let want = content_length(&buf[..head_end]).unwrap_or(0);
            if buf.len() >= head_end + 4 + want {
                break;
            }
        }
        if buf.len() > 64 * 1024 * 1024 {
            break;
        }
    }
    Ok(buf)
}

fn content_length(head: &[u8]) -> Option<usize> {
    let lower = head.to_ascii_lowercase();
    let i = find(&lower, b"content-length:")?;
    let rest = &head[i + 15..];
    let end = rest
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok()?.trim().parse().ok()
}

/// Absolute-form request (`GET http://host/path`) → rewrite to origin-form and forward.
async fn forward_http(
    mut client: TcpStream,
    head: Vec<u8>,
    method: &str,
    target: &str,
    cfg: ProxyConfig,
) -> Result<()> {
    let store = cfg.store.clone();
    let (mut host, port, path) = split_absolute(target);
    if host.is_empty() {
        host = header_value(&head, b"host").unwrap_or_default();
    }
    if host.is_empty() {
        let _ = client
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Ok(());
    }
    let host_only = host.split(':').next().unwrap_or(&host).to_string();

    // Rewrite only the request target; every other byte is preserved.
    let upstream_req = rewrite_target(&head, &path);

    let in_scope = cfg.scope.contains(&host_only, port, &path, false);
    if !in_scope {
        // Forward transparently but do not retain. Counted so the UI can show it is happening.
        // Interception is deliberately downstream of this test: out-of-scope traffic is not the
        // engagement's business, and holding it would freeze whatever else the browser is doing.
        return forward_only(client, upstream_req, &host_only, port).await;
    }

    // Hold BEFORE the store write so history records what was actually sent — see `intercept`.
    let upstream_req = match hold_for_review(
        &cfg,
        &host_only,
        port,
        false,
        method,
        &path,
        Bytes::from(upstream_req),
    )
    .await
    {
        Reviewed::Send(b) => b,
        Reviewed::Dropped { raw, reason } => {
            let resp = dropped_response(&reason);
            let _ = client.write_all(&resp).await;
            let _ = client.flush().await;
            record_drop(
                &store, &host_only, port, false, method, &path, raw, resp, &reason,
            );
            return Ok(());
        }
    };

    // Re-derive the start line from the bytes that are actually going out. An operator who rewrote
    // the path must not find the pre-edit path in history — the index has to agree with the
    // message it indexes. The upstream host and port stay as originally addressed: editing the
    // `Host` header changes what the origin is told, not which origin we dial.
    let (method, path) = start_line_parts(&upstream_req);

    let req_id = store.put(upstream_req.clone(), Direction::Request);
    let ex_id = store.add_exchange(Exchange {
        related: Vec::new(),
        id: 0,
        request: req_id,
        response: None,
        host: host_only.clone(),
        port,
        tls: false,
        method: method.to_string(),
        path: path.clone(),
        status: None,
        response_len: 0,
        started_ms: now_ms(),
        duration_ms: 0,
        notes: None,
    });

    let started = Instant::now();
    let mut upstream = match TcpStream::connect((host_only.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            let body = format!("burpsy: upstream connect failed: {e}");
            let resp = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = client.write_all(resp.as_bytes()).await;
            return Ok(());
        }
    };
    upstream.set_nodelay(true).ok();
    upstream
        .write_all(&upstream_req)
        .await
        .context("write upstream")?;
    upstream.flush().await.ok();

    // Stream to the client while accumulating for the store.
    let mut resp = Vec::with_capacity(16 * 1024);
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        let n = upstream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&chunk[..n]);
        if client.write_all(&chunk[..n]).await.is_err() {
            break;
        }
    }
    let _ = client.flush().await;

    let status = parse_status(&resp);
    let len = resp.len();
    let resp_id = store.put(Bytes::from(resp), Direction::Response);
    store.set_response(
        ex_id,
        resp_id,
        status.unwrap_or(0),
        len,
        started.elapsed().as_millis() as u64,
    );
    spawn_scan(&cfg, ex_id, resp_id);
    Ok(())
}

/// Proxy an out-of-scope request without storing anything.
async fn forward_only(mut client: TcpStream, req: Vec<u8>, host: &str, port: u16) -> Result<()> {
    let Ok(mut up) = TcpStream::connect((host, port)).await else {
        let _ = client
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Ok(());
    };
    up.set_nodelay(true).ok();
    up.write_all(&req).await.ok();
    up.flush().await.ok();
    let _ = tokio::io::copy(&mut up, &mut client).await;
    Ok(())
}

/// `CONNECT host:port` → 200, then either splice blind or (once implemented) intercept.
///
/// The policy decision is made and *recorded* here even though interception itself is not wired up
/// yet, so history always states whether a tunnel was deliberately passed through or merely not
/// decryptable. Silence on that distinction is how a tester ends up trusting an empty history.
async fn tunnel(mut client: TcpStream, target: &str, cfg: ProxyConfig) -> Result<()> {
    let store = cfg.store.clone();
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(443)),
        None => (target.to_string(), 443),
    };

    let action = cfg.tls.action_for(&host, port);

    // Intercept when the policy allows it AND a CA is loaded.
    if action == TlsAction::Intercept && cfg.engine.is_some() {
        return mitm(client, host, port, cfg).await;
    }

    let note = match action {
        TlsAction::Passthrough => {
            let why = cfg
                .tls
                .reason_for(&host, port)
                .unwrap_or_else(|| "passthrough".to_string());
            format!("passthrough: {why}")
        }
        TlsAction::Intercept => {
            "policy says intercept, but no CA is loaded; tunnelled blind".into()
        }
    };

    let started = Instant::now();
    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            record_failed_connect(
                &store,
                &host,
                port,
                &format!("upstream connect failed: {e}"),
                started,
            );
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("write connect ok")?;

    // Record the tunnel so history reflects reality; contents stay opaque without MITM.
    let marker = Bytes::from(format!("CONNECT {host}:{port}\r\n\r\n"));
    let req_id = store.put(marker, Direction::Request);
    let ex_id = store.add_exchange(Exchange {
        related: Vec::new(),
        id: 0,
        request: req_id,
        response: None,
        host: host.clone(),
        port,
        tls: true,
        method: "CONNECT".into(),
        path: String::new(),
        status: None,
        response_len: 0,
        started_ms: now_ms(),
        duration_ms: 0,
        notes: Some(note),
    });

    let (up, down) = tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .unwrap_or((0, 0));

    let summary = Bytes::from(format!(
        "HTTP/1.1 200 Connection Established\r\n\r\n[tunnel closed: {up} up / {down} down]"
    ));
    let len = summary.len();
    let resp_id = store.put(summary, Direction::Response);
    store.set_response(
        ex_id,
        resp_id,
        200,
        len,
        started.elapsed().as_millis() as u64,
    );
    Ok(())
}

/// Intercept a `CONNECT`: terminate TLS toward the client, open TLS upstream, and proxy plaintext.
///
/// After `200 Connection Established` the client speaks TLS expecting the real server, so we
/// present a leaf minted for that host. Requests then arrive in **origin form** (the client believes
/// it is talking directly to the server), which is why no target rewriting happens here — unlike the
/// plain-HTTP path.
///
/// Keep-alive is honoured: the loop keeps reading exchanges off the same TLS session until either
/// side closes, because a browser will pipeline many requests down one CONNECT.
async fn mitm(mut client: TcpStream, host: String, port: u16, cfg: ProxyConfig) -> Result<()> {
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    let engine = cfg
        .engine
        .clone()
        .context("mitm called without a TLS engine")?;
    let store = cfg.store.clone();

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("write connect ok")?;

    // Client side: leaf signed for this host. Fallback covers IP-literal CONNECTs (no SNI).
    let acceptor = TlsAcceptor::from(Arc::new(engine.server_config(&host)));
    let mut tls_client = match acceptor.accept(client).await {
        Ok(s) => s,
        Err(e) => {
            // Almost always the CA not being trusted yet — worth saying so loudly once.
            tracing::warn!(
                "client TLS handshake failed for {host}: {e} (is the burpsy CA installed?)"
            );
            return Ok(());
        }
    };

    // Upstream side. Every way this can fail is recorded before returning: an intercepted CONNECT
    // that never reached the origin must still leave a trace, or history reads as "never visited".
    let connect_started = Instant::now();
    let upstream_tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            record_failed_connect(
                &store,
                &host,
                port,
                &format!("upstream connect failed: {e}"),
                connect_started,
            );
            return Ok(());
        }
    };
    upstream_tcp.set_nodelay(true).ok();
    let connector = TlsConnector::from(tls::upstream_client_config());
    let dns = match rustls_pki_types::ServerName::try_from(host.clone()) {
        Ok(d) => d,
        Err(_) => {
            record_failed_connect(
                &store,
                &host,
                port,
                "invalid DNS name for TLS",
                connect_started,
            );
            return Ok(());
        }
    };
    let mut tls_upstream = match connector.connect(dns, upstream_tcp).await {
        Ok(s) => s,
        Err(e) => {
            record_failed_connect(
                &store,
                &host,
                port,
                &format!("upstream TLS handshake failed: {e}"),
                connect_started,
            );
            return Ok(());
        }
    };

    // Now it is just HTTP over two streams.
    loop {
        let req = match read_message(&mut tls_client).await {
            Ok(r) if !r.is_empty() => r,
            _ => break,
        };

        let (method, path) = start_line_parts(&req);
        let req = match hold_for_review(&cfg, &host, port, true, &method, &path, Bytes::from(req))
            .await
        {
            Reviewed::Send(b) => b,
            Reviewed::Dropped { raw, reason } => {
                let resp = dropped_response(&reason);
                let _ = tls_client.write_all(&resp).await;
                let _ = tls_client.flush().await;
                record_drop(
                    &store, &host, port, true, &method, &path, raw, resp, &reason,
                );
                // The client asked for one request and got a complete answer, so the TLS session is
                // still in a sane state: keep serving it rather than tearing down every other
                // pipelined request on this connection.
                continue;
            }
        };
        // As on the plain path: index the bytes that go out, not the ones that came in.
        let (method, path) = start_line_parts(&req);

        let req_id = store.put(req.clone(), Direction::Request);
        let ex_id = store.add_exchange(Exchange {
            related: Vec::new(),
            id: 0,
            request: req_id,
            response: None,
            host: host.clone(),
            port,
            tls: true,
            method,
            path,
            status: None,
            response_len: 0,
            started_ms: now_ms(),
            duration_ms: 0,
            notes: Some("intercepted".into()),
        });

        let started = Instant::now();
        if tls_upstream.write_all(&req).await.is_err() {
            break;
        }
        tls_upstream.flush().await.ok();

        let mut resp = Vec::with_capacity(16 * 1024);
        let mut chunk = vec![0u8; 16 * 1024];
        let mut client_gone = false;
        loop {
            // A read error is treated as end of stream: we already have whatever the server
            // managed to send, and surfacing the error would discard a usable partial response.
            let n = tls_upstream.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            resp.extend_from_slice(&chunk[..n]);
            if tls_client.write_all(&chunk[..n]).await.is_err() {
                client_gone = true;
                break;
            }
            if let Some(total) = response_complete_len(&resp)
                && resp.len() >= total
            {
                break;
            }
        }
        let _ = tls_client.flush().await;

        let status = parse_status(&resp);
        let len = resp.len();
        let resp_id = store.put(Bytes::from(resp), Direction::Response);
        store.set_response(
            ex_id,
            resp_id,
            status.unwrap_or(0),
            len,
            started.elapsed().as_millis() as u64,
        );
        spawn_scan(&cfg, ex_id, resp_id);

        if client_gone {
            break;
        }
    }
    Ok(())
}

/// Read one HTTP message (headers + declared body) from any stream.
async fn read_message<S>(s: &mut S) -> Result<Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = vec![0u8; 8192];
    loop {
        let n = s.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(head_end) = find(&buf, b"\r\n\r\n") {
            let want = content_length(&buf[..head_end]).unwrap_or(0);
            if buf.len() >= head_end + 4 + want {
                break;
            }
        }
        if buf.len() > 64 * 1024 * 1024 {
            break;
        }
    }
    Ok(buf)
}

/// Total expected response length if framing is known, so keep-alive does not stall us.
fn response_complete_len(buf: &[u8]) -> Option<usize> {
    let head_end = find(buf, b"\r\n\r\n").map(|i| i + 4)?;
    let lower = buf[..head_end].to_ascii_lowercase();
    if find(&lower, b"transfer-encoding: chunked").is_some() {
        return if find(&buf[head_end..], b"0\r\n\r\n").is_some() {
            Some(buf.len())
        } else {
            None
        };
    }
    let n = content_length(&buf[..head_end])?;
    Some(head_end + n)
}

fn start_line_parts(req: &[u8]) -> (String, String) {
    let line_end = req
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(req.len());
    let line = String::from_utf8_lossy(&req[..line_end]).to_string();
    let mut it = line.split_whitespace();
    (
        it.next().unwrap_or_default().to_string(),
        it.next().unwrap_or_default().to_string(),
    )
}

/// Split `http://host:port/path` into `(host, port, path)`.
fn split_absolute(target: &str) -> (String, u16, String) {
    let (tls, rest) = if let Some(r) = target.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = target.strip_prefix("http://") {
        (false, r)
    } else {
        return (String::new(), 80, target.to_string());
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (h, p) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse().unwrap_or(if tls { 443 } else { 80 }),
        ),
        None => (hostport.to_string(), if tls { 443 } else { 80 }),
    };
    (h, p, path.to_string())
}

/// Replace the request target in the start line, preserving every other byte.
fn rewrite_target(head: &[u8], path: &str) -> Vec<u8> {
    let line_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    let line = &head[..line_end];
    let spaces: Vec<usize> = line
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b' ')
        .map(|(i, _)| i)
        .collect();
    if spaces.len() < 2 {
        return head.to_vec();
    }
    let (s1, s2) = (spaces[0], spaces[spaces.len() - 1]);
    let mut out = Vec::with_capacity(head.len());
    out.extend_from_slice(&line[..=s1]);
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(&line[s2..]);
    out.extend_from_slice(&head[line_end..]);
    out
}

fn header_value(head: &[u8], name: &[u8]) -> Option<String> {
    let lower = head.to_ascii_lowercase();
    let mut pat = Vec::with_capacity(name.len() + 2);
    pat.push(b'\n');
    pat.extend_from_slice(name);
    pat.push(b':');
    let i = find(&lower, &pat)?;
    let rest = &head[i + pat.len()..];
    let end = rest
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).trim().to_string())
}

fn parse_status(buf: &[u8]) -> Option<u16> {
    let line_end = buf.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let line = &buf[..line_end];
    let sp = line.iter().position(|&b| b == b' ')?;
    let rest = &line[sp + 1..];
    let end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok()?.parse().ok()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Outcome of showing a request to the operator.
enum Reviewed {
    /// Send these bytes upstream. Identical to the input unless the operator rewrote them.
    Send(Bytes),
    /// Do not send. Carries the bytes that would have gone out, so history can still record them.
    Dropped { raw: Bytes, reason: String },
}

/// Park a request for operator review, if interception is on and the target is in scope.
///
/// The scope test is repeated here even though `forward_http` already made it: the MITM path has no
/// equivalent gate, and "out-of-scope traffic passes through untouched" is a property that must hold
/// for every caller, not just the one that happens to check first.
async fn hold_for_review(
    cfg: &ProxyConfig,
    host: &str,
    port: u16,
    tls: bool,
    method: &str,
    path: &str,
    raw: Bytes,
) -> Reviewed {
    let Some(ic) = cfg.intercept.as_ref() else {
        return Reviewed::Send(raw);
    };
    if !ic.is_enabled() || !cfg.scope.contains(host, port, path, tls) {
        return Reviewed::Send(raw);
    }
    let meta = intercept::HeldMeta {
        host: host.to_string(),
        port,
        tls,
        method: method.to_string(),
        path: path.to_string(),
    };
    match ic.hold(meta, raw.clone()).await {
        intercept::Verdict::Forward(b) => Reviewed::Send(b),
        intercept::Verdict::Drop(reason) => Reviewed::Dropped { raw, reason },
    }
}

/// The answer a dropped request's client gets.
///
/// A real status rather than a closed socket: a client that sees the connection die cannot tell an
/// operator's decision from a network fault, and browsers retry the latter. 403 is what a refusing
/// proxy is supposed to say, and the header makes the origin of the refusal unambiguous.
fn dropped_response(reason: &str) -> Bytes {
    let body = format!("burpsy: request dropped by operator ({reason})");
    Bytes::from(format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/plain\r\n\
         X-Burpsy-Intercept: dropped\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    ))
}

/// Record a request the operator refused to forward, with the synthetic reply its client received.
#[allow(clippy::too_many_arguments)]
fn record_drop(
    store: &TrafficStore,
    host: &str,
    port: u16,
    tls: bool,
    method: &str,
    path: &str,
    raw: Bytes,
    response: Bytes,
    reason: &str,
) {
    let req_id = store.put(raw, Direction::Request);
    let ex_id = store.add_exchange(Exchange {
        related: Vec::new(),
        id: 0,
        request: req_id,
        response: None,
        host: host.to_string(),
        port,
        tls,
        method: method.to_string(),
        path: path.to_string(),
        status: None,
        response_len: 0,
        started_ms: now_ms(),
        duration_ms: 0,
        notes: Some(format!("dropped by operator: {reason}")),
    });
    let len = response.len();
    let resp_id = store.put(response, Direction::Response);
    store.set_response(ex_id, resp_id, 403, len, 0);
}

/// Record a `CONNECT` that never became a tunnel.
///
/// Without this the failure is invisible: a host that is unreachable, DNS-broken or presenting a
/// TLS handshake we cannot complete looks exactly like a host nobody ever visited. That ambiguity
/// is worse than a noisy history — an operator concluding "the app never talks to that domain" from
/// silence is drawing a conclusion from missing evidence.
fn record_failed_connect(
    store: &TrafficStore,
    host: &str,
    port: u16,
    reason: &str,
    started: Instant,
) -> u64 {
    let marker = Bytes::from(format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    ));
    let req_id = store.put(marker, Direction::Request);
    let ex_id = store.add_exchange(Exchange {
        related: Vec::new(),
        id: 0,
        request: req_id,
        response: None,
        host: host.to_string(),
        port,
        tls: true,
        method: "CONNECT".into(),
        path: String::new(),
        status: None,
        response_len: 0,
        started_ms: now_ms(),
        duration_ms: 0,
        notes: Some(format!("connect failed: {reason}")),
    });
    let body = format!("burpsy: {reason}");
    let synthetic = Bytes::from(format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    ));
    let len = synthetic.len();
    let resp_id = store.put(synthetic, Direction::Response);
    store.set_response(
        ex_id,
        resp_id,
        502,
        len,
        started.elapsed().as_millis() as u64,
    );
    tracing::debug!("recorded failed CONNECT {host}:{port}: {reason}");
    ex_id
}

/// Queue a passive scan without blocking the response path.
///
/// Deliberately fire-and-forget on a separate task: a proxy that slows down as its check set grows
/// is a proxy people switch off, and Burp's own engine shows where coupling scan cost to request
/// handling leads (it sheds work via LIMIT_EXCEEDED).
fn spawn_scan(cfg: &ProxyConfig, exchange_id: u64, response_id: burpsy_core::MsgId) {
    let Some(sc) = cfg.scanner.clone() else {
        return;
    };
    let store = cfg.store.clone();
    tokio::spawn(async move {
        let n = sc.scan(&store, exchange_id, response_id);
        if n > 0 {
            tracing::info!("passive scan: {n} finding(s) on exchange {exchange_id}");
        }
    });
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_absolute_form() {
        assert_eq!(
            split_absolute("http://a.test:8080/x?y=1"),
            ("a.test".to_string(), 8080, "/x?y=1".to_string())
        );
        assert_eq!(
            split_absolute("https://b.test/"),
            ("b.test".to_string(), 443, "/".to_string())
        );
        assert_eq!(
            split_absolute("/origin/form"),
            (String::new(), 80, "/origin/form".to_string())
        );
    }

    #[test]
    fn rewrite_preserves_all_other_bytes() {
        let head = b"GET http://a.test/x HTTP/1.1\r\nhOsT: a.test\r\nX-Odd:  1 \r\n\r\n";
        let out = rewrite_target(head, "/x");
        let s = String::from_utf8_lossy(&out);
        assert!(s.starts_with("GET /x HTTP/1.1\r\n"), "{s}");
        assert!(s.contains("hOsT: a.test\r\n"), "{s}");
        assert!(s.contains("X-Odd:  1 \r\n"), "{s}");
    }

    #[test]
    fn reads_content_length() {
        assert_eq!(
            content_length(b"POST / HTTP/1.1\r\nContent-Length: 42\r\n"),
            Some(42)
        );
        assert_eq!(content_length(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn finds_host_header_case_insensitively() {
        let h = b"GET / HTTP/1.1\r\nhOsT: x.test\r\n\r\n";
        assert_eq!(header_value(h, b"host").as_deref(), Some("x.test"));
    }
}
