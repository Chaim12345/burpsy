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
//! # Interception
//!
//! Optional and off by default. When a hold queue is attached (see [`ProxyConfig::with_interceptor`]
//! and the [`intercept`] module), an in-scope request is parked before it is forwarded so an
//! operator can rewrite or refuse it. Out-of-scope traffic is never held, and holding one request
//! parks only its own connection task.
//!
//! Responses have their own hold point and their own condition list, and it is **inactive by
//! default**: switching the master switch on holds requests, exactly as it always has, and starts
//! holding responses only once the operator says so. See [`intercept`] for why the two lists differ.
//!
//! One consequence is structural and cannot be designed away. Streaming a response to the client and
//! holding it are mutually exclusive — a byte on the socket cannot be recalled — so the choice is
//! made *before* the response arrives, by [`Interceptor::may_hold_response`]. When it says yes the
//! response is buffered whole, and when it says no the bytes are relayed chunk by chunk exactly as
//! before. So a response condition costs latency on the routes it could match, and nothing anywhere
//! else.
//!
//! # HTTP/2, and exactly how far it goes
//!
//! An intercepted connection negotiates ALPN honestly: the client's own offer goes upstream, whatever
//! the target picks is what the client is then offered, and the answer is recorded on every
//! [`Exchange`] as [`Protocol`]. An h2-capable target is therefore **not** downgraded to HTTP/1.1
//! behind the operator's back, and the two legs of a connection always carry the same protocol.
//!
//! The switch that drives that offer is the master one, [`Interceptor::is_enabled`], and it stays
//! that way now that interception has condition lists: ALPN is settled from the ClientHello, before
//! any request exists for a condition to match. Conditions narrow what is *held*, never what is
//! *offered*, so an operator whose rules name one host still pays the downgrade on every host.
//!
//! The corollary: no condition of either list ever sees h2 traffic, because the hold queue is an
//! HTTP/1 parser and h2 streams are relayed at the frame level, not held for review. Consistent,
//! but worth knowing before writing a `status_code` rule and wondering why an h2-capable origin
//! never trips it.
//!
//! **HTTP/2 is relayed, not refused.** A connection that negotiates `h2` is driven by the `h2`
//! crate on both legs — every stream is forwarded to the origin and back, and each round trip is
//! recorded as an `Exchange` with `protocol: Protocol::Http2`. The relay renders each stream in
//! HTTP/1 shape for the store (start line + headers + body), so every existing tool keeps working.
//! The limit, stated rather than hidden: the stored bytes are a re-rendering, not the wire octets
//! — HPACK makes byte-exact replay of a captured header block impossible. Interception (the hold
//! queue) is not wired for h2 yet; streams are forwarded and recorded, not held for editing.
//!
//! Two other halves of "the tool uses HTTP/2 when the target supports it" remain outside this crate:
//! the scanner's audit egress and Intruder still speak HTTP/1.1 to every target, because
//! `burpsy_sender::AuthorisedSender` is not protocol-aware. Against an h2-only origin they fail
//! rather than downgrade. `.planning/ROADMAP.md` records H2-04 as Partial for these reasons — the
//! proxy relay is done, the sender egress is not.
//!
//! # Memory
//!
//! Bodies are read once, converted to `Bytes`, handed to the store. Nothing upstream keeps a second
//! copy — the [`Exchange`] carries `MsgId`s only.

use anyhow::{Context, Result};
use burpsy_core::{Direction, Exchange, Protocol, TrafficStore};
use bytes::Bytes;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Ceiling on a response buffered for operator review. The same 64 MiB `read_head` and `read_message`
/// stop at, because a response held for review has no EOF to rely on and the client is getting nothing
/// while it grows.
const MAX_BUFFERED_RESPONSE: usize = 64 * 1024 * 1024;

mod h2_relay;
pub mod intercept;

pub mod tls;
pub mod tls_policy;
pub mod ws;
pub use intercept::{
    Facts, HeldMeta, HeldView, InterceptRule, InterceptRuleSpec, InterceptRules, InterceptRulesSpec,
    Interceptor, MatchCategory, MatchField, Verdict,
};
pub use tls::{CertAuthority, TlsEngine, default_ca_dir, load_or_generate_ca};
pub use tls_policy::{TlsAction, TlsPolicy};
pub use ws::{WsCapture, WsStats};

/// Everything a connection handler needs.
#[derive(Clone)]
pub struct ProxyConfig {
    pub store: Arc<TrafficStore>,
    pub tls: Arc<TlsPolicy>,
    /// When present, `CONNECT` to a non-passthrough host is intercepted rather than tunnelled.
    pub engine: Option<Arc<TlsEngine>>,
    /// Gates what gets STORED. Out-of-scope traffic is still forwarded — otherwise pointing a
    /// browser at the proxy would break every site outside the engagement — it just is not kept.
    ///
    /// A [`burpsy_core::SharedScope`] rather than an `Arc<Scope>`, so an operator adding a host to
    /// scope from the UI changes what this proxy captures from the next request onwards. That is the
    /// widening the confirmation dialog in front of the API warns about: it does not retroactively
    /// capture anything, but everything after it lands in history.
    pub scope: burpsy_core::SharedScope,
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
            scope: burpsy_core::SharedScope::allow_everything(),
            scanner: None,
            intercept: None,
        }
    }

    pub fn with_scanner(mut self, s: Arc<burpsy_scanner::PassiveScanner>) -> Self {
        self.scanner = Some(s);
        self
    }

    /// Pass an owned `Scope` to start a fresh one, or a cloned [`burpsy_core::SharedScope`] to join
    /// the one the rest of the process is reading. The binary does the latter — a proxy on its own
    /// private copy would keep capturing by the startup rules after an operator edited them.
    pub fn with_scope(mut self, sc: impl Into<burpsy_core::SharedScope>) -> Self {
        self.scope = sc.into();
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
    // Where the terminator search has already looked. Without it, every 8 KiB chunk rescanned the
    // whole accumulated buffer from byte 0 — quadratic in body size, so a 64 MiB upload cost on the
    // order of 10^11 byte comparisons on the proxy's own read path. A proxy that gets slower as the
    // upload grows is a proxy people turn off, which is the failure this project exists to avoid.
    let mut searched = 0usize;
    let mut head_end: Option<usize> = None;
    loop {
        let n = s.read(&mut chunk).await.context("read request")?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if head_end.is_none() {
            // Resume 3 bytes back: the 4-byte terminator can straddle a chunk boundary, so the
            // overlap is what keeps the incremental search equivalent to rescanning.
            let from = searched.saturating_sub(3);
            head_end = find(&buf[from..], b"\r\n\r\n").map(|i| from + i);
            searched = buf.len();
        }
        if let Some(end) = head_end {
            let want = content_length(&buf[..end]).unwrap_or(0);
            if buf.len() >= end + 4 + want {
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
        // Forward transparently but do not retain. Interception is deliberately downstream of
        // this test: out-of-scope traffic is not the engagement's business, and holding it would
        // freeze whatever else the browser is doing. Not recorded at all — this is the ordinary,
        // expected case for everything outside scope, and a marker row per unrelated request
        // would make history noisier than the traffic anyone asked to see.
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
            let resp = dropped_response("request", &reason);
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

    // Scope was tested against the PRE-edit path; the operator may have rewritten it since. Scope
    // governs retention, not egress (see `ProxyConfig::scope`), so a request edited onto an
    // excluded path must not be stored or passively scanned — preventing exactly that retention is
    // what the exclusion is for. The request still goes out, as out-of-scope traffic always does.
    // Unlike the ordinary out-of-scope case above, this one *is* recorded: the request was already
    // shown to the operator as in-scope, so their own edit is what moved it out — silence here
    // would let them edit a request out of history and never know it happened.
    if !cfg.scope.contains(&host_only, port, &path, false) {
        record_scope_skip(&store, &host_only, port, false, &method, &path);
        return forward_only(client, upstream_req.to_vec(), &host_only, port).await;
    }

    let req_id = store.put(upstream_req.clone(), Direction::Request);
    let ex_id = store.add_exchange(Exchange {
        related: Vec::new(),
        protocol: Protocol::Http1,
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

    // Decided before the response exists, because streaming and holding are exclusive. Built from
    // the POST-edit method and path, so a response condition is judged against the request that
    // actually went out rather than the one that arrived.
    let meta = intercept::HeldMeta {
        host: host_only.clone(),
        port,
        tls: false,
        method: method.clone(),
        path: path.clone(),
    };
    let offer_response = will_offer_response(&cfg, &meta);

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

    // A `101 Switching Protocols` turns everything after it into WebSocket frames rather than more
    // HTTP, so an upgrade request has its response *head* read on its own before the streaming loop
    // below could mistake frames for a response body. Entered only when the client actually asked
    // for an upgrade, so every other request takes the identical path it always took.
    let mut prefix = Vec::new();
    if burpsy_core::ws::is_upgrade_request(&upstream_req) {
        let (head, rest) = read_response_head(&mut upstream).await;
        if burpsy_core::ws::is_upgrade_response(&head) {
            return relay_websocket(
                client,
                upstream,
                head,
                rest,
                &cfg,
                Some(ex_id),
                started,
                &host_only,
                port,
                false,
                &path,
            )
            .await;
        }
        // The origin refused the upgrade. What it sent is an ordinary response, and the bytes
        // already read are its beginning — hand them to the loop rather than losing them.
        prefix = head;
        prefix.extend_from_slice(&rest);
    }

    // Stream to the client while accumulating for the store — unless the response is going to be
    // offered for review, in which case nothing may reach the client until the verdict is in.
    let mut resp = prefix;
    if !resp.is_empty() && !offer_response {
        let _ = client.write_all(&resp).await;
    }
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        // Checked before reading, so a response already complete in the refused-upgrade prefix does
        // not wait on a read that will never return.
        if offer_response && response_is_complete(&resp, &meta.method) {
            break;
        }
        // Same cap, and for the same reason, as `read_head` and `read_message`. It matters more here:
        // a response whose framing never completes — SSE, a long poll, a chunked stream with no
        // terminator — has no EOF to stop on, and the client is receiving nothing while we wait. At
        // the cap we stop and offer what we have, exactly as those two do for a message this size.
        if offer_response && resp.len() > MAX_BUFFERED_RESPONSE {
            tracing::warn!(
                "{}:{port} response exceeded {MAX_BUFFERED_RESPONSE} bytes while being held for \
                 review; offering it truncated rather than buffering without limit",
                meta.host
            );
            break;
        }
        let n = upstream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&chunk[..n]);
        if !offer_response && client.write_all(&chunk[..n]).await.is_err() {
            break;
        }
    }

    // What the client actually receives is what history records, the same rule the request side
    // follows: an operator who rewrites a response must not find the origin's original in history,
    // because every later replay and every passive scan would work from bytes nobody saw.
    let mut resp = Bytes::from(resp);
    if offer_response {
        resp = match hold_response_for_review(&cfg, &meta, resp).await {
            Reviewed::Send(b) => b,
            // The exchange already exists, and the store has no "amend this message" operation, so
            // the refusal is recorded by the synthetic answer's own `X-Burpsy-Intercept` header
            // rather than by a note. It is the bytes the client got either way.
            Reviewed::Dropped { reason, .. } => dropped_response("response", &reason),
        };
        let _ = client.write_all(&resp).await;
    }
    let _ = client.flush().await;

    let status = parse_status(&resp);
    let len = resp.len();
    let resp_id = store.put(resp, Direction::Response);
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
    // An upgrade request needs both directions for the life of the connection, because after a `101`
    // the client keeps talking and a one-way copy would leave it able to receive and unable to send.
    // Gated on the request rather than applied unconditionally: an ordinary response ends at upstream
    // EOF, and additionally waiting for the client to close would hold a task per idle browser
    // connection. Nothing is recorded either way — out-of-scope traffic is forwarded, not retained.
    if burpsy_core::ws::is_upgrade_request(&req) {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
        return Ok(());
    }
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
        protocol: Protocol::Http1,
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
///
/// # Handshake ordering, and why it is this way round
///
/// The ClientHello is **peeked before anything is dialled**, via `LazyConfigAcceptor`. Two things
/// depend on that. The protocol offered upstream has to be the client's own offer (see
/// [`tls::alpn_offer`]), and the client-facing config has to name the single protocol the target then
/// picked — a config committed before the target answered cannot do either, and rustls has already
/// sent a fatal `NoApplicationProtocol` alert by the time you find out. It also keeps a client that
/// aborts the handshake, which is the normal outcome until the burpsy CA is installed, costing zero
/// upstream connections: peeking is cheap and needs no socket.
///
/// # HTTP/2 is negotiated and relayed
///
/// An h2-negotiated connection is driven by `h2_relay::relay_h2`: the `h2` crate owns both legs,
/// every stream is forwarded to the origin and back, and each round trip is recorded as an exchange
/// with `protocol: Protocol::Http2`. The hold queue does not apply to h2 streams — they are
/// forwarded and recorded, not held for editing. Downgrading to HTTP/1.1 would be the one thing
/// H2-04 forbids; the route to interception on an h2-capable origin is the hold queue's deliberate,
/// visible downgrade (switching interception on makes the offer `http/1.1` only).
async fn mitm(mut client: TcpStream, host: String, port: u16, cfg: ProxyConfig) -> Result<()> {
    use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

    let engine = cfg
        .engine
        .clone()
        .context("mitm called without a TLS engine")?;
    let store = cfg.store.clone();

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("write connect ok")?;

    // Peek only. No certificate is minted and no socket is opened until the client's offer is known.
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client);
    tokio::pin!(acceptor);
    let start = match acceptor.as_mut().await {
        Ok(s) => s,
        Err(e) => {
            // Almost always the CA not being trusted yet — worth saying so loudly once.
            tracing::warn!("client TLS hello failed for {host}: {e} (is the burpsy CA installed?)");
            return Ok(());
        }
    };
    let client_offer: Vec<Vec<u8>> = start
        .client_hello()
        .alpn()
        .map(|ps| ps.map(<[u8]>::to_vec).collect())
        .unwrap_or_default();

    // The operator's own switch, read per connection. Attached-but-off is not intercepting: it is
    // the toggle the API exposes that C6's downgrade has to follow, or the downgrade is caused by a
    // wiring decision the operator cannot see.
    let intercepting = cfg.intercept.as_ref().is_some_and(|ic| ic.is_enabled());
    let offer = tls::alpn_offer(&client_offer, intercepting);
    if !client_offer.is_empty() && offer.is_empty() {
        // Nothing the client will speak is anything we can carry. Recorded with the reason, because
        // a bare TLS alert leaves an operator with a browser error and no history row to explain it.
        let offered: Vec<String> = client_offer
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        record_failed_connect(
            &store,
            &host,
            port,
            &format!(
                "client offered ALPN [{}] and nothing there can be carried{}",
                offered.join(", "),
                if intercepting {
                    " while the interception hold queue is on"
                } else {
                    ""
                }
            ),
            Instant::now(),
        );
        return Ok(());
    }

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
    let connector = TlsConnector::from(tls::upstream_client_config(&offer));
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

    // What the target actually chose — not what we hoped for, and not a default.
    let negotiated: Option<Vec<u8>> = tls_upstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let protocol = match tls::negotiated_protocol(negotiated.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            record_failed_connect(&store, &host, port, &e.to_string(), connect_started);
            return Ok(());
        }
    };

    // Offer the client exactly the one protocol upstream settled on, so the two legs cannot differ.
    let client_alpn: Vec<Vec<u8>> = negotiated.into_iter().collect();
    let mut tls_client = match start
        .into_stream(Arc::new(engine.server_config(&host, &client_alpn)))
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "client TLS handshake failed for {host}: {e} (is the burpsy CA installed?)"
            );
            return Ok(());
        }
    };

    if protocol == Protocol::Http2 {
        // Relay the connection: drive h2 on both legs and record every stream as its own
        // exchange. This replaces the old record-and-close behaviour that made h2-capable
        // origins unbrowsable through the proxy. The HTTP/1 hold queue is not applied to h2
        // streams yet — they are forwarded and recorded, not held (see `h2_relay`).
        let authority = format!("{host}:{port}");
        return h2_relay::relay_h2(tls_client, tls_upstream, &cfg, &host, port, &authority)
            .await;
    }

    // Now it is just HTTP over two streams.
    loop {
        let req = match read_message(&mut tls_client).await {
            Ok(r) if !r.is_empty() => r,
            _ => break,
        };

        let (method, path) = start_line_parts(&req);
        // Scope was never tested for this loop at all before this line — unlike `forward_http`,
        // which gates once before the hold and once after. Test it now, against the pre-hold
        // path, so ordinary out-of-scope MITM traffic (never edited, never held) is forwarded
        // without being stored, exactly as `forward_http`'s line-256 gate does for plain HTTP.
        let in_scope_before = cfg.scope.contains(&host, port, &path, true);
        let req = match hold_for_review(&cfg, &host, port, true, &method, &path, Bytes::from(req))
            .await
        {
            Reviewed::Send(b) => b,
            Reviewed::Dropped { raw, reason } => {
                let resp = dropped_response("request", &reason);
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
        // Answered before `path` is moved into the exchange below, and cloned only for a request
        // that actually asked to upgrade — a per-request allocation on the keep-alive loop would be
        // paid by every ordinary request to buy nothing.
        let upgrade_requested = burpsy_core::ws::is_upgrade_request(&req);
        let ws_path = upgrade_requested.then(|| path.clone());

        // Scope was tested against the PRE-edit path above; the operator may have rewritten it
        // since. Scope governs retention, not egress (see `ProxyConfig::scope`), so a request
        // edited onto an excluded path must not be stored or passively scanned, but it still goes
        // out — this is the identical rule `forward_http` applies at its own post-edit check.
        let in_scope_after = cfg.scope.contains(&host, port, &path, true);
        let retain = in_scope_before && in_scope_after;
        // Only a request that WAS in scope and got edited out of it is worth a history row: the
        // operator saw it as in-scope before touching it. Ordinary out-of-scope MITM traffic that
        // was never held (see `hold_for_review`'s internal scope test) gets none, matching
        // `forward_http`'s line-256 gate, which also stays silent for traffic nobody asked to see.
        if in_scope_before && !in_scope_after {
            record_scope_skip(&store, &host, port, true, &method, &path);
        }

        // As on the plain path, decided before the response exists and from the post-edit facts.
        // Built here rather than beside the read loop because the exchange below moves `method` and
        // `path` into the row it stores.
        let meta = intercept::HeldMeta {
            host: host.clone(),
            port,
            tls: true,
            method: method.clone(),
            path: path.clone(),
        };
        let offer_response = will_offer_response(&cfg, &meta);

        let ex_id = retain.then(|| {
            let req_id = store.put(req.clone(), Direction::Request);
            store.add_exchange(Exchange {
                related: Vec::new(),
                // The protocol this connection actually negotiated. `Http1` here is a measurement,
                // not a default: the h2 arm returned above, so reaching this line means ALPN
                // settled on http/1.1 or the target sent no ALPN extension at all.
                protocol,
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
            })
        });

        let started = Instant::now();
        if tls_upstream.write_all(&req).await.is_err() {
            break;
        }
        tls_upstream.flush().await.ok();

        // Same reasoning as the plain path: a `101` means the rest of this connection is frames, so
        // an upgrade request's response head is read on its own before the loop below could take
        // frames for a body. Note this also ends the keep-alive loop — after an upgrade there are no
        // more HTTP requests on this connection, by definition.
        let mut prefix = Vec::new();
        if upgrade_requested {
            let (head, rest) = read_response_head(&mut tls_upstream).await;
            if burpsy_core::ws::is_upgrade_response(&head) {
                return relay_websocket(
                    tls_client,
                    tls_upstream,
                    head,
                    rest,
                    &cfg,
                    ex_id,
                    started,
                    &host,
                    port,
                    true,
                    ws_path.as_deref().unwrap_or_default(),
                )
                .await;
            }
            prefix = head;
            prefix.extend_from_slice(&rest);
        }

        let mut resp = prefix;
        let mut chunk = vec![0u8; 16 * 1024];
        let mut client_gone = false;
        // Nothing reaches the client before the verdict when the response is being offered.
        if !resp.is_empty() && !offer_response && tls_client.write_all(&resp).await.is_err() {
            client_gone = true;
        }
        while !client_gone {
            // Checked before reading rather than after writing, so a response already complete in
            // the refused-upgrade prefix does not wait on a read that will never return.
            if response_is_complete(&resp, &meta.method) {
                break;
            }
            if offer_response && resp.len() > MAX_BUFFERED_RESPONSE {
                tracing::warn!(
                    "{host}:{port} response exceeded {MAX_BUFFERED_RESPONSE} bytes while being held \
                     for review; offering it truncated rather than buffering without limit"
                );
                break;
            }
            // A read error is treated as end of stream: we already have whatever the server
            // managed to send, and surfacing the error would discard a usable partial response.
            let n = tls_upstream.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            resp.extend_from_slice(&chunk[..n]);
            // Nothing reaches the client before the verdict when the response is being offered.
            if !offer_response && tls_client.write_all(&chunk[..n]).await.is_err() {
                client_gone = true;
                break;
            }
        }

        // Same rule as the request half and as the plain-HTTP path: history records the bytes the
        // client actually received, not the ones the origin sent.
        let mut resp = Bytes::from(resp);
        if offer_response {
            resp = match hold_response_for_review(&cfg, &meta, resp).await {
                Reviewed::Send(b) => b,
                Reviewed::Dropped { reason, .. } => dropped_response("response", &reason),
            };
            if tls_client.write_all(&resp).await.is_err() {
                client_gone = true;
            }
        }
        let _ = tls_client.flush().await;

        // Out-of-scope traffic (before or after the edit) is relayed above like any other request;
        // it is simply never given an exchange to attach a response to.
        if let Some(ex_id) = ex_id {
            let status = parse_status(&resp);
            let len = resp.len();
            let resp_id = store.put(resp, Direction::Response);
            store.set_response(
                ex_id,
                resp_id,
                status.unwrap_or(0),
                len,
                started.elapsed().as_millis() as u64,
            );
            spawn_scan(&cfg, ex_id, resp_id);
        }

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
    // Same incremental terminator search as `read_head`, for the same reason — this is the MITM
    // loop's read path, so it carries every intercepted request and response.
    let mut searched = 0usize;
    let mut head_end: Option<usize> = None;
    loop {
        let n = s.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if head_end.is_none() {
            let from = searched.saturating_sub(3);
            head_end = find(&buf[from..], b"\r\n\r\n").map(|i| from + i);
            searched = buf.len();
        }
        if let Some(end) = head_end {
            let want = content_length(&buf[..end]).unwrap_or(0);
            if buf.len() >= end + 4 + want {
                break;
            }
        }
        if buf.len() > 64 * 1024 * 1024 {
            break;
        }
    }
    Ok(buf)
}

/// Read only as far as the end of the response headers, returning `(head, bytes read past it)`.
///
/// Separate from [`read_message`] because that one reads a *whole* message, which for a `101` is a
/// contradiction: there is no body, the connection does not close, and the next bytes are frames. So
/// the leftover is returned rather than swallowed — a server is free to put its first frames in the
/// same segment as the handshake response, and dropping them would lose the opening of every
/// conversation.
///
/// Never fails: a read error or EOF yields whatever arrived, and the caller's `is_upgrade_response`
/// test then simply says no.
async fn read_response_head<S>(s: &mut S) -> (Vec<u8>, Vec<u8>)
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = vec![0u8; 4096];
    // Same incremental terminator search, with the same 3-byte resume overlap, as `read_head`.
    let mut searched = 0usize;
    loop {
        let from = searched.saturating_sub(3);
        if let Some(i) = find(&buf[from..], b"\r\n\r\n") {
            let rest = buf.split_off(from + i + 4);
            return (buf, rest);
        }
        searched = buf.len();
        // A handshake answer is a few hundred bytes. This bound exists so a peer that never sends a
        // terminator cannot make us buffer without limit.
        if buf.len() > 256 * 1024 {
            return (buf, Vec::new());
        }
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return (buf, Vec::new()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Record the `101`, then relay frames until the connection closes.
///
/// The handshake response is stored **before** the relay starts, not after it ends. A WebSocket can
/// stay open for hours, and an exchange whose response only appears when the socket finally closes
/// would leave history showing a request that never got an answer for the entire session.
#[allow(clippy::too_many_arguments)]
async fn relay_websocket<C, U>(
    mut client: C,
    upstream: U,
    head: Vec<u8>,
    rest: Vec<u8>,
    cfg: &ProxyConfig,
    exchange: Option<u64>,
    started: Instant,
    host: &str,
    port: u16,
    tls: bool,
    path: &str,
) -> Result<()>
where
    C: tokio::io::AsyncRead + AsyncWriteExt + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if client.write_all(&head).await.is_err() {
        return Ok(());
    }
    let _ = client.flush().await;

    if let Some(ex_id) = exchange {
        let len = head.len();
        let resp_id = cfg.store.put(Bytes::from(head), Direction::Response);
        // 101 by construction: the caller reached here only because `is_upgrade_response` said so.
        cfg.store
            .set_response(ex_id, resp_id, 101, len, started.elapsed().as_millis() as u64);
    }

    let capture = exchange.map(|ex| {
        ws::WsCapture::new(
            cfg.store.clone(),
            ex,
            cfg.scope.clone(),
            host,
            port,
            tls,
            path,
        )
    });
    let stats = ws::relay(client, upstream, &rest, capture).await;
    // The skipped count is named unconditionally, including when it is zero: "0 excluded" and a
    // sentence that simply omits the subject are not the same statement to someone checking coverage.
    tracing::info!(
        "websocket {host}:{port}{path} closed: {} message(s) captured, {} excluded by scope, \
         {} up / {} down",
        stats.messages,
        stats.skipped_out_of_scope,
        stats.up,
        stats.down
    );
    if let Some(reason) = stats.capture_stopped {
        record_ws_capture_stopped(&cfg.store, host, port, tls, path, &reason);
    }
    Ok(())
}

/// Record that a WebSocket connection's message index stopped short, and why.
///
/// A marker exchange rather than silence, for the same reason [`record_failed_connect`] writes one: a
/// history that shows 40 messages on a socket that carried 4000 is worse than one that says it lost
/// track. This is written when the connection ends, so it sits after the messages it is qualifying.
/// The frames themselves were relayed unmodified throughout — the note says so, because an operator
/// reading "capture stopped" will otherwise reasonably wonder whether their app broke.
fn record_ws_capture_stopped(
    store: &TrafficStore,
    host: &str,
    port: u16,
    tls: bool,
    path: &str,
    reason: &str,
) -> u64 {
    let marker = Bytes::from(format!(
        "WEBSOCKET {path} — capture stopped\r\nHost: {host}:{port}\r\n\r\n"
    ));
    let req_id = store.put(marker, Direction::Request);
    let ex_id = store.add_exchange(Exchange {
        related: Vec::new(),
        protocol: Protocol::Http1,
        id: 0,
        request: req_id,
        response: None,
        host: host.to_string(),
        port,
        tls,
        method: "WEBSOCKET".into(),
        path: path.to_string(),
        status: None,
        response_len: 0,
        started_ms: now_ms(),
        duration_ms: 0,
        notes: Some(format!("websocket capture stopped — {reason}")),
    });
    let synthetic = ws::capture_stopped_marker(reason);
    let len = synthetic.len();
    let resp_id = store.put(synthetic, Direction::Response);
    store.set_response(ex_id, resp_id, 0, len, 0);
    ex_id
}

/// Total expected response length if framing is known, so keep-alive does not stall us.
///
/// `head_only` must be true when the request was a `HEAD`: nothing in a response reveals that, and a
/// `HEAD` answer carries the `Content-Length` a `GET` would have returned without the body to match.
///
/// **Bodiless statuses are checked BEFORE the framing headers.** A `204` and a `304` legitimately echo
/// a length they will not send, so reading `Content-Length` first is what stalls a read loop waiting
/// for bytes the origin never sends. That was survivable while this only trimmed a streamed relay —
/// the client already had the bytes — but it is not survivable now that it is the exit condition for
/// *buffering a response for review*: the stall happens before the response is offered, so it is not
/// in the hold queue and the operator has nothing to release. A browser with a warm cache emits `304`s
/// continuously, so one active response rule was enough to wedge it.
///
/// This is the same conclusion `complete_len` in `crates/sender/src/transport/net.rs` reached for the
/// sender's own read path. The two are deliberately separate copies: framing sits on each crate's hot
/// path and neither crate depends on the other. A third caller should push it into `burpsy-core`.
fn response_complete_len(buf: &[u8], head_only: bool) -> Option<usize> {
    let head_end = find(buf, b"\r\n\r\n").map(|i| i + 4)?;
    let lower = buf[..head_end].to_ascii_lowercase();
    if head_only || parse_status_at(&lower).is_some_and(|c| c == 204 || c == 304) {
        return Some(head_end);
    }
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

/// Has the origin said everything it is going to say?
///
/// The one place the three framing rules meet: step over interim `1xx` heads, then ask whether the
/// final response is complete, given whether the request was a `HEAD`. Both response loops call this
/// rather than `response_complete_len` directly, so neither can forget one of the three.
fn response_is_complete(resp: &[u8], method: &str) -> bool {
    let start = final_response_start(resp);
    let head_only = method.eq_ignore_ascii_case("HEAD");
    response_complete_len(&resp[start..], head_only)
        .is_some_and(|total| resp.len() - start >= total)
}

/// Where the *final* response begins: the offset past any interim `1xx` heads in front of it.
///
/// A `100 Continue` or a `103 Early Hints` (which CDNs send routinely) is complete at the end of its
/// own head and carries no body, but it is not an answer — the real response follows on the same
/// connection. Four separate things have to measure from the final head or they all read the interim
/// one instead: framing (a `500` behind a `103` frames as unterminated and hangs the hold), condition
/// matching (a `status_code` rule tests `103` and never fires), the recorded status (history says
/// `103`), and re-deriving `Content-Length` on an edited response (the length lands in the `103`'s
/// headers and describes the real response as its body). Loops, because both interim statuses can
/// arrive before the final one.
///
/// `pub` for that fourth caller: the API layer's response editor is in `burpsy-web` and needs the same
/// answer. A local copy there would be a second definition of where a response starts, which is how
/// two halves of one feature end up disagreeing about the same bytes.
pub fn final_response_start(buf: &[u8]) -> usize {
    let mut start = 0usize;
    while let Some(rel) = find(&buf[start..], b"\r\n\r\n").map(|i| i + 4) {
        if parse_status_at(&buf[start..start + rel]).is_some_and(|c| (100..200).contains(&c)) {
            start += rel;
        } else {
            break;
        }
    }
    start
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

/// `pub(crate)` for `intercept`: a condition on a message's content type has to read the same header
/// the rest of the proxy reads, and two parsers that disagree would make a rule fire here and not
/// there.
pub(crate) fn header_value(head: &[u8], name: &[u8]) -> Option<String> {
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

/// The status of the response in `buf`, skipping any interim `1xx` heads in front of it.
///
/// `pub(crate)` for `intercept`, which shows the operator a held response's status and matches
/// conditions against it. Both want the answer, not the `103` that preceded it.
pub(crate) fn parse_status(buf: &[u8]) -> Option<u16> {
    parse_status_at(&buf[final_response_start(buf)..])
}

/// The status on the start line at `buf[0]`, whatever it is. The interim-skipping wrapper above is
/// what callers want; this is the primitive it and the framing check are both built from.
fn parse_status_at(buf: &[u8]) -> Option<u16> {
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
/// The scope test is repeated here even though `forward_http` and `mitm` each make it again after
/// this call, at the post-edit point: this one decides whether to hold at all, theirs decide
/// whether to retain what was actually sent. "Out-of-scope traffic passes through untouched" has
/// to hold for every caller and at every point an edit could move something out of scope, not just
/// the one that happens to check first.
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

/// Park a complete response for operator review, if a response condition wants it held.
///
/// Mirrors [`hold_for_review`], including the repeated scope test, for the same reason: "out-of-scope
/// traffic passes through untouched" has to hold at every point something could be held, not only at
/// the one that happens to check first. The interceptor tests its own condition list, so a response
/// this reaches can still be released untouched — [`will_offer_response`] only decides whether the
/// question is worth asking, and the two answers differ precisely when a condition needed the
/// response's own status or content type to settle.
async fn hold_response_for_review(
    cfg: &ProxyConfig,
    meta: &intercept::HeldMeta,
    raw: Bytes,
) -> Reviewed {
    let Some(ic) = cfg.intercept.as_ref() else {
        return Reviewed::Send(raw);
    };
    if !cfg.scope.contains(&meta.host, meta.port, &meta.path, meta.tls) {
        return Reviewed::Send(raw);
    }
    match ic.hold_response(meta.clone(), raw.clone()).await {
        intercept::Verdict::Forward(b) => Reviewed::Send(b),
        intercept::Verdict::Drop(reason) => Reviewed::Dropped { raw, reason },
    }
}

/// Whether this exchange's response must be buffered whole before the client sees any of it.
///
/// The pre-response half of the decision above, and the only one that can be made in time: bytes
/// already written to the client cannot be recalled, so the choice between relaying and holding has
/// to be taken before the first of them arrives. `false` leaves the streaming relay byte-for-byte as
/// it was, which is what every request on a route no response condition names gets.
fn will_offer_response(cfg: &ProxyConfig, meta: &intercept::HeldMeta) -> bool {
    cfg.intercept
        .as_ref()
        .is_some_and(|ic| ic.may_hold_response(meta))
        && cfg.scope.contains(&meta.host, meta.port, &meta.path, meta.tls)
}

/// The answer a client gets when the operator drops half of an exchange — `what` names which.
///
/// A real status rather than a closed socket: a client that sees the connection die cannot tell an
/// operator's decision from a network fault, and browsers retry the latter. 403 is what a refusing
/// proxy is supposed to say, and the header makes the origin of the refusal unambiguous. A suppressed
/// *response* gets the same treatment and the same status — the origin answered, and the operator is
/// the one forbidding the client that answer.
fn dropped_response(what: &str, reason: &str) -> Bytes {
    let body = format!("burpsy: {what} dropped by operator ({reason})");
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
        protocol: Protocol::Http1,
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

/// Record that an operator's own edit moved an already-shown request onto an excluded path.
///
/// Scope governs retention, not egress (see `ProxyConfig::scope`): the request still reaches its
/// origin exactly as ordinary out-of-scope traffic does, so this is called right before the
/// transparent forward, never instead of it. What it must not do is store the edited bytes — that
/// is the whole point of the exclusion — so a synthetic marker stands in for them, the same trade
/// `tunnel` makes for a passed-through `CONNECT`: the *fact* that scope stopped retention belongs
/// in history, the excluded content does not. Called for both plain HTTP and MITM; unlike ordinary
/// out-of-scope traffic, this is worth a row because the operator saw the request as in-scope
/// before editing it — their own edit is what moved it out, and silence here would hide that.
fn record_scope_skip(store: &TrafficStore, host: &str, port: u16, tls: bool, method: &str, path: &str) {
    let marker = Bytes::from(format!(
        "{method} {path} — edited onto an excluded path; forwarded to the origin, not retained\r\n\r\n"
    ));
    let req_id = store.put(marker, Direction::Request);
    store.add_exchange(Exchange {
        related: Vec::new(),
        protocol: Protocol::Http1,
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
        notes: Some(
            "edited onto an excluded path: forwarded to the origin, not retained".to_string(),
        ),
    });
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
        protocol: Protocol::Http1,
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
pub(crate) fn spawn_scan(cfg: &ProxyConfig, exchange_id: u64, response_id: burpsy_core::MsgId) {
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

pub(crate) fn now_ms() -> u64 {
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

    /// The incremental header-terminator search in `read_head`/`read_message` must find exactly what
    /// a full rescan would, including when the four-byte terminator straddles a chunk boundary.
    ///
    /// Written as a property over every possible split rather than a couple of hand-picked offsets,
    /// because the failure mode is a specific alignment: resume without the 3-byte overlap and the
    /// terminator is missed only when it happens to span the seam, which no fixed-size fixture is
    /// guaranteed to hit.
    #[test]
    fn the_incremental_terminator_search_agrees_with_a_full_rescan_at_every_split() {
        let msg: &[u8] = b"POST /upload HTTP/1.1\r\nHost: x.test\r\nContent-Length: 5\r\n\r\nhello";
        let full = find(msg, b"\r\n\r\n").expect("the terminator is present");

        for split in 1..msg.len() {
            // Feed the message as two chunks split at every possible offset, mirroring the loop's
            // resume logic exactly.
            let mut buf: Vec<u8> = Vec::new();
            let mut searched = 0usize;
            let mut head_end: Option<usize> = None;

            for part in [&msg[..split], &msg[split..]] {
                buf.extend_from_slice(part);
                if head_end.is_none() {
                    let from = searched.saturating_sub(3);
                    head_end = find(&buf[from..], b"\r\n\r\n").map(|i| from + i);
                    searched = buf.len();
                }
            }

            assert_eq!(
                head_end,
                Some(full),
                "split at {split} found {head_end:?}, but a full rescan finds {full} — the resume \
                 overlap is not covering a terminator that straddles the seam"
            );
        }
    }

    /// A buffer with no terminator yet must keep reading rather than settle on a wrong answer.
    #[test]
    fn an_incomplete_head_reports_no_terminator_rather_than_guessing() {
        let mut buf: Vec<u8> = Vec::new();
        let mut searched = 0usize;
        let mut head_end: Option<usize> = None;
        for part in [&b"GET / HTTP/1.1\r\n"[..], &b"Host: x.test\r\n"[..]] {
            buf.extend_from_slice(part);
            if head_end.is_none() {
                let from = searched.saturating_sub(3);
                head_end = find(&buf[from..], b"\r\n\r\n").map(|i| from + i);
                searched = buf.len();
            }
        }
        assert_eq!(
            head_end, None,
            "no CRLFCRLF has arrived, so there is no head end yet"
        );
    }

    #[test]
    fn finds_host_header_case_insensitively() {
        let h = b"GET / HTTP/1.1\r\nhOsT: x.test\r\n\r\n";
        assert_eq!(header_value(h, b"host").as_deref(), Some("x.test"));
    }
}
