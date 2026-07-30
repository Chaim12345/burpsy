//! HTTP/2 relay: drive both legs of an intercepted, ALPN-negotiated `h2` connection and
//! reconstruct every stream as its own [`Exchange`].
//!
//! # Why this is a relay and not a byte pump
//!
//! HTTP/1 through this proxy is a byte pump: read one message, forward the bytes, read the answer.
//! HTTP/2 cannot be pumped. One TCP connection carries many concurrent streams, each independently
//! flow-controlled, and the header octets are HPACK indices into a dynamic table the two endpoints
//! built together — so the bytes a client sent are not the bytes the origin can decode. The `h2`
//! crate owns the frame layer, HPACK and multiplexing on both legs; this module is the glue that
//! reads a request off the client leg, re-lowers it onto the origin leg, and carries the answer
//! back, recording each round trip as a first-class exchange.
//!
//! # What is recorded, and the honest limit of that
//!
//! Each stream becomes an [`Exchange`] whose request and response are rendered in HTTP/1 shape
//! (start line + headers + body), exactly as [`Protocol::version_token`] intends: an h2 exchange
//! sits in history looking like an HTTP/1 one so every existing tool keeps working. The limit,
//! stated rather than hidden: **the stored bytes are a re-rendering, not the wire octets.** HPACK
//! makes byte-exact replay of a captured header block impossible (the indices mean nothing off
//! this connection), so "resend these exact bytes" has no h2 analogue. Header-*list* exactness is
//! preserved — field order, duplicates and unusual casing survive — and the body is byte-exact.
//!
//! # Interception is not wired here yet
//!
//! The HTTP/1 hold queue parses a request, parks it, and forwards what an operator approved. That
//! parser is HTTP/1-shaped; bolting it on here would mean re-rendering to bytes, letting an
//! operator edit bytes, and re-parsing to h2 — a round trip that can lose information. Until that
//! is designed, h2 streams are forwarded and recorded but not held. This is the same honest
//! partial the crate docs claim, now one step further: h2 is browsable and visible, not yet
//! editable.

use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use h2::server::SendResponse;
use http::header::{CONTENT_LENGTH, HOST};
use http::{Request, Response, Uri, Version};
use tokio::io::{AsyncRead, AsyncWrite};

use burpsy_core::{Direction, Exchange, Protocol, TrafficStore};

use crate::ProxyConfig;

/// Whether a header is connection-specific and must be dropped when re-lowering onto an h2 leg
/// (RFC 9113 §8.2.2). `host` is included because the authority travels as `:authority` on the way
/// out — carrying it as a plain header too would duplicate it.
fn is_hop_header(name: &http::header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

/// Relay HTTP/2 between an already-TLS-handshaked client leg and origin leg, recording each stream
/// as an exchange in `cfg.store`.
///
/// `authority` is the `host[:port]` the browser addressed (the CONNECT target), used as the
/// outgoing `:authority`. Both streams have completed TLS with ALPN selecting `h2`; this drives
/// the h2 handshake on each leg and then forwards streams until the client leg closes. A single
/// stream failing (origin reset, refused request) is recorded and skipped — one broken request
/// must not tear down the browser's whole session, which is exactly how a connection-level pump
/// would behave and the failure mode this relay exists to avoid.
pub async fn relay_h2<ClientIO, TargetIO>(
    client_io: ClientIO,
    target_io: TargetIO,
    cfg: &ProxyConfig,
    host: &str,
    port: u16,
    authority: &str,
) -> Result<()>
where
    ClientIO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    TargetIO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Server leg: the browser sent the connection preface; we accept it.
    let mut from_client = h2::server::handshake(client_io)
        .await
        .context("h2 handshake with the client")?;

    // Client leg: we send the preface to the origin. `handshake` returns the request handle and a
    // connection future that does no work until polled, so it must be driven on its own task for
    // the lifetime of the relay — every `send_request` below depends on it making progress.
    let (to_target, target_conn) = h2::client::handshake(target_io)
        .await
        .context("h2 handshake with the origin")?;
    tokio::spawn(async move {
        if let Err(e) = target_conn.await {
            tracing::debug!("origin h2 connection ended: {e}");
        }
    });

    tracing::debug!("h2 relay established for {host}:{port}");

    while let Some(accepted) = from_client.accept().await {
        let (request, respond) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("client h2 connection ended: {e}");
                break;
            }
        };
        let mut to_target = to_target.clone();
        let cfg = cfg.clone();
        let host = host.to_string();
        let authority = authority.to_string();
        // One task per stream so concurrent requests do not serialise behind each other's bodies.
        tokio::spawn(async move {
            if let Err(e) =
                relay_stream(request, respond, &mut to_target, &cfg, &host, port, &authority).await
            {
                tracing::debug!("h2 stream to {host}:{port} failed: {e}");
            }
        });
    }

    Ok(())
}

/// Forward one stream: buffer the request body, lower it onto the origin leg, buffer the answer,
/// and record the round trip as an exchange.
#[allow(clippy::too_many_arguments)]
async fn relay_stream(
    request: Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    to_target: &mut h2::client::SendRequest<Bytes>,
    cfg: &ProxyConfig,
    host: &str,
    port: u16,
    authority: &str,
) -> Result<()> {
    let store = &cfg.store;
    let started = Instant::now();

    let (parts, mut req_body) = request.into_parts();
    let method = parts.method.clone();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // Buffer the request body and release flow-control window as it arrives, or a large upload
    // stalls once it fills the default 64 KiB window.
    let req_body_bytes = drain_body(&mut req_body).await?;

    // Retention follows the same rule as the HTTP/1 path: scope gates what is STORED, never what
    // is forwarded. Out-of-scope streams are proxied but not kept. The exchange is created up
    // front — before the origin is contacted — so its id exists for the response to attach to, and
    // so a stream that fails mid-flight still leaves a request row in history.
    let ex_id = if cfg.scope.contains(host, port, &path, true) {
        let req_id = store.put(
            render_request_bytes(&method, &path, host, &parts.headers, &req_body_bytes),
            Direction::Request,
        );
        Some(store.add_exchange(Exchange {
            related: Vec::new(),
            protocol: Protocol::Http2,
            id: 0,
            request: req_id,
            response: None,
            host: host.to_string(),
            port,
            tls: true,
            method: method.to_string(),
            path: path.clone(),
            status: None,
            response_len: 0,
            started_ms: crate::now_ms(),
            duration_ms: 0,
            notes: None,
        }))
    } else {
        None
    };

    // Lower the request onto the origin leg. `h2` rebuilds the pseudo-headers from the typed
    // request; we hand it the header list minus the connection-specific ones it forbids.
    let out_req = build_outgoing_request(&method, &path, authority, &parts.headers)?;
    let (resp_fut, mut out_body) = to_target
        .send_request(out_req, req_body_bytes.is_empty())
        .context("forward request to the origin")?;
    if !req_body_bytes.is_empty() {
        send_body(&mut out_body, req_body_bytes).await?;
    }

    // The origin's answer. A reset or refusal is recorded as a failed exchange rather than dropped:
    // a stream the operator never sees in history looks like one that never happened.
    let response = match resp_fut.await {
        Ok(r) => r,
        Err(e) => {
            if let Some(ex_id) = ex_id {
                record_failed_response(store, ex_id, &e.to_string(), started);
            }
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
            return Err(e.into());
        }
    };

    let (resp_parts, mut resp_body) = response.into_parts();
    let status = resp_parts.status;
    let resp_body_bytes = drain_body(&mut resp_body).await?;

    // Forward the answer to the browser, then record it.
    let client_resp = build_outgoing_response(status, &resp_parts.headers)?;
    let mut to_client = respond
        .send_response(client_resp, resp_body_bytes.is_empty())
        .context("forward response to the client")?;
    if !resp_body_bytes.is_empty() {
        send_body(&mut to_client, resp_body_bytes.clone()).await?;
    }

    if let Some(ex_id) = ex_id {
        let resp_id = store.put(
            render_response_bytes(status, &resp_parts.headers, &resp_body_bytes),
            Direction::Response,
        );
        store.set_response(
            ex_id,
            resp_id,
            status.as_u16(),
            resp_body_bytes.len(),
            started.elapsed().as_millis() as u64,
        );
        crate::spawn_scan(cfg, ex_id, resp_id);
    }

    Ok(())
}

/// Read a stream's DATA frames to end-of-stream, releasing each frame's flow-control window as it
/// is consumed so the peer is never blocked on a window we have already drained.
async fn drain_body(body: &mut h2::RecvStream) -> Result<Bytes> {
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.context("reading an h2 body frame")?;
        let len = chunk.len();
        buf.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(len)
            .context("releasing h2 flow-control capacity")?;
    }
    Ok(Bytes::from(buf))
}

/// Send a buffered body on a stream, reserving window before each write. `h2` bounds a single
/// frame at 16 MiB and the peer's window may be smaller, so this loops over what capacity is
/// actually granted rather than assuming the whole body fits at once.
async fn send_body(stream: &mut h2::SendStream<Bytes>, body: Bytes) -> Result<()> {
    let mut remaining = body;
    while !remaining.is_empty() {
        stream.reserve_capacity(remaining.len());
        // Park until the peer grants window rather than spinning on `capacity()`. `capacity` can
        // legitimately be 0 right after reserving, and a `yield_now` loop would then burn a core
        // for as long as a slow reader keeps the window shut. `poll_capacity` registers a waker,
        // so waiting costs nothing; `None` means the stream will never grant more.
        let cap = match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(c) => c.context("waiting for h2 flow-control capacity")?,
            None => anyhow::bail!("the peer closed the stream before accepting the whole body"),
        };
        let n = remaining.len().min(cap);
        let chunk = remaining.split_to(n);
        let end = remaining.is_empty();
        stream
            .send_data(chunk, end)
            .context("sending an h2 body frame")?;
    }
    Ok(())
}

/// Render a request in HTTP/1 shape for the store: a start line, the header list, a
/// `Content-Length` reconstructed from the buffered body (h2 strips it on the way in), and the
/// body. This is the shape [`burpsy_core::parse`] understands, so the exchange's spans and every
/// downstream tool work unchanged.
fn render_request_bytes(
    method: &http::Method,
    path: &str,
    host: &str,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Bytes {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{method} {path} HTTP/2\r\n").as_bytes());
    let mut saw_host = false;
    for (name, value) in headers.iter() {
        if name == CONTENT_LENGTH {
            continue; // reconstructed from the buffered body below
        }
        if let Ok(v) = value.to_str() {
            out.extend_from_slice(format!("{}: {v}\r\n", name.as_str()).as_bytes());
            if name == HOST {
                saw_host = true;
            }
        }
    }
    if !saw_host {
        out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    Bytes::from(out)
}

/// Render a response in HTTP/1 shape for the store, reconstructing `Content-Length` the same way
/// the request renderer does.
fn render_response_bytes(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Bytes {
    let mut out = Vec::new();
    out.extend_from_slice(format!("HTTP/2 {}\r\n", status.as_u16()).as_bytes());
    for (name, value) in headers.iter() {
        if name == CONTENT_LENGTH {
            continue; // reconstructed from the buffered body below
        }
        if let Ok(v) = value.to_str() {
            out.extend_from_slice(format!("{}: {v}\r\n", name.as_str()).as_bytes());
        }
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    Bytes::from(out)
}

/// Build the typed request handed to the origin leg: pseudo-headers derived from the method, path
/// and authority, plus the header list with connection-specific headers removed.
fn build_outgoing_request(
    method: &http::Method,
    path: &str,
    authority: &str,
    headers: &http::HeaderMap,
) -> Result<Request<()>> {
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build()
        .context("building the outgoing request URI")?;
    let mut req = Request::builder()
        .method(method.clone())
        .uri(uri)
        .version(Version::HTTP_2);
    let h = req.headers_mut().context("request builder already errored")?;
    for (name, value) in headers.iter() {
        if is_hop_header(name) {
            continue;
        }
        h.append(name.clone(), value.clone());
    }
    req.body(()).context("assembling the outgoing request")
}

/// Build the typed response handed back to the client leg: the status plus the header list with
/// connection-specific headers and `Content-Length` removed (`h2` derives framing from the DATA
/// frames and rejects an explicit `Content-Length` that disagrees with them).
fn build_outgoing_response(
    status: http::StatusCode,
    headers: &http::HeaderMap,
) -> Result<Response<()>> {
    let mut resp = Response::builder().status(status).version(Version::HTTP_2);
    let h = resp.headers_mut().context("response builder already errored")?;
    for (name, value) in headers.iter() {
        if is_hop_header(name) || name == CONTENT_LENGTH {
            continue;
        }
        h.append(name.clone(), value.clone());
    }
    resp.body(()).context("assembling the outgoing response")
}

/// Record a stream whose origin response failed (reset, refusal, or transport error) so history
/// shows the request with a note rather than vanishing.
fn record_failed_response(store: &TrafficStore, ex_id: u64, reason: &str, started: Instant) {
    let note = Bytes::from(format!(
        "HTTP/2 502\r\nContent-Length: 0\r\nX-Burpsy-Error: {reason}\r\n\r\n"
    ));
    let resp_id = store.put(note, Direction::Response);
    store.set_response(
        ex_id,
        resp_id,
        502,
        0,
        started.elapsed().as_millis() as u64,
    );
}
