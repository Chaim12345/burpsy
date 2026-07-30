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
use http::header::CONTENT_LENGTH;
use http::{Request, Response, Uri, Version};
use tokio::io::{AsyncRead, AsyncWrite};

use burpsy_core::{Direction, Exchange, Protocol, TrafficStore};
use burpsy_http2::normalise::{render_request, render_response};

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
            render_request(method.as_str(), &path, host, &header_list(&parts.headers), &req_body_bytes),
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
            render_response(status.as_u16(), &header_list(&resp_parts.headers), &resp_body_bytes),
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

/// Convert a typed header map into the verbatim-bytes field list `burpsy_http2::normalise`
/// renders — the same list the egress authoriser will extract a path from in a later slice, so
/// history and authorisation cannot render the same stream two different ways.
///
/// **This is where header-list-exactness's order guarantee already has a hole, and it predates
/// this function.** `http::HeaderMap`'s own docs say its iteration order is "arbitrary, but
/// consistent across platforms for the same crate version" [`http` 1.4.2,
/// `src/header/map.rs:36-41`] — not wire order. By the time a stream reaches this module the true
/// order the peer sent is already gone; this function is exact from here on (every field the map
/// holds is carried through, byte for byte, in whatever order the map gives them), but "from
/// here on" is doing real work in that sentence. The design's §5 names the fix: build the field
/// list from the tap's own decode instead of `h2`'s typed view, which is not yet wired (that is
/// slice 5/6's job).
///
/// One thing this function does improve on the renderer it replaces: a header value that fails
/// `HeaderValue::to_str` is no longer silently dropped. `as_bytes` hands back the raw octets
/// regardless, and header-list-exactness is `burpsy-http2`'s stated guarantee, not "exact unless
/// it's not UTF-8".
fn header_list(headers: &http::HeaderMap) -> Vec<(Bytes, Bytes)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                Bytes::copy_from_slice(name.as_str().as_bytes()),
                Bytes::copy_from_slice(value.as_bytes()),
            )
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::parse;

    fn b(s: &str) -> Bytes {
        Bytes::copy_from_slice(s.as_bytes())
    }

    /// The design's slice 3 requires this exact property, and it is why the renderer lives in
    /// `burpsy-http2` rather than here: `render_request`'s output must be the same shape
    /// `burpsy_core::parse` already understands, or an h2 exchange would sit in history as
    /// something every other tool mis-reads. `burpsy-http2` cannot assert this itself — it must
    /// not depend on `burpsy-core` — so the round trip is proved here, where the proxy already
    /// depends on both.
    #[test]
    fn render_request_output_parses_back_into_the_same_ordered_field_list() {
        let headers = [
            (b("Host"), b("example.com")),
            (b("X-Foo"), b("1")),
            (b("x-foo"), b("2")),
            (b("Accept"), b("*/*")),
        ];
        let body = b"hello world";
        let rendered = render_request("POST", "/x?y=1", "example.com", &headers, body);

        let shape = parse(&rendered, Direction::Request)
            .expect("a renderer whose own crate's tests already assert this shape must parse");

        assert_eq!(
            &rendered[shape.first_token.offset..shape.first_token.end()],
            b"POST",
            "the method must survive as the parser's first start-line token"
        );
        assert_eq!(
            &rendered[shape.second_token.offset..shape.second_token.end()],
            b"/x?y=1",
            "the path, including its query, must survive as the second start-line token"
        );
        assert_eq!(
            &rendered[shape.third_token.offset..shape.third_token.end()],
            b"HTTP/2",
            "the version token must be the h2 label, not a downgraded HTTP/1.1"
        );

        // The renderer appends a reconstructed `Content-Length` after the given fields (no
        // `Host` synthesis here, since one is already present) — so the parsed list is the
        // input list plus exactly that one trailing field, in the order the renderer writes it.
        let mut want: Vec<(Vec<u8>, Vec<u8>)> =
            headers.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect();
        want.push((b"Content-Length".to_vec(), body.len().to_string().into_bytes()));

        let got: Vec<(Vec<u8>, Vec<u8>)> = shape
            .headers
            .iter()
            .map(|hs| {
                (
                    rendered[hs.name.offset..hs.name.end()].to_vec(),
                    rendered[hs.value.offset..hs.value.end()].to_vec(),
                )
            })
            .collect();

        assert_eq!(
            got, want,
            "duplicate names, unusual casing and field order must all survive the round trip \
             through burpsy_core::parse, with only the reconstructed Content-Length added"
        );

        assert_eq!(
            &rendered[shape.body.offset..shape.body.end()],
            body,
            "the body must be recovered byte-for-byte at the offset the parser reports"
        );
    }

    /// `header_list` — the actual conversion the relay calls — must preserve duplicate values
    /// under one `HeaderName`, not just duplicate *entries* in a hand-built list. `HeaderMap`
    /// stores every `Set-Cookie` value under a single key and `iter()` yields the key once per
    /// associated value [`http` 1.4.2 `HeaderMap::iter` docs], so this is the property the unit
    /// tests on `Vec<(Bytes, Bytes)>` above cannot exercise on their own.
    #[test]
    fn header_list_and_render_request_together_preserve_duplicate_header_map_values() {
        let mut map = http::HeaderMap::new();
        map.append("set-cookie", http::HeaderValue::from_static("a=1"));
        map.append("set-cookie", http::HeaderValue::from_static("b=2"));

        let rendered = render_request("GET", "/", "example.com", &header_list(&map), b"");
        let shape = parse(&rendered, Direction::Request).expect("must parse");

        let cookies: Vec<&[u8]> = shape
            .headers
            .iter()
            .filter(|hs| rendered[hs.name.offset..hs.name.end()].eq_ignore_ascii_case(b"set-cookie"))
            .map(|hs| &rendered[hs.value.offset..hs.value.end()])
            .collect();

        assert_eq!(
            cookies,
            vec![b"a=1".as_slice(), b"b=2".as_slice()],
            "both Set-Cookie values from the HeaderMap must reach the parsed record, in order: \
             {:?}",
            String::from_utf8_lossy(&rendered)
        );
    }
}
