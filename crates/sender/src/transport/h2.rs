//! A single-stream h2 egress client: connect, preface, SETTINGS, one HEADERS
//! (+ `CONTINUATION` as needed), DATA, then read frames until `END_STREAM` or a deadline.
//!
//! # Why single-stream is the whole design, not a limitation to work around
//!
//! A general h2 client multiplexes streams, tracks per-stream flow-control windows, honours
//! `SETTINGS_MAX_CONCURRENT_STREAMS`, and reprioritises. None of that exists here, on purpose:
//! this client opens one connection, uses exactly stream 1, and never receives a second stream
//! from the peer because it never asks for one. That is what makes hand-rolling it viable — see
//! `crates/http2/src/lib.rs` for the parallel argument about the frame and HPACK layers this is
//! built on. The external `h2` crate stays a `proxy`-only dependency; duplicating it here would
//! trade "a small hand-written client we can reason about completely" for "a second, worse copy
//! of a general one."
//!
//! # Flow control is satisfied, not negotiated
//!
//! We advertise a large `SETTINGS_INITIAL_WINDOW_SIZE` and raise the connection-level window with
//! a `WINDOW_UPDATE` right after our `SETTINGS`, so a peer sending us a response never stalls
//! waiting for window we would otherwise have to top up mid-stream. We do not parse the peer's
//! `SETTINGS` for its own initial window or max frame size — for the short-lived, small-body
//! requests this client sends, the RFC 9113 defaults (65535-octet window, 16384-octet max frame)
//! the peer assumes until we've said otherwise are never exercised. A body large enough to hit
//! that ceiling is out of scope for a single-stream testing client.
//!
//! # `send_fields` vs `send_program`: honest vs. deliberately dishonest
//!
//! `send_fields` speaks the protocol: it HPACK-encodes a field list itself, so it ACKs the peer's
//! `SETTINGS` and `PING` because a real h2 server expects that courtesy from anything claiming to
//! speak h2. `send_program` does none of that — it writes `program.encode()` verbatim and reads
//! raw frames back with no interpretation, because H2-03 exists to emit octets the spec forbids
//! and a client that "corrected" or reacted to the peer mid-program would be lying about what was
//! actually put on the wire.

use anyhow::{Context, Result, anyhow, bail};
use burpsy_bcheck::eval::Target;
use burpsy_http2::{
    CONNECTION_PREFACE, Decoder, Encoder, FrameSpec, H2FrameProgram, RawFrame, Tail, flags,
    read_frames, types,
};
use bytes::{BufMut, Bytes, BytesMut};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use super::net::SendResult;

/// The only stream this client ever opens.
const STREAM_ID: u32 = 1;

/// `SETTINGS_INITIAL_WINDOW_SIZE`, RFC 9113 §6.5.2.
const SETTING_INITIAL_WINDOW_SIZE: u16 = 0x4;

/// The largest legal flow-control window (RFC 9113 §6.9.1: a `WINDOW_UPDATE` or
/// `SETTINGS_INITIAL_WINDOW_SIZE` above `2^31 - 1` is a `FLOW_CONTROL_ERROR`), and what we
/// advertise as our own per-stream initial window — see the module doc's "flow control" section.
const INITIAL_WINDOW_SIZE: u32 = (1 << 31) - 1;

/// How much to raise the connection-level window above its RFC-default starting value (65535)
/// via our post-`SETTINGS` `WINDOW_UPDATE`, so the connection-level window matches the per-stream
/// one we just advertised.
const CONNECTION_WINDOW_INCREMENT: u32 = INITIAL_WINDOW_SIZE - 65_535;

/// `SETTINGS_HEADER_TABLE_SIZE`'s RFC 9113 §6.5.2 default. We never send our own
/// `SETTINGS_HEADER_TABLE_SIZE`, so this is what both directions actually use: it bounds our
/// [`Decoder`] (the size we implicitly told the peer to encode against) and our [`Encoder`] (the
/// size we assume the peer will decode against, since we send our request before waiting to learn
/// otherwise from the peer's own `SETTINGS`).
const DEFAULT_HEADER_TABLE_SIZE: usize = 4096;

/// `SETTINGS_MAX_FRAME_SIZE`'s RFC 9113 §6.5.2 default — the largest frame payload we assume a
/// peer will accept, since (per the module doc) we do not parse the peer's `SETTINGS` to learn a
/// larger one before sending our own frames.
const DEFAULT_MAX_FRAME_SIZE: usize = 16_384;

/// Outcome of [`send_program`]: the frames read back, verbatim, with no protocol interpretation.
pub struct H2ProgramResult {
    /// The exact octets read off the socket after writing the program — not reassembled or
    /// reframed, because a malformed program is frequently one whose framing does not agree with
    /// what a spec-compliant reader would expect, and re-deriving frames from it would launder
    /// exactly the disagreement this exists to show.
    pub raw_frames: Bytes,
    pub duration: Duration,
    /// How many *complete* frames [`burpsy_http2::read_frames`] could parse out of `raw_frames`.
    /// A truncated tail (the peer closed mid-frame, or never sent enough to finish one) is not
    /// counted — inflating this to make a partial read look like a full frame would be exactly
    /// the "partial result looks complete" dishonesty this project refuses to ship.
    pub frames_read: usize,
}

/// The union of what both a plain [`TcpStream`] and a `tokio-rustls` client stream can do, so
/// [`connect`] can hand back one concrete type regardless of `target.tls`.
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Connect to `target`, negotiating h2 over ALPN when `target.tls` is set.
///
/// For plain-text targets this returns a bare TCP socket with no upgrade dance: the caller is
/// expected to write [`CONNECTION_PREFACE`] itself, which *is* the h2c "prior knowledge" mode
/// (RFC 9113 §3.3) — the operator asserted this target speaks h2, so there is nothing to sniff or
/// negotiate.
///
/// For TLS targets, ALPN offers `h2` and nothing else. A peer that completes the handshake without
/// selecting `h2` is a silent downgrade to whatever it did pick (most often `http/1.1`, or nothing
/// if it doesn't support ALPN at all) — continuing as if the caller's h2 request would still make
/// sense on that connection is exactly the kind of unproven-success claim this project refuses to
/// make, so it is a hard error naming what the peer selected instead.
async fn connect(target: &Target) -> Result<Box<dyn Stream>> {
    let addr = format!("{}:{}", target.host, target.port);
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connect {addr}"))?;
    tcp.set_nodelay(true).ok();

    if !target.tls {
        return Ok(Box::new(tcp));
    }

    // Reuse the one no-verify TLS config both other transports share (`super::tls`), but offer
    // ALPN `h2` only on the clone — this connection is exclusively for h2, so anything else the
    // shared config's default (no ALPN at all) might otherwise let through must not be offered.
    let mut cfg = (*super::tls::insecure_client_config()).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let dns = ServerName::try_from(target.host.clone())
        .map_err(|_| anyhow!("invalid DNS name {:?}", target.host))?;
    let tls = connector.connect(dns, tcp).await.context("tls handshake")?;

    match tls.get_ref().1.alpn_protocol() {
        Some(b"h2") => {}
        Some(other) => bail!(
            "peer selected {:?} via ALPN instead of h2 — refusing to speak h2 on a connection \
             it did not agree to",
            String::from_utf8_lossy(other)
        ),
        None => bail!("peer did not negotiate an ALPN protocol; h2 was required"),
    }
    Ok(Box::new(tls))
}

/// Write one frame: header then payload, in that order, nothing else.
async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, f: &FrameSpec) -> Result<()> {
    s.write_all(&f.header().encode())
        .await
        .context("write frame header")?;
    if !f.payload.is_empty() {
        s.write_all(&f.payload).await.context("write frame payload")?;
    }
    Ok(())
}

/// `SETTINGS` payload advertising our per-stream initial window — see the module doc.
fn settings_payload() -> Bytes {
    let mut buf = BytesMut::with_capacity(6);
    buf.put_u16(SETTING_INITIAL_WINDOW_SIZE);
    buf.put_u32(INITIAL_WINDOW_SIZE);
    buf.freeze()
}

/// A `WINDOW_UPDATE` payload: the 31-bit increment, top bit clear (RFC 9113 §6.9).
fn window_update_payload(increment: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_u32(increment & 0x7FFF_FFFF);
    buf.freeze()
}

/// Write the preface, our `SETTINGS`, and a connection-level `WINDOW_UPDATE` — the fixed prelude
/// every honest exchange on this client starts with (see the module doc's flow-control note for
/// why the `WINDOW_UPDATE` matters here and `connect`'s doc for why the preface alone is enough
/// for h2c).
async fn write_preface_and_settings<S: AsyncWrite + Unpin>(s: &mut S) -> Result<()> {
    s.write_all(CONNECTION_PREFACE)
        .await
        .context("write connection preface")?;
    write_frame(s, &FrameSpec::new(types::SETTINGS, 0, 0, settings_payload()))
        .await
        .context("write initial SETTINGS")?;
    write_frame(
        s,
        &FrameSpec::new(
            types::WINDOW_UPDATE,
            0,
            0,
            window_update_payload(CONNECTION_WINDOW_INCREMENT),
        ),
    )
    .await
    .context("write connection WINDOW_UPDATE")?;
    s.flush().await.ok();
    Ok(())
}

/// Split an HPACK-encoded header `block` into a `HEADERS` frame followed by zero or more
/// `CONTINUATION` frames, none exceeding `max_frame_size` octets of payload. `END_HEADERS` is set
/// only on the last frame; `END_STREAM` is set on the first (`HEADERS`) frame when `end_stream` is
/// true, since a request with no body ends the stream at the header block and RFC 9113 §6.2
/// defines `END_STREAM` only for `HEADERS`, never `CONTINUATION`.
///
/// None of our own output ever sets `PADDED` or `PRIORITY`, so every frame this produces carries
/// exactly one contiguous slice of `block` as its payload with nothing else to strip.
fn header_frames(block: &[u8], stream_id: u32, end_stream: bool, max_frame_size: usize) -> Vec<FrameSpec> {
    let chunks: Vec<&[u8]> = block.chunks(max_frame_size.max(1)).collect();
    let chunks = if chunks.is_empty() { vec![&[][..]] } else { chunks };
    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let ty = if i == 0 { types::HEADERS } else { types::CONTINUATION };
            let mut fl = 0u8;
            if i == last {
                fl |= flags::END_HEADERS;
            }
            if i == 0 && end_stream {
                fl |= flags::END_STREAM;
            }
            FrameSpec::new(ty, fl, stream_id, Bytes::copy_from_slice(chunk))
        })
        .collect()
}

/// Split `body` into `DATA` frames of at most `max_frame_size` octets each, `END_STREAM` on the
/// last one. Only called when `body` is non-empty, so `chunks` is never empty.
fn data_frames(body: &[u8], stream_id: u32, max_frame_size: usize) -> Vec<FrameSpec> {
    let chunks: Vec<&[u8]> = body.chunks(max_frame_size.max(1)).collect();
    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let fl = if i == last { flags::END_STREAM } else { 0 };
            FrameSpec::new(types::DATA, fl, stream_id, Bytes::copy_from_slice(chunk))
        })
        .collect()
}

/// Strip a frame's optional `PADDED` pad-length octet and trailing padding (RFC 9113 §6.1 DATA,
/// §6.2 HEADERS share this shape), returning the `[start, end)` range of the real payload within
/// `payload`. Bounds-checked against attacker-controlled lengths before any slicing happens.
fn strip_pad(payload: &Bytes, padded: bool) -> Result<(usize, usize)> {
    if !padded {
        return Ok((0, payload.len()));
    }
    let pad_len = *payload
        .first()
        .ok_or_else(|| anyhow!("frame too short to carry the PADDED pad-length octet"))? as usize;
    if payload.len() < 1 + pad_len {
        bail!("declared padding ({pad_len} octets) exceeds the frame's payload");
    }
    Ok((1, payload.len() - pad_len))
}

/// The header-block fragment inside one `HEADERS` frame's payload, with `PADDED` padding and a
/// `PRIORITY` prefix (stream dependency + weight, RFC 9113 §6.2) stripped if present.
fn headers_fragment(raw: &RawFrame) -> Result<Bytes> {
    let padded = raw.header.flags & flags::PADDED != 0;
    let (mut start, end) = strip_pad(&raw.payload, padded)?;
    if raw.header.flags & flags::PRIORITY != 0 {
        if end < start + 5 {
            bail!("HEADERS frame too short for its PRIORITY flag");
        }
        start += 5;
    }
    if end < start {
        bail!("HEADERS frame padding overlaps its fixed-size fields");
    }
    Ok(raw.payload.slice(start..end))
}

/// The data fragment inside one `DATA` frame's payload, with `PADDED` padding stripped if present.
fn data_fragment(raw: &RawFrame) -> Result<Bytes> {
    let padded = raw.header.flags & flags::PADDED != 0;
    let (start, end) = strip_pad(&raw.payload, padded)?;
    if end < start {
        bail!("DATA frame padding overlaps its data");
    }
    Ok(raw.payload.slice(start..end))
}

/// Read frames from `stream` until `stream_id`'s response is complete: its header block is fully
/// decoded and `END_STREAM` has been observed on it. Along the way, ACKs the peer's `SETTINGS` and
/// `PING` — the minimum a real h2 server expects even from a client this small — and treats
/// `RST_STREAM` on `stream_id` or a connection-wide `GOAWAY` as failures rather than partial
/// answers, since neither leaves us with a response the peer actually intended to complete.
async fn read_response<S>(
    stream: &mut S,
    stream_id: u32,
    decoder: &mut Decoder,
) -> Result<(Vec<(Bytes, Bytes)>, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = BytesMut::new();
    let mut header_block = BytesMut::new();
    let mut collecting_headers = false;
    let mut headers_done = false;
    let mut stream_ended = false;
    let mut response_headers = Vec::new();
    let mut body = Vec::new();

    loop {
        let n = stream
            .read_buf(&mut buf)
            .await
            .context("read h2 response")?;
        if n == 0 {
            bail!("peer closed the connection before stream {stream_id} completed");
        }

        let (frames, tail) = read_frames(&buf);
        for raw in &frames {
            match raw.header.ty {
                types::SETTINGS if raw.header.flags & flags::ACK == 0 => {
                    write_frame(stream, &FrameSpec::new(types::SETTINGS, flags::ACK, 0, Bytes::new()))
                        .await
                        .context("ack peer SETTINGS")?;
                }
                types::PING if raw.header.flags & flags::ACK == 0 => {
                    write_frame(
                        stream,
                        &FrameSpec::new(types::PING, flags::ACK, 0, raw.payload.clone()),
                    )
                    .await
                    .context("ack peer PING")?;
                }
                types::HEADERS if raw.header.stream_id_masked() == stream_id => {
                    header_block.extend_from_slice(&headers_fragment(raw)?);
                    collecting_headers = true;
                    if raw.header.flags & flags::END_HEADERS != 0 {
                        response_headers.extend(
                            decoder
                                .decode(&header_block)
                                .map_err(|e| anyhow!("decoding response HEADERS: {e}"))?,
                        );
                        header_block.clear();
                        collecting_headers = false;
                        headers_done = true;
                    }
                    if raw.header.flags & flags::END_STREAM != 0 {
                        stream_ended = true;
                    }
                }
                types::CONTINUATION if collecting_headers && raw.header.stream_id_masked() == stream_id => {
                    header_block.extend_from_slice(&raw.payload);
                    if raw.header.flags & flags::END_HEADERS != 0 {
                        response_headers.extend(
                            decoder
                                .decode(&header_block)
                                .map_err(|e| anyhow!("decoding response HEADERS/CONTINUATION: {e}"))?,
                        );
                        header_block.clear();
                        collecting_headers = false;
                        headers_done = true;
                    }
                }
                types::DATA if raw.header.stream_id_masked() == stream_id => {
                    body.extend_from_slice(&data_fragment(raw)?);
                    if raw.header.flags & flags::END_STREAM != 0 {
                        stream_ended = true;
                    }
                }
                types::RST_STREAM if raw.header.stream_id_masked() == stream_id => {
                    bail!("peer sent RST_STREAM on stream {stream_id}");
                }
                types::GOAWAY => {
                    bail!("peer sent GOAWAY before stream {stream_id} completed");
                }
                _ => {}
            }
        }

        let consumed = match tail {
            Tail::Complete => buf.len(),
            Tail::Incomplete { offset, .. } => offset,
        };
        let _ = buf.split_to(consumed);

        if headers_done && stream_ended {
            return Ok((response_headers, body));
        }
    }
}

/// HPACK-encode `fields` (in caller order, duplicates and all — see [`Encoder::encode`]'s own
/// contract), send them as HEADERS/CONTINUATION on stream 1, followed by `body` as DATA if
/// non-empty, then read the response back into a [`SendResult`] whose `raw_response` is
/// [`burpsy_http2::normalise::render_response`]'s rendering of the decoded status/headers/body —
/// the same shape every existing tool already consumes.
///
/// `timeout` bounds the whole call — connect, handshake, write, and read — not any single read.
pub(crate) async fn send_fields(
    target: &Target,
    fields: &[(Bytes, Bytes)],
    body: &[u8],
    timeout: Duration,
) -> Result<SendResult> {
    let started = Instant::now();

    let fut = async {
        let mut stream = connect(target).await?;
        write_preface_and_settings(&mut stream).await?;

        let mut encoder = Encoder::new(DEFAULT_HEADER_TABLE_SIZE);
        let block = encoder.encode(fields);
        let mut frames = header_frames(&block, STREAM_ID, body.is_empty(), DEFAULT_MAX_FRAME_SIZE);
        if !body.is_empty() {
            frames.extend(data_frames(body, STREAM_ID, DEFAULT_MAX_FRAME_SIZE));
        }
        for f in &frames {
            write_frame(&mut stream, f).await.context("write request frame")?;
        }
        stream.flush().await.ok();

        let mut decoder = Decoder::new(DEFAULT_HEADER_TABLE_SIZE);
        let (response_fields, resp_body) = read_response(&mut stream, STREAM_ID, &mut decoder).await?;

        let mut status = None;
        let mut headers = Vec::with_capacity(response_fields.len());
        for (name, value) in response_fields {
            if name.as_ref() == b":status" {
                status = std::str::from_utf8(&value)
                    .ok()
                    .and_then(|v| v.parse::<u16>().ok());
            } else if !name.starts_with(b":") {
                headers.push((name, value));
            }
        }
        let status = status.ok_or_else(|| anyhow!("h2 response carried no valid :status field"))?;
        let raw_response = burpsy_http2::normalise::render_response(status, &headers, &resp_body);
        Ok::<_, anyhow::Error>((raw_response, status))
    };

    let (raw_response, status) = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow!("timeout after {timeout:?}"))??;

    Ok(SendResult {
        raw_response,
        duration: started.elapsed(),
        status: Some(status),
    })
}

/// Write `program.encode()` verbatim — correcting, reordering, or adding nothing, because emitting
/// octets the spec forbids is H2-03's entire point — then read frames back until `program.read_for_ms`
/// elapses or the peer closes the connection, whichever comes first.
///
/// `program`'s own `preface` flag decides whether a preface goes out; this function never adds a
/// second one. `timeout` bounds the whole call, exactly as in [`send_fields`].
pub(crate) async fn send_program(
    target: &Target,
    program: &H2FrameProgram,
    timeout: Duration,
) -> Result<H2ProgramResult> {
    let started = Instant::now();
    let encoded = program.encode();
    let read_for = Duration::from_millis(program.read_for_ms);

    let fut = async {
        let mut stream = connect(target).await?;
        stream.write_all(&encoded).await.context("write program")?;
        stream.flush().await.ok();

        let mut buf = BytesMut::new();
        let mut chunk = [0u8; 16 * 1024];
        let read_until_close_or_deadline = async {
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e) => return Err(anyhow::Error::new(e).context("read h2 program response")),
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        // A peer that never closes must not hang this loop forever: `read_for_ms` bounds it
        // independently of the outer `timeout`. Elapsing here is not itself an error — whatever
        // was read by then is the honest answer, same as a peer that closed on its own.
        if let Ok(Err(e)) = tokio::time::timeout(read_for, read_until_close_or_deadline).await {
            return Err(e);
        }

        let (frames, _tail) = read_frames(&buf);
        Ok::<_, anyhow::Error>((Bytes::from(buf), frames.len()))
    };

    let (raw_frames, frames_read) = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow!("timeout after {timeout:?}"))??;

    Ok(H2ProgramResult {
        raw_frames,
        duration: started.elapsed(),
        frames_read,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TCP port on `127.0.0.1` guaranteed to be refusing connections: bind, read the ephemeral
    /// port back, then drop the listener before anything can connect to it.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.local_addr().expect("local_addr").port()
    }

    fn target(port: u16) -> Target {
        Target {
            host: "127.0.0.1".to_string(),
            port,
            tls: false,
        }
    }

    #[tokio::test]
    async fn send_fields_against_a_closed_port_fails_instead_of_hanging_or_panicking() {
        let result = send_fields(&target(closed_port()), &[], b"", Duration::from_secs(2)).await;
        assert!(
            result.is_err(),
            "a closed port refuses the TCP connect; that must surface as an error, not a hang"
        );
    }

    #[tokio::test]
    async fn send_program_against_a_closed_port_fails_instead_of_hanging_or_panicking() {
        let program = H2FrameProgram::default();
        let result = send_program(&target(closed_port()), &program, Duration::from_secs(2)).await;
        assert!(
            result.is_err(),
            "a closed port refuses the TCP connect; that must surface as an error, not a hang"
        );
    }

    #[test]
    fn a_single_frame_header_block_decodes_back_to_the_exact_ordered_field_list() {
        let fields = vec![
            (Bytes::from_static(b":method"), Bytes::from_static(b"GET")),
            (Bytes::from_static(b":path"), Bytes::from_static(b"/")),
            (Bytes::from_static(b"x-test"), Bytes::from_static(b"value")),
            // A duplicate name: header-list-exactness means duplicates survive, not collapse.
            (Bytes::from_static(b"x-test"), Bytes::from_static(b"second")),
        ];
        let mut encoder = Encoder::new(DEFAULT_HEADER_TABLE_SIZE);
        let block = encoder.encode(&fields);

        let frames = header_frames(&block, STREAM_ID, true, DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(
            frames.len(),
            1,
            "a header block this small must not be split — it is the control case for the split test"
        );
        assert_eq!(frames[0].ty, types::HEADERS);
        assert_ne!(
            frames[0].flags & flags::END_HEADERS,
            0,
            "the only frame in an unsplit block must carry END_HEADERS"
        );

        let mut decoder = Decoder::new(DEFAULT_HEADER_TABLE_SIZE);
        let decoded = decoder
            .decode(&frames[0].payload)
            .expect("our own writer's output must be valid HPACK");
        assert_eq!(
            decoded, fields,
            "decoding the frame our writer produced must return the exact ordered field list, \
             duplicates included, that the caller supplied"
        );
    }

    #[test]
    fn a_header_block_larger_than_one_frame_splits_into_headers_then_continuation() {
        let fields: Vec<(Bytes, Bytes)> = (0..2000)
            .map(|i| {
                (
                    Bytes::from(format!("x-header-{i}")),
                    Bytes::from("v".repeat(20)),
                )
            })
            .collect();
        let mut encoder = Encoder::new(DEFAULT_HEADER_TABLE_SIZE);
        let block = encoder.encode(&fields);
        assert!(
            block.len() > DEFAULT_MAX_FRAME_SIZE,
            "test setup is broken if the block does not exceed one frame: nothing would be exercised"
        );

        let frames = header_frames(&block, STREAM_ID, true, DEFAULT_MAX_FRAME_SIZE);
        assert!(
            frames.len() > 1,
            "a block bigger than one max-size frame must produce more than one frame"
        );
        assert_eq!(frames[0].ty, types::HEADERS, "the first frame must be HEADERS");
        for f in &frames[1..] {
            assert_eq!(
                f.ty,
                types::CONTINUATION,
                "every frame after the first in a split block must be CONTINUATION"
            );
        }
        for f in &frames[..frames.len() - 1] {
            assert_eq!(
                f.flags & flags::END_HEADERS,
                0,
                "only the final frame of a split header block may set END_HEADERS"
            );
        }
        assert_ne!(
            frames.last().unwrap().flags & flags::END_HEADERS,
            0,
            "the final frame of a split header block must set END_HEADERS"
        );

        let mut reassembled = BytesMut::new();
        for f in &frames {
            reassembled.extend_from_slice(&f.payload);
        }
        let mut decoder = Decoder::new(DEFAULT_HEADER_TABLE_SIZE);
        let decoded = decoder
            .decode(&reassembled)
            .expect("concatenating our HEADERS + CONTINUATION payloads must reproduce valid HPACK");
        assert_eq!(
            decoded, fields,
            "decoding the reassembled split block must return the exact original ordered field list"
        );
    }

    #[tokio::test]
    async fn send_fields_times_out_when_the_peer_accepts_and_then_sends_nothing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            // Accept and hold the connection open forever, sending nothing back — the peer this
            // test is about.
            if let Ok((socket, _)) = listener.accept().await {
                std::mem::forget(socket);
                std::future::pending::<()>().await;
            }
        });

        let started = Instant::now();
        let result = send_fields(
            &target(addr.port()),
            &[(Bytes::from_static(b":method"), Bytes::from_static(b"GET"))],
            b"",
            Duration::from_millis(300),
        )
        .await;
        let elapsed = started.elapsed();

        assert!(
            result.is_err(),
            "a peer that accepts and never responds must produce a timeout error, not a hang"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the call took {elapsed:?} against a 300ms timeout; the deadline is not being honoured"
        );
    }
}
