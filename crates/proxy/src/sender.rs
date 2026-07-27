//! Blocking outbound sender for active checks.
//!
//! # Why blocking, inside an async crate
//!
//! The BCheck evaluator is synchronous and recursive. Making it async would force `Box::pin` through
//! `exec` and `eval_bool` for no benefit, since active checks are rate-limited by design — the
//! bottleneck is deliberate delay, not thread count. So the evaluator runs on a blocking pool and
//! this sender uses `std::net` directly.
//!
//! # Why certificate verification is off
//!
//! Reusing [`crate::tls::upstream_client_config`], which does not verify certificates. That is
//! correct here and would be wrong almost anywhere else: a scanner exists to test hosts whose TLS is
//! frequently self-signed, expired, or misconfigured, and refusing to connect would silently skip
//! exactly the targets most likely to be vulnerable. Nothing confidential is sent to these hosts
//! that the base request did not already carry.
//!
//! # Why `Connection: close` was the whole story, and what replaced it
//!
//! Originally every probe closed its connection, so a response with neither `Content-Length` nor
//! chunked framing terminated at EOF instead of hanging until the read timeout. That property is
//! not negotiable: an unframed response has no in-band end marker, and only the socket closing
//! tells you where it stopped.
//!
//! But 127 active checks against one exchange meant 127 handshakes, which on TLS is most of the
//! wall-clock cost of an audit. So there is now a keep-alive path, built so the property above
//! survives intact:
//!
//! * The **first** probe to a given `(host, port, tls)` always goes out `Connection: close`, exactly
//!   as before. Whatever framing that target uses, the probe that discovers it is the one that
//!   cannot hang.
//! * That first response is classified. Only a response that declared a `Content-Length` and ended
//!   **exactly** there promotes the target to keep-alive. Anything else — chunked, unframed,
//!   truncated at the size cap, or a byte longer than it claimed — pins the target to
//!   close-per-probe permanently.
//! * A connection goes back in the pool only after a response that was again exactly
//!   `Content-Length`-framed and did not ask to close.
//!
//! Chunked responses are deliberately excluded even though they are self-terminating, because
//! [`response_complete`] finds the terminal chunk with a substring scan: a body that merely contains
//! `0\r\n\r\n` reads as complete early. Under close-per-probe the leftover bytes die with the
//! socket. Under reuse they would become the *next* probe's response, and a check would report on a
//! response that belongs to a different request. A phantom finding is the worst thing a scanner can
//! produce, so the parser's imprecision is contained rather than trusted.
//!
//! # The escape hatch
//!
//! [`probe_wants_close`] keeps a probe off the shared connection when it is unparsable (sent
//! verbatim — nothing can be assumed about it), when it carries `Transfer-Encoding` or is not
//! HTTP/1.1 (request-smuggling probes exist precisely to make two parsers disagree about where the
//! request ends), or when the caller already wrote `Connection: close`. `NetSender::without_reuse`
//! turns the whole pool off.

use burpsy_bcheck::eval::{Sender, Target};
use burpsy_core::edit::RequestEdit;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Sends probe requests over TCP, with TLS when the target requires it.
pub struct NetSender {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    /// Hard cap on a response body, so a hostile or broken server cannot exhaust memory.
    pub max_response: usize,
    /// Master switch for the keep-alive pool. `false` restores close-per-probe for everything.
    pub reuse: bool,
    pool: Pool,
}

impl Default for NetSender {
    fn default() -> Self {
        Self {
            // Deliberately short. These multiply by the number of active checks in one audit pass,
            // so a generous per-probe timeout becomes a very long total. The audit budget in
            // `burpsy_scanner` bounds the total independently.
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            max_response: 8 * 1024 * 1024,
            reuse: true,
            pool: Pool::default(),
        }
    }
}

impl NetSender {
    /// Close-per-probe for every request, whatever the target looks like.
    ///
    /// For callers whose correctness depends on one request per connection across the board, rather
    /// than the per-probe [`probe_wants_close`] hatch.
    pub fn without_reuse() -> Self {
        Self {
            reuse: false,
            ..Self::default()
        }
    }

    /// How many connections are parked for reuse right now. Exposed so a caller can prove reuse is
    /// happening instead of assuming it.
    pub fn pooled_connections(&self) -> usize {
        self.pool
            .entries
            .lock()
            .values()
            .map(|e| e.idle.len())
            .sum()
    }

    fn connect(&self, target: &Target) -> Result<Conn, String> {
        let addrs = format!("{}:{}", target.host, target.port);
        let addr = std::net::ToSocketAddrs::to_socket_addrs(&addrs)
            .map_err(|e| format!("resolve {addrs}: {e}"))?
            .next()
            .ok_or_else(|| format!("resolve {addrs}: no address"))?;
        let sock = TcpStream::connect_timeout(&addr, self.connect_timeout)
            .map_err(|e| format!("connect {addr}: {e}"))?;
        sock.set_read_timeout(Some(self.read_timeout)).ok();
        sock.set_nodelay(true).ok();

        if target.tls {
            let name = rustls_pki_types::ServerName::try_from(target.host.clone())
                .map_err(|_| format!("bad server name {:?}", target.host))?;
            let conn = rustls::ClientConnection::new(crate::tls::upstream_client_config(), name)
                .map_err(|e| format!("tls setup: {e}"))?;
            Ok(Conn::Tls(Box::new(rustls::StreamOwned::new(conn, sock))))
        } else {
            Ok(Conn::Plain(sock))
        }
    }

    /// One probe on a connection nobody else has touched.
    fn on_fresh_connection(
        &self,
        target: &Target,
        wire: &[u8],
    ) -> Result<(Vec<u8>, Framing), String> {
        let mut conn = self.connect(target)?;
        exchange(&mut conn, wire, self.max_response).map_err(Wire::into_message)
    }

    /// One probe over a pooled connection where possible, falling back to a fresh one.
    fn keep_alive_probe(&self, target: &Target, key: &Key, raw: &[u8]) -> Result<Vec<u8>, String> {
        let wire = force_keep_alive(raw);

        if let Some(mut conn) = self.pool.take(key) {
            match exchange(&mut conn, &wire, self.max_response) {
                Ok((body, framing)) => {
                    if framing.reusable() {
                        self.pool.put(key, conn);
                    }
                    return Ok(body);
                }
                // A pooled socket the server reaped while it was idle gives us nothing at all. That
                // is the expected cost of pooling, not a finding: retry the same probe once on a
                // fresh connection. Only a zero-byte failure qualifies, so a probe that got a
                // partial response is never silently sent twice.
                Err(Wire::Dead(why)) => {
                    tracing::debug!("pooled connection to {key:?} was dead ({why}); reconnecting")
                }
                Err(Wire::Failed(msg)) => return Err(msg),
            }
        }

        let mut conn = self.connect(target)?;
        let (body, framing) =
            exchange(&mut conn, &wire, self.max_response).map_err(Wire::into_message)?;
        if framing.reusable() {
            self.pool.put(key, conn);
        }
        Ok(body)
    }
}

impl Sender for NetSender {
    fn send(&self, target: &Target, raw: &[u8]) -> Result<Vec<u8>, String> {
        let key = Key {
            host: target.host.clone(),
            port: target.port,
            tls: target.tls,
        };

        if !self.reuse || probe_wants_close(raw) {
            return self
                .on_fresh_connection(target, &force_close(raw))
                .map(|(body, _)| body);
        }

        match self.pool.framing(&key) {
            Framed::Exact => self.keep_alive_probe(target, &key, raw),
            Framed::CloseOnly => self
                .on_fresh_connection(target, &force_close(raw))
                .map(|(body, _)| body),
            // First contact. Close-per-probe, and learn from what comes back.
            Framed::Unknown => {
                let (body, framing) = self.on_fresh_connection(target, &force_close(raw))?;
                self.pool.learn(
                    &key,
                    if framing.exact_content_length {
                        Framed::Exact
                    } else {
                        Framed::CloseOnly
                    },
                );
                Ok(body)
            }
        }
    }
}

// ---- connection pool -------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct Key {
    host: String,
    port: u16,
    tls: bool,
}

/// What we have learned about how one target frames its responses.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum Framed {
    /// Not probed yet. The next probe goes out close-per-probe and settles this.
    #[default]
    Unknown,
    /// Answers with an exact `Content-Length`. Safe to keep alive.
    Exact,
    /// Chunked, unframed, or otherwise not safely delimitable. Close-per-probe, permanently.
    CloseOnly,
}

/// Either half of a connection, so the exchange logic does not care about TLS.
enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(b),
            Conn::Tls(s) => s.read(b),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(b),
            Conn::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

struct Idle {
    conn: Conn,
    since: Instant,
}

#[derive(Default)]
struct Entry {
    framed: Framed,
    idle: Vec<Idle>,
}

/// Idle connections and per-target framing knowledge, keyed on `(host, port, tls)`.
///
/// One audit pass constructs one [`NetSender`], so the pool's lifetime is the lifetime of that
/// audit. Nothing survives it — a scanner holding sockets open to a target between runs would be
/// making a decision about the target's resources that the operator did not ask for.
struct Pool {
    entries: Mutex<HashMap<Key, Entry>>,
    /// Idle sockets are cheap to discard and expensive to guess wrong about; anything parked longer
    /// than this is assumed reaped by the peer.
    idle_timeout: Duration,
    max_idle_per_key: usize,
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            idle_timeout: Duration::from_secs(15),
            // The evaluator sends probes sequentially, so one idle socket per target is the steady
            // state. The rest is headroom for a caller that parallelises later.
            max_idle_per_key: 4,
        }
    }
}

impl Pool {
    fn framing(&self, k: &Key) -> Framed {
        self.entries
            .lock()
            .get(k)
            .map(|e| e.framed)
            .unwrap_or_default()
    }

    fn learn(&self, k: &Key, f: Framed) {
        self.entries.lock().entry(k.clone()).or_default().framed = f;
    }

    fn take(&self, k: &Key) -> Option<Conn> {
        let mut g = self.entries.lock();
        let e = g.get_mut(k)?;
        while let Some(i) = e.idle.pop() {
            if i.since.elapsed() < self.idle_timeout {
                return Some(i.conn);
            }
        }
        None
    }

    fn put(&self, k: &Key, conn: Conn) {
        let mut g = self.entries.lock();
        let e = g.entry(k.clone()).or_default();
        if e.idle.len() >= self.max_idle_per_key {
            e.idle.remove(0);
        }
        e.idle.push(Idle {
            conn,
            since: Instant::now(),
        });
    }
}

/// Why an exchange did not produce a response.
enum Wire {
    /// Nothing came back at all — the socket was already gone. Safe to retry.
    Dead(String),
    /// A real failure. Retrying would just send the probe twice.
    Failed(String),
}

impl Wire {
    fn into_message(self) -> String {
        match self {
            Wire::Dead(m) | Wire::Failed(m) => m,
        }
    }
}

/// Write one request and read one response over an existing connection.
fn exchange(conn: &mut Conn, wire: &[u8], max: usize) -> Result<(Vec<u8>, Framing), Wire> {
    if let Err(e) = conn.write_all(wire) {
        return Err(Wire::Dead(format!("write: {e}")));
    }
    conn.flush().ok();
    match read_response_framed(conn, max) {
        Ok(v) => Ok(v),
        // Not one byte came back. On a reused socket that is the peer having closed or reset it
        // while it sat idle, which is expected and safe to retry.
        Err(f) if f.silent => Err(Wire::Dead(f.message)),
        Err(f) => Err(Wire::Failed(f.message)),
    }
}

/// Set `Connection: close` on the outgoing probe, replacing any keep-alive the base request had.
fn force_close(raw: &[u8]) -> Vec<u8> {
    match RequestEdit::from_raw(raw) {
        Ok(mut r) => {
            r.set_header("Connection", "close");
            r.to_raw()
        }
        // Unparsable here means the caller supplied a deliberately malformed raw request — send it
        // exactly as written rather than "fixing" the thing under test.
        Err(_) => raw.to_vec(),
    }
}

/// Set `Connection: keep-alive`, for a probe that has already been cleared for a shared connection.
///
/// Only ever reached when [`probe_wants_close`] said no, so the parse cannot fail in practice; the
/// verbatim fallback matches [`force_close`] rather than inventing a second policy for the case.
fn force_keep_alive(raw: &[u8]) -> Vec<u8> {
    match RequestEdit::from_raw(raw) {
        Ok(mut r) => {
            r.set_header("Connection", "keep-alive");
            r.to_raw()
        }
        Err(_) => raw.to_vec(),
    }
}

/// Must this probe have a connection to itself?
///
/// Each arm is a different reason, and each one is a case where sharing would produce a wrong
/// answer rather than merely a slow one:
///
/// * **Unparsable** — sent verbatim by [`force_close`], so we cannot reason about its framing.
/// * **`Transfer-Encoding` present, or not HTTP/1.1** — request-smuggling and parser-differential
///   probes are built so two parsers disagree about where the request ends. Whatever the server
///   thinks is left over would be prepended to the next probe on that connection.
/// * **Caller already said `Connection: close`** — take them at their word.
fn probe_wants_close(raw: &[u8]) -> bool {
    let Ok(r) = RequestEdit::from_raw(raw) else {
        return true;
    };
    r.version != "HTTP/1.1"
        || r.header("transfer-encoding").is_some()
        || r.header("connection")
            .is_some_and(|v| v.to_ascii_lowercase().contains("close"))
}

/// How a response was delimited, which is what decides whether its connection can be handed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Framing {
    /// Declared a `Content-Length` and the buffer ends exactly there — no surplus, no shortfall.
    exact_content_length: bool,
    /// The response asked for the connection to be closed (explicitly, or by being HTTP/1.0).
    server_wants_close: bool,
}

impl Framing {
    fn reusable(&self) -> bool {
        self.exact_content_length && !self.server_wants_close
    }
}

/// Why a response could not be read, and whether the peer said anything at all.
#[derive(Debug)]
struct ReadFail {
    message: String,
    /// Not one byte arrived. Distinguished from every other failure because it is the signature of
    /// a connection that was already gone, which a caller holding a pooled socket must be able to
    /// tell apart from a target that answered badly.
    silent: bool,
}

impl ReadFail {
    fn silent(message: String) -> Self {
        Self {
            message,
            silent: true,
        }
    }
    fn loud(message: String) -> Self {
        Self {
            message,
            silent: false,
        }
    }
}

/// Read one HTTP response — honour `Content-Length`, then chunked framing, else read to EOF — and
/// report how it was delimited.
fn read_response_framed(s: &mut impl Read, max: usize) -> Result<(Vec<u8>, Framing), ReadFail> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 16 * 1024];
    let mut head_end: Option<usize> = None;
    let mut truncated = false;

    loop {
        let n = match s.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => n,
            // Deliberately loud even at zero bytes: a timeout means the peer may still be thinking,
            // and re-sending after waiting the full budget both doubles the worst case and risks
            // performing a probe's side effect twice.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(ReadFail::loud(format!(
                    "read timeout after {} bytes",
                    buf.len()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // A server that closes without a clean shutdown still gave us bytes worth parsing.
            Err(e) => {
                if buf.is_empty() {
                    return Err(ReadFail::silent(format!("read: {e}")));
                }
                break;
            }
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > max {
            buf.truncate(max);
            truncated = true;
            break;
        }
        if head_end.is_none() {
            head_end = find_head_end(&buf);
        }
        if let Some(he) = head_end
            && response_complete(&buf, he)
        {
            break;
        }
    }
    if buf.is_empty() {
        return Err(ReadFail::silent("empty response".into()));
    }
    let framing = match head_end.or_else(|| find_head_end(&buf)) {
        // A truncated response is by definition not where the server said it would end, so the
        // connection's position is unknown and it can never be reused.
        Some(he) if !truncated => {
            let head = String::from_utf8_lossy(&buf[..he]).to_ascii_lowercase();
            Framing {
                exact_content_length: header_value(&head, "content-length")
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .is_some_and(|len| buf.len() == he + len),
                server_wants_close: wants_close(&head),
            }
        }
        _ => Framing {
            exact_content_length: false,
            server_wants_close: true,
        },
    };
    Ok((buf, framing))
}

/// Does this lower-cased response head say the connection is finished?
///
/// HTTP/1.0 counts even without the header: persistence there is opt-in via
/// `Connection: keep-alive`, so its absence means close.
fn wants_close(lower_head: &str) -> bool {
    if header_value(lower_head, "connection").is_some_and(|v| v.contains("close")) {
        return true;
    }
    lower_head.starts_with("http/1.0")
        && !header_value(lower_head, "connection").is_some_and(|v| v.contains("keep-alive"))
}

fn find_head_end(b: &[u8]) -> Option<usize> {
    b.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| b.windows(2).position(|w| w == b"\n\n").map(|i| i + 2))
}

/// True when the buffer holds a whole response given where its headers ended.
fn response_complete(buf: &[u8], head_end: usize) -> bool {
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    if let Some(len) =
        header_value(&head, "content-length").and_then(|v| v.trim().parse::<usize>().ok())
    {
        return buf.len() >= head_end + len;
    }
    if header_value(&head, "transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        // Terminal zero-length chunk.
        return buf[head_end..].windows(5).any(|w| w == b"0\r\n\r\n");
    }
    // No framing: only EOF ends it. `Connection: close` is what makes that terminate.
    false
}

fn header_value<'a>(lower_head: &'a str, name: &str) -> Option<&'a str> {
    lower_head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        (n.trim() == name).then_some(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Just the bytes, for the framing tests that predate the pool and should still read the same.
    fn read_response(s: &mut impl Read, max: usize) -> Result<Vec<u8>, String> {
        read_response_framed(s, max)
            .map(|(buf, _)| buf)
            .map_err(|f| f.message)
    }

    #[test]
    fn a_content_length_response_stops_at_the_stated_length() {
        // Trailing bytes stand in for a pipelined follow-up: they must not be swallowed into this
        // response.
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let got = read_response(&mut Cursor::new(wire.to_vec()), 1 << 20).unwrap();
        let head_end = find_head_end(&got).unwrap();
        assert!(response_complete(&got, head_end));
        assert!(got.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[test]
    fn a_chunked_response_is_complete_at_the_terminal_chunk() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n";
        let got = read_response(&mut Cursor::new(wire.to_vec()), 1 << 20).unwrap();
        assert_eq!(got, wire.to_vec());
    }

    #[test]
    fn an_unframed_response_is_read_to_eof() {
        let wire = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody bytes with no length";
        let got = read_response(&mut Cursor::new(wire.to_vec()), 1 << 20).unwrap();
        assert_eq!(got, wire.to_vec());
    }

    #[test]
    fn an_oversized_response_is_truncated_not_unbounded() {
        let mut wire = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        wire.extend(std::iter::repeat_n(b'x', 100_000));
        let got = read_response(&mut Cursor::new(wire), 4096).unwrap();
        assert!(
            got.len() <= 4096 + 16 * 1024,
            "cap must bound the buffer, got {}",
            got.len()
        );
    }

    #[test]
    fn an_empty_reply_is_an_error_not_an_empty_response() {
        // Otherwise a check would evaluate against a zero-byte "response" and could report on it.
        let e = read_response(&mut Cursor::new(Vec::new()), 1 << 20).unwrap_err();
        assert!(e.contains("empty"), "got {e:?}");
    }

    #[test]
    fn connection_close_is_forced_and_replaces_keep_alive() {
        let out = force_close(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Connection: close"), "got {s:?}");
        assert!(!s.contains("keep-alive"));
    }

    #[test]
    fn a_malformed_raw_request_is_sent_verbatim() {
        // Request smuggling and parser-differential checks depend on sending exactly these bytes.
        let bad = b"GARBAGE";
        assert_eq!(force_close(bad), bad.to_vec());
    }

    #[test]
    fn keep_alive_replaces_whatever_connection_header_the_base_request_had() {
        let out = force_keep_alive(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Connection: keep-alive"), "got {s:?}");
        assert!(!s.contains("Connection: close"), "got {s:?}");
    }

    #[test]
    fn probes_that_must_own_their_connection_are_recognised() {
        // A plain probe is poolable.
        assert!(!probe_wants_close(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        // Malformed: sent verbatim, framing unknowable.
        assert!(probe_wants_close(b"GARBAGE"));
        // The classic CL.TE smuggling shape: two parsers, two opinions on where this ends.
        assert!(probe_wants_close(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ));
        // HTTP/1.0 has no persistent connections by default.
        assert!(probe_wants_close(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n"));
        // The caller said so outright.
        assert!(probe_wants_close(
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        ));
    }

    #[test]
    fn a_response_that_overruns_its_content_length_is_not_reusable() {
        // Surplus bytes mean the connection is at an unknown offset. Under reuse those bytes would
        // become the next probe's response, so this classification is what prevents that.
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let (_, f) = read_response_framed(&mut Cursor::new(wire.to_vec()), 1 << 20).unwrap();
        assert!(
            !f.exact_content_length,
            "surplus bytes must not count as exact framing"
        );
        assert!(!f.reusable());
    }

    #[test]
    fn a_chunked_response_is_never_reusable_even_though_it_is_complete() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n";
        let (_, f) = read_response_framed(&mut Cursor::new(wire.to_vec()), 1 << 20).unwrap();
        assert!(
            !f.reusable(),
            "the terminal-chunk scan is a substring match, so reuse is unsafe"
        );
    }

    #[test]
    fn an_exactly_framed_response_that_does_not_ask_to_close_is_reusable() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (_, f) = read_response_framed(&mut Cursor::new(wire.to_vec()), 1 << 20).unwrap();
        assert!(f.reusable());

        let closing = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
        let (_, f) = read_response_framed(&mut Cursor::new(closing.to_vec()), 1 << 20).unwrap();
        assert!(f.exact_content_length);
        assert!(!f.reusable(), "a server that says close must be believed");

        let old = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (_, f) = read_response_framed(&mut Cursor::new(old.to_vec()), 1 << 20).unwrap();
        assert!(
            !f.reusable(),
            "HTTP/1.0 is not persistent unless it says so"
        );
    }

    // ---- against a real listener ---------------------------------------------------------
    //
    // These count accepted TCP connections, which is the only honest way to prove reuse: a test
    // that asserts on the pool's own bookkeeping would pass even if every probe dialled out.

    #[derive(Clone, Copy, PartialEq)]
    enum Origin {
        /// Exact `Content-Length`, persistent. The case reuse exists for.
        Framed,
        /// No framing at all; terminates by closing. The case reuse must never break.
        Unframed,
        /// Exact `Content-Length` but closes anyway, without saying so — so a pooled socket goes
        /// stale between probes.
        FramedButCloses,
    }

    struct Server {
        addr: SocketAddr,
        accepts: Arc<AtomicUsize>,
    }

    fn spawn_origin(mode: Origin) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();
        std::thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(mut sock) = sock else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    while let Some(req) = read_one_request(&mut sock) {
                        let close_after = req.to_ascii_lowercase().contains("connection: close")
                            || mode != Origin::Framed;
                        let body = b"PONG";
                        let head = match mode {
                            Origin::Unframed => "HTTP/1.1 200 OK\r\nServer: t\r\n\r\n".to_string(),
                            _ => {
                                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                            }
                        };
                        if sock.write_all(head.as_bytes()).is_err() || sock.write_all(body).is_err()
                        {
                            break;
                        }
                        sock.flush().ok();
                        if close_after {
                            break;
                        }
                    }
                });
            }
        });
        Server { addr, accepts }
    }

    /// Read exactly one header block. The probes in these tests carry no body.
    fn read_one_request(s: &mut TcpStream) -> Option<String> {
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        loop {
            match s.read(&mut b) {
                Ok(0) | Err(_) => return None,
                Ok(_) => buf.push(b[0]),
            }
            if buf.ends_with(b"\r\n\r\n") {
                return Some(String::from_utf8_lossy(&buf).into_owned());
            }
        }
    }

    fn target_of(s: &Server) -> Target {
        Target {
            host: s.addr.ip().to_string(),
            port: s.addr.port(),
            tls: false,
        }
    }

    const PROBE: &[u8] = b"GET /probe HTTP/1.1\r\nHost: t\r\n\r\n";

    #[test]
    fn probes_after_the_first_share_one_connection_to_a_content_length_origin() {
        let origin = spawn_origin(Origin::Framed);
        let sender = NetSender::default();
        let t = target_of(&origin);

        for i in 0..3 {
            let r = sender
                .send(&t, PROBE)
                .unwrap_or_else(|e| panic!("probe {i}: {e}"));
            assert!(
                r.ends_with(b"PONG"),
                "probe {i} got {:?}",
                String::from_utf8_lossy(&r)
            );
        }
        // One connection to learn the framing (close-per-probe), one shared by probes 2 and 3.
        assert_eq!(
            origin.accepts.load(Ordering::SeqCst),
            2,
            "three probes should cost two connections, not three"
        );
        assert_eq!(
            sender.pooled_connections(),
            1,
            "the shared connection stays parked"
        );
    }

    #[test]
    fn an_unframed_origin_keeps_getting_a_fresh_connection_per_probe() {
        let origin = spawn_origin(Origin::Unframed);
        let sender = NetSender::default();
        let t = target_of(&origin);

        for i in 0..3 {
            let r = sender
                .send(&t, PROBE)
                .unwrap_or_else(|e| panic!("probe {i}: {e}"));
            assert!(
                r.ends_with(b"PONG"),
                "probe {i} got {:?}",
                String::from_utf8_lossy(&r)
            );
        }
        assert_eq!(
            origin.accepts.load(Ordering::SeqCst),
            3,
            "an EOF-delimited response must never be read over a shared connection"
        );
        assert_eq!(sender.pooled_connections(), 0);
    }

    #[test]
    fn a_probe_that_asks_for_close_is_never_pooled_even_against_a_poolable_origin() {
        let origin = spawn_origin(Origin::Framed);
        let sender = NetSender::default();
        let t = target_of(&origin);
        let smuggle = b"GET /probe HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";

        for i in 0..3 {
            sender
                .send(&t, smuggle)
                .unwrap_or_else(|e| panic!("probe {i}: {e}"));
        }
        assert_eq!(
            origin.accepts.load(Ordering::SeqCst),
            3,
            "the escape hatch must bypass the pool"
        );
    }

    #[test]
    fn a_pooled_connection_the_server_already_closed_is_retried_on_a_fresh_one() {
        let origin = spawn_origin(Origin::FramedButCloses);
        let sender = NetSender::default();
        let t = target_of(&origin);

        // Every probe must still succeed even though the socket we parked was already dead.
        for i in 0..3 {
            let r = sender
                .send(&t, PROBE)
                .unwrap_or_else(|e| panic!("probe {i}: {e}"));
            assert!(
                r.ends_with(b"PONG"),
                "probe {i} got {:?}",
                String::from_utf8_lossy(&r)
            );
        }
        assert_eq!(origin.accepts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn without_reuse_every_probe_gets_its_own_connection() {
        let origin = spawn_origin(Origin::Framed);
        let sender = NetSender::without_reuse();
        let t = target_of(&origin);

        for i in 0..3 {
            sender
                .send(&t, PROBE)
                .unwrap_or_else(|e| panic!("probe {i}: {e}"));
        }
        assert_eq!(origin.accepts.load(Ordering::SeqCst), 3);
        assert_eq!(sender.pooled_connections(), 0);
    }

    #[test]
    fn the_pool_is_keyed_on_host_port_and_tls_so_two_origins_do_not_share() {
        let a = spawn_origin(Origin::Framed);
        let b = spawn_origin(Origin::Framed);
        let sender = NetSender::default();

        for _ in 0..2 {
            sender.send(&target_of(&a), PROBE).unwrap();
            sender.send(&target_of(&b), PROBE).unwrap();
        }
        assert_eq!(a.accepts.load(Ordering::SeqCst), 2);
        assert_eq!(b.accepts.load(Ordering::SeqCst), 2);
        assert_eq!(
            sender.pooled_connections(),
            2,
            "one parked connection per target"
        );
    }
}
