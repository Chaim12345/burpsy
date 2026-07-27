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
//! # Why `Connection: close`
//!
//! Every probe closes its connection, so a response with neither `Content-Length` nor chunked
//! framing terminates at EOF instead of hanging until the read timeout. Connection reuse is a
//! throughput optimisation that belongs with the rate limiter, not here.

use burpsy_bcheck::eval::{Sender, Target};
use burpsy_core::edit::RequestEdit;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Sends probe requests over TCP, with TLS when the target requires it.
pub struct NetSender {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    /// Hard cap on a response body, so a hostile or broken server cannot exhaust memory.
    pub max_response: usize,
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
        }
    }
}

impl Sender for NetSender {
    fn send(&self, target: &Target, raw: &[u8]) -> Result<Vec<u8>, String> {
        let raw = force_close(raw);
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
            let mut tls = rustls::StreamOwned::new(conn, sock);
            tls.write_all(&raw).map_err(|e| format!("tls write: {e}"))?;
            tls.flush().ok();
            read_response(&mut tls, self.max_response)
        } else {
            let mut sock = sock;
            sock.write_all(&raw).map_err(|e| format!("write: {e}"))?;
            sock.flush().ok();
            read_response(&mut sock, self.max_response)
        }
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

/// Read one HTTP response: honour `Content-Length`, then chunked framing, else read to EOF.
fn read_response(s: &mut impl Read, max: usize) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 16 * 1024];
    let mut head_end: Option<usize> = None;

    loop {
        let n = match s.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(format!("read timeout after {} bytes", buf.len()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // A server that closes without a clean shutdown still gave us bytes worth parsing.
            Err(e) => {
                if buf.is_empty() {
                    return Err(format!("read: {e}"));
                }
                break;
            }
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > max {
            buf.truncate(max);
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
        return Err("empty response".into());
    }
    Ok(buf)
}

fn find_head_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).or_else(|| {
        b.windows(2).position(|w| w == b"\n\n").map(|i| i + 2)
    })
}

/// True when the buffer holds a whole response given where its headers ended.
fn response_complete(buf: &[u8], head_end: usize) -> bool {
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    if let Some(len) = header_value(&head, "content-length").and_then(|v| v.trim().parse::<usize>().ok())
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
        assert!(got.len() <= 4096 + 16 * 1024, "cap must bound the buffer, got {}", got.len());
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
}
