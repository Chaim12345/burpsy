//! Async transport: `tokio` + `tokio-rustls`, bytes written verbatim.
//!
//! Moved here from `burpsy-repeater` so that opening a socket is not something any crate can do by
//! calling a public function. It is `pub(crate)`: the only way to reach it is through
//! [`crate::AuthorisedSender`], which checks scope first.
//!
//! # Why raw TCP and not hyper
//!
//! A typed HTTP client is the wrong tool for a pentest proxy. `hyper` — correctly, for a general
//! client — normalises header casing and ordering, rewrites `Content-Length`/`Transfer-Encoding`,
//! and rejects malformed requests. Those are exactly the things a tester must control: request
//! smuggling, header injection and parser-differential work all depend on sending bytes *exactly*
//! as typed.

use anyhow::{Context, Result, anyhow};
use burpsy_bcheck::eval::Target;
use bytes::Bytes;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

/// Outcome of one send.
#[derive(Debug, Clone)]
pub struct SendResult {
    pub raw_response: Bytes,
    pub duration: Duration,
    pub status: Option<u16>,
}

/// TLS config that does not verify certificates.
///
/// Deliberate: a testing proxy must reach hosts with self-signed, expired or mismatched certs —
/// refusing them would make the tool useless against staging, which is most of the work. This is an
/// outbound testing client, not a browser.
fn insecure_tls() -> Arc<ClientConfig> {
    use tokio_rustls::rustls::DigitallySignedStruct;
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, UnixTime};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
            use tokio_rustls::rustls::SignatureScheme::*;
            vec![
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                ECDSA_NISTP256_SHA256,
                ECDSA_NISTP384_SHA384,
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
                ED25519,
            ]
        }
    }

    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    )
}

/// Send raw request bytes to `target` and read the response.
///
/// `raw` is written verbatim — no header rewriting, no reordering.
pub(crate) async fn send(target: &Target, raw: &[u8], timeout: Duration) -> Result<SendResult> {
    let started = Instant::now();
    let addr = format!("{}:{}", target.host, target.port);
    // Derived here, where the request bytes are: a HEAD response is complete at its head and
    // nothing in the response itself says so.
    let head_only = request_is_head(raw);

    let fut = async {
        let tcp = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("connect {addr}"))?;
        tcp.set_nodelay(true).ok();

        let buf = if target.tls {
            let connector = TlsConnector::from(insecure_tls());
            let dns = ServerName::try_from(target.host.clone())
                .map_err(|_| anyhow!("invalid DNS name {:?}", target.host))?;
            let mut s = connector.connect(dns, tcp).await.context("tls handshake")?;
            s.write_all(raw).await.context("write")?;
            s.flush().await.ok();
            read_response(&mut s, head_only).await?
        } else {
            let mut s = tcp;
            s.write_all(raw).await.context("write")?;
            s.flush().await.ok();
            read_response(&mut s, head_only).await?
        };
        Ok::<Vec<u8>, anyhow::Error>(buf)
    };

    let buf = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow!("timeout after {timeout:?}"))??;

    let status = parse_status(&buf);
    Ok(SendResult {
        raw_response: Bytes::from(buf),
        duration: started.elapsed(),
        status,
    })
}

/// Read until framing is satisfied or the peer closes.
///
/// Honours `Content-Length` and `Transfer-Encoding: chunked` so a keep-alive server does not stall
/// us until timeout; otherwise reads to EOF. Interim `1xx` responses are skipped: they precede the
/// real response on the same connection (RFC 9110 §15.2) and returning one as the final answer
/// would silently discard what the operator actually asked for.
async fn read_response<S>(s: &mut S, head_only: bool) -> Result<Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = vec![0u8; 16 * 1024];
    // Offset past any interim 1xx responses already consumed. Framing checks and the returned
    // slice both start here, so `parse_status` and `raw_response` describe the final response.
    let mut start = 0usize;
    loop {
        let n = s.read(&mut chunk).await.context("read")?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);

        // Skip interim 1xx responses: they are complete at the end of their head and carry no
        // body, but the real response follows on the same connection. Loop because `100 Continue`
        // then `103 Early Hints` can both arrive before the final status.
        while let Some(rel_end) = head_end(&buf[start..]) {
            let interim = String::from_utf8_lossy(&buf[start..start + rel_end]).to_ascii_lowercase();
            let code = interim
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|c| c.parse::<u16>().ok());
            if code.is_some_and(|c| (100..200).contains(&c)) {
                start += rel_end;
            } else {
                break;
            }
        }

        if let Some(total) = complete_len(&buf[start..], head_only)
            && buf.len() - start >= total
        {
            break;
        }
    }
    Ok(buf[start..].to_vec())
}

/// If response framing is known and satisfied, the expected total length.
///
/// Bodiless responses (204, 304, HEAD) are checked BEFORE the framing headers: they legitimately
/// echo the `Content-Length` a GET would have returned, and reading that header first is the bug
/// that stalls the read loop waiting for bytes the server will never send.
fn complete_len(buf: &[u8], head_only: bool) -> Option<usize> {
    let head_end = find(buf, b"\r\n\r\n").map(|i| i + 4)?;
    let head = &buf[..head_end];
    let lower = head.to_ascii_lowercase();

    if head_only || status_is_bodiless(&lower) {
        return Some(head_end);
    }

    if find(&lower, b"transfer-encoding: chunked").is_some() {
        return if find(&buf[head_end..], b"0\r\n\r\n").is_some() {
            Some(buf.len())
        } else {
            None
        };
    }
    let i = find(&lower, b"content-length:")?;
    let rest = &head[i + 15..];
    let line_end = rest.iter().position(|&b| b == b'\r')?;
    let n: usize = std::str::from_utf8(&rest[..line_end])
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(head_end + n)
}

/// Byte offset just past the first `\r\n\r\n`, or `None` if the head is not yet complete.
fn head_end(buf: &[u8]) -> Option<usize> {
    find(buf, b"\r\n\r\n").map(|i| i + 4)
}

/// `204` and `304` carry no body, whatever their headers claim. `1xx` is deliberately excluded:
/// it is an interim response, not a bodiless final one — see `read_response`, which steps over
/// those rather than treating them as an answer.
///
/// Takes bytes rather than `&str` so the caller's lower-cased head needs no lossy conversion.
fn status_is_bodiless(lower_head: &[u8]) -> bool {
    parse_status(lower_head).is_some_and(|c| c == 204 || c == 304)
}

/// Whether the outgoing request bytes begin with `HEAD`. Nothing in the response reveals this, so
/// it must be derived from the request at the point where those bytes are available.
fn request_is_head(raw: &[u8]) -> bool {
    raw.starts_with(b"HEAD ")
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_status(buf: &[u8]) -> Option<u16> {
    let line_end = buf.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let line = &buf[..line_end];
    let sp = line.iter().position(|&b| b == b' ')?;
    let rest = &line[sp + 1..];
    let end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_framing_is_satisfied_at_the_declared_length() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(complete_len(buf, false), Some(buf.len()));
    }

    #[test]
    fn a_body_shorter_than_content_length_is_not_yet_complete() {
        let head = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
        let buf = format!("{head}hi").into_bytes();
        // Framing is known — head plus the declared 10 bytes — and the buffer has not reached it,
        // so the read loop must keep going rather than treat this as a finished response.
        assert_eq!(complete_len(&buf, false), Some(head.len() + 10));
        assert!(complete_len(&buf, false).unwrap() > buf.len());
    }

    #[test]
    fn chunked_framing_completes_only_on_the_terminal_chunk() {
        let partial = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert_eq!(complete_len(partial, false), None);
        let done = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(complete_len(done, false), Some(done.len()));
    }

    #[test]
    fn the_status_line_yields_its_code() {
        assert_eq!(parse_status(b"HTTP/1.1 404 Not Found\r\n\r\n"), Some(404));
        assert_eq!(parse_status(b"HTTP/1.1 200\r\n\r\n"), Some(200));
        assert_eq!(parse_status(b"garbage"), None);
    }

    #[test]
    fn a_bodiless_response_completes_at_its_head_despite_advertising_a_length() {
        // This is the async transport behind Repeater and Intruder. A repeater sends captured
        // bytes verbatim, keep-alive included, so a 304 that echoes the length a GET would have
        // returned used to satisfy no framing at all: the loop blocked and `tokio::time::timeout`
        // discarded the whole response in front of the operator.
        for status in ["204 No Content", "304 Not Modified"] {
            let raw = format!("HTTP/1.1 {status}\r\nContent-Length: 4\r\n\r\n");
            let b = raw.as_bytes();
            assert_eq!(
                complete_len(b, false),
                Some(b.len()),
                "{status} ends at its head"
            );
        }
        // The same header on a 200 is real, so that response is genuinely unfinished.
        let b = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";
        assert_eq!(complete_len(b, false), Some(b.len() + 4));
    }

    #[test]
    fn a_head_response_completes_at_its_head_because_the_request_said_so() {
        // Only the request knows; the response is indistinguishable from a GET's.
        let b = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";
        assert_eq!(complete_len(b, true), Some(b.len()));
        assert_eq!(complete_len(b, false), Some(b.len() + 4));
    }

    #[test]
    fn the_head_method_is_recognised_and_not_confused_with_a_prefix() {
        assert!(request_is_head(b"HEAD /p HTTP/1.1\r\n\r\n"));
        assert!(!request_is_head(b"GET /p HTTP/1.1\r\n\r\n"));
        assert!(
            !request_is_head(b"HEADER /p HTTP/1.1\r\n\r\n"),
            "a method that merely starts with HEAD is a different method"
        );
    }

    #[test]
    fn an_interim_1xx_is_not_mistaken_for_a_bodiless_final_response() {
        // Both are bodiless; only 204/304 are final. Calling a 1xx complete would return the
        // placeholder and silently drop the real answer.
        for status in ["100 Continue", "103 Early Hints"] {
            let raw = format!("HTTP/1.1 {status}\r\n\r\n");
            assert!(
                !status_is_bodiless(&raw.to_ascii_lowercase().into_bytes()),
                "{status} is interim, not a final bodiless response"
            );
        }
    }
}
