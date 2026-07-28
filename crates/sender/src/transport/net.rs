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
            read_response(&mut s).await?
        } else {
            let mut s = tcp;
            s.write_all(raw).await.context("write")?;
            s.flush().await.ok();
            read_response(&mut s).await?
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
/// us until timeout; otherwise reads to EOF.
async fn read_response<S>(s: &mut S) -> Result<Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        let n = s.read(&mut chunk).await.context("read")?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(total) = complete_len(&buf)
            && buf.len() >= total
        {
            break;
        }
    }
    Ok(buf)
}

/// If response framing is known and satisfied, the expected total length.
fn complete_len(buf: &[u8]) -> Option<usize> {
    let head_end = find(buf, b"\r\n\r\n").map(|i| i + 4)?;
    let head = &buf[..head_end];
    let lower = head.to_ascii_lowercase();

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
        assert_eq!(complete_len(buf), Some(buf.len()));
    }

    #[test]
    fn a_body_shorter_than_content_length_is_not_yet_complete() {
        let head = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
        let buf = format!("{head}hi").into_bytes();
        // Framing is known — head plus the declared 10 bytes — and the buffer has not reached it,
        // so the read loop must keep going rather than treat this as a finished response.
        assert_eq!(complete_len(&buf), Some(head.len() + 10));
        assert!(complete_len(&buf).unwrap() > buf.len());
    }

    #[test]
    fn chunked_framing_completes_only_on_the_terminal_chunk() {
        let partial = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert_eq!(complete_len(partial), None);
        let done = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(complete_len(done), Some(done.len()));
    }

    #[test]
    fn the_status_line_yields_its_code() {
        assert_eq!(parse_status(b"HTTP/1.1 404 Not Found\r\n\r\n"), Some(404));
        assert_eq!(parse_status(b"HTTP/1.1 200\r\n\r\n"), Some(200));
        assert_eq!(parse_status(b"garbage"), None);
    }
}
