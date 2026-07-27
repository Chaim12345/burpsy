//! burpsy-repeater — byte-exact HTTP send engine.
//!
//! # Why raw TCP and not hyper
//!
//! A typed HTTP client is the wrong tool for a pentest proxy. `hyper` — correctly, for a general
//! client — normalises header casing and ordering, rewrites `Content-Length`/`Transfer-Encoding`,
//! and rejects malformed requests. Those are exactly the things a tester must control: request
//! smuggling, header injection and parser-differential work all depend on sending bytes *exactly*
//! as typed.
//!
//! So the wire layer is `tokio::net::TcpStream` + `tokio-rustls`, and a request is just `&[u8]`.
//! Burp makes the same call — Repeater exposes global toggles for `UpdateContentLength`,
//! `EnableH1ConnectionReuse` and `EnableH2ConnectionReuse` (recovered from `burp.Zcu0`), which only
//! makes sense if the default is to leave the bytes alone.

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

/// Where and how to send.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16, tls: bool) -> Self {
        Self {
            host: host.into(),
            port,
            tls,
        }
    }

    /// Parse `host:port`, `https://host/path`, or a bare host.
    pub fn parse(s: &str) -> Result<Self> {
        let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            (false, s)
        };
        let hostport = rest.split('/').next().unwrap_or(rest);
        let (h, p) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().unwrap_or(if tls { 443 } else { 80 })),
            None => (hostport, if tls { 443 } else { 80 }),
        };
        if h.is_empty() {
            return Err(anyhow!("empty host in target {s:?}"));
        }
        Ok(Self::new(h, p, tls))
    }
}

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
pub async fn send(target: &Target, raw: &[u8], timeout: Duration) -> Result<SendResult> {
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
    use tokio::net::TcpListener;

    #[test]
    fn target_parsing() {
        let t = Target::parse("https://example.test/a/b").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.tls),
            ("example.test", 443, true)
        );
        let t = Target::parse("h.test:8080").unwrap();
        assert_eq!((t.host.as_str(), t.port, t.tls), ("h.test", 8080, false));
        let t = Target::parse("http://h.test").unwrap();
        assert_eq!((t.host.as_str(), t.port, t.tls), ("h.test", 80, false));
        assert!(Target::parse("http://").is_err());
    }

    #[test]
    fn content_length_framing_detected() {
        let b = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(complete_len(b), Some(b.len()));
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nhello";
        assert!(complete_len(partial).unwrap() > partial.len());
    }

    #[tokio::test]
    async fn sends_bytes_verbatim_and_reads_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; 1024];
            let n = sock.read(&mut got).await.unwrap();
            got.truncate(n);
            sock.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nhi")
                .await
                .unwrap();
            got
        });

        // Deliberately odd casing, spacing and ordering: must arrive unchanged.
        let raw = b"GeT /x HTTP/1.1\r\nhOsT: verbatim.test\r\nX-Odd:  1 \r\n\r\n";
        let t = Target::new("127.0.0.1", addr.port(), false);
        let r = send(&t, raw, Duration::from_secs(5)).await.unwrap();

        assert_eq!(r.status, Some(201));
        assert!(r.raw_response.ends_with(b"hi"));

        let received = server.await.unwrap();
        assert_eq!(&received[..], &raw[..], "bytes were altered in transit");
    }

    #[tokio::test]
    async fn timeout_is_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _s = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let t = Target::new("127.0.0.1", addr.port(), false);
        let e = send(&t, b"GET / HTTP/1.1\r\n\r\n", Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("timeout"), "got: {e}");
    }
}
