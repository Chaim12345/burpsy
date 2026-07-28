//! ALPN negotiation through the real proxy, against real TLS origins.
//!
//! Every property here is a handshake outcome, and a handshake outcome cannot be observed from a unit
//! test: `alpn_offer` and `negotiated_protocol` are covered directly in `tls.rs`, but "an h2-capable
//! target is not downgraded" is a claim about what two rustls endpoints agreed on with the proxy
//! between them. So each test drives a client socket through `burpsy_proxy::serve`, a `CONNECT`, and a
//! full TLS handshake to an origin that offers a known ALPN list.
//!
//! `CONNECT localhost:<port>` rather than `127.0.0.1:<port>` throughout, because [`TlsPolicy`] sends
//! IP-literal CONNECTs down the blind-tunnel path — there is no SNI hostname to sign for — and a blind
//! tunnel negotiates nothing. `localhost` resolves to the loopback origin and is interceptable.

use burpsy_core::{Exchange, Protocol, TrafficStore};
use burpsy_proxy::{Interceptor, ProxyConfig, TlsEngine, tls};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn engine() -> Arc<TlsEngine> {
    let (ca, _, _) = tls::generate_ca("burpsy alpn test").unwrap();
    Arc::new(TlsEngine::new(ca))
}

/// A TLS origin offering exactly `alpn`, answering one HTTP/1 request when that is what got picked.
///
/// Under `h2` it reads to EOF and answers nothing. That is not a shortcut: the proxy records such a
/// connection and closes it without sending a byte of application data, so an h2 driver here would
/// have nothing to talk to. What the origin has to do is *negotiate* h2, and it does.
async fn spawn_tls_origin(alpn: Vec<Vec<u8>>) -> SocketAddr {
    let eng = engine();
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(eng.resolver_for("localhost"));
    cfg.alpn_protocols = alpn;
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Keep the engine alive for the life of the origin: the resolver holds the only CA.
        let _eng = eng;
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                if tls.get_ref().1.alpn_protocol() == Some(tls::ALPN_H2) {
                    let mut sink = Vec::new();
                    let _ = tls.read_to_end(&mut sink).await;
                    return;
                }
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = tls.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = "ORIGIN OK";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });
    addr
}

async fn spawn_proxy(cfg: ProxyConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { burpsy_proxy::serve(listener, cfg).await });
    addr
}

/// `CONNECT` through the proxy and hand back the completed client-side TLS session.
///
/// The `200 Connection Established` reply is read one octet at a time up to its terminator. A larger
/// read would swallow the first TLS records behind it, and then the handshake this test exists to
/// observe would fail for a reason that has nothing to do with ALPN.
async fn connect_through(
    proxy: SocketAddr,
    origin_port: u16,
    offer: Vec<Vec<u8>>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let req = format!(
        "CONNECT localhost:{origin_port} HTTP/1.1\r\nHost: localhost:{origin_port}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    s.flush().await.unwrap();

    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = s.read(&mut one).await.unwrap();
        assert_eq!(n, 1, "proxy closed before answering CONNECT");
        head.push(one[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "CONNECT got {head:?}");

    let connector = TlsConnector::from(tls::upstream_client_config(&offer));
    let dns = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    connector.connect(dns, s).await
}

fn intercepting_config(store: Arc<TrafficStore>, on: bool) -> (ProxyConfig, Arc<Interceptor>) {
    let ic = Interceptor::new();
    ic.set_enabled(on);
    let cfg = ProxyConfig::new(store)
        .with_tls_engine(engine())
        .with_interceptor(ic.clone());
    (cfg, ic)
}

/// Poll rather than sleep: the exchange is written after the handshake the test just observed.
async fn wait_for_exchange(store: &TrafficStore) -> Exchange {
    for _ in 0..5000 {
        let rows = store.exchanges(0, 10);
        if let Some(first) = rows.into_iter().next() {
            return first;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("timed out waiting for an exchange to be recorded");
}

fn owned(v: &[u8]) -> Vec<u8> {
    v.to_vec()
}

#[tokio::test]
async fn an_h2_capable_target_is_negotiated_as_h2_and_never_downgraded_behind_the_operator() {
    let origin = spawn_tls_origin(vec![owned(tls::ALPN_H2), owned(tls::ALPN_HTTP11)]).await;
    let store = TrafficStore::new();
    let proxy = spawn_proxy(ProxyConfig::new(store.clone()).with_tls_engine(engine())).await;

    let tls_client = connect_through(
        proxy,
        origin.port(),
        vec![owned(tls::ALPN_H2), owned(tls::ALPN_HTTP11)],
    )
    .await
    .expect("the client handshake must complete");

    // The property H2-04 turns on. The target offered h2 first, the client offered h2 first, and the
    // proxy in between neither hid the offer from the target nor hid the answer from the client.
    assert_eq!(
        tls_client.get_ref().1.alpn_protocol(),
        Some(tls::ALPN_H2),
        "an h2-capable target must not be served to the client as http/1.1"
    );

    // And the protocol is recorded as what was used, not as a default.
    let ex = wait_for_exchange(&store).await;
    assert_eq!(ex.protocol, Protocol::Http2);
    assert_eq!(ex.host, "localhost");
    assert_eq!(ex.port, origin.port());
    let note = ex.notes.clone().unwrap_or_default();
    assert!(
        note.contains("not forwarded"),
        "the gap must be stated on the row, not implied; notes were {note:?}"
    );
}

#[tokio::test]
async fn interception_downgrades_an_h2_capable_target_and_the_operator_caused_it() {
    // C6: the hold queue is an HTTP/1 message parser, so mirroring h2 would make most traffic
    // uninterceptable while the switch still said interception was on. Downgrading keeps the feature
    // working, and this is the case where H2-04's "not *silently* downgrading" is satisfied by the
    // downgrade being the operator's own switch.
    let origin = spawn_tls_origin(vec![owned(tls::ALPN_H2), owned(tls::ALPN_HTTP11)]).await;
    let store = TrafficStore::new();
    let (cfg, _ic) = intercepting_config(store.clone(), true);
    let proxy = spawn_proxy(cfg).await;

    let tls_client = connect_through(
        proxy,
        origin.port(),
        vec![owned(tls::ALPN_H2), owned(tls::ALPN_HTTP11)],
    )
    .await
    .expect("the client handshake must complete");

    assert_eq!(
        tls_client.get_ref().1.alpn_protocol(),
        Some(tls::ALPN_HTTP11),
        "with the hold queue on, both legs must be http/1.1"
    );
}

#[tokio::test]
async fn an_attached_but_switched_off_queue_does_not_downgrade() {
    // The switch that causes the downgrade has to be the one the operator can see. Keying on "an
    // interceptor is wired up" instead would make a build decision look like an operator decision.
    let origin = spawn_tls_origin(vec![owned(tls::ALPN_H2), owned(tls::ALPN_HTTP11)]).await;
    let store = TrafficStore::new();
    let (cfg, ic) = intercepting_config(store.clone(), false);
    let proxy = spawn_proxy(cfg).await;

    let tls_client = connect_through(
        proxy,
        origin.port(),
        vec![owned(tls::ALPN_H2), owned(tls::ALPN_HTTP11)],
    )
    .await
    .expect("the client handshake must complete");

    assert!(!ic.is_enabled());
    assert_eq!(
        tls_client.get_ref().1.alpn_protocol(),
        Some(tls::ALPN_H2),
        "an attached-but-disabled queue is not interception and must not cause a downgrade"
    );
}

#[tokio::test]
async fn a_target_that_sends_no_alpn_is_recorded_as_http1_and_still_forwarded() {
    // The arm the design's M2 says was never handled, and the one e2e-tls.sh exercises on every run:
    // an origin with no ALPN extension at all. Treating that as assumed-h2 would break every plain
    // TLS origin. This also proves the reordered handshake still forwards a real request.
    let origin = spawn_tls_origin(Vec::new()).await;
    let store = TrafficStore::new();
    let proxy = spawn_proxy(ProxyConfig::new(store.clone()).with_tls_engine(engine())).await;

    let mut tls_client = connect_through(
        proxy,
        origin.port(),
        vec![owned(tls::ALPN_H2), owned(tls::ALPN_HTTP11)],
    )
    .await
    .expect("the client handshake must complete");

    assert_eq!(
        tls_client.get_ref().1.alpn_protocol(),
        None,
        "an absent ALPN extension is mirrored as an absent one, not invented"
    );

    tls_client
        .write_all(b"GET /alpn HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tls_client.flush().await.unwrap();
    let mut reply = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = tls_client.read(&mut chunk).await {
        if n == 0 {
            break;
        }
        reply.extend_from_slice(&chunk[..n]);
        if reply.windows(4).any(|w| w == b"\r\n\r\n") && reply.ends_with(b"ORIGIN OK") {
            break;
        }
    }
    let reply = String::from_utf8_lossy(&reply).into_owned();
    assert!(reply.contains("ORIGIN OK"), "got {reply:?}");

    let ex = wait_for_exchange(&store).await;
    assert_eq!(
        ex.protocol,
        Protocol::Http1,
        "no ALPN means HTTP/1.1, and that is a measurement rather than a fallback"
    );
    assert_eq!(ex.method, "GET");
    assert_eq!(ex.path, "/alpn");
}

#[tokio::test]
async fn a_client_offering_only_h2_while_interception_is_on_is_refused_with_the_reason_recorded() {
    // The corner C6 creates: an h2-only client cannot be served while the queue is on. A bare TLS
    // alert would leave an operator with a browser error and an empty history, which is the same
    // ambiguity `record_failed_connect` exists to remove.
    let origin = spawn_tls_origin(vec![owned(tls::ALPN_H2)]).await;
    let store = TrafficStore::new();
    let (cfg, _ic) = intercepting_config(store.clone(), true);
    let proxy = spawn_proxy(cfg).await;

    let outcome = connect_through(proxy, origin.port(), vec![owned(tls::ALPN_H2)]).await;
    assert!(
        outcome.is_err(),
        "the proxy must not complete a handshake it cannot carry"
    );

    let ex = wait_for_exchange(&store).await;
    let note = ex.notes.clone().unwrap_or_default();
    assert!(
        note.contains("ALPN") && note.contains("h2"),
        "the refusal must name what the client offered; notes were {note:?}"
    );
    assert_eq!(ex.status, Some(502));
}
