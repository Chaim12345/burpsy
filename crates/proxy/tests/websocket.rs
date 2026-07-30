//! WebSocket capture against a real proxy, a real origin and real client sockets.
//!
//! The unit tests in `src/ws.rs` drive the relay directly over in-memory duplexes, which proves the
//! framing and the capture but says nothing about the part that is easy to get wrong: noticing the
//! handshake in the middle of the ordinary HTTP path, and not breaking that path for everything
//! else. That only shows up end to end, so these go through `burpsy_proxy::serve` on an ephemeral
//! port.

use burpsy_core::ws::{WsOpcode, unmask};
use burpsy_core::{Direction, Scope, ScopeRule, TrafficStore};
use burpsy_proxy::ProxyConfig;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An origin that completes a WebSocket handshake and then echoes every text frame back, prefixed.
///
/// Deliberately hand-rolled rather than a WebSocket library: the point is to control the exact bytes
/// on the wire, including putting the first server frame in the same write as the `101` — the case
/// that loses the opening of every conversation if the proxy drops it.
async fn spawn_ws_origin(greet_with_handshake: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
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
                let asked_to_upgrade = burpsy_core::ws::is_upgrade_request(&buf);
                if !asked_to_upgrade {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain",
                        )
                        .await;
                    return;
                }
                let mut out = b"HTTP/1.1 101 Switching Protocols\r\n\
                                Upgrade: websocket\r\n\
                                Connection: Upgrade\r\n\r\n"
                    .to_vec();
                if greet_with_handshake {
                    out.extend_from_slice(&frame(true, 0x1, None, b"welcome"));
                }
                if sock.write_all(&out).await.is_err() {
                    return;
                }
                // Echo loop. Reads whole frames the lazy way — the test only sends small unfragmented
                // ones — and answers each with its payload prefixed.
                loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    let Ok(Some(h)) = burpsy_core::ws::parse_frame_header(&chunk[..n]) else {
                        return;
                    };
                    let mut payload = chunk[h.header_len..n].to_vec();
                    if let Some(m) = h.mask {
                        unmask(&mut payload, m, 0);
                    }
                    let mut reply = b"echo:".to_vec();
                    reply.extend_from_slice(&payload);
                    if sock
                        .write_all(&frame(true, h.opcode.bits(), None, &reply))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn frame(fin: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    out.push(mask_bit | payload.len() as u8);
    match mask {
        Some(m) => {
            out.extend_from_slice(&m);
            let at = out.len();
            out.extend_from_slice(payload);
            unmask(&mut out[at..], m, 0);
        }
        None => out.extend_from_slice(payload),
    }
    out
}

async fn spawn_proxy(cfg: ProxyConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = burpsy_proxy::serve(listener, cfg).await;
    });
    addr
}

/// Poll rather than sleep a fixed time: a fixed sleep is either flaky or slow.
async fn wait_for_ws(store: &TrafficStore, n: usize) {
    for _ in 0..3000 {
        if store.ws_count() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!(
        "timed out waiting for {n} captured message(s), have {}",
        store.ws_count()
    );
}

fn payload_of(store: &TrafficStore, m: &burpsy_core::WsMessage) -> String {
    String::from_utf8_lossy(&store.get(m.payload).unwrap().raw).into_owned()
}

/// WS-01: a handshake through the proxy upgrades, both directions are captured, and the client's
/// masked frame reads as plaintext in history.
#[tokio::test]
async fn a_websocket_handshake_through_the_proxy_is_upgraded_and_captured() {
    let origin = spawn_ws_origin(true).await;
    let store = TrafficStore::new();
    let proxy = spawn_proxy(ProxyConfig::new(store.clone())).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin}/chat HTTP/1.1\r\n\
                 Host: {origin}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: keep-alive, Upgrade\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    // The 101 and the server's opening frame come back together.
    let mut buf = vec![0u8; 4096];
    let mut seen = Vec::new();
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = client.read(&mut buf).await.unwrap();
        assert_ne!(n, 0, "the proxy closed before answering the handshake");
        seen.extend_from_slice(&buf[..n]);
    }
    let head = String::from_utf8_lossy(&seen);
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols"),
        "the client must see the origin's own 101: {head:?}"
    );

    client
        .write_all(&frame(true, 0x1, Some([0x11, 0x22, 0x33, 0x44]), b"ping me"))
        .await
        .unwrap();

    // Two captured messages: the origin's greeting and the client's request. The echo makes three.
    wait_for_ws(&store, 3).await;

    let rows = store.ws_messages(0, 10);
    let sent: Vec<String> = rows
        .iter()
        .filter(|m| m.direction == Direction::Request)
        .map(|m| payload_of(&store, m))
        .collect();
    let received: Vec<String> = rows
        .iter()
        .filter(|m| m.direction == Direction::Response)
        .map(|m| payload_of(&store, m))
        .collect();

    assert_eq!(
        sent,
        vec!["ping me".to_string()],
        "the client's masked frame must appear unmasked in history"
    );
    assert!(
        received.contains(&"welcome".to_string()),
        "a frame sent alongside the 101 must not be dropped: {received:?}"
    );
    assert!(
        received.contains(&"echo:ping me".to_string()),
        "the echo must be captured too: {received:?}"
    );
    assert!(rows.iter().all(|m| m.opcode == WsOpcode::Text));

    // The handshake exchange itself is in history, answered 101, and every message names it.
    let ex = store.exchange(rows[0].exchange).expect("the handshake exchange");
    assert_eq!(ex.status, Some(101));
    assert_eq!(ex.path, "/chat");
    assert_eq!(store.verify_index(), Ok(()));
}

/// WS-03: out-of-scope traffic is relayed and never stored — the same rule the HTTP path follows.
///
/// The echo assertion at the end is the one that matters, and it caught a real defect: `forward_only`
/// relayed out-of-scope traffic with a one-way `tokio::io::copy`, which is right for a request/response
/// exchange and leaves an upgraded connection able to receive and unable to send. An out-of-scope
/// WebSocket is not recorded, but it still has to *work* — that is the whole point of forwarding
/// traffic outside the engagement rather than blocking it.
#[tokio::test]
async fn an_out_of_scope_websocket_is_relayed_without_being_recorded() {
    let origin = spawn_ws_origin(false).await;
    let store = TrafficStore::new();
    let mut scope = Scope::new();
    scope.add(ScopeRule::include("in-scope.test"));
    let proxy = spawn_proxy(ProxyConfig::new(store.clone()).with_scope(scope)).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin}/chat HTTP/1.1\r\nHost: {origin}\r\n\
                 Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let mut seen = Vec::new();
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = client.read(&mut buf).await.unwrap();
        assert_ne!(n, 0, "an out-of-scope upgrade must still be forwarded");
        seen.extend_from_slice(&buf[..n]);
    }
    assert!(
        String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 101"),
        "the upgrade must succeed even though nothing is recorded"
    );

    // And the socket genuinely works afterwards.
    client
        .write_all(&frame(true, 0x1, Some([1, 1, 1, 1]), b"hi"))
        .await
        .unwrap();
    let n = client.read(&mut buf).await.unwrap();
    let echoed = burpsy_core::ws::parse_frame_header(&buf[..n]).unwrap().unwrap();
    assert_eq!(
        &buf[echoed.header_len..n],
        b"echo:hi",
        "the echo must come back through an unrecorded relay"
    );

    assert_eq!(
        store.ws_count(),
        0,
        "out-of-scope frames must not be stored, exactly as out-of-scope requests are not"
    );
    assert_eq!(store.counts().0, 0, "and no exchange row either");
}

/// WS-01: the regression that matters most. Adding WebSocket detection must leave an ordinary
/// request byte-identical, including one that merely *asks* to upgrade and is refused.
#[tokio::test]
async fn ordinary_http_is_unaffected_including_a_refused_upgrade() {
    // This origin answers 200 to anything that is not an upgrade request, and 101 to one that is.
    let origin = spawn_ws_origin(false).await;
    let store = TrafficStore::new();
    let proxy = spawn_proxy(ProxyConfig::new(store.clone())).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/plain HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&got),
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain",
        "a non-upgrade request must be relayed exactly as before"
    );
    assert_eq!(store.ws_count(), 0);
    let ex = store.exchange(0).expect("the ordinary exchange is recorded");
    assert_eq!((ex.status, ex.response_len), (Some(200), got.len()));
}

/// WS-01: a client that asks to upgrade and gets an ordinary response back must see that response
/// whole — the head this code reads separately has to be handed on, not swallowed.
#[tokio::test]
async fn an_upgrade_the_origin_refuses_falls_back_to_the_ordinary_response_path() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap();
    // An origin that refuses every upgrade with a bodied 400, head and body in separate writes so
    // the fallback has to reassemble them.
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut chunk = [0u8; 4096];
            let mut buf = Vec::new();
            loop {
                let Ok(n) = sock.read(&mut chunk).await else {
                    break;
                };
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 9\r\n\r\n")
                .await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = sock.write_all(b"no thanks").await;
            let _ = sock.shutdown().await;
        }
    });

    let store = TrafficStore::new();
    let proxy = spawn_proxy(ProxyConfig::new(store.clone())).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin}/chat HTTP/1.1\r\nHost: {origin}\r\n\
                 Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&got),
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 9\r\n\r\nno thanks",
        "the head read to test for a 101 must be forwarded, not consumed"
    );
    assert_eq!(store.ws_count(), 0, "a refused upgrade carries no frames");
    let ex = store.exchange(0).unwrap();
    assert_eq!(ex.status, Some(400));
    assert_eq!(
        ex.response_len,
        got.len(),
        "history must record the whole response, prefix included"
    );
}
