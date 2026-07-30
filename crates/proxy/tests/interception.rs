//! Interception against a real proxy, a real origin and real client sockets.
//!
//! Everything here goes through `burpsy_proxy::serve` on an ephemeral port. The properties under
//! test are all about what happens *between* connections — one held request not stalling another,
//! an edit reaching the wire, a drop not reaching it — and none of those can be observed by calling
//! the interceptor directly.

use burpsy_core::{Scope, ScopeRule, TrafficStore};
use burpsy_proxy::{
    InterceptRuleSpec, InterceptRules, InterceptRulesSpec, Interceptor, MatchField, ProxyConfig,
    TlsEngine, tls,
};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// An origin that echoes what it was asked for and counts how many requests actually arrived.
struct Origin {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

async fn spawn_origin() -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let counter = counter.clone();
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
                counter.fetch_add(1, Ordering::SeqCst);
                let line = String::from_utf8_lossy(&buf);
                let start = line.lines().next().unwrap_or_default();
                let mut it = start.split_whitespace();
                let body = format!(
                    "ORIGIN {} {}",
                    it.next().unwrap_or_default(),
                    it.next().unwrap_or_default()
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    Origin { addr, hits }
}

/// An origin that answers and then **stays open**.
///
/// `spawn_origin` closes its socket after one response, so every test using it leaves the proxy's read
/// loop on an EOF — which means those tests pass whether or not the loop understands framing at all.
/// Holding a response makes framing load-bearing: there is no EOF coming, so a loop that waits for a
/// body the origin will never send never offers the response, and the operator has nothing to release.
/// This origin exists to make that failure reachable, and it answers the three shapes that cause it.
async fn spawn_keepalive_origin() -> SocketAddr {
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
                let head = String::from_utf8_lossy(&buf).to_string();
                let resp: &str = if head.starts_with("HEAD ") {
                    // A HEAD answer names the length a GET would have returned, and sends no body.
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 42\r\n\r\n"
                } else if head.contains("/interim") {
                    // What a CDN does: early hints, then the real answer, on one connection.
                    "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n\
                     HTTP/1.1 500 Server Error\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nboom!"
                } else {
                    // A 304 legitimately echoes a length it will not send. This is the shape a browser
                    // with a warm cache produces continuously.
                    "HTTP/1.1 304 Not Modified\r\nContent-Type: text/html\r\nContent-Length: 99\r\n\r\n"
                };
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
                // Deliberately never closed: the whole point is that no EOF arrives.
                std::future::pending::<()>().await;
            });
        }
    });
    addr
}

/// Send one request through the proxy and read whatever comes back within `ms`.
///
/// Deliberately *not* framing-aware, unlike `read_response`: a framing-aware reader here would have to
/// reimplement the logic under test, and would then hang on exactly the responses these tests are
/// about. The deadline is the assertion — the proxy either answers promptly or it does not.
async fn probe(proxy: SocketAddr, origin: SocketAddr, method: &str, path: &str, ms: u64) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let req = format!("{method} http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    s.flush().await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, s.read(&mut chunk)).await {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Bring up a proxy on an ephemeral port and hand back where to reach it.
async fn spawn_proxy(cfg: ProxyConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { burpsy_proxy::serve(listener, cfg).await });
    addr
}

/// Send one absolute-form request through the proxy and read the whole reply.
async fn through_proxy(proxy: SocketAddr, origin: SocketAddr, path: &str) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let req =
        format!("GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\nAccept: */*\r\n\r\n",);
    s.write_all(req.as_bytes()).await.unwrap();
    s.flush().await.unwrap();
    read_response(&mut s).await
}

/// Read headers, then exactly the declared body. Falls back to EOF when unframed.
///
/// Generic over the stream so both a plain `TcpStream` (HTTP) and a `TlsStream` (MITM) share one
/// completion rule — a duplicated copy for TLS is exactly how the two paths would drift apart.
async fn read_response<S: AsyncReadExt + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = s.read(&mut chunk).await {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
            let want = head.lines().find_map(|l| {
                let (n, v) = l.split_once(':')?;
                (n.trim() == "content-length").then(|| v.trim().parse::<usize>().ok())?
            });
            if let Some(w) = want
                && buf.len() >= i + 4 + w
            {
                break;
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Poll rather than sleep: a fixed sleep is either flaky or slow.
async fn wait_for_pending(ic: &Interceptor, n: usize) {
    for _ in 0..3000 {
        if ic.pending() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!(
        "timed out waiting for {n} held request(s); have {}",
        ic.pending()
    );
}

fn config(store: Arc<TrafficStore>, ic: Arc<Interceptor>, scope: Scope) -> ProxyConfig {
    ProxyConfig::new(store)
        .with_scope(scope)
        .with_interceptor(ic)
}

fn tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A fresh CA-backed engine, one per test — MITM needs a real leaf-signing engine, and each test
/// gets its own so none can interfere with another's certificate cache.
fn tls_engine() -> Arc<TlsEngine> {
    let (ca, _, _) = tls::generate_ca("burpsy interception test").unwrap();
    Arc::new(TlsEngine::new(ca))
}

/// A TLS origin that echoes the request line, exactly like `spawn_origin` but over a real TLS
/// socket and offering only `http/1.1` — the MITM scope test needs ciphertext the proxy actually
/// has to decrypt, not a plaintext stand-in.
async fn spawn_tls_origin() -> SocketAddr {
    let eng = tls_engine();
    let mut server_cfg = rustls::ServerConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(eng.resolver_for("localhost"));
    server_cfg.alpn_protocols = vec![tls::ALPN_HTTP11.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

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
                let line = String::from_utf8_lossy(&buf);
                let start = line.lines().next().unwrap_or_default();
                let mut it = start.split_whitespace();
                let body = format!(
                    "ORIGIN {} {}",
                    it.next().unwrap_or_default(),
                    it.next().unwrap_or_default()
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });
    addr
}

/// `CONNECT localhost:<port>` through the proxy, then a client TLS handshake speaking `http/1.1`.
///
/// `localhost`, not `127.0.0.1`: `TlsPolicy` sends IP-literal `CONNECT`s down the blind-tunnel
/// path — there is no SNI hostname to sign a leaf for — and a blind tunnel never reaches `mitm`.
async fn connect_tls_through(
    proxy: SocketAddr,
    origin_port: u16,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let req =
        format!("CONNECT localhost:{origin_port} HTTP/1.1\r\nHost: localhost:{origin_port}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    s.flush().await.unwrap();

    // Read the `200 Connection Established` reply one octet at a time: a larger read would
    // swallow the first TLS records behind it.
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = s.read(&mut one).await.unwrap();
        assert_eq!(n, 1, "proxy closed before answering CONNECT");
        head.push(one[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "CONNECT got {head:?}");

    let connector = TlsConnector::from(tls::upstream_client_config(&[tls::ALPN_HTTP11.to_vec()]));
    let dns = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    connector.connect(dns, s).await.unwrap()
}

/// The property most likely to break, and the reason for a oneshot per request rather than a gate.
///
/// "Must not block another connection" does NOT mean B skips the queue — a real intercepting proxy
/// holds every matching request while interception is on, and B is just as in-scope as A. It means
/// the hold queue must not be a single gate that serializes connection handling: A parked in its own
/// oneshot must not stop the proxy from accepting, parsing and queueing B independently. If holding
/// were implemented as (say) a mutex taken for the duration of the wait rather than a oneshot per
/// request, B's connection would never even reach the point of being queued — it would stall inside
/// accept()/read() waiting on that lock, which is indistinguishable from the proxy being frozen.
#[tokio::test]
async fn holding_one_request_does_not_block_another_connection() {
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), Scope::allow_everything())).await;

    // A goes first and gets held.
    let held_a = {
        let oa = origin.addr;
        tokio::spawn(async move { through_proxy(proxy, oa, "/held-a").await })
    };
    wait_for_pending(&ic, 1).await;

    // B arrives while A is still parked. If the queue were a single gate rather than a oneshot per
    // request, this would never even reach the point of being counted — the connection would be
    // stuck behind A at the accept/read level, which is exactly the bug this test exists to catch.
    let held_b = {
        let oa = origin.addr;
        tokio::spawn(async move { through_proxy(proxy, oa, "/held-b").await })
    };
    wait_for_pending(&ic, 2).await;
    assert!(
        !held_a.is_finished() && !held_b.is_finished(),
        "both must still be parked — this proves B reached the queue without waiting on A"
    );

    // Order of release is independent: forwarding B first must not require touching A.
    let queued = ic.list();
    assert_eq!(queued.len(), 2);
    let b_id = queued.iter().find(|q| q.path == "/held-b").unwrap().id;
    let a_id = queued.iter().find(|q| q.path == "/held-a").unwrap().id;

    assert!(ic.forward(b_id, None));
    let b = held_b.await.unwrap();
    assert!(b.contains("ORIGIN GET /held-b"), "B got {b:?}");
    assert_eq!(ic.pending(), 1, "only A should remain held");
    assert!(
        !held_a.is_finished(),
        "forwarding B must not have released A"
    );

    assert!(ic.forward(a_id, None));
    let a = held_a.await.unwrap();
    assert!(a.contains("ORIGIN GET /held-a"), "A got {a:?}");
    assert_eq!(ic.pending(), 0);
    assert_eq!(origin.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_edited_request_is_what_reaches_the_origin_and_what_history_records() {
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), Scope::allow_everything())).await;

    let client = {
        let oa = origin.addr;
        tokio::spawn(async move { through_proxy(proxy, oa, "/original").await })
    };
    wait_for_pending(&ic, 1).await;

    let held = ic.list().remove(0);
    assert!(
        held.raw.contains("GET /original HTTP/1.1"),
        "held raw was {:?}",
        held.raw
    );
    let edited = held
        .raw
        .replace("/original", "/rewritten")
        .replace("Accept: */*", "Accept: edited");
    assert!(ic.forward(held.id, Some(Bytes::from(edited))));

    // The origin saw the edit...
    let body = client.await.unwrap();
    assert!(
        body.contains("ORIGIN GET /rewritten"),
        "origin echoed {body:?}"
    );

    // ...and so does history, both in the indexed path and in the stored bytes.
    let exchanges = store.exchanges(0, 10);
    assert_eq!(exchanges.len(), 1, "one forwarded request, one exchange");
    assert_eq!(
        exchanges[0].path, "/rewritten",
        "the index must not keep the pre-edit path"
    );
    let stored = store.get(exchanges[0].request).unwrap();
    let text = String::from_utf8_lossy(&stored.raw);
    assert!(
        text.contains("GET /rewritten HTTP/1.1"),
        "stored request was {text:?}"
    );
    assert!(
        text.contains("Accept: edited"),
        "stored request was {text:?}"
    );
    assert!(
        !text.contains("/original"),
        "the original bytes must not survive: {text:?}"
    );
}

#[tokio::test]
async fn a_dropped_request_gets_a_synthetic_response_and_never_reaches_the_origin() {
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), Scope::allow_everything())).await;

    let client = {
        let oa = origin.addr;
        tokio::spawn(async move { through_proxy(proxy, oa, "/nope").await })
    };
    wait_for_pending(&ic, 1).await;
    let id = ic.list()[0].id;
    assert!(ic.drop_request(id, "testing the drop path"));

    let body = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("a dropped request must answer its client, not hang it")
        .unwrap();
    assert!(body.starts_with("HTTP/1.1 403 Forbidden"), "got {body:?}");
    assert!(body.contains("X-Burpsy-Intercept: dropped"), "got {body:?}");
    assert!(
        body.contains("testing the drop path"),
        "the reason must reach the client: {body:?}"
    );
    assert_eq!(
        origin.hits.load(Ordering::SeqCst),
        0,
        "a dropped request must not be sent"
    );

    // The attempt is still history: an operator needs to see what they refused.
    let exchanges = store.exchanges(0, 10);
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].status, Some(403));
    assert!(
        exchanges[0]
            .notes
            .as_deref()
            .unwrap_or_default()
            .contains("dropped by operator"),
        "notes were {:?}",
        exchanges[0].notes
    );
}

#[tokio::test]
async fn an_edited_response_is_what_the_client_reads_and_what_history_records() {
    // The response hold point in one test: the client sees nothing until the verdict, the edit is
    // what it eventually reads, and history agrees with the client rather than with the origin.
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    // Requests stay blanket-held (the default); responses have to be switched on.
    ic.set_response_rules(InterceptRules::unconditional());
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), Scope::allow_everything())).await;

    let client = {
        let oa = origin.addr;
        tokio::spawn(async move { through_proxy(proxy, oa, "/two-halves").await })
    };

    // Half one: the request.
    wait_for_pending(&ic, 1).await;
    let req = ic.list().remove(0);
    assert_eq!(req.direction, "request");
    assert_eq!(req.status, None);
    assert!(ic.forward(req.id, None));

    // Half two: the response the origin sent back, held on the same connection task.
    wait_for_pending(&ic, 1).await;
    let resp = ic.list().remove(0);
    assert_eq!(resp.direction, "response");
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.path, "/two-halves",
        "a held response carries the route of the request that provoked it"
    );
    assert!(
        resp.raw.contains("ORIGIN GET /two-halves"),
        "held response was {:?}",
        resp.raw
    );
    assert!(
        !client.is_finished(),
        "the client must have read nothing while the response is held — if it has finished, the \
         relay streamed past the hold point"
    );

    let edited = resp.raw.replace("ORIGIN", "REWRITTEN");
    assert!(ic.forward(resp.id, Some(Bytes::from(edited))));

    let body = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("forwarding the response must release the client")
        .unwrap();
    assert!(body.contains("REWRITTEN GET /two-halves"), "client read {body:?}");
    assert!(!body.contains("ORIGIN GET"), "client read {body:?}");

    let exchanges = store.exchanges(0, 10);
    assert_eq!(exchanges.len(), 1);
    let stored = store.get(exchanges[0].response.expect("a response was stored")).unwrap();
    let text = String::from_utf8_lossy(&stored.raw);
    assert!(
        text.contains("REWRITTEN GET /two-halves"),
        "history must record what the client actually read: {text:?}"
    );
    assert!(
        !text.contains("ORIGIN GET"),
        "the origin's original bytes must not survive the edit: {text:?}"
    );
}

#[tokio::test]
async fn a_dropped_response_reaches_the_client_as_a_synthetic_answer_not_a_dead_socket() {
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    ic.set_response_rules(InterceptRules::unconditional());
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), Scope::allow_everything())).await;

    let client = {
        let oa = origin.addr;
        tokio::spawn(async move { through_proxy(proxy, oa, "/suppressed").await })
    };
    wait_for_pending(&ic, 1).await;
    assert!(ic.forward(ic.list()[0].id, None));
    wait_for_pending(&ic, 1).await;
    assert!(ic.drop_request(ic.list()[0].id, "not for this client"));

    let body = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("a dropped response must still answer the client")
        .unwrap();
    assert!(body.starts_with("HTTP/1.1 403"), "client read {body:?}");
    assert!(body.contains("response dropped by operator"), "client read {body:?}");
    assert!(body.contains("not for this client"), "client read {body:?}");
    assert!(
        !body.contains("ORIGIN GET"),
        "the origin's answer must not leak past the drop: {body:?}"
    );
    assert_eq!(
        origin.hits.load(Ordering::SeqCst),
        1,
        "dropping a response happens after the origin has already answered"
    );
}

#[tokio::test]
async fn a_response_condition_that_cannot_match_the_route_leaves_the_relay_streaming() {
    // The pre-response prefilter, observed from outside: a host condition naming somewhere else must
    // not buffer, must not hold, and must not delay the client.
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    ic.set_request_rules(InterceptRules::off());
    ic.set_response_rules(
        InterceptRules::compile(InterceptRulesSpec {
            active: true,
            rules: vec![InterceptRuleSpec::new(MatchField::Host, "^nowhere\\.test$")],
        })
        .unwrap(),
    );
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), Scope::allow_everything())).await;

    let body = tokio::time::timeout(
        Duration::from_secs(5),
        through_proxy(proxy, origin.addr, "/streamed"),
    )
    .await
    .expect("a condition that cannot match must not hold anything")
    .to_string();

    assert!(body.contains("ORIGIN GET /streamed"), "got {body:?}");
    assert_eq!(ic.pending(), 0, "nothing should have entered the queue");
    assert_eq!(
        store.exchanges(0, 10).len(),
        1,
        "capture is unaffected by conditions; only holding is"
    );
}

#[tokio::test]
async fn a_status_code_condition_holds_the_response_it_names_and_relays_the_others() {
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    ic.set_request_rules(InterceptRules::off());
    // The origin only ever answers 200, so `^5..$` can never match — but it is a *response* fact,
    // so the prefilter has to buffer to find that out, and then release without holding.
    ic.set_response_rules(
        InterceptRules::compile(InterceptRulesSpec {
            active: true,
            rules: vec![InterceptRuleSpec::new(MatchField::StatusCode, "^5..$")],
        })
        .unwrap(),
    );
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), Scope::allow_everything())).await;

    let body = tokio::time::timeout(
        Duration::from_secs(5),
        through_proxy(proxy, origin.addr, "/a-200"),
    )
    .await
    .expect("a 200 does not match ^5..$, so it must be released unheld")
    .to_string();
    assert!(body.contains("ORIGIN GET /a-200"), "got {body:?}");
    assert_eq!(ic.pending(), 0);

    // Now a condition the same response does satisfy: same route, same origin, held this time.
    ic.set_response_rules(
        InterceptRules::compile(InterceptRulesSpec {
            active: true,
            rules: vec![InterceptRuleSpec::new(MatchField::StatusCode, "^200$")],
        })
        .unwrap(),
    );
    let client = {
        let oa = origin.addr;
        tokio::spawn(async move { through_proxy(proxy, oa, "/a-200-again").await })
    };
    wait_for_pending(&ic, 1).await;
    let held = ic.list().remove(0);
    assert_eq!(held.direction, "response");
    assert_eq!(held.status, Some(200));
    assert!(ic.forward(held.id, None));
    let body = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("forwarding must release the client")
        .unwrap();
    assert!(body.contains("ORIGIN GET /a-200-again"), "got {body:?}");
}

/// Interception on, requests untouched, every response offered — the configuration each of the three
/// framing tests below needs.
fn responses_only(store: Arc<TrafficStore>, ic: Arc<Interceptor>) -> ProxyConfig {
    ic.set_enabled(true);
    ic.set_request_rules(InterceptRules::off());
    ic.set_response_rules(InterceptRules::unconditional());
    config(store, ic, Scope::allow_everything())
}

#[tokio::test]
async fn a_bodiless_response_completes_by_framing_not_by_the_origin_hanging_up() {
    // The regression: `response_complete_len` read `Content-Length` before noticing that a 304 has no
    // body, so the buffering branch waited for 99 bytes that never come. With no EOF to rescue it the
    // client got nothing *and* the response never reached the queue — so the operator could not even
    // release it. `wait_for_pending` below is what fails if that comes back.
    let origin = spawn_keepalive_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    let proxy = spawn_proxy(responses_only(store.clone(), ic.clone())).await;

    let client = tokio::spawn(async move { probe(proxy, origin, "GET", "/cached", 3000).await });
    wait_for_pending(&ic, 1).await;
    let held = ic.list().remove(0);
    assert_eq!(held.direction, "response");
    assert_eq!(held.status, Some(304));
    assert!(ic.forward(held.id, None));

    let body = client.await.unwrap();
    assert!(body.starts_with("HTTP/1.1 304"), "client read {body:?}");
}

#[tokio::test]
async fn a_head_response_is_complete_at_its_head_whatever_length_it_advertises() {
    // Nothing in a response says the request was a HEAD, so the method has to be carried to the
    // framing check. Without it this waits for 42 bytes the origin is correct never to send.
    let origin = spawn_keepalive_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    let proxy = spawn_proxy(responses_only(store.clone(), ic.clone())).await;

    let client = tokio::spawn(async move { probe(proxy, origin, "HEAD", "/thing", 3000).await });
    wait_for_pending(&ic, 1).await;
    let held = ic.list().remove(0);
    assert_eq!(held.method, "HEAD");
    assert_eq!(held.status, Some(200));
    assert!(
        held.raw.ends_with("\r\n\r\n"),
        "the head is the whole message: {:?}",
        held.raw
    );
    assert!(ic.forward(held.id, None));

    let body = client.await.unwrap();
    assert!(body.starts_with("HTTP/1.1 200"), "client read {body:?}");
}

#[tokio::test]
async fn an_interim_1xx_is_not_the_status_that_conditions_or_history_see() {
    // A 103 is complete at the end of its own head, so anchoring on the first `\r\n\r\n` framed the
    // exchange as unterminated *and* made every response condition test `103`. A rule naming 5xx
    // would silently never fire on a 500 that arrived behind early hints, and history would say 103.
    let origin = spawn_keepalive_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    ic.set_request_rules(InterceptRules::off());
    ic.set_response_rules(
        InterceptRules::compile(InterceptRulesSpec {
            active: true,
            rules: vec![InterceptRuleSpec::new(MatchField::StatusCode, "^5..$")],
        })
        .unwrap(),
    );
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), Scope::allow_everything())).await;

    let client = tokio::spawn(async move { probe(proxy, origin, "GET", "/interim", 3000).await });
    wait_for_pending(&ic, 1).await;
    let held = ic.list().remove(0);
    assert_eq!(
        held.status,
        Some(500),
        "the answer is the 500, not the 103 in front of it"
    );
    assert!(
        held.raw.contains("103 Early Hints"),
        "the interim head still goes to the client, so it is still in the held bytes: {:?}",
        held.raw
    );
    assert!(ic.forward(held.id, None));

    let body = client.await.unwrap();
    assert!(body.contains("103 Early Hints"), "client read {body:?}");
    assert!(body.contains("boom!"), "client read {body:?}");

    let exchanges = store.exchanges(0, 10);
    assert_eq!(exchanges.len(), 1);
    assert_eq!(
        exchanges[0].status,
        Some(500),
        "history must record the answer, not the hint"
    );
}

#[tokio::test]
async fn out_of_scope_traffic_passes_through_untouched_while_interception_is_on() {
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    // Scope covers a host this test never contacts, so the origin is out of scope.
    let mut scope = Scope::new();
    scope.add(ScopeRule::include("in-scope.test"));
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), scope)).await;

    let body = tokio::time::timeout(
        Duration::from_secs(5),
        through_proxy(proxy, origin.addr, "/elsewhere"),
    )
    .await
    .expect("out-of-scope traffic must not be held")
    .to_string();

    assert!(body.contains("ORIGIN GET /elsewhere"), "got {body:?}");
    assert_eq!(
        ic.pending(),
        0,
        "out-of-scope traffic must never enter the queue"
    );
    assert_eq!(
        store.exchanges(0, 10).len(),
        0,
        "out-of-scope traffic is forwarded but not retained"
    );
}

/// The capture side of runtime-editable scope, which is what the UI's confirmation dialog warns about.
///
/// Scope used to be fixed at startup and every subsystem held its own `Arc<Scope>` copy, so this could
/// not have passed: the proxy task would keep testing the rules it was spawned with. The dialog makes
/// two promises and both are asserted here — traffic after the edit is captured, and traffic from
/// before it is *not* retroactively captured, because the proxy never had those bytes to keep.
#[tokio::test]
async fn a_rule_added_while_the_proxy_runs_changes_what_it_captures_from_then_on() {
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    // One handle. The proxy gets a clone of it, not a clone of the rules.
    let scope = burpsy_core::SharedScope::empty();
    let proxy = spawn_proxy(ProxyConfig::new(store.clone()).with_scope(scope.clone())).await;

    let body = tokio::time::timeout(
        Duration::from_secs(5),
        through_proxy(proxy, origin.addr, "/before"),
    )
    .await
    .expect("out-of-scope traffic is still forwarded");
    assert!(body.contains("ORIGIN GET /before"), "got {body:?}");
    assert_eq!(
        store.exchanges(0, 10).len(),
        0,
        "nothing is in scope yet, so nothing is retained"
    );

    // The operator adds the host. Same process, same proxy task, no restart.
    scope.add_rule(ScopeRule::include("127.0.0.1"));

    let body = tokio::time::timeout(
        Duration::from_secs(5),
        through_proxy(proxy, origin.addr, "/after"),
    )
    .await
    .expect("in-scope traffic must still be forwarded");
    assert!(body.contains("ORIGIN GET /after"), "got {body:?}");

    let exchanges = store.exchanges(0, 10);
    assert_eq!(
        exchanges.len(),
        1,
        "exactly the request made after the edit should be in history"
    );
    assert_eq!(
        exchanges[0].path, "/after",
        "the pre-edit request must not be captured retroactively"
    );
}

#[tokio::test]
async fn an_edit_that_moves_a_request_onto_an_excluded_path_is_forwarded_but_not_retained() {
    // A-4 re-tested scope after the hold for the plain path; this is the sibling that re-test
    // must actually protect against: an operator's own edit moving a request onto a path the
    // scope excludes, after it was already shown to them as in-scope.
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    let mut scope = Scope::new();
    scope.add(ScopeRule::include("127.0.0.1"));
    scope.add(ScopeRule::exclude("127.0.0.1").with_path_prefix("/excluded"));
    let proxy = spawn_proxy(config(store.clone(), ic.clone(), scope)).await;

    let client = {
        let oa = origin.addr;
        tokio::spawn(async move { through_proxy(proxy, oa, "/original").await })
    };
    wait_for_pending(&ic, 1).await;

    let held = ic.list().remove(0);
    let edited = held.raw.replace("/original", "/excluded/secret");
    assert!(ic.forward(held.id, Some(Bytes::from(edited))));

    // The origin still receives the edit — scope governs retention, not egress.
    let body = client.await.unwrap();
    assert!(
        body.contains("ORIGIN GET /excluded/secret"),
        "origin echoed {body:?}"
    );
    assert_eq!(
        origin.hits.load(Ordering::SeqCst),
        1,
        "the edited request must reach the origin exactly once"
    );

    // History gets one explanatory row, not the excluded request itself: silence here would let
    // an operator edit a request out of scope and out of history in the same keystroke.
    let exchanges = store.exchanges(0, 10);
    assert_eq!(
        exchanges.len(),
        1,
        "the edit must leave a marker, not the retained request: {exchanges:?}"
    );
    assert!(!exchanges[0].tls);
    assert!(
        exchanges[0]
            .notes
            .as_deref()
            .unwrap_or_default()
            .contains("excluded"),
        "notes were {:?}",
        exchanges[0].notes
    );
    let stored = store.get(exchanges[0].request).unwrap();
    let text = String::from_utf8_lossy(&stored.raw);
    assert!(
        !text.starts_with("GET /excluded/secret HTTP/1.1") && !text.contains("Accept: */*"),
        "the excluded request's real headers must not be retained, only the marker: {text:?}"
    );
}

#[tokio::test]
async fn an_edit_that_moves_a_mitm_request_onto_an_excluded_path_is_forwarded_but_not_retained() {
    // The MITM sibling of the test above. A-4's re-test lived only in `forward_http`; `mitm` had
    // no scope test in its loop at all, so this must fail without the fix in `mitm`.
    let origin_port = spawn_tls_origin().await.port();
    let store = TrafficStore::new();
    let ic = Interceptor::new();
    ic.set_enabled(true);
    let mut scope = Scope::new();
    scope.add(ScopeRule::include("localhost"));
    scope.add(ScopeRule::exclude("localhost").with_path_prefix("/excluded"));
    let cfg = ProxyConfig::new(store.clone())
        .with_scope(scope)
        .with_interceptor(ic.clone())
        .with_tls_engine(tls_engine());
    let proxy = spawn_proxy(cfg).await;

    let mut tls_client = connect_tls_through(proxy, origin_port).await;
    tls_client
        .write_all(b"GET /original HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\n")
        .await
        .unwrap();
    tls_client.flush().await.unwrap();

    wait_for_pending(&ic, 1).await;
    let held = ic.list().remove(0);
    assert!(held.tls, "the held request must be marked tls: {held:?}");
    let edited = held.raw.replace("/original", "/excluded/secret");
    assert!(ic.forward(held.id, Some(Bytes::from(edited))));

    let reply = read_response(&mut tls_client).await;
    assert!(
        reply.contains("ORIGIN GET /excluded/secret"),
        "the origin must still receive the edited request over TLS: {reply:?}"
    );

    let exchanges = store.exchanges(0, 10);
    assert_eq!(
        exchanges.len(),
        1,
        "the MITM edit must leave a marker, not the retained request: {exchanges:?}"
    );
    assert!(
        exchanges[0].tls,
        "the marker must still record this as a TLS exchange"
    );
    assert!(
        exchanges[0]
            .notes
            .as_deref()
            .unwrap_or_default()
            .contains("excluded"),
        "notes were {:?}",
        exchanges[0].notes
    );
    let stored = store.get(exchanges[0].request).unwrap();
    let text = String::from_utf8_lossy(&stored.raw);
    assert!(
        !text.starts_with("GET /excluded/secret HTTP/1.1") && !text.contains("Accept: */*"),
        "the excluded MITM request's real headers must not be retained, only the marker: {text:?}"
    );
}

#[tokio::test]
async fn a_connect_that_cannot_reach_upstream_is_recorded_rather_than_vanishing() {
    let store = TrafficStore::new();
    let cfg = ProxyConfig::new(store.clone());
    let proxy = spawn_proxy(cfg).await;

    // Bind and immediately drop a listener to get a port nothing is listening on.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let mut s = TcpStream::connect(proxy).await.unwrap();
    let req = format!("CONNECT 127.0.0.1:{dead} HTTP/1.1\r\nHost: 127.0.0.1:{dead}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
        .await
        .expect("a failed CONNECT must answer, not hang")
        .unwrap();
    let reply = String::from_utf8_lossy(&buf);
    assert!(reply.starts_with("HTTP/1.1 502"), "client got {reply:?}");

    let exchanges = store.exchanges(0, 10);
    assert_eq!(exchanges.len(), 1, "the failed attempt must leave a trace");
    let ex = &exchanges[0];
    assert_eq!(ex.method, "CONNECT");
    assert_eq!(ex.host, "127.0.0.1");
    assert_eq!(ex.port, dead);
    assert!(ex.tls);
    assert_eq!(ex.status, Some(502));
    let note = ex.notes.clone().unwrap_or_default();
    assert!(note.contains("connect failed"), "notes were {note:?}");
    let resp = store
        .get(ex.response.expect("a synthetic response is recorded"))
        .unwrap();
    assert!(
        String::from_utf8_lossy(&resp.raw).contains("upstream connect failed"),
        "the recorded reason must name the failure"
    );
}

#[tokio::test]
async fn a_successful_connect_and_a_failed_one_are_distinguishable_in_history() {
    // The whole point of recording failures: "never visited" and "unreachable" must not look alike.
    let origin = spawn_origin().await;
    let store = TrafficStore::new();
    let proxy = spawn_proxy(ProxyConfig::new(store.clone())).await;

    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    for port in [origin.addr.port(), dead] {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        let req = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        s.flush().await.unwrap();
        // Half-close so the blind tunnel to the reachable port terminates promptly.
        s.shutdown().await.ok();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    }

    let mut rows = store.exchanges(0, 10);
    rows.sort_by_key(|e| e.port == dead);
    assert_eq!(rows.len(), 2, "both attempts are recorded");
    assert_eq!(rows[0].status, Some(200), "the reachable host tunnelled");
    assert_eq!(
        rows[1].status,
        Some(502),
        "the unreachable host is a distinct row"
    );
    assert!(
        rows[1]
            .notes
            .clone()
            .unwrap_or_default()
            .contains("connect failed")
    );
}
