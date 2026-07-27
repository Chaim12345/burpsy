//! Interception against a real proxy, a real origin and real client sockets.
//!
//! Everything here goes through `burpsy_proxy::serve` on an ephemeral port. The properties under
//! test are all about what happens *between* connections — one held request not stalling another,
//! an edit reaching the wire, a drop not reaching it — and none of those can be observed by calling
//! the interceptor directly.

use burpsy_core::{Scope, ScopeRule, TrafficStore};
use burpsy_proxy::{Interceptor, ProxyConfig};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
            let Ok((mut sock, _)) = listener.accept().await else { break };
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = sock.read(&mut chunk).await else { return };
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
    let req = format!(
        "GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\nAccept: */*\r\n\r\n",
    );
    s.write_all(req.as_bytes()).await.unwrap();
    s.flush().await.unwrap();
    read_response(&mut s).await
}

/// Read headers, then exactly the declared body. Falls back to EOF when unframed.
async fn read_response(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let Ok(n) = s.read(&mut chunk).await else { break };
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
    panic!("timed out waiting for {n} held request(s); have {}", ic.pending());
}

fn config(store: Arc<TrafficStore>, ic: Arc<Interceptor>, scope: Scope) -> ProxyConfig {
    ProxyConfig::new(store).with_scope(scope).with_interceptor(ic)
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
    assert!(!held_a.is_finished(), "forwarding B must not have released A");

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
    assert!(held.raw.contains("GET /original HTTP/1.1"), "held raw was {:?}", held.raw);
    let edited = held.raw.replace("/original", "/rewritten").replace("Accept: */*", "Accept: edited");
    assert!(ic.forward(held.id, Some(Bytes::from(edited))));

    // The origin saw the edit...
    let body = client.await.unwrap();
    assert!(body.contains("ORIGIN GET /rewritten"), "origin echoed {body:?}");

    // ...and so does history, both in the indexed path and in the stored bytes.
    let exchanges = store.exchanges(0, 10);
    assert_eq!(exchanges.len(), 1, "one forwarded request, one exchange");
    assert_eq!(exchanges[0].path, "/rewritten", "the index must not keep the pre-edit path");
    let stored = store.get(exchanges[0].request).unwrap();
    let text = String::from_utf8_lossy(&stored.raw);
    assert!(text.contains("GET /rewritten HTTP/1.1"), "stored request was {text:?}");
    assert!(text.contains("Accept: edited"), "stored request was {text:?}");
    assert!(!text.contains("/original"), "the original bytes must not survive: {text:?}");
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
    assert!(body.contains("testing the drop path"), "the reason must reach the client: {body:?}");
    assert_eq!(origin.hits.load(Ordering::SeqCst), 0, "a dropped request must not be sent");

    // The attempt is still history: an operator needs to see what they refused.
    let exchanges = store.exchanges(0, 10);
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].status, Some(403));
    assert!(
        exchanges[0].notes.as_deref().unwrap_or_default().contains("dropped by operator"),
        "notes were {:?}",
        exchanges[0].notes
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
    assert_eq!(ic.pending(), 0, "out-of-scope traffic must never enter the queue");
    assert_eq!(
        store.exchanges(0, 10).len(),
        0,
        "out-of-scope traffic is forwarded but not retained"
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
    let resp = store.get(ex.response.expect("a synthetic response is recorded")).unwrap();
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
    assert_eq!(rows[1].status, Some(502), "the unreachable host is a distinct row");
    assert!(rows[1].notes.clone().unwrap_or_default().contains("connect failed"));
}
