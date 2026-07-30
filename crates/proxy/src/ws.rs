//! WebSocket relay: once a handshake has been answered `101`, this pumps frames both ways.
//!
//! # Relay first, capture second — always in that order
//!
//! Every byte read from one side is written to the other **before** the capture looks at it, and the
//! bytes written are the bytes read. That ordering is the whole safety argument for this phase: no
//! parse result, no cap, and no bug in [`burpsy_core::ws`] can change what the two peers see. A
//! WebSocket carries the live application — a chat, a trading feed, a terminal — and a proxy that
//! corrupts it is worse than a proxy that cannot see it.
//!
//! It also means the two directions are described by *two* things that must not be confused: the
//! relayed byte counts, which are exact, and the captured message index, which is bounded by
//! [`burpsy_core::ws::Reassembler::max_message_bytes`] and says so per row.
//!
//! # One task, two directions
//!
//! A `select!` over the two reads rather than two spawned tasks, for the reason
//! [`crate::intercept`] gives about held requests: a connection's cost stays on the connection's own
//! task, and nothing here is shared with any other connection. `AsyncReadExt::read` is
//! cancellation-safe, so losing the losing branch of the `select!` loses no bytes.
//!
//! # Desynchronisation stops the capture, not the connection
//!
//! If the frame stream can no longer be located — the one [`burpsy_core::ws::WsError`] case — every
//! later "message" this side decoded would be fiction. So capture for that direction stops, the
//! reason is reported to the caller so it can be recorded, and relaying continues untouched. The
//! alternative, tearing the connection down because *our* view of it broke, would make an
//! inspection tool the cause of the outage.
//!
//! # Where scope is decided, stated explicitly (WS-03)
//!
//! **Per message, not once at the handshake.** A WebSocket can stay open for the whole engagement,
//! so authorising it at `Upgrade` and never again means an operator who narrows scope at 14:00 keeps
//! retaining traffic they excluded until the socket happens to close. The check is therefore in
//! [`WsCapture::retains`], evaluated for every message, against the handshake's host, port, path and
//! scheme — a connection has exactly one of each, so the *subject* of the decision is fixed even
//! though the *policy* is not.
//!
//! `Scope` is runtime-editable (`SharedScope` is an `Arc<RwLock<Scope>>` handle, shared rather than
//! cloned-and-frozen), so this is not hypothetical: narrowing or widening scope while a connection
//! is open takes effect on the very next message, without the socket being torn down and reopened.
//! `scope_narrowed_on_an_open_connection_stops_retention_on_the_very_next_message` and
//! `scope_widened_on_an_open_connection_starts_retention_on_the_very_next_message` below mutate the
//! same `SharedScope` handle an open connection is already holding, rather than constructing a new
//! one — that is what makes the check-per-message placement observable rather than merely correct
//! in principle.
//!
//! What it governs is retention, never egress — the identical rule `ProxyConfig::scope` states for
//! HTTP. An out-of-scope message is relayed and not stored, and gets no marker row, for the same
//! reason ordinary out-of-scope HTTP traffic gets none: a row per unrelated message would make
//! history noisier than the traffic anyone asked to see. It is counted in
//! [`WsStats::skipped_out_of_scope`] and named in the connection's closing log line, so "excluded" is
//! never indistinguishable from "never happened".

use burpsy_core::ws::{Reassembler, WsError, WsMessage};
use burpsy_core::{Direction, SharedScope, TrafficStore};
use bytes::Bytes;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read buffer per direction. Matches the response-streaming buffer in `lib.rs`.
const RELAY_CHUNK: usize = 16 * 1024;

/// Where a relayed connection's messages are recorded.
///
/// Absent at the call site means the connection is relayed and not recorded — the ordinary
/// out-of-scope case, handled exactly as it is for HTTP.
#[derive(Clone)]
pub struct WsCapture {
    pub store: Arc<TrafficStore>,
    /// The handshake exchange whose `101` opened this connection.
    pub exchange: u64,
    /// Payload bytes kept per message. Beyond it, the shortfall is counted on the row.
    pub max_message_bytes: usize,
    /// Re-tested for every message rather than once at the handshake — see the module docs on
    /// WS-03. Shared with the proxy config, so a scope edit takes effect on open sockets.
    pub scope: SharedScope,
    /// The handshake's routing facts: the subject of every scope decision on this connection.
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub path: String,
}

impl WsCapture {
    pub fn new(
        store: Arc<TrafficStore>,
        exchange: u64,
        scope: SharedScope,
        host: impl Into<String>,
        port: u16,
        tls: bool,
        path: impl Into<String>,
    ) -> Self {
        Self {
            store,
            exchange,
            max_message_bytes: burpsy_core::ws::DEFAULT_MAX_MESSAGE_BYTES,
            scope,
            host: host.into(),
            port,
            tls,
            path: path.into(),
        }
    }

    /// Whether a message on this connection is retained *right now*.
    ///
    /// Read per message. That is the point: the answer is allowed to change while the socket is open,
    /// and a cached answer is exactly the "authorised once at Upgrade" defect WS-03 names.
    pub fn retains(&self) -> bool {
        self.scope.contains(&self.host, self.port, &self.path, self.tls)
    }
}

/// What a relayed connection turned out to be, once it closed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WsStats {
    /// Bytes relayed client→server, exactly as they went out.
    pub up: u64,
    /// Bytes relayed server→client, exactly as they came in.
    pub down: u64,
    /// Messages written to the index. Zero when the connection was not recorded.
    pub messages: u64,
    /// Messages relayed but not retained, because scope excluded this connection at the moment they
    /// arrived. Counted rather than silently absent — see the module docs on WS-03.
    pub skipped_out_of_scope: u64,
    /// Why capture stopped early, if it did. `None` means the index covers the whole connection.
    pub capture_stopped: Option<String>,
}

/// Relay a WebSocket connection until either side closes.
///
/// `upstream_prefix` is whatever arrived on the upstream leg *after* the `101` head — a server may
/// put its first frames in the same segment as the handshake response, and dropping them would lose
/// the opening of every conversation.
pub async fn relay<C, U>(
    client: C,
    upstream: U,
    upstream_prefix: &[u8],
    capture: Option<WsCapture>,
) -> WsStats
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    let cap = capture.as_ref().map(|c| c.max_message_bytes);
    let mut to_server = Side::new(Direction::Request, cap);
    let mut to_client = Side::new(Direction::Response, cap);
    let mut stats = WsStats::default();

    if !upstream_prefix.is_empty() {
        if client_write.write_all(upstream_prefix).await.is_err() {
            return stats;
        }
        let _ = client_write.flush().await;
        stats.down += upstream_prefix.len() as u64;
        to_client.observe(upstream_prefix, capture.as_ref(), &mut stats);
    }

    let mut from_client = vec![0u8; RELAY_CHUNK];
    let mut from_upstream = vec![0u8; RELAY_CHUNK];
    loop {
        tokio::select! {
            r = client_read.read(&mut from_client) => {
                let Ok(n) = r else { break };
                if n == 0 {
                    break;
                }
                // Unmodified, and before anything else looks at it.
                if upstream_write.write_all(&from_client[..n]).await.is_err() {
                    break;
                }
                let _ = upstream_write.flush().await;
                stats.up += n as u64;
                to_server.observe(&from_client[..n], capture.as_ref(), &mut stats);
            }
            r = upstream_read.read(&mut from_upstream) => {
                let Ok(n) = r else { break };
                if n == 0 {
                    break;
                }
                if client_write.write_all(&from_upstream[..n]).await.is_err() {
                    break;
                }
                let _ = client_write.flush().await;
                stats.down += n as u64;
                to_client.observe(&from_upstream[..n], capture.as_ref(), &mut stats);
            }
        }
    }

    // Report whichever side gave up first. Both sides carry the same kind of fault, and one reason
    // is what the operator needs; two would just be the same sentence twice.
    stats.capture_stopped = to_server.fault.take().or_else(|| to_client.fault.take());
    stats
}

/// One direction's decoder. Holds no payload beyond the message being assembled.
struct Side {
    direction: Direction,
    frames: Option<Reassembler>,
    fault: Option<String>,
}

impl Side {
    fn new(direction: Direction, max_message_bytes: Option<usize>) -> Self {
        Self {
            direction,
            // `None` when nothing is being recorded: not merely unused, but never constructed, so a
            // relayed-but-not-captured connection pays no reassembly cost at all.
            frames: max_message_bytes.map(Reassembler::new),
            fault: None,
        }
    }

    fn observe(&mut self, bytes: &[u8], capture: Option<&WsCapture>, stats: &mut WsStats) {
        let (Some(frames), Some(cap)) = (self.frames.as_mut(), capture) else {
            return;
        };
        // The fault is held rather than returned on: a read can carry several frames, and messages
        // this one decoded *before* the bad header are complete and real. Discarding them would lose
        // evidence the parser already has, which is the opposite of what stopping the capture is for.
        let fault = frames.feed(bytes).err();
        while let Some(ev) = frames.pop() {
            // Asked here, per message, so narrowing scope on an open socket takes effect at once.
            if !cap.retains() {
                stats.skipped_out_of_scope += 1;
                continue;
            }
            let len = ev.payload.len();
            let payload = cap.store.put(ev.payload, self.direction);
            cap.store.add_ws_message(WsMessage {
                id: 0,
                exchange: cap.exchange,
                payload,
                direction: self.direction,
                opcode: ev.opcode,
                len,
                dropped: ev.dropped,
                fragments: ev.fragments,
                at_ms: now_ms(),
                note: ev.note,
            });
            stats.messages += 1;
        }
        if let Some(e) = fault {
            self.stop(e);
        }
    }

    /// Stop decoding this direction. Relaying is unaffected — see the module docs.
    fn stop(&mut self, e: WsError) {
        let which = match self.direction {
            Direction::Request => "client\u{2192}server",
            Direction::Response => "server\u{2192}client",
        };
        tracing::warn!("websocket capture stopped on the {which} stream: {e}");
        self.frames = None;
        self.fault = Some(format!("{which}: {e}"));
    }
}

/// A close frame's status code, if it carries one.
///
/// Not used by the relay — a close frame is relayed like any other — but the payload is two big-endian
/// bytes followed by an optional UTF-8 reason, and a UI that rendered those two bytes as text would
/// show mojibake instead of `1000`. Exposed here so exactly one implementation of that decode exists.
pub fn close_status(payload: &[u8]) -> Option<(u16, String)> {
    if payload.len() < 2 {
        return None;
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    Some((code, String::from_utf8_lossy(&payload[2..]).into_owned()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A synthetic payload standing in for a connection whose capture stopped, so the reason is in the
/// store rather than only in the log.
pub fn capture_stopped_marker(reason: &str) -> Bytes {
    Bytes::from(format!(
        "[burpsy: WebSocket capture stopped — {reason}. Frames continued to be relayed unmodified, \
         so the connection was not affected; the message index below this point is incomplete.]"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::ws::{WsOpcode, unmask};
    use tokio::io::duplex;

    fn frame(fin: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        let n = payload.len();
        if n < 126 {
            out.push(mask_bit | n as u8);
        } else {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        if let Some(m) = mask {
            out.extend_from_slice(&m);
            let at = out.len();
            out.extend_from_slice(payload);
            unmask(&mut out[at..], m, 0);
        } else {
            out.extend_from_slice(payload);
        }
        out
    }

    /// A store with one exchange, so a `WsMessage` has a handshake to belong to.
    fn store_with_exchange() -> (Arc<TrafficStore>, u64) {
        let store = TrafficStore::new();
        let req = store.put(
            Bytes::from_static(b"GET /ws HTTP/1.1\r\nHost: t.test\r\n\r\n"),
            Direction::Request,
        );
        let ex = store.add_exchange(burpsy_core::Exchange {
            request: req,
            host: "t.test".into(),
            port: 80,
            method: "GET".into(),
            path: "/ws".into(),
            ..Default::default()
        });
        (store, ex)
    }

    /// A capture that retains everything, so a test that is not about scope is not about scope.
    fn capture(store: Arc<TrafficStore>, exchange: u64) -> WsCapture {
        WsCapture::new(
            store,
            exchange,
            burpsy_core::SharedScope::allow_everything(),
            "t.test",
            80,
            false,
            "/ws",
        )
    }

    /// WS-01: both directions are captured, and the masked client frame reads as plaintext.
    #[tokio::test]
    async fn a_relayed_connection_records_both_directions() {
        let (store, ex) = store_with_exchange();
        let (client, mut client_peer) = duplex(4096);
        let (upstream, mut upstream_peer) = duplex(4096);

        let relay = tokio::spawn(relay(
            client,
            upstream,
            &[],
            Some(capture(store.clone(), ex)),
        ));

        client_peer
            .write_all(&frame(true, 0x1, Some([1, 2, 3, 4]), b"hello from the browser"))
            .await
            .unwrap();
        upstream_peer
            .write_all(&frame(true, 0x1, None, b"hello from the server"))
            .await
            .unwrap();

        // The relay is what proves delivery: read the opposite side of each write.
        let mut buf = vec![0u8; 128];
        let n = upstream_peer.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            &frame(true, 0x1, Some([1, 2, 3, 4]), b"hello from the browser")[..],
            "the client's frame must reach the server byte-for-byte, mask included"
        );
        let n = client_peer.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            &frame(true, 0x1, None, b"hello from the server")[..]
        );

        drop(client_peer);
        drop(upstream_peer);
        let stats = relay.await.unwrap();
        assert_eq!(stats.messages, 2, "both messages recorded: {stats:?}");
        assert!(stats.capture_stopped.is_none(), "{stats:?}");

        let rows = store.ws_messages(0, 10);
        assert_eq!(rows.len(), 2);
        let payload = |m: &WsMessage| {
            String::from_utf8_lossy(&store.get(m.payload).unwrap().raw).into_owned()
        };
        let c2s = rows.iter().find(|m| m.direction == Direction::Request).unwrap();
        let s2c = rows.iter().find(|m| m.direction == Direction::Response).unwrap();
        assert_eq!(
            payload(c2s),
            "hello from the browser",
            "history must show the unmasked payload"
        );
        assert_eq!(payload(s2c), "hello from the server");
        assert_eq!(c2s.exchange, ex, "every message names its handshake");
        assert_eq!(c2s.opcode, WsOpcode::Text);
        assert_eq!(store.verify_index(), Ok(()), "the ws index must stay coherent");
    }

    /// WS-01: bytes the server sent alongside its `101` are relayed and captured, not dropped.
    #[tokio::test]
    async fn frames_arriving_with_the_handshake_response_are_not_lost() {
        let (store, ex) = store_with_exchange();
        let (client, mut client_peer) = duplex(4096);
        let (upstream, upstream_peer) = duplex(4096);
        let prefix = frame(true, 0x1, None, b"welcome");

        let relay = tokio::spawn({
            let store = store.clone();
            let prefix = prefix.clone();
            async move {
                relay(
                    client,
                    upstream,
                    &prefix,
                    Some(capture(store, ex)),
                )
                .await
            }
        });

        let mut buf = vec![0u8; 64];
        let n = client_peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &prefix[..], "the prefix reaches the client");

        drop(client_peer);
        drop(upstream_peer);
        let stats = relay.await.unwrap();
        assert_eq!(stats.messages, 1);
        assert_eq!(stats.down, prefix.len() as u64);
    }

    /// WS-01: an unparseable length stops the index and says so, and the relay keeps working.
    #[tokio::test]
    async fn a_broken_frame_stream_stops_capturing_but_keeps_relaying() {
        let (store, ex) = store_with_exchange();
        let (client, mut client_peer) = duplex(4096);
        let (upstream, mut upstream_peer) = duplex(4096);

        let relay = tokio::spawn(relay(
            client,
            upstream,
            &[],
            Some(capture(store.clone(), ex)),
        ));

        // A 64-bit length with the reserved high bit set: nothing after it can be located.
        let mut broken = vec![0x82u8, 0xff];
        broken.extend_from_slice(&(1u64 << 63).to_be_bytes());
        broken.extend_from_slice(&[0u8; 4]);
        client_peer.write_all(&broken).await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = upstream_peer.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            &broken[..],
            "a frame this proxy cannot parse must still be forwarded unmodified"
        );

        // And the connection is still usable afterwards in the other direction.
        upstream_peer
            .write_all(&frame(true, 0x1, None, b"still alive"))
            .await
            .unwrap();
        let n = client_peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &frame(true, 0x1, None, b"still alive")[..]);

        drop(client_peer);
        drop(upstream_peer);
        let stats = relay.await.unwrap();
        assert_eq!(
            stats.messages, 1,
            "the good frame that arrived before the fault must still be indexed: {stats:?}"
        );
        let stopped = stats.capture_stopped.expect("the fault must be reported");
        assert!(
            stopped.contains("client\u{2192}server"),
            "the reason must name the direction that broke: {stopped}"
        );
        assert!(stopped.contains("unknowable"), "{stopped}");
        assert_eq!(
            stats.up, broken.len() as u64,
            "relayed byte counts stay exact even when the index gives up"
        );
    }

    /// WS-01: with no capture, nothing is recorded and the connection still works — the
    /// out-of-scope case.
    #[tokio::test]
    async fn an_uncaptured_connection_is_relayed_and_stored_nowhere() {
        let (store, _ex) = store_with_exchange();
        let before = store.counts().1;
        let (client, mut client_peer) = duplex(4096);
        let (upstream, mut upstream_peer) = duplex(4096);

        let relay = tokio::spawn(relay(client, upstream, &[], None));
        let wire = frame(true, 0x2, None, b"opaque");
        client_peer.write_all(&wire).await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = upstream_peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &wire[..]);

        drop(client_peer);
        drop(upstream_peer);
        let stats = relay.await.unwrap();
        assert_eq!(stats.messages, 0);
        assert_eq!(stats.up, wire.len() as u64, "still counted, just not stored");
        assert_eq!(store.counts().1, before, "nothing was written to the store");
        assert_eq!(store.ws_count(), 0);
    }

    /// WS-03: a connection scope excludes has every message relayed, counted, and stored nowhere.
    ///
    /// The exclusion is asked for **each** message rather than cached per connection. This fixture
    /// builds the excluding `SharedScope` before the connection opens, so it covers the "always was
    /// out of scope" case; see the two tests below for scope changing *while the connection is open*,
    /// which is the case this rule exists for.
    #[tokio::test]
    async fn an_excluded_connection_is_relayed_counted_and_retained_nowhere() {
        let (store, ex) = store_with_exchange();
        let before = store.ws_count();
        let (client, mut client_peer) = duplex(4096);
        let (upstream, mut upstream_peer) = duplex(4096);

        let mut narrowed = burpsy_core::Scope::new();
        narrowed.add(burpsy_core::ScopeRule::include("somewhere.else"));
        let mut excluded = capture(store.clone(), ex);
        excluded.scope = burpsy_core::SharedScope::new(narrowed);
        assert!(
            !excluded.retains(),
            "the fixture must actually exclude this connection, or the test proves nothing"
        );

        let relay_task = tokio::spawn(relay(client, upstream, &[], Some(excluded)));
        let first = frame(true, 0x1, None, b"one");
        let second = frame(true, 0x1, None, b"two");
        client_peer.write_all(&first).await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = upstream_peer.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            &first[..],
            "scope governs retention, never egress — the frame still reaches the origin"
        );
        client_peer.write_all(&second).await.unwrap();
        let n = upstream_peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &second[..]);

        drop(client_peer);
        drop(upstream_peer);
        let stats = relay_task.await.unwrap();
        assert_eq!(stats.messages, 0, "nothing retained while out of scope");
        assert_eq!(
            stats.skipped_out_of_scope, 2,
            "both exclusions counted — one per message, not one per connection"
        );
        assert_eq!(store.ws_count(), before, "the index did not grow");
    }

    /// WS-03: narrowing scope on an *already-open* connection stops retention on the very next
    /// message — no new connection, no reconstructed `WsCapture`, just a write through the same
    /// `SharedScope` handle the running relay task is already holding a clone of.
    #[tokio::test]
    async fn scope_narrowed_on_an_open_connection_stops_retention_on_the_very_next_message() {
        let (store, ex) = store_with_exchange();
        let (client, mut client_peer) = duplex(4096);
        let (upstream, mut upstream_peer) = duplex(4096);

        let mut starting = burpsy_core::Scope::new();
        let rule_id = starting.add_rule(burpsy_core::ScopeRule::include("t.test"));
        let shared = burpsy_core::SharedScope::new(starting);
        let mut cap = capture(store.clone(), ex);
        cap.scope = shared.clone();
        assert!(
            cap.retains(),
            "the fixture must start in scope, or narrowing it proves nothing"
        );

        let relay_task = tokio::spawn(relay(client, upstream, &[], Some(cap)));

        let before = frame(true, 0x1, None, b"while in scope");
        client_peer.write_all(&before).await.unwrap();
        let mut buf = vec![0u8; 128];
        let n = upstream_peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &before[..]);

        // The operator narrows scope through the same handle the open connection is holding —
        // exactly what the running web UI does, not a new `SharedScope` built for the test.
        shared.remove_rule(rule_id);

        let after = frame(true, 0x1, None, b"after narrowing");
        client_peer.write_all(&after).await.unwrap();
        let n = upstream_peer.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            &after[..],
            "narrowed scope still relays — it only governs retention"
        );

        drop(client_peer);
        drop(upstream_peer);
        let stats = relay_task.await.unwrap();
        assert_eq!(
            stats.messages, 1,
            "only the message sent before narrowing was retained: {stats:?}"
        );
        assert_eq!(
            stats.skipped_out_of_scope, 1,
            "the post-narrowing message was counted, not silently dropped"
        );
        assert_eq!(store.ws_count(), 1);
    }

    /// WS-03: the reverse direction — widening scope on an *already-open* connection starts
    /// retention on the very next message, with no reconnect needed.
    #[tokio::test]
    async fn scope_widened_on_an_open_connection_starts_retention_on_the_very_next_message() {
        let (store, ex) = store_with_exchange();
        let (client, mut client_peer) = duplex(4096);
        let (upstream, mut upstream_peer) = duplex(4096);

        let shared = burpsy_core::SharedScope::new(burpsy_core::Scope::new());
        let mut cap = capture(store.clone(), ex);
        cap.scope = shared.clone();
        assert!(
            !cap.retains(),
            "the fixture must start out of scope, or widening it proves nothing"
        );

        let relay_task = tokio::spawn(relay(client, upstream, &[], Some(cap)));

        let before = frame(true, 0x1, None, b"while excluded");
        client_peer.write_all(&before).await.unwrap();
        let mut buf = vec![0u8; 128];
        let n = upstream_peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &before[..], "still relayed while excluded");

        // Widen scope through the same handle — the operator adding an include rule mid-engagement.
        shared.add_rule(burpsy_core::ScopeRule::include("t.test"));

        let after = frame(true, 0x1, None, b"after widening");
        client_peer.write_all(&after).await.unwrap();
        let n = upstream_peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &after[..]);

        drop(client_peer);
        drop(upstream_peer);
        let stats = relay_task.await.unwrap();
        assert_eq!(
            stats.messages, 1,
            "only the message sent after widening was retained: {stats:?}"
        );
        assert_eq!(stats.skipped_out_of_scope, 1, "the pre-widening message was counted");
        assert_eq!(store.ws_count(), 1);
    }

    #[test]
    fn a_close_frames_status_code_is_read_as_a_number_not_as_text() {
        assert_eq!(
            close_status(&[0x03, 0xe8, b'b', b'y', b'e']),
            Some((1000, "bye".to_string()))
        );
        assert_eq!(close_status(&[]), None, "a bare close carries no code");
        assert_eq!(close_status(&[0x03]), None, "a truncated code is not a code");
    }
}
