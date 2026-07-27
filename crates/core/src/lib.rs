//! burpsy-core — HTTP message model and append-only traffic store.
//!
//! # Why this shape
//!
//! The teardown of Burp's scanner (see `SCAN_ENGINE.md` in the analysis repo) found the memory
//! model to be the root cost, not the JVM:
//!
//! * `scanner.issues_reported.store_issues_within_queue_items: true` — findings are retained *on*
//!   audit items, so the work queue holds payloads.
//! * audit items live in an *observable* collection, so listeners keep completed work alive.
//! * insertion points are materialised as objects and threaded through every dispatch call.
//! * the stored/second-order check path threads two full requests.
//!
//! Consequence: `requests × insertion points × checks` is unbounded, and Burp bounds it by
//! **discarding work** (`LIMIT_EXCEEDED`).
//!
//! This crate inverts that. Raw bytes are written **once** into an append-only log. Everything
//! downstream — history entries, insertion points, attack results — holds a [`MsgId`] plus
//! `(offset, len)` spans. Nothing copies a body. That turns the cap from "drop work" into
//! "apply backpressure", because the resident set no longer scales with work in flight.

pub mod edit;
pub mod findings;
pub mod scope;
pub mod sitemap;
pub use findings::{Confidence, Finding, FindingStore, Inserted, NewFinding, Occurrence, Severity};
pub use scope::{RuleKind, Scope, ScopeRule};

use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Handle to a stored message. Cheap to copy; carries no payload.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct MsgId(pub u64);

/// A span within a message: the only thing we ever hold instead of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub offset: usize,
    pub len: usize,
}

impl Span {
    pub fn new(offset: usize, len: usize) -> Self {
        Self { offset, len }
    }
    pub fn end(&self) -> usize {
        self.offset + self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Which half of an exchange a stored blob is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Request,
    Response,
}

/// Parsed structure of an HTTP message, expressed purely as spans into the stored bytes.
///
/// Deliberately holds no `String`/`Vec<u8>`: parsing yields offsets, so a parsed message costs
/// a fixed ~100 bytes regardless of a multi-megabyte body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageShape {
    pub direction: Direction,
    /// Request: method. Response: HTTP version.
    pub first_token: Span,
    /// Request: target (path+query). Response: status code.
    pub second_token: Span,
    /// Request: HTTP version. Response: reason phrase.
    pub third_token: Span,
    pub headers: Vec<HeaderSpan>,
    pub body: Span,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HeaderSpan {
    pub name: Span,
    pub value: Span,
}

/// A stored HTTP message: raw bytes plus its span map.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: MsgId,
    pub raw: Bytes,
    pub shape: MessageShape,
}

impl StoredMessage {
    /// Borrow a span as bytes. Zero-copy: `Bytes::slice` bumps a refcount.
    pub fn slice(&self, s: Span) -> Bytes {
        if s.end() > self.raw.len() {
            return Bytes::new();
        }
        self.raw.slice(s.offset..s.end())
    }

    /// Lossy UTF-8 view of a span, for display only.
    pub fn text(&self, s: Span) -> String {
        String::from_utf8_lossy(&self.slice(s)).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<Bytes> {
        let want = name.as_bytes();
        self.shape.headers.iter().find_map(|h| {
            let n = self.slice(h.name);
            if n.len() == want.len() && n.eq_ignore_ascii_case(want) {
                Some(self.slice(h.value))
            } else {
                None
            }
        })
    }

    pub fn body(&self) -> Bytes {
        self.slice(self.shape.body)
    }
}

/// Errors from parsing a raw message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    NoHeaderTerminator,
    EmptyStartLine,
    MalformedStartLine,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ParseError::NoHeaderTerminator => "no CRLFCRLF/LFLF header terminator",
            ParseError::EmptyStartLine => "empty start line",
            ParseError::MalformedStartLine => "start line does not have 3 tokens",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ParseError {}

/// Parse a raw HTTP message into spans. Never allocates for the body.
///
/// Tolerant by design: RE and pentest traffic is frequently malformed, and a strict parser would
/// reject exactly the requests you most want to inspect. Accepts both CRLF and bare LF.
pub fn parse(raw: &[u8], direction: Direction) -> Result<MessageShape, ParseError> {
    let (head_end, body_start) = find_header_end(raw).ok_or(ParseError::NoHeaderTerminator)?;

    let line_end = find_line_end(raw, 0).unwrap_or(head_end);
    if line_end == 0 {
        return Err(ParseError::EmptyStartLine);
    }
    let toks = split3(raw, 0, line_end);
    let (first_token, second_token, third_token) = match toks {
        Some(t) => t,
        None => return Err(ParseError::MalformedStartLine),
    };

    let mut headers = Vec::new();
    let mut pos = next_line_start(raw, line_end);
    while pos < head_end {
        let eol = find_line_end(raw, pos).unwrap_or(head_end);
        if eol <= pos {
            break;
        }
        if let Some(colon) = raw[pos..eol].iter().position(|&b| b == b':') {
            let name = Span::new(pos, colon);
            let mut vs = pos + colon + 1;
            while vs < eol && (raw[vs] == b' ' || raw[vs] == b'\t') {
                vs += 1;
            }
            headers.push(HeaderSpan {
                name,
                value: Span::new(vs, eol.saturating_sub(vs)),
            });
        }
        pos = next_line_start(raw, eol);
    }

    Ok(MessageShape {
        direction,
        first_token,
        second_token,
        third_token,
        headers,
        body: Span::new(body_start, raw.len().saturating_sub(body_start)),
    })
}

/// Returns `(index of end-of-headers, index where body starts)`.
fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(i) = find_sub(raw, b"\r\n\r\n") {
        return Some((i, i + 4));
    }
    if let Some(i) = find_sub(raw, b"\n\n") {
        return Some((i, i + 2));
    }
    // Headers with no terminator: treat the whole buffer as head, empty body.
    Some((raw.len(), raw.len()))
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn find_line_end(raw: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i < raw.len() {
        if raw[i] == b'\r' && i + 1 < raw.len() && raw[i + 1] == b'\n' {
            return Some(i);
        }
        if raw[i] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn next_line_start(raw: &[u8], eol: usize) -> usize {
    if eol < raw.len() && raw[eol] == b'\r' && eol + 1 < raw.len() && raw[eol + 1] == b'\n' {
        eol + 2
    } else if eol < raw.len() && raw[eol] == b'\n' {
        eol + 1
    } else {
        eol
    }
}

/// Split `raw[start..end]` on ASCII space into exactly three spans.
fn split3(raw: &[u8], start: usize, end: usize) -> Option<(Span, Span, Span)> {
    let seg = &raw[start..end];
    let s1 = seg.iter().position(|&b| b == b' ')?;
    let rest = &seg[s1 + 1..];
    // A response reason phrase may be absent ("HTTP/1.1 200"); tolerate a missing third token.
    match rest.iter().position(|&b| b == b' ') {
        Some(s2) => Some((
            Span::new(start, s1),
            Span::new(start + s1 + 1, s2),
            Span::new(start + s1 + 1 + s2 + 1, rest.len().saturating_sub(s2 + 1)),
        )),
        None => Some((
            Span::new(start, s1),
            Span::new(start + s1 + 1, rest.len()),
            Span::new(end, 0),
        )),
    }
}

/// A reference from an exchange to a record that belongs to it.
///
/// HTTP/1 gives an exchange exactly one request and at most one response, which is why
/// [`Exchange`] names those two directly. Every protocol after that breaks the assumption: an
/// HTTP/2 exchange is a stream of frames, and a WebSocket connection carries frames indefinitely
/// in both directions. Rather than widen `Exchange` once per protocol, a record carries a list of
/// children and the variant says what kind each one is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildRef {
    /// A WebSocket frame carried by this connection.
    WsFrame(MsgId),
    /// An HTTP/2 frame belonging to this stream.
    H2Frame(MsgId),
}

impl ChildRef {
    /// The stored message this reference points at, whatever its kind.
    pub fn msg(&self) -> MsgId {
        match self {
            ChildRef::WsFrame(m) | ChildRef::H2Frame(m) => *m,
        }
    }
}

/// One proxied exchange. Holds ids, never payloads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Exchange {
    pub id: u64,
    pub request: MsgId,
    pub response: Option<MsgId>,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    /// Response body length in bytes, recorded so the UI never needs to load the body.
    pub response_len: usize,
    pub started_ms: u64,
    pub duration_ms: u64,
    pub notes: Option<String>,
    /// Records belonging to this exchange beyond its request/response pair.
    ///
    /// Empty for every HTTP/1 exchange, and `#[serde(default)]` so a capture serialised before
    /// this field existed still deserialises.
    #[serde(default)]
    pub related: Vec<ChildRef>,
}

/// Append-only message log plus an exchange index.
///
/// Bytes for a message are written once and never moved. `Bytes` gives refcounted slices, so
/// handing a request to the repeater, an intruder attack and the web UI simultaneously costs
/// three pointers, not three copies.
/// # The one invariant
///
/// **Position is the id.** `messages[i].id == MsgId(i)` and `exchanges[i].id == i`, always. Every
/// lookup below is a bounds-checked index rather than a scan, and that is only sound because ids
/// are handed out by the same lock acquisition that appends the record.
///
/// This used to be false in a way nothing caught. `put` took its id from an
/// `AtomicU64::fetch_add`, then parsed (unlocked), then took the write lock to push — so two
/// threads could reserve ids 7 and 8 and push in the order 8, 7, leaving `messages[7].id ==
/// MsgId(8)`. Lookups scanned for `.id`, so they stayed correct and the defect was invisible; it
/// would have become a silent mis-resolution the moment any index trusted position. Parsing still
/// happens outside the lock — it needs nothing from the store and is the expensive part — but the
/// id is now assigned under the lock that appends, so the two cannot disagree.
#[derive(Debug, Default)]
pub struct TrafficStore {
    inner: RwLock<StoreInner>,
}

#[derive(Debug, Default)]
struct StoreInner {
    /// Position is the id: `messages[i].id == MsgId(i)`.
    messages: Vec<StoredMessage>,
    /// Position is the id: `exchanges[i].id == i`.
    exchanges: Vec<Exchange>,
    /// Running total of stored bytes, so `counts()` does not walk the log.
    bytes: usize,
}

impl TrafficStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Store raw bytes, parse to spans, return the handle.
    pub fn put(&self, raw: Bytes, direction: Direction) -> MsgId {
        // Parsed outside the lock: it needs nothing from the store, and holding a write lock
        // across it would serialise every concurrent capture behind one parse.
        let shape = parse(&raw, direction).unwrap_or(MessageShape {
            direction,
            first_token: Span::new(0, 0),
            second_token: Span::new(0, 0),
            third_token: Span::new(0, 0),
            headers: Vec::new(),
            body: Span::new(0, raw.len()),
        });
        let len = raw.len();
        let mut g = self.inner.write();
        // Assigned under the lock that appends — see the type's invariant note.
        let id = MsgId(g.messages.len() as u64);
        g.messages.push(StoredMessage { id, raw, shape });
        g.bytes += len;
        id
    }

    /// Resolve a message id to its bytes. O(1): the id *is* the position.
    pub fn get(&self, id: MsgId) -> Option<StoredMessage> {
        let g = self.inner.read();
        let m = g.messages.get(id.0 as usize)?;
        debug_assert_eq!(m.id, id, "message index desynchronised from id");
        Some(m.clone())
    }

    pub fn add_exchange(&self, mut ex: Exchange) -> u64 {
        let mut g = self.inner.write();
        let id = g.exchanges.len() as u64;
        ex.id = id;
        g.exchanges.push(ex);
        id
    }

    pub fn set_response(
        &self,
        exchange_id: u64,
        resp: MsgId,
        status: u16,
        len: usize,
        dur_ms: u64,
    ) {
        let mut g = self.inner.write();
        if let Some(e) = g.exchanges.get_mut(exchange_id as usize) {
            e.response = Some(resp);
            e.status = Some(status);
            e.response_len = len;
            e.duration_ms = dur_ms;
        }
    }

    /// Newest-first page of exchanges. Returns clones of the *index*, which holds no bodies.
    pub fn exchanges(&self, offset: usize, limit: usize) -> Vec<Exchange> {
        let g = self.inner.read();
        g.exchanges
            .iter()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Resolve an exchange id. O(1): the id *is* the position.
    pub fn exchange(&self, id: u64) -> Option<Exchange> {
        let g = self.inner.read();
        let e = g.exchanges.get(id as usize)?;
        debug_assert_eq!(e.id, id, "exchange index desynchronised from id");
        Some(e.clone())
    }

    /// Attach a child record to an exchange. `false` if the exchange id is unknown.
    pub fn add_related(&self, exchange_id: u64, child: ChildRef) -> bool {
        let mut g = self.inner.write();
        match g.exchanges.get_mut(exchange_id as usize) {
            Some(e) => {
                e.related.push(child);
                true
            }
            None => false,
        }
    }

    /// Children of an exchange, in the order they were attached.
    pub fn related(&self, exchange_id: u64) -> Vec<ChildRef> {
        self.inner
            .read()
            .exchanges
            .get(exchange_id as usize)
            .map(|e| e.related.clone())
            .unwrap_or_default()
    }

    /// `(exchanges, messages, stored bytes)`. O(1) — `bytes` is maintained on write.
    pub fn counts(&self) -> (usize, usize, usize) {
        let g = self.inner.read();
        (g.exchanges.len(), g.messages.len(), g.bytes)
    }

    /// Check the position-is-the-id invariant every O(1) lookup above depends on, plus the
    /// running byte total.
    ///
    /// Exists so the invariant is *checkable* rather than merely asserted in a doc comment: a
    /// caller that has just migrated or replayed a capture can prove the index is coherent instead
    /// of inferring it from the absence of a crash. Returns the first disagreement it finds, naming
    /// the id — a verifier that only said "mismatch" would leave you no better off than a panic.
    pub fn verify_index(&self) -> Result<(), String> {
        let g = self.inner.read();
        for (i, m) in g.messages.iter().enumerate() {
            if m.id.0 != i as u64 {
                return Err(format!(
                    "message at position {i} carries id {} — position is not the id",
                    m.id.0
                ));
            }
        }
        for (i, e) in g.exchanges.iter().enumerate() {
            if e.id != i as u64 {
                return Err(format!(
                    "exchange at position {i} carries id {} — position is not the id",
                    e.id
                ));
            }
            for child in &e.related {
                let cid = child.msg();
                if cid.0 as usize >= g.messages.len() {
                    return Err(format!(
                        "exchange {i} references child message {} which does not exist",
                        cid.0
                    ));
                }
            }
            if let Some(r) = e.response
                && r.0 as usize >= g.messages.len()
            {
                return Err(format!(
                    "exchange {i} references response message {} which does not exist",
                    r.0
                ));
            }
        }
        let summed: usize = g.messages.iter().map(|m| m.raw.len()).sum();
        if summed != g.bytes {
            return Err(format!(
                "byte total drifted: counted {summed}, tracked {}",
                g.bytes
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_into_spans() {
        let raw = b"GET /a?b=1 HTTP/1.1\r\nHost: x.test\r\nX-A: 1\r\n\r\nbody!".to_vec();
        let m = parse(&raw, Direction::Request).unwrap();
        let sm = StoredMessage {
            id: MsgId(0),
            raw: Bytes::from(raw),
            shape: m,
        };
        assert_eq!(sm.text(sm.shape.first_token), "GET");
        assert_eq!(sm.text(sm.shape.second_token), "/a?b=1");
        assert_eq!(sm.text(sm.shape.third_token), "HTTP/1.1");
        assert_eq!(sm.shape.headers.len(), 2);
        assert_eq!(&sm.header("host").unwrap()[..], b"x.test");
        assert_eq!(&sm.body()[..], b"body!");
    }

    #[test]
    fn tolerates_lf_only_and_missing_reason() {
        let raw = b"HTTP/1.1 204\nX: y\n\n".to_vec();
        let m = parse(&raw, Direction::Response).unwrap();
        let sm = StoredMessage {
            id: MsgId(1),
            raw: Bytes::from(raw),
            shape: m,
        };
        assert_eq!(sm.text(sm.shape.first_token), "HTTP/1.1");
        assert_eq!(sm.text(sm.shape.second_token), "204");
        assert_eq!(sm.shape.headers.len(), 1);
    }

    #[test]
    fn slicing_is_zero_copy() {
        let raw = Bytes::from(vec![b'x'; 4096]);
        let store = TrafficStore::new();
        let id = store.put(raw.clone(), Direction::Request);
        let a = store.get(id).unwrap().raw;
        // Same allocation, not a copy.
        assert_eq!(a.as_ptr(), raw.as_ptr());
    }

    /// STORE-03. The id a caller was handed must resolve to *that caller's* message, no matter how
    /// many threads were appending at the time.
    ///
    /// Because `get` is now a positional index rather than a scan for `.id`, this test only passes
    /// while position-is-the-id holds. Under the previous implementation — id from an atomic, then
    /// an unlocked parse, then the push — the two could interleave out of order, and a positional
    /// `get` would hand back another thread's bytes. The per-message payload is unique so that
    /// failure reads as "resolved to another thread's message", not merely as a count mismatch.
    #[test]
    fn ids_and_insertion_order_agree_under_concurrent_puts() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 400;

        let store = TrafficStore::new();
        let start = Arc::new(std::sync::Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);

        for t in 0..THREADS {
            let store = Arc::clone(&store);
            let start = Arc::clone(&start);
            handles.push(std::thread::spawn(move || {
                // Release all threads together, so the appends genuinely contend.
                start.wait();
                let mut issued = Vec::with_capacity(PER_THREAD);
                for i in 0..PER_THREAD {
                    let raw =
                        Bytes::from(format!("GET /t{t}/i{i} HTTP/1.1\r\nHost: x.test\r\n\r\n"));
                    let id = store.put(raw.clone(), Direction::Request);
                    issued.push((id, raw));
                }
                issued
            }));
        }

        let issued: Vec<(MsgId, Bytes)> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker thread panicked"))
            .collect();

        assert_eq!(issued.len(), THREADS * PER_THREAD);

        for (id, expected) in &issued {
            let got = store.get(*id).expect("every issued id must resolve");
            assert_eq!(got.id, *id);
            assert_eq!(
                &got.raw[..],
                &expected[..],
                "id {id:?} resolved to another thread's message"
            );
        }

        // Ids are dense and unique across the whole run: exactly 0..n, each once.
        let mut ids: Vec<u64> = issued.iter().map(|(i, _)| i.0).collect();
        ids.sort_unstable();
        assert_eq!(ids, (0..(THREADS * PER_THREAD) as u64).collect::<Vec<_>>());

        store.verify_index().expect("index must be coherent");
    }

    /// STORE-02. Lookups are positional, so an id past the end is `None` rather than a panic or a
    /// scan that quietly finds nothing.
    #[test]
    fn unknown_ids_resolve_to_none_not_a_panic() {
        let store = TrafficStore::new();
        let id = store.put(
            Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"),
            Direction::Request,
        );
        assert!(store.get(id).is_some());
        assert!(store.get(MsgId(id.0 + 1)).is_none());
        assert!(store.get(MsgId(u64::MAX)).is_none());
        assert!(store.exchange(0).is_none());
        assert!(store.exchange(u64::MAX).is_none());
    }

    /// STORE-04. An exchange owns many children, starts with none, and rejects an unknown id
    /// rather than silently dropping the reference.
    #[test]
    fn an_exchange_carries_many_related_records() {
        let store = TrafficStore::new();
        let req = store.put(
            Bytes::from_static(b"GET /ws HTTP/1.1\r\n\r\n"),
            Direction::Request,
        );
        let ex = store.add_exchange(Exchange {
            related: Vec::new(),
            request: req,
            host: "x.test".into(),
            port: 443,
            tls: true,
            method: "GET".into(),
            path: "/ws".into(),
            ..Default::default()
        });

        assert!(store.related(ex).is_empty(), "children start empty");

        let f1 = store.put(Bytes::from_static(b"frame-one"), Direction::Request);
        let f2 = store.put(Bytes::from_static(b"frame-two"), Direction::Response);
        let f3 = store.put(Bytes::from_static(b"h2-frame"), Direction::Request);
        assert!(store.add_related(ex, ChildRef::WsFrame(f1)));
        assert!(store.add_related(ex, ChildRef::WsFrame(f2)));
        assert!(store.add_related(ex, ChildRef::H2Frame(f3)));

        let kids = store.related(ex);
        assert_eq!(kids.len(), 3, "one exchange owns many children");
        assert_eq!(kids[0], ChildRef::WsFrame(f1));
        assert_eq!(kids[2].msg(), f3);
        assert_eq!(store.exchange(ex).unwrap().related, kids);

        // An unknown exchange reports the failure rather than swallowing the reference.
        assert!(!store.add_related(ex + 99, ChildRef::WsFrame(f1)));

        store.verify_index().expect("index must be coherent");
    }

    /// STORE-02. `counts` reports the byte total from a running tally, so it does not walk the log.
    /// `verify_index` is what proves the tally has not drifted from reality.
    #[test]
    fn counts_tracks_bytes_without_walking_the_log() {
        let store = TrafficStore::new();
        let mut expected = 0usize;
        for i in 0..50 {
            let raw = Bytes::from(format!(
                "GET /{i} HTTP/1.1\r\nHost: x\r\n\r\n{}",
                "b".repeat(i)
            ));
            expected += raw.len();
            store.put(raw, Direction::Request);
        }
        let (exchanges, messages, bytes) = store.counts();
        assert_eq!(exchanges, 0);
        assert_eq!(messages, 50);
        assert_eq!(bytes, expected);
        store
            .verify_index()
            .expect("tracked total must match reality");
    }

    /// STORE-04 forward-compatibility: a capture serialised before `related` existed still loads.
    #[test]
    fn an_exchange_without_a_related_field_still_deserialises() {
        let legacy = r#"{"id":3,"request":7,"response":null,"host":"x.test","port":80,
            "tls":false,"method":"GET","path":"/","status":null,"response_len":0,
            "started_ms":0,"duration_ms":0,"notes":null}"#;
        let ex: Exchange = serde_json::from_str(legacy).expect("legacy exchange must deserialise");
        assert_eq!(ex.id, 3);
        assert!(ex.related.is_empty());
    }
}
