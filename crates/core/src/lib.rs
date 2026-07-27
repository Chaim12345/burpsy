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
pub use findings::{Confidence, Finding, FindingStore, Inserted, NewFinding, Occurrence, Severity};
pub use scope::{RuleKind, Scope, ScopeRule};

use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Handle to a stored message. Cheap to copy; carries no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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

/// One proxied exchange. Holds ids, never payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Append-only message log plus an exchange index.
///
/// Bytes for a message are written once and never moved. `Bytes` gives refcounted slices, so
/// handing a request to the repeater, an intruder attack and the web UI simultaneously costs
/// three pointers, not three copies.
#[derive(Debug, Default)]
pub struct TrafficStore {
    inner: RwLock<StoreInner>,
    next_msg: AtomicU64,
    next_exchange: AtomicU64,
}

#[derive(Debug, Default)]
struct StoreInner {
    messages: Vec<StoredMessage>,
    exchanges: Vec<Exchange>,
}

impl TrafficStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Store raw bytes, parse to spans, return the handle.
    pub fn put(&self, raw: Bytes, direction: Direction) -> MsgId {
        let id = MsgId(self.next_msg.fetch_add(1, Ordering::Relaxed));
        let shape = parse(&raw, direction).unwrap_or(MessageShape {
            direction,
            first_token: Span::new(0, 0),
            second_token: Span::new(0, 0),
            third_token: Span::new(0, 0),
            headers: Vec::new(),
            body: Span::new(0, raw.len()),
        });
        self.inner
            .write()
            .messages
            .push(StoredMessage { id, raw, shape });
        id
    }

    pub fn get(&self, id: MsgId) -> Option<StoredMessage> {
        let g = self.inner.read();
        g.messages.iter().find(|m| m.id == id).cloned()
    }

    pub fn add_exchange(&self, mut ex: Exchange) -> u64 {
        let id = self.next_exchange.fetch_add(1, Ordering::Relaxed);
        ex.id = id;
        self.inner.write().exchanges.push(ex);
        id
    }

    pub fn set_response(&self, exchange_id: u64, resp: MsgId, status: u16, len: usize, dur_ms: u64) {
        let mut g = self.inner.write();
        if let Some(e) = g.exchanges.iter_mut().find(|e| e.id == exchange_id) {
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

    pub fn exchange(&self, id: u64) -> Option<Exchange> {
        self.inner
            .read()
            .exchanges
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let g = self.inner.read();
        let bytes = g.messages.iter().map(|m| m.raw.len()).sum();
        (g.exchanges.len(), g.messages.len(), bytes)
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
}
