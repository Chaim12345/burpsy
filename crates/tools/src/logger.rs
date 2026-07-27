//! Logger — every request burpsy itself sent, kept apart from proxy history.
//!
//! # Why this is a separate store and not a flag on `Exchange`
//!
//! During an engagement the operator has to answer "did *I* do that?" constantly. A 500 in the
//! history is a bug worth reporting if the browser caused it and a self-inflicted artefact if
//! Intruder caused it; a `DELETE /account/7` is a finding or an accident depending on who sent it.
//! Burp's `ToolType` (`Zgdx.java`: TARGET, PROXY, SCANNER, INTRUDER, REPEATER, SEQUENCER, COMPARER,
//! LOGGER) tags every item with its origin and its Logger tab shows all of them together.
//!
//! This log deliberately goes the other way: [`Tool`] has **no proxy variant**, so browser traffic
//! cannot end up here by construction. Proxy history is `TrafficStore`'s exchange index; this is
//! the record of what the tools did. Two stores, one question each, and no filter to forget to set.
//!
//! # Memory
//!
//! An entry holds `MsgId`s and an exchange id, never bytes — the payloads already live once in the
//! `TrafficStore`. An entry is therefore around a hundred bytes plus its host and path strings, and
//! the log is capped and evicts oldest-first so a million-request Intruder run degrades into a
//! recent-history window instead of an OOM. [`ToolLog::dropped`] reports what was evicted, because
//! a log that silently loses entries is worse than one that admits it.

use burpsy_core::MsgId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

/// Which tool sent the request. No `Proxy`: see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Repeater,
    Intruder,
    /// Active-scan probes.
    Scanner,
    /// Requests issued by a BCheck's `send request`.
    Bcheck,
}

impl Tool {
    pub fn as_str(self) -> &'static str {
        match self {
            Tool::Repeater => "repeater",
            Tool::Intruder => "intruder",
            Tool::Scanner => "scanner",
            Tool::Bcheck => "bcheck",
        }
    }

    pub fn parse(s: &str) -> Option<Tool> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "repeater" => Tool::Repeater,
            "intruder" => Tool::Intruder,
            "scanner" => Tool::Scanner,
            "bcheck" => Tool::Bcheck,
            _ => return None,
        })
    }

    pub const ALL: [Tool; 4] = [Tool::Repeater, Tool::Intruder, Tool::Scanner, Tool::Bcheck];
}

/// What the caller knows when it is about to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    pub tool: Tool,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
    pub request: MsgId,
    /// Epoch milliseconds. Passed in rather than read from the clock so this crate stays free of
    /// ambient state and its tests are deterministic.
    pub started_ms: u64,
    /// The `TrafficStore` exchange, when the caller made one.
    pub exchange: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: u64,
    pub tool: Tool,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
    pub request: MsgId,
    pub response: Option<MsgId>,
    pub status: Option<u16>,
    pub response_len: usize,
    pub started_ms: u64,
    pub duration_ms: u64,
    pub exchange: Option<u64>,
    pub note: Option<String>,
    /// Set when the send failed. A failed attempt is still evidence — a connection reset after a
    /// specific payload is often the finding — so it is logged rather than discarded.
    pub error: Option<String>,
}

/// Default cap. 100k entries is roughly 20 MB of index and more scrollback than anyone reads.
pub const DEFAULT_CAPACITY: usize = 100_000;

#[derive(Debug)]
pub struct ToolLog {
    inner: RwLock<VecDeque<Entry>>,
    next: AtomicU64,
    dropped: AtomicU64,
    capacity: usize,
}

impl Default for ToolLog {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl ToolLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(VecDeque::new()),
            next: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            capacity: capacity.max(1),
        }
    }

    /// Record a request that is about to go out. Returns the id to complete it with.
    pub fn started(&self, s: Started) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut g = self.inner.write();
        while g.len() >= self.capacity {
            g.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        g.push_back(Entry {
            id,
            tool: s.tool,
            host: s.host,
            port: s.port,
            tls: s.tls,
            method: s.method,
            path: s.path,
            request: s.request,
            response: None,
            status: None,
            response_len: 0,
            started_ms: s.started_ms,
            duration_ms: 0,
            exchange: s.exchange,
            note: s.note,
            error: None,
        });
        id
    }

    /// Attach the response. Ids ascend with insertion order, so the entry is found by binary
    /// search — a linear scan would make an Intruder run quadratic in its own log.
    pub fn finished(&self, id: u64, response: MsgId, status: Option<u16>, len: usize, dur_ms: u64) {
        self.with_entry(id, |e| {
            e.response = Some(response);
            e.status = status;
            e.response_len = len;
            e.duration_ms = dur_ms;
        });
    }

    pub fn failed(&self, id: u64, error: impl Into<String>, dur_ms: u64) {
        let error = error.into();
        self.with_entry(id, |e| {
            e.error = Some(error);
            e.duration_ms = dur_ms;
        });
    }

    fn with_entry(&self, id: u64, f: impl FnOnce(&mut Entry)) {
        let mut g = self.inner.write();
        if let Ok(i) = g.binary_search_by_key(&id, |e| e.id) {
            f(&mut g[i]);
        }
    }

    pub fn get(&self, id: u64) -> Option<Entry> {
        let g = self.inner.read();
        g.binary_search_by_key(&id, |e| e.id)
            .ok()
            .map(|i| g[i].clone())
    }

    /// Newest first, matching the way history is read.
    pub fn entries(&self, offset: usize, limit: usize) -> Vec<Entry> {
        self.inner
            .read()
            .iter()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn by_tool(&self, tool: Tool, offset: usize, limit: usize) -> Vec<Entry> {
        self.inner
            .read()
            .iter()
            .rev()
            .filter(|e| e.tool == tool)
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// How many entries each tool currently holds, in [`Tool::ALL`] order.
    pub fn counts(&self) -> [usize; 4] {
        let g = self.inner.read();
        let mut out = [0usize; 4];
        for e in g.iter() {
            let i = Tool::ALL.iter().position(|t| *t == e.tool).unwrap_or(0);
            out[i] += 1;
        }
        out
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Entries evicted to stay within the cap.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Forget everything, but keep counting ids so an in-flight `finished` cannot land on a
    /// recycled entry and rewrite the wrong request.
    pub fn clear(&self) {
        self.inner.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started(tool: Tool, path: &str) -> Started {
        Started {
            tool,
            host: "target.test".into(),
            port: 443,
            tls: true,
            method: "GET".into(),
            path: path.into(),
            request: MsgId(1),
            started_ms: 1_700_000_000_000,
            exchange: Some(7),
            note: None,
        }
    }

    #[test]
    fn a_request_is_recorded_then_completed_with_its_response() {
        let log = ToolLog::new();
        let id = log.started(started(Tool::Repeater, "/login"));
        assert_eq!(log.get(id).unwrap().response, None, "not finished yet");
        log.finished(id, MsgId(2), Some(302), 1234, 45);
        let e = log.get(id).unwrap();
        assert_eq!(e.status, Some(302));
        assert_eq!(e.response, Some(MsgId(2)));
        assert_eq!(e.response_len, 1234);
        assert_eq!(e.duration_ms, 45);
        assert_eq!(e.exchange, Some(7));
    }

    #[test]
    fn a_failed_send_is_kept_because_a_reset_after_a_payload_is_itself_evidence() {
        let log = ToolLog::new();
        let id = log.started(started(Tool::Intruder, "/search"));
        log.failed(id, "connection reset by peer", 900);
        let e = log.get(id).unwrap();
        assert_eq!(e.error.as_deref(), Some("connection reset by peer"));
        assert_eq!(e.status, None);
        assert_eq!(log.len(), 1, "the attempt stays in the log");
    }

    #[test]
    fn entries_come_back_newest_first_and_filter_by_tool() {
        let log = ToolLog::new();
        log.started(started(Tool::Repeater, "/a"));
        log.started(started(Tool::Intruder, "/b"));
        log.started(started(Tool::Repeater, "/c"));
        let all = log.entries(0, 10);
        assert_eq!(
            all.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
            vec!["/c", "/b", "/a"]
        );
        let rep = log.by_tool(Tool::Repeater, 0, 10);
        assert_eq!(
            rep.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
            vec!["/c", "/a"]
        );
        assert_eq!(log.counts(), [2, 1, 0, 0]);
    }

    #[test]
    fn the_cap_evicts_oldest_first_and_admits_how_many_it_dropped() {
        let log = ToolLog::with_capacity(3);
        for i in 0..10 {
            log.started(started(Tool::Scanner, &format!("/{i}")));
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.dropped(), 7);
        let paths: Vec<String> = log.entries(0, 10).into_iter().map(|e| e.path).collect();
        assert_eq!(paths, vec!["/9", "/8", "/7"], "the newest three survive");
    }

    #[test]
    fn completing_an_evicted_entry_is_a_no_op_rather_than_a_panic() {
        // Intruder finishes requests out of order; by then the entry may be long gone.
        let log = ToolLog::with_capacity(2);
        let first = log.started(started(Tool::Intruder, "/0"));
        log.started(started(Tool::Intruder, "/1"));
        log.started(started(Tool::Intruder, "/2"));
        log.finished(first, MsgId(9), Some(200), 10, 1);
        assert!(log.get(first).is_none());
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn ids_keep_ascending_after_a_clear_so_a_late_completion_cannot_hit_the_wrong_request() {
        let log = ToolLog::new();
        let first = log.started(started(Tool::Repeater, "/a"));
        log.clear();
        let second = log.started(started(Tool::Repeater, "/b"));
        assert!(second > first, "{second} must not reuse {first}");
        log.finished(first, MsgId(5), Some(200), 1, 1);
        assert_eq!(
            log.get(second).unwrap().response,
            None,
            "the new entry is untouched"
        );
    }

    #[test]
    fn tool_names_round_trip_and_there_is_no_proxy_variant() {
        for t in Tool::ALL {
            assert_eq!(Tool::parse(t.as_str()), Some(t));
        }
        // The whole point of this store: browser traffic cannot be logged here.
        assert_eq!(Tool::parse("proxy"), None);
    }
}
