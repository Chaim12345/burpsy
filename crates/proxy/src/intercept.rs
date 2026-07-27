//! Request interception: hold a request, let an operator rewrite it, then forward or drop.
//!
//! # Why a oneshot per held request rather than a shared "resume" flag
//!
//! The property that matters is that holding one request must not stall anything else. A single
//! gate — one mutex, one condvar, one "paused" boolean — makes every connection wait on the same
//! thing, so inspecting one request freezes the browser. Instead each held request parks *its own*
//! connection task on *its own* [`oneshot`] receiver. Nothing else in the process is touched: other
//! connections are separate tasks that never look at this queue, and the queue mutex is only ever
//! held long enough to insert or remove a map entry, never across an `await`.
//!
//! (`parking_lot::MutexGuard` is `!Send`, so "never across an await" is enforced by the compiler
//! rather than by discipline.)
//!
//! # Why the store write happens after the verdict, not before
//!
//! An operator who edits a request needs history to show what was actually sent — a history that
//! records the pre-edit bytes is worse than useless, because every later replay and every scan
//! would work from a request that never left the machine. The store has no "amend this message"
//! operation by design (messages are immutable so spans into them stay valid forever), so the only
//! way to record the truth is to decide first and store second.
//!
//! The consequence, stated plainly: **a held request does not appear in `/api/history` until it is
//! forwarded or dropped.** While held it is visible only through the interception queue. That is the
//! same split Burp presents, and it is the price of never lying about what was sent.
//!
//! # Fail-open, deliberately
//!
//! If the resume channel is dropped without a verdict — the only way that happens is the whole
//! queue being torn down — [`Interceptor::hold`] forwards the original request rather than hanging
//! the client. A proxy that silently strands connections is indistinguishable from a network fault.

use bytes::Bytes;
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::oneshot;

/// What the operator decided about a held request.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Send these bytes upstream — the original, or the operator's rewrite.
    Forward(Bytes),
    /// Never send it. The client gets a synthetic response carrying this reason.
    Drop(String),
}

/// The routing facts about a held request, taken from the connection that is holding it.
#[derive(Debug, Clone)]
pub struct HeldMeta {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
}

/// One queue entry as the API renders it.
///
/// `raw` is lossy UTF-8 because the operator edits it as text. The bytes actually forwarded are
/// whatever comes back from [`Interceptor::forward`], so a request containing invalid UTF-8 that is
/// forwarded *unedited* still goes out byte-exact — only an explicit rewrite can lose bytes, and
/// that is the operator's choice.
#[derive(Debug, Clone, Serialize)]
pub struct HeldView {
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
    /// How long this request has been waiting, so a stale queue is visible rather than mysterious.
    pub held_ms: u64,
    pub len: usize,
    pub raw: String,
}

struct Waiting {
    meta: HeldMeta,
    raw: Bytes,
    since: Instant,
    resume: oneshot::Sender<Verdict>,
}

/// The hold queue. One per proxy; share it with the API layer via `Arc`.
pub struct Interceptor {
    enabled: AtomicBool,
    next_id: AtomicU64,
    /// `BTreeMap` rather than `HashMap`: ids are monotonic, so iteration order is arrival order and
    /// the operator sees the queue in the order the requests actually arrived.
    held: Mutex<BTreeMap<u64, Waiting>>,
}

impl std::fmt::Debug for Interceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interceptor")
            .field("enabled", &self.is_enabled())
            .field("pending", &self.pending())
            .finish()
    }
}

impl Interceptor {
    /// A disabled interceptor. Interception is opt-in: a proxy that starts by holding traffic looks
    /// broken to whoever pointed a browser at it.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            held: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Turn interception on or off. Turning it **off releases the whole queue unedited** and returns
    /// how many were released: an operator who switches interception off is saying "stop bothering
    /// me", not "strand the requests you already took".
    pub fn set_enabled(&self, on: bool) -> usize {
        self.enabled.store(on, Ordering::Relaxed);
        if on {
            return 0;
        }
        let drained: Vec<Waiting> = std::mem::take(&mut *self.held.lock())
            .into_values()
            .collect();
        let n = drained.len();
        for w in drained {
            let _ = w.resume.send(Verdict::Forward(w.raw));
        }
        n
    }

    pub fn pending(&self) -> usize {
        self.held.lock().len()
    }

    /// Park this request until the operator decides. Returns instantly when interception is off, so
    /// the disabled path costs one relaxed atomic load and nothing else.
    pub async fn hold(&self, meta: HeldMeta, raw: Bytes) -> Verdict {
        if !self.is_enabled() {
            return Verdict::Forward(raw);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut q = self.held.lock();
            q.insert(
                id,
                Waiting {
                    meta,
                    raw: raw.clone(),
                    since: Instant::now(),
                    resume: tx,
                },
            );
        }
        tracing::debug!("held request {id} ({} byte(s))", raw.len());
        match rx.await {
            Ok(v) => v,
            Err(_) => Verdict::Forward(raw),
        }
    }

    /// The queue, oldest first.
    pub fn list(&self) -> Vec<HeldView> {
        let q = self.held.lock();
        q.iter()
            .map(|(id, w)| HeldView {
                id: *id,
                host: w.meta.host.clone(),
                port: w.meta.port,
                tls: w.meta.tls,
                method: w.meta.method.clone(),
                path: w.meta.path.clone(),
                held_ms: w.since.elapsed().as_millis() as u64,
                len: w.raw.len(),
                raw: String::from_utf8_lossy(&w.raw).into_owned(),
            })
            .collect()
    }

    /// Release `id`, optionally replacing its bytes. `false` means there is no such held request —
    /// it was already resolved, or the client hung up.
    pub fn forward(&self, id: u64, edited: Option<Bytes>) -> bool {
        let Some(w) = self.held.lock().remove(&id) else {
            return false;
        };
        let bytes = edited.unwrap_or_else(|| w.raw.clone());
        w.resume.send(Verdict::Forward(bytes)).is_ok()
    }

    /// Refuse to forward `id`; its client gets a synthetic response naming `reason`.
    pub fn drop_request(&self, id: u64, reason: impl Into<String>) -> bool {
        let Some(w) = self.held.lock().remove(&id) else {
            return false;
        };
        w.resume.send(Verdict::Drop(reason.into())).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn meta() -> HeldMeta {
        HeldMeta {
            host: "a.test".into(),
            port: 80,
            tls: false,
            method: "GET".into(),
            path: "/x".into(),
        }
    }

    #[tokio::test]
    async fn a_disabled_interceptor_forwards_the_original_bytes_without_queueing() {
        let ic = Interceptor::new();
        let v = ic
            .hold(meta(), Bytes::from_static(b"GET /x HTTP/1.1\r\n\r\n"))
            .await;
        match v {
            Verdict::Forward(b) => assert_eq!(&b[..], b"GET /x HTTP/1.1\r\n\r\n"),
            Verdict::Drop(r) => panic!("disabled interceptor dropped: {r}"),
        }
        assert_eq!(ic.pending(), 0, "a disabled hold must not enter the queue");
    }

    #[tokio::test]
    async fn forwarding_with_edited_bytes_returns_the_edit_not_the_original() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"ORIGINAL")).await })
        };
        wait_for_pending(&ic, 1).await;

        let view = ic.list();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].raw, "ORIGINAL");
        assert_eq!(view[0].path, "/x");
        assert!(ic.forward(view[0].id, Some(Bytes::from_static(b"EDITED"))));

        match held.await.unwrap() {
            Verdict::Forward(b) => assert_eq!(&b[..], b"EDITED"),
            Verdict::Drop(r) => panic!("expected forward, got drop: {r}"),
        }
        assert_eq!(ic.pending(), 0);
    }

    #[tokio::test]
    async fn dropping_a_held_request_yields_a_drop_verdict_carrying_the_reason() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"REQ")).await })
        };
        wait_for_pending(&ic, 1).await;
        let id = ic.list()[0].id;
        assert!(ic.drop_request(id, "operator said no"));

        match held.await.unwrap() {
            Verdict::Drop(r) => assert_eq!(r, "operator said no"),
            Verdict::Forward(_) => panic!("expected drop"),
        }
    }

    #[tokio::test]
    async fn resolving_an_unknown_id_reports_failure_rather_than_pretending() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        assert!(!ic.forward(999, None));
        assert!(!ic.drop_request(999, "x"));
    }

    #[tokio::test]
    async fn turning_interception_off_releases_everything_already_held() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let a = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"A")).await })
        };
        let b = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"B")).await })
        };
        wait_for_pending(&ic, 2).await;

        assert_eq!(
            ic.set_enabled(false),
            2,
            "both held requests must be released"
        );
        for h in [a, b] {
            match h.await.unwrap() {
                Verdict::Forward(_) => {}
                Verdict::Drop(r) => panic!("switching interception off must not drop: {r}"),
            }
        }
        assert_eq!(ic.pending(), 0);
    }

    #[tokio::test]
    async fn the_queue_is_listed_in_arrival_order() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        for (n, p) in ["/first", "/second", "/third"].into_iter().enumerate() {
            let spawned = ic.clone();
            let mut m = meta();
            m.path = p.to_string();
            tokio::spawn(async move { spawned.hold(m, Bytes::from_static(b"R")).await });
            // Serialised on purpose: arrival order is only meaningful if arrival is ordered.
            wait_for_pending(&ic, n + 1).await;
        }
        let paths: Vec<String> = ic.list().into_iter().map(|v| v.path).collect();
        assert_eq!(paths, vec!["/first", "/second", "/third"]);
    }

    /// Poll rather than sleep a fixed time: a fixed sleep is either flaky or slow.
    async fn wait_for_pending(ic: &Interceptor, n: usize) {
        for _ in 0..2000 {
            if ic.pending() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!(
            "timed out waiting for {n} held request(s), have {}",
            ic.pending()
        );
    }
}
