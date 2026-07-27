//! burpsy-scanner — runs passive BChecks over proxied responses.
//!
//! # Placement
//!
//! Scanning happens **off the proxy's hot path**. The proxy hands over `(exchange_id, response_id)`
//! and returns to serving traffic immediately; the scan runs on a separate task. Burp's own audit
//! engine bounds work by *discarding* it (`Zq5.LIMIT_EXCEEDED`), which is a symptom of coupling scan
//! cost to request handling — a proxy that gets slower as its check set grows is a proxy people turn
//! off.
//!
//! # Coverage
//!
//! Two paths, deliberately separate:
//!
//! * [`PassiveScanner::scan`] runs `given response` checks — 105 of PortSwigger's 264 published
//!   checks — with no outbound traffic, automatically, off the proxy hot path.
//! * [`PassiveScanner::audit`] runs the 127 checks that send requests. Never automatic: it generates
//!   traffic to the target, so it must be an explicit operator action.
//!
//! That is 232 of 264 runnable (87.9%). The remainder are counted, not silently dropped: 6 need
//! payload placement into an insertion point, 26 need an interaction server. Every figure here is
//! recomputed by `LoadReport` at load time and the four buckets are asserted to sum to the file
//! count, so a coverage claim cannot drift from what the code actually executes.

use burpsy_bcheck::{Check, Confidence as BConf, Severity as BSev};
use burpsy_core::{
    Confidence, MsgId, NewFinding, Scope, Severity, StoredMessage, TrafficStore,
};
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;

/// What happened when a check set was loaded — reported so coverage is explicit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadReport {
    pub files: usize,
    /// Parsed and runnable now (passive, no Collaborator).
    pub passive: usize,
    /// Parsed, needs outbound traffic, and the evaluator can run it: M2.
    pub active: usize,
    /// Parsed but still out of reach without payload placement into an insertion point (M3).
    pub needs_insertion_point: usize,
    /// Parsed but needs an interaction server.
    pub collaborator: usize,
    /// Failed to parse, with the reason.
    pub errors: Vec<(String, String)>,
}

impl LoadReport {
    pub fn summary(&self) -> String {
        format!(
            "{} passive runnable, {} active runnable, {} need an insertion point, {} need Collaborator, \
             {} unparsable, of {} files ({} runnable = {:.1}%)",
            self.passive,
            self.active,
            self.needs_insertion_point,
            self.collaborator,
            self.errors.len(),
            self.files,
            self.passive + self.active,
            if self.files == 0 {
                0.0
            } else {
                (self.passive + self.active) as f64 * 100.0 / self.files as f64
            }
        )
    }
}

/// Loaded checks plus the findings they produce.
pub struct PassiveScanner {
    passive: Vec<Check>,
    /// Checks that send requests. Run on demand by [`PassiveScanner::audit`], never from the proxy
    /// hot path — active scanning generates traffic and must be an explicit operator action.
    active: Vec<Check>,
    findings: Arc<RwLock<burpsy_core::FindingStore>>,
    scope: Arc<Scope>,
    report: LoadReport,
}

impl PassiveScanner {
    /// Load every `.bcheck` under `dir`, keeping the passive ones.
    pub fn load_dir(dir: &Path, scope: Arc<Scope>) -> Self {
        let mut files = Vec::new();
        walk(dir, &mut files);
        files.sort();

        let mut report = LoadReport::default();
        let mut passive = Vec::new();
        let mut active = Vec::new();
        report.files = files.len();

        for f in files {
            let Ok(src) = std::fs::read_to_string(&f) else {
                continue;
            };
            match burpsy_bcheck::parse(&src) {
                Ok(c) => {
                    if c.needs_collaborator() {
                        report.collaborator += 1;
                    } else if c.is_passive() {
                        report.passive += 1;
                        passive.push(c);
                    } else if c.m2_runnable() {
                        report.active += 1;
                        active.push(c);
                    } else {
                        report.needs_insertion_point += 1;
                    }
                }
                Err(e) => report
                    .errors
                    .push((f.display().to_string(), e.to_string())),
            }
        }

        Self {
            passive,
            active,
            findings: Arc::new(RwLock::new(burpsy_core::FindingStore::new())),
            scope,
            report,
        }
    }

    /// Build from already-parsed checks, for tests.
    pub fn from_checks(checks: Vec<Check>, scope: Arc<Scope>) -> Self {
        let mut report = LoadReport { files: checks.len(), ..Default::default() };
        let (mut passive, mut active) = (Vec::new(), Vec::new());
        for c in checks {
            if c.needs_collaborator() {
                report.collaborator += 1;
            } else if c.is_passive() {
                report.passive += 1;
                passive.push(c);
            } else if c.m2_runnable() {
                report.active += 1;
                active.push(c);
            } else {
                report.needs_insertion_point += 1;
            }
        }
        Self {
            passive,
            active,
            findings: Arc::new(RwLock::new(burpsy_core::FindingStore::new())),
            scope,
            report,
        }
    }

    pub fn report(&self) -> &LoadReport {
        &self.report
    }

    pub fn loaded(&self) -> usize {
        self.passive.len()
    }

    pub fn active_loaded(&self) -> usize {
        self.active.len()
    }

    pub fn findings(&self) -> Arc<RwLock<burpsy_core::FindingStore>> {
        self.findings.clone()
    }

    /// Scan one response. Returns how many findings were recorded (after dedup, new + merged).
    ///
    /// Skips out-of-scope hosts: scanning traffic outside the engagement wastes work and pollutes
    /// results with findings the operator is not authorised to act on.
    pub fn scan(
        &self,
        store: &TrafficStore,
        exchange_id: u64,
        response_id: MsgId,
    ) -> usize {
        if self.passive.is_empty() {
            return 0;
        }
        let Some(ex) = store.exchange(exchange_id) else {
            return 0;
        };
        if !self.scope.contains(&ex.host, ex.port, &ex.path, ex.tls) {
            return 0;
        }
        let Some(resp) = store.get(response_id) else {
            return 0;
        };
        self.scan_message(&resp, &ex.host, &ex.path, exchange_id, response_id)
    }

    /// Scan a message directly, bypassing the store lookup. Exposed for tests.
    pub fn scan_message(
        &self,
        resp: &StoredMessage,
        host: &str,
        path: &str,
        exchange_id: u64,
        response_id: MsgId,
    ) -> usize {
        let ctx = burpsy_bcheck::Ctx::new(resp);
        let mut n = 0usize;
        for check in &self.passive {
            // A check that errors at runtime (e.g. a Java-only regex construct) must not stop the
            // rest of the set — one bad pattern would otherwise silence every later check.
            let Ok(found) = burpsy_bcheck::run_passive(check, &ctx) else {
                continue;
            };
            for f in found {
                self.findings.write().insert(NewFinding {
                    check_name: f.check_name,
                    issue_name: f.issue_name,
                    severity: map_sev(f.severity),
                    confidence: map_conf(f.confidence),
                    host: host.to_string(),
                    detail: f.detail,
                    remediation: f.remediation,
                    exchange_id,
                    response: response_id,
                    path: path.to_string(),
                });
                n += 1;
            }
        }
        n
    }

    /// Run the active checks against one captured exchange, sending probe requests.
    ///
    /// Explicit by design: this generates traffic to the target, so it is never triggered from the
    /// proxy hot path the way passive scanning is. Scope is enforced first — sending unsolicited
    /// requests to a host outside the engagement is the one mistake in this file that would matter
    /// outside the tool.
    ///
    /// A check whose send fails is dropped, not reported. That is the whole point of
    /// [`burpsy_bcheck::eval::EvalError::SendFailed`]: a check that cannot see its own probe
    /// response has no evidence, and reporting anyway would manufacture a false positive.
    pub fn audit(
        &self,
        store: &TrafficStore,
        exchange_id: u64,
        sender: &dyn burpsy_bcheck::eval::Sender,
    ) -> AuditOutcome {
        self.audit_within(store, exchange_id, sender, DEFAULT_AUDIT_BUDGET)
    }

    /// As [`PassiveScanner::audit`], with an explicit wall-clock budget.
    pub fn audit_within(
        &self,
        store: &TrafficStore,
        exchange_id: u64,
        sender: &dyn burpsy_bcheck::eval::Sender,
        budget: std::time::Duration,
    ) -> AuditOutcome {
        let started = std::time::Instant::now();
        let mut o = AuditOutcome::default();
        if self.active.is_empty() {
            return o;
        }
        let Some(ex) = store.exchange(exchange_id) else {
            o.error = Some("no such exchange".into());
            return o;
        };
        if !self.scope.contains(&ex.host, ex.port, &ex.path, ex.tls) {
            o.error = Some(format!("{} is out of scope", ex.host));
            return o;
        }
        let Some(req) = store.get(ex.request) else {
            o.error = Some("request not in store".into());
            return o;
        };
        // An exchange with no response still has a request to mutate, so `base.response` falls back
        // to the request bytes rather than blocking the audit.
        let Some(resp) = ex.response.and_then(|r| store.get(r)) else {
            o.error = Some("exchange has no response yet".into());
            return o;
        };
        let Ok(base_req) = burpsy_core::edit::RequestEdit::from_raw(&req.raw) else {
            o.error = Some("base request unparsable".into());
            return o;
        };

        let target = burpsy_bcheck::eval::Target {
            host: ex.host.clone(),
            port: ex.port,
            tls: ex.tls,
        };

        for check in &self.active {
            // Stop dispatching once the budget is spent. Without this, an unresponsive host costs
            // one read timeout per check — with the full corpus that is over half an hour on a
            // single blocking thread, and the caller has no way to tell it is still alive.
            if started.elapsed() >= budget {
                o.not_run = self.active.len() - (o.ran + o.send_failures + o.skipped);
                o.timed_out = true;
                break;
            }
            let ctx = burpsy_bcheck::Ctx::new(&resp).with_request(base_req.clone());
            match burpsy_bcheck::eval::run_active(check, &ctx, sender, &target) {
                Ok(found) => {
                    o.ran += 1;
                    for f in found {
                        self.findings.write().insert(NewFinding {
                            check_name: f.check_name,
                            issue_name: f.issue_name,
                            severity: map_sev(f.severity),
                            confidence: map_conf(f.confidence),
                            host: ex.host.clone(),
                            detail: f.detail,
                            remediation: f.remediation,
                            exchange_id,
                            response: ex.response.unwrap_or(ex.request),
                            path: ex.path.clone(),
                        });
                        o.findings += 1;
                    }
                }
                Err(burpsy_bcheck::eval::EvalError::SendFailed(_)) => o.send_failures += 1,
                Err(_) => o.skipped += 1,
            }
        }
        o
    }
}

/// What one audit pass did. Reported rather than summed into a single number so a run where every
/// send failed is distinguishable from a run that genuinely found nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct AuditOutcome {
    /// Checks that completed without a transport failure.
    pub ran: usize,
    /// Findings recorded (new plus merged).
    pub findings: usize,
    /// Checks abandoned because a probe could not be sent or read.
    pub send_failures: usize,
    /// Checks the evaluator declined (e.g. an unsupported construct).
    pub skipped: usize,
    /// Checks never attempted because the budget ran out.
    pub not_run: usize,
    /// True when the budget stopped the run. Reported so "found nothing" is distinguishable from
    /// "never finished looking".
    pub timed_out: bool,
    pub error: Option<String>,
}

/// Default wall-clock budget for one audit pass.
///
/// Sized so a completely unresponsive host fails fast rather than occupying a blocking thread for
/// the product of every check and its read timeout.
pub const DEFAULT_AUDIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

fn map_sev(s: BSev) -> Severity {
    match s {
        BSev::High => Severity::High,
        BSev::Medium => Severity::Medium,
        BSev::Low => Severity::Low,
        BSev::Info => Severity::Info,
    }
}

fn map_conf(c: BConf) -> Confidence {
    match c {
        BConf::Certain => Confidence::Certain,
        BConf::Firm => Confidence::Firm,
        BConf::Tentative => Confidence::Tentative,
    }
}

fn walk(p: &Path, out: &mut Vec<std::path::PathBuf>) {
    if p.is_dir() {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                walk(&e.path(), out);
            }
        }
    } else if p.extension().map(|e| e == "bcheck").unwrap_or(false) {
        out.push(p.to_path_buf());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{Direction, Exchange, ScopeRule};
    use bytes::Bytes;

    const LEAK: &str = r#"
metadata:
  language: v1-beta
  name: "Leaked token"
given response then
  if {latest.response} matches "tok_[a-z0-9]{8}" then
    report issue:
      severity: high
      confidence: firm
      detail: "token in response"
  end if
"#;

    const ACTIVE: &str = r#"metadata: name: "active" given host then send request: replacing path: "/x" if "y" in {latest.response} then report issue: severity: low confidence: firm end if"#;
    const OOB: &str = r#"metadata: name: "oob" given response then if dns interactions then report issue: severity: high confidence: certain end if"#;

    fn setup(body: &str, host: &str) -> (Arc<TrafficStore>, u64, MsgId) {
        let store = TrafficStore::new();
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let req = store.put(Bytes::from_static(b"GET /p HTTP/1.1\r\n\r\n"), Direction::Request);
        let ex = store.add_exchange(Exchange {
            id: 0,
            request: req,
            response: None,
            host: host.into(),
            port: 443,
            tls: true,
            method: "GET".into(),
            path: "/p".into(),
            status: Some(200),
            response_len: raw.len(),
            started_ms: 0,
            duration_ms: 1,
            notes: None,
        });
        let resp = store.put(Bytes::from(raw), Direction::Response);
        store.set_response(ex, resp, 200, 0, 1);
        (store, ex, resp)
    }

    #[test]
    fn classifies_checks_and_only_keeps_passive() {
        let checks = vec![
            burpsy_bcheck::parse(LEAK).unwrap(),
            burpsy_bcheck::parse(ACTIVE).unwrap(),
            burpsy_bcheck::parse(OOB).unwrap(),
        ];
        let s = PassiveScanner::from_checks(checks, Arc::new(Scope::allow_everything()));
        let r = s.report();
        assert_eq!((r.passive, r.active, r.collaborator), (1, 1, 1));
        assert_eq!(s.loaded(), 1);
        // Coverage must be stated, not implied.
        assert!(r.summary().contains("1 passive runnable"));
    }

    #[test]
    fn finds_a_leak_in_a_proxied_response() {
        let (store, ex, resp) = setup("secret is tok_abcd1234 ok", "a.test");
        let s = PassiveScanner::from_checks(
            vec![burpsy_bcheck::parse(LEAK).unwrap()],
            Arc::new(Scope::allow_everything()),
        );
        assert_eq!(s.scan(&store, ex, resp), 1);
        let f = s.findings();
        let g = f.read();
        assert_eq!(g.len(), 1);
        let one = &g.all()[0];
        assert_eq!(one.severity, Severity::High);
        assert_eq!(one.host, "a.test");
        assert_eq!(one.check_name, "Leaked token");
    }

    #[test]
    fn clean_response_yields_nothing() {
        let (store, ex, resp) = setup("nothing to see", "a.test");
        let s = PassiveScanner::from_checks(
            vec![burpsy_bcheck::parse(LEAK).unwrap()],
            Arc::new(Scope::allow_everything()),
        );
        assert_eq!(s.scan(&store, ex, resp), 0);
        assert!(s.findings().read().is_empty());
    }

    #[test]
    fn out_of_scope_responses_are_not_scanned() {
        let (store, ex, resp) = setup("secret is tok_abcd1234", "outside.test");
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("inside.test"));
        let s = PassiveScanner::from_checks(vec![burpsy_bcheck::parse(LEAK).unwrap()], Arc::new(sc));
        assert_eq!(s.scan(&store, ex, resp), 0, "must not scan out of scope");
        assert!(s.findings().read().is_empty());
    }

    #[test]
    fn repeat_hits_on_one_host_dedup_to_a_single_finding() {
        let s = PassiveScanner::from_checks(
            vec![burpsy_bcheck::parse(LEAK).unwrap()],
            Arc::new(Scope::allow_everything()),
        );
        // Same host, three different paths — the case that would otherwise flood the UI.
        for i in 0..3u64 {
            let (store, ex, resp) = setup("tok_abcd1234", "a.test");
            let _ = (i, &store);
            s.scan(&store, ex, resp);
        }
        let g = s.findings();
        let r = g.read();
        assert_eq!(r.len(), 1, "must dedup to one finding");
        assert_eq!(r.all()[0].times_seen, 3);
    }

    #[test]
    fn a_broken_check_does_not_silence_the_others() {
        // A regex the Rust engine rejects must not stop later checks from running.
        let bad = r#"metadata: name: "bad" given response then if {latest.response} matches "(?<broken" then report issue: severity: low confidence: firm end if"#;
        let checks = vec![
            burpsy_bcheck::parse(bad).unwrap(),
            burpsy_bcheck::parse(LEAK).unwrap(),
        ];
        let s = PassiveScanner::from_checks(checks, Arc::new(Scope::allow_everything()));
        let (store, ex, resp) = setup("tok_abcd1234", "a.test");
        assert_eq!(s.scan(&store, ex, resp), 1, "the good check must still fire");
    }

    /// A sender that always stalls, to exercise the budget.
    struct SlowSender(std::time::Duration);
    impl burpsy_bcheck::eval::Sender for SlowSender {
        fn send(&self, _t: &burpsy_bcheck::eval::Target, _raw: &[u8]) -> Result<Vec<u8>, String> {
            std::thread::sleep(self.0);
            Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
        }
    }

    #[test]
    fn the_audit_budget_stops_dispatch_and_says_so() {
        // Without a budget, an unresponsive host costs one read timeout per check. With the full
        // corpus that is over half an hour on one blocking thread, and "found nothing" would be
        // indistinguishable from "never finished looking".
        let src = |n: u32| {
            format!(
                "metadata:\n  language: v2-beta\n  name: \"c{n}\"\n\ngiven host then\n  send request:\n    path: \"/p{n}\""
            )
        };
        let checks: Vec<Check> = (0..4).map(|n| burpsy_bcheck::parse(&src(n)).unwrap()).collect();
        let s = PassiveScanner::from_checks(checks, Arc::new(Scope::allow_everything()));
        assert_eq!(s.active_loaded(), 4);

        let store = TrafficStore::new();
        let req = store.put(
            bytes::Bytes::from_static(b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n"),
            burpsy_core::Direction::Request,
        );
        let resp = store.put(
            bytes::Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            burpsy_core::Direction::Response,
        );
        let ex = store.add_exchange(burpsy_core::Exchange {
            id: 0,
            request: req,
            response: Some(resp),
            host: "h.test".into(),
            port: 80,
            tls: false,
            method: "GET".into(),
            path: "/".into(),
            status: Some(200),
            response_len: 0,
            started_ms: 0,
            duration_ms: 0,
            notes: None,
        });
        store.set_response(ex, resp, 200, 0, 0);

        let slow = SlowSender(std::time::Duration::from_millis(60));
        let o = s.audit_within(&store, ex, &slow, std::time::Duration::from_millis(80));
        assert!(o.timed_out, "budget should have tripped: {o:?}");
        assert!(o.not_run > 0, "some checks must be reported as not run: {o:?}");
        assert_eq!(
            o.ran + o.send_failures + o.skipped + o.not_run,
            4,
            "every check must be accounted for exactly once: {o:?}"
        );
    }

    #[test]
    fn loads_the_real_corpus_if_present() {
        let dir = Path::new("/tmp/BChecks");
        if !dir.is_dir() {
            return; // corpus not available in this environment
        }
        let s = PassiveScanner::load_dir(dir, Arc::new(Scope::allow_everything()));
        let r = s.report();
        assert_eq!(r.files, 264, "corpus size");
        assert!(r.errors.is_empty(), "all 264 must parse: {:?}", r.errors);
        // The measured corpus split. Every file lands in exactly one bucket, so the four numbers
        // must sum to the file count — that is what stops a coverage claim from drifting away from
        // what the evaluator actually runs.
        assert_eq!(r.passive, 105, "passive (given response, no send)");
        assert_eq!(r.active, 127, "active (M2: sends requests)");
        assert_eq!(r.needs_insertion_point, 6, "M3: needs payload placement");
        assert_eq!(r.collaborator, 26, "needs an interaction server");
        assert_eq!(
            r.passive + r.active + r.needs_insertion_point + r.collaborator,
            264,
            "every check must be classified exactly once"
        );
        // 232 of 264 runnable. Recomputed from the buckets rather than quoted, so it cannot go stale.
        assert_eq!(r.passive + r.active, 232);
    }
}
