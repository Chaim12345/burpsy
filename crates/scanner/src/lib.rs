//! burpsy-scanner — passive BCheck scanning, an active audit engine, and Burp's issue catalog.
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
//!
//! # Bounding the audit
//!
//! [`audit`] holds the dispatch model: `burp.Zcud`'s seven scopes, an item state machine, and the
//! two-level circuit breakers from Burp's `scanner/error_handling/*` config keys. The design
//! difference from Burp is *where* the bound is applied. Burp expands the work, does it, and then
//! discards the overflow. This engine refuses the work at admission and **names the refusal**:
//! every check considered for an item lands in exactly one [`Disposition`], and
//! [`AuditOutcome::considered`] equals the size of the check set. A caller can therefore always
//! distinguish "ran everything and found nothing" from "stopped looking".
//!
//! # Issue metadata
//!
//! [`catalog`] carries Burp's 183 shipped issue definitions — background, remediation, typical
//! severity, CWE and CAPEC — transcribed from the teardown. A finding gets that text attached when
//! its issue name is an exact match for a catalogued issue and the check supplied no remediation of
//! its own. Exact matches only: attaching the wrong issue's remediation would put invented security
//! advice in front of an operator.

use burpsy_bcheck::{Check, Confidence as BConf, Severity as BSev};
use burpsy_core::{Confidence, MsgId, NewFinding, Scope, Severity, StoredMessage, TrafficStore};
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod audit;
pub mod catalog;
mod catalog_data;

use audit::{ItemBreaker, SessionBreaker};
pub use audit::{
    AuditConfig, AuditLedger, BuiltInConfig, DEFAULT_AUDIT_BUDGET, DispatchScope, Disposition,
    ItemState,
};

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
    /// The dispatch scope of each entry in `active`, resolved once at load rather than per audit.
    /// Kept parallel to `active` by only ever appending to both together.
    scopes: Vec<Option<DispatchScope>>,
    findings: Arc<RwLock<burpsy_core::FindingStore>>,
    scope: Arc<Scope>,
    report: LoadReport,
}

/// `(dispatch units, flat plan of (unit index, check index) steps, undispatchable count)` —
/// named because clippy's `type_complexity` is right that the bare tuple is hard to read at a
/// glance, and this is exactly the shape [`PassiveScanner::plan`] returns.
type DispatchPlan = (Vec<(DispatchScope, String)>, Vec<(usize, usize)>, usize);

impl PassiveScanner {
    /// Load every `.bcheck` under `dir`, keeping the passive ones.
    pub fn load_dir(dir: &Path, scope: Arc<Scope>) -> Self {
        let mut files = Vec::new();
        walk(dir, &mut files);
        files.sort();

        let mut report = LoadReport { files: files.len(), ..Default::default() };
        let mut checks = Vec::new();
        for f in files {
            let Ok(src) = std::fs::read_to_string(&f) else {
                continue;
            };
            match burpsy_bcheck::parse(&src) {
                Ok(c) => checks.push(c),
                Err(e) => report.errors.push((f.display().to_string(), e.to_string())),
            }
        }
        Self::build(checks, scope, report)
    }

    /// Build from already-parsed checks, for tests.
    pub fn from_checks(checks: Vec<Check>, scope: Arc<Scope>) -> Self {
        let report = LoadReport { files: checks.len(), ..Default::default() };
        Self::build(checks, scope, report)
    }

    fn build(checks: Vec<Check>, scope: Arc<Scope>, mut report: LoadReport) -> Self {
        let (mut passive, mut active, mut scopes) = (Vec::new(), Vec::new(), Vec::new());
        for c in checks {
            if c.needs_collaborator() {
                report.collaborator += 1;
            } else if c.is_passive() {
                report.passive += 1;
                passive.push(c);
            } else if c.m2_runnable() {
                report.active += 1;
                scopes.push(DispatchScope::from_frequency(&c.frequency));
                active.push(c);
            } else {
                report.needs_insertion_point += 1;
            }
        }
        Self {
            passive,
            active,
            scopes,
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

    /// The dispatch scope of every loaded active check, in load order.
    ///
    /// Exposed so a caller can see *how often* the set will run before running it: the number of
    /// dispatch units, not the number of checks, is what an audit costs.
    pub fn active_scopes(&self) -> &[Option<DispatchScope>] {
        &self.scopes
    }

    pub fn findings(&self) -> Arc<RwLock<burpsy_core::FindingStore>> {
        self.findings.clone()
    }

    /// Scan one response. Returns how many findings were recorded (after dedup, new + merged).
    ///
    /// Skips out-of-scope hosts: scanning traffic outside the engagement wastes work and pollutes
    /// results with findings the operator is not authorised to act on.
    pub fn scan(&self, store: &TrafficStore, exchange_id: u64, response_id: MsgId) -> usize {
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
                self.record(f, host, path, exchange_id, response_id);
                n += 1;
            }
        }
        n
    }

    fn record(
        &self,
        f: burpsy_bcheck::Finding,
        host: &str,
        path: &str,
        exchange_id: u64,
        response: MsgId,
    ) {
        let mut nf = NewFinding {
            check_name: f.check_name,
            issue_name: f.issue_name,
            severity: map_sev(f.severity),
            confidence: map_conf(f.confidence),
            host: host.to_string(),
            detail: f.detail,
            remediation: f.remediation,
            exchange_id,
            response,
            path: path.to_string(),
        };
        enrich(&mut nf);
        self.findings.write().insert(nf);
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
    ///
    /// One-shot: a fresh [`AuditLedger`] admits everything, so re-auditing the same exchange really
    /// re-audits it. Scope collapse belongs to a *session* ([`PassiveScanner::audit_session`]), not
    /// to a single operator-triggered audit — an operator who clicks audit again means it.
    pub fn audit_within(
        &self,
        store: &TrafficStore,
        exchange_id: u64,
        sender: &dyn burpsy_bcheck::eval::Sender,
        budget: Duration,
    ) -> AuditOutcome {
        let cfg = AuditConfig { time_budget: budget, ..AuditConfig::default() };
        let mut run = Run::new(&cfg);
        self.audit_item(store, exchange_id, sender, &mut run)
    }

    /// Audit a batch of exchanges under one shared budget, ledger and set of circuit breakers.
    ///
    /// This is where bounding pays for itself. A `given host` check has one answer per host, so
    /// auditing 500 exchanges on one host dispatches it once and refuses the other 499 as
    /// [`Disposition::AlreadyCovered`] — refused before a request is built, and *counted*, so the
    /// saving is visible rather than looking like checks that quietly stopped firing.
    ///
    /// The time and request budgets are session-wide, not per exchange: once either is spent the
    /// loop stops admitting items rather than re-deciding the same thing for each remaining one.
    /// Every skipped item still comes back with its whole check set attributed to the reason.
    ///
    /// Scope is re-checked for every exchange, inside the loop. Hoisting that check would let one
    /// in-scope exchange authorise traffic to an out-of-scope host in the same batch.
    pub fn audit_session(
        &self,
        store: &TrafficStore,
        exchange_ids: &[u64],
        sender: &dyn burpsy_bcheck::eval::Sender,
        cfg: &AuditConfig,
    ) -> SessionOutcome {
        let mut run = Run::new(cfg);
        let mut breaker = SessionBreaker::new(cfg);
        let mut out = SessionOutcome::default();

        for &id in exchange_ids {
            // Three whole-item refusals, decided before the exchange is even looked up. Each
            // condition is monotone, so re-deriving it per check would mean parsing every
            // remaining request only to refuse it. Every one of them is still counted: a
            // remaining item is never an item that came back clean.
            if out.paused {
                out.push(id, self.refuse_whole_item(ItemState::Paused, |o| &mut o.session_paused));
                continue;
            }
            if run.out_of_time() {
                let mut o = self.refuse_whole_item(ItemState::Bounded, |o| &mut o.not_run);
                o.timed_out = true;
                out.timed_out = true;
                out.push(id, o);
                continue;
            }
            if run.over_request_budget(0) {
                out.push(
                    id,
                    self.refuse_whole_item(ItemState::Bounded, |o| &mut o.request_budget_spent),
                );
                continue;
            }
            let o = self.audit_item(store, id, sender, &mut run);
            if o.state.dispatched() && breaker.item_finished(o.state == ItemState::Failed) {
                out.paused = true;
            }
            out.timed_out |= o.timed_out;
            out.push(id, o);
        }

        out.requests_sent = run.requests_sent;
        out.dispatch_units = run.ledger.units();
        out.failed_items = breaker.failed_items() as usize;
        out
    }

    /// An outcome for an item the session refused outright, with every check attributed to the
    /// reason it was refused. Nothing here is dispatched, so `requests_sent` stays zero.
    fn refuse_whole_item(
        &self,
        state: ItemState,
        counter: fn(&mut AuditOutcome) -> &mut usize,
    ) -> AuditOutcome {
        let mut o = AuditOutcome { state, ..AuditOutcome::default() };
        *counter(&mut o) = self.active.len();
        o
    }

    /// Audit one exchange within a run's shared budget and ledger.
    fn audit_item(
        &self,
        store: &TrafficStore,
        exchange_id: u64,
        sender: &dyn burpsy_bcheck::eval::Sender,
        run: &mut Run<'_>,
    ) -> AuditOutcome {
        let mut o = AuditOutcome::default();
        if self.active.is_empty() {
            o.state = ItemState::Audited;
            return o;
        }
        let Some(ex) = store.exchange(exchange_id) else {
            return o.refuse(ItemState::Unauditable, "no such exchange");
        };
        // Scope first, before a single byte is built. Sending unsolicited requests to a host
        // outside the engagement is the one bug in this crate that matters outside the tool.
        if !self.scope.contains(&ex.host, ex.port, &ex.path, ex.tls) {
            let why = format!("{} is out of scope", ex.host);
            return o.refuse(ItemState::OutOfScope, &why);
        }
        let Some(req) = store.get(ex.request) else {
            return o.refuse(ItemState::Unauditable, "request not in store");
        };
        let Some(resp) = ex.response.and_then(|r| store.get(r)) else {
            return o.refuse(ItemState::Unauditable, "exchange has no response yet");
        };
        let Ok(base_req) = burpsy_core::edit::RequestEdit::from_raw(&req.raw) else {
            return o.refuse(ItemState::Unauditable, "base request unparsable");
        };

        o.state = ItemState::Auditing;
        let target =
            burpsy_bcheck::eval::Target { host: ex.host.clone(), port: ex.port, tls: ex.tls };
        let metered = Metered::new(sender, &self.scope);
        let mut breaker = ItemBreaker::new(run.cfg);

        // The plan is built before anything is dispatched, so "how much did we not do" is
        // answerable at every point rather than reconstructed afterwards.
        let (units, plan, undispatchable) = self.plan(&ex);
        o.skipped += undispatchable;

        let mut pos = 0usize;
        let mut stop = None;
        'units: while pos < plan.len() {
            let unit_ix = plan[pos].0;
            let mut abandoned = false;
            while pos < plan.len() && plan[pos].0 == unit_ix {
                // Hard stops. Each is monotone — once spent it stays spent — so the rest of the
                // plan is attributed in one go rather than re-tested per step.
                if run.out_of_time() {
                    o.timed_out = true;
                    stop = Some(Disposition::TimeBudgetSpent);
                    break 'units;
                }
                if run.over_request_budget(metered.sent()) {
                    stop = Some(Disposition::RequestBudgetSpent);
                    break 'units;
                }

                let check = plan[pos].1;
                pos += 1;
                if abandoned {
                    o.unit_abandoned += 1;
                    continue;
                }
                if !run.ledger.admit(&units[unit_ix].1, check) {
                    o.already_covered += 1;
                    continue;
                }

                let ctx = burpsy_bcheck::Ctx::new(&resp).with_request(base_req.clone());
                match burpsy_bcheck::eval::run_active(&self.active[check], &ctx, &metered, &target)
                {
                    Ok(found) => {
                        o.ran += 1;
                        breaker.check_succeeded();
                        for f in found {
                            self.record(
                                f,
                                &ex.host,
                                &ex.path,
                                exchange_id,
                                ex.response.unwrap_or(ex.request),
                            );
                            o.findings += 1;
                        }
                    }
                    Err(burpsy_bcheck::eval::EvalError::SendFailed(_)) => {
                        o.send_failures += 1;
                        abandoned = breaker.check_failed();
                    }
                    // The evaluator declining a construct says nothing about the target's health,
                    // so it neither trips the breaker nor clears a failure streak.
                    Err(_) => o.skipped += 1,
                }
            }
            if breaker.unit_finished(abandoned) {
                break;
            }
        }

        // Everything left in the plan is work this engine chose not to admit. Attributing it is
        // what turns a bound into something a caller can see. The breaker owns whether the item
        // failed; `stop` owns why dispatch ended.
        let remaining = plan.len() - pos;
        o.state = if breaker.item_failed() {
            o.item_failed += remaining;
            ItemState::Failed
        } else {
            match stop {
                Some(Disposition::TimeBudgetSpent) => {
                    o.not_run += remaining;
                    ItemState::Bounded
                }
                Some(Disposition::RequestBudgetSpent) => {
                    o.request_budget_spent += remaining;
                    ItemState::Bounded
                }
                _ => ItemState::Audited,
            }
        };
        o.requests_sent = metered.sent();
        o.requests_refused = metered.refused();
        run.requests_sent = run.requests_sent.saturating_add(o.requests_sent);
        debug_assert_eq!(o.considered(), self.active.len(), "every check must be accounted for");
        o
    }

    /// Group the active checks into dispatch units for one exchange, coarsest scope first.
    ///
    /// Returns the units, a flat plan of `(unit index, check index)` steps in dispatch order, and
    /// the number of checks that have no dispatch unit at all. Those last are counted rather than
    /// dropped: a check that silently vanishes from the plan would make the outcome's counters
    /// stop summing to the check set, and the whole point of the counters is that they do.
    fn plan(&self, ex: &burpsy_core::Exchange) -> DispatchPlan {
        let mut units = Vec::new();
        let mut plan = Vec::new();
        // A check whose `given` clause binds to no active scope — `given response` with a send in
        // its body is the one shape that reaches here — has nowhere to run.
        let mut undispatchable = self.scopes.iter().filter(|s| s.is_none()).count();
        for scope in DispatchScope::ALL {
            let members: Vec<usize> =
                (0..self.active.len()).filter(|&i| self.scopes[i] == Some(scope)).collect();
            if members.is_empty() {
                continue;
            }
            match scope.unit_key(ex) {
                Some(key) => {
                    let ix = units.len();
                    units.push((scope, key));
                    plan.extend(members.into_iter().map(|c| (ix, c)));
                }
                // A check bound to a scope this engine cannot key is in the same position.
                // `m2_runnable` keeps insertion-point checks out of `active`, so this is empty for
                // the published corpus — the scope-coverage test pins that.
                None => undispatchable += members.len(),
            }
        }
        (units, plan, undispatchable)
    }
}

/// The catalog definition behind a finding, when its issue name is one of Burp's 183.
///
/// Matched on the exact normalised name, never on a substring: a finding titled "SQL injection in
/// login" is not the catalogued "SQL injection" issue, and pretending otherwise would attach
/// authoritative-looking remediation to something it was not written about.
pub fn definition_for(f: &burpsy_core::Finding) -> Option<&'static catalog::IssueDefinition> {
    catalog::by_name(f.issue_name.as_deref().unwrap_or(&f.check_name))
}

/// Fill in remediation from Burp's catalog when the check supplied none and the issue name is an
/// exact match. Severity is never overwritten: the catalog's `typicalSeverity` describes an issue
/// class, while a finding's severity is a judgement about the evidence in hand.
fn enrich(f: &mut NewFinding) {
    if f.remediation.is_some() {
        return;
    }
    let name = f.issue_name.as_deref().unwrap_or(&f.check_name);
    if let Some(d) = catalog::by_name(name) {
        f.remediation = d.remediation_text();
    }
}

/// Shared state for one audit run: the clock, the budget, and the ledger.
struct Run<'a> {
    cfg: &'a AuditConfig,
    started: Instant,
    ledger: AuditLedger,
    /// Probes sent by items already finished. The current item's are counted separately, because
    /// its meter is still live.
    requests_sent: u32,
}

impl<'a> Run<'a> {
    fn new(cfg: &'a AuditConfig) -> Self {
        Self { cfg, started: Instant::now(), ledger: AuditLedger::new(), requests_sent: 0 }
    }

    fn out_of_time(&self) -> bool {
        self.started.elapsed() >= self.cfg.time_budget
    }

    /// `current_item` is the live meter of the item being dispatched, which has not yet been
    /// folded into `requests_sent`. Pass 0 to ask about the session total alone.
    fn over_request_budget(&self, current_item: u32) -> bool {
        self.cfg
            .max_requests
            .is_some_and(|max| self.requests_sent.saturating_add(current_item) >= max)
    }
}

/// Counts the probes a check actually sends, so the request budget bounds reality rather than an
/// estimate of it.
struct Metered<'a> {
    inner: &'a dyn burpsy_bcheck::eval::Sender,
    scope: &'a Scope,
    sent: std::cell::Cell<u32>,
    refused: std::cell::Cell<u32>,
}

impl<'a> Metered<'a> {
    fn new(inner: &'a dyn burpsy_bcheck::eval::Sender, scope: &'a Scope) -> Self {
        Self {
            inner,
            scope,
            sent: std::cell::Cell::new(0),
            refused: std::cell::Cell::new(0),
        }
    }

    fn sent(&self) -> u32 {
        self.sent.get()
    }

    fn refused(&self) -> u32 {
        self.refused.get()
    }
}

impl burpsy_bcheck::eval::Sender for Metered<'_> {
    /// Meters the request, and refuses it if its own bytes fall outside scope.
    ///
    /// The scope test lives here, wrapping the sender, rather than inside the evaluator: a BCheck
    /// interpreter has no business knowing about engagement authorisation, and putting the check on
    /// the send path makes it unbypassable instead of merely present. `audit_item` already tested
    /// the *base* exchange, but a check that does `replacing path:` sends something else entirely,
    /// and only these bytes say where it is really going.
    fn send(&self, target: &burpsy_bcheck::eval::Target, raw: &[u8]) -> Result<Vec<u8>, String> {
        if let Err(why) = self
            .scope
            .authorise_request(&target.host, target.port, target.tls, raw)
        {
            self.refused.set(self.refused.get().saturating_add(1));
            return Err(why);
        }
        self.sent.set(self.sent.get().saturating_add(1));
        self.inner.send(target, raw)
    }
}

/// What one audit pass did. Reported rather than summed into a single number so a run where every
/// send failed is distinguishable from a run that genuinely found nothing.
///
/// The nine disposition counters partition the check set: [`AuditOutcome::considered`] equals the
/// number of active checks whenever the item was dispatched. Six of the nine mean the engine chose
/// not to look, and a caller that ignores them is reading a bound as a clean result.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct AuditOutcome {
    /// Where the item ended up.
    pub state: ItemState,
    /// Checks that completed without a transport failure.
    pub ran: usize,
    /// Findings recorded (new plus merged).
    pub findings: usize,
    /// Checks abandoned because a probe could not be sent or read.
    pub send_failures: usize,
    /// Checks the evaluator declined (e.g. an unsupported construct).
    pub skipped: usize,
    /// Checks never attempted because the time budget ran out.
    pub not_run: usize,
    /// Checks not admitted because an identical `(dispatch unit, check)` already ran this session.
    pub already_covered: usize,
    /// Checks not admitted because the outbound-request budget was spent.
    pub request_budget_spent: usize,
    /// Checks not admitted because consecutive failures abandoned their dispatch unit.
    pub unit_abandoned: usize,
    /// Checks not admitted because the item breaker failed the whole item.
    pub item_failed: usize,
    /// Checks not admitted because the session breaker paused the run before this item.
    pub session_paused: usize,
    /// Probe requests this item actually sent.
    pub requests_sent: u32,
    /// Probes refused because the request's own path fell outside scope — typically a check that
    /// rewrote the path onto something the operator excluded. Reported, never silent: a refusal is
    /// the engine declining to look, not the target coming back clean.
    pub requests_refused: u32,
    /// True when the time budget stopped the run. Reported so "found nothing" is distinguishable
    /// from "never finished looking".
    pub timed_out: bool,
    pub error: Option<String>,
}

impl AuditOutcome {
    /// Every check that reached a disposition. Equals the size of the active check set whenever
    /// the item was dispatched, and zero when it was refused before any work.
    pub fn considered(&self) -> usize {
        self.ran
            + self.send_failures
            + self.skipped
            + self.not_run
            + self.already_covered
            + self.request_budget_spent
            + self.unit_abandoned
            + self.item_failed
            + self.session_paused
    }

    /// The full disposition histogram, so a caller can render *why* the engine stopped without
    /// hard-coding which of the counters mean "did not look".
    pub fn dispositions(&self) -> [(Disposition, usize); 9] {
        [
            (Disposition::Ran, self.ran),
            (Disposition::Unsupported, self.skipped),
            (Disposition::SendFailed, self.send_failures),
            (Disposition::AlreadyCovered, self.already_covered),
            (Disposition::TimeBudgetSpent, self.not_run),
            (Disposition::RequestBudgetSpent, self.request_budget_spent),
            (Disposition::UnitAbandoned, self.unit_abandoned),
            (Disposition::ItemFailed, self.item_failed),
            (Disposition::SessionPaused, self.session_paused),
        ]
    }

    /// Checks the engine declined to admit. Non-zero here means a clean result is not a clean bill
    /// of health.
    pub fn not_admitted(&self) -> usize {
        self.not_run
            + self.already_covered
            + self.request_budget_spent
            + self.unit_abandoned
            + self.item_failed
            + self.session_paused
    }

    fn refuse(mut self, state: ItemState, why: &str) -> Self {
        self.state = state;
        self.error = Some(why.to_string());
        self
    }
}

/// What a whole [`PassiveScanner::audit_session`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SessionOutcome {
    /// One entry per requested exchange, in the order given.
    pub items: Vec<(u64, AuditOutcome)>,
    pub findings: usize,
    /// Probe requests sent across the whole session.
    pub requests_sent: u32,
    /// Distinct dispatch units the ledger saw — the real size of the work, as opposed to the
    /// number of exchanges asked for.
    pub dispatch_units: usize,
    /// Items the item breaker failed.
    pub failed_items: usize,
    /// True when the session breaker stopped admitting items.
    pub paused: bool,
    /// True when the time budget stopped at least one item.
    pub timed_out: bool,
}

impl SessionOutcome {
    fn push(&mut self, id: u64, o: AuditOutcome) {
        self.findings += o.findings;
        self.items.push((id, o));
    }

    /// Items that ran every check they were given.
    pub fn completed(&self) -> usize {
        self.items.iter().filter(|(_, o)| o.state.completed_audit()).count()
    }

    /// Checks the engine declined to admit across the session.
    pub fn not_admitted(&self) -> usize {
        self.items.iter().map(|(_, o)| o.not_admitted()).sum()
    }
}

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

    /// One captured exchange on `host`, ready to audit.
    fn auditable(store: &TrafficStore, host: &str, path: &str) -> u64 {
        let req = store.put(
            Bytes::from(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            Direction::Request,
        );
        let resp = store.put(
            Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            Direction::Response,
        );
        let ex = store.add_exchange(Exchange {
            id: 0,
            request: req,
            response: Some(resp),
            host: host.into(),
            port: 80,
            tls: false,
            method: "GET".into(),
            path: path.into(),
            status: Some(200),
            response_len: 0,
            started_ms: 0,
            duration_ms: 0,
            notes: None,
        });
        store.set_response(ex, resp, 200, 0, 0);
        ex
    }

    /// `n` distinct `given host` checks, each sending one probe.
    fn host_checks(n: u32) -> Vec<Check> {
        (0..n)
            .map(|i| {
                burpsy_bcheck::parse(&format!(
                    "metadata:\n  language: v2-beta\n  name: \"c{i}\"\n\ngiven host then\n  send request:\n    path: \"/p{i}\""
                ))
                .unwrap()
            })
            .collect()
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
        let checks = vec![burpsy_bcheck::parse(bad).unwrap(), burpsy_bcheck::parse(LEAK).unwrap()];
        let s = PassiveScanner::from_checks(checks, Arc::new(Scope::allow_everything()));
        let (store, ex, resp) = setup("tok_abcd1234", "a.test");
        assert_eq!(s.scan(&store, ex, resp), 1, "the good check must still fire");
    }

    /// A sender that always stalls, to exercise the time budget.
    struct SlowSender(Duration);
    impl burpsy_bcheck::eval::Sender for SlowSender {
        fn send(&self, _t: &burpsy_bcheck::eval::Target, _raw: &[u8]) -> Result<Vec<u8>, String> {
            std::thread::sleep(self.0);
            Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
        }
    }

    /// A sender that answers immediately, recording every host it was asked to reach.
    #[derive(Default)]
    struct RecordingSender(RwLock<Vec<String>>);
    impl burpsy_bcheck::eval::Sender for RecordingSender {
        fn send(&self, t: &burpsy_bcheck::eval::Target, _raw: &[u8]) -> Result<Vec<u8>, String> {
            self.0.write().push(t.host.clone());
            Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
        }
    }

    /// A sender whose every send fails, to drive the circuit breakers.
    struct FailingSender;
    impl burpsy_bcheck::eval::Sender for FailingSender {
        fn send(&self, _t: &burpsy_bcheck::eval::Target, _raw: &[u8]) -> Result<Vec<u8>, String> {
            Err("connection refused".into())
        }
    }

    #[test]
    fn the_audit_budget_stops_dispatch_and_says_so() {
        // Without a budget, an unresponsive host costs one read timeout per check. With the full
        // corpus that is over half an hour on one blocking thread, and "found nothing" would be
        // indistinguishable from "never finished looking".
        let s = PassiveScanner::from_checks(host_checks(4), Arc::new(Scope::allow_everything()));
        assert_eq!(s.active_loaded(), 4);

        let store = TrafficStore::new();
        let ex = auditable(&store, "h.test", "/");

        let slow = SlowSender(Duration::from_millis(60));
        let o = s.audit_within(&store, ex, &slow, Duration::from_millis(80));
        assert!(o.timed_out, "budget should have tripped: {o:?}");
        assert!(o.not_run > 0, "some checks must be reported as not run: {o:?}");
        assert_eq!(
            o.ran + o.send_failures + o.skipped + o.not_run,
            4,
            "every check must be accounted for exactly once: {o:?}"
        );
        assert_eq!(o.considered(), 4);
        assert_eq!(o.state, ItemState::Bounded, "bounded is not the same as audited");
        assert!(!o.state.completed_audit(), "a bounded item must not read as a clean audit");
    }

    #[test]
    fn every_check_is_accounted_for_exactly_once_on_a_healthy_audit() {
        let s = PassiveScanner::from_checks(host_checks(5), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ex = auditable(&store, "h.test", "/");
        let o = s.audit(&store, ex, &RecordingSender::default());
        assert_eq!(o.ran, 5);
        assert_eq!(o.considered(), 5, "the partition must cover the whole check set");
        assert_eq!(o.not_admitted(), 0, "nothing was refused, so nothing may be reported as such");
        assert_eq!(o.state, ItemState::Audited);
        assert_eq!(o.requests_sent, 5);
    }

    #[test]
    fn a_repeat_audit_of_one_exchange_really_re_audits_it() {
        // Scope collapse belongs to a session. An operator who triggers an audit twice means it,
        // and must not silently get "already covered".
        let s = PassiveScanner::from_checks(host_checks(3), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ex = auditable(&store, "h.test", "/");
        let sender = RecordingSender::default();
        assert_eq!(s.audit(&store, ex, &sender).ran, 3);
        let second = s.audit(&store, ex, &sender);
        assert_eq!(second.ran, 3, "a one-shot audit starts with an empty ledger");
        assert_eq!(second.already_covered, 0);
        assert_eq!(sender.0.read().len(), 6);
    }

    #[test]
    fn a_session_collapses_host_scoped_checks_to_one_dispatch_per_host_and_counts_the_rest() {
        // The saving that makes bounding worthwhile: 3 host-scoped checks over 20 exchanges on one
        // host is 3 dispatches, not 60. The 57 refusals are reported, so the drop in `ran` cannot
        // be mistaken for checks that quietly stopped firing.
        let s = PassiveScanner::from_checks(host_checks(3), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ids: Vec<u64> =
            (0..20).map(|i| auditable(&store, "h.test", &format!("/p{i}"))).collect();

        let sender = RecordingSender::default();
        let out = s.audit_session(&store, &ids, &sender, &AuditConfig::default());

        assert_eq!(sender.0.read().len(), 3, "one probe per check, not per exchange");
        assert_eq!(out.requests_sent, 3);
        assert_eq!(out.dispatch_units, 1, "twenty exchanges, one host");
        let ran: usize = out.items.iter().map(|(_, o)| o.ran).sum();
        let covered: usize = out.items.iter().map(|(_, o)| o.already_covered).sum();
        assert_eq!((ran, covered), (3, 57));
        assert_eq!(ran + covered, 3 * 20, "every check on every item is accounted for");
        assert_eq!(out.completed(), 20, "each item still completed its whole check set");
        assert_eq!(out.not_admitted(), 57, "the saving is visible, not silent");
    }

    #[test]
    fn path_scoped_checks_collapse_across_query_strings_but_not_across_paths() {
        // `given path` is the second-largest saving after `given host`: a crawl of one endpoint
        // with fifty query permutations is one dispatch unit, because the query is not part of
        // the path. Two genuinely different paths stay two units.
        let path_check = burpsy_bcheck::parse(
            "metadata:\n  language: v2-beta\n  name: \"p\"\n\ngiven path then\n  send request:\n    path: \"/probe\"",
        )
        .unwrap();
        let s = PassiveScanner::from_checks(
            vec![path_check],
            Arc::new(Scope::allow_everything()),
        );
        assert_eq!(s.active_scopes(), [Some(DispatchScope::PerPath)]);

        let store = TrafficStore::new();
        let mut ids: Vec<u64> =
            (0..5).map(|i| auditable(&store, "h.test", &format!("/search?q={i}"))).collect();
        ids.push(auditable(&store, "h.test", "/other"));

        let sender = RecordingSender::default();
        let out = s.audit_session(&store, &ids, &sender, &AuditConfig::default());
        assert_eq!(out.dispatch_units, 2, "/search and /other, whatever the query");
        assert_eq!(sender.0.read().len(), 2);
        let covered: usize = out.items.iter().map(|(_, o)| o.already_covered).sum();
        assert_eq!(covered, 4, "the four query permutations are refused and counted");
        assert_eq!(out.completed(), 6);
    }

    #[test]
    fn a_session_across_two_hosts_dispatches_host_checks_once_per_host() {
        let s = PassiveScanner::from_checks(host_checks(2), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ids = vec![
            auditable(&store, "a.test", "/"),
            auditable(&store, "b.test", "/"),
            auditable(&store, "a.test", "/other"),
        ];
        let sender = RecordingSender::default();
        let out = s.audit_session(&store, &ids, &sender, &AuditConfig::default());
        assert_eq!(out.dispatch_units, 2, "two hosts");
        let mut hosts = sender.0.read().clone();
        hosts.sort();
        assert_eq!(hosts, vec!["a.test", "a.test", "b.test", "b.test"]);
    }

    #[test]
    fn a_session_never_sends_to_an_out_of_scope_host_even_beside_in_scope_ones() {
        // The one bug in this crate that matters outside the tool. The scope check lives inside the
        // per-item loop precisely so a batch cannot launder an out-of-scope host through an
        // in-scope neighbour.
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("inside.test"));
        let s = PassiveScanner::from_checks(host_checks(2), Arc::new(sc));
        let store = TrafficStore::new();
        let ids = vec![
            auditable(&store, "outside.test", "/"),
            auditable(&store, "inside.test", "/"),
            auditable(&store, "outside.test", "/again"),
        ];
        let sender = RecordingSender::default();
        let out = s.audit_session(&store, &ids, &sender, &AuditConfig::default());

        assert_eq!(
            *sender.0.read(),
            vec!["inside.test", "inside.test"],
            "no probe may reach a host outside the engagement"
        );
        let states: Vec<ItemState> = out.items.iter().map(|(_, o)| o.state).collect();
        assert_eq!(states, vec![ItemState::OutOfScope, ItemState::Audited, ItemState::OutOfScope]);
        // A refused item reports zero considered checks and says why, rather than looking clean.
        assert_eq!(out.items[0].1.considered(), 0);
        assert_eq!(out.items[0].1.error.as_deref(), Some("outside.test is out of scope"));
        assert_eq!(out.completed(), 1);
    }

    #[test]
    fn the_request_budget_refuses_new_checks_instead_of_discarding_finished_ones() {
        // Burp's LIMIT_EXCEEDED throws away work already done. Here the ceiling stops the *next*
        // check from starting, so every probe sent bought a completed result.
        let s = PassiveScanner::from_checks(host_checks(10), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ex = auditable(&store, "h.test", "/");
        let cfg = AuditConfig { max_requests: Some(4), ..AuditConfig::default() };
        let sender = RecordingSender::default();
        let out = s.audit_session(&store, &[ex], &sender, &cfg);

        let o = &out.items[0].1;
        assert_eq!(o.ran, 4, "four checks completed");
        assert_eq!(o.request_budget_spent, 6, "six were refused before they started");
        assert_eq!(o.considered(), 10);
        assert_eq!(sender.0.read().len(), 4, "the ceiling bounds what is sent");
        assert_eq!(o.state, ItemState::Bounded);
        assert!(!o.timed_out, "this bound is the request budget, not the clock");
    }

    #[test]
    fn the_request_budget_carries_across_items_instead_of_resetting_per_item() {
        // A per-item ceiling would not be a session bound at all: N items would each spend the
        // full allowance. Three different hosts, so the ledger collapses nothing and every
        // request is a real one.
        let s = PassiveScanner::from_checks(host_checks(4), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ids: Vec<u64> = (0..3).map(|i| auditable(&store, &format!("h{i}.test"), "/")).collect();
        let cfg = AuditConfig { max_requests: Some(5), ..AuditConfig::default() };
        let sender = RecordingSender::default();
        let out = s.audit_session(&store, &ids, &sender, &cfg);

        assert_eq!(sender.0.read().len(), 5, "the session ceiling, not five per item");
        assert_eq!(out.requests_sent, 5);
        let per_item: Vec<(usize, usize, u32)> = out
            .items
            .iter()
            .map(|(_, o)| (o.ran, o.request_budget_spent, o.requests_sent))
            .collect();
        // Item 1 spends 4 of 5; item 2 gets one more check in and is cut off; item 3 never starts.
        assert_eq!(per_item, vec![(4, 0, 4), (1, 3, 1), (0, 4, 0)]);
        let states: Vec<ItemState> = out.items.iter().map(|(_, o)| o.state).collect();
        assert_eq!(states, vec![ItemState::Audited, ItemState::Bounded, ItemState::Bounded]);
        assert_eq!(out.completed(), 1, "only the first item ran its whole set");
        assert_eq!(out.not_admitted(), 7);
        for (_, o) in &out.items {
            assert_eq!(o.considered(), 4, "including the item that never started");
        }
    }

    #[test]
    fn a_spent_time_budget_stops_the_session_rather_than_re_deciding_it_per_exchange() {
        let s = PassiveScanner::from_checks(host_checks(2), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ids: Vec<u64> = (0..4).map(|i| auditable(&store, &format!("h{i}.test"), "/")).collect();
        let cfg =
            AuditConfig { time_budget: Duration::from_millis(80), ..AuditConfig::default() };
        let out = s.audit_session(&store, &ids, &SlowSender(Duration::from_millis(60)), &cfg);

        assert!(out.timed_out);
        // Every item after the clock ran out is Bounded with its whole set in `not_run`, and
        // sent nothing — the budget bounds the session, not each exchange in it.
        let tail: Vec<_> = out
            .items
            .iter()
            .skip(2)
            .map(|(_, o)| (o.state, o.not_run, o.requests_sent))
            .collect();
        assert_eq!(tail, vec![(ItemState::Bounded, 2, 0), (ItemState::Bounded, 2, 0)]);
        assert_eq!(out.completed(), 1, "only the first item finished inside the budget");
        for (_, o) in &out.items {
            assert_eq!(o.considered(), 2);
        }
    }

    #[test]
    fn two_consecutive_send_failures_abandon_the_rest_of_the_dispatch_unit() {
        let s = PassiveScanner::from_checks(host_checks(6), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ex = auditable(&store, "dead.test", "/");
        let o = s.audit(&store, ex, &FailingSender);

        assert_eq!(o.send_failures, 2, "the breaker stops after two consecutive failures");
        assert_eq!(o.unit_abandoned, 4, "the rest of the unit is refused, not attempted");
        assert_eq!(o.considered(), 6);
        assert_eq!(o.ran, 0);
        // One abandoned unit is not yet two, so the item itself is not failed.
        assert_eq!(o.state, ItemState::Audited);
        assert_eq!(o.findings, 0);
    }

    #[test]
    fn the_session_breaker_stops_admitting_items_and_reports_the_ones_it_skipped() {
        // Two dispatch units per item (host- and request-scoped), both failing, fails the item;
        // two failed items then pause the session.
        let mut checks = host_checks(2);
        for name in ["r", "r2"] {
            checks.push(
                burpsy_bcheck::parse(&format!(
                    "metadata:\n  language: v2-beta\n  name: \"{name}\"\n\ngiven request then\n  send request:\n    path: \"/{name}\""
                ))
                .unwrap(),
            );
        }
        let s = PassiveScanner::from_checks(checks, Arc::new(Scope::allow_everything()));
        assert_eq!(s.active_loaded(), 4);

        let store = TrafficStore::new();
        let ids: Vec<u64> =
            (0..5).map(|i| auditable(&store, &format!("dead{i}.test"), "/")).collect();
        let cfg = AuditConfig { pause_session_after_failed_items: 2, ..AuditConfig::default() };
        let out = s.audit_session(&store, &ids, &FailingSender, &cfg);

        assert!(out.paused, "the session breaker must trip: {out:?}");
        assert_eq!(out.failed_items, 2);
        let states: Vec<ItemState> = out.items.iter().map(|(_, o)| o.state).collect();
        assert_eq!(
            states,
            vec![
                ItemState::Failed,
                ItemState::Failed,
                ItemState::Paused,
                ItemState::Paused,
                ItemState::Paused
            ]
        );
        // The three items never started are reported as such, not as three clean audits.
        assert_eq!(out.completed(), 0);
        for (_, o) in out.items.iter().skip(2) {
            assert_eq!(o.session_paused, 4);
            assert_eq!(o.considered(), 4);
            assert_eq!(o.requests_sent, 0);
        }
    }

    #[test]
    fn disabling_the_breakers_keeps_every_check_dispatched_against_a_dead_host() {
        // Burp's "Never stop audit due to application errors" preset, taken to its conclusion.
        let s = PassiveScanner::from_checks(host_checks(6), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ex = auditable(&store, "dead.test", "/");
        let out = s.audit_session(&store, &[ex], &FailingSender, &AuditConfig::without_breakers());
        let o = &out.items[0].1;
        assert_eq!(o.send_failures, 6, "with the breaker off every check is attempted");
        assert_eq!(o.unit_abandoned, 0);
        assert_eq!(o.state, ItemState::Audited);
    }

    #[test]
    fn a_check_with_no_dispatch_unit_is_counted_rather_than_silently_dropped() {
        // `given response` plus a send is not passive and not insertion-point bound, so it lands
        // in the active set with no active dispatch scope. It cannot run — but it must still show
        // up in the counters, or the outcome would claim to have considered a check it never saw.
        let orphan = burpsy_bcheck::parse(
            "metadata:\n  language: v2-beta\n  name: \"orphan\"\n\ngiven response then\n  send request:\n    path: \"/x\"",
        )
        .unwrap();
        let mut checks = host_checks(2);
        checks.push(orphan);
        let s = PassiveScanner::from_checks(checks, Arc::new(Scope::allow_everything()));
        assert_eq!(s.active_loaded(), 3);
        assert_eq!(
            s.active_scopes().iter().filter(|s| s.is_none()).count(),
            1,
            "the orphan binds to no active dispatch scope"
        );

        let store = TrafficStore::new();
        let ex = auditable(&store, "h.test", "/");
        let sender = RecordingSender::default();
        let o = s.audit(&store, ex, &sender);
        assert_eq!(o.ran, 2);
        assert_eq!(o.skipped, 1, "the orphan is reported as unrunnable, not omitted");
        assert_eq!(o.considered(), 3);
        assert_eq!(sender.0.read().len(), 2);
    }

    #[test]
    fn the_disposition_histogram_partitions_the_check_set() {
        let s = PassiveScanner::from_checks(host_checks(6), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let ex = auditable(&store, "dead.test", "/");
        let o = s.audit(&store, ex, &FailingSender);

        let hist = o.dispositions();
        assert_eq!(hist.iter().map(|(_, n)| n).sum::<usize>(), o.considered());
        assert_eq!(o.considered(), 6);
        let nonzero: Vec<_> = hist.iter().filter(|(_, n)| *n > 0).copied().collect();
        assert_eq!(
            nonzero,
            vec![(Disposition::SendFailed, 2), (Disposition::UnitAbandoned, 4)]
        );
        // Four sixths of the check set never looked at this host. An operator reading only
        // "0 findings" would be reading a bound as a clean result.
        assert_eq!(
            hist.iter().filter(|(d, n)| d.stopped_looking() && *n > 0).count(),
            1
        );
        assert_eq!(o.not_admitted(), 4);
    }

    #[test]
    fn an_exchange_with_no_response_is_unauditable_rather_than_clean() {
        let s = PassiveScanner::from_checks(host_checks(2), Arc::new(Scope::allow_everything()));
        let store = TrafficStore::new();
        let req = store.put(Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"), Direction::Request);
        let ex = store.add_exchange(Exchange {
            id: 0,
            request: req,
            response: None,
            host: "h.test".into(),
            port: 80,
            tls: false,
            method: "GET".into(),
            path: "/".into(),
            status: None,
            response_len: 0,
            started_ms: 0,
            duration_ms: 0,
            notes: None,
        });
        let o = s.audit(&store, ex, &RecordingSender::default());
        assert_eq!(o.state, ItemState::Unauditable);
        assert!(!o.state.completed_audit());
        assert_eq!(o.error.as_deref(), Some("exchange has no response yet"));
        assert_eq!(o.considered(), 0);
    }

    #[test]
    fn a_finding_named_after_a_catalogued_issue_gains_burps_remediation() {
        let src = r#"
metadata:
  language: v1-beta
  name: "SQL injection"
given response then
  if {latest.response} matches "syntax error" then
    report issue:
      severity: high
      confidence: firm
      detail: "database error in response"
  end if
"#;
        let s = PassiveScanner::from_checks(
            vec![burpsy_bcheck::parse(src).unwrap()],
            Arc::new(Scope::allow_everything()),
        );
        let (store, ex, resp) = setup("a syntax error occurred", "a.test");
        assert_eq!(s.scan(&store, ex, resp), 1);

        let f = s.findings();
        let g = f.read();
        let one = &g.all()[0];
        let rem = one.remediation.as_deref().expect("catalog remediation must be attached");
        assert!(
            rem.starts_with("The most effective way to prevent SQL injection attacks"),
            "must be Burp's shipped text: {}",
            &rem[..rem.len().min(80)]
        );
        // The catalog describes the issue class; the check judged the evidence. Severity stays the
        // check's call, and the definition is reachable for anything else the UI wants to show.
        assert_eq!(one.severity, Severity::High);
        let d = definition_for(one).expect("the finding resolves to a catalogued issue");
        assert_eq!(d.type_index, 0x0010_0200);
        assert_eq!(d.cwe_ids().collect::<Vec<_>>(), vec![89, 94, 116]);
    }

    #[test]
    fn a_check_that_supplies_its_own_remediation_keeps_it() {
        let src = r#"
metadata:
  language: v1-beta
  name: "SQL injection"
given response then
  if {latest.response} matches "syntax error" then
    report issue:
      severity: high
      confidence: firm
      detail: "d"
      remediation: "Use the ORM."
  end if
"#;
        let s = PassiveScanner::from_checks(
            vec![burpsy_bcheck::parse(src).unwrap()],
            Arc::new(Scope::allow_everything()),
        );
        let (store, ex, resp) = setup("a syntax error occurred", "a.test");
        s.scan(&store, ex, resp);
        let f = s.findings();
        let g = f.read();
        assert_eq!(
            g.all()[0].remediation.as_deref(),
            Some("Use the ORM."),
            "the check's own advice must win over the catalog's"
        );
    }

    #[test]
    fn a_finding_with_no_catalogued_name_gains_nothing_rather_than_something_approximate() {
        let s = PassiveScanner::from_checks(
            vec![burpsy_bcheck::parse(LEAK).unwrap()],
            Arc::new(Scope::allow_everything()),
        );
        let (store, ex, resp) = setup("tok_abcd1234", "a.test");
        s.scan(&store, ex, resp);
        let f = s.findings();
        let g = f.read();
        assert_eq!(g.all()[0].remediation, None, "no near-enough match may be attached");
        assert!(definition_for(&g.all()[0]).is_none());
    }

    #[test]
    fn a_check_that_rewrites_the_path_out_of_scope_is_refused_before_it_sends() {
        // The base exchange is in scope at /p, so `audit_item`'s own check passes. The check then
        // does `replacing path: "/x"` — which is excluded. Only the outgoing bytes know that, so
        // this is the case a base-request scope test structurally cannot catch.
        let mut scope = Scope::new();
        scope.add(ScopeRule::include("t.test"));
        scope.add(ScopeRule::exclude("t.test").with_path_prefix("/x"));

        let checks = vec![burpsy_bcheck::parse(ACTIVE).unwrap()];
        let s = PassiveScanner::from_checks(checks, Arc::new(scope));
        assert_eq!(s.active_loaded(), 1);

        let store = TrafficStore::new();
        let ex = auditable(&store, "t.test", "/p");
        let sender = RecordingSender::default();
        let o = s.audit(&store, ex, &sender);

        assert!(
            sender.0.read().is_empty(),
            "an out-of-scope request reached the network: {:?}",
            sender.0.read()
        );
        assert_eq!(o.requests_sent, 0, "nothing may be counted as sent");
        assert_eq!(o.requests_refused, 1, "the refusal must be visible, not silent");
        assert_eq!(o.findings, 0, "and a refused probe must never yield a finding");
    }

    #[test]
    fn a_check_staying_within_scope_still_sends_normally() {
        // Guard against over-correcting: the refusal must be about the path, not about active
        // checks in general.
        let mut scope = Scope::new();
        scope.add(ScopeRule::include("t.test"));
        scope.add(ScopeRule::exclude("t.test").with_path_prefix("/nowhere-near"));

        let checks = vec![burpsy_bcheck::parse(ACTIVE).unwrap()];
        let s = PassiveScanner::from_checks(checks, Arc::new(scope));
        let store = TrafficStore::new();
        let ex = auditable(&store, "t.test", "/p");
        let sender = RecordingSender::default();
        let o = s.audit(&store, ex, &sender);

        assert_eq!(o.requests_sent, 1, "an in-scope rewrite must still go out");
        assert_eq!(o.requests_refused, 0);
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

    #[test]
    fn the_real_corpus_reaches_only_the_dispatch_scopes_this_engine_implements() {
        let dir = Path::new("/tmp/BChecks");
        if !dir.is_dir() {
            return; // corpus not available in this environment
        }
        let s = PassiveScanner::load_dir(dir, Arc::new(Scope::allow_everything()));
        assert_eq!(s.active_scopes().len(), 127);
        let count = |want: DispatchScope| {
            s.active_scopes().iter().filter(|s| **s == Some(want)).count()
        };
        // Measured over the corpus, not assumed. `given url`, the in-session scope and the two
        // insertion-point scopes have no runnable BCheck form today, so nothing lands in them —
        // pinned here so that gap stays a stated fact rather than an unexamined one.
        let (host, path, request) = (
            count(DispatchScope::PerHost),
            count(DispatchScope::PerPath),
            count(DispatchScope::PerRequest),
        );
        assert_eq!((host, path, request), (89, 11, 27), "given host / given path / given request");
        assert_eq!(host + path + request, 127, "the three reached scopes cover every active check");
        for empty in [
            DispatchScope::PerUrl,
            DispatchScope::InSessionPerRequest,
            DispatchScope::PerInsertionPoint,
            DispatchScope::StoredPerInsertionPoint,
        ] {
            assert_eq!(count(empty), 0, "{} has no runnable BCheck form", empty.label());
        }
        let mut used: Vec<DispatchScope> = s.active_scopes().iter().flatten().copied().collect();
        used.sort();
        used.dedup();
        assert!(
            used.iter().all(DispatchScope::is_reachable),
            "an active check must never bind to a scope with no dispatch unit"
        );
        assert_eq!(
            s.active_scopes().iter().filter(|s| s.is_none()).count(),
            0,
            "every active check binds to some scope"
        );
    }

    #[test]
    fn none_of_the_two_hundred_and_sixty_four_check_names_is_a_catalogued_issue() {
        let dir = Path::new("/tmp/BChecks");
        if !dir.is_dir() {
            return; // corpus not available in this environment
        }
        // Measured, not assumed: the BChecks corpus is community CVE and token-detection checks,
        // while Burp's 183 definitions are its built-in audit taxonomy. The two populations do not
        // overlap at all, so enrichment fires on nothing in this corpus. Pinned so that if a future
        // check *is* named after a catalogued issue, someone has to decide that deliberately rather
        // than discover it through a surprise block of remediation text.
        let s = PassiveScanner::load_dir(dir, Arc::new(Scope::allow_everything()));
        let matched = s
            .passive
            .iter()
            .chain(&s.active)
            .filter(|c| catalog::by_name(&c.metadata.name).is_some())
            .count();
        assert_eq!(matched, 0, "no published BCheck shares a name with a catalogued issue");
    }
}
