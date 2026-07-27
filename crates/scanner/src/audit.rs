//! The audit engine: seven dispatch scopes, an item state machine, and admission-side bounding.
//!
//! # The decision this module exists to make
//!
//! Burp bounds unbounded audit growth by *discarding* work. `burp.Zq5.LIMIT_EXCEEDED` marks an
//! insertion point that Burp expanded, queued, and then abandoned — *"Burp Scanner didn't audit
//! this insertion point, as it reached the maximum limit of insertion points to audit per
//! request."* The expansion happened, the memory was allocated, the cost was paid, and the result
//! was thrown away. `requests × insertion points × checks` is unbounded, and a cap applied at the
//! end is the most expensive place to apply one.
//!
//! This engine bounds the work **admitted**. Every unit of work passes an admission gate *before*
//! dispatch, and nothing that starts is ever abandoned mid-flight. A refusal is not silence: it is
//! a named [`Disposition`] with a count, so a caller can always tell "looked and found nothing"
//! from "stopped looking". That distinction is the whole contract — a scanner that quietly stops
//! looking reports a clean bill of health for a host it barely touched.
//!
//! # Scope collapse is the largest saving
//!
//! `burp.Zcud` defines seven dispatch scopes because *how often a check runs* is the primary
//! determinant of cost. A `given host` check auditing 500 captured exchanges on one host is 500
//! dispatches of a check whose answer cannot change between them. [`AuditLedger`] records which
//! `(dispatch unit, check)` pairs have run, so the second through five-hundredth are refused as
//! [`Disposition::AlreadyCovered`] — refused before a request is built, not after.
//!
//! This is admission control rather than caching: nothing is stored except one bit per pair, and
//! the refusal is reported rather than silently folded into "found nothing".
//!
//! # What is faithful to Burp and what is ours
//!
//! The seven scopes and the two-level failure model are Burp's, recovered from `burp.Zcud` and
//! from the `scanner/error_handling/*` keys in `resources/BuiltInConfigs/`. The state names are
//! ours, because the semantics differ: Burp's `Zq5` describes the fate of an insertion point that
//! was already expanded, and ours describes whether work was admitted at all. `Zq5`'s
//! `permanentIndex` byte is not reproduced — it is assigned in a static initialiser the obfuscator
//! stripped, so no recovered value exists to be faithful to.

use std::collections::HashMap;
use std::time::Duration;

use burpsy_bcheck::ast::Frequency;
use burpsy_core::Exchange;

/// How often a check runs — `burp.Zcud`'s seven dispatch scopes.
///
/// Listed coarsest-first, which is also the order this engine dispatches them in: a host that has
/// stopped answering should be discovered once by the host-scoped checks, not rediscovered by
/// every request-scoped check afterwards. (`Zcud` declares them in a different order; the
/// membership is what is recovered, the ordering is a choice made here.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum DispatchScope {
    /// Once per host. `Zcud::getActivePerHostChecksFactory`.
    PerHost,
    /// Once per path, ignoring the query string. `Zcud::getActivePerPathChecksFactory`.
    PerPath,
    /// Once per URL, i.e. per path *and* query. `Zcud::getActivePerUrlChecksFactory`.
    PerUrl,
    /// Once per captured request. `Zcud::getActivePerRequestChecksFactory`.
    PerRequest,
    /// Per request, but only while the session is valid.
    /// `Zcud::getInSessionActivePerRequestChecksFactory`.
    InSessionPerRequest,
    /// Once per insertion point — Burp's cost centre.
    /// `Zcud::getActivePerInsertionPointChecksFactory`.
    PerInsertionPoint,
    /// Per insertion point, threading a second stored request for second-order checks.
    /// `Zcud::getStoredActivePerInsertionPointChecksFactory`.
    StoredPerInsertionPoint,
}

impl DispatchScope {
    /// All seven, in dispatch order.
    pub const ALL: [DispatchScope; 7] = [
        DispatchScope::PerHost,
        DispatchScope::PerPath,
        DispatchScope::PerUrl,
        DispatchScope::PerRequest,
        DispatchScope::InSessionPerRequest,
        DispatchScope::PerInsertionPoint,
        DispatchScope::StoredPerInsertionPoint,
    ];

    /// The scope a BCheck's `given` clause binds to, or `None` when the check is passive.
    ///
    /// BCheck's grammar reaches four of the seven. `PerUrl` has no `given` form;
    /// `InSessionPerRequest` needs session handling this crate does not have; the two
    /// insertion-point scopes need payload placement, which lives in the BCheck evaluator.
    /// [`DispatchScope::is_reachable`] states that gap rather than leaving it implied.
    pub fn from_frequency(f: &Frequency) -> Option<DispatchScope> {
        match f {
            Frequency::Host => Some(DispatchScope::PerHost),
            Frequency::Path => Some(DispatchScope::PerPath),
            Frequency::Request => Some(DispatchScope::PerRequest),
            Frequency::InsertionPoint(_) => Some(DispatchScope::PerInsertionPoint),
            // `given response` is the passive scanner, not one of the active dispatch scopes.
            Frequency::Response => None,
        }
    }

    /// True when this engine can actually dispatch the scope today.
    ///
    /// The three unreachable scopes are defined because they are part of the recovered `Zcud`
    /// model and a reimplementation that silently omitted them would misrepresent its coverage.
    /// Nothing pretends to dispatch them: [`DispatchScope::unit_key`] returns `None`, so no work
    /// is ever admitted to them.
    pub fn is_reachable(&self) -> bool {
        matches!(
            self,
            DispatchScope::PerHost
                | DispatchScope::PerPath
                | DispatchScope::PerUrl
                | DispatchScope::PerRequest
        )
    }

    /// The key identifying one dispatch unit of this scope, or `None` when the scope is not
    /// reachable — an unreachable scope must yield no unit rather than a plausible-looking one.
    ///
    /// The keys nest: every `PerRequest` unit sits inside a `PerUrl` unit, inside a `PerPath`
    /// unit, inside a `PerHost` unit. `tls` is part of the host key because `http://h` and
    /// `https://h` are different origins and can serve different applications.
    pub fn unit_key(&self, ex: &Exchange) -> Option<String> {
        let scheme = if ex.tls { "https" } else { "http" };
        let origin = format!("{scheme}://{}:{}", ex.host, ex.port);
        // `Exchange::path` is the request target, so it carries the query string when there is
        // one. A path unit is that target with the query removed.
        let path_only = ex.path.split('?').next().unwrap_or(&ex.path);
        Some(match self {
            DispatchScope::PerHost => origin,
            DispatchScope::PerPath => format!("{origin}{path_only}"),
            DispatchScope::PerUrl => format!("{origin}{}", ex.path),
            DispatchScope::PerRequest => format!("{origin}#{}", ex.id),
            DispatchScope::InSessionPerRequest
            | DispatchScope::PerInsertionPoint
            | DispatchScope::StoredPerInsertionPoint => return None,
        })
    }

    pub fn label(&self) -> &'static str {
        match self {
            DispatchScope::PerHost => "per host",
            DispatchScope::PerPath => "per path",
            DispatchScope::PerUrl => "per URL",
            DispatchScope::PerRequest => "per request",
            DispatchScope::InSessionPerRequest => "per request, in session",
            DispatchScope::PerInsertionPoint => "per insertion point",
            DispatchScope::StoredPerInsertionPoint => "per insertion point, stored",
        }
    }
}

/// What became of one `(dispatch unit, check)` pair.
///
/// Every check considered for an item lands in exactly one of these, and the counts on
/// [`crate::AuditOutcome`] sum to the number of checks considered. That identity is what makes the
/// bound observable: three of these mean "the engine chose not to look", and no caller can mistake
/// them for a negative result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Disposition {
    /// Dispatched and completed. Its verdict is evidence.
    Ran,
    /// The evaluator declined the check — an unsupported construct, not a result.
    Unsupported,
    /// A probe could not be sent or read, so the check never saw its own response.
    SendFailed,
    /// Not admitted: an identical `(dispatch unit, check)` already ran in this session.
    AlreadyCovered,
    /// Not admitted: the wall-clock budget was spent.
    TimeBudgetSpent,
    /// Not admitted: the outbound-request budget was spent.
    RequestBudgetSpent,
    /// Not admitted: consecutive check failures abandoned the rest of this dispatch unit.
    UnitAbandoned,
    /// Not admitted: consecutive unit failures failed the whole item.
    ItemFailed,
    /// Not admitted: the session-level failure breaker paused the run before this item.
    SessionPaused,
}

impl Disposition {
    /// True when the check actually reached the target. Only these produce evidence.
    pub fn is_dispatched(&self) -> bool {
        matches!(self, Disposition::Ran | Disposition::SendFailed)
    }

    /// True when the engine declined to admit the work — the reason a clean result here would be
    /// a lie.
    pub fn stopped_looking(&self) -> bool {
        !matches!(
            self,
            Disposition::Ran | Disposition::Unsupported | Disposition::SendFailed
        )
    }

    /// One line an operator can act on.
    pub fn explanation(&self) -> &'static str {
        match self {
            Disposition::Ran => "the check ran to completion",
            Disposition::Unsupported => "the evaluator cannot run this check, so it proves nothing",
            Disposition::SendFailed => {
                "the probe could not be sent or read, so the check saw no evidence"
            }
            Disposition::AlreadyCovered => {
                "an identical check already ran against this dispatch unit"
            }
            Disposition::TimeBudgetSpent => "not started: the audit time budget was already spent",
            Disposition::RequestBudgetSpent => {
                "not started: the outbound request budget was already spent"
            }
            Disposition::UnitAbandoned => {
                "not started: too many consecutive failures on this dispatch unit"
            }
            Disposition::ItemFailed => {
                "not started: too many failing dispatch units on this request"
            }
            Disposition::SessionPaused => {
                "not started: the session was paused by the failure breaker"
            }
        }
    }
}

/// The lifecycle of one audit item — one captured exchange being audited.
///
/// This is the counterpart of Burp's `Zq5` at the level our engine actually has: `Zq5` tracks an
/// insertion point, and until insertion points exist here the item is the finest unit with a
/// lifecycle. `NON_TERMINAL_STATUSES` and `COMPLETED_AUDIT_STATUSES` have direct analogues in
/// [`ItemState::is_terminal`] and [`ItemState::completed_audit`].
///
/// [`ItemState::Pending`] and [`ItemState::Auditing`] are the two non-terminal states. Because
/// this engine resolves an item synchronously, neither is ever observed on a returned outcome —
/// they exist so [`ItemState::is_terminal`] means something, and so a future asynchronous queue
/// has the states it needs rather than inventing them later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub enum ItemState {
    /// Admitted to the session, not yet dispatched.
    #[default]
    Pending,
    /// Dispatch in progress.
    Auditing,
    /// Every check reached a disposition; the item is finished.
    Audited,
    /// A budget was spent before every check was dispatched. Not a failure, and not a clean audit
    /// either — this is precisely the distinction Burp's `LIMIT_EXCEEDED` collapses by presenting
    /// abandoned work as a finished item.
    Bounded,
    /// The item breaker tripped: too many consecutive dispatch units failed.
    Failed,
    /// The session breaker tripped before this item was reached. Nothing was sent.
    Paused,
    /// Refused before any traffic: the host is not in the engagement scope.
    OutOfScope,
    /// Nothing to audit: the exchange is missing, has no response yet, or will not parse.
    Unauditable,
}

impl ItemState {
    /// Burp's `NON_TERMINAL_STATUSES`, inverted: work is still outstanding on this item.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, ItemState::Pending | ItemState::Auditing)
    }

    /// Burp's `COMPLETED_AUDIT_STATUSES`: the item finished with no work outstanding.
    ///
    /// "No work outstanding" rather than "every check sent a request", because a check refused as
    /// [`Disposition::AlreadyCovered`] *was* run — against an earlier item covering the same
    /// dispatch unit. Counting scope collapse as incomplete would make the saving look like a
    /// coverage regression, which is backwards.
    ///
    /// Deliberately false for [`ItemState::Bounded`], [`ItemState::Failed`] and
    /// [`ItemState::Paused`]. Those items have work the engine declined and did not make up
    /// anywhere else, and treating them as audited is how a coverage claim drifts from what ran.
    pub fn completed_audit(&self) -> bool {
        matches!(self, ItemState::Audited)
    }

    /// True when checks were dispatched against this item, so its disposition counts should
    /// account for every check considered.
    pub fn dispatched(&self) -> bool {
        matches!(
            self,
            ItemState::Audited | ItemState::Bounded | ItemState::Failed
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            ItemState::Pending => "pending",
            ItemState::Auditing => "auditing",
            ItemState::Audited => "audited",
            ItemState::Bounded => "bounded",
            ItemState::Failed => "failed",
            ItemState::Paused => "paused",
            ItemState::OutOfScope => "out of scope",
            ItemState::Unauditable => "unauditable",
        }
    }
}

/// Budgets and circuit breakers for an audit run.
///
/// The four breaker fields are Burp's `scanner/error_handling/*` keys, renamed for the unit this
/// engine has (a dispatch unit, not an insertion point). `0` disables a breaker, which is how the
/// shipped *"Never stop audit due to application errors"* preset switches off task pausing while
/// leaving the per-item breakers armed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    /// Wall-clock ceiling for the whole run.
    pub time_budget: Duration,
    /// Ceiling on outbound probe requests for the whole run. `None` leaves it uncapped.
    ///
    /// Enforced at admission: once the count is reached no further check is *started*. A check
    /// already running may finish its own probes, so the true total can exceed the ceiling by one
    /// check's worth. Bounding admission is the point — a check is never killed halfway and its
    /// completed work never thrown away.
    pub max_requests: Option<u32>,
    /// Burp: `consecutive_audit_check_failures_to_skip_insertion_point`.
    pub consecutive_check_failures_to_abandon_unit: u32,
    /// Burp: `consecutive_insertion_point_failures_to_fail_audit_item`.
    pub consecutive_unit_failures_to_fail_item: u32,
    /// Burp: `pause_task_failed_audit_item_count`.
    pub pause_session_after_failed_items: u32,
    /// Burp: `pause_task_failed_audit_item_percentage`.
    pub pause_session_at_failed_item_percentage: u8,
}

/// Default wall-clock budget for one audit run.
///
/// Sized so a completely unresponsive host fails fast rather than occupying a blocking thread for
/// the product of every check and its read timeout.
pub const DEFAULT_AUDIT_BUDGET: Duration = Duration::from_secs(120);

impl Default for AuditConfig {
    /// Breaker defaults are the values every shipped preset that sets them uses: 2 and 2 for the
    /// per-item breakers, and 0 — disabled — for session pausing. Pausing a whole run is a
    /// decision an operator should opt into, not one that happens because a handful of requests
    /// timed out.
    fn default() -> Self {
        Self {
            time_budget: DEFAULT_AUDIT_BUDGET,
            max_requests: None,
            consecutive_check_failures_to_abandon_unit: 2,
            consecutive_unit_failures_to_fail_item: 2,
            pause_session_after_failed_items: 0,
            pause_session_at_failed_item_percentage: 0,
        }
    }
}

impl AuditConfig {
    /// Every breaker off. The counterpart of Burp's `Zgff` "Disable error handling" preset, which
    /// sets all five error-handling keys to 0.
    pub fn without_breakers() -> Self {
        Self {
            consecutive_check_failures_to_abandon_unit: 0,
            consecutive_unit_failures_to_fail_item: 0,
            pause_session_after_failed_items: 0,
            pause_session_at_failed_item_percentage: 0,
            ..Self::default()
        }
    }
}

/// One of Burp's shipped scan configurations, reduced to the keys this engine implements.
///
/// Burp ships 29 configurations in `resources/BuiltInConfigs/`. Six set
/// `scanner/error_handling/*` or `scanner/audit_optimization/maximum_crawl_and_audit_time`; the
/// other 23 configure crawling, insertion-point selection, parameter relocation and JavaScript
/// analysis, none of which this crate has. Those six are transcribed here and the rest are
/// omitted rather than represented by knobs that do nothing.
///
/// A field is `None` when the source file does not set the key. That is not the same as zero:
/// zero disables a breaker, absent inherits [`AuditConfig::default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInConfig {
    pub name: &'static str,
    pub consecutive_check_failures_to_abandon_unit: Option<u32>,
    pub consecutive_unit_failures_to_fail_item: Option<u32>,
    pub pause_session_after_failed_items: Option<u32>,
    /// `scanner/audit_optimization/maximum_crawl_and_audit_time`, in minutes.
    pub maximum_audit_time_minutes: Option<u32>,
}

impl BuiltInConfig {
    /// Overlay this preset's keys onto a base configuration, leaving unset keys alone.
    pub fn apply(&self, mut base: AuditConfig) -> AuditConfig {
        if let Some(v) = self.consecutive_check_failures_to_abandon_unit {
            base.consecutive_check_failures_to_abandon_unit = v;
        }
        if let Some(v) = self.consecutive_unit_failures_to_fail_item {
            base.consecutive_unit_failures_to_fail_item = v;
        }
        if let Some(v) = self.pause_session_after_failed_items {
            base.pause_session_after_failed_items = v;
        }
        if let Some(m) = self.maximum_audit_time_minutes {
            base.time_budget = Duration::from_secs(u64::from(m) * 60);
        }
        base
    }
}

/// The six shipped configurations that set a key this engine implements.
///
/// Transcribed from `resources/BuiltInConfigs/*.json` in the Burp Suite 2026.7.1 jar. None of them
/// sets `pause_task_failed_audit_item_percentage`, so no preset here carries one.
pub const BUILT_IN_CONFIGS: &[BuiltInConfig] = &[
    BuiltInConfig {
        name: "Crawl and Audit - Balanced",
        consecutive_check_failures_to_abandon_unit: Some(2),
        consecutive_unit_failures_to_fail_item: Some(2),
        pause_session_after_failed_items: None,
        maximum_audit_time_minutes: None,
    },
    BuiltInConfig {
        name: "Crawl and Audit - CICD Optimized",
        consecutive_check_failures_to_abandon_unit: Some(2),
        consecutive_unit_failures_to_fail_item: Some(2),
        pause_session_after_failed_items: Some(0),
        maximum_audit_time_minutes: Some(15),
    },
    BuiltInConfig {
        name: "Crawl and Audit - Deep",
        consecutive_check_failures_to_abandon_unit: Some(2),
        consecutive_unit_failures_to_fail_item: Some(2),
        pause_session_after_failed_items: Some(0),
        maximum_audit_time_minutes: None,
    },
    BuiltInConfig {
        name: "Crawl and Audit - Fast",
        consecutive_check_failures_to_abandon_unit: Some(2),
        consecutive_unit_failures_to_fail_item: Some(2),
        pause_session_after_failed_items: None,
        maximum_audit_time_minutes: None,
    },
    BuiltInConfig {
        name: "Crawl and Audit - Lightweight",
        consecutive_check_failures_to_abandon_unit: Some(2),
        consecutive_unit_failures_to_fail_item: Some(2),
        pause_session_after_failed_items: Some(0),
        maximum_audit_time_minutes: Some(15),
    },
    BuiltInConfig {
        name: "Never stop audit due to application errors",
        consecutive_check_failures_to_abandon_unit: Some(2),
        consecutive_unit_failures_to_fail_item: Some(2),
        pause_session_after_failed_items: Some(0),
        maximum_audit_time_minutes: None,
    },
];

/// Look up a shipped configuration by its exact name.
pub fn built_in_config(name: &str) -> Option<&'static BuiltInConfig> {
    BUILT_IN_CONFIGS.iter().find(|c| c.name == name)
}

/// Which `(dispatch unit, check)` pairs have already been audited.
///
/// This is the admission bound made concrete. It holds one key per dispatch unit and one bit per
/// check, so remembering that all 127 active checks ran against a host costs the host string plus
/// sixteen bytes — not a retained copy of the work. Exact, not probabilistic: a hash-only ledger
/// would occasionally collide and skip a check, and a silently skipped check in a security scanner
/// is a false negative nobody can see.
#[derive(Debug, Clone, Default)]
pub struct AuditLedger {
    done: HashMap<String, Vec<u64>>,
    admitted: usize,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit `check` against `unit`, returning `false` if that pair already ran.
    pub fn admit(&mut self, unit: &str, check: usize) -> bool {
        let (word, bit) = (check / 64, check % 64);
        let bits = match self.done.get_mut(unit) {
            Some(b) => b,
            None => self.done.entry(unit.to_string()).or_default(),
        };
        if bits.len() <= word {
            bits.resize(word + 1, 0);
        }
        let mask = 1u64 << bit;
        if bits[word] & mask != 0 {
            return false;
        }
        bits[word] |= mask;
        self.admitted += 1;
        true
    }

    /// Distinct dispatch units seen.
    pub fn units(&self) -> usize {
        self.done.len()
    }

    /// Total pairs admitted — the amount of work this ledger has let through.
    pub fn admitted(&self) -> usize {
        self.admitted
    }
}

/// The two-level failure model from `scanner/error_handling/*`, as a value that can be stepped.
///
/// Level one: N consecutive check failures abandon the rest of the dispatch unit. Level two: N
/// consecutive unit failures fail the item. The session-level count/percentage breaker lives on
/// [`SessionBreaker`] because it spans items.
#[derive(Debug, Clone)]
pub(crate) struct ItemBreaker {
    abandon_unit_after: u32,
    fail_item_after: u32,
    consecutive_check_failures: u32,
    consecutive_unit_failures: u32,
    item_failed: bool,
}

impl ItemBreaker {
    pub(crate) fn new(cfg: &AuditConfig) -> Self {
        Self {
            abandon_unit_after: cfg.consecutive_check_failures_to_abandon_unit,
            fail_item_after: cfg.consecutive_unit_failures_to_fail_item,
            consecutive_check_failures: 0,
            consecutive_unit_failures: 0,
            item_failed: false,
        }
    }

    /// A check completed without a transport failure.
    pub(crate) fn check_succeeded(&mut self) {
        self.consecutive_check_failures = 0;
    }

    /// A check's probe could not be sent. Returns true when the rest of the unit is abandoned.
    pub(crate) fn check_failed(&mut self) -> bool {
        self.consecutive_check_failures += 1;
        self.abandon_unit_after > 0 && self.consecutive_check_failures >= self.abandon_unit_after
    }

    /// A dispatch unit finished. Returns true when the item is failed.
    pub(crate) fn unit_finished(&mut self, abandoned: bool) -> bool {
        self.consecutive_check_failures = 0;
        if abandoned {
            self.consecutive_unit_failures += 1;
        } else {
            self.consecutive_unit_failures = 0;
        }
        if self.fail_item_after > 0 && self.consecutive_unit_failures >= self.fail_item_after {
            self.item_failed = true;
        }
        self.item_failed
    }

    pub(crate) fn item_failed(&self) -> bool {
        self.item_failed
    }
}

/// The session-level breaker: `pause_task_failed_audit_item_count` and `…_percentage`.
#[derive(Debug, Clone)]
pub(crate) struct SessionBreaker {
    after_count: u32,
    at_percentage: u8,
    failed: u32,
    finished: u32,
}

impl SessionBreaker {
    pub(crate) fn new(cfg: &AuditConfig) -> Self {
        Self {
            after_count: cfg.pause_session_after_failed_items,
            at_percentage: cfg.pause_session_at_failed_item_percentage,
            failed: 0,
            finished: 0,
        }
    }

    /// Record an item's outcome. Returns true once the session should pause.
    pub(crate) fn item_finished(&mut self, failed: bool) -> bool {
        self.finished += 1;
        if failed {
            self.failed += 1;
        }
        self.tripped()
    }

    pub(crate) fn tripped(&self) -> bool {
        if self.after_count > 0 && self.failed >= self.after_count {
            return true;
        }
        if self.at_percentage > 0 && self.finished > 0 {
            let pct = self.failed as u64 * 100 / self.finished as u64;
            return pct >= u64::from(self.at_percentage);
        }
        false
    }

    pub(crate) fn failed_items(&self) -> u32 {
        self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_bcheck::ast::IpType;

    fn exchange(id: u64, host: &str, path: &str, tls: bool) -> Exchange {
        Exchange {
            id,
            request: burpsy_core::MsgId(0),
            response: None,
            host: host.into(),
            port: if tls { 443 } else { 80 },
            tls,
            method: "GET".into(),
            path: path.into(),
            status: Some(200),
            response_len: 0,
            started_ms: 0,
            duration_ms: 0,
            notes: None,
        }
    }

    #[test]
    fn bcheck_given_clauses_reach_four_of_the_seven_dispatch_scopes() {
        assert_eq!(
            DispatchScope::from_frequency(&Frequency::Host),
            Some(DispatchScope::PerHost)
        );
        assert_eq!(
            DispatchScope::from_frequency(&Frequency::Path),
            Some(DispatchScope::PerPath)
        );
        assert_eq!(
            DispatchScope::from_frequency(&Frequency::Request),
            Some(DispatchScope::PerRequest)
        );
        assert_eq!(
            DispatchScope::from_frequency(&Frequency::InsertionPoint(vec![IpType::Any])),
            Some(DispatchScope::PerInsertionPoint)
        );
        // `given response` is passive; it is not an active dispatch scope at all.
        assert_eq!(DispatchScope::from_frequency(&Frequency::Response), None);
    }

    #[test]
    fn the_three_unreachable_scopes_yield_no_dispatch_unit() {
        let ex = exchange(1, "a.test", "/x", true);
        let reachable: Vec<_> = DispatchScope::ALL
            .iter()
            .filter(|s| s.is_reachable())
            .collect();
        assert_eq!(reachable.len(), 4, "four of seven are wired up");
        for s in DispatchScope::ALL {
            // Nothing can be admitted to a scope with no key, so an unreachable scope cannot
            // quietly appear to have been audited.
            assert_eq!(
                s.unit_key(&ex).is_some(),
                s.is_reachable(),
                "{} disagrees with its own reachability",
                s.label()
            );
        }
    }

    #[test]
    fn dispatch_unit_keys_nest_from_host_down_to_request() {
        let a = exchange(1, "a.test", "/shop/item?id=1", true);
        let b = exchange(2, "a.test", "/shop/item?id=2", true);
        let k = |s: DispatchScope, e: &Exchange| s.unit_key(e).unwrap();

        // Same host, same path, different query, different request.
        assert_eq!(k(DispatchScope::PerHost, &a), k(DispatchScope::PerHost, &b));
        assert_eq!(k(DispatchScope::PerPath, &a), k(DispatchScope::PerPath, &b));
        assert_ne!(k(DispatchScope::PerUrl, &a), k(DispatchScope::PerUrl, &b));
        assert_ne!(
            k(DispatchScope::PerRequest, &a),
            k(DispatchScope::PerRequest, &b)
        );

        assert_eq!(k(DispatchScope::PerHost, &a), "https://a.test:443");
        assert_eq!(
            k(DispatchScope::PerPath, &a),
            "https://a.test:443/shop/item"
        );
        assert_eq!(
            k(DispatchScope::PerUrl, &a),
            "https://a.test:443/shop/item?id=1"
        );
    }

    #[test]
    fn plaintext_and_tls_on_one_hostname_are_different_dispatch_units() {
        // Different origins can serve different applications, so auditing one must not mark the
        // other as covered.
        let plain = exchange(1, "a.test", "/", false);
        let tls = exchange(2, "a.test", "/", true);
        assert_ne!(
            DispatchScope::PerHost.unit_key(&plain),
            DispatchScope::PerHost.unit_key(&tls)
        );
    }

    #[test]
    fn the_ledger_admits_a_pair_once_and_refuses_the_repeat() {
        let mut l = AuditLedger::new();
        assert!(l.admit("https://a.test:443", 0));
        assert!(
            !l.admit("https://a.test:443", 0),
            "the same pair must not be admitted twice"
        );
        assert!(
            l.admit("https://a.test:443", 1),
            "a different check is a different pair"
        );
        assert!(
            l.admit("https://b.test:443", 0),
            "a different unit is a different pair"
        );
        assert_eq!(l.units(), 2);
        assert_eq!(l.admitted(), 3);
    }

    #[test]
    fn the_ledger_tracks_check_indices_beyond_one_bitmap_word() {
        let mut l = AuditLedger::new();
        for i in [0usize, 63, 64, 126, 127] {
            assert!(l.admit("u", i), "check {i} should be new");
        }
        for i in [0usize, 63, 64, 126, 127] {
            assert!(!l.admit("u", i), "check {i} should be a repeat");
        }
        assert_eq!(l.admitted(), 5);
        assert_eq!(l.units(), 1);
    }

    #[test]
    fn two_consecutive_check_failures_abandon_the_unit_and_two_units_fail_the_item() {
        let mut b = ItemBreaker::new(&AuditConfig::default());
        assert!(!b.check_failed(), "one failure is not enough");
        assert!(
            b.check_failed(),
            "the second consecutive failure abandons the unit"
        );
        assert!(
            !b.unit_finished(true),
            "one abandoned unit is not enough to fail the item"
        );
        assert!(!b.check_failed());
        assert!(b.check_failed());
        assert!(
            b.unit_finished(true),
            "the second abandoned unit fails the item"
        );
        assert!(b.item_failed());
    }

    #[test]
    fn a_success_between_failures_resets_the_unit_breaker() {
        let mut b = ItemBreaker::new(&AuditConfig::default());
        assert!(!b.check_failed());
        b.check_succeeded();
        assert!(
            !b.check_failed(),
            "the streak restarted, so this is failure one again"
        );
        assert!(b.check_failed());
    }

    #[test]
    fn a_healthy_unit_resets_the_item_breaker() {
        let mut b = ItemBreaker::new(&AuditConfig::default());
        assert!(!b.unit_finished(true));
        assert!(!b.unit_finished(false), "a good unit clears the streak");
        assert!(
            !b.unit_finished(true),
            "so this is abandoned unit one again"
        );
        assert!(b.unit_finished(true));
    }

    #[test]
    fn zero_disables_a_breaker_as_the_shipped_never_stop_preset_does() {
        let mut b = ItemBreaker::new(&AuditConfig::without_breakers());
        for _ in 0..50 {
            assert!(
                !b.check_failed(),
                "with the breaker off no failure count abandons the unit"
            );
        }
        for _ in 0..50 {
            assert!(!b.unit_finished(true));
        }
        assert!(!b.item_failed());
    }

    #[test]
    fn the_session_breaker_is_off_by_default_and_trips_on_a_count_when_armed() {
        let mut off = SessionBreaker::new(&AuditConfig::default());
        for _ in 0..100 {
            assert!(!off.item_finished(true), "pausing a run must be opted into");
        }
        assert_eq!(off.failed_items(), 100);

        let cfg = AuditConfig {
            pause_session_after_failed_items: 3,
            ..AuditConfig::default()
        };
        let mut armed = SessionBreaker::new(&cfg);
        assert!(!armed.item_finished(true));
        assert!(!armed.item_finished(false));
        assert!(!armed.item_finished(true));
        assert!(
            armed.item_finished(true),
            "the third failed item trips the count breaker"
        );
    }

    #[test]
    fn the_session_breaker_trips_on_a_percentage_when_armed() {
        let cfg = AuditConfig {
            pause_session_at_failed_item_percentage: 50,
            ..AuditConfig::default()
        };
        let mut b = SessionBreaker::new(&cfg);
        assert!(b.item_finished(true), "1 of 1 failed is 100%");

        let mut b = SessionBreaker::new(&cfg);
        assert!(!b.item_finished(false));
        assert!(!b.item_finished(false));
        assert!(!b.item_finished(false));
        assert!(!b.item_finished(true), "1 of 4 is 25%");
        assert!(!b.item_finished(false));
        assert!(!b.item_finished(true), "2 of 6 is 33%");
        assert!(!b.item_finished(true), "3 of 7 is 42%");
        assert!(b.item_finished(true), "4 of 8 is 50%");
    }

    #[test]
    fn built_in_presets_overlay_only_the_keys_their_source_file_sets() {
        let lightweight = built_in_config("Crawl and Audit - Lightweight").unwrap();
        let cfg = lightweight.apply(AuditConfig::default());
        assert_eq!(
            cfg.time_budget,
            Duration::from_secs(15 * 60),
            "maximum_crawl_and_audit_time"
        );
        assert_eq!(cfg.consecutive_check_failures_to_abandon_unit, 2);
        assert_eq!(cfg.pause_session_after_failed_items, 0);

        // Balanced sets neither the pause count nor a time limit, so both keep the default —
        // an absent key is not a zero.
        let balanced = built_in_config("Crawl and Audit - Balanced").unwrap();
        let cfg = balanced.apply(AuditConfig::default());
        assert_eq!(
            cfg.time_budget, DEFAULT_AUDIT_BUDGET,
            "absent key must not become zero"
        );
        assert_eq!(cfg.consecutive_unit_failures_to_fail_item, 2);

        assert_eq!(
            BUILT_IN_CONFIGS.len(),
            6,
            "of Burp's 29 shipped configurations"
        );
        assert!(built_in_config("Crawl and Audit - Nonexistent").is_none());
    }

    #[test]
    fn every_disposition_is_either_evidence_or_an_admitted_reason_to_distrust_a_clean_result() {
        let all = [
            Disposition::Ran,
            Disposition::Unsupported,
            Disposition::SendFailed,
            Disposition::AlreadyCovered,
            Disposition::TimeBudgetSpent,
            Disposition::RequestBudgetSpent,
            Disposition::UnitAbandoned,
            Disposition::ItemFailed,
            Disposition::SessionPaused,
        ];
        // Only `Ran` is a trustworthy negative result. Everything else either did not reach the
        // target or did not prove anything, and says so.
        assert_eq!(all.iter().filter(|d| !d.stopped_looking()).count(), 3);
        assert_eq!(all.iter().filter(|d| d.is_dispatched()).count(), 2);
        assert!(Disposition::AlreadyCovered.stopped_looking());
        assert!(!Disposition::Ran.stopped_looking());
        assert!(all.iter().all(|d| !d.explanation().is_empty()));
    }

    #[test]
    fn only_a_fully_audited_item_counts_as_completed() {
        assert!(ItemState::Audited.completed_audit());
        // A bounded, failed or paused item is finished but not audited. Counting any of them as
        // audited is how a coverage number stops meaning anything.
        for s in [
            ItemState::Bounded,
            ItemState::Failed,
            ItemState::Paused,
            ItemState::OutOfScope,
            ItemState::Unauditable,
        ] {
            assert!(s.is_terminal(), "{} should be terminal", s.label());
            assert!(
                !s.completed_audit(),
                "{} must not count as audited",
                s.label()
            );
        }
        assert!(!ItemState::Pending.is_terminal());
        assert!(!ItemState::Auditing.is_terminal());
        // Dispatched states are the ones whose disposition counts must cover the whole check set.
        assert!(ItemState::Audited.dispatched());
        assert!(ItemState::Bounded.dispatched());
        assert!(ItemState::Failed.dispatched());
        assert!(!ItemState::OutOfScope.dispatched());
        assert!(!ItemState::Paused.dispatched());
    }
}
