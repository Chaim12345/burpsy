//! Runtime coverage for the passive check set: which checks actually ran, and for the ones that
//! did not, why.
//!
//! # The gap this closes
//!
//! [`crate::PassiveScanner::scan_message`] must not let one bad check silence the rest — a Java-only
//! regex construct in check #40 cannot be allowed to stop checks #41 through #105 from running. That
//! `continue`-past-an-error behaviour is correct and stays exactly as it was. What was missing is that
//! nothing counted it: a check erroring on every single response was indistinguishable, from the
//! outside, from a check that ran cleanly and never fired. [`CoverageTracker`] is the record that makes
//! the two distinguishable.
//!
//! # Why per-check identity, not just a count
//!
//! "26 checks never ran" tells an operator nothing they can act on. "These 26, because their regex
//! does not compile in this engine" does. [`LoadReport`](crate::LoadReport) already has the weaker
//! shape — counts only, identities dropped at classification time — and repeating that here would
//! throw away the same information a second time.
//!
//! # Why the default is "not run", never "ran"
//!
//! [`CheckCoverage::default`] has every counter at zero, which [`CheckCoverage::state`] reads as
//! [`CoverageState::NeverDispatched`]. A record only leaves that state when [`CoverageTracker::record_scan`]
//! is actually called with evidence for it — a check is never assumed to have run just because it was
//! loaded. That is the fail-safe direction: an instrumentation bug that forgets to wire a call site
//! leaves that check looking unknown, not clean.
//!
//! # Why one lock per scan, not one per check
//!
//! [`PassiveScanner`](crate::PassiveScanner) is held behind an `Arc` and scanned from multiple
//! off-hot-path tasks concurrently, so the per-check table is behind a [`parking_lot::RwLock`]. Taking
//! that lock once per check, per response, would mean 105 lock acquisitions for one proxied response.
//! Instead [`crate::PassiveScanner::scan_message`] evaluates every check against its local `deltas`
//! buffer first — plain stack/heap memory, no lock involved — and [`CoverageTracker::record_scan`]
//! takes the write lock exactly once to fold the whole buffer in.

use std::sync::atomic::{AtomicU64, Ordering};

use burpsy_bcheck::Check;
use parking_lot::RwLock;

/// Why [`crate::PassiveScanner::scan`] returned before any check even got a chance to run.
///
/// Each of these used to collapse into a return of `0`, the same value a response that was genuinely
/// scanned and found clean produces. That collapse is the defect this type exists to name: a caller
/// reading only the return value cannot tell "scanned, clean" from "never looked".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ScanSkip {
    /// No passive checks are loaded, so there was nothing to run regardless of the exchange.
    NoChecksLoaded,
    /// `exchange_id` is not in the store.
    ExchangeNotFound,
    /// The exchange's host/port/path/TLS falls outside the engagement scope.
    OutOfScope,
    /// `response_id` is not in the store.
    ResponseNotFound,
}

impl ScanSkip {
    /// All four, in the order [`crate::PassiveScanner::scan`] tests them — so a caller iterating this
    /// array sees skips in the same order the early returns would fire.
    pub const ALL: [ScanSkip; 4] = [
        ScanSkip::NoChecksLoaded,
        ScanSkip::ExchangeNotFound,
        ScanSkip::OutOfScope,
        ScanSkip::ResponseNotFound,
    ];

    /// One line an operator can act on.
    pub fn explanation(&self) -> &'static str {
        match self {
            ScanSkip::NoChecksLoaded => "no passive checks are loaded",
            ScanSkip::ExchangeNotFound => "the exchange id is not in the store",
            ScanSkip::OutOfScope => "the host is outside the engagement scope",
            ScanSkip::ResponseNotFound => "the response id is not in the store",
        }
    }

    /// Position in [`ScanSkip::ALL`], and the matching slot in [`CoverageTracker::skips`]. A plain
    /// `match` rather than `ALL.iter().position(..)`: the mapping must be total and exhaustive at
    /// compile time, not discovered by a runtime search that could come back empty.
    fn slot(&self) -> usize {
        match self {
            ScanSkip::NoChecksLoaded => 0,
            ScanSkip::ExchangeNotFound => 1,
            ScanSkip::OutOfScope => 2,
            ScanSkip::ResponseNotFound => 3,
        }
    }
}

/// The bucket a reporting caller should actually show for one check, collapsed from the raw counters
/// on [`CheckCoverage`].
///
/// Erroring beats a clean run: a check that errored on some responses and ran cleanly on others is
/// [`CoverageState::Errored`], not [`CoverageState::RanClean`]. A partly-broken check is not a
/// trustworthy negative result, and picking whichever counter is larger would let one clean response
/// paper over ninety-nine broken ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CoverageState {
    /// No evidence this check was ever handed a response.
    NeverDispatched,
    /// Ran at least once, never errored, and never produced a finding.
    RanClean,
    /// Ran at least once, never errored, and produced at least one finding.
    RanAndFound,
    /// Errored at least once. [`CheckCoverage::errored`] and [`CheckCoverage::last_error`] carry the
    /// detail.
    Errored,
}

impl CoverageState {
    /// All four, so a caller can build a histogram without hard-coding which states exist —
    /// mirrors [`crate::audit::Disposition`]'s exhaustive array for the same reason.
    pub const ALL: [CoverageState; 4] = [
        CoverageState::NeverDispatched,
        CoverageState::RanClean,
        CoverageState::RanAndFound,
        CoverageState::Errored,
    ];
}

/// Runtime evidence for one loaded passive check.
///
/// Defaults to all-zero / `None`, which [`CheckCoverage::state`] reads as
/// [`CoverageState::NeverDispatched`] — the safe direction, covered in the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct CheckCoverage {
    pub name: String,
    /// Responses this check evaluated without erroring, whether or not it found anything.
    pub ran: u64,
    /// Findings produced across every response in `ran`. Can exceed `ran`: one response can carry
    /// more than one match.
    pub findings: u64,
    /// Responses where the evaluator returned an error instead of a verdict. Kept as its own counter
    /// rather than folded into `ran`, because a check erroring on every response must never be read as
    /// having run cleanly.
    pub errored: u64,
    /// The most recently observed runtime error. `Some` exactly when `errored > 0`.
    pub last_error: Option<String>,
}

impl CheckCoverage {
    /// Collapse the raw counters into the bucket a caller should render. See
    /// [`CoverageState`] for why `errored` takes priority over a nonzero `ran`.
    pub fn state(&self) -> CoverageState {
        if self.errored > 0 {
            CoverageState::Errored
        } else if self.ran == 0 {
            CoverageState::NeverDispatched
        } else if self.findings > 0 {
            CoverageState::RanAndFound
        } else {
            CoverageState::RanClean
        }
    }
}

/// An owned, point-in-time snapshot of every loaded passive check's runtime coverage, plus how many
/// times [`crate::PassiveScanner::scan`] returned before any check ran.
///
/// Owned rather than a lock guard, so a later reporting crate can hold this after the call returns
/// instead of holding [`crate::PassiveScanner`] locked while it renders — the same shape as
/// [`crate::PassiveScanner::report`] and [`crate::PassiveScanner::findings`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct CoverageReport {
    /// One entry per loaded passive check, in load order.
    pub checks: Vec<CheckCoverage>,
    /// Exchange-level skips, one count per [`ScanSkip`] reason.
    pub skips: Vec<(ScanSkip, u64)>,
}

impl CoverageReport {
    /// How many loaded checks are in `state`.
    pub fn count(&self, state: CoverageState) -> usize {
        self.checks.iter().filter(|c| c.state() == state).count()
    }

    /// The full state histogram over every loaded check.
    ///
    /// A **tested invariant**: summing this must equal the number of loaded checks. [`CheckCoverage::state`]
    /// is meant to be exhaustive — every check lands in exactly one bucket — and this is what lets a
    /// test catch a future state added to [`CoverageState`] without being wired into that
    /// classification, rather than that gap silently under-reporting coverage.
    pub fn partition(&self) -> [(CoverageState, usize); 4] {
        CoverageState::ALL.map(|st| (st, self.count(st)))
    }
}

/// The mutable coverage table [`crate::PassiveScanner`] holds behind an `Arc`.
///
/// Crate-private: [`crate::PassiveScanner::coverage`] is the only way in, returning an owned
/// [`CoverageReport`] rather than exposing the lock.
pub(crate) struct CoverageTracker {
    per_check: RwLock<Vec<CheckCoverage>>,
    /// Indexed by [`ScanSkip::slot`]. Plain atomics rather than a lock: each early return in `scan`
    /// increments exactly one counter and nothing else, so there is no batch to fold in the way
    /// `record_scan` folds a whole check set.
    skips: [AtomicU64; 4],
}

impl CoverageTracker {
    /// One record per check, named and zeroed, in the same order as the passive check set — so a
    /// check's position here always matches its position in `deltas` passed to
    /// [`CoverageTracker::record_scan`].
    pub(crate) fn new(checks: &[Check]) -> Self {
        let per_check = checks
            .iter()
            .map(|c| CheckCoverage {
                name: c.metadata.name.clone(),
                ..Default::default()
            })
            .collect();
        Self {
            per_check: RwLock::new(per_check),
            skips: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Record one whole-exchange skip. Relaxed ordering: this is an independent counter with no other
    /// memory it needs to stay ordered against.
    pub(crate) fn record_skip(&self, why: ScanSkip) {
        self.skips[why.slot()].fetch_add(1, Ordering::Relaxed);
    }

    /// Fold one scan's worth of per-check outcomes into the table in a single write-lock acquisition.
    ///
    /// `deltas` is index-aligned with the passive check set: `Ok(n)` means the check ran and produced
    /// `n` findings (`0` is a clean run, not an error); `Err(msg)` means it errored this time.
    pub(crate) fn record_scan(&self, deltas: &[Result<u64, String>]) {
        let mut recs = self.per_check.write();
        for (rec, delta) in recs.iter_mut().zip(deltas) {
            match delta {
                Ok(findings) => {
                    rec.ran += 1;
                    rec.findings += findings;
                }
                Err(msg) => {
                    rec.errored += 1;
                    rec.last_error = Some(msg.clone());
                }
            }
        }
    }

    /// An owned copy of the current table, for [`crate::PassiveScanner::coverage`].
    pub(crate) fn snapshot(&self) -> CoverageReport {
        let checks = self.per_check.read().clone();
        let skips = ScanSkip::ALL
            .iter()
            .map(|s| (*s, self.skips[s.slot()].load(Ordering::Relaxed)))
            .collect();
        CoverageReport { checks, skips }
    }
}
