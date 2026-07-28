//! Report serialisation: HTML for a human, JSON for a machine, SARIF for a code-scanning consumer.
//!
//! # What this module is for
//!
//! Three renderings of one model. The model is [`RunCoverage`], and the reason it comes first is
//! success criterion 3: *a zero-finding report must enumerate what did not run and why, so a clean
//! report cannot be mistaken for full coverage.* The findings list is the easy part — every scanner
//! can print findings. The part that is normally missing, and the part this module exists for, is the
//! statement of what was **not** checked.
//!
//! # Why the coverage model is composed, never counted afresh
//!
//! Every number here is read off something that already exists:
//!
//! | Question | Source |
//! |---|---|
//! | What was loaded, and what could not be? | [`crate::LoadReport`] |
//! | Which passive checks actually ran, errored, or never ran? | [`crate::CoverageReport`] |
//! | Why did the engine decline active work? | [`crate::AuditOutcome::dispositions`] |
//!
//! A second set of counters maintained by the reporter would be a parallel mechanism, and a parallel
//! mechanism is how a coverage claim drifts from what the code did: the report would keep saying
//! "everything ran" long after the engine stopped running it. So this module owns no counters. It
//! owns a *classification* — which of those existing numbers mean "checked", which mean "declined",
//! and which mean "not known" — plus the three writers.
//!
//! # The default is "not checked"
//!
//! [`RunFacts::audits`] being empty does not mean the active check set came back clean; it means no
//! audit ran, and that is what the report says. The same inversion runs through the whole model: a
//! population with no evidence reports as unchecked, never as clean. A builder that started from
//! "ran" and demoted on failure would behave identically on the happy path and wrongly on every path
//! that matters.
//!
//! # Why there is no coverage percentage
//!
//! A percentage needs one denominator, and there is no single population here. Loaded passive checks
//! (one entry per check) and active check *dispatches* (one entry per `(item, check)` pair) are
//! different units, and the corpus buckets are a third. Summing them for a headline figure would
//! produce a number whose meaning changes with the shape of the run, and every plausible way to make
//! it look tidy — dropping the skipped buckets from the denominator being the obvious one — inflates
//! it. The report therefore states counts per population and never divides them.
//!
//! # Why this lives in `scanner` and pulls in `serde_json`
//!
//! The coverage model names [`crate::Disposition`], [`crate::ScanSkip`] and [`crate::LoadReport`] by
//! type. Declaring the reasons as strings somewhere else would let them drift from the engine's
//! actual dispositions with no compile error, which is precisely the failure this module is built to
//! prevent, so it lives beside them.
//!
//! That costs a `serde_json` dependency in a crate that had none. Taken deliberately, in preference
//! to hand-rolling a JSON encoder: this crate already declines to hand-roll an HTML parser
//! ([`crate::catalog`]) for the same reason, and a bespoke string escaper in the one output a
//! machine consumer parses is a worse trade than a dependency the workspace already builds. HTML is
//! still hand-rolled — see [`html`] for why escaping there is a security control rather than
//! formatting, and why a template engine's guarantees are the wrong thing to take on trust.

pub mod html;
pub mod json;
pub mod sarif;

use crate::{AuditOutcome, CoverageState, Disposition, ItemState, LoadReport, ScanSkip};
use burpsy_core::{Finding, Scope, ScopeRule, RuleKind, Severity};

/// Tool name, as it appears in every format.
pub const TOOL_NAME: &str = "burpsy";

/// Tool version, from the crate's own manifest so it cannot drift from the build.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Everything a report is built from.
///
/// A named-field struct rather than six positional arguments: `&LoadReport` and `&CoverageReport`
/// are both "the coverage inputs" to a reader and transposing them would compile in some orderings.
pub struct RunFacts<'a> {
    /// The engagement scope. A coverage claim without its scope is not a claim about anything.
    pub scope: &'a Scope,
    /// Load-time classification of the check corpus.
    pub load: &'a LoadReport,
    /// Runtime evidence from the passive path.
    pub passive: &'a crate::CoverageReport,
    /// Every audit session whose outcomes this report covers.
    ///
    /// **Empty means no audit ran.** It is not an active check set that came back clean, and the
    /// report says so — see [`NeverRunReason::NoAuditRequested`].
    pub audits: &'a [crate::SessionOutcome],
    /// The findings, in the order [`burpsy_core::FindingStore::all`] returns them (most severe
    /// first). The writers preserve that order rather than re-sorting.
    pub findings: &'a [Finding],
    /// Generation time in Unix milliseconds. Passed in rather than read from the clock here so a
    /// test can pin it and diff a whole document.
    pub generated_unix_ms: u64,
}

/// A finished report: the coverage statement plus the findings it qualifies.
///
/// Owned, so the writers can run after every lock in the scanner has been released.
#[derive(Debug, Clone)]
pub struct Report {
    pub generated_unix_ms: u64,
    pub scope: ScopeStatement,
    pub coverage: RunCoverage,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn from_facts(f: RunFacts<'_>) -> Self {
        Self {
            generated_unix_ms: f.generated_unix_ms,
            scope: ScopeStatement::from_scope(f.scope),
            coverage: RunCoverage::compose(f.load, f.passive, f.audits),
            findings: f.findings.to_vec(),
        }
    }

    /// Findings by severity, in the order [`burpsy_core::FindingStore::severity_counts`] uses:
    /// high, medium, low, info.
    pub fn severity_counts(&self) -> [usize; 4] {
        let mut c = [0usize; 4];
        for f in &self.findings {
            let i = match f.severity {
                Severity::High => 0,
                Severity::Medium => 1,
                Severity::Low => 2,
                Severity::Info => 3,
            };
            c[i] += 1;
        }
        c
    }

    /// The verdict every format leads with.
    ///
    /// Derived from the counters rather than stored, so it cannot disagree with the table below it.
    /// The findings count is part of the input because "clean" is a claim about findings *and*
    /// coverage: a fully-checked run with findings is complete but not clean, and a zero-finding run
    /// with declined work is neither.
    pub fn verdict(&self) -> Verdict {
        self.coverage.verdict(self.findings.len())
    }

    /// Generation time as an RFC 3339 UTC timestamp.
    pub fn generated_at(&self) -> String {
        rfc3339_utc_millis(self.generated_unix_ms)
    }
}

/// The scope a coverage claim is scoped to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeStatement {
    /// True when the scope was explicitly set to allow everything. Reported because it changes what
    /// the rest of the report means: nothing was excluded, so nothing was skipped for being out of
    /// scope.
    pub allow_all: bool,
    /// One human-readable line per rule, include and exclude alike.
    pub rules: Vec<String>,
}

impl ScopeStatement {
    pub fn from_scope(s: &Scope) -> Self {
        Self {
            allow_all: s.allow_all,
            rules: s.rules.iter().map(describe_rule).collect(),
        }
    }

    /// One sentence for a report header.
    pub fn summary(&self) -> String {
        if self.allow_all {
            return "every host (scope set to allow everything)".to_owned();
        }
        if self.rules.is_empty() {
            return "no scope rules: nothing is in scope, so nothing was scanned".to_owned();
        }
        self.rules.join("; ")
    }
}

fn describe_rule(r: &ScopeRule) -> String {
    let mut s = String::new();
    s.push_str(match r.kind {
        RuleKind::Include => "include ",
        RuleKind::Exclude => "exclude ",
    });
    s.push_str(r.host.as_deref().unwrap_or("any host"));
    if let Some(p) = r.port {
        s.push_str(&format!(":{p}"));
    }
    if let Some(p) = &r.path_prefix {
        s.push(' ');
        s.push_str(p);
        s.push('*');
    }
    match r.tls {
        Some(true) => s.push_str(" (https only)"),
        Some(false) => s.push_str(" (http only)"),
        None => {}
    }
    s
}

/// The unit a not-checked count is measured in.
///
/// Present so the counts are never added together. "26 checks were not loaded", "18 check dispatches
/// were declined", "1 audit item was refused before any check ran" and "4 responses were never
/// scanned" are four different statements, and one total over them would be a number with no meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Loaded checks, counted once each.
    Checks,
    /// `(audit item, check)` pairs. One check audited against ten items is ten dispatches.
    Dispatches,
    /// Whole audit items — one captured exchange each — refused before any check was admitted.
    Items,
    /// Captured responses handed to the passive path.
    Responses,
    /// Individual places in a request the insertion-point enumerator declined to build a point
    /// for. Its own unit rather than folded into [`Unit::Dispatches`]: a check with three header
    /// points and one declined body dispatches once — that dispatch is `Ran` — but declines one
    /// place, and summing the two together would conflate "the check ran" with "everything the
    /// check asked to test was covered".
    InsertionPoints,
}

impl Unit {
    pub fn id(&self) -> &'static str {
        match self {
            Unit::Checks => "checks",
            Unit::Dispatches => "dispatches",
            Unit::Items => "audit_items",
            Unit::Responses => "responses",
            Unit::InsertionPoints => "insertion_points",
        }
    }

    /// True when a non-zero count in this unit means work the operator asked for was not done.
    ///
    /// [`Unit::Responses`] is excluded: the dominant reason a response is skipped is that its host is
    /// out of scope, which is the operator's own instruction rather than an incomplete scan. The
    /// counts are still reported — they are simply not what decides the verdict, and the scope
    /// statement in every format's header is where that limit belongs.
    pub fn decides_the_verdict(&self) -> bool {
        !matches!(self, Unit::Responses)
    }
}

/// Which load-time bucket a check fell out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBucket {
    /// Needs an interaction (Collaborator) server, which this build does not have.
    Collaborator,
    /// Needs payload placement into an insertion point.
    NeedsInsertionPoint,
    /// Did not parse.
    Unparsable,
}

impl LoadBucket {
    pub fn id(&self) -> &'static str {
        match self {
            LoadBucket::Collaborator => "not_loaded/collaborator",
            LoadBucket::NeedsInsertionPoint => "not_loaded/insertion_point",
            LoadBucket::Unparsable => "not_loaded/unparsable",
        }
    }

    pub fn explanation(&self) -> &'static str {
        match self {
            LoadBucket::Collaborator => {
                "the check needs an out-of-band interaction server, which this build does not have"
            }
            LoadBucket::NeedsInsertionPoint => {
                "the check needs payload placement into a request insertion point, which is not implemented yet"
            }
            LoadBucket::Unparsable => "the check file could not be parsed, so it was never loaded",
        }
    }
}

/// Loaded, runnable, and still never reached.
///
/// Distinct from a [`Disposition`]: a disposition is the engine declining admitted work, these are
/// checks the engine was never asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeverRunReason {
    /// No audit session is in this report. Active scanning is operator-triggered, so this is the
    /// ordinary state of a proxy that has only been browsed through — and the single most important
    /// thing for a report to say, because a `FindingStore` with no findings looks identical whether
    /// the active set ran clean or nobody ever started it.
    NoAuditRequested,
    /// A loaded passive check that was never handed a single response.
    PassiveNeverDispatched,
    /// A loaded passive check whose evaluator errored. It is counted as runnable and proved nothing.
    PassiveRuntimeError,
    /// A native check (SCAN-01 / SCAN-02) ran and cannot back a clean result.
    ///
    /// Not a failure and not a clean run: an absent vulnerability dataset, an unidentifiable script,
    /// a wordlist cut short by a budget. `crate::native::NativeCoverage::inconclusive` is the
    /// engine's own name for it, and this row is what carries it into a report.
    NativeInconclusive,
}

impl NeverRunReason {
    pub fn id(&self) -> &'static str {
        match self {
            NeverRunReason::NoAuditRequested => "never_run/no_audit_requested",
            NeverRunReason::PassiveNeverDispatched => "never_run/passive_never_dispatched",
            NeverRunReason::PassiveRuntimeError => "never_run/passive_runtime_error",
            NeverRunReason::NativeInconclusive => "never_run/native_inconclusive",
        }
    }

    pub fn explanation(&self) -> &'static str {
        match self {
            NeverRunReason::NoAuditRequested => {
                "no audit was run, so no active check was ever dispatched at a target"
            }
            NeverRunReason::PassiveNeverDispatched => {
                "the check was loaded but never handed a response to evaluate"
            }
            NeverRunReason::PassiveRuntimeError => {
                "the evaluator errored on at least one response, so this check's silence is not evidence"
            }
            NeverRunReason::NativeInconclusive => {
                "the check ran but cannot back a clean result: its dataset, wordlist or budget \
                 stopped short of a conclusion"
            }
        }
    }
}

/// Why something was not checked, typed rather than stringly so a new engine disposition cannot slip
/// into a report as prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCheckedReason {
    /// Never loaded.
    NotLoaded(LoadBucket),
    /// Loaded and admitted, then declined by the engine.
    NotDispatched(Disposition),
    /// Loaded and runnable, never reached.
    NeverRun(NeverRunReason),
    /// The passive path returned before any check ran, for a whole response.
    ScanSkipped(ScanSkip),
    /// A whole audit item was refused before any check was admitted.
    ///
    /// Its own variant because such an item has **no dispositions at all** — the engine never got as
    /// far as considering a check, so every disposition counter on its outcome is zero. Without this
    /// row, auditing one out-of-scope exchange would produce a report in which the active section
    /// says `audit_requested: true`, every counter reads zero, and nothing anywhere states that the
    /// audit the operator triggered examined nothing.
    ItemRefused(ItemState),
    /// A place in a request the insertion-point enumerator refused to build a point for — a body
    /// it cannot splice into (multipart, XML, non-UTF-8), most often.
    ///
    /// Distinct from `NotDispatched(Disposition::Unsupported)`: that row counts whole checks the
    /// engine declined outright, where no point of the requested kinds survived at all. This one
    /// counts individual declined places regardless of whether the check they belong to still ran
    /// its other points — a check with 3 header points and a declined body is `Ran` once *and*
    /// contributes one entry here. Both rows can be true of the same dispatch at once; that is
    /// the point.
    InsertionDeclined,
}

impl NotCheckedReason {
    /// A stable machine key. Stable because JSON and SARIF consumers key on it; renaming one is a
    /// breaking change to those formats, not a cosmetic edit.
    pub fn id(&self) -> &'static str {
        match self {
            NotCheckedReason::NotLoaded(b) => b.id(),
            NotCheckedReason::NotDispatched(d) => disposition_id(*d),
            NotCheckedReason::NeverRun(r) => r.id(),
            NotCheckedReason::ScanSkipped(s) => scan_skip_id(*s),
            NotCheckedReason::ItemRefused(s) => item_refused_id(*s),
            NotCheckedReason::InsertionDeclined => "partial_coverage/insertion_declined",
        }
    }

    /// One line an operator can act on. Delegates to the engine's own wording wherever the engine
    /// has some, so the report and the log say the same thing.
    pub fn explanation(&self) -> &'static str {
        match self {
            NotCheckedReason::NotLoaded(b) => b.explanation(),
            NotCheckedReason::NotDispatched(d) => d.explanation(),
            NotCheckedReason::NeverRun(r) => r.explanation(),
            NotCheckedReason::ScanSkipped(s) => s.explanation(),
            NotCheckedReason::ItemRefused(s) => item_refused_explanation(*s),
            NotCheckedReason::InsertionDeclined => {
                "the insertion-point enumerator found a place to inject but refused to build a \
                 point there — see the identities for what and why"
            }
        }
    }

    pub fn unit(&self) -> Unit {
        match self {
            NotCheckedReason::NotLoaded(_) | NotCheckedReason::NeverRun(_) => Unit::Checks,
            NotCheckedReason::NotDispatched(_) => Unit::Dispatches,
            NotCheckedReason::ScanSkipped(_) => Unit::Responses,
            NotCheckedReason::ItemRefused(_) => Unit::Items,
            NotCheckedReason::InsertionDeclined => Unit::InsertionPoints,
        }
    }
}

/// The mapping from an engine disposition to a stable report key.
///
/// A `match` here rather than `serde`'s derived variant name: the derived name is an implementation
/// detail of `Disposition` and a refactor there would silently rename a published JSON and SARIF
/// key. This mapping is exhaustive, so adding a disposition fails to compile until it has a key.
fn disposition_id(d: Disposition) -> &'static str {
    match d {
        Disposition::Ran => "dispatched/ran",
        Disposition::Unsupported => "not_dispatched/unsupported",
        Disposition::SendFailed => "not_dispatched/send_failed",
        Disposition::AlreadyCovered => "covered_elsewhere/already_covered",
        Disposition::TimeBudgetSpent => "not_dispatched/time_budget_spent",
        Disposition::RequestBudgetSpent => "not_dispatched/request_budget_spent",
        Disposition::UnitAbandoned => "not_dispatched/unit_abandoned",
        Disposition::ItemFailed => "not_dispatched/item_failed",
        Disposition::SessionPaused => "not_dispatched/session_paused",
    }
}

fn scan_skip_id(s: ScanSkip) -> &'static str {
    match s {
        ScanSkip::NoChecksLoaded => "scan_skipped/no_checks_loaded",
        ScanSkip::ExchangeNotFound => "scan_skipped/exchange_not_found",
        ScanSkip::OutOfScope => "scan_skipped/out_of_scope",
        ScanSkip::ResponseNotFound => "scan_skipped/response_not_found",
    }
}

fn item_state_id(s: ItemState) -> &'static str {
    match s {
        ItemState::Pending => "pending",
        ItemState::Auditing => "auditing",
        ItemState::Audited => "audited",
        ItemState::Bounded => "bounded",
        ItemState::Failed => "failed",
        ItemState::Paused => "paused",
        ItemState::OutOfScope => "out_of_scope",
        ItemState::Unauditable => "unauditable",
    }
}

/// The same states as [`item_state_id`], prefixed, because here they are a not-checked *reason*
/// rather than a neutral fact in the outcome histogram. A consumer must be able to tell
/// "one item ended up out of scope" from "one item was refused, so nothing about it was checked".
fn item_refused_id(s: ItemState) -> &'static str {
    match s {
        ItemState::Pending => "item_refused/pending",
        ItemState::Auditing => "item_refused/auditing",
        ItemState::Audited => "item_refused/audited",
        ItemState::Bounded => "item_refused/bounded",
        ItemState::Failed => "item_refused/failed",
        ItemState::Paused => "item_refused/paused",
        ItemState::OutOfScope => "item_refused/out_of_scope",
        ItemState::Unauditable => "item_refused/unauditable",
    }
}

/// Why a whole item was refused, in the operator's terms.
///
/// [`ItemState::label`] returns a display word ("out of scope"), not a reason, so the wording lives
/// here. Every variant is covered even though only three can currently reach this row with zero
/// dispositions: a mapping that guessed at the rest is what would go wrong quietly when the engine
/// grows the asynchronous queue its non-terminal states exist for.
fn item_refused_explanation(s: ItemState) -> &'static str {
    match s {
        ItemState::OutOfScope => {
            "the exchange's host is outside the engagement scope, so nothing was sent to it"
        }
        ItemState::Unauditable => {
            "the exchange is missing, has no response yet, or will not parse, so there was nothing \
             to audit"
        }
        ItemState::Paused => {
            "the session failure breaker paused the run before this item was reached; nothing was sent"
        }
        ItemState::Bounded => "a budget was spent before this item was started",
        ItemState::Failed => "the item breaker failed this item before any check was admitted",
        ItemState::Audited => {
            "reported as audited with no check considered, which should not happen; treated as \
             unchecked rather than clean"
        }
        ItemState::Pending | ItemState::Auditing => {
            "the item is still outstanding: it was neither completed nor refused"
        }
    }
}

/// One row of the "what was not checked, and why" statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotChecked {
    pub reason: NotCheckedReason,
    /// How many, in [`NotCheckedReason::unit`].
    pub count: usize,
    /// Concrete identities where they are retained. Empty is not a claim that there are none — see
    /// [`Unknown`] for the buckets whose identities the loader drops.
    pub identities: Vec<String>,
}

/// Something a report structurally cannot know, stated so it is never rendered as a zero.
///
/// These are not gaps to close in a later phase. They are limits of what a proxy-and-check-set tool
/// can observe, and a report that omits them is making a stronger claim than its evidence supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unknown {
    pub subject: String,
    pub because: String,
}

impl Unknown {
    fn new(subject: &str, because: &str) -> Self {
        Self {
            subject: subject.to_owned(),
            because: because.to_owned(),
        }
    }
}

/// Corpus coverage: what the loader classified, and what it could not load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusCoverage {
    pub files: usize,
    pub passive_loaded: usize,
    pub active_loaded: usize,
    pub collaborator: usize,
    pub needs_insertion_point: usize,
    /// `(file, parse error)` for each check that did not load.
    pub unparsable: Vec<(String, String)>,
}

impl CorpusCoverage {
    /// The four not-loaded-or-loaded buckets, summed. Equals [`CorpusCoverage::files`] — the same
    /// identity [`crate::LoadReport`] is already tested for, re-derived here so a report cannot show
    /// buckets that do not add up to the corpus they came from.
    pub fn accounted(&self) -> usize {
        self.passive_loaded
            + self.active_loaded
            + self.collaborator
            + self.needs_insertion_point
            + self.unparsable.len()
    }
}

/// Passive-path coverage, per loaded check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassiveCoverage {
    /// One count per [`CoverageState`], over every loaded passive check.
    pub states: Vec<(CoverageState, usize)>,
    /// Names of checks that never ran, so "31 never ran" is actionable.
    pub never_dispatched: Vec<String>,
    /// `(check, last error)` for checks whose evaluator errored.
    pub errored: Vec<(String, String)>,
    /// Whole-response skips, one count per reason.
    pub skips: Vec<(ScanSkip, u64)>,
    /// Responses on which at least one check ran. Zero here with a non-empty check set means the
    /// passive path never saw traffic.
    pub responses_scanned: u64,
}

impl PassiveCoverage {
    fn count(&self, st: CoverageState) -> usize {
        self.states
            .iter()
            .find(|(s, _)| *s == st)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    }

    /// Checks whose silence is evidence: they ran and never errored.
    pub fn checked(&self) -> usize {
        self.count(CoverageState::RanClean) + self.count(CoverageState::RanAndFound)
    }
}

/// Active-audit coverage, aggregated across every item in every session in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveCoverage {
    /// Active checks the loader made runnable. The per-item denominator.
    pub loaded: usize,
    /// False when no audit session was supplied at all.
    pub audit_requested: bool,
    /// Audit items by terminal state.
    pub items: Vec<(ItemState, usize)>,
    /// The nine-way disposition histogram, summed over every item.
    pub dispositions: Vec<(Disposition, usize)>,
    pub requests_sent: u32,
    /// Probes refused because the request's own path fell outside scope.
    pub requests_refused: u32,
    /// True when a time budget stopped at least one item.
    pub timed_out: bool,
    /// True when the session failure breaker stopped admitting items.
    pub paused: bool,
    /// Per-item error strings, deduplicated. Empty when nothing errored.
    pub errors: Vec<String>,
    /// Items refused before a single check was admitted, by terminal state.
    ///
    /// Kept apart from `items` because these contribute **no dispositions at all** — every counter on
    /// their outcome is zero, so without this they would leave no trace in the not-checked statement
    /// and an audit of one out-of-scope exchange would report as an audit that found nothing.
    pub refused_items: Vec<(ItemState, usize)>,
    /// Individual insertion points the enumerator declined, summed over every dispatch — the real
    /// count of places not tested, whether the check that hit them ended up `Ran` (a mixed
    /// request) or `Unsupported` (nothing else to test). Drives the `NotChecked` row's count.
    pub declined_points: usize,
    /// The distinct `"what: reason"` lines behind `declined_points`, deduplicated. A run auditing
    /// many identical multipart POSTs declines the same body shape every time; the count says how
    /// often, this says what kinds — printing every repetition would bury the one that matters
    /// under duplicates of itself.
    pub declined_reasons: Vec<String>,
}

impl ActiveCoverage {
    fn count(&self, d: Disposition) -> usize {
        self.dispositions
            .iter()
            .find(|(x, _)| *x == d)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    }

    /// Check dispatches that completed. The only disposition under which "no finding" is evidence.
    pub fn ran(&self) -> usize {
        self.count(Disposition::Ran)
    }

    /// Dispatches refused because an identical `(dispatch unit, check)` had already run.
    ///
    /// Its own category, neither checked nor unchecked: within one session the covering dispatch
    /// provably happened, so the work was done — but it was not done *here*, and collapsing it into
    /// `ran` would overstate what this item proves. See [`RunCoverage::unknowns`] for the case where
    /// the covering dispatch is not in this report at all.
    pub fn covered_elsewhere(&self) -> usize {
        self.count(Disposition::AlreadyCovered)
    }

    /// Every dispatch the engine reached a disposition for.
    pub fn considered(&self) -> usize {
        self.dispositions.iter().map(|(_, n)| *n).sum()
    }
}

/// The composed coverage statement. This is what all three formats render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCoverage {
    pub corpus: CorpusCoverage,
    pub passive: PassiveCoverage,
    pub active: ActiveCoverage,
    /// SCAN-01 / SCAN-02 runtime state, taken straight off [`crate::CoverageReport::native`] rather
    /// than re-derived: the native checks own the only honest account of an absent dataset or a
    /// wordlist cut short.
    pub native: crate::native::NativeCoverage,
    pub unknowns: Vec<Unknown>,
}

impl RunCoverage {
    fn compose(
        load: &LoadReport,
        passive: &crate::CoverageReport,
        audits: &[crate::SessionOutcome],
    ) -> Self {
        let corpus = CorpusCoverage {
            files: load.files,
            passive_loaded: load.passive,
            active_loaded: load.active,
            collaborator: load.collaborator,
            needs_insertion_point: load.needs_insertion_point,
            unparsable: load.errors.clone(),
        };
        let native = passive.native.clone();

        let never_dispatched = passive
            .checks
            .iter()
            .filter(|c| c.state() == CoverageState::NeverDispatched)
            .map(|c| c.name.clone())
            .collect();
        let errored = passive
            .checks
            .iter()
            .filter(|c| c.state() == CoverageState::Errored)
            .map(|c| {
                (
                    c.name.clone(),
                    c.last_error.clone().unwrap_or_else(|| {
                        // `last_error` is documented as `Some` exactly when `errored > 0`. If that
                        // ever stops holding, say so rather than printing an empty cell that reads
                        // as "no error".
                        "errored with no message recorded".to_owned()
                    }),
                )
            })
            .collect();
        let passive = PassiveCoverage {
            states: passive.partition().to_vec(),
            never_dispatched,
            errored,
            skips: passive.skips.clone(),
            responses_scanned: passive.checks.iter().map(|c| c.ran).max().unwrap_or(0),
        };

        let active = compose_active(load.active, audits);
        let unknowns = unknowns_for(&corpus, &passive, &active, &native, audits);

        Self {
            corpus,
            passive,
            active,
            native,
            unknowns,
        }
    }

    /// Every "not checked" row, in a fixed order: corpus buckets, the never-run set, the engine's
    /// per-dispatch refusals, declined insertion points, whole audit items refused before any
    /// check, then whole-response skips.
    ///
    /// Rows with a zero count are omitted, because a table of zeroes buries the non-zero row that
    /// matters. Rows are never omitted for being *inconvenient*: this is the only place any format
    /// gets its not-checked statement from, so a bucket missing here is missing from all three.
    pub fn not_checked(&self) -> Vec<NotChecked> {
        let mut rows = Vec::new();
        let mut push = |reason: NotCheckedReason, count: usize, identities: Vec<String>| {
            if count > 0 {
                rows.push(NotChecked {
                    reason,
                    count,
                    identities,
                });
            }
        };

        push(
            NotCheckedReason::NotLoaded(LoadBucket::Collaborator),
            self.corpus.collaborator,
            Vec::new(),
        );
        push(
            NotCheckedReason::NotLoaded(LoadBucket::NeedsInsertionPoint),
            self.corpus.needs_insertion_point,
            Vec::new(),
        );
        push(
            NotCheckedReason::NotLoaded(LoadBucket::Unparsable),
            self.corpus.unparsable.len(),
            self.corpus
                .unparsable
                .iter()
                .map(|(f, e)| format!("{f}: {e}"))
                .collect(),
        );

        // Hole 3, and the one that makes a zero-finding report honest: the active set is loaded and
        // runnable and nothing ever dispatched it.
        if !self.active.audit_requested {
            push(
                NotCheckedReason::NeverRun(NeverRunReason::NoAuditRequested),
                self.corpus.active_loaded,
                Vec::new(),
            );
        }
        push(
            NotCheckedReason::NeverRun(NeverRunReason::PassiveNeverDispatched),
            self.passive.count(CoverageState::NeverDispatched),
            self.passive.never_dispatched.clone(),
        );
        push(
            NotCheckedReason::NeverRun(NeverRunReason::PassiveRuntimeError),
            self.passive.count(CoverageState::Errored),
            self.passive
                .errored
                .iter()
                .map(|(c, e)| format!("{c}: {e}"))
                .collect(),
        );
        push(
            NotCheckedReason::NeverRun(NeverRunReason::NativeInconclusive),
            self.native_inconclusive().len(),
            self.native_inconclusive(),
        );

        for (d, n) in &self.active.dispositions {
            // `Ran` is evidence and `AlreadyCovered` is its own category; the other seven are the
            // engine declining to look. Driven off `stopped_looking` and `is_dispatched` rather than
            // a hand-written list, so a new disposition is classified by the engine's own rules.
            let not_checked = *d != Disposition::Ran && *d != Disposition::AlreadyCovered;
            if not_checked {
                push(NotCheckedReason::NotDispatched(*d), *n, Vec::new());
            }
        }

        push(
            NotCheckedReason::InsertionDeclined,
            self.active.declined_points,
            self.active.declined_reasons.clone(),
        );

        for (st, n) in &self.active.refused_items {
            push(NotCheckedReason::ItemRefused(*st), *n, Vec::new());
        }

        for (s, n) in &self.passive.skips {
            push(NotCheckedReason::ScanSkipped(*s), *n as usize, Vec::new());
        }

        rows
    }

    /// The summary line of each enabled native check that cannot back a clean result.
    ///
    /// Empty when no native check is enabled, and empty when every enabled one reached a conclusion.
    /// Those two are distinguishable from `native.js_libraries` / `native.jwt_weak_secret` being
    /// `None` versus `Some`, which is why this returns the lines rather than a bare count.
    pub fn native_inconclusive(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(js) = &self.native.js_libraries
            && js.inconclusive()
        {
            v.push(format!(
                "{}: {}",
                crate::js_vulns::JsLibraryCheck::NAME,
                js.dataset.summary()
            ));
        }
        if let Some(jwt) = &self.native.jwt_weak_secret
            && jwt.inconclusive()
        {
            v.push(format!(
                "{}: {}",
                crate::jwt_weak::JwtWeakSecretCheck::NAME,
                jwt.summary()
            ));
        }
        v
    }

    /// Total not-checked count over every unit that [`Unit::decides_the_verdict`].
    ///
    /// Summed only to answer "was anything left undone", never divided into a percentage — the units
    /// are not interchangeable and the module docs say why.
    pub fn not_checked_total(&self) -> usize {
        self.not_checked()
            .iter()
            .filter(|r| r.reason.unit().decides_the_verdict())
            .map(|r| r.count)
            .sum()
    }

    /// Checks and dispatches whose silence is evidence.
    pub fn checked_total(&self) -> usize {
        self.passive.checked() + self.active.ran()
    }

    /// The verdict, derived from the counters above.
    ///
    /// The structural [`RunCoverage::unknowns`] deliberately do **not** force a partial verdict. They
    /// are unconditional — every run has them — so treating them as incompleteness would make
    /// [`Verdict::FullyChecked`] unreachable by construction and turn the distinction this enum
    /// exists to draw into decoration. They are stated in their own section of every format instead,
    /// and [`Verdict::headline`] points at them rather than claiming an unqualified all-clear.
    pub fn verdict(&self, findings: usize) -> Verdict {
        let checked = self.checked_total();
        let not_checked = self.not_checked_total();
        if checked == 0 {
            return Verdict::NothingChecked;
        }
        if not_checked > 0 {
            return Verdict::PartiallyChecked {
                checked,
                not_checked,
                findings,
            };
        }
        Verdict::FullyChecked { checked, findings }
    }
}

fn compose_active(loaded: usize, audits: &[crate::SessionOutcome]) -> ActiveCoverage {
    let mut dispositions: Vec<(Disposition, usize)> = AuditOutcome::default()
        .dispositions()
        .iter()
        .map(|(d, _)| (*d, 0usize))
        .collect();
    let mut items: Vec<(ItemState, usize)> = Vec::new();
    let mut refused_items: Vec<(ItemState, usize)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut declined_points = 0usize;
    let mut declined_reasons: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut requests_sent = 0u32;
    let mut requests_refused = 0u32;
    let (mut timed_out, mut paused) = (false, false);

    for s in audits {
        requests_sent = requests_sent.saturating_add(s.requests_sent);
        timed_out |= s.timed_out;
        paused |= s.paused;
        for (_, o) in &s.items {
            requests_refused = requests_refused.saturating_add(o.requests_refused);
            for (d, n) in o.dispositions() {
                if let Some(slot) = dispositions.iter_mut().find(|(x, _)| *x == d) {
                    slot.1 += n;
                }
            }
            match items.iter_mut().find(|(st, _)| *st == o.state) {
                Some(slot) => slot.1 += 1,
                None => items.push((o.state, 1)),
            }
            // Zero dispositions means the engine never got as far as considering a check, so this
            // item leaves no trace in the disposition histogram. Recorded separately so the
            // not-checked statement can still name it.
            if o.considered() == 0 {
                match refused_items.iter_mut().find(|(st, _)| *st == o.state) {
                    Some(slot) => slot.1 += 1,
                    None => refused_items.push((o.state, 1)),
                }
            }
            if let Some(e) = &o.error
                && !errors.contains(e)
            {
                errors.push(e.clone());
            }
            // `o.declined` overlays `Ran` and `Unsupported`; it never partitions the disposition
            // histogram above, so it is accumulated on the side. The count is the real number of
            // places not tested; the reason set is deduplicated for display — see the field doc.
            declined_points += o.declined.len();
            declined_reasons.extend(o.declined.iter().cloned());
        }
    }

    ActiveCoverage {
        loaded,
        audit_requested: !audits.is_empty(),
        items,
        dispositions,
        requests_sent,
        requests_refused,
        timed_out,
        paused,
        errors,
        refused_items,
        declined_points,
        declined_reasons: declined_reasons.into_iter().collect(),
    }
}

/// The structural unknowns, plus the two that depend on the run's shape.
///
/// Assembled here rather than written into each format so all three say the same thing, and so
/// adding one is a single edit that cannot reach two formats and miss the third.
fn unknowns_for(
    corpus: &CorpusCoverage,
    passive: &PassiveCoverage,
    active: &ActiveCoverage,
    native: &crate::native::NativeCoverage,
    audits: &[crate::SessionOutcome],
) -> Vec<Unknown> {
    let mut v = vec![
        Unknown::new(
            "whether the loaded corpus is the currently published corpus",
            &format!(
                "{} check files were found on disk; the tool cannot know what the upstream project \
                 publishes today, so every count here is corpus-as-loaded, not corpus-as-published",
                corpus.files
            ),
        ),
        Unknown::new(
            "whether the captured traffic represents the application",
            "coverage of a site is not computable from a proxy's history: a check can only look at \
             responses that were captured, and nothing here knows what was never visited",
        ),
    ];

    // The loader increments a count and drops the check, so the report can say "26" but not which
    // 26. Stated rather than left as an empty identity list that reads as "none".
    if corpus.collaborator > 0 || corpus.needs_insertion_point > 0 {
        v.push(Unknown::new(
            "which specific checks fell into the Collaborator and insertion-point buckets",
            "the loader records those two buckets as counts and does not retain the check \
             identities, so they are reported as totals only",
        ));
    }

    if active.covered_elsewhere() > 0 && audits.len() > 1 {
        v.push(Unknown::new(
            "whether every dispatch refused as already-covered is covered within this report",
            "the refusal is exact within one audit session, but this report spans more than one \
             session and each has its own ledger, so a refusal cannot be resolved to the dispatch \
             that admitted it",
        ));
    }

    if active.count(Disposition::SendFailed) > 0 {
        v.push(Unknown::new(
            "whether the targets of failed probes are clean",
            "a check whose probe could not be sent or read never saw its own response, so it \
             proves nothing about that target either way",
        ));
    }

    if passive.responses_scanned == 0 && corpus.passive_loaded > 0 {
        v.push(Unknown::new(
            "what the passive check set would have found",
            "no response was ever scanned, so the passive result is an absence of evidence rather \
             than evidence of absence",
        ));
    }

    if native.js_libraries.is_some() {
        v.push(Unknown::new(
            "whether the vulnerable-JavaScript dataset is current",
            "the dataset is vendored at build time; a library disclosed after that build is not in \
             it, so a clean SCAN-01 result is relative to the dataset named in the coverage detail",
        ));
    }

    v
}

/// The headline every format leads with.
///
/// Deliberately not a percentage, and deliberately carrying the finding count: "clean" is a joint
/// claim about coverage and findings, and the two failure modes a report must not permit are calling
/// an incomplete run clean and calling a complete run with findings clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every check, dispatch and audit item reached a conclusion. With `findings == 0` this is the
    /// only state in which "clean" is honest — and even then it is honest only *within* the scope and
    /// the stated unknowns, which is why [`Verdict::headline`] says so rather than declaring an
    /// unqualified all-clear.
    FullyChecked { checked: usize, findings: usize },
    /// Some work was declined, never reached, or refused. A zero-finding report in this state is
    /// **not** a clean bill of health.
    PartiallyChecked {
        checked: usize,
        not_checked: usize,
        findings: usize,
    },
    /// Nothing is known to have run. A report in this state must not contain the word "clean".
    NothingChecked,
}

impl Verdict {
    /// A stable machine key, for the JSON and SARIF renderings.
    pub fn id(&self) -> &'static str {
        match self {
            Verdict::FullyChecked { .. } => "fully_checked",
            Verdict::PartiallyChecked { .. } => "partially_checked",
            Verdict::NothingChecked => "nothing_checked",
        }
    }

    /// True when a reader may treat "no finding" as evidence.
    pub fn coverage_is_complete(&self) -> bool {
        matches!(self, Verdict::FullyChecked { .. })
    }

    /// One sentence, used verbatim by all three writers.
    pub fn headline(&self) -> String {
        match self {
            Verdict::FullyChecked { checked, findings: 0 } => format!(
                "Checked and clean: {checked} checks and dispatches reached a conclusion and none \
                 reported a finding. That holds within the scope stated above and the limits listed \
                 under what is not knowable from this run."
            ),
            Verdict::FullyChecked { checked, findings } => format!(
                "Checked: {checked} checks and dispatches reached a conclusion; {findings} findings \
                 reported."
            ),
            Verdict::PartiallyChecked {
                checked,
                not_checked,
                findings,
            } => format!(
                "Partial coverage: {checked} checks and dispatches reached a conclusion, \
                 {not_checked} did not. {findings} findings reported. This is not a clean bill of \
                 health — see what was not checked, below."
            ),
            Verdict::NothingChecked => "Nothing was checked: no check is known to have run against \
                 any target, so this report says nothing about the security of the target."
                .to_owned(),
        }
    }
}

/// An RFC 3339 UTC timestamp from Unix milliseconds.
///
/// Hand-rolled because the workspace has no date crate and this is the only place one would be
/// needed. The civil-date arithmetic is the standard days-to-`(y, m, d)` conversion with the era
/// shifted to March so leap days land at the end of a cycle; it is exact for every value in range,
/// which a `days / 365`-style approximation is not.
pub fn rfc3339_utc_millis(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // Shift the epoch to 0000-03-01 so a 400-year era begins on a March, which puts February 29th
    // last in every cycle and removes the leap-year special case entirely.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Unix milliseconds now, for a caller that has no clock of its own.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Wrap one operator-triggered [`crate::PassiveScanner::audit`] as a session, so a caller retaining
/// outcomes for a report has one type to keep.
///
/// `audit` returns a bare [`AuditOutcome`] because it is deliberately one-shot with a fresh ledger,
/// and that is right for the engine. It leaves a caller assembling a report with two shapes to
/// handle, so the conversion lives here rather than being open-coded in every binary — an
/// open-coded version that forgot `requests_sent` would under-report traffic the tool actually sent.
pub fn single_audit(exchange_id: u64, o: AuditOutcome) -> crate::SessionOutcome {
    crate::SessionOutcome {
        findings: o.findings,
        requests_sent: o.requests_sent,
        timed_out: o.timed_out,
        failed_items: usize::from(o.state == ItemState::Failed),
        // One exchange, so one dispatch unit at most — and none at all when the item was refused
        // before any check was admitted.
        dispatch_units: usize::from(o.considered() > 0),
        paused: o.state == ItemState::Paused,
        items: vec![(exchange_id, o)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CheckCoverage, SessionOutcome};

    /// A `LoadReport` with the shipped corpus's shape: 264 files, 105 passive, 127 active, 6
    /// insertion-point, 26 Collaborator.
    pub(super) fn shipped_load() -> LoadReport {
        LoadReport {
            files: 264,
            passive: 105,
            active: 127,
            needs_insertion_point: 6,
            collaborator: 26,
            errors: Vec::new(),
        }
    }

    pub(super) fn passive_all_ran(n: usize) -> crate::CoverageReport {
        crate::CoverageReport {
            checks: (0..n)
                .map(|i| CheckCoverage {
                    name: format!("check {i}"),
                    ran: 3,
                    ..Default::default()
                })
                .collect(),
            skips: ScanSkip::ALL.iter().map(|s| (*s, 0)).collect(),
            ..Default::default()
        }
    }

    /// A session in which four dispatches ran and six were refused for want of request budget —
    /// the canonical "the report must not look clean" run.
    pub(super) fn bounded_session() -> SessionOutcome {
        SessionOutcome {
            items: vec![(
                1,
                AuditOutcome {
                    state: ItemState::Bounded,
                    ran: 4,
                    request_budget_spent: 6,
                    requests_sent: 4,
                    ..Default::default()
                },
            )],
            findings: 0,
            requests_sent: 4,
            dispatch_units: 1,
            failed_items: 0,
            paused: false,
            timed_out: false,
        }
    }

    fn report(audits: &[SessionOutcome]) -> Report {
        let scope = Scope::allow_everything();
        let load = shipped_load();
        let passive = passive_all_ran(105);
        Report::from_facts(RunFacts {
            scope: &scope,
            load: &load,
            passive: &passive,
            audits,
            findings: &[],
            generated_unix_ms: 1_753_660_800_000,
        })
    }

    #[test]
    fn a_report_with_no_audit_session_says_the_whole_active_set_was_never_dispatched() {
        let r = report(&[]);
        let row = r
            .coverage
            .not_checked()
            .into_iter()
            .find(|row| row.reason == NotCheckedReason::NeverRun(NeverRunReason::NoAuditRequested))
            .expect("a report with no audit must carry the no-audit-requested row");
        assert_eq!(
            row.count, 127,
            "every loaded active check is unchecked, not clean"
        );
    }

    #[test]
    fn the_verdict_is_never_fully_checked_while_the_collaborator_bucket_is_populated() {
        let r = report(&[bounded_session()]);
        assert!(
            !r.verdict().coverage_is_complete(),
            "26 Collaborator-gated checks were never loaded, so coverage is not complete: {:?}",
            r.verdict()
        );
    }

    #[test]
    fn a_bounded_session_reports_its_refused_dispatches_as_not_checked() {
        let r = report(&[bounded_session()]);
        let rows = r.coverage.not_checked();
        let refused = rows
            .iter()
            .find(|row| {
                row.reason == NotCheckedReason::NotDispatched(Disposition::RequestBudgetSpent)
            })
            .expect("the request-budget refusal must appear");
        assert_eq!(refused.count, 6);
        assert_eq!(r.coverage.active.ran(), 4);
    }

    #[test]
    fn the_corpus_buckets_sum_to_the_file_count() {
        let r = report(&[]);
        assert_eq!(
            r.coverage.corpus.accounted(),
            r.coverage.corpus.files,
            "every loaded and not-loaded bucket must account for exactly one file"
        );
    }

    #[test]
    fn a_run_where_no_check_ever_ran_is_reported_as_nothing_checked() {
        let scope = Scope::allow_everything();
        let load = shipped_load();
        let passive = crate::CoverageReport {
            checks: (0..105)
                .map(|i| CheckCoverage {
                    name: format!("check {i}"),
                    ..Default::default()
                })
                .collect(),
            skips: vec![(ScanSkip::OutOfScope, 12)],
            ..Default::default()
        };
        let r = Report::from_facts(RunFacts {
            scope: &scope,
            load: &load,
            passive: &passive,
            audits: &[],
            findings: &[],
            generated_unix_ms: 0,
        });
        assert_eq!(r.verdict(), Verdict::NothingChecked);
        assert!(
            !r.verdict().headline().contains("clean"),
            "a report that checked nothing must not contain the word clean: {}",
            r.verdict().headline()
        );
    }

    #[test]
    fn a_passive_check_that_errored_is_not_counted_as_having_run() {
        let scope = Scope::allow_everything();
        let load = LoadReport {
            files: 2,
            passive: 2,
            ..Default::default()
        };
        let passive = crate::CoverageReport {
            checks: vec![
                CheckCoverage {
                    name: "good".into(),
                    ran: 5,
                    ..Default::default()
                },
                CheckCoverage {
                    name: "bad".into(),
                    ran: 4,
                    errored: 1,
                    last_error: Some("unsupported regex construct".into()),
                    ..Default::default()
                },
            ],
            skips: Vec::new(),
            ..Default::default()
        };
        let r = Report::from_facts(RunFacts {
            scope: &scope,
            load: &load,
            passive: &passive,
            audits: &[],
            findings: &[],
            generated_unix_ms: 0,
        });
        assert_eq!(r.coverage.passive.checked(), 1);
        let row = r
            .coverage
            .not_checked()
            .into_iter()
            .find(|row| {
                row.reason == NotCheckedReason::NeverRun(NeverRunReason::PassiveRuntimeError)
            })
            .expect("the errored check must be reported");
        assert_eq!(row.count, 1);
        assert_eq!(
            row.identities,
            vec!["bad: unsupported regex construct".to_owned()],
            "the operator needs the check name and the evaluator's message, not just a count"
        );
    }

    #[test]
    fn not_checked_rows_never_mix_check_counts_with_response_counts() {
        let scope = Scope::allow_everything();
        let load = shipped_load();
        let passive = crate::CoverageReport {
            checks: passive_all_ran(105).checks,
            skips: vec![(ScanSkip::OutOfScope, 40)],
            ..Default::default()
        };
        let r = Report::from_facts(RunFacts {
            scope: &scope,
            load: &load,
            passive: &passive,
            audits: &[],
            findings: &[],
            generated_unix_ms: 0,
        });
        let rows = r.coverage.not_checked();
        let skip = rows
            .iter()
            .find(|row| row.reason == NotCheckedReason::ScanSkipped(ScanSkip::OutOfScope))
            .expect("the out-of-scope skip must be reported");
        assert_eq!(skip.reason.unit(), Unit::Responses);
        assert!(
            !r.coverage
                .not_checked()
                .iter()
                .filter(|row| row.reason.unit() == Unit::Responses)
                .any(|row| row.count == 0),
            "zero rows are omitted so the non-zero ones are visible"
        );
        assert_eq!(
            r.coverage.not_checked_total(),
            26 + 6 + 127,
            "the 40 skipped responses must not be added to a count of checks"
        );
    }

    #[test]
    fn every_disposition_and_scan_skip_has_a_distinct_stable_key() {
        // Sourced from the engine's own exhaustive histogram rather than a list retyped here: a
        // tenth disposition then shows up in this test automatically instead of being silently
        // untested.
        let mut ids: Vec<&str> = AuditOutcome::default()
            .dispositions()
            .iter()
            .map(|(d, _)| disposition_id(*d))
            .collect();
        ids.extend(ScanSkip::ALL.iter().map(|s| scan_skip_id(*s)));
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(n, ids.len(), "two reasons share a machine key: {ids:?}");
    }

    #[test]
    fn rfc3339_conversion_is_exact_at_known_instants() {
        assert_eq!(rfc3339_utc_millis(0), "1970-01-01T00:00:00.000Z");
        // A leap day, which is where a naive days/365 conversion drifts.
        assert_eq!(
            rfc3339_utc_millis(1_709_164_800_000),
            "2024-02-29T00:00:00.000Z"
        );
        assert_eq!(
            rfc3339_utc_millis(1_753_660_800_123),
            "2025-07-28T00:00:00.123Z"
        );
    }

    #[test]
    fn a_check_that_ran_and_declined_a_place_reports_both_without_stealing_from_ran() {
        // The QA finding: a check with real points that ran alongside a declined body must count
        // as `Ran` exactly once — `declined` is a non-partitioning overlay, not a tenth
        // disposition — and the reason must still reach every rendered format.
        let o = AuditOutcome {
            state: ItemState::Audited,
            ran: 1,
            requests_sent: 3,
            declined: vec!["request body: multipart body: framing not modelled".to_owned()],
            ..Default::default()
        };
        assert_eq!(o.considered(), 1, "the overlay must not inflate considered()");
        assert_eq!(o.dispositions()[0], (Disposition::Ran, 1));

        let r = report(&[single_audit(1, o)]);
        let row = r
            .coverage
            .not_checked()
            .into_iter()
            .find(|row| row.reason == NotCheckedReason::InsertionDeclined)
            .expect("the declined insertion point must appear as its own not-checked row");
        assert_eq!(row.count, 1);
        assert_eq!(row.reason.unit(), Unit::InsertionPoints);
        assert_eq!(
            row.identities,
            vec!["request body: multipart body: framing not modelled".to_owned()]
        );
        assert!(
            matches!(r.verdict(), Verdict::PartiallyChecked { .. }),
            "a declined place is unfinished coverage, not a clean run: {:?}",
            r.verdict()
        );

        let json = super::json::to_json(&r);
        assert!(
            json.contains("multipart body: framing not modelled"),
            "the decline reason must reach the JSON export"
        );
        let html = super::html::to_html(&r);
        assert!(
            html.contains("multipart body: framing not modelled"),
            "the decline reason must reach the HTML report"
        );
    }

    #[test]
    fn a_single_audit_wrapped_as_a_session_keeps_every_disposition_and_its_traffic() {
        let o = AuditOutcome {
            state: ItemState::Bounded,
            ran: 4,
            request_budget_spent: 6,
            requests_sent: 4,
            ..Default::default()
        };
        let s = single_audit(42, o.clone());
        assert_eq!(s.items, vec![(42, o)]);
        assert_eq!(s.requests_sent, 4);
        assert_eq!(s.dispatch_units, 1);
        assert_eq!(s.failed_items, 0);

        // An item refused before any check was admitted dispatched nothing, and must not be counted
        // as a dispatch unit that produced no findings.
        let refused = single_audit(
            7,
            AuditOutcome {
                state: ItemState::OutOfScope,
                ..Default::default()
            },
        );
        assert_eq!(refused.dispatch_units, 0);
    }

    #[test]
    fn a_wrapped_single_audit_reaches_the_reports_active_coverage() {
        let scope = Scope::allow_everything();
        let load = shipped_load();
        let passive = passive_all_ran(105);
        let audits = [single_audit(
            1,
            AuditOutcome {
                state: ItemState::Bounded,
                ran: 4,
                request_budget_spent: 6,
                ..Default::default()
            },
        )];
        let r = Report::from_facts(RunFacts {
            scope: &scope,
            load: &load,
            passive: &passive,
            audits: &audits,
            findings: &[],
            generated_unix_ms: 0,
        });
        assert!(r.coverage.active.audit_requested);
        assert_eq!(r.coverage.active.ran(), 4);
        assert!(
            !r.coverage.not_checked().iter().any(|row| row.reason
                == NotCheckedReason::NeverRun(NeverRunReason::NoAuditRequested)),
            "an audit did run, so the no-audit row must not appear"
        );
    }
}
