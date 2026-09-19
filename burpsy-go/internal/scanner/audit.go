// The audit engine's vocabulary: seven dispatch scopes, an item state machine, admission-side
// budgets, and the two-level failure model.
//
// # The decision this file exists to make
//
// Burp bounds unbounded audit growth by *discarding* work. `burp.Zq5.LIMIT_EXCEEDED` marks an
// insertion point that Burp expanded, queued, and then abandoned — "Burp Scanner didn't audit this
// insertion point, as it reached the maximum limit of insertion points to audit per request." The
// expansion happened, the memory was allocated, the cost was paid, and the result was thrown away.
// `requests × insertion points × checks` is unbounded, and a cap applied at the end is the most
// expensive place to apply one.
//
// This engine bounds the work **admitted**. Every unit of work passes an admission gate *before*
// dispatch, and nothing that starts is ever abandoned mid-flight. A refusal is not silence: it is a
// named Disposition with a count, so a caller can always tell "looked and found nothing" from
// "stopped looking". That distinction is the whole contract — a scanner that quietly stops looking
// reports a clean bill of health for a host it barely touched. It is the same argument
// CoverageTracker makes for the passive set, at the level the active set has.
//
// # Scope collapse is the largest saving
//
// `burp.Zcud` defines seven dispatch scopes because *how often a check runs* is the primary
// determinant of cost. A `given host` check auditing 500 captured exchanges on one host is 500
// dispatches of a check whose answer cannot change between them. AuditLedger records which
// `(dispatch unit, check)` pairs have run, so the second through five-hundredth are refused as
// DispositionAlreadyCovered — refused before a request is built, not after.
//
// This is admission control rather than caching: nothing is stored except one bit per pair, and the
// refusal is reported rather than silently folded into "found nothing".
//
// # What is faithful to Burp and what is ours
//
// The seven scopes and the two-level failure model are Burp's, recovered from `burp.Zcud` and from
// the `scanner/error_handling/*` keys in `resources/BuiltInConfigs/`. The state names are ours,
// because the semantics differ: Burp's `Zq5` describes the fate of an insertion point that was
// already expanded, and ours describes whether work was admitted at all. `Zq5`'s `permanentIndex`
// byte is not reproduced — it is assigned in a static initialiser the obfuscator stripped, so no
// recovered value exists to be faithful to.
//
// This is a faithful port of crates/scanner/src/audit.rs. Named divergences, all of them forced by
// Go rather than chosen:
//
//   - Rust's `Option<u32>` becomes OptUint32, because "absent" and "zero" are different answers
//     here and a plain uint32 would collapse them.
//   - AuditLedger carries its own mutex. Rust's `admit(&mut self)` makes exclusive access a
//     compile-time fact; Go's ActiveScanner.AuditSession audits items concurrently, so exactness
//     has to be enforced at run time instead.
//   - Rust's `Frequency` enum is a parsed AST node; Go's bcheck parser records the same five
//     `given` forms as a string on Check.Given, so DispatchScopeForGiven keys off that string.
package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
)

// OptUint32 is Rust's Option<u32> as a comparable Go value.
//
// Absent and zero are different answers throughout this file: zero *disables* a breaker (that is
// how Burp's shipped "Never stop audit due to application errors" preset switches task pausing off),
// while absent means "this config file does not set the key, inherit the default". A plain uint32
// with a "0 means unset" convention would make the shipped presets unrepresentable.
type OptUint32 struct {
	Value uint32
	Set   bool
}

// SomeUint32 is a set option, the counterpart of Rust's `Some(v)`.
func SomeUint32(v uint32) OptUint32 { return OptUint32{Value: v, Set: true} }

// DispatchScope is how often a check runs — `burp.Zcud`'s seven dispatch scopes.
//
// Listed coarsest-first, which is also the order this engine dispatches them in: a host that has
// stopped answering should be discovered once by the host-scoped checks, not rediscovered by every
// request-scoped check afterwards. (`Zcud` declares them in a different order; the membership is
// what is recovered, the ordering is a choice made here.)
type DispatchScope int

const (
	// DispatchScopePerHost runs once per host. `Zcud::getActivePerHostChecksFactory`.
	DispatchScopePerHost DispatchScope = iota
	// DispatchScopePerPath runs once per path, ignoring the query string.
	// `Zcud::getActivePerPathChecksFactory`.
	DispatchScopePerPath
	// DispatchScopePerUrl runs once per URL, i.e. per path *and* query.
	// `Zcud::getActivePerUrlChecksFactory`.
	DispatchScopePerUrl
	// DispatchScopePerRequest runs once per captured request.
	// `Zcud::getActivePerRequestChecksFactory`.
	DispatchScopePerRequest
	// DispatchScopeInSessionPerRequest runs per request, but only while the session is valid.
	// `Zcud::getInSessionActivePerRequestChecksFactory`.
	DispatchScopeInSessionPerRequest
	// DispatchScopePerInsertionPoint runs once per insertion point — Burp's cost centre.
	// `Zcud::getActivePerInsertionPointChecksFactory`.
	DispatchScopePerInsertionPoint
	// DispatchScopeStoredPerInsertionPoint runs per insertion point, threading a second stored
	// request for second-order checks. `Zcud::getStoredActivePerInsertionPointChecksFactory`.
	DispatchScopeStoredPerInsertionPoint
)

// DispatchScopeAll is all seven, in dispatch order — so a caller planning work walks scopes
// coarsest-first without hard-coding which scopes exist.
var DispatchScopeAll = [7]DispatchScope{
	DispatchScopePerHost,
	DispatchScopePerPath,
	DispatchScopePerUrl,
	DispatchScopePerRequest,
	DispatchScopeInSessionPerRequest,
	DispatchScopePerInsertionPoint,
	DispatchScopeStoredPerInsertionPoint,
}

// DispatchScopeForGiven maps a BCheck `given` clause to the scope it binds to, reporting false when
// the check is passive.
//
// BCheck's grammar reaches four of the seven. DispatchScopePerUrl has no `given` form;
// DispatchScopeInSessionPerRequest needs session handling this package does not have;
// DispatchScopePerInsertionPoint needs payload placement, which the bcheck evaluator now
// provides (the scope is reachable — see IsReachable); DispatchScopeStoredPerInsertionPoint has
// no `given` form either. DispatchScope.IsReachable states that gap rather than leaving it
// implied.
//
// The argument is Check.Given — the Go parser's record of the same five forms Rust's `Frequency`
// enum carries, so `given response` is the passive scanner and not an active dispatch scope at all.
func DispatchScopeForGiven(given string) (DispatchScope, bool) {
	switch strings.ToLower(strings.TrimSpace(given)) {
	case "host":
		return DispatchScopePerHost, true
	case "path":
		return DispatchScopePerPath, true
	case "request":
		return DispatchScopePerRequest, true
	case "insertion point":
		return DispatchScopePerInsertionPoint, true
	}
	// `given response` — and anything the parser could not classify — has no active dispatch scope.
	return DispatchScopePerHost, false
}

// IsReachable reports whether this engine can actually dispatch the scope today.
//
// DispatchScopePerInsertionPoint became reachable when the corpus's active checks were wired in:
// the check's run covers every point of one request internally (Enumerate), so one admission per
// request admits the whole point set.
//
// DispatchScopeStoredPerInsertionPoint became reachable when StoredCheckDescriptors bound ten
// native checks to it. Until then it deliberately yielded no unit, so nothing could appear to have
// been audited under a scope with no implementation behind it. Leaving it unreachable *after*
// binding checks to it inverted that protection into the harm it was guarding against: all ten
// rows counted as runnable coverage while the engine admitted no work to them, so every one could
// only ever report "unsupported" - and nothing in the registry said so.
func (s DispatchScope) IsReachable() bool {
	switch s {
	case DispatchScopePerHost, DispatchScopePerPath, DispatchScopePerUrl, DispatchScopePerRequest,
		DispatchScopePerInsertionPoint, DispatchScopeStoredPerInsertionPoint:
		return true
	}
	return false
}

// UnitKey is the key identifying one dispatch unit of this scope, reporting false when the scope is
// not reachable — an unreachable scope must yield no unit rather than a plausible-looking one.
//
// The keys nest: every per-request unit sits inside a per-URL unit, inside a per-path unit, inside
// a per-host unit. TLS is part of the host key because `http://h` and `https://h` are different
// origins and can serve different applications.
func (s DispatchScope) UnitKey(ex *core.Exchange) (string, bool) {
	if ex == nil {
		return "", false
	}
	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	origin := fmt.Sprintf("%s://%s:%d", scheme, ex.Host, ex.Port)
	// Exchange.Path is the request target, so it carries the query string when there is one. A path
	// unit is that target with the query removed.
	pathOnly := ex.Path
	if i := strings.IndexByte(pathOnly, '?'); i >= 0 {
		pathOnly = pathOnly[:i]
	}
	// The request-content fingerprint (6n4d): appended to the three URL-keyed scopes so the
	// ledger's collapse is content-aware. Same content = same key (identical work stays
	// collapsed — cross-task dedup's whole point); changed content = a different key, so a
	// second capture of this endpoint whose parameters or body changed is re-admitted and
	// re-audited rather than silently "already covered". The per-request and
	// per-insertion-point scopes already key by ex.ID, which a new capture always has a new
	// one of — appending the fingerprint there would change nothing and cost a longer key.
	// Zero (an exchange minted without the capture seam) keys the way it always did, so
	// restored sessions and tests that build exchanges by hand do not change identity
	// mid-run.
	fp := ""
	if ex.RequestFP != 0 {
		fp = fmt.Sprintf("#fp%x", ex.RequestFP)
	}
	switch s {
	case DispatchScopePerHost:
		return origin + fp, true
	case DispatchScopePerPath:
		return origin + pathOnly + fp, true
	case DispatchScopePerUrl:
		return origin + ex.Path + fp, true
	case DispatchScopePerRequest:
		return fmt.Sprintf("%s#%d", origin, ex.ID), true
	case DispatchScopePerInsertionPoint, DispatchScopeStoredPerInsertionPoint:
		// One request's point set is one unit: the check's run covers every point of this request
		// internally (bcheck.Enumerate), and a second capture of the same request carries the same
		// points and the same base values, so the answer cannot differ. Finer than per-request
		// keying would buy nothing — the ledger exists to collapse identical work, and two
		// captures of one request are identical work.
		//
		// The stored variant keys identically. It differs in what it is handed, not in how often it
		// runs: the same request, plus the prior capture of that endpoint threaded into
		// CheckContext.StoredExchange.
		return fmt.Sprintf("%s#%d", origin, ex.ID), true
	}
	return "", false
}

// Label is the operator-facing name of the scope.
func (s DispatchScope) Label() string {
	switch s {
	case DispatchScopePerHost:
		return "per host"
	case DispatchScopePerPath:
		return "per path"
	case DispatchScopePerUrl:
		return "per URL"
	case DispatchScopePerRequest:
		return "per request"
	case DispatchScopeInSessionPerRequest:
		return "per request, in session"
	case DispatchScopePerInsertionPoint:
		return "per insertion point"
	case DispatchScopeStoredPerInsertionPoint:
		return "per insertion point, stored"
	}
	return "unknown scope"
}

// MarshalJSON writes the label rather than the ordinal, so the wire shape stays readable and stays
// stable if a scope is ever inserted into the middle of the list. Rust gets this from serde's
// variant naming; Go has to say it.
func (s DispatchScope) MarshalJSON() ([]byte, error) { return json.Marshal(s.Label()) }

// Disposition is what became of one `(dispatch unit, check)` pair.
//
// Every check considered for an item lands in exactly one of these, and the counts on AuditOutcome
// sum to the number of checks considered. That identity is what makes the bound observable: six of
// these mean "the engine chose not to look", and no caller can mistake them for a negative result.
type Disposition int

const (
	// DispositionRan means dispatched and completed. Its verdict is evidence.
	DispositionRan Disposition = iota
	// DispositionUnsupported means the evaluator declined the check — an unsupported construct, or
	// a check with no implementation behind it. Not a result.
	DispositionUnsupported
	// DispositionSendFailed means a probe could not be sent or read, so the check never saw its own
	// response.
	DispositionSendFailed
	// DispositionAlreadyCovered means not admitted: an identical `(dispatch unit, check)` already
	// ran in this session.
	DispositionAlreadyCovered
	// DispositionTimeBudgetSpent means not admitted: the wall-clock budget was spent.
	DispositionTimeBudgetSpent
	// DispositionRequestBudgetSpent means not admitted: the outbound-request budget was spent.
	DispositionRequestBudgetSpent
	// DispositionUnitAbandoned means not admitted: consecutive check failures abandoned the rest of
	// this dispatch unit.
	DispositionUnitAbandoned
	// DispositionItemFailed means not admitted: consecutive unit failures failed the whole item.
	DispositionItemFailed
	// DispositionSessionPaused means not admitted: the session-level failure breaker paused the run
	// before this item.
	DispositionSessionPaused
)

// DispositionAll is all nine, in the order AuditOutcome.Dispositions reports them.
var DispositionAll = [9]Disposition{
	DispositionRan,
	DispositionUnsupported,
	DispositionSendFailed,
	DispositionAlreadyCovered,
	DispositionTimeBudgetSpent,
	DispositionRequestBudgetSpent,
	DispositionUnitAbandoned,
	DispositionItemFailed,
	DispositionSessionPaused,
}

// IsDispatched reports whether the check actually reached the target. Only these produce evidence.
func (d Disposition) IsDispatched() bool {
	return d == DispositionRan || d == DispositionSendFailed
}

// StoppedLooking reports whether the engine declined to admit the work — the reason a clean result
// here would be a lie.
func (d Disposition) StoppedLooking() bool {
	switch d {
	case DispositionRan, DispositionUnsupported, DispositionSendFailed:
		return false
	}
	return true
}

// String is the short name, matching what serde emits for the Rust enum. Used on the wire and in
// log lines; Explanation is the operator-facing sentence.
func (d Disposition) String() string {
	switch d {
	case DispositionRan:
		return "ran"
	case DispositionUnsupported:
		return "unsupported"
	case DispositionSendFailed:
		return "send failed"
	case DispositionAlreadyCovered:
		return "already covered"
	case DispositionTimeBudgetSpent:
		return "time budget spent"
	case DispositionRequestBudgetSpent:
		return "request budget spent"
	case DispositionUnitAbandoned:
		return "unit abandoned"
	case DispositionItemFailed:
		return "item failed"
	case DispositionSessionPaused:
		return "session paused"
	}
	return "unknown disposition"
}

// Explanation is one line an operator can act on.
func (d Disposition) Explanation() string {
	switch d {
	case DispositionRan:
		return "the check ran to completion"
	case DispositionUnsupported:
		return "the evaluator cannot run this check, so it proves nothing"
	case DispositionSendFailed:
		return "the probe could not be sent or read, so the check saw no evidence"
	case DispositionAlreadyCovered:
		return "an identical check already ran against this dispatch unit"
	case DispositionTimeBudgetSpent:
		return "not started: the audit time budget was already spent"
	case DispositionRequestBudgetSpent:
		return "not started: the outbound request budget was already spent"
	case DispositionUnitAbandoned:
		return "not started: too many consecutive failures on this dispatch unit"
	case DispositionItemFailed:
		return "not started: too many failing dispatch units on this request"
	case DispositionSessionPaused:
		return "not started: the session was paused by the failure breaker"
	}
	return "unknown disposition"
}

// MarshalJSON writes the short name rather than the ordinal. See DispatchScope.MarshalJSON.
func (d Disposition) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// ItemState is the lifecycle of one audit item — one captured exchange being audited.
//
// This is the counterpart of Burp's `Zq5` at the level this engine actually has: `Zq5` tracks an
// insertion point, and until insertion points exist here the item is the finest unit with a
// lifecycle. `NON_TERMINAL_STATUSES` and `COMPLETED_AUDIT_STATUSES` have direct analogues in
// IsTerminal and CompletedAudit.
//
// ItemStatePending and ItemStateAuditing are the two non-terminal states. Because this engine
// resolves an item synchronously, neither is ever observed on a returned outcome — they exist so
// IsTerminal means something, and so a future asynchronous queue has the states it needs rather
// than inventing them later. Pending is the zero value, matching the Rust `#[default]`.
type ItemState int

const (
	// ItemStatePending means admitted to the session, not yet dispatched.
	ItemStatePending ItemState = iota
	// ItemStateAuditing means dispatch is in progress.
	ItemStateAuditing
	// ItemStateAudited means every check reached a disposition; the item is finished.
	ItemStateAudited
	// ItemStateBounded means a budget was spent before every check was dispatched. Not a failure,
	// and not a clean audit either — this is precisely the distinction Burp's `LIMIT_EXCEEDED`
	// collapses by presenting abandoned work as a finished item.
	ItemStateBounded
	// ItemStateFailed means the item breaker tripped: too many consecutive dispatch units failed.
	ItemStateFailed
	// ItemStatePaused means the session breaker tripped before this item was reached. Nothing was
	// sent.
	ItemStatePaused
	// ItemStateOutOfScope means refused before any traffic: the host is not in the engagement scope.
	ItemStateOutOfScope
	// ItemStateUnauditable means there is nothing to audit: the exchange is missing or has no
	// response yet.
	ItemStateUnauditable
)

// ItemStateAll is all eight, so a caller can build a histogram without hard-coding which states
// exist — mirrors DispositionAll and CoverageStateAll for the same reason.
var ItemStateAll = [8]ItemState{
	ItemStatePending,
	ItemStateAuditing,
	ItemStateAudited,
	ItemStateBounded,
	ItemStateFailed,
	ItemStatePaused,
	ItemStateOutOfScope,
	ItemStateUnauditable,
}

// IsTerminal is Burp's `NON_TERMINAL_STATUSES`, inverted: false while work is still outstanding on
// this item.
func (s ItemState) IsTerminal() bool {
	return s != ItemStatePending && s != ItemStateAuditing
}

// CompletedAudit is Burp's `COMPLETED_AUDIT_STATUSES`: the item finished with no work outstanding.
//
// "No work outstanding" rather than "every check sent a request", because a check refused as
// DispositionAlreadyCovered *was* run — against an earlier item covering the same dispatch unit.
// Counting scope collapse as incomplete would make the saving look like a coverage regression,
// which is backwards.
//
// Deliberately false for ItemStateBounded, ItemStateFailed and ItemStatePaused. Those items have
// work the engine declined and did not make up anywhere else, and treating them as audited is how a
// coverage claim drifts from what ran.
func (s ItemState) CompletedAudit() bool { return s == ItemStateAudited }

// Dispatched reports whether checks were dispatched against this item, so its disposition counts
// should account for every check considered.
func (s ItemState) Dispatched() bool {
	switch s {
	case ItemStateAudited, ItemStateBounded, ItemStateFailed:
		return true
	}
	return false
}

// Label is the operator-facing name of the state.
func (s ItemState) Label() string {
	switch s {
	case ItemStatePending:
		return "pending"
	case ItemStateAuditing:
		return "auditing"
	case ItemStateAudited:
		return "audited"
	case ItemStateBounded:
		return "bounded"
	case ItemStateFailed:
		return "failed"
	case ItemStatePaused:
		return "paused"
	case ItemStateOutOfScope:
		return "out of scope"
	case ItemStateUnauditable:
		return "unauditable"
	}
	return "unknown state"
}

// MarshalJSON writes the label rather than the ordinal. See DispatchScope.MarshalJSON.
func (s ItemState) MarshalJSON() ([]byte, error) { return json.Marshal(s.Label()) }

// AuditConfig holds the budgets and circuit breakers for an audit run.
//
// The four breaker fields are Burp's `scanner/error_handling/*` keys, renamed for the unit this
// engine has (a dispatch unit, not an insertion point). Zero disables a breaker, which is how the
// shipped "Never stop audit due to application errors" preset switches off task pausing while
// leaving the per-item breakers armed.
//
// This sits alongside ScanConfig rather than replacing it, and the two do not overlap: ScanConfig
// answers "which checks are in the set", AuditConfig answers "how much work may be admitted, and
// when to stop". The one field that could have disagreed — a wall-clock timeout — is not duplicated;
// see ActiveScanner.AuditConfig for how ScanConfig.Timeout feeds this.
//
// The `scanner/issues_reported/*` and `scanner/insertion_point_types/*` keys are the sanctioned
// exception: a shipped configuration names check classes and point classes a run must honour, and
// a preset overlay (BuiltInConfig.Apply) writes them here. The overlay is an approximation and
// auditLevelNotes says exactly where it bends.
// DefaultLightAuditSamplePerKind is the inherited light-audit threshold (7bkj): twenty
// CLEAN same-(kind, host) points in one run. Burp's own bank does not name a number; twenty
// is a prior strong enough that a 21st identical-clean point is evidence the type is
// handled uniformly on this host, and small enough that a genuinely varied surface breaks
// it long before it skips anything meaningful.
const DefaultLightAuditSamplePerKind uint32 = 20

// DefaultAutoBackoffMs is the inherited per-step backoff after a 429/503 (fkl8): two
// seconds — the range Burp's own auto_backoff operates in, long enough for a per-minute
// token bucket to refill a little between steps, short enough that a rate-limited audit
// still makes progress inside a normal run's time budget.
const DefaultAutoBackoffMs uint32 = 2000

type AuditConfig struct {
	// TimeBudget is the wall-clock ceiling for the whole run.
	TimeBudget time.Duration
	// MaxRequests is the ceiling on outbound probe requests for the whole run. Unset leaves it
	// uncapped.
	//
	// Enforced at admission: once the count is reached no further check is *started*. A check
	// already running may finish its own probes, so the true total can exceed the ceiling by one
	// check's worth. Bounding admission is the point — a check is never killed halfway and its
	// completed work never thrown away.
	MaxRequests OptUint32
	// ConsecutiveCheckFailuresToAbandonUnit is Burp's
	// `consecutive_audit_check_failures_to_skip_insertion_point`.
	ConsecutiveCheckFailuresToAbandonUnit uint32
	// ConsecutiveUnitFailuresToFailItem is Burp's
	// `consecutive_insertion_point_failures_to_fail_audit_item`.
	ConsecutiveUnitFailuresToFailItem uint32
	// PauseSessionAfterFailedItems is Burp's `pause_task_failed_audit_item_count`.
	PauseSessionAfterFailedItems uint32
	// PauseSessionAtFailedItemPercentage is Burp's `pause_task_failed_audit_item_percentage`.
	PauseSessionAtFailedItemPercentage uint8
	// Ledger is an optional admission ledger that outlives this run. Nil — the default — gives each
	// run a fresh one, which is right for a one-shot audit: the caller asked for these exchanges to
	// be audited and nothing earlier should refuse that work.
	//
	// It exists because the live sweep is not one-shot. The sweep calls AuditSession every three
	// seconds forever, so a per-run ledger resets scope collapse on every tick, and every
	// `given host` and `given path` check re-dispatches against the same host every three seconds
	// for the life of the process. Against trickling proxy traffic that was invisible. Against a
	// crawl it is dominant, and it would look exactly like the crawler causing a request storm.
	//
	// A shared ledger is the fix and it is not free: it is the one piece of audit state that grows
	// with the size of the site rather than with the size of the batch. A caller that shares one is
	// responsible for bounding it — see AuditLedger.Units and the sweep's own unit cap.
	Ledger *AuditLedger
	// Items is an optional queue that retains what the engine decided about each item, so a surface
	// outside the call can read it. Nil — the default — keeps every existing caller's cost exactly
	// where it was: a CLI audit and a unit test allocate nothing and enumerate nothing.
	//
	// Separate from Ledger, and deliberately so. Ledger is load-bearing: it decides what is admitted,
	// and dropping it changes what the engine does. Items is pure observation: dropping it changes
	// only what can be read afterwards. Folding the two into one field would make a reporting surface
	// able to alter admission, which is the wrong direction of dependency for the thing whose job is
	// to say what the engine did.
	Items *AuditItemLedger
	// PassiveChecks is Burp's `scanner/issues_reported/scan_type_passive`: false turns off the
	// passive check families for this run (auditLevelPassiveFamilies). Unset inherits the base
	// ScanConfig switch set.
	PassiveChecks OptUint32
	// LightActiveChecks, MediumActiveChecks and IntrusiveActiveChecks are Burp's
	// `scan_type_light_active`, `scan_type_medium_active` and `scan_type_intrusive_active`. This
	// engine has no per-check intrusiveness ranking, so the three tiers collapse to one gate: every
	// tier that is set to false turns the active families off; any tier set true leaves the base
	// switch set alone. auditLevelNotes records the approximation.
	LightActiveChecks     OptUint32
	MediumActiveChecks    OptUint32
	IntrusiveActiveChecks OptUint32
	// JavaScriptAnalysis is Burp's `scanner/issues_reported/scan_type_javascript_analysis`: false
	// turns off the DOM family (ScanConfig.CheckDOM) for this run.
	JavaScriptAnalysis OptUint32
	// InsertionKinds names the bcheck point classes this run enumerates, overriding the engine
	// default (DefaultProbeInsertionKinds) when non-empty. Written by the
	// `scanner/insertion_point_types/*` preset keys; a run-level caller may set it directly.
	InsertionKinds []string
	// StoreQueueItems is Burp's `scanner/issues_reported/store_issues_within_queue_items`: false
	// asks the caller that owns the queue not to attach it. Unset or true leaves the caller's own
	// behaviour alone — the engine never builds the queue itself.
	StoreQueueItems OptUint32
	// MaxInsertionPointsPerRequest is Burp's
	// `scanner/misc_insertion_point_options/max_insertion_points_per_base_request`: how many
	// insertion points one base request may yield before the rest are dropped and reported.
	//
	// Unset takes bcheck.DefaultMaxInsertionPoints (30, Burp's own shipped default). A set value of
	// zero is NOT "no ceiling" and is not accepted anywhere an operator can reach — it would
	// enumerate nothing and audit nothing while reporting a completed run, so the parser and the
	// write endpoint refuse it by name rather than clamping it to something the operator did not
	// ask for.
	MaxInsertionPointsPerRequest OptUint32
	// NestedInsertionPoints is Burp's
	// `scanner/misc_insertion_point_options/use_nested_insertion_points`: false stops the
	// enumerator expanding the JSON/base64/XML structure inside a parameter value, so only the flat
	// parameter is probed.
	//
	// Unset inherits the engine default, which is on — Burp ships it true. The points given up are
	// counted onto the run's own record as a bcheck.Declined, so a run with it off cannot be
	// mistaken for one that found nothing nested.
	NestedInsertionPoints OptUint32
	// LightAuditSamplePerKind is the light-audit tier's threshold (7bkj): after this many
	// CLEAN same-(kind, host) points in one run, further points of that type on that host
	// are skipped as repetitive — Burp's "Skipped due to repetitive behavior" (Zq5). Unset
	// inherits DefaultLightAuditSamplePerKind; set-and-zero turns the tier off, which is a
	// real choice (an engagement that must pay full price for every point, e.g. a
	// compliance sweep, can say so) and must not read as unset.
	LightAuditSamplePerKind OptUint32
	// AutoBackoffMs is the per-step delay the dispatch loop applies after a probe came back
	// 429 or 503 (burpsy-react-ui-fkl8) — Burp's resource-pool auto_backoff, in the
	// smallest honest shape: a counter and a sleep, not a resource-pool rewrite. Unset
	// inherits the default (see DefaultAutoBackoffMs); zero disables the backoff, which is
	// a real choice (an operator who knows the target's limiter resets per-minute may
	// prefer to let the request budget eat the 429s) and must not read as "unset".
	AutoBackoffMs OptUint32
	// SkipAllTestsForParameters is Burp's
	// scanner/ignored_insertion_points/skip_all_tests_for_parameters: parameters an operator
	// exempted from testing entirely, by name. A named parameter's points are dropped from
	// every kind before the per-request cap, and the drop is a bcheck.Declined so the audit
	// item's queue row says the parameter was skipped rather than absent.
	//
	// Burp's softer sibling — skip_server_side_injection_for_parameters, which exempts only
	// the injection checks — is deliberately not modelled: burpsy's check families do not yet
	// partition into server-side-injection versus rest, and a skip list that could not name
	// what it exempts would be a control silently testing more than it claims to skip.
	SkipAllTestsForParameters []string
}

// enumerateOptions is how this configuration tunes the insertion-point enumerator.
//
// One method rather than two field reads at each call site: the probe harness, the audit-item
// ledger and the check context all need the same pair, and a site that read the cap but forgot the
// nested flag would enumerate a point set no configuration asked for.
func (cfg AuditConfig) enumerateOptions() bcheck.EnumerateOptions {
	opts := bcheck.EnumerateOptions{Max: bcheck.DefaultMaxInsertionPoints}
	if cfg.MaxInsertionPointsPerRequest.Set && cfg.MaxInsertionPointsPerRequest.Value > 0 {
		opts.Max = int(cfg.MaxInsertionPointsPerRequest.Value)
	}
	// Set-and-zero is the only spelling that turns nesting off. Unset inherits the engine default
	// (on), which is what every caller had before the key existed.
	if cfg.NestedInsertionPoints.Set && cfg.NestedInsertionPoints.Value == 0 {
		opts.NoNested = true
	}
	// The operator's parameter skip list rides every enumeration the run makes — probe
	// harness, audit-item ledger and check context — because enumerateOptions is the one
	// place all three read.
	opts.SkipAllTestsForParameters = cfg.SkipAllTestsForParameters
	return opts
}

// InsertionKindsOrDefault is the point classes this configuration enumerates, resolved: its own
// list when it carries one, DefaultProbeInsertionKinds otherwise. The exported counterpart of
// insertionKinds, for surfaces outside this package that report what a run would do.
func (cfg AuditConfig) InsertionKindsOrDefault() []string {
	return cfg.insertionKinds()
}

// MaxInsertionPointsPerBaseRequest is the ceiling this configuration enumerates under, resolved:
// the operator's value when they set one, bcheck.DefaultMaxInsertionPoints otherwise.
//
// Exported because the audit-queue row reports the threshold behind every skipped-past-the-limit
// point, and reporting the constant there while the run used something else is precisely the
// mismatch this key was filed for.
func (cfg AuditConfig) MaxInsertionPointsPerBaseRequest() int {
	return cfg.enumerateOptions().Max
}

// NestedInsertionPointsEnabled reports whether this configuration expands nested points.
func (cfg AuditConfig) NestedInsertionPointsEnabled() bool {
	return !cfg.enumerateOptions().NoNested
}

// DefaultAuditBudget is the default wall-clock budget for one audit run.
//
// Sized so a completely unresponsive host fails fast rather than occupying a goroutine for the
// product of every check and its read timeout.
const DefaultAuditBudget = 120 * time.Second

// insertionKinds is the point classes this run enumerates: the configuration's own list when the
// overlay or the caller set one, the engine default otherwise. The "none" sentinel from a
// fully-disabled overlay is returned as-is — no kind matches it, which is the point.
func (cfg AuditConfig) insertionKinds() []string {
	if len(cfg.InsertionKinds) > 0 {
		return cfg.InsertionKinds
	}
	return DefaultProbeInsertionKinds
}

// DefaultAuditConfig is the shipped default.
//
// Breaker defaults are the values every shipped preset that sets them uses: 2 and 2 for the
// per-item breakers, and 0 — disabled — for session pausing. Pausing a whole run is a decision an
// operator should opt into, not one that happens because a handful of requests timed out.
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		TimeBudget:                            DefaultAuditBudget,
		MaxRequests:                           OptUint32{},
		ConsecutiveCheckFailuresToAbandonUnit: 2,
		ConsecutiveUnitFailuresToFailItem:     2,
		PauseSessionAfterFailedItems:          0,
		PauseSessionAtFailedItemPercentage:    0,
	}
}

// AuditConfigWithoutBreakers has every breaker off. The counterpart of Burp's `Zgff` "Disable error
// handling" preset, which sets all five error-handling keys to 0.
func AuditConfigWithoutBreakers() AuditConfig {
	cfg := DefaultAuditConfig()
	cfg.ConsecutiveCheckFailuresToAbandonUnit = 0
	cfg.ConsecutiveUnitFailuresToFailItem = 0
	cfg.PauseSessionAfterFailedItems = 0
	cfg.PauseSessionAtFailedItemPercentage = 0
	return cfg
}

// BuiltInConfig is one of Burp's shipped scan configurations, reduced to the keys this engine
// implements.
//
// Burp ships 29 configurations in `resources/BuiltInConfigs/`. Six set `scanner/error_handling/*`
// or `scanner/audit_optimization/maximum_crawl_and_audit_time`; the other 23 configure crawling,
// insertion-point selection, parameter relocation and JavaScript analysis, none of which this
// package has. Those six are transcribed here and the rest are omitted rather than represented by
// knobs that do nothing.
//
// A field is unset when the source file does not set the key. That is not the same as zero: zero
// disables a breaker, unset inherits DefaultAuditConfig.
type BuiltInConfig struct {
	Name                                  string
	ConsecutiveCheckFailuresToAbandonUnit OptUint32
	ConsecutiveUnitFailuresToFailItem     OptUint32
	PauseSessionAfterFailedItems          OptUint32
	PauseSessionAtFailedItemPercentage    OptUint32
	// MaximumAuditTimeMinutes is `scanner/audit_optimization/maximum_crawl_and_audit_time`.
	MaximumAuditTimeMinutes OptUint32

	// The eight `scanner/insertion_point_types/*` keys. Each is one point class the run enumerates;
	// true keeps it, false removes it from the engine default set. The mapping to bcheck kinds is
	// insertionPointKindFor.
	InsertURLParams       OptUint32
	InsertBodyParams      OptUint32
	InsertCookies         OptUint32
	InsertHTTPHeaders     OptUint32
	InsertParamName       OptUint32
	InsertURLPathFilename OptUint32
	InsertURLPathFolders  OptUint32
	InsertEntireBody      OptUint32

	// The six `scanner/modifying_parameter_locations/*` keys: whether the run also probes a
	// parameter that has been *moved* to another location, which is how Burp finds checks that
	// resolve a parameter differently depending on where it arrives. Each maps 1:1 onto the
	// bcheck relocation kind of the same name; `url` in Burp's spelling is the query string.
	RelocateBodyToURL    OptUint32
	RelocateBodyToCookie OptUint32
	RelocateURLToBody    OptUint32
	RelocateURLToCookie  OptUint32
	RelocateCookieToBody OptUint32
	RelocateCookieToURL  OptUint32

	// The nine `scanner/issues_reported/*` keys. See AuditConfig for how each is honoured; the three
	// per-issue selection keys (scan_only_selected_issues, select_individual_issues, selected_issues)
	// have no field because this engine has no per-issue selection — their rows carry no read and
	// Apply reports them unapplied rather than pretending.
	PassiveChecks         OptUint32
	LightActiveChecks     OptUint32
	MediumActiveChecks    OptUint32
	IntrusiveActiveChecks OptUint32
	JavaScriptAnalysis    OptUint32
	StoreQueueItems       OptUint32

	// The two `scanner/misc_insertion_point_options/*` keys: how many insertion points one base
	// request may yield, and whether the enumerator expands the structure inside a parameter value.
	// Burp ships them as 30 and true.
	MaxInsertionPointsPerRequest OptUint32
	UseNestedInsertionPoints     OptUint32

	// UnrepresentableKeys records keys a parsed source named that this engine has no field for — the
	// per-issue selection trio. Only ParseBurpConfig fills it; the six transcribed presets never do.
	// ApplyWithReport reports them unapplied, so a loaded configuration never drops a key silently.
	UnrepresentableKeys []string
}

// builtInConfigKeys is the one description of what a shipped configuration can change.
//
// Both Apply and BuiltInConfig.Keys read this table, which is the point: SCAN-03 asks an operator to
// be able to *choose* a configuration, and a chooser has to be told what each one does. The obvious
// way to tell them — a hand-written list of key names in whatever surface presents the choice — is a
// second copy of this knowledge that drifts the first time a key is added, and drifts silently,
// because a listing that is missing a key still renders. So the list an operator reads and the
// overlay the engine performs are generated from the same rows, and a key can only exist here once.
//
// read and apply are a pair per row: read pulls the preset's value for the key, apply is the only
// place that knows which AuditConfig field it lands in and in what unit. Test
// Test_every_built_in_config_field_has_a_key_row asserts every OptUint32 field on BuiltInConfig has
// exactly one row.
//
// applies records whether setting the key changes what the engine does. A false row is represented
// on the wire and in Apply's report — never silently dropped — because this engine has no
// mechanism behind it. The three per-issue selection keys are the only ones.
var builtInConfigKeys = []struct {
	// name is the key as this engine's own API spells it.
	name string
	// burpKey is the key as Burp's configuration JSON spells it, so an operator comparing against
	// Burp's own UI can find the same knob.
	burpKey string
	// what is one line an operator can act on: what changes when this key is set.
	what string
	// read pulls the key's value from a preset. Nil on an applies=false row.
	read func(BuiltInConfig) OptUint32
	// apply overlays the value onto a run configuration. Nil on an applies=false row.
	apply func(*AuditConfig, uint32)
	// max is the largest value this key can carry, or 0 for unbounded. The parser refuses a larger
	// one rather than truncating it: a percentage of 300 is a corrupted file, and loading it as 44
	// would run a configuration nobody wrote.
	max uint32
	// min is the smallest value this key can carry, or 0 for no floor. The parser refuses a smaller
	// one for the same reason it refuses a larger one, and one key needs it: an insertion-point
	// ceiling of zero enumerates nothing, so a run under it would audit nothing and report a
	// completed audit. Clamping that to 1 would run a configuration nobody wrote; refusing names
	// the value.
	min uint32
	// applies reports whether the key changes engine behaviour when set.
	applies bool
}{
	{
		name:    "consecutive_check_failures_to_abandon_unit",
		burpKey: "scanner/error_handling/consecutive_audit_check_failures_to_skip_insertion_point",
		what:    "how many checks may fail in a row before the rest of that dispatch unit is abandoned (0 disables the breaker)",
		read:    func(c BuiltInConfig) OptUint32 { return c.ConsecutiveCheckFailuresToAbandonUnit },
		apply:   func(a *AuditConfig, v uint32) { a.ConsecutiveCheckFailuresToAbandonUnit = v },
		applies: true,
	},
	{
		name:    "consecutive_unit_failures_to_fail_item",
		burpKey: "scanner/error_handling/consecutive_insertion_point_failures_to_fail_audit_item",
		what:    "how many dispatch units may be abandoned in a row before the whole item is failed (0 disables the breaker)",
		read:    func(c BuiltInConfig) OptUint32 { return c.ConsecutiveUnitFailuresToFailItem },
		apply:   func(a *AuditConfig, v uint32) { a.ConsecutiveUnitFailuresToFailItem = v },
		applies: true,
	},
	{
		name:    "pause_session_after_failed_items",
		burpKey: "scanner/error_handling/pause_task_failed_audit_item_count",
		what:    "how many failed items pause the whole session (0 means never pause on a count)",
		read:    func(c BuiltInConfig) OptUint32 { return c.PauseSessionAfterFailedItems },
		apply:   func(a *AuditConfig, v uint32) { a.PauseSessionAfterFailedItems = v },
		applies: true,
	},
	{
		name:    "pause_session_at_failed_item_percentage",
		burpKey: "scanner/error_handling/pause_task_failed_audit_item_percentage",
		what:    "the percentage of failed items that pauses the whole session (0 means never pause on a percentage)",
		read:    func(c BuiltInConfig) OptUint32 { return c.PauseSessionAtFailedItemPercentage },
		apply:   func(a *AuditConfig, v uint32) { a.PauseSessionAtFailedItemPercentage = uint8(v) },
		max:     100,
		applies: true,
	},
	{
		name:    "maximum_audit_time_minutes",
		burpKey: "scanner/audit_optimization/maximum_crawl_and_audit_time",
		what:    "the wall-clock ceiling for the whole run, in minutes",
		read:    func(c BuiltInConfig) OptUint32 { return c.MaximumAuditTimeMinutes },
		apply:   func(a *AuditConfig, v uint32) { a.TimeBudget = time.Duration(v) * time.Minute },
		applies: true,
	},

	// scanner/insertion_point_types — where the audit enumerates insertion points. Setting any of
	// these keys materialises the run's point set from the engine default and then applies each
	// set key on top; see Apply.
	{
		name:    "insert_url_params",
		burpKey: "scanner/insertion_point_types/insert_url_params",
		what:    "whether query-string parameters are enumerated as insertion points",
		read:    func(c BuiltInConfig) OptUint32 { return c.InsertURLParams },
		apply:   applyInsertionKind("query"),
		applies: true,
	},
	{
		name:    "insert_body_params",
		burpKey: "scanner/insertion_point_types/insert_body_params",
		what:    "whether form and structured body parameters are enumerated as insertion points",
		read:    func(c BuiltInConfig) OptUint32 { return c.InsertBodyParams },
		apply:   applyInsertionKind("body"),
		applies: true,
	},
	{
		name:    "insert_cookies",
		burpKey: "scanner/insertion_point_types/insert_cookies",
		what:    "whether cookies are enumerated as insertion points",
		read:    func(c BuiltInConfig) OptUint32 { return c.InsertCookies },
		apply:   applyInsertionKind("cookie"),
		applies: true,
	},
	{
		name:    "insert_http_headers",
		burpKey: "scanner/insertion_point_types/insert_http_headers",
		what:    "whether request headers are enumerated as insertion points",
		read:    func(c BuiltInConfig) OptUint32 { return c.InsertHTTPHeaders },
		apply:   applyInsertionKind("header"),
		applies: true,
	},
	{
		name:    "insert_param_name",
		burpKey: "scanner/insertion_point_types/insert_param_name",
		what:    "whether parameter *names* (URL and body) are enumerated as insertion points",
		read:    func(c BuiltInConfig) OptUint32 { return c.InsertParamName },
		apply:   applyInsertionKind("param_name_url", "param_name_body"),
		applies: true,
	},
	{
		name:    "insert_url_path_filename",
		burpKey: "scanner/insertion_point_types/insert_url_path_filename",
		what:    "whether the URL path's final segment is enumerated as an insertion point",
		read:    func(c BuiltInConfig) OptUint32 { return c.InsertURLPathFilename },
		apply:   applyInsertionKind("url_path_filename"),
		applies: true,
	},
	{
		name:    "insert_url_path_folders",
		burpKey: "scanner/insertion_point_types/insert_url_path_folders",
		what:    "whether the URL path's folder segments are enumerated as insertion points",
		read:    func(c BuiltInConfig) OptUint32 { return c.InsertURLPathFolders },
		apply:   applyInsertionKind("url_path_folder"),
		applies: true,
	},
	{
		name:    "insert_entire_body",
		burpKey: "scanner/insertion_point_types/insert_entire_body",
		what:    "whether the whole body is enumerated as one insertion point, independent of any parameter",
		read:    func(c BuiltInConfig) OptUint32 { return c.InsertEntireBody },
		apply:   applyInsertionKind("entire_body"),
		applies: true,
	},

	// scanner/modifying_parameter_locations — the six relocations. Each adds (or removes) one
	// relocation kind on top of whatever point set the preset selected: a preset that names only a
	// relocation starts from the engine's own default set, because these keys are additions to the
	// standard points rather than a replacement for them (see applyParameterLocations).
	{
		name:    "relocate_body_to_url",
		burpKey: "scanner/modifying_parameter_locations/body_to_url",
		what:    "whether a request also probes each form body parameter as if it had been moved into the query string",
		read:    func(c BuiltInConfig) OptUint32 { return c.RelocateBodyToURL },
		apply:   applyInsertionKind("relocate_body_to_query"),
		applies: true,
	},
	{
		name:    "relocate_body_to_cookie",
		burpKey: "scanner/modifying_parameter_locations/body_to_cookie",
		what:    "whether a request also probes each form body parameter as if it had been moved into a cookie",
		read:    func(c BuiltInConfig) OptUint32 { return c.RelocateBodyToCookie },
		apply:   applyInsertionKind("relocate_body_to_cookie"),
		applies: true,
	},
	{
		name:    "relocate_url_to_body",
		burpKey: "scanner/modifying_parameter_locations/url_to_body",
		what:    "whether a request also probes each query parameter as if it had been moved into the form body",
		read:    func(c BuiltInConfig) OptUint32 { return c.RelocateURLToBody },
		apply:   applyInsertionKind("relocate_query_to_body"),
		applies: true,
	},
	{
		name:    "relocate_url_to_cookie",
		burpKey: "scanner/modifying_parameter_locations/url_to_cookie",
		what:    "whether a request also probes each query parameter as if it had been moved into a cookie",
		read:    func(c BuiltInConfig) OptUint32 { return c.RelocateURLToCookie },
		apply:   applyInsertionKind("relocate_query_to_cookie"),
		applies: true,
	},
	{
		name:    "relocate_cookie_to_body",
		burpKey: "scanner/modifying_parameter_locations/cookie_to_body",
		what:    "whether a request also probes each cookie as if it had been moved into the form body",
		read:    func(c BuiltInConfig) OptUint32 { return c.RelocateCookieToBody },
		apply:   applyInsertionKind("relocate_cookie_to_body"),
		applies: true,
	},
	{
		name:    "relocate_cookie_to_url",
		burpKey: "scanner/modifying_parameter_locations/cookie_to_url",
		what:    "whether a request also probes each cookie as if it had been moved into the query string",
		read:    func(c BuiltInConfig) OptUint32 { return c.RelocateCookieToURL },
		apply:   applyInsertionKind("relocate_cookie_to_query"),
		applies: true,
	},

	// scanner/issues_reported — which check classes the run admits. The mapping is documented on
	// AuditConfig and auditLevelNotes; per-check intrusiveness ranking does not exist here, so the
	// three Burp tiers collapse to one active gate.
	{
		name:    "scan_type_passive",
		burpKey: "scanner/issues_reported/scan_type_passive",
		what:    "whether the passive check families run (0 turns them off for the run)",
		read:    func(c BuiltInConfig) OptUint32 { return c.PassiveChecks },
		apply:   func(a *AuditConfig, v uint32) { a.PassiveChecks = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_type_light_active",
		burpKey: "scanner/issues_reported/scan_type_light_active",
		what:    "one of Burp's three active tiers; every tier set to 0 turns the active families off (0 here), any set to 1 leaves the base switches alone",
		read:    func(c BuiltInConfig) OptUint32 { return c.LightActiveChecks },
		apply:   func(a *AuditConfig, v uint32) { a.LightActiveChecks = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_type_medium_active",
		burpKey: "scanner/issues_reported/scan_type_medium_active",
		what:    "one of Burp's three active tiers; every tier set to 0 turns the active families off (0 here), any set to 1 leaves the base switches alone",
		read:    func(c BuiltInConfig) OptUint32 { return c.MediumActiveChecks },
		apply:   func(a *AuditConfig, v uint32) { a.MediumActiveChecks = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_type_intrusive_active",
		burpKey: "scanner/issues_reported/scan_type_intrusive_active",
		what:    "one of Burp's three active tiers; every tier set to 0 turns the active families off (0 here), any set to 1 leaves the base switches alone",
		read:    func(c BuiltInConfig) OptUint32 { return c.IntrusiveActiveChecks },
		apply:   func(a *AuditConfig, v uint32) { a.IntrusiveActiveChecks = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_type_javascript_analysis",
		burpKey: "scanner/issues_reported/scan_type_javascript_analysis",
		what:    "whether the DOM-based checks run (0 turns them off for the run)",
		read:    func(c BuiltInConfig) OptUint32 { return c.JavaScriptAnalysis },
		apply:   func(a *AuditConfig, v uint32) { a.JavaScriptAnalysis = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "store_issues_within_queue_items",
		burpKey: "scanner/issues_reported/store_issues_within_queue_items",
		what:    "whether the caller's audit queue retains per-item records (0 asks the caller not to attach it)",
		read:    func(c BuiltInConfig) OptUint32 { return c.StoreQueueItems },
		apply:   func(a *AuditConfig, v uint32) { a.StoreQueueItems = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_only_selected_issues",
		burpKey: "scanner/issues_reported/scan_only_selected_issues",
		what:    "not applied: this engine has no per-issue selection to restrict a scan to",
		applies: false,
	},
	{
		name:    "select_individual_issues",
		burpKey: "scanner/issues_reported/select_individual_issues",
		what:    "not applied: this engine has no per-issue selection, only family switches",
		applies: false,
	},
	{
		name:    "selected_issues",
		burpKey: "scanner/issues_reported/selected_issues",
		what:    "not applied: this engine has no per-issue selection, only family switches",
		applies: false,
	},

	// The rest of Burp's scanner keys, listed so that a configuration naming one is told which key
	// did nothing rather than being left to compare its file against this engine's behaviour. Every
	// key in Burp's 29 shipped configurations has a row here or above; a row with no `read` is
	// reported by ApplyWithReport and never applied, and its `what` says why.
	//
	// This is the honest half of a partial capability: the alternative — omitting the row — made the
	// key invisible, because ApplyWithReport can only name a key it has a row for. A scan
	// configuration that says "follow redirects" and silently does not is the same defect class as a
	// scan that reports a partial result as a complete one.
	{
		name:    "number_of_follow_up_passes",
		burpKey: "scanner/error_handling/number_of_follow_up_passes",
		what:    "not applied: an audit item's checks run once per dispatch unit; this engine has no follow-up pass to repeat them",
		applies: false,
	},
	{
		name:    "consolidate_passive_issues",
		burpKey: "scanner/audit_optimization/consolidate_passive_issues",
		what:    "not applied: the passive tracker already records one finding per issue per response; there is no scan-wide consolidation step to switch",
		applies: false,
	},
	{
		name:    "follow_redirections",
		burpKey: "scanner/audit_optimization/follow_redirections",
		what:    "not applied: redirect following is the sender's policy for the whole engagement, not a per-run audit key this engine reads",
		applies: false,
	},
	{
		name:    "maintain_session",
		burpKey: "scanner/audit_optimization/maintain_session",
		what:    "not applied: this engine does not drive the session coordinator for its own audit probes",
		applies: false,
	},
	{
		name:    "scan_accuracy",
		burpKey: "scanner/audit_optimization/scan_accuracy",
		what:    "not applied: Burp's accuracy presets change which checks run per issue type; here the check set is decided by the family switches",
		applies: false,
	},
	{
		name:    "scan_speed",
		burpKey: "scanner/audit_optimization/scan_speed",
		what:    "not applied: Burp's speed presets trade check coverage for time; a run here is bounded by request budget and wall clock instead",
		applies: false,
	},
	{
		name:    "skip_ineffective_checks",
		burpKey: "scanner/audit_optimization/skip_ineffective_checks",
		what:    "not applied: this engine infers nothing about a check's effectiveness, so it has nothing to skip on",
		applies: false,
	},
	{
		name:    "audit_connect_timeout",
		burpKey: "scanner/audit_project_option_overrides/connect_timeout",
		what:    "not applied: probe timeouts come from the sender's own configuration, which an audit run does not override",
		applies: false,
	},
	{
		name:    "audit_normal_timeout",
		burpKey: "scanner/audit_project_option_overrides/normal_timeout",
		what:    "not applied: probe timeouts come from the sender's own configuration, which an audit run does not override",
		applies: false,
	},
	{
		name:    "quick_scan_url_params",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_url_params",
		what:    "not applied: quick-scan point classes are selected here through scanner/insertion_point_types/*; a second key set naming the same classes would be a second control for one decision",
		applies: false,
	},
	{
		name:    "quick_scan_body_params",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_body_params",
		what:    "not applied: quick-scan point classes are selected here through scanner/insertion_point_types/*; a second key set naming the same classes would be a second control for one decision",
		applies: false,
	},
	{
		name:    "quick_scan_cookies",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_cookies",
		what:    "not applied: quick-scan point classes are selected here through scanner/insertion_point_types/*; a second key set naming the same classes would be a second control for one decision",
		applies: false,
	},
	{
		name:    "quick_scan_http_headers",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_http_headers",
		what:    "not applied: quick-scan point classes are selected here through scanner/insertion_point_types/*; a second key set naming the same classes would be a second control for one decision",
		applies: false,
	},
	{
		name:    "quick_scan_param_name",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_param_name",
		what:    "not applied: quick-scan point classes are selected here through scanner/insertion_point_types/*; a second key set naming the same classes would be a second control for one decision",
		applies: false,
	},
	{
		name:    "quick_scan_entire_body",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_entire_body",
		what:    "not applied: quick-scan point classes are selected here through scanner/insertion_point_types/*; a second key set naming the same classes would be a second control for one decision",
		applies: false,
	},
	{
		name:    "quick_scan_url_path_filename",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_url_path_filename",
		what:    "not applied: quick-scan point classes are selected here through scanner/insertion_point_types/*; a second key set naming the same classes would be a second control for one decision",
		applies: false,
	},
	{
		name:    "quick_scan_url_path_folders",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_url_path_folders",
		what:    "not applied: quick-scan point classes are selected here through scanner/insertion_point_types/*; a second key set naming the same classes would be a second control for one decision",
		applies: false,
	},
	{
		name:    "skip_all_tests_for_parameters",
		burpKey: "scanner/ignored_insertion_points/skip_all_tests_for_parameters",
		what:    "not applied: Burp's value is not a name list but a list of match rules ({enabled, parameter, item, match_type, expression} - e.g. match_type matches_regex over an xml_attribute name), and this engine has neither a rule matcher over parameter type and item nor a list-valued key: every row here reads through OptUint32, so the key has no shape to land in",
		applies: false,
	},
	{
		name:    "skip_server_side_injection_for_parameters",
		burpKey: "scanner/ignored_insertion_points/skip_server_side_injection_for_parameters",
		what:    "not applied: needs the same rule matcher skip_all_tests_for_parameters needs, and additionally a server-side-injection classification of the check set - CheckDescriptor carries a phase and a dispatch scope but no injection-class grouping, so there is no set of checks to exclude a parameter from",
		applies: false,
	},
	{
		name:    "javascript_use_static_analysis",
		burpKey: "scanner/javascript_analysis/use_static_analysis",
		what:    "not applied: DOM analysis is selected as a family (scanner/issues_reported/scan_type_javascript_analysis); this engine has no static-only mode to choose",
		applies: false,
	},
	{
		name:    "javascript_use_dynamic_analysis",
		burpKey: "scanner/javascript_analysis/use_dynamic_analysis",
		what:    "not applied: this engine runs one DOM pass per item and has no separate dynamic-only mode to choose",
		applies: false,
	},
	{
		name:    "javascript_fetch_out_of_scope_resources",
		burpKey: "scanner/javascript_analysis/fetch_out_of_scope_resources",
		what:    "not applied: resource fetching is the DOM engine's own scope policy, not a key an audit run carries",
		applies: false,
	},
	{
		name:    "javascript_request_missing_dependencies",
		burpKey: "scanner/javascript_analysis/request_missing_dependencies",
		what:    "not applied: this engine does not re-request a page's missing script dependencies",
		applies: false,
	},
	{
		name:    "javascript_max_static_time_per_item",
		burpKey: "scanner/javascript_analysis/max_static_time_per_item",
		what:    "not applied: DOM analysis is time-bounded by its own engine, not by the audit configuration",
		applies: false,
	},
	{
		name:    "javascript_max_dynamic_time_per_item",
		burpKey: "scanner/javascript_analysis/max_dynamic_time_per_item",
		what:    "not applied: DOM analysis is time-bounded by its own engine, not by the audit configuration",
		applies: false,
	},
	{
		name:    "max_insertion_points_per_base_request",
		burpKey: "scanner/misc_insertion_point_options/max_insertion_points_per_base_request",
		what:    "how many insertion points one base request may yield before the rest are dropped and reported as skipped past the limit (unset takes Burp's default of 30)",
		read:    func(c BuiltInConfig) OptUint32 { return c.MaxInsertionPointsPerRequest },
		apply:   func(a *AuditConfig, v uint32) { a.MaxInsertionPointsPerRequest = SomeUint32(v) },
		min:     1,
		applies: true,
	},
	{
		name:    "use_nested_insertion_points",
		burpKey: "scanner/misc_insertion_point_options/use_nested_insertion_points",
		what:    "whether the enumerator expands the JSON/base64/XML structure inside a parameter value into its own insertion points (off leaves only the flat parameter, and says how many points it gave up)",
		read:    func(c BuiltInConfig) OptUint32 { return c.UseNestedInsertionPoints },
		apply:   func(a *AuditConfig, v uint32) { a.NestedInsertionPoints = SomeUint32(v) },
		applies: true,
	},
}

// BuiltInConfigKey is one key a shipped configuration can carry, with this preset's value for it or
// the fact that this preset leaves it alone.
//
// Set false is not Value 0: unset inherits the base configuration, zero disables a breaker. Both
// spellings appear in Burp's shipped files and they mean different things, so the two are reported
// separately rather than collapsed into a number.
type BuiltInConfigKey struct {
	// Name is the key as this engine's API spells it.
	Name string `json:"name"`
	// BurpKey is the key as Burp's own configuration JSON spells it.
	BurpKey string `json:"burp_key"`
	// What is one line describing what setting this key changes.
	What string `json:"what"`
	// Value is meaningful only when Set is true.
	Value uint32 `json:"value,omitempty"`
	// Set reports whether this preset's source file sets the key at all.
	Set bool `json:"set"`
	// Applies reports whether setting the key changes what this engine does. False keys are listed
	// anyway — a shipped configuration loads without silently dropping keys — and Apply reports
	// them as unapplied.
	Applies bool `json:"applies"`
}

// BuiltInConfigKeys returns every key this engine's scan-configuration table knows, each carrying
// what setting it changes and whether this engine applies it. `Applies` false means the key is
// accepted, described and reported — never applied.
//
// It is the whole-set counterpart of BuiltInConfig.Keys, which answers the same question for one
// preset. A caller listing what a configuration *could* carry needs this one; a caller showing what
// a particular preset does needs that one.
func BuiltInConfigKeys() []BuiltInConfigKey {
	out := make([]BuiltInConfigKey, 0, len(builtInConfigKeys))
	for _, k := range builtInConfigKeys {
		out = append(out, BuiltInConfigKey{
			Name:    k.name,
			BurpKey: k.burpKey,
			What:    k.what,
			Applies: k.applies,
		})
	}
	return out
}

// Keys returns every key a shipped configuration can carry, in a fixed order, each carrying this
// preset's value or reporting itself unset.
//
// Every key is returned, including the ones this preset does not set. A listing that dropped the unset
// ones would leave an operator unable to tell "this preset leaves the time budget alone" from "this
// engine has no time budget" — the same collapse CheckCoverage exists to prevent, applied to
// configuration rather than to checks.
func (c BuiltInConfig) Keys() []BuiltInConfigKey {
	out := make([]BuiltInConfigKey, 0, len(builtInConfigKeys))
	for _, k := range builtInConfigKeys {
		var v OptUint32
		if k.read != nil {
			v = k.read(c)
		}
		out = append(out, BuiltInConfigKey{
			Name:    k.name,
			BurpKey: k.burpKey,
			What:    k.what,
			Value:   v.Value,
			Set:     v.Set,
			Applies: k.applies,
		})
	}
	return out
}

// insertionPointKindFor maps an insertion_point_types key to the bcheck point classes it governs.
// Every key in the table's insertion section must map to at least one kind — asserted by
// Test_every_insertion_point_key_maps_to_a_bcheck_kind — so a key that lost its mapping cannot
// silently stop selecting points.
var insertionPointKindFor = map[string][]string{
	"insert_url_params":        {"query"},
	"insert_body_params":       {"body"},
	"insert_cookies":           {"cookie"},
	"insert_http_headers":      {"header"},
	"insert_param_name":        {"param_name_url", "param_name_body"},
	"insert_url_path_filename": {"url_path_filename"},
	"insert_url_path_folders":  {"url_path_folder"},
	"insert_entire_body":       {"entire_body"},
}

// applyInsertionKind builds the row's apply: 1 adds the kinds, 0 removes them.
func applyInsertionKind(kinds ...string) func(*AuditConfig, uint32) {
	return func(a *AuditConfig, v uint32) {
		if v != 0 {
			a.InsertionKinds = addKinds(a.InsertionKinds, kinds...)
			return
		}
		a.InsertionKinds = removeKinds(a.InsertionKinds, kinds...)
	}
}

// addKinds appends every kind not already present, preserving order.
func addKinds(kinds []string, add ...string) []string {
	seen := make(map[string]bool, len(kinds)+len(add))
	for _, k := range kinds {
		seen[k] = true
	}
	for _, k := range add {
		if !seen[k] {
			kinds = append(kinds, k)
			seen[k] = true
		}
	}
	return kinds
}

// removeKinds filters kinds in place, preserving order.
func removeKinds(kinds []string, drop ...string) []string {
	dropSet := make(map[string]bool, len(drop))
	for _, k := range drop {
		dropSet[k] = true
	}
	out := kinds[:0]
	for _, k := range kinds {
		if !dropSet[k] {
			out = append(out, k)
		}
	}
	return out
}

// anyInsertionKeySet reports whether the preset touches the insertion_point_types section at all.
func (c BuiltInConfig) anyInsertionKeySet() bool {
	for _, k := range builtInConfigKeys {
		if strings.HasPrefix(k.burpKey, "scanner/insertion_point_types/") && k.read != nil {
			if k.read(c).Set {
				return true
			}
		}
	}
	return false
}

// insertionDefaultKinds is the point set an insertion_point_types overlay starts from: everything
// the eight keys govern, minus entire body. This matches the engine's own default (the four core
// classes) plus the four finer classes Burp's defaults leave on but this engine had no reason to
// enumerate unasked. The overlay is explicit — an operator naming the section is specifying point
// selection — so the base is the full Burp-shaped set rather than the engine's conservative one.
func insertionDefaultKinds() []string {
	return []string{"query", "header", "cookie", "body", "param_name_url", "param_name_body", "url_path_filename", "url_path_folder"}
}

// applyInsertionPointTypes materialises the run's point set and overlays every key this preset
// sets. Called once from Apply before the table walk.
func (c BuiltInConfig) applyInsertionPointTypes(a *AuditConfig) {
	a.InsertionKinds = insertionDefaultKinds()
	for _, k := range builtInConfigKeys {
		if !strings.HasPrefix(k.burpKey, "scanner/insertion_point_types/") {
			continue
		}
		if v := k.read(c); v.Set {
			k.apply(a, v.Value)
		}
	}
	if len(a.InsertionKinds) == 0 {
		// Every point class was explicitly disabled. Empty means "the engine default" elsewhere, so
		// pin a sentinel no kind matches rather than letting zero fall back to the default.
		a.InsertionKinds = []string{"none"}
	}
}

// anyRelocationKeySet reports whether the preset touches modifying_parameter_locations at all.
func (c BuiltInConfig) anyRelocationKeySet() bool {
	for _, k := range builtInConfigKeys {
		if strings.HasPrefix(k.burpKey, "scanner/modifying_parameter_locations/") && k.read != nil {
			if k.read(c).Set {
				return true
			}
		}
	}
	return false
}

// applyParameterLocations adds or removes each relocation kind the preset names.
//
// The base matters. A relocation key is an *addition* to the run's standard points, so a preset that
// names only a relocation must not end up with a point set containing that relocation alone — the
// engine default is materialised first when nothing else has selected a set. When the preset already
// named insertion_point_types, that materialisation has happened and this only adds to it, so the two
// sections compose instead of one silently replacing the other. Called once from ApplyWithReport
// before the table walk.
func (c BuiltInConfig) applyParameterLocations(a *AuditConfig) {
	if len(a.InsertionKinds) == 0 {
		a.InsertionKinds = append([]string(nil), DefaultProbeInsertionKinds...)
	}
	for _, k := range builtInConfigKeys {
		if !strings.HasPrefix(k.burpKey, "scanner/modifying_parameter_locations/") || k.read == nil {
			continue
		}
		if v := k.read(c); v.Set {
			k.apply(a, v.Value)
		}
	}
}

// Apply overlays this preset's keys onto a base configuration, leaving unset keys alone.
//
// Keys this engine cannot apply (Applies false in Keys) are recorded by ApplyWithReport; this
// shorthand keeps the long-standing call sites unchanged and simply drops them, which is why a
// caller honouring a shipped configuration should prefer ApplyWithReport.
func (c BuiltInConfig) Apply(base AuditConfig) AuditConfig {
	applied, _ := c.ApplyWithReport(base)
	return applied
}

// ApplyWithReport overlays this preset like Apply and additionally returns every key the preset
// sets that this engine cannot apply. The report is the not-silent half of the contract: a shipped
// configuration loads, and the caller can say in the same breath exactly which of its keys did
// nothing here rather than letting them vanish.
//
// A field-less key counts as set only when UnrepresentableKeys records it — the parser's record of
// keys the source named that have no field to land in. The match accepts either spelling of that
// record: the section-qualified path the parser writes (`issues_reported/selected_issues`, which is
// what an operator can find in their file) or the bare row name a caller may set by hand. Matching
// only the bare name was a silent drop: a parsed per-issue key was recorded, never reported, and a
// configuration saying "scan only these issues" read as fully honoured.
func (c BuiltInConfig) ApplyWithReport(base AuditConfig) (AuditConfig, []string) {
	if c.anyInsertionKeySet() {
		c.applyInsertionPointTypes(&base)
	}
	if c.anyRelocationKeySet() {
		c.applyParameterLocations(&base)
	}
	parsed := make(map[string]bool, len(c.UnrepresentableKeys))
	for _, name := range c.UnrepresentableKeys {
		parsed[name] = true
	}
	var unapplied []string
	for _, k := range builtInConfigKeys {
		switch {
		case k.read == nil:
			if parsed[strings.TrimPrefix(k.burpKey, "scanner/")] || parsed[k.name] {
				unapplied = append(unapplied, k.name)
			}
		case k.read(c).Set && !k.applies:
			unapplied = append(unapplied, k.name)
		case k.read(c).Set:
			k.apply(&base, k.read(c).Value)
		}
	}
	return base, unapplied
}

// BuiltInConfigNames lists every shipped configuration's name, in table order.
//
// Exists so a caller refusing an unknown name can say what the known ones are, rather than answering a
// typo with a bare "not found" and leaving the operator to guess at exact strings that contain spaces
// and hyphens.
func BuiltInConfigNames() []string {
	out := make([]string, 0, len(BuiltInConfigs))
	for _, c := range BuiltInConfigs {
		out = append(out, c.Name)
	}
	return out
}

// BurpShippedConfigCount is how many scan configurations Burp Suite 2026.7.1 ships in
// resources/BuiltInConfigs/.
//
// Named and kept here, beside the subset this engine implements, so every surface that reports "6 of
// N" reads N from one place. Two hand-written 29s — one in the API body, one in the CLI listing — is a
// number that can drift in one surface and not the other, and a wrong denominator makes the six look
// like the whole of what Burp has.
const BurpShippedConfigCount = 29

// BurpShippedConfigsSettingAnHonouredKey is how many of those 29 set at least one scanner key this
// engine honours — the answer to "will loading this file do anything here?", which is a different
// question from "how many are transcribed as built-in presets" (6).
//
// The two numbers were conflated in the CLI listing, which said 6 of 29 configurations set a key
// this engine honours. Six presets are *transcribed*; fifteen shipped files actually set a key that
// takes effect, because nine more configure only `issues_reported/*` keys, which this engine has
// honoured all along. Re-derived on 2026-09-14 by walking every `scanner/*` leaf in
// /root/burp-re/in/extract/resources/BuiltInConfigs and intersecting it with this table's
// applies=true rows; the key table it was derived against is pinned by
// audit_config_keys_test.go, so promoting a key moves this constant deliberately rather than
// silently.
const BurpShippedConfigsSettingAnHonouredKey = 15

// BuiltInConfigs is the six shipped configurations that set a key this engine implements.
//
// Transcribed from `resources/BuiltInConfigs/*.json` in the Burp Suite 2026.7.1 jar, and faithful
// for every key this engine *honours*: the error-handling and time limits they always carried, plus
// the eight `insertion_point_types` keys three of them select and the percentage two of them set.
// Those were missing for as long as the engine had no field for them, which made a selected preset
// silently ignore part of what Burp's own file says — the same defect the unapplied-key report
// exists to prevent, one layer up.
//
// A key these files set that this engine does not honour is deliberately absent here and named by
// `-scan-config list-unapplied` instead: transcribing a value into a preset that cannot act on it
// would put a number in the listing that means nothing.
var BuiltInConfigs = []BuiltInConfig{
	{
		Name:                                  "Crawl and Audit - Balanced",
		ConsecutiveCheckFailuresToAbandonUnit: SomeUint32(2),
		ConsecutiveUnitFailuresToFailItem:     SomeUint32(2),
	},
	{
		Name:                                  "Crawl and Audit - CICD Optimized",
		ConsecutiveCheckFailuresToAbandonUnit: SomeUint32(2),
		ConsecutiveUnitFailuresToFailItem:     SomeUint32(2),
		PauseSessionAfterFailedItems:          SomeUint32(0),
		PauseSessionAtFailedItemPercentage:    SomeUint32(0),
		MaximumAuditTimeMinutes:               SomeUint32(15),
		InsertURLParams:                       SomeUint32(1),
		InsertBodyParams:                      SomeUint32(1),
		InsertCookies:                         SomeUint32(1),
		InsertHTTPHeaders:                     SomeUint32(0),
		InsertParamName:                       SomeUint32(0),
		InsertURLPathFilename:                 SomeUint32(0),
		InsertURLPathFolders:                  SomeUint32(0),
		InsertEntireBody:                      SomeUint32(0),
	},
	{
		Name:                                  "Crawl and Audit - Deep",
		ConsecutiveCheckFailuresToAbandonUnit: SomeUint32(2),
		ConsecutiveUnitFailuresToFailItem:     SomeUint32(2),
		PauseSessionAfterFailedItems:          SomeUint32(0),
	},
	{
		Name:                                  "Crawl and Audit - Fast",
		ConsecutiveCheckFailuresToAbandonUnit: SomeUint32(2),
		ConsecutiveUnitFailuresToFailItem:     SomeUint32(2),
		InsertURLParams:                       SomeUint32(1),
		InsertBodyParams:                      SomeUint32(1),
		InsertCookies:                         SomeUint32(1),
		InsertHTTPHeaders:                     SomeUint32(0),
		InsertParamName:                       SomeUint32(0),
		InsertURLPathFilename:                 SomeUint32(0),
		InsertURLPathFolders:                  SomeUint32(0),
		InsertEntireBody:                      SomeUint32(0),
	},
	{
		Name:                                  "Crawl and Audit - Lightweight",
		ConsecutiveCheckFailuresToAbandonUnit: SomeUint32(2),
		ConsecutiveUnitFailuresToFailItem:     SomeUint32(2),
		PauseSessionAfterFailedItems:          SomeUint32(0),
		MaximumAuditTimeMinutes:               SomeUint32(15),
		InsertURLParams:                       SomeUint32(1),
		InsertBodyParams:                      SomeUint32(1),
		InsertCookies:                         SomeUint32(1),
		InsertHTTPHeaders:                     SomeUint32(0),
		InsertParamName:                       SomeUint32(0),
		InsertURLPathFilename:                 SomeUint32(0),
		InsertURLPathFolders:                  SomeUint32(0),
		InsertEntireBody:                      SomeUint32(0),
	},
	{
		Name:                                  "Never stop audit due to application errors",
		ConsecutiveCheckFailuresToAbandonUnit: SomeUint32(2),
		ConsecutiveUnitFailuresToFailItem:     SomeUint32(2),
		PauseSessionAfterFailedItems:          SomeUint32(0),
		PauseSessionAtFailedItemPercentage:    SomeUint32(0),
	},
}

// BuiltInConfigByName looks up a shipped configuration by its exact name.
func BuiltInConfigByName(name string) (BuiltInConfig, bool) {
	for _, c := range BuiltInConfigs {
		if c.Name == name {
			return c, true
		}
	}
	return BuiltInConfig{}, false
}

// AuditLedger records which `(dispatch unit, check)` pairs have already been audited.
//
// This is the admission bound made concrete. It holds one key per dispatch unit and one bit per
// check, so remembering that all 127 active checks ran against a host costs the host string plus
// sixteen bytes — not a retained copy of the work. Exact, not probabilistic: a hash-only ledger
// would occasionally collide and skip a check, and a silently skipped check in a security scanner
// is a false negative nobody can see.
//
// The mutex is the one divergence from the Rust original, where `admit(&mut self)` makes exclusive
// access a compile-time fact. ActiveScanner.AuditSession audits items concurrently, so the resident
// set has to stay exact at run time instead: two goroutines racing on the same pair must produce
// exactly one admission, never two.
type AuditLedger struct {
	mu       sync.Mutex
	done     map[string][]uint64
	admitted int
}

// NewAuditLedger returns an empty ledger, admitting everything once.
func NewAuditLedger() *AuditLedger {
	return &AuditLedger{done: make(map[string][]uint64)}
}

// Admit admits check against unit, returning false if that pair already ran.
//
// A negative index is refused rather than panicking or silently wrapping: there is no such check,
// so there is nothing to admit.
func (l *AuditLedger) Admit(unit string, check int) bool {
	if check < 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done == nil {
		l.done = make(map[string][]uint64)
	}
	word, bit := check/64, check%64
	bits := l.done[unit]
	if len(bits) <= word {
		grown := make([]uint64, word+1)
		copy(grown, bits)
		bits = grown
	}
	mask := uint64(1) << bit
	if bits[word]&mask != 0 {
		l.done[unit] = bits
		return false
	}
	bits[word] |= mask
	l.done[unit] = bits
	l.admitted++
	return true
}

// Units reports the distinct dispatch units seen.
func (l *AuditLedger) Units() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.done)
}

// Admitted reports the total pairs admitted — the amount of work this ledger has let through.
func (l *AuditLedger) Admitted() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.admitted
}

// itemBreaker is the two-level failure model from `scanner/error_handling/*`, as a value that can be
// stepped.
//
// Level one: N consecutive check failures abandon the rest of the dispatch unit. Level two: N
// consecutive unit failures fail the item. The session-level count/percentage breaker lives on
// sessionBreaker because it spans items.
//
// Unexported, and deliberately not mutex-guarded: one of these belongs to exactly one item, which
// exactly one goroutine dispatches.
type itemBreaker struct {
	abandonUnitAfter         uint32
	failItemAfter            uint32
	consecutiveCheckFailures uint32
	consecutiveUnitFailures  uint32
	itemFailed               bool
}

func newItemBreaker(cfg AuditConfig) *itemBreaker {
	return &itemBreaker{
		abandonUnitAfter: cfg.ConsecutiveCheckFailuresToAbandonUnit,
		failItemAfter:    cfg.ConsecutiveUnitFailuresToFailItem,
	}
}

// checkSucceeded records a check that completed without a transport failure.
func (b *itemBreaker) checkSucceeded() { b.consecutiveCheckFailures = 0 }

// checkFailed records a check whose probe could not be sent. Returns true when the rest of the unit
// is abandoned.
func (b *itemBreaker) checkFailed() bool {
	b.consecutiveCheckFailures++
	return b.abandonUnitAfter > 0 && b.consecutiveCheckFailures >= b.abandonUnitAfter
}

// unitFinished records that a dispatch unit finished. Returns true when the item is failed.
func (b *itemBreaker) unitFinished(abandoned bool) bool {
	b.consecutiveCheckFailures = 0
	if abandoned {
		b.consecutiveUnitFailures++
	} else {
		b.consecutiveUnitFailures = 0
	}
	if b.failItemAfter > 0 && b.consecutiveUnitFailures >= b.failItemAfter {
		b.itemFailed = true
	}
	return b.itemFailed
}

// failed reports whether the item breaker has tripped.
func (b *itemBreaker) failed() bool { return b.itemFailed }

// sessionBreaker is the session-level breaker: `pause_task_failed_audit_item_count` and
// `…_percentage`.
//
// Mutex-guarded where the Rust original is `&mut`: Go's AuditSession may finish several items
// concurrently, and a breaker that miscounts under contention is a breaker that pauses a run for
// the wrong reason.
type sessionBreaker struct {
	mu           sync.Mutex
	afterCount   uint32
	atPercentage uint8
	failedItems  uint32
	finished     uint32
}

func newSessionBreaker(cfg AuditConfig) *sessionBreaker {
	return &sessionBreaker{
		afterCount:   cfg.PauseSessionAfterFailedItems,
		atPercentage: cfg.PauseSessionAtFailedItemPercentage,
	}
}

// itemFinished records an item's outcome. Returns true once the session should pause.
func (b *sessionBreaker) itemFinished(failed bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.finished++
	if failed {
		b.failedItems++
	}
	return b.trippedLocked()
}

// tripped reports whether the breaker has already tripped, without stepping it.
func (b *sessionBreaker) tripped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.trippedLocked()
}

func (b *sessionBreaker) trippedLocked() bool {
	if b.afterCount > 0 && b.failedItems >= b.afterCount {
		return true
	}
	if b.atPercentage > 0 && b.finished > 0 {
		pct := uint64(b.failedItems) * 100 / uint64(b.finished)
		return pct >= uint64(b.atPercentage)
	}
	return false
}

// failed reports how many items the item breaker failed.
func (b *sessionBreaker) failed() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failedItems
}
