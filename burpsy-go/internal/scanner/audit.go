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
	"github.com/burpsy-go/burpsy/internal/sender"
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
	// ItemStateCancelled means an operator stopped this item and nothing else (burpsy-react-ui-exiu).
	//
	// Its own state rather than a flavour of ItemStateBounded, because the two are different facts
	// about coverage and an operator reading one as the other reaches the wrong conclusion: bounded
	// says the target was too expensive, cancelled says a person stopped it. Burp has CANCELLED for
	// exactly this reason, and the audit-item context menu offers it (running-scans/results/
	// audit-items/index.html:102-115).
	//
	// Reached only from ItemStatePending — cancelling work already in flight would mean abandoning
	// a dispatched probe mid-exchange, which the engine cannot do without a per-item context it does
	// not have. So a cancel lands on the next item's gate, which is where the queue is anyway.
	ItemStateCancelled
)

// ItemStateAll is all nine, so a caller can build a histogram without hard-coding which states
// exist — mirrors DispositionAll and CoverageStateAll for the same reason. The array's length is the
// count a caller would otherwise hand-code, so it is written out rather than derived.
var ItemStateAll = [9]ItemState{
	ItemStatePending,
	ItemStateAuditing,
	ItemStateAudited,
	ItemStateBounded,
	ItemStateFailed,
	ItemStatePaused,
	ItemStateOutOfScope,
	ItemStateUnauditable,
	ItemStateCancelled,
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
	case ItemStateCancelled:
		return "cancelled"
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
// a preset overlay (BuiltInConfig.Apply) writes them here. Where the overlay bends, the key row's
// own text says so (BuiltInConfigKeys), and what a selection named but did not act on is carried in
// DeclinedDetectionMethods.
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

// DefaultMaxItemsInProgress is the inherited admission cap on audit items in flight at once
// (burpsy-react-ui-3ymo) — Burp's own shipped default for
// scanner/audit_optimization/max_items_in_progress. It bounds the resident set of concurrently
// dispatching items independently of ScanConfig.MaxConcurrency's worker-pool size: a session with
// more workers than this cap still holds only this many items past admission at once, the rest
// waiting rather than being refused.
const DefaultMaxItemsInProgress uint32 = 10

type AuditConfig struct {
	// ManualSpans are operator-marked [start,end) byte ranges over the audited request
	// (burpsy-react-ui-806w). When set — only a single-exchange "audit this marked request" ever sets
	// them — the enumerator audits exactly those spans and skips its heuristics, Burp's precedence for
	// a manual insertion point. Empty is every other audit: the enumerator guesses as before.
	ManualSpans [][2]int
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
	// `scan_type_light_active`, `scan_type_medium_active` and `scan_type_intrusive_active`. Each
	// selects the checks carrying that rank (CheckInvasiveness) and the three are independent: a
	// preset that enables light and disables intrusive runs the light checks and leaves the
	// intrusive ones out, which is what the three keys mean in Burp.
	//
	// A key that is not set says nothing about its tier. Setting all three to 0 admits no active
	// check at all; setting none leaves the base ScanConfig switches untouched. A tier set to 0
	// excludes that tier's checks even when its family switch is on, so the overlay narrows the
	// base set rather than replacing it.
	LightActiveChecks     OptUint32
	MediumActiveChecks    OptUint32
	IntrusiveActiveChecks OptUint32
	// JavaScriptAnalysis is Burp's `scanner/issues_reported/scan_type_javascript_analysis`: false
	// turns off the DOM family (ScanConfig.CheckDOM) for this run.
	JavaScriptAnalysis OptUint32
	// ScanSpeed is Burp's `scanner/audit_optimization/scan_speed` as a CheckSpeed rank
	// (burpsy-react-ui-ev7y). Unset leaves every check admitted, which is what a configuration that
	// never mentions speed means — not 'fast', which would silently narrow a run nobody narrowed.
	ScanSpeed OptUint32
	// ScanAccuracy is Burp's `scanner/audit_optimization/scan_accuracy` as a CheckAccuracy level,
	// bounding how many mutation attempts a check spends per candidate (4/8/10, Zs_2.java:8). Unset
	// leaves the engine's own per-check bounds alone.
	ScanAccuracy OptUint32
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
	// SkipIneffectiveChecks is Burp's
	// `scanner/audit_optimization/skip_ineffective_checks`: drop an insertion point the engine
	// cannot get an interesting response from, before its probes are sent.
	//
	// The key row for this used to read "not applied: this engine infers nothing about a
	// check's effectiveness, so it has nothing to skip on", which was false — Burp's gate is
	// PER INSERTION POINT, not per check (Zfhb.java:81-83, burpsy-react-ui-y4om), and the
	// point-level seam the gate needs is the one the light-audit tier already occupies one
	// loop away. The two are different decisions and both exist: the light tier asks whether
	// this point's TYPE has behaved uniformly on this host across the run, this one asks
	// whether THIS point responds to anything at all.
	//
	// Unset is the Burp default (on). Set-and-zero turns the gate off, which is a real choice
	// for an engagement that must pay full price for every point — the same set/unset
	// distinction every other OptUint32 knob on this struct uses.
	SkipIneffectiveChecks OptUint32
	// PointEffective is the oracle skip_ineffective_checks asks, supplied by the dispatcher
	// (which owns the run's per-point ledger). It takes the CHECK as well as the point,
	// because the prior is keyed per (check, kind, name, host): one check finding nothing
	// at a place is not evidence about another check, and Burp's own gate is a per-message-
	// class probe, so a prior shared across checks would gate away a check that had never
	// looked. Not an operator-facing field: nil means no oracle and therefore no skips, which
	// is what a context built outside a dispatched audit gets — the light tier's nil-safe
	// reading, for the same reason.
	//
	// Tagged `json:"-"` (burpsy-react-ui-5b0t): encoding/json refuses func-typed fields
	// even when nil, so a struct carrying one cannot be marshalled at all — which 500'd
	// every scan-config save and clone through the API. This is runtime wiring, never
	// configuration; a document that tried to carry it would be carrying a closure the
	// operator did not write.
	PointEffective func(check string, p bcheck.InsertionPoint) bool `json:"-"`
	// CheckName is the row name the effectiveness prior is keyed by, set by the check that is
	// enumerating (runInjection does it). Not operator-facing: a check's own name is not a
	// setting, and an empty value is its own bucket rather than a shared one.
	CheckName string
	// AutoBackoffMs is the per-step delay the dispatch loop applies after a probe came back
	// 429 or 503 (burpsy-react-ui-fkl8) — Burp's resource-pool auto_backoff, in the
	// smallest honest shape: a counter and a sleep, not a resource-pool rewrite. Unset
	// inherits the default (see DefaultAutoBackoffMs); zero disables the backoff, which is
	// a real choice (an operator who knows the target's limiter resets per-minute may
	// prefer to let the request budget eat the 429s) and must not read as "unset".
	AutoBackoffMs OptUint32
	// PerHostThrottleMs is Burp's resource-pool throttle_interval_millis: the minimum
	// interval between probes to the SAME host. Unset means no per-host throttle (the
	// global request budget still applies). Set-and-zero is treated as unset.
	PerHostThrottleMs OptUint32
	// PerHostThrottleRandom enables Burp's throttle_random_enabled: jitter the
	// per-host interval by up to 50% so a fixed cadence is not fingerprintable.
	PerHostThrottleRandom bool
	// PerHostMaxInFlight is Burp's resource-pool concurrent_request_limit: the ceiling
	// on probes in flight to ONE host at a time, distinct from the global worker count.
	// Unset means no per-host cap. Set-and-zero is treated as 1.
	PerHostMaxInFlight OptUint32
	// MaxItemsInProgress is Burp's scanner/audit_optimization/max_items_in_progress
	// (burpsy-react-ui-3ymo): the ceiling on audit items admitted past the Auditing gate at
	// once, enforced independently of ScanConfig.MaxConcurrency's worker-pool size. An item
	// over the cap waits for a slot rather than being refused — the cap governs how many are
	// simultaneously in flight, not how many are ever audited. Unset inherits
	// DefaultMaxItemsInProgress; set-and-zero is treated as the smallest real cap (1) rather
	// than as "unbounded", because zero would admit nothing and every worker would block
	// forever waiting for a slot that never opens.
	MaxItemsInProgress OptUint32
	// SkipAllTestsForParameters is Burp's
	// scanner/ignored_insertion_points/skip_all_tests_for_parameters: parameters an operator
	// exempted from testing entirely, by name. A named parameter's points are dropped from
	// every kind before the per-request cap, and the drop is a bcheck.Declined so the audit
	// item's queue row says the parameter was skipped rather than absent.
	//
	// Burp's softer sibling is SkipServerSideInjectionForParameters, below.
	SkipAllTestsForParameters []string
	// SkipServerSideInjectionForParameters is Burp's
	// scanner/ignored_insertion_points/skip_server_side_injection_for_parameters: parameters, by
	// name, that the server-side injection checks do not probe while every other check still does
	// (burpsy-react-ui-gmdk). Which checks those are, and when, is Burp's own split
	// (server_side_injection.go): SQL injection and XPath always; the rest — reflected XSS included —
	// only while skip_ineffective_checks is on. Applied per check, never to the run-wide
	// enumeration, and each drop is a bcheck.Declined on that check's coverage.
	SkipServerSideInjectionForParameters []string
	// FollowUpPasses is Burp's scanner/error_handling/number_of_follow_up_passes: how many extra
	// passes a FAILED item is re-dispatched (Zxdx.java:27,36; shipped default 1 at Zp0d.java:120-121).
	//
	// Unset inherits DefaultFollowUpPasses. Zero is a real choice — an operator who would rather
	// have a failed item's coverage accounted as lost than pay for a retry against a target that is
	// refusing — and must not read as "unset", which is why this is an OptUint32 like the breakers.
	FollowUpPasses OptUint32

	// FollowRedirects is Burp's scanner/audit_optimization/follow_redirections, a boolean
	// (Zhd_.java:41). Unset or 0 follows nothing — every probe reads the 30x it got, which is what
	// every audit did before the key was read. 1 makes the reflected-XSS check follow a probe's
	// redirect within the engagement scope (on-site only when no scope is configured) and look for its
	// breakout on the landing page too. See run_overrides.go for the mapping and for why it is that one
	// check.
	FollowRedirects OptUint32
	// ConnectTimeout and NormalTimeout are Burp's scanner/audit_project_option_overrides/
	// {connect_timeout,normal_timeout}, in whole SECONDS (Zbuj.java:19-22). Unset leaves the
	// engagement's bound; zero is Burp's "never time out". Either one set gives the run its own derived
	// sender (runSenderFor), so the engagement sender every other tool shares is never changed.
	ConnectTimeout OptUint32
	NormalTimeout  OptUint32

	// The javascript_analysis keys (burpsy-react-ui-9mti, Zxc3.java:27-31). The two analysis switches
	// are booleans, unset meaning on (both techniques, which is what every audit did before they were
	// read); the two limits are SECONDS per item, unset or zero meaning no limit. js_analysis.go says
	// what "static" and "dynamic" are in this engine.
	JavaScriptStaticAnalysis  OptUint32
	JavaScriptDynamicAnalysis OptUint32
	MaxStaticTimePerItem      OptUint32
	MaxDynamicTimePerItem     OptUint32

	// The eight `scanner/frequently_occurring_insertion_points/quick_scan_*` keys, carried on the RUN
	// as well as on the preset: they are applied per run, and the set they resolve to is what the
	// light tier's gate reads.
	QuickScanURLParams       OptUint32
	QuickScanBodyParams      OptUint32
	QuickScanCookies         OptUint32
	QuickScanHTTPHeaders     OptUint32
	QuickScanParamName       OptUint32
	QuickScanURLPathFilename OptUint32
	QuickScanURLPathFolders  OptUint32
	QuickScanEntireBody      OptUint32

	// LightAuditKinds is the DERIVED set the light tier's gate reads. Not computed per dispatch: the
	// eight keys above are the input and this is their output, rebuilt whenever one is applied, so
	// that a later overlay can take back what an earlier one gave (see rebuildLightAuditKinds).
	LightAuditKinds LightAuditKinds

	// IssueTypes is the operator's per-issue selection: the catalogue type indexes a run is restricted
	// to, empty meaning no restriction. Burp's dispatch is a two-stage filter for exactly this —
	// the family switches first, then a per-check predicate over the selected issue types
	// (Zwy6.java:36-75, and lambda$isEnabled$1 at :170-184) — and without the second stage a run
	// cannot be narrowed past its families, so "confirm one issue class after a fix" is impossible
	// (burpsy-react-ui-kvmx).
	//
	// It is a set of type indexes rather than names because the catalogue is the identity: a name is
	// a label, and a label an operator typed against Burp's own UI has to mean the same thing here.
	//
	// A WHITELIST, and only one of Burp's two readings of selected_issues: an imported file fills it
	// only under scan_only_selected_issues. Without that flag Burp's list is per-issue overrides —
	// see DisabledIssueTypes and issue_selection.go — and filling this from it would narrow a full
	// audit to the handful of types the file happened to override.
	IssueTypes []uint32
	// DisabledIssueTypes is the deny half of Burp's per-issue selection: the types a configuration's
	// selected_issues marks `enabled: false`. A check of one of these types is not dispatched, and a
	// type not named here is untouched. Empty means nothing is removed.
	DisabledIssueTypes []uint32
	// DisabledDetectionMethods are the (issue type, detection method) pairs a configuration's
	// selected_issues turned off — "Time delays" for SQL injection, say. Keyed per type because Burp
	// resolves a method name inside its type (Zwx_.java:43-61). A check that declares a disabled
	// method is not dispatched (filterBySelection); a probe of one is withheld at the harness.
	DisabledDetectionMethods []IssueDetectionMethod
	// DeclinedDetectionMethods is what the configuration's selection named that this engine did not
	// act on, each with its reason: an enabled method burpsy's check does not implement ("Burp
	// Infiltrator" always), a method name Burp itself would ignore, a type outside the catalogue.
	// Recorded at load time so the configuration view can show it, and repeated onto the outcome of
	// every item whose check of that type runs (AuditOutcome.MethodsDeclined).
	DeclinedDetectionMethods MethodDeclines
}

// IssueTypesFrom is the per-run selection carried over from a scanner's live configuration, so the
// audit engine and the check-set builder read ONE list rather than two that can disagree.
func (cfg ScanConfig) IssueTypesFrom() []uint32 { return cfg.IssueTypes }

// rebuildLightAuditKinds derives the light tier's per-kind set from the eight keys just applied.
//
// DERIVED rather than accumulated, and that is the whole point of the polarity: a key set to FALSE
// removes its kinds, and a key left UNSET says nothing. Accumulating across an overlay would make a
// later preset unable to un-tick something an earlier one ticked, and "set to false" would mean
// "was never mentioned" for every key applied after the first.
func (a *AuditConfig) rebuildLightAuditKinds() {
	fields := []struct {
		set OptUint32
		key string
	}{
		{a.QuickScanURLParams, "quick_scan_url_params"},
		{a.QuickScanBodyParams, "quick_scan_body_params"},
		{a.QuickScanCookies, "quick_scan_cookies"},
		{a.QuickScanHTTPHeaders, "quick_scan_http_headers"},
		{a.QuickScanParamName, "quick_scan_param_name"},
		{a.QuickScanURLPathFilename, "quick_scan_url_path_filename"},
		{a.QuickScanURLPathFolders, "quick_scan_url_path_folders"},
		{a.QuickScanEntireBody, "quick_scan_entire_body"},
	}
	any := LightAuditKinds{}
	// The kinds explicitly taken OUT, not the ones ticked in. See LightApplies: the eight keys are a
	// deny list, and building the inverse would mean ticking url params silently removed cookies
	// from the light pass.
	var out []string
	for _, f := range fields {
		if !f.set.Set {
			continue
		}
		any.Set = true
		if f.set.Value == 0 {
			out = append(out, quickScanKeyKinds[f.key]...)
		}
	}
	any.kinds = out
	a.LightAuditKinds = any
}

// IsIssueTypeSelected reports whether a catalogue type is in the operator's selection. On a
// ScanConfig, because that is what the live configuration and the coverage report both read.
//
// An EMPTY selection is "no restriction", not "nothing selected" — the reading every optional field
// on this configuration uses. The two are only told apart by Set, because a configuration that
// named no selection and one that selected nothing have to behave differently: the first is what a
// preset that never mentions this key means, and the second is what an operator who cleared the list
// means.
func (cfg ScanConfig) IsIssueTypeSelected(typeIndex uint32) bool {
	if len(cfg.IssueTypes) == 0 {
		return true
	}
	for _, t := range cfg.IssueTypes {
		if t == typeIndex {
			return true
		}
	}
	return false
}

// DefaultFollowUpPasses is Burp's shipped default for number_of_follow_up_passes (Zp0d.java:120-121).
//
// One, not zero: a follow-up pass exists for the TRANSIENT failure — a timeout, a 502 from a
// backend mid-restart, a dropped connection — and one retry catches it without turning a
// permanently-broken target into double the traffic.
const DefaultFollowUpPasses = 1

// followUpPasses resolves the configured count, with the same unset-means-default rule every other
// OptUint32 knob uses.
func (cfg AuditConfig) followUpPasses() int {
	if cfg.FollowUpPasses.Set {
		return int(cfg.FollowUpPasses.Value)
	}
	return DefaultFollowUpPasses
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
	// Operator-marked spans short-circuit the heuristics (burpsy-react-ui-806w). Rides this one path
	// so the probe harness, the item ledger and the check context all see the same manual points.
	opts.ManualSpans = cfg.ManualSpans
	// The per-point effectiveness gate (burpsy-react-ui-y4om) rides the same path. It is a
	// FUNCTION rather than a value because the oracle needs the run's own state: a point
	// counts as effective when the run has seen it answer something, which is a per-run
	// fact no configuration can carry. Unset is Burp's default (on); set-and-zero turns the
	// gate off. The predicate itself is installed by the dispatcher, which owns the run.
	if cfg.PointEffective != nil {
		opts.PointEffective = cfg.PointEffective
	}
	opts.CheckName = cfg.CheckName
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

// resolvedMaxItemsInProgress is MaxItemsInProgress with the shipped default filled in and the
// deadlock case guarded, following the same set/zero/unset reading as MaxItemsInProgress itself.
func (cfg AuditConfig) resolvedMaxItemsInProgress() uint32 {
	if !cfg.MaxItemsInProgress.Set {
		return DefaultMaxItemsInProgress
	}
	if cfg.MaxItemsInProgress.Value == 0 {
		return 1
	}
	return cfg.MaxItemsInProgress.Value
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
// LightAuditKinds is the set of insertion-point kinds the light-audit tier is opted into.
//
// Burp's own control for this is the `scanner/frequently_occurring_insertion_points/quick_scan_*`
// family, and its panel says what it is: "runs a lighter audit ... Select the insertion point types
// this applies to" (Zrdr.java:26), with the per-kind gate at Zb1q.java:111-118.
//
// The zero value — no key mentioned — means EVERY kind is in the light pass, which is the behaviour
// before this field existed. That direction is the safe one: a configuration that never mentions
// these keys gets what it always got.
type LightAuditKinds struct {
	// Set records that the source file mentioned at least one of the eight keys. It is what separates
	// "this configuration said nothing about quick scans" from "this configuration turned them off",
	// which are different requests and a zero alone cannot tell apart.
	Set bool
	// kinds are the point classes taken OUT of the light pass, in the same vocabulary the enumerator
	// uses (query, body, cookie, header, …). A deny list, because that is the polarity the eight keys
	// have; see LightApplies.
	kinds []string
}

// LightApplies reports whether kind is in the light pass.
//
// The polarity is the one Burp's own eight keys have, and it is a DENY list: a key set to TRUE adds
// its kinds, a key set to FALSE removes them, and a key the file never mentioned leaves them alone.
// So once any key is set, a kind is in the light pass unless something explicitly took it OUT.
//
// Getting that backwards is the bug this comment is here for. Reading the set as an allow-list --
// "only the ticked kinds are in" -- means that ticking url params takes COOKIES out of the light
// pass, which is the opposite of what the operator asked and of what their configuration file says.
// The first version of this did exactly that, and the test for it is in quick_scan_kinds_test.go.
func (l LightAuditKinds) LightApplies(kind string) bool {
	if !l.Set {
		return true
	}
	for _, k := range l.kinds {
		if k == kind {
			return false
		}
	}
	return true
}

// ExcludedKinds is the deny list as a list, for the settings surface and for a report that has to
// name what the configuration took out of the light pass. A run with nothing excluded still has
// every kind in the light tier, so this is empty rather than "all kinds" in the common case.
func (l LightAuditKinds) ExcludedKinds() []string { return append([]string(nil), l.kinds...) }

// quickScanKeyKinds maps each of Burp's eight quick_scan_* keys to the point classes it governs. The
// same vocabulary the insertion_point_types rows use, because they gate the SAME classes at a
// different stage -- which is the distinction the key table's comment is about.
//
// Declared here rather than in the key table so the table's rows and the engine's gate read one
// mapping, and a key moved to the wrong class could not leave the two disagreeing.
var quickScanKeyKinds = map[string][]string{
	"quick_scan_url_params":        {"query"},
	"quick_scan_body_params":       {"body"},
	"quick_scan_cookies":           {"cookie"},
	"quick_scan_http_headers":      {"header"},
	"quick_scan_param_name":        {"param_name_url", "param_name_body"},
	"quick_scan_url_path_filename": {"url_path_filename"},
	"quick_scan_url_path_folders":  {"url_path_folder"},
	"quick_scan_entire_body":       {"entire_body"},
}

type BuiltInConfig struct {
	Name                                  string
	ConsecutiveCheckFailuresToAbandonUnit OptUint32
	ConsecutiveUnitFailuresToFailItem     OptUint32
	PauseSessionAfterFailedItems          OptUint32
	PauseSessionAtFailedItemPercentage    OptUint32
	// MaximumAuditTimeMinutes is `scanner/audit_optimization/maximum_crawl_and_audit_time`.
	MaximumAuditTimeMinutes OptUint32
	// MaxItemsInProgress is `scanner/audit_optimization/max_items_in_progress`.
	MaxItemsInProgress OptUint32

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

	// The eight `scanner/frequently_occurring_insertion_points/quick_scan_*` keys: which insertion
	// point classes get the LIGHT pass. True keeps the kind in the light tier, false takes it out and
	// gives it the full pass.
	//
	// A separate decision from the eight insertion_point_types keys above, which choose which points
	// are ENUMERATED at all. Declining these as redundant with those was factually wrong, and it is what
	// left an operator unable to say "light for URL params, full for body params"
	// (burpsy-react-ui-02qi).
	QuickScanURLParams       OptUint32
	QuickScanBodyParams      OptUint32
	QuickScanCookies         OptUint32
	QuickScanHTTPHeaders     OptUint32
	QuickScanParamName       OptUint32
	QuickScanURLPathFilename OptUint32
	QuickScanURLPathFolders  OptUint32
	QuickScanEntireBody      OptUint32

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

	// FollowUpPasses is `scanner/error_handling/number_of_follow_up_passes`.
	FollowUpPasses OptUint32
	// FollowRedirections, AuditConnectTimeout and AuditNormalTimeout are the three per-run project
	// overrides (burpsy-react-ui-o2p3). The two timeouts are seconds; Burp's -1 ("not overridden")
	// leaves them unset and is recorded in InheritedOverrides.
	FollowRedirections  OptUint32
	AuditConnectTimeout OptUint32
	AuditNormalTimeout  OptUint32
	// The javascript_analysis keys (burpsy-react-ui-9mti). The two times are seconds.
	JSUseStaticAnalysis        OptUint32
	JSUseDynamicAnalysis       OptUint32
	JSMaxStaticSecondsPerItem  OptUint32
	JSMaxDynamicSecondsPerItem OptUint32
	// InheritedOverrides names the override rows a file set to -1, Burp's "not overridden"
	// (Zbuj.java:27-28). They ask for nothing and are honoured as asked, so they are reported applied —
	// never in neither list.
	InheritedOverrides []string

	// The nine `scanner/issues_reported/*` keys. See AuditConfig for how each is honoured. The three
	// per-issue selection keys are read the way Burp reads them (issue_selection.go): the two
	// booleans choose the mode, and selected_issues is per-issue overrides unless
	// scan_only_selected_issues makes it a whitelist.
	SelectIndividualIssues OptUint32
	ScanOnlySelectedIssues OptUint32
	// SelectedIssues is the parsed selected_issues list; SelectedIssuesSet tells "the file carried an
	// empty list" from "the file did not name the key", which select different behaviour.
	SelectedIssues        []SelectedIssue
	SelectedIssuesSet     bool
	PassiveChecks         OptUint32
	LightActiveChecks     OptUint32
	MediumActiveChecks    OptUint32
	IntrusiveActiveChecks OptUint32
	JavaScriptAnalysis    OptUint32
	ScanSpeed             OptUint32
	ScanAccuracy          OptUint32
	StoreQueueItems       OptUint32

	// The two `scanner/misc_insertion_point_options/*` keys: how many insertion points one base
	// request may yield, and whether the enumerator expands the structure inside a parameter value.
	// Burp ships them as 30 and true.
	MaxInsertionPointsPerRequest OptUint32
	UseNestedInsertionPoints     OptUint32
	// SkipIneffectiveChecks is `scanner/audit_optimization/skip_ineffective_checks` (y4om): the
	// per-insertion-point effectiveness gate. Burp ships it true in 3 of its 29 configurations,
	// so a loaded configuration has to be able to say either.
	SkipIneffectiveChecks OptUint32

	// IgnoredParameterRules counts, per `scanner/ignored_insertion_points/*` key the source set, how
	// many match rules its list carried. Burp's value is a list of rule objects, not of names; an
	// empty list is fully honoured (there is nothing to skip) and a non-empty one is reported, because
	// this engine has no matcher for Burp's rule shape.
	IgnoredParameterRules map[string]int

	// UnrepresentableKeys records keys a parsed source named that this engine has no field for. Only
	// ParseBurpConfig fills it; the six transcribed presets never do. ApplyWithReport reports them
	// unapplied, so a loaded configuration never drops a key silently.
	UnrepresentableKeys []string
	// ParsedKeys is every `scanner/*` key the source named, section-qualified
	// (`issues_reported/selected_issues`). It is the denominator of the apply report: every one of
	// them must come back either applied or unapplied, never neither (burpsy-react-ui-saq3.1).
	ParsedKeys []string
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
	// listShaped marks a key whose Burp value is not a scalar: the control IS honoured, but through
	// a reduced form of Burp's value. Such a row is neither in the applied count nor in the
	// "not applied" list an operator reads as "unsupported" — it appears as its own category, because
	// "we support this, but not the way you probably meant" is a third answer and reporting it as
	// either of the other two is what burpsy-react-ui-86le was (burpsy-react-ui-86le fixed the row
	// that said "not applied" for a control the engine honours).
	listShaped bool
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
	{
		name:    "max_items_in_progress",
		burpKey: "scanner/audit_optimization/max_items_in_progress",
		what:    "the ceiling on audit items admitted past the auditing gate at once; an item over the cap waits for a slot rather than being refused (Burp's shipped default is 10)",
		read:    func(c BuiltInConfig) OptUint32 { return c.MaxItemsInProgress },
		apply:   func(a *AuditConfig, v uint32) { a.MaxItemsInProgress = SomeUint32(v) },
		min:     1,
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
	// AuditConfig; the three active tiers select checks by their CheckInvasiveness rank, so each key
	// here changes engine behaviour on its own and the matrix can report all three as applied.
	{
		name:    "scan_type_passive",
		burpKey: "scanner/issues_reported/scan_type_passive",
		what:    "whether the passive check families run (0 turns them off for the run); not consulted when select_individual_issues or scan_only_selected_issues is true, as in Burp (Zmzw.java:86)",
		read:    func(c BuiltInConfig) OptUint32 { return c.PassiveChecks },
		apply:   func(a *AuditConfig, v uint32) { a.PassiveChecks = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_type_light_active",
		burpKey: "scanner/issues_reported/scan_type_light_active",
		what:    "whether the light-tier checks run; each Burp active tier selects its own ranked checks, and an unset key inherits the base switches; not consulted when select_individual_issues or scan_only_selected_issues is true, as in Burp (Zmzw.java:86)",
		read:    func(c BuiltInConfig) OptUint32 { return c.LightActiveChecks },
		apply:   func(a *AuditConfig, v uint32) { a.LightActiveChecks = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_type_medium_active",
		burpKey: "scanner/issues_reported/scan_type_medium_active",
		what:    "whether the medium-tier checks run; each Burp active tier selects its own ranked checks, and an unset key inherits the base switches; not consulted when select_individual_issues or scan_only_selected_issues is true, as in Burp (Zmzw.java:86)",
		read:    func(c BuiltInConfig) OptUint32 { return c.MediumActiveChecks },
		apply:   func(a *AuditConfig, v uint32) { a.MediumActiveChecks = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_type_intrusive_active",
		burpKey: "scanner/issues_reported/scan_type_intrusive_active",
		what:    "whether the intrusive-tier checks run; each Burp active tier selects its own ranked checks, and an unset key inherits the base switches; not consulted when select_individual_issues or scan_only_selected_issues is true, as in Burp (Zmzw.java:86)",
		read:    func(c BuiltInConfig) OptUint32 { return c.IntrusiveActiveChecks },
		apply:   func(a *AuditConfig, v uint32) { a.IntrusiveActiveChecks = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_type_javascript_analysis",
		burpKey: "scanner/issues_reported/scan_type_javascript_analysis",
		what:    "whether the DOM-based checks run (0 turns them off for the run); not consulted when select_individual_issues or scan_only_selected_issues is true, as in Burp (Zmzw.java:86)",
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
		// Burp's three selection keys form ONE control, read as Burp reads it (issue_selection.go):
		// either boolean puts the run in selection mode, where the scan_type_* flags are not consulted
		// (Zmzw.java:80-87); scan_only_selected_issues additionally makes selected_issues a whitelist
		// (Zwnn.java:13-25). The two booleans are scalars with a field each; the list is applied by
		// applyIssueSelection after the row walk, because selection mode takes back the tiers.
		//
		// The booleans used to be "partly applied" rows with no field, and the parser recorded them in
		// UnrepresentableKeys, where the listShaped skip in ApplyWithReport dropped them from both the
		// applied and the unapplied answer (burpsy-react-ui-saq3.1).
		name:    "scan_only_selected_issues",
		burpKey: "scanner/issues_reported/scan_only_selected_issues",
		what:    "true makes selected_issues a whitelist: only its enabled entries run, and a type it does not list does not run (an empty list restricts nothing). Either this or select_individual_issues puts the run in per-issue mode, where the scan_type_* keys are not consulted",
		read:    func(c BuiltInConfig) OptUint32 { return c.ScanOnlySelectedIssues },
		apply:   func(*AuditConfig, uint32) {},
		applies: true,
	},
	{
		name:    "select_individual_issues",
		burpKey: "scanner/issues_reported/select_individual_issues",
		what:    "true puts the run in per-issue mode: selected_issues decides each type and the scan_type_* keys are not consulted. Without scan_only_selected_issues the list is per-issue overrides, so a type it does not list still runs",
		read:    func(c BuiltInConfig) OptUint32 { return c.SelectIndividualIssues },
		apply:   func(*AuditConfig, uint32) {},
		applies: true,
	},
	{
		name:       "selected_issues",
		burpKey:    "scanner/issues_reported/selected_issues",
		what:       "partly applied: in per-issue mode an entry with enabled false removes that issue type from the run, and under scan_only_selected_issues the enabled entries are the whole run. A detection method set false is withheld for that issue type: its probes are not sent and the withheld count is in the item's methods_declined, while a check stays dispatched while any method it registers is left enabled for it (Zwy6's per-pair rule) and is withheld whole only when the set is exhausted. A method set true that burpsy's check does not implement (Burp Infiltrator always; for SQL injection Collaborator plus the Oracle and MySQL timing banks) cannot run, and is named in declined_detection_methods with the reason. Outside per-issue mode Burp ignores the list, and a non-empty one is reported unapplied",
		listShaped: true,
		applies:    true,
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
		// how many extra passes a FAILED item is re-dispatched (Burp's shipped default is 1)
		what:    "how many extra passes a failed item is re-dispatched; 0 is a real choice — an operator who would rather account the item's coverage as lost than retry against a target that is refusing",
		min:     0,
		read:    func(c BuiltInConfig) OptUint32 { return c.FollowUpPasses },
		apply:   func(a *AuditConfig, v uint32) { a.FollowUpPasses = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "consolidate_passive_issues",
		burpKey: "scanner/audit_optimization/consolidate_passive_issues",
		what:    "not applied: a run cannot switch merging off for its own passive findings — duplicate issues are merged at intake by the finding store for the whole project, under the operator's consolidation action (keep existing / keep both / keep new, set in Issues › Consolidation)",
		applies: false,
	},
	{
		name:    "follow_redirections",
		burpKey: "scanner/audit_optimization/follow_redirections",
		// Burp's boolean "Follow redirections where necessary" (Zhd_.java:41,55). The documentation's
		// reason for it is the check burpsy applies it to; Burp's own per-check predicate was not
		// located, so this names exactly what follows and what does not (run_overrides.go).
		what:    "true makes the reflected-XSS check follow a probe's redirect — within the engagement scope, or to the same host and port when no scope is configured, every hop authorised and paced like a probe — and look for its breakout on the page it lands on as well as in the 30x. Every other check reads the 30x itself either way (open redirection and header injection depend on it). False or unset follows nothing, as before",
		read:    func(c BuiltInConfig) OptUint32 { return c.FollowRedirections },
		apply:   func(a *AuditConfig, v uint32) { a.FollowRedirects = SomeUint32(v) },
		applies: true,
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
		what:    "how many mutation attempts a check spends per candidate: minimise_false_negatives 4, normal 8, minimise_false_positives 10 (Burp's own table)",
		read:    func(c BuiltInConfig) OptUint32 { return c.ScanAccuracy },
		apply:   func(a *AuditConfig, v uint32) { a.ScanAccuracy = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "scan_speed",
		burpKey: "scanner/audit_optimization/scan_speed",
		what:    "which per-check mutation sets run: fast admits only the cheapest checks, thorough admits every one, and a check with no declared speed runs at every level",
		read:    func(c BuiltInConfig) OptUint32 { return c.ScanSpeed },
		apply:   func(a *AuditConfig, v uint32) { a.ScanSpeed = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "skip_ineffective_checks",
		burpKey: "scanner/audit_optimization/skip_ineffective_checks",
		// Applied, and per INSERTION POINT rather than per check — which is what Burp does
		// (Zfhb.java:81-83 gates the per-insertion-point dispatch filter on the point's own
		// effectiveness, Zfhb.java:81-83 via Zcgg.Zw → point.Zp(new Zc3c())). The old row said
		// the engine "infers nothing about a check's effectiveness", which was the wrong
		// subject: the gate never asked about a check. What the model cannot recover from the
		// tree is Burp's exact predicate, so the row says so rather than claiming a match —
		// the decision is ported, the metric is ours (point_effectiveness.go).
		what:    "applied per insertion point: a place this run has probed without a single answer is dropped from the next dispatch (the predicate is ours, not Burp's — see point_effectiveness.go)",
		read:    func(c BuiltInConfig) OptUint32 { return c.SkipIneffectiveChecks },
		apply:   func(a *AuditConfig, v uint32) { a.SkipIneffectiveChecks = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "parallel_crawl_and_audit",
		burpKey: "scanner/audit_optimization/parallel_crawl_and_audit",
		what:    "not applied: crawling and auditing are already separate operator-triggered actions here, not one task with a run-together/sequential switch to flip",
		applies: false,
	},
	{
		name:    "logging_enabled",
		burpKey: "scanner/audit_optimization/logging_enabled",
		what:    "not applied: this engine has no separate per-audit request log to switch; every probe an audit sends is already recorded in the traffic store",
		applies: false,
	},
	{
		name:    "audit_connect_timeout",
		burpKey: "scanner/audit_project_option_overrides/connect_timeout",
		what:    "seconds this run's probes may spend connecting (TCP connect and TLS handshake), in place of the engagement's network setting and for this run only: the run gets its own derived sender behind the same scope gate, and the engagement sender Repeater and Intruder share is unchanged. 0 never times out; -1 (Burp's \"not overridden\") leaves the engagement's bound. Probes sent after the run returns — the deferred stored and out-of-band phases — use the engagement's",
		read:    func(c BuiltInConfig) OptUint32 { return c.AuditConnectTimeout },
		apply:   func(a *AuditConfig, v uint32) { a.ConnectTimeout = SomeUint32(v) },
		max:     sender.MaxTimeoutMS / 1000,
		applies: true,
	},
	{
		name:    "audit_normal_timeout",
		burpKey: "scanner/audit_project_option_overrides/normal_timeout",
		what:    "seconds this run's probes wait for a response once connected before the probe is recorded as a send failure, in place of the engagement's network setting and for this run only (its own derived sender, the engagement sender unchanged); a shorter per-probe budget still wins. 0 never times out — the probe is then bounded only by the audit's time budget; -1 (Burp's \"not overridden\") leaves the engagement's bound. Probes sent after the run returns use the engagement's",
		read:    func(c BuiltInConfig) OptUint32 { return c.AuditNormalTimeout },
		apply:   func(a *AuditConfig, v uint32) { a.NormalTimeout = SomeUint32(v) },
		max:     sender.MaxTimeoutMS / 1000,
		applies: true,
	},
	{
		name:    "quick_scan_url_params",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_url_params",
		// whether URL parameters get the light pass. This is a DIFFERENT decision from the insertion_point_types
		// key of the same name: that one chooses whether the points are enumerated at all, this one
		// whether the enumerated ones get the cheap pass or the full one. Declining these as
		// redundant was factually wrong, and it is what left an operator unable to ask for a light
		// audit of some kinds and a full audit of others (burpsy-react-ui-02qi, Zrdr.java:26).
		what:    "whether URL parameters get the light audit tier rather than the full pass for every point of that kind",
		read:    func(c BuiltInConfig) OptUint32 { return c.QuickScanURLParams },
		apply:   func(a *AuditConfig, v uint32) { a.QuickScanURLParams = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "quick_scan_body_params",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_body_params",
		// whether body parameters get the light pass. This is a DIFFERENT decision from the insertion_point_types
		// key of the same name: that one chooses whether the points are enumerated at all, this one
		// whether the enumerated ones get the cheap pass or the full one. Declining these as
		// redundant was factually wrong, and it is what left an operator unable to ask for a light
		// audit of some kinds and a full audit of others (burpsy-react-ui-02qi, Zrdr.java:26).
		what:    "whether body parameters get the light audit tier rather than the full pass for every point of that kind",
		read:    func(c BuiltInConfig) OptUint32 { return c.QuickScanBodyParams },
		apply:   func(a *AuditConfig, v uint32) { a.QuickScanBodyParams = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "quick_scan_cookies",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_cookies",
		// whether cookies get the light pass. This is a DIFFERENT decision from the insertion_point_types
		// key of the same name: that one chooses whether the points are enumerated at all, this one
		// whether the enumerated ones get the cheap pass or the full one. Declining these as
		// redundant was factually wrong, and it is what left an operator unable to ask for a light
		// audit of some kinds and a full audit of others (burpsy-react-ui-02qi, Zrdr.java:26).
		what:    "whether cookies get the light audit tier rather than the full pass for every point of that kind",
		read:    func(c BuiltInConfig) OptUint32 { return c.QuickScanCookies },
		apply:   func(a *AuditConfig, v uint32) { a.QuickScanCookies = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "quick_scan_http_headers",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_http_headers",
		// whether HTTP headers get the light pass. This is a DIFFERENT decision from the insertion_point_types
		// key of the same name: that one chooses whether the points are enumerated at all, this one
		// whether the enumerated ones get the cheap pass or the full one. Declining these as
		// redundant was factually wrong, and it is what left an operator unable to ask for a light
		// audit of some kinds and a full audit of others (burpsy-react-ui-02qi, Zrdr.java:26).
		what:    "whether HTTP headers get the light audit tier rather than the full pass for every point of that kind",
		read:    func(c BuiltInConfig) OptUint32 { return c.QuickScanHTTPHeaders },
		apply:   func(a *AuditConfig, v uint32) { a.QuickScanHTTPHeaders = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "quick_scan_param_name",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_param_name",
		// whether parameter names get the light pass. This is a DIFFERENT decision from the insertion_point_types
		// key of the same name: that one chooses whether the points are enumerated at all, this one
		// whether the enumerated ones get the cheap pass or the full one. Declining these as
		// redundant was factually wrong, and it is what left an operator unable to ask for a light
		// audit of some kinds and a full audit of others (burpsy-react-ui-02qi, Zrdr.java:26).
		what:    "whether parameter names get the light audit tier rather than the full pass for every point of that kind",
		read:    func(c BuiltInConfig) OptUint32 { return c.QuickScanParamName },
		apply:   func(a *AuditConfig, v uint32) { a.QuickScanParamName = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "quick_scan_entire_body",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_entire_body",
		// whether the entire body get the light pass. This is a DIFFERENT decision from the insertion_point_types
		// key of the same name: that one chooses whether the points are enumerated at all, this one
		// whether the enumerated ones get the cheap pass or the full one. Declining these as
		// redundant was factually wrong, and it is what left an operator unable to ask for a light
		// audit of some kinds and a full audit of others (burpsy-react-ui-02qi, Zrdr.java:26).
		what:    "whether the entire body get the light audit tier rather than the full pass for every point of that kind",
		read:    func(c BuiltInConfig) OptUint32 { return c.QuickScanEntireBody },
		apply:   func(a *AuditConfig, v uint32) { a.QuickScanEntireBody = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "quick_scan_url_path_filename",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_url_path_filename",
		// whether URL path filenames get the light pass. This is a DIFFERENT decision from the insertion_point_types
		// key of the same name: that one chooses whether the points are enumerated at all, this one
		// whether the enumerated ones get the cheap pass or the full one. Declining these as
		// redundant was factually wrong, and it is what left an operator unable to ask for a light
		// audit of some kinds and a full audit of others (burpsy-react-ui-02qi, Zrdr.java:26).
		what:    "whether URL path filenames get the light audit tier rather than the full pass for every point of that kind",
		read:    func(c BuiltInConfig) OptUint32 { return c.QuickScanURLPathFilename },
		apply:   func(a *AuditConfig, v uint32) { a.QuickScanURLPathFilename = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "quick_scan_url_path_folders",
		burpKey: "scanner/frequently_occurring_insertion_points/quick_scan_url_path_folders",
		// whether URL path folders get the light pass. This is a DIFFERENT decision from the insertion_point_types
		// key of the same name: that one chooses whether the points are enumerated at all, this one
		// whether the enumerated ones get the cheap pass or the full one. Declining these as
		// redundant was factually wrong, and it is what left an operator unable to ask for a light
		// audit of some kinds and a full audit of others (burpsy-react-ui-02qi, Zrdr.java:26).
		what:    "whether URL path folders get the light audit tier rather than the full pass for every point of that kind",
		read:    func(c BuiltInConfig) OptUint32 { return c.QuickScanURLPathFolders },
		apply:   func(a *AuditConfig, v uint32) { a.QuickScanURLPathFolders = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "skip_all_tests_for_parameters",
		burpKey: "scanner/ignored_insertion_points/skip_all_tests_for_parameters",
		// PARTLY applied, and saying "not applied" was a false statement in an operator-facing table
		// (burpsy-react-ui-86le). The control IS honoured: /api/scanner/configs accepts
		// skip_all_tests_for_parameters as a list of parameter names, AuditConfig carries it, and
		// the enumerator drops a matching point from every kind as a bcheck.Declined. What is not
		// ported is Burp's VALUE SHAPE — a list of match rules ({enabled, parameter, item,
		// match_type, expression}, e.g. matches_regex over an xml_attribute name) rather than a list
		// of names — so a rule that matched by expression or by item arrives here as a name that
		// matches nothing.
		//
		// So this is not a row that does not apply, and it is not a row that fully applies either.
		// listShaped marks it as the second, which keeps it OUT of the "not applied" list an
		// operator reads as "this control is unsupported" while keeping the reason text naming what
		// is genuinely missing.
		what:       "partly applied: a parameter NAME in this list (set through /api/scanner/configs) has its insertion points dropped from every check. Burp's own value is a list of match rules ({parameter, item, match_type, expression}) and this engine has no matcher for them: a loaded file's empty list is honoured as the no-op it is, and a non-empty one is reported unapplied rather than read as names",
		listShaped: true,
		applies:    true,
	},
	{
		name:    "skip_server_side_injection_for_parameters",
		burpKey: "scanner/ignored_insertion_points/skip_server_side_injection_for_parameters",
		// Applied since burpsy-react-ui-gmdk, through the same reduced value shape as the skip-all
		// list: parameter NAMES set through the API, and Burp's rule objects reported when a file
		// carries them. The classification of the check set it needed is server_side_injection.go.
		what:       "partly applied: a parameter NAME in this list (set through /api/scanner/configs) is not probed by the server-side injection checks — SQL injection and XPath always, and OS command, code, template, XSS, XXE, path traversal, LDAP and the rest of Burp's set while skip_ineffective_checks is on — and is still probed by every other check. Burp's own value is a list of match rules ({parameter, item, match_type, expression}) and this engine has no matcher for them: a loaded file's empty list is honoured as the no-op it is, and a non-empty one is reported unapplied",
		listShaped: true,
		applies:    true,
	},
	{
		// Burp's two analysis switches (Zxc3.java:27-28; burpsy-react-ui-9mti). Static is the audit's
		// lexical source-to-sink pass (AnalyzeDOMDocument); dynamic is everything that drives the
		// browser. See js_analysis.go.
		name:    "javascript_use_static_analysis",
		burpKey: "scanner/javascript_analysis/use_static_analysis",
		what:    "false stops the audit's static DOM pass — the lexical source-to-sink analysis of each item's own scripts — and the browser confirmation it seeds, which has nothing to confirm without it; the browser-driven DOM checks still run while dynamic analysis is on. True or unset runs it. The proxy-capture static pass is not an audit run and does not read this key",
		read:    func(c BuiltInConfig) OptUint32 { return c.JSUseStaticAnalysis },
		apply:   func(a *AuditConfig, v uint32) { a.JavaScriptStaticAnalysis = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "javascript_use_dynamic_analysis",
		burpKey: "scanner/javascript_analysis/use_dynamic_analysis",
		what:    "false takes every browser-driven DOM check out of the run's check set and skips the browser confirmation of static candidates, so the run starts no browser; the static pass's candidates are then reported as tentative findings saying dynamic analysis was off. The crawl's rendered-location pass reads the scanner's configuration and declines with the reason. The deferred stored-DOM render (FinishScan) is scan-level and does not read it. True or unset runs both",
		read:    func(c BuiltInConfig) OptUint32 { return c.JSUseDynamicAnalysis },
		apply:   func(a *AuditConfig, v uint32) { a.JavaScriptDynamicAnalysis = SomeUint32(v) },
		applies: true,
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
		what:    "seconds the static DOM pass may spend on one item (Burp labels the field in seconds, Zrde.java:204,230); when it runs out the pass stops, keeps what it found, marks the analysis incomplete, and the item's javascript_analysis_skips names the static pass and the limit. 0 is no limit, as Burp's documentation says of zero or blank",
		read:    func(c BuiltInConfig) OptUint32 { return c.JSMaxStaticSecondsPerItem },
		apply:   func(a *AuditConfig, v uint32) { a.MaxStaticTimePerItem = SomeUint32(v) },
		applies: true,
	},
	{
		name:    "javascript_max_dynamic_time_per_item",
		burpKey: "scanner/javascript_analysis/max_dynamic_time_per_item",
		what:    "seconds the browser-driven DOM work may spend on one item, on one clock started by the item's first browser use and shared by its DOM checks and the confirmation tier; a DOM check stopped by it, or not started because it was spent, is counted skipped (never clean, and never a send failure that trips the breaker) and named in the item's javascript_analysis_skips. 0 is no limit",
		read:    func(c BuiltInConfig) OptUint32 { return c.JSMaxDynamicSecondsPerItem },
		apply:   func(a *AuditConfig, v uint32) { a.MaxDynamicTimePerItem = SomeUint32(v) },
		applies: true,
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
	// Partial marks a key this engine honours through a REDUCED form of Burp's value: the control
	// works, and the parts of the value it does not understand do not (burpsy-react-ui-86le).
	//
	// It is the third answer, and reporting it as either of the other two is the defect: `Applies:
	// false` on a control the engine honours is a settings page telling an operator their skip list
	// is unsupported while it silently works, and `Applies: true` would be the reverse — claiming
	// full support for a value shape this engine cannot read. A consumer showing "unsupported"
	// should exclude a Partial row; one showing what is missing should read What.
	Partial bool `json:"partial"`
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
			Partial: k.listShaped,
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
			Partial: k.listShaped,
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
	applied, rep := c.applyWithAccounting(base)
	return applied, rep.Unapplied
}

// configApplyReport is the full accounting of one overlay, by row name: every key the source set
// lands in exactly one of the two lists. ApplyWithReport returns the second; the first exists so a
// test can prove the partition holds rather than trusting that a key missing from "unapplied" was
// applied (burpsy-react-ui-saq3.1 was a key in neither).
type configApplyReport struct {
	Applied   []string
	Unapplied []string
}

// applyWithAccounting is ApplyWithReport with the applied half of the answer kept.
func (c BuiltInConfig) applyWithAccounting(base AuditConfig) (AuditConfig, configApplyReport) {
	var rep configApplyReport
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
	named := func(k string) bool {
		for _, row := range builtInConfigKeys {
			if row.name == k {
				return parsed[strings.TrimPrefix(row.burpKey, "scanner/")] || parsed[row.name]
			}
		}
		return false
	}
	for _, k := range builtInConfigKeys {
		switch {
		case k.listShaped:
			// Honoured through a reduced form of Burp's value. Accounted below by the handler that
			// owns the value's shape — never skipped outright: that skip is what left a parsed
			// selected_issues in neither list (burpsy-react-ui-saq3.1).
			continue
		case k.read != nil && k.read(c).Set:
			if !k.applies {
				rep.Unapplied = append(rep.Unapplied, k.name)
				continue
			}
			k.apply(&base, k.read(c).Value)
			rep.Applied = append(rep.Applied, k.name)
		case named(k.name):
			// The source named the key and there is no value here this engine can act on.
			rep.Unapplied = append(rep.Unapplied, k.name)
		}
	}
	// An override the source set to Burp's -1 asked for nothing and got nothing: applied, as asked.
	rep.Applied = append(rep.Applied, c.InheritedOverrides...)
	c.applyIssueSelection(&base, &rep, named("selected_issues"))
	c.accountIgnoredParameterRules(&rep, named)
	// A recorded key no row claims — a `scanner/*` key or section this table has never heard of — is
	// reported as the source spelled it. Without this the parser recorded it and the report, which
	// only walks rows, never said so: the same neither-applied-nor-reported hole, one level out.
	rowFor := make(map[string]bool, 2*len(builtInConfigKeys))
	for _, k := range builtInConfigKeys {
		rowFor[strings.TrimPrefix(k.burpKey, "scanner/")] = true
		rowFor[k.name] = true
	}
	for _, recorded := range c.UnrepresentableKeys {
		if !rowFor[recorded] {
			rep.Unapplied = append(rep.Unapplied, recorded)
		}
	}
	// The light tier's per-kind set is derived from the eight quick_scan_* fields, so it is built
	// HERE rather than by each row. Doing it per row looks tidier and is untestable: the rebuild reads
	// the whole set, so eight of them produce the same answer as one and a row that stopped rebuilding
	// would be indistinguishable from one that did. A single rebuild after the loop is both cheaper
	// and the only version a test can pin.
	base.rebuildLightAuditKinds()
	return base, rep
}

// accountIgnoredParameterRules accounts for the list-shaped `ignored_insertion_points` rows a
// source set. Burp's value is a list of match rules; this engine honours parameter NAMES set
// through its own API and has no matcher for Burp's rule objects. An empty list asks for nothing and
// is therefore honoured in full; a non-empty one is reported — reading a rule object as a name
// would skip a parameter nobody named, or none of the ones that were.
func (c BuiltInConfig) accountIgnoredParameterRules(rep *configApplyReport, named func(string) bool) {
	for _, k := range builtInConfigKeys {
		if !k.listShaped || !strings.HasPrefix(k.burpKey, "scanner/ignored_insertion_points/") {
			continue
		}
		n, set := c.IgnoredParameterRules[k.name]
		switch {
		case set && n == 0:
			rep.Applied = append(rep.Applied, k.name)
		case set:
			rep.Unapplied = append(rep.Unapplied, k.name)
		case named(k.name):
			rep.Unapplied = append(rep.Unapplied, k.name)
		}
	}
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
// this engine honours. Six presets are *transcribed*; eighteen shipped files set a key that takes
// effect here. Re-derived on 2026-10-07 (burpsy-react-ui-saq3.1) from the files themselves: each is
// vendored byte-for-byte in testdata/burp-configs, and
// TestTheHonouredShippedConfigurationCountIsDerivedFromBurpsOwnFiles counts the ones whose import
// applies at least one key. It was 15 on 2026-09-14; scan_speed and scan_accuracy (ev7y) and the
// eight quick_scan_* and number_of_follow_up_passes parser mappings (saq3.1) are what moved it.
const BurpShippedConfigsSettingAnHonouredKey = 18

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
	// failedUnits records, per dispatch unit, the checks whose probe could not be sent. Burp's
	// follow-up pass consults this before it re-dispatches: a check that failed because the
	// TRANSPORT failed is worth retrying, and a check that failed because the response said so is not
	// (Zwy6.java's Zz — `failedForEntireInsertionPoint < 1L` returns true, meaning "skip", for
	// exactly this case).
	//
	// The distinction is the whole value of a follow-up pass. Without it, a re-pass re-sends
	// everything the first pass sent, including the checks whose failure the response cannot fix, and
	// a broken target gets N times the traffic for the same coverage. burpsy's Admit was a single bit
	// with no failure memory at all, so there was nothing to consult (burpsy-react-ui-5efx).
	failedUnits map[string]map[string]bool
}

func newItemBreaker(cfg AuditConfig) *itemBreaker {
	return &itemBreaker{
		abandonUnitAfter: cfg.ConsecutiveCheckFailuresToAbandonUnit,
		failItemAfter:    cfg.ConsecutiveUnitFailuresToFailItem,
	}
}

// checkSucceeded records a check that completed without a transport failure.
func (b *itemBreaker) checkSucceeded() { b.consecutiveCheckFailures = 0 }

// checkFailed records that check could not be sent within unit, and returns true when the rest of
// the unit is abandoned.
//
// unit and check are recorded so a follow-up pass can ask whether this check already failed for a
// reason the response will not change. They are looked up on every dispatch of every unit, so the
// map is created lazily — the common case, a run where nothing fails, allocates nothing.
func (b *itemBreaker) checkFailed(unit, check string) bool {
	b.consecutiveCheckFailures++
	if unit != "" && check != "" {
		if b.failedUnits == nil {
			b.failedUnits = make(map[string]map[string]bool)
		}
		checks := b.failedUnits[unit]
		if checks == nil {
			checks = make(map[string]bool)
			b.failedUnits[unit] = checks
		}
		checks[check] = true
	}
	return b.abandonUnitAfter > 0 && b.consecutiveCheckFailures >= b.abandonUnitAfter
}

// beginPass starts a follow-up pass: the consecutive counters reset so a pass is measured against the
// same thresholds rather than inheriting the count that stopped the last one, while the failure
// MEMORY is kept -- that memory is exactly what narrows the pass.
//
// itemFailed deliberately survives. An item that tripped the breaker is still failed after a pass
// that did not clear it, and clearing the flag here would make the engine's final verdict depend on
// whether a retry happened rather than on whether the work succeeded -- so a pass that fixed
// nothing would report the item as merely BOUNDED, which is a claim this engine does not make.
func (b *itemBreaker) beginPass() {
	b.consecutiveCheckFailures = 0
	b.consecutiveUnitFailures = 0
}

// AlreadyFailed reports whether this check has failed within this unit on an earlier pass of this
// item.
//
// The predicate Burp's re-pass driver consults before re-dispatching, and the reason a follow-up
// pass is bounded work rather than more of the same: a check that already could not be sent is
// either going to be sent now (a transient 502, a dropped connection) or fail identically (a
// connection the target refuses outright), and the response cannot tell the two apart, so the
// honest thing is to try once more and count the retry rather than to assume.
func (b *itemBreaker) AlreadyFailed(unit, check string) bool {
	if b.failedUnits == nil || unit == "" || check == "" {
		return false
	}
	return b.failedUnits[unit][check]
}

// FailedCheckCount is how many checks have failed within unit across this item's passes, which is
// what Burp's `failedForEntireInsertionPoint` counts.
func (b *itemBreaker) FailedCheckCount(unit string) int {
	if b.failedUnits == nil {
		return 0
	}
	return len(b.failedUnits[unit])
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
