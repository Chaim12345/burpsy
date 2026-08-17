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
	switch s {
	case DispatchScopePerHost:
		return origin, true
	case DispatchScopePerPath:
		return origin + pathOnly, true
	case DispatchScopePerUrl:
		return origin + ex.Path, true
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
}

// DefaultAuditBudget is the default wall-clock budget for one audit run.
//
// Sized so a completely unresponsive host fails fast rather than occupying a goroutine for the
// product of every check and its read timeout.
const DefaultAuditBudget = 120 * time.Second

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
	// MaximumAuditTimeMinutes is `scanner/audit_optimization/maximum_crawl_and_audit_time`.
	MaximumAuditTimeMinutes OptUint32
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
// Test_every_built_in_config_field_has_a_key_row asserts the row count matches the number of fields on
// BuiltInConfig, so a field added without a row fails rather than being quietly unreportable and
// quietly not applied.
var builtInConfigKeys = []struct {
	// name is the key as this engine's own API spells it.
	name string
	// burpKey is the key as Burp's configuration JSON spells it, so an operator comparing against
	// Burp's own UI can find the same knob.
	burpKey string
	// what is one line an operator can act on: what changes when this key is set.
	what  string
	read  func(BuiltInConfig) OptUint32
	apply func(*AuditConfig, uint32)
}{
	{
		name:    "consecutive_check_failures_to_abandon_unit",
		burpKey: "scanner/error_handling/consecutive_audit_check_failures_to_skip_insertion_point",
		what:    "how many checks may fail in a row before the rest of that dispatch unit is abandoned (0 disables the breaker)",
		read:    func(c BuiltInConfig) OptUint32 { return c.ConsecutiveCheckFailuresToAbandonUnit },
		apply:   func(a *AuditConfig, v uint32) { a.ConsecutiveCheckFailuresToAbandonUnit = v },
	},
	{
		name:    "consecutive_unit_failures_to_fail_item",
		burpKey: "scanner/error_handling/consecutive_insertion_point_failures_to_fail_audit_item",
		what:    "how many dispatch units may be abandoned in a row before the whole item is failed (0 disables the breaker)",
		read:    func(c BuiltInConfig) OptUint32 { return c.ConsecutiveUnitFailuresToFailItem },
		apply:   func(a *AuditConfig, v uint32) { a.ConsecutiveUnitFailuresToFailItem = v },
	},
	{
		name:    "pause_session_after_failed_items",
		burpKey: "scanner/error_handling/pause_task_failed_audit_item_count",
		what:    "how many failed items pause the whole session (0 means never pause on a count)",
		read:    func(c BuiltInConfig) OptUint32 { return c.PauseSessionAfterFailedItems },
		apply:   func(a *AuditConfig, v uint32) { a.PauseSessionAfterFailedItems = v },
	},
	{
		name:    "maximum_audit_time_minutes",
		burpKey: "scanner/audit_optimization/maximum_crawl_and_audit_time",
		what:    "the wall-clock ceiling for the whole run, in minutes",
		read:    func(c BuiltInConfig) OptUint32 { return c.MaximumAuditTimeMinutes },
		apply:   func(a *AuditConfig, v uint32) { a.TimeBudget = time.Duration(v) * time.Minute },
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
		v := k.read(c)
		out = append(out, BuiltInConfigKey{
			Name:    k.name,
			BurpKey: k.burpKey,
			What:    k.what,
			Value:   v.Value,
			Set:     v.Set,
		})
	}
	return out
}

// Apply overlays this preset's keys onto a base configuration, leaving unset keys alone.
func (c BuiltInConfig) Apply(base AuditConfig) AuditConfig {
	for _, k := range builtInConfigKeys {
		if v := k.read(c); v.Set {
			k.apply(&base, v.Value)
		}
	}
	return base
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

// BuiltInConfigs is the six shipped configurations that set a key this engine implements.
//
// Transcribed from `resources/BuiltInConfigs/*.json` in the Burp Suite 2026.7.1 jar.
//
// Two of the 29 shipped configurations *do* set `pause_task_failed_audit_item_percentage`, both to
// 0 — "Crawl and Audit - CICD Optimized" and "Never stop audit due to application errors". No
// preset here carries it because BuiltInConfig has no field for the key, so it could not be
// overlaid even where it is set. That is a gap in what this engine reads, not an absence in what
// Burp ships.
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
		MaximumAuditTimeMinutes:               SomeUint32(15),
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
	},
	{
		Name:                                  "Crawl and Audit - Lightweight",
		ConsecutiveCheckFailuresToAbandonUnit: SomeUint32(2),
		ConsecutiveUnitFailuresToFailItem:     SomeUint32(2),
		PauseSessionAfterFailedItems:          SomeUint32(0),
		MaximumAuditTimeMinutes:               SomeUint32(15),
	},
	{
		Name:                                  "Never stop audit due to application errors",
		ConsecutiveCheckFailuresToAbandonUnit: SomeUint32(2),
		ConsecutiveUnitFailuresToFailItem:     SomeUint32(2),
		PauseSessionAfterFailedItems:          SomeUint32(0),
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
