// The audit queue: the items the engine decided about, retained so an operator can read them.
//
// # What was missing
//
// audit.go and audit_engine.go already implement the whole audit-item state machine — eight states,
// nine dispositions, a plan of `(dispatch unit, check)` steps, two-level failure breakers. Every one
// of those facts was computed and then thrown away: AuditWithin returns an AuditOutcome to its
// caller, the live sweep folds it into a task note and an event line, and nothing kept the item. So
// the engine could say "this item was bounded after 40% of its plan" exactly once, to whoever was
// holding the return value, and an operator asking "what is in the audit queue and what did it not
// look at" had nowhere to ask.
//
// This file is that missing retention, and nothing more: it stores what the engine already decided.
// It computes no verdict of its own.
//
// # Why the rows are written by the engine rather than assembled by a reader
//
// A reader cannot reconstruct these facts. `AuditOutcome` says how many checks were not admitted but
// not how much of the plan had run when dispatch stopped; the plan itself is a local variable in
// auditItem; and the breaker thresholds in force are a property of the run's AuditConfig, which the
// outcome does not carry. Rebuilding any of that outside the loop would mean a second implementation
// of the engine's accounting, and two implementations of one count is how they drift.
//
// # The three things that must never be one number
//
// A skipped insertion point, an abandoned dispatch unit and a failed item are three different
// events with three different causes, and this file keeps them apart on purpose:
//
//   - A **skipped insertion point** is a place in the request the enumerator would not build a point
//     for — a plain-text body it models no container in, the parts of a multipart body whose framing
//     it cannot read, or a point past the per-request ceiling. Nothing was
//     dispatched there and nothing failed; the request simply has attack surface this tool declines
//     to reach. Carried as AuditItemPoint rows with a skipped status and the enumerator's own reason.
//   - An **abandoned dispatch unit** is a unit the check-failure breaker gave up on after
//     ConsecutiveCheckFailuresToAbandonUnit checks failed in a row. Work was dispatched, it failed,
//     and the rest of that unit was never started. Counted as AuditOutcome.UnitsAbandoned (units) and
//     AuditOutcome.UnitAbandoned (the checks in them).
//   - A **failed item** is one where ConsecutiveUnitFailuresToFailItem units were abandoned back to
//     back, so the whole item stopped. ItemStateFailed, and AuditOutcome.ItemFailed for the checks.
//
// Summing them would produce a number with no cause and no remedy. The thresholds that produced the
// second and third are stored on the row (AuditItemBreakers) rather than left to be inferred from a
// config the reader would have to fetch separately and hope had not changed since.
//
// # Parity with burp.Zq5, stated rather than implied
//
// Burp's `AuditItemStatus` (`burp.Zq5`) has fifteen constants and describes the fate of an insertion
// point that has *already been expanded*. This engine's ItemState has eight and describes whether
// work was admitted at all. Six of Burp's fifteen have an exact counterpart here and use Burp's own
// operator-facing string, because an operator moving between the two tools should not have to learn
// a second word for the same fact. The rest do not, and BurpStatusesNotModelled names every one with
// the reason — a parity table that listed only the matches would make a two-thirds match look total.
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

// BurpStatus is the `burp.Zq5` constant this state corresponds to, or "" when Burp has none.
//
// Empty is a real answer, not a gap to be filled with the nearest-looking constant: ItemStatePaused
// exists because this engine's session-level failure breaker can stop admitting items, which Burp
// models on the *task* rather than on the item, so there is no Zq5 value that means it. Naming
// CANCELLED there would tell an operator the run was cancelled when nobody cancelled anything.
func (s ItemState) BurpStatus() string {
	switch s {
	case ItemStatePending:
		return "PENDING"
	case ItemStateAuditing:
		return "AUDITING"
	case ItemStateAudited:
		return "AUDITED"
	case ItemStateBounded:
		// Burp's LIMIT_EXCEEDED is the same act — expansion happened and the work was not done —
		// reached from a different limit. Burp's is the per-request insertion-point ceiling; this
		// engine's is the run's time or request budget. AuditItem.Note says which.
		return "LIMIT_EXCEEDED"
	case ItemStateFailed:
		return "FAILED_TO_SCAN"
	case ItemStateCancelled:
		// Burp's own constant, and the reason ItemStateCancelled is its own state: this is a
		// decision, not a bound. Folding it into LIMIT_EXCEEDED would tell an operator the target was
		// too expensive to audit when in fact a person stopped it, which is the opposite remedy.
		return "CANCELLED"
	}
	return ""
}

// StatusLabel is the operator-facing label for this state: Burp's own string where the semantics
// match, and this engine's own where they do not.
//
// The strings for the matching six are transcribed from the Burp Suite 2026.7.1 UI (see
// docs/research-java/UI_FILES_MAP.md). The other two are written here because inventing a Burp-looking
// label for a state Burp does not have would be the same lie as the missing-constant one above.
func (s ItemState) StatusLabel() string {
	switch s {
	case ItemStatePending:
		return "Pending"
	case ItemStateAuditing:
		return "Auditing"
	case ItemStateAudited:
		return "Audited"
	case ItemStateBounded:
		return "Skipped as limit exceeded"
	case ItemStateFailed:
		return "Failed to scan"
	case ItemStatePaused:
		return "Paused by the failure breaker"
	case ItemStateOutOfScope:
		return "Skipped as out of scope"
	case ItemStateCancelled:
		// Burp's own string for CANCELLED, and the reason this state exists as its own: "we stopped
		// this" and "this hit a bound" are different facts about coverage, and an operator reading a
		// cancelled item as a bounded one concludes the target was too hard rather than that they
		// stopped it.
		return "Cancelled"
	case ItemStateUnauditable:
		return "Skipped as nothing to audit"
	}
	return "Unknown state"
}

// BurpStatusGap is one `burp.Zq5` constant this engine has no state for, and why.
type BurpStatusGap struct {
	// Status is the Java constant, spelled as `burp.Zq5` spells it.
	Status string `json:"status"`
	// Label is the operator-facing string Burp shows for it, "" where the extraction recovered the
	// constant but no display string.
	Label string `json:"label"`
	// Why is what this engine does not have. Not a promise to add it — a statement of what a reader
	// comparing the two queues will not find here.
	Why string `json:"why"`
}

// BurpAuditItemStatusCount is how many constants `burp.Zq5` declares.
//
// Named beside the gap list so every surface reporting "6 of N" reads N from one place, the same
// reason BurpShippedConfigCount exists next to BuiltInConfigs.
const BurpAuditItemStatusCount = 15

// BurpStatusesNotModelled is every `burp.Zq5` constant with no ItemState behind it.
//
// Eight of fifteen, which is the point of writing them down: a status vocabulary that listed only its
// seven matches would let a reader conclude the state machines agree. Two of the eight are the
// light-audit ROWS, and they are absent for a reason that changed under this table's feet: the light
// tier exists (burpsy-react-ui-7bkj) as a skip decision inside a running item, not as a separate
// pass, so it has no item state of its own to finish in. Two more because this engine has no
// per-issue selection; three because it has no per-parameter-type or nesting-depth gate; one —
// NO_INSERTION_POINT_CHECKS — is not absent at all but lives at point granularity instead, where it
// belongs (see AuditItemPointNoChecks).
//
// What the engine does with the repetitive-behaviour rule, since that row is no longer here and a
// reader who came for it would find nothing: the light tier counts CLEAN same-(kind, host) points
// across a run and, from the Nth, declines the rest of that type on that host. The decline lands
// in the item's skipped total — the same place every other skip does — rather than as a state of
// its own, because a skipped point is not a different kind of item. Burp's content-similarity half
// is declined rather than half-built; see auditRun.lightAudit for why.
//
// The light rows are the reason this list was wrong once. It said "there is no light-active pass"
// three times while audit_engine.go implemented one, and a disclosure that denies a capability the
// engine has is worse than no disclosure at all: a reader who has just been wrong about light
// auditing has no reason to believe the rows about selection or parameter types either
// (burpsy-react-ui-xdtx). Every row here is now checked against the engine by a test — see
// TestTheNotModelledTableAgreesWithWhatTheEngineCanReach — so the next stale row is a failing test
// rather than a comment somebody has to remember to re-read.
var BurpStatusesNotModelled = []BurpStatusGap{
	{Status: "LIGHT_AUDITING", Label: "Light-auditing",
		Why: "the light tier is not a pass an item is dispatched into; it is a skip decision taken while the item runs, so there is no window in which an item is light-auditing rather than auditing"},
	{Status: "LIGHT_AUDITED", Label: "Light-audited",
		Why: "for the same reason: a point the light tier declines is counted in the item's skipped total with SKIPPED_DUE_TO_REPETITIVE_BEHAVIOUR, and the item still finishes in the ordinary audited state"},
	{Status: "NOT_LIGHT_AUDITED", Label: "",
		Why: "a point is never 'eligible for the light pass and skipped by it' — it either runs, or the tier declines it for repetition, and both are visible on the item that raised it"},
	{Status: "SKIPPED_PARAMETER_TYPE", Label: "Skipped",
		Why: "insertion points are not gated by parameter type; the enumerator either builds a point or declines the place and says why"},
	{Status: "SKIPPED_INSERTION_POINT_TYPE", Label: "Skipped",
		Why: "a check names the insertion-point kinds it walks; there is no scanner-wide insertion_point_types gate to exclude one"},
	{Status: "SKIPPED_BY_SELECTION", Label: "Skipped",
		Why: "an audit runs the enabled check set; there is no per-issue selection an item could be excluded by"},
	{Status: "NO_PARAMETER_MOVEMENT", Label: "Skipped as parameter movement not enabled",
		Why: "parameter relocation exists as six insertion-point kinds, but it is not a separately gated pass that can report having found no movement"},
	{Status: "NO_NESTING_ALLOWED", Label: "",
		Why: "nested insertion points are expanded unconditionally; there is no depth limit that could stop and be reported"},
}

// AuditItemPointStatus is what became of one insertion point of one audit item.
//
// # The granularity this vocabulary is honest about
//
// This engine does not dispatch per individual insertion point. DispatchScope.UnitKey keys both
// insertion-point scopes at one unit per request, because a check's own run walks every point of that
// request internally (bcheck.Enumerate) — see audit.go. So the engine has no per-point verdict to
// report, and the statuses below are the *unit's* fate attributed to each point it covered, except
// the two skip statuses, which are the enumerator's own answer about that place specifically.
//
// Presenting a per-point verdict the engine did not compute would be the exact failure this package
// exists to prevent, so the API states the granularity beside the rows rather than letting a
// per-point table imply a per-point audit.
type AuditItemPointStatus int

const (
	// AuditItemPointPending means the item has not been dispatched yet.
	AuditItemPointPending AuditItemPointStatus = iota
	// AuditItemPointAuditing means dispatch is in progress.
	AuditItemPointAuditing
	// AuditItemPointCovered means an admitted insertion-point check walked this request's point set.
	AuditItemPointCovered
	// AuditItemPointNoChecks is Burp's NO_INSERTION_POINT_CHECKS: the point exists and the enabled
	// check set has nothing bound to an insertion-point scope, so nothing was ever going to look here.
	AuditItemPointNoChecks
	// AuditItemPointNotAdmitted means the unit covering this point was refused at the admission gate —
	// a spent budget, an abandoned unit, a failed item, or a paused session.
	AuditItemPointNotAdmitted
	// AuditItemPointFailed is Burp's FAILED_TO_SCAN: the item breaker failed the item this point
	// belongs to.
	AuditItemPointFailed
	// AuditItemPointCancelled is Burp's CANCELLED: the caller's context ended the run.
	AuditItemPointCancelled
	// AuditItemPointSkippedLimit is Burp's LIMIT_EXCEEDED: the place is past the per-request insertion
	// point ceiling, so no point was built for it.
	AuditItemPointSkippedLimit
	// AuditItemPointSkippedDeclined means the enumerator refused to build a point for this place —
	// a body whose framing it does not model, an unparseable request. Nothing was dispatched and
	// nothing failed: this is attack surface the tool declines to reach, and it is the one status
	// here that is a property of the place rather than of the audit.
	AuditItemPointSkippedDeclined
	// AuditItemPointSkippedNested is Burp's "Skipped as nested insertion points not enabled": the
	// place is inside an already-decoded parameter value and the run turned nested expansion off.
	//
	// Distinct from SkippedDeclined, which is attack surface the enumerator *cannot* reach. This is
	// surface it deliberately did not reach because the operator configured it that way, and the
	// two must not read alike: one is a tool limitation to file, the other is a setting to change.
	AuditItemPointSkippedNested
	// AuditItemPointSkippedOperator is Burp's operator skip list: the parameter was exempted
	// from testing by name — scanner.ignored_insertion_points.skip_all_tests_for_parameters.
	// A third "deliberate" status beside SkippedNested because the operator's exemption and a
	// run-config toggle answer different questions: one names THIS parameter on THIS
	// engagement, the other is a global audit configuration, and the operator reading the
	// queue needs to know which setting to change.
	AuditItemPointSkippedOperator
)

// Label is the operator-facing label, using Burp's own string for the four statuses that have one.
func (s AuditItemPointStatus) Label() string {
	switch s {
	case AuditItemPointPending:
		return "Pending"
	case AuditItemPointAuditing:
		return "Auditing"
	case AuditItemPointCovered:
		return "Audited"
	case AuditItemPointNoChecks:
		return "No insertion point checks"
	case AuditItemPointNotAdmitted:
		return "Skipped as limit exceeded"
	case AuditItemPointFailed:
		return "Failed to scan"
	case AuditItemPointCancelled:
		return "Cancelled"
	case AuditItemPointSkippedLimit:
		return "Skipped as limit exceeded"
	case AuditItemPointSkippedDeclined:
		return "Skipped"
	case AuditItemPointSkippedNested:
		return "Skipped as nested insertion points not enabled"
	case AuditItemPointSkippedOperator:
		return "Skipped by the operator's parameter skip list"
	}
	return "Unknown"
}

// IsSkip reports whether this status means no work was dispatched at this point. The two skip
// statuses are properties of the place; the rest describe what the audit did with it.
func (s AuditItemPointStatus) IsSkip() bool {
	return s == AuditItemPointSkippedLimit || s == AuditItemPointSkippedDeclined ||
		s == AuditItemPointSkippedNested || s == AuditItemPointSkippedOperator
}

// MarshalJSON writes the label rather than the ordinal, matching DispatchScope and Disposition — the
// wire shape stays readable and stays stable if a status is inserted into the middle of the list.
func (s AuditItemPointStatus) MarshalJSON() ([]byte, error) { return json.Marshal(s.Label()) }

// AuditItemPoint is one insertion point of one audit item, or one place the enumerator declined.
//
// Kind tells the two apart: an enumerated point carries its bcheck.IpKind, and a declined place
// carries "" because there is no point to have a kind. That distinction is load-bearing rather than
// cosmetic — a declined place is attack surface that was never reachable, and counting it among the
// points would inflate the coverage denominator with places nothing could ever have tested.
//
// The point's base value is deliberately not stored. This package's whole thesis is that raw bytes
// are written once and never copied, and a queue holding one substring of the request per parameter
// per retained item would be a second copy of the traffic, kept for a table column.
type AuditItemPoint struct {
	// Kind is the bcheck.IpKind of an enumerated point, "" for a declined place.
	Kind string `json:"kind"`
	// Name is the parameter, header or cookie name for an enumerated point; for a declined place it
	// is what was declined ("request body").
	Name   string               `json:"name"`
	Status AuditItemPointStatus `json:"status"`
	// Detail is why the status is not "Audited", "" when it is. For a declined place this is the
	// enumerator's own reason, which is the only place the specific refusal is recorded.
	Detail string `json:"detail,omitempty"`
}

// AuditItemBreakers is the budget and breaker configuration this item was audited under.
//
// Stored on the row rather than fetched alongside it, because the question an operator asks about a
// skipped item is "what threshold did I hit", and answering it from a separately-fetched current
// configuration would answer about the configuration *now* — which a -scan-config change, or a
// per-request `config` name on the audit that produced this row, may already have moved.
type AuditItemBreakers struct {
	// TimeBudgetMs is the run's wall-clock ceiling, 0 when there was none.
	TimeBudgetMs int64 `json:"time_budget_ms"`
	// MaxRequests is the run's outbound-probe ceiling. Nil is uncapped, which is a different
	// instruction from a cap of zero — see scanner.OptUint32.
	MaxRequests                           *uint32 `json:"max_requests"`
	ConsecutiveCheckFailuresToAbandonUnit uint32  `json:"consecutive_check_failures_to_abandon_unit"`
	ConsecutiveUnitFailuresToFailItem     uint32  `json:"consecutive_unit_failures_to_fail_item"`
	PauseSessionAfterFailedItems          uint32  `json:"pause_session_after_failed_items"`
	PauseSessionAtFailedItemPercentage    uint8   `json:"pause_session_at_failed_item_percentage"`
	// MaxInsertionPointsPerRequest is the enumerator's per-request ceiling — the threshold behind
	// every AuditItemPointSkippedLimit row. The run's own value, not the engine default: an
	// operator who lowered the ceiling and read 30 here would be reading about a run that never
	// happened.
	MaxInsertionPointsPerRequest int `json:"max_insertion_points_per_request"`
	// NestedInsertionPoints reports whether this run expanded the JSON/base64/XML structure inside
	// parameter values. False is the explanation for every AuditItemPointSkippedNested row.
	NestedInsertionPoints bool `json:"nested_insertion_points"`
}

func newAuditItemBreakers(cfg AuditConfig) AuditItemBreakers {
	b := AuditItemBreakers{
		TimeBudgetMs:                          cfg.TimeBudget.Milliseconds(),
		ConsecutiveCheckFailuresToAbandonUnit: cfg.ConsecutiveCheckFailuresToAbandonUnit,
		ConsecutiveUnitFailuresToFailItem:     cfg.ConsecutiveUnitFailuresToFailItem,
		PauseSessionAfterFailedItems:          cfg.PauseSessionAfterFailedItems,
		PauseSessionAtFailedItemPercentage:    cfg.PauseSessionAtFailedItemPercentage,
		MaxInsertionPointsPerRequest:          cfg.MaxInsertionPointsPerBaseRequest(),
		NestedInsertionPoints:                 cfg.NestedInsertionPointsEnabled(),
	}
	if cfg.MaxRequests.Set {
		n := cfg.MaxRequests.Value
		b.MaxRequests = &n
	}
	return b
}

// AuditItem is one row of the audit queue: one captured exchange the engine has decided about.
//
// One row per exchange, not one per audit. Burp's queue behaves the same way — "Audit again" replaces
// an item's status rather than appending a second row — and Attempts is what keeps that from hiding
// history: a row saying "Audited, 3 attempts" is a different claim from one saying "Audited".
type AuditItem struct {
	ExchangeID core.ExchangeID `json:"exchange_id"`
	// Seq is the queue position, monotonically increasing per enqueue. A re-audit takes a new one, so
	// "most recently queued" is orderable without comparing wall-clock times.
	Seq uint64 `json:"seq"`
	// Method, Host, Port, TLS and Path identify the request. Empty/zero until the engine has resolved
	// the exchange, which is after the item is queued — so a Pending row can be unnamed, and reports
	// that honestly rather than showing a plausible-looking placeholder.
	Method string `json:"method"`
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	TLS    bool   `json:"tls"`
	Path   string `json:"path"`

	State ItemState `json:"state"`
	// StatusLabel is State's operator-facing label, and BurpStatus the burp.Zq5 constant it
	// corresponds to ("" when Burp has none). Both on the row rather than derived by the reader,
	// because the Cancelled flag overrides them: a bounded item whose context ended is Burp's
	// CANCELLED, not its LIMIT_EXCEEDED.
	StatusLabel string `json:"status_label"`
	BurpStatus  string `json:"burp_status"`
	// Note is why this item is in a non-audited state, in one line an operator can act on. Empty for
	// an item that ran its whole plan.
	Note string `json:"note,omitempty"`
	// Attempts counts how many times this exchange has been queued for audit, including this one.
	Attempts int `json:"attempts"`

	// Checks is the size of the enabled check set this item was measured against — the number
	// AuditOutcome.Considered equals for a dispatched item.
	Checks int `json:"checks"`
	// UnitsPlanned and StepsPlanned are the shape of the plan: how many dispatch units the item was
	// broken into and how many (unit, check) steps that came to. StepsDone is how many of those steps
	// reached a disposition.
	//
	// StepsPlanned is zero for an item refused before planning, and that is not the same as a plan of
	// length zero that finished: a percentage computed from a zero denominator is undefined, and the
	// API reports it as absent rather than as 0%.
	UnitsPlanned int `json:"units_planned"`
	StepsPlanned int `json:"steps_planned"`
	StepsDone    int `json:"steps_done"`

	// Outcome is the engine's own accounting, unmodified. The nine disposition counters partition
	// Checks for a dispatched item; see AuditOutcome.
	Outcome AuditOutcome `json:"outcome"`
	// Breakers is the configuration in force for this item — the thresholds behind any skip.
	Breakers AuditItemBreakers `json:"breakers"`

	// Points is this request's insertion points and the places the enumerator declined, in
	// enumeration order with the declines last. Empty when no item ledger was attached at audit time
	// or when the request could not be read.
	Points []AuditItemPoint `json:"points"`
	// PointKinds names the insertion-point kinds Points was enumerated for. Reported because the
	// count means nothing without it: "9 insertion points" is a claim about the four kinds the native
	// injection evaluators walk, not about every place a payload could go.
	PointKinds []string `json:"point_kinds"`
	// PointsEnumerated, PointsSkipped and PointsPlaces are three counts that must never be one.
	// Enumerated is points a payload could be placed in; Skipped is points past the per-request
	// ceiling that were dropped; Places is distinct places the enumerator refused outright.
	PointsEnumerated int `json:"points_enumerated"`
	PointsSkipped    int `json:"points_skipped"`
	PointsPlaces     int `json:"points_declined_places"`

	// QueuedUnixMs and UpdatedUnixMs are when the item was queued and when its row last changed.
	QueuedUnixMs  int64 `json:"queued_unix_ms"`
	UpdatedUnixMs int64 `json:"updated_unix_ms"`
}

// CoveragePercent is how much of the item's plan reached a disposition, and whether that percentage
// is defined at all.
//
// Deliberately not clamped to 100 on a terminal item: a bounded item that stopped after two of five
// steps is finished *and* 40% audited, and those are the two facts an operator needs at once. A
// progress bar that snapped to 100 the moment the item left the queue would report exactly the
// completeness the engine refused to claim.
//
// False means undefined rather than zero. An item refused before planning has no plan to be a
// fraction of, and 0% would read as "nothing done yet, something still to do".
func (i AuditItem) CoveragePercent() (int, bool) {
	if i.StepsPlanned <= 0 {
		return 0, false
	}
	return i.StepsDone * 100 / i.StepsPlanned, true
}

// AuditItemLedger retains the audit queue: one row per exchange, bounded, newest-queued first.
//
// # Why it is bounded, and why the bound is reported
//
// This is retained state that grows with the number of exchanges audited, which over a long crawl is
// unbounded. AuditLedger next door has the same property and solves it the same way — a cap, and a
// caller that can see the cap was hit. An eviction here is not a coverage loss (the findings and the
// task rows outlive it) but it is a loss of the *record* of what was not looked at, so Evicted is
// reported alongside Retained: a queue showing 500 rows out of 4,000 items audited must not read as
// a queue of 500 items.
//
// Nil is a supported state and every method tolerates it, which is what lets AuditConfig.Items
// default to nil: a CLI audit and a unit test pay nothing for a queue nobody reads.
type AuditItemLedger struct {
	mu   sync.Mutex
	cap  int
	seq  uint64
	rows map[core.ExchangeID]*AuditItem
	// order is the enqueue order, oldest first. Eviction takes from the front; reads walk it
	// backwards. A re-audited item moves to the back, because a new attempt is new work.
	order    []core.ExchangeID
	enqueued int
	evicted  int
}

// DefaultAuditItemCap is how many audit items one ledger retains.
//
// Five hundred is more than the live sweep's batch size (200) so a single tick is never partly
// evicted while it is still being read, and small enough that the retained rows — each holding at
// most bcheck.DefaultMaxInsertionPoints point names — stay in the low megabytes.
const DefaultAuditItemCap = 500

// NewAuditItemLedger returns an empty ledger retaining at most cap items. A non-positive cap takes
// DefaultAuditItemCap; a caller that wants no queue passes nil to AuditConfig.Items instead.
func NewAuditItemLedger(cap int) *AuditItemLedger {
	if cap <= 0 {
		cap = DefaultAuditItemCap
	}
	return &AuditItemLedger{cap: cap, rows: make(map[core.ExchangeID]*AuditItem)}
}

// Enqueue admits an item to the queue in ItemStatePending, or bumps an existing row to a new attempt.
//
// checks is the size of the check set the item will be measured against, known before dispatch
// because enabledChecks is snapshotted once per run.
func (l *AuditItemLedger) Enqueue(id core.ExchangeID, checks int) {
	if l == nil {
		return
	}
	now := time.Now().UnixMilli()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	l.enqueued++
	row, ok := l.rows[id]
	if !ok {
		row = &AuditItem{ExchangeID: id, QueuedUnixMs: now}
		l.rows[id] = row
		l.order = append(l.order, id)
	} else {
		// A re-audit resets the accounting but keeps the identity and the attempt count: the previous
		// outcome described a run that is over, and leaving its dispositions on the row while the state
		// says Pending would show refusals from an audit nobody is running.
		row.Outcome = AuditOutcome{}
		row.UnitsPlanned, row.StepsPlanned, row.StepsDone = 0, 0, 0
		row.Points, row.PointKinds = nil, nil
		row.PointsEnumerated, row.PointsSkipped, row.PointsPlaces = 0, 0, 0
		row.Note = ""
		row.QueuedUnixMs = now
		l.moveToBackLocked(id)
	}
	row.Seq = l.seq
	row.Attempts++
	row.Checks = checks
	l.setStateLocked(row, ItemStatePending, false, "")
	row.UpdatedUnixMs = now
	l.evictLocked()
}

// Begin records that dispatch has started: the exchange's identity, the shape of the plan, and this
// request's insertion points.
func (l *AuditItemLedger) Begin(id core.ExchangeID, ex *core.Exchange, cfg AuditConfig,
	unitsPlanned, stepsPlanned int, points []AuditItemPoint, kinds []string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	row := l.rows[id]
	if row == nil {
		return
	}
	identifyLocked(row, ex)
	row.Breakers = newAuditItemBreakers(cfg)
	row.UnitsPlanned, row.StepsPlanned, row.StepsDone = unitsPlanned, stepsPlanned, 0
	row.Points, row.PointKinds = points, kinds
	row.PointsEnumerated, row.PointsSkipped, row.PointsPlaces = 0, 0, 0
	for _, p := range points {
		switch {
		case p.Status == AuditItemPointSkippedLimit:
			row.PointsSkipped++
		case p.Status == AuditItemPointSkippedDeclined:
			row.PointsPlaces++
		default:
			row.PointsEnumerated++
		}
	}
	l.setStateLocked(row, ItemStateAuditing, false, "")
	row.UpdatedUnixMs = time.Now().UnixMilli()
}

// Step records one `(dispatch unit, check)` step reaching a disposition, so a long-running item's
// progress is readable while it runs rather than only once it is over.
func (l *AuditItemLedger) Step(id core.ExchangeID) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if row := l.rows[id]; row != nil {
		row.StepsDone++
		row.UpdatedUnixMs = time.Now().UnixMilli()
	}
}

// Resolve records an item's terminal outcome.
//
// One method for both the items that were dispatched and the items the session refused before it
// planned them, because the row is the same shape either way and a second method would let the two
// paths drift about which fields a terminal row carries. A refused item simply has no plan, which
// StepsPlanned == 0 already says.
//
// ex may be nil — an item refused because no such exchange exists has no identity to record, and a
// plausible-looking placeholder there would be worse than an empty row that says so. note is why the
// item is in a non-audited state, in the engine's own words, and is empty for one that ran its plan.
func (l *AuditItemLedger) Resolve(id core.ExchangeID, ex *core.Exchange, o AuditOutcome,
	cfg AuditConfig, note string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	row := l.rows[id]
	if row == nil {
		return
	}
	identifyLocked(row, ex)
	row.Outcome = o
	// Written on every resolve, not only when Begin ran: an item the session refused was still
	// refused *by* a threshold, and that threshold is the one thing the row has to be able to name.
	row.Breakers = newAuditItemBreakers(cfg)
	l.setStateLocked(row, o.State, o.Cancelled, note)
	resolvePoints(row, o)
	row.UpdatedUnixMs = time.Now().UnixMilli()
}

// Cancel stops one queued item and nothing else (burpsy-react-ui-exiu).
//
// Burp's audit-item context menu has offered Cancel since running-scans/results/audit-items/
// index.html:102-115, and without it the only way to stop one unwanted item is to disable the
// enclosing live task, which stops everything including the items that are fine. A crawler that
// reached a slow or heavily-guarded URL holds a slot and a thread until its own bounds expire, and
// the queue offers no way to reclaim just that one.
//
// It only moves a PENDING item. Work already dispatched belongs to a probe in flight and the engine
// has no per-item context to abandon it with; cancelling there would mean a half-sent request
// counted as complete. So the cancel is recorded and the item's gate reads it before dispatch —
// which is where a queued item is anyway, and which is why the state is reachable at all.
//
// An item that is not pending is refused rather than relabelled, because moving a finished row to
// Cancelled would erase the outcome it recorded. "You cannot cancel this" is the honest answer for
// an item that already finished, and it is different from "no such item".
func (l *AuditItemLedger) Cancel(id core.ExchangeID) (bool, string) {
	if l == nil {
		return false, "no audit queue is being recorded"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	row, ok := l.rows[id]
	if !ok {
		return false, "no queued item for that exchange"
	}
	if row.State != ItemStatePending {
		// Not refused as an error — the operator asked for a state and the item already has one. The
		// reason says which, so the console can say "this item already finished" rather than a bare
		// failure the operator cannot act on.
		return false, "this item is already " + row.State.StatusLabel() + ", so it cannot be cancelled"
	}
	l.setStateLocked(row, ItemStateCancelled, false,
		"Cancelled by the operator before this item was dispatched.")
	row.UpdatedUnixMs = time.Now().UnixMilli()
	return true, "cancelled"
}

// Cancelled reports whether an operator cancelled this item, which is the flag auditItem's gate reads
// before it dispatches.
//
// A map on the ledger rather than a field on the row, because the state alone is not enough: the
// engine sets the terminal state itself, and a cancelled item that has not been reached yet is
// still Pending on the row while the gate must already say no.
func (l *AuditItemLedger) Cancelled(id core.ExchangeID) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	row, ok := l.rows[id]
	return ok && row.State == ItemStateCancelled
}

// identifyLocked fills in the request identity, when there is one to fill in.
func identifyLocked(row *AuditItem, ex *core.Exchange) {
	if ex == nil {
		return
	}
	row.Method, row.Host, row.Port, row.TLS, row.Path = ex.Method, ex.Host, ex.Port, ex.TLS, ex.Path
}

// setStateLocked writes a state and the two labels derived from it, applying the Cancelled override.
func (l *AuditItemLedger) setStateLocked(row *AuditItem, state ItemState, cancelled bool, note string) {
	row.State = state
	row.Note = note
	// A bounded item whose context ended is Burp's CANCELLED, not its LIMIT_EXCEEDED. The engine folds
	// cancellation into DispositionTimeBudgetSpent for counting — a tenth disposition would break the
	// nine-way partition — but keeps the flag, and this is the surface the flag exists for: "the
	// operator navigated away" and "this host is too slow to audit in two minutes" are different facts
	// about the same stopped item.
	if cancelled && state == ItemStateBounded {
		row.StatusLabel, row.BurpStatus = "Cancelled", "CANCELLED"
		return
	}
	row.StatusLabel, row.BurpStatus = state.StatusLabel(), state.BurpStatus()
}

// resolvePoints attributes the item's outcome to each enumerated point.
//
// The two skip statuses are left alone: they are the enumerator's answer about a place, decided
// before any dispatch, and an audit's outcome cannot change whether a body's container was modelled.
func resolvePoints(row *AuditItem, o AuditOutcome) {
	status := pointStatusFor(row, o)
	detail := ""
	switch status {
	case AuditItemPointNoChecks:
		detail = "the enabled check set has no check bound to an insertion-point scope, so nothing was dispatched at this point"
	case AuditItemPointNotAdmitted:
		detail = "the dispatch unit covering this point was refused at the admission gate"
	case AuditItemPointFailed:
		detail = "the item-level failure breaker failed this request before its point set was covered"
	case AuditItemPointCancelled:
		detail = "the run was cancelled before this point's unit was dispatched"
	}
	for i := range row.Points {
		if row.Points[i].Status.IsSkip() {
			continue
		}
		row.Points[i].Status = status
		row.Points[i].Detail = detail
	}
}

// pointStatusFor decides what one item's outcome says about the points it covered.
//
// UnitsPlanned is what separates "no insertion-point check was in the set" from "one was and it did
// not get through": an item with no plan at all had no unit to admit, which is Burp's
// NO_INSERTION_POINT_CHECKS rather than a refusal.
func pointStatusFor(row *AuditItem, o AuditOutcome) AuditItemPointStatus {
	if row.UnitsPlanned == 0 {
		return AuditItemPointNoChecks
	}
	switch o.State {
	case ItemStateAudited:
		return AuditItemPointCovered
	case ItemStateFailed:
		return AuditItemPointFailed
	case ItemStateBounded:
		if o.Cancelled {
			return AuditItemPointCancelled
		}
		return AuditItemPointNotAdmitted
	case ItemStatePaused, ItemStateOutOfScope, ItemStateUnauditable:
		return AuditItemPointNotAdmitted
	}
	return AuditItemPointAuditing
}

// moveToBackLocked moves id to the end of the enqueue order.
func (l *AuditItemLedger) moveToBackLocked(id core.ExchangeID) {
	for i, existing := range l.order {
		if existing == id {
			l.order = append(l.order[:i], l.order[i+1:]...)
			break
		}
	}
	l.order = append(l.order, id)
}

// evictLocked drops the oldest rows until the ledger is inside its cap, counting every drop.
func (l *AuditItemLedger) evictLocked() {
	for len(l.order) > l.cap {
		oldest := l.order[0]
		l.order = l.order[1:]
		delete(l.rows, oldest)
		l.evicted++
	}
}

// AuditItemStats is what the queue itself can and cannot say.
//
// Retained is rows held; Enqueued is every item ever admitted, including re-audits; Evicted is rows
// dropped at the cap. Retained alone would read as the whole history of the process, which after a
// crawl it is not.
type AuditItemStats struct {
	Retained int `json:"retained"`
	Enqueued int `json:"enqueued"`
	Evicted  int `json:"evicted"`
	Cap      int `json:"cap"`
}

// Stats reports the queue's own bounds.
func (l *AuditItemLedger) Stats() AuditItemStats {
	if l == nil {
		return AuditItemStats{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return AuditItemStats{Retained: len(l.order), Enqueued: l.enqueued, Evicted: l.evicted, Cap: l.cap}
}

// Items returns the retained rows, most recently queued first, at most limit of them.
//
// Copied out rather than handed over: the engine keeps mutating these rows while an item runs, and a
// reader iterating the live structs would see a row change under it. A non-positive limit returns
// everything retained.
func (l *AuditItemLedger) Items(limit int) []AuditItem {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 || limit > len(l.order) {
		limit = len(l.order)
	}
	out := make([]AuditItem, 0, limit)
	for i := len(l.order) - 1; i >= 0 && len(out) < limit; i-- {
		row := l.rows[l.order[i]]
		if row == nil {
			continue
		}
		copied := *row
		if len(row.Points) > 0 {
			copied.Points = append([]AuditItemPoint(nil), row.Points...)
		}
		if len(row.PointKinds) > 0 {
			copied.PointKinds = append([]string(nil), row.PointKinds...)
		}
		out = append(out, copied)
	}
	return out
}

// ItemStateCount pairs one item state with how many retained items are in it, and with the label an
// operator reads. The label travels with the count for the same reason DispositionCount's reason
// does: a bare histogram makes the caller re-derive what each bucket means.
type ItemStateCount struct {
	State       ItemState `json:"state"`
	StatusLabel string    `json:"status_label"`
	BurpStatus  string    `json:"burp_status"`
	Count       int       `json:"count"`
	// CompletedAudit marks the one state that means no work is outstanding, so a caller can render
	// "how much of this queue actually finished" without hard-coding which state that is.
	CompletedAudit bool `json:"completed_audit"`
}

// StateCounts is the histogram over all eight states, in ItemStateAll order, including the zeroes.
//
// Every state is returned, including the empty ones, for the reason CheckCoverage returns undispatched
// checks: a histogram that dropped its zeroes would leave an operator unable to tell "nothing failed"
// from "this build cannot report failures".
func (l *AuditItemLedger) StateCounts() []ItemStateCount {
	counts := map[ItemState]int{}
	if l != nil {
		l.mu.Lock()
		for _, row := range l.rows {
			counts[row.State]++
		}
		l.mu.Unlock()
	}
	out := make([]ItemStateCount, 0, len(ItemStateAll))
	for _, s := range ItemStateAll {
		out = append(out, ItemStateCount{
			State:          s,
			StatusLabel:    s.StatusLabel(),
			BurpStatus:     s.BurpStatus(),
			Count:          counts[s],
			CompletedAudit: s.CompletedAudit(),
		})
	}
	return out
}

// declinedPastLimitPrefix is how bcheck names the decline it records when a request's points are
// truncated at the per-request ceiling.
//
// Matched on rather than inferred from a count, and matched on the `What` field specifically, because
// the ceiling decline is the one that carries Burp's LIMIT_EXCEEDED meaning and the others do not.
// This is the same trade CoverageReport.skipCount makes when it matches on an explanation rather than
// trusting a position, and it is protected the same way: Test_a_capped_enumeration_is_labelled_as_the
// _limit_being_exceeded fails if bcheck's wording moves, rather than the label silently degrading to
// a generic skip.
const declinedPastLimitPrefix = bcheck.DeclinedPastLimitWhat

// auditItemPoints enumerates one request's insertion points and the places the enumerator declined,
// as queue rows in Pending status.
//
// kinds is returned alongside because the count is meaningless without it — see
// AuditItem.PointKinds. Enumeration happens only when an item ledger is attached, so a CLI audit and
// a unit test pay nothing: it is one request parse per item, cheap beside a probe but not free.
func auditItemPoints(raw []byte, kinds []string, opts bcheck.EnumerateOptions) ([]AuditItemPoint, []string) {
	if len(raw) == 0 {
		return nil, kinds
	}
	points, declined := bcheck.EnumerateWith(raw, kinds, opts)
	out := make([]AuditItemPoint, 0, len(points)+len(declined))
	for _, p := range points {
		out = append(out, AuditItemPoint{
			Kind:   string(p.Kind),
			Name:   p.Name,
			Status: AuditItemPointPending,
		})
	}
	for _, d := range declined {
		status := AuditItemPointSkippedDeclined
		switch {
		case strings.HasPrefix(d.What, declinedPastLimitPrefix):
			status = AuditItemPointSkippedLimit
		case strings.HasPrefix(d.What, bcheck.DeclinedNestedDisabledWhat):
			status = AuditItemPointSkippedNested
		case strings.HasPrefix(d.What, bcheck.DeclinedSkippedParamWhat):
			status = AuditItemPointSkippedOperator
		}
		out = append(out, AuditItemPoint{Name: d.What, Status: status, Detail: d.Reason})
	}
	return out, kinds
}

// auditItemNote is one line saying why an item is in a non-audited state, for the queue row.
//
// Built from the outcome rather than from the state alone, because two items in ItemStateBounded can
// have stopped for different reasons and the threshold that stopped them is the actionable half.
// phaseSummary names the phases that ran for an item, and — the half that matters — says which of
// the item's checks belonged to phases that produced nothing.
//
// Burp tracks per-phase state because "this stage ran and found nothing" and "this stage never ran"
// are different facts an operator diagnosing a thin result needs to separate. The counters alone
// cannot say it: four skipped checks read identically whether they were all in the stored phase or
// spread across three (burpsy-react-ui-0qhf).
//
// Returns "" for an audited item whose phases all ran, so the queue's note column stays empty for
// the ordinary case rather than carrying a line that says nothing.
func phaseSummary(o AuditOutcome) string {
	if len(o.ByPhase) == 0 {
		return ""
	}
	// Deterministic order: declaration order, so the same outcome always renders the same line.
	var ran, quiet []string
	for _, phase := range AllCheckPhases {
		po, ok := o.ByPhase[phase.String()]
		if !ok {
			continue
		}
		name := phase.String()
		if po.Ran > 0 {
			ran = append(ran, name)
			continue
		}
		// A phase with no check that ran: report its disposition so the line explains the absence.
		switch {
		case po.Skipped > 0:
			quiet = append(quiet, fmt.Sprintf("%s skipped %d", name, po.Skipped))
		case po.SendFailures > 0:
			quiet = append(quiet, fmt.Sprintf("%s failed to send %d", name, po.SendFailures))
		case po.NotRun > 0:
			quiet = append(quiet, fmt.Sprintf("%s never ran %d", name, po.NotRun))
		case po.AlreadyCovered > 0:
			quiet = append(quiet, fmt.Sprintf("%s already covered %d", name, po.AlreadyCovered))
		}
	}
	// The note exists to explain a phase that produced nothing. When every phase in the table ran,
	// there is no absence to explain and reporting "ran: active" on every audited item would turn
	// the column into noise an operator learns to skip.
	if len(quiet) == 0 {
		return ""
	}
	parts := make([]string, 0, 2)
	if len(ran) > 0 {
		parts = append(parts, "ran: "+strings.Join(ran, ", "))
	}
	parts = append(parts, "no check ran in "+strings.Join(quiet, "; "))
	return strings.Join(parts, " · ")
}

func auditItemNote(o AuditOutcome, cfg AuditConfig) string {
	if o.Error != "" {
		return o.Error
	}
	switch o.State {
	case ItemStateAudited:
		return phaseSummary(o)
	case ItemStateFailed:
		return fmt.Sprintf("%d dispatch unit(s) were abandoned back to back, which is this run's limit of %d consecutive unit failures per item",
			o.UnitsAbandoned, cfg.ConsecutiveUnitFailuresToFailItem)
	case ItemStatePaused:
		return fmt.Sprintf("the session-level failure breaker had already paused the run: it pauses after %d failed item(s)",
			cfg.PauseSessionAfterFailedItems)
	case ItemStateBounded:
		if o.Cancelled {
			return "the caller's context ended the run before this item's plan was dispatched"
		}
		if o.RequestBudgetSpent > 0 {
			max := "uncapped"
			if cfg.MaxRequests.Set {
				max = fmt.Sprintf("%d", cfg.MaxRequests.Value)
			}
			return fmt.Sprintf("the run's outbound-request budget of %s probe(s) was spent before %d step(s) of this item's plan were started",
				max, o.RequestBudgetSpent)
		}
		return fmt.Sprintf("the run's wall-clock budget of %s was spent before %d step(s) of this item's plan were started",
			cfg.TimeBudget, o.NotRun)
	}
	return ""
}
