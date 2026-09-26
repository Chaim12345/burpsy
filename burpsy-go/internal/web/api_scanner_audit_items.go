// The audit queue on the wire: Burp's `auditItemsTable`, and its "Audit again" action.
//
// # What had no door
//
// internal/scanner implements the whole audit-item state machine — eight states, nine dispositions, a
// plan of `(dispatch unit, check)` steps, an admission ledger and two levels of failure breaker — and
// none of it was reachable from this package except as the one-shot body of POST /api/audit/{id}.
// An operator could audit an exchange and read what that audit did; they could not ask what the audit
// *queue* held, which items the live sweep had bounded, or which insertion points anything had
// covered. The engine's answer to "what did you not look at" existed and had no reader.
//
// # Why this endpoint is an index and resolves no bytes
//
// internal/web/AGENTS.md's rule: a list endpoint serves index rows and never resolves message
// payloads. Every field here is captured by the engine at audit time — the plan's shape, the
// disposition counts, the insertion-point names — and none of it is looked up when the list is
// served. The one thing that would have required reading a message is the insertion-point set, which
// is why it is enumerated inside the audit (where the request bytes are already in hand for the
// probes) rather than here. A handler that enumerated points per row would read one stored request
// per item on every poll, which is exactly the regression that rule exists to prevent.
//
// # Why there is no "total"
//
// A skipped insertion point, an abandoned dispatch unit and a failed item are three different events
// with three different causes and three different remedies. `totals` therefore has no field called
// total: every count is named for what it counts, and the three above are three fields. Summing them
// would produce a number that looks like a coverage figure and answers no question — the specific
// dishonesty this whole surface exists to avoid.
package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// defaultAuditItemPageSize bounds the rows one GET returns.
//
// Two hundred matches the live sweep's batch size, so one tick's worth of items always comes back
// whole: a page that cut a batch in half would show an operator a partial sweep and give them no way
// to tell that was what they were looking at. The response reports `truncated` either way.
const defaultAuditItemPageSize = 200

// maxAuditItemPageSize is the ceiling on ?limit. Equal to the ledger's own retention cap, because a
// caller cannot be served more rows than exist.
const maxAuditItemPageSize = scanner.DefaultAuditItemCap

// auditItemTotals is what the retained queue adds up to, with every count named for what it counts.
//
// There is deliberately no aggregate field. See the file header: the three skip-shaped facts here —
// InsertionPointsSkippedAtLimit, UnitsAbandoned, ItemsFailed — are different events, and a caller
// that wanted one number would have to decide for itself which of them it was willing to conflate.
//
// The counts are over *retained* items only, which is why ItemsRetained sits at the top of the struct
// rather than being left to be read off the array length: after a long crawl the ledger has evicted
// rows, and a totals block that did not say what its denominator was would read as the whole history
// of the process.
type auditItemTotals struct {
	ItemsRetained int `json:"items_retained"`
	// ItemsCompletedAudit is items in the one state that means no work is outstanding. Not "items
	// finished" — a bounded item is finished too, and counting it here is how a coverage claim drifts
	// from what ran.
	ItemsCompletedAudit int `json:"items_completed_audit"`
	ItemsBounded        int `json:"items_bounded"`
	ItemsFailed         int `json:"items_failed"`
	ItemsPaused         int `json:"items_paused"`
	ItemsOutOfScope     int `json:"items_out_of_scope"`
	ItemsUnauditable    int `json:"items_unauditable"`
	ItemsPending        int `json:"items_pending"`
	ItemsAuditing       int `json:"items_auditing"`

	// ChecksConsidered is every check that reached a disposition; ChecksRan is those that completed.
	// ChecksNotAdmitted is the six admission-side refusals, which includes AlreadyCovered — see
	// AuditOutcome.NotAdmitted, and note that scanner.Breakdown deliberately disagrees about that one.
	ChecksConsidered  int `json:"checks_considered"`
	ChecksRan         int `json:"checks_ran"`
	ChecksNotAdmitted int `json:"checks_not_admitted"`
	// ChecksAlreadyCovered is work that ran, against an earlier item covering the same dispatch unit.
	// Reported on its own because it is the engine's largest saving and reads as a gap if it is not.
	ChecksAlreadyCovered int `json:"checks_already_covered"`
	ChecksUnsupported    int `json:"checks_unsupported"`
	ChecksSendFailed     int `json:"checks_send_failed"`
	// ChecksUndecided is checks that ran but could not reach a verdict. Their empty result is
	// undecided, not clean.
	ChecksUndecided int `json:"checks_undecided"`

	UnitsPlanned   int `json:"units_planned"`
	UnitsAbandoned int `json:"units_abandoned"`

	// The three insertion-point counts, kept apart on purpose. Enumerated is places a payload could go;
	// SkippedAtLimit is points dropped at the per-request ceiling; PlacesDeclined is distinct places the
	// enumerator refused outright (a body whose framing it does not model).
	InsertionPointsEnumerated     int `json:"insertion_points_enumerated"`
	InsertionPointsSkippedAtLimit int `json:"insertion_points_skipped_at_limit"`
	InsertionPointPlacesDeclined  int `json:"insertion_point_places_declined"`

	ProbesSent           uint32 `json:"probes_sent"`
	ProbesRefusedByScope uint32 `json:"probes_refused_by_scope"`
	Findings             int    `json:"findings"`
	// FindingsDropped is findings the engine discarded because the check that produced them never saw
	// a probe response.
	FindingsDropped int `json:"findings_dropped"`
}

func newAuditItemTotals(items []scanner.AuditItem) auditItemTotals {
	t := auditItemTotals{ItemsRetained: len(items)}
	for _, it := range items {
		if it.State.CompletedAudit() {
			t.ItemsCompletedAudit++
		}
		switch it.State {
		case scanner.ItemStatePending:
			t.ItemsPending++
		case scanner.ItemStateAuditing:
			t.ItemsAuditing++
		case scanner.ItemStateBounded:
			t.ItemsBounded++
		case scanner.ItemStateFailed:
			t.ItemsFailed++
		case scanner.ItemStatePaused:
			t.ItemsPaused++
		case scanner.ItemStateOutOfScope:
			t.ItemsOutOfScope++
		case scanner.ItemStateUnauditable:
			t.ItemsUnauditable++
		}
		o := it.Outcome
		t.ChecksConsidered += o.Considered()
		t.ChecksRan += o.Ran
		t.ChecksNotAdmitted += o.NotAdmitted()
		t.ChecksAlreadyCovered += o.AlreadyCovered
		t.ChecksUnsupported += o.Skipped
		t.ChecksSendFailed += o.SendFailures
		t.ChecksUndecided += o.Unmeasurable
		t.UnitsPlanned += o.UnitsPlanned
		t.UnitsAbandoned += o.UnitsAbandoned
		t.InsertionPointsEnumerated += it.PointsEnumerated
		t.InsertionPointsSkippedAtLimit += it.PointsSkipped
		t.InsertionPointPlacesDeclined += it.PointsPlaces
		t.ProbesSent += o.RequestsSent
		t.ProbesRefusedByScope += o.RequestsRefused
		t.Findings += o.Findings
		t.FindingsDropped += o.FindingsDropped
	}
	return t
}

// auditItemsView is the GET body.
type auditItemsView struct {
	// Items are the retained rows, most recently queued first.
	Items []scanner.AuditItem `json:"items"`
	// Returned is len(Items) and Retained is what the ledger holds, so a page can be told from the
	// queue. Truncated is the same fact as a boolean because a client rendering a banner should not
	// have to compare two numbers to know whether to.
	Returned  int  `json:"returned"`
	Truncated bool `json:"truncated"`
	// Queue is the ledger's own bounds: retained, ever-enqueued, evicted, and the cap. An evicted row
	// is a lost record of what was not looked at, so it is reported rather than left to be inferred
	// from a count that stopped growing.
	Queue scanner.AuditItemStats `json:"queue"`
	// States is the histogram over all eight item states, zeroes included.
	States  []scanner.ItemStateCount `json:"states"`
	Totals  auditItemTotals          `json:"totals"`
	Hint    string                   `json:"hint,omitempty"`
	Parity  auditItemParityView      `json:"parity"`
	Caveats auditItemCaveatsView     `json:"caveats"`
}

// auditItemParityView states how far this queue's status vocabulary matches Burp's.
//
// Reported on the endpoint rather than written into the UI, for the reason
// BuiltInConfig.Keys is generated: a hand-written parity claim in a template renders perfectly
// while being out of date, and a partial match presented without its denominator reads as a total
// one.
type auditItemParityView struct {
	// BurpStatusesDeclared is how many constants burp.Zq5 has; Modelled is how many have an
	// ItemState behind them.
	BurpStatusesDeclared int `json:"burp_statuses_declared"`
	Modelled             int `json:"burp_statuses_modelled"`
	// NotModelled names every one that does not, with why. The list, not just the count: "9 of 15
	// missing" is not actionable and "no light-active pass, no per-issue selection" is.
	NotModelled []scanner.BurpStatusGap `json:"burp_statuses_not_modelled"`
}

// auditItemCaveatsView is what this queue cannot say, stated beside what it can.
type auditItemCaveatsView struct {
	// InsertionPointKinds names the kinds Points was enumerated for. Without it the point counts are
	// unreadable: "9 insertion points" is a claim about four kinds, not about every place a payload
	// could go.
	InsertionPointKinds []string `json:"insertion_point_kinds"`
	// PointGranularity says that a point's status is its dispatch unit's fate rather than a verdict
	// about that point specifically, because this engine keys one unit per request for both
	// insertion-point scopes.
	PointGranularity string `json:"point_granularity"`
	// MaxInsertionPointsPerRequest and NestedInsertionPoints are the two
	// `scanner/misc_insertion_point_options/*` settings the server's DEFAULT configuration carries.
	//
	// Queue-wide, so they are the default and not any one run's answer: an audit launched under a
	// named configuration can use different ones, and each item's own `breakers` block records what
	// that item was actually audited under. PerRunNote says so rather than leaving a reader to
	// assume the number here applied to every row.
	MaxInsertionPointsPerRequest int  `json:"max_insertion_points_per_request"`
	NestedInsertionPoints        bool `json:"nested_insertion_points"`
	// PerRunNote points at the per-item record, because these two values used to be reported here as
	// engine constants while a run could not change them. Now it can.
	PerRunNote string `json:"per_run_note"`
}

const auditItemPerRunNote = "these two values are the server's default configuration; an audit " +
	"launched under a named scan configuration may use different ones, and each item's own breakers " +
	"block records the ceiling and the nested-points setting that item was audited under"

const auditItemPointGranularity = "This engine keys one dispatch unit per request for both " +
	"insertion-point scopes, because a check's own run walks every point of that request internally. " +
	"So an enumerated point's status is the fate of the unit that covered it, not a verdict about " +
	"that point on its own. The two skipped statuses are the exception: those are the enumerator's " +
	"answer about that place, decided before any dispatch."

// auditItemsEmptyHint is what an empty queue means, which is not the same as an empty result.
const auditItemsEmptyHint = "no exchange has been queued for audit in this process yet; " +
	"audit one from HTTP history, or turn on the live sweep under Target › Issues"

// handleScannerAuditItems serves GET /api/scanner/audit-items: the audit queue.
func (s *Server) handleScannerAuditItems(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := defaultAuditItemPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		// A malformed or out-of-range limit is refused rather than clamped. Clamping would serve a
		// different page than the caller asked for and report it as the one they asked for, which is
		// the same class of lie as an unknown scan-configuration name silently falling back to the
		// default (see resolveAuditConfig).
		if err != nil || n < 1 || n > maxAuditItemPageSize {
			http.Error(w, fmt.Sprintf("limit must be between 1 and %d", maxAuditItemPageSize),
				http.StatusBadRequest)
			return
		}
		limit = n
	}
	// The server's own default, so the caveats block reports what an unnamed audit would run under
	// rather than three engine constants that a configuration can now move.
	base := s.auditBaseConfig()
	items := s.auditItems.Items(limit)
	stats := s.auditItems.Stats()
	view := auditItemsView{
		Items:     items,
		Returned:  len(items),
		Truncated: len(items) < stats.Retained,
		Queue:     stats,
		States:    s.auditItems.StateCounts(),
		Totals:    newAuditItemTotals(items),
		Parity: auditItemParityView{
			BurpStatusesDeclared: scanner.BurpAuditItemStatusCount,
			Modelled:             scanner.BurpAuditItemStatusCount - len(scanner.BurpStatusesNotModelled),
			NotModelled:          scanner.BurpStatusesNotModelled,
		},
		Caveats: auditItemCaveatsView{
			InsertionPointKinds:          base.InsertionKindsOrDefault(),
			PointGranularity:             auditItemPointGranularity,
			MaxInsertionPointsPerRequest: base.MaxInsertionPointsPerBaseRequest(),
			NestedInsertionPoints:        base.NestedInsertionPointsEnabled(),
			PerRunNote:                   auditItemPerRunNote,
		},
	}
	// An empty array is a real answer and gets a reason, so "nothing has been audited" is
	// distinguishable from "this build cannot report the queue" — the same argument /api/issues makes
	// by reporting its catalogue size.
	if stats.Enqueued == 0 {
		view.Hint = auditItemsEmptyHint
	}
	// Items is never null on the wire: a client that has to handle both null and [] for "nothing here"
	// will eventually handle one of them wrong.
	if view.Items == nil {
		view.Items = []scanner.AuditItem{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
}

// cancelAuditItem serves POST /api/scanner/audit-items/{id}/cancel — Burp's
// `auditItemContextMenuCancel` (running-scans/results/audit-items/index.html:102-115).
//
// It stops ONE item and nothing else, which is the whole reason it exists: the alternatives are
// waiting for a slow or heavily-guarded URL to exhaust its own bounds, or disabling the enclosing
// live task, which stops every item including the ones that were fine. A crawler that reached one
// bad URL holds a slot and a thread until its budget runs out, and the queue had no way to reclaim
// just that one (burpsy-react-ui-exiu).
//
// Not an attack, so it is not routed through runAudit and needs no config: it sends nothing. The
// method check comes after the id parse for the same reason the sibling action's does — a URL that
// names nothing should say so rather than answer "wrong verb".
//
// A refusal is a 409 with the reason, not a 400: the request was well-formed and the item simply is
// not in a state that can be cancelled. Collapsing "no such item" and "this item already finished"
// into one answer would leave the operator unable to tell a stale row from a live one.
func (s *Server) cancelAuditItem(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// err != nil only, for the reason handleScannerAuditItemAction states: ids count from zero, so
	// refusing 0 would make the very first capture the one row that cannot be cancelled.
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange id", http.StatusBadRequest)
		return
	}
	ok, reason := s.auditItems.Cancel(core.ExchangeID(id))
	if !ok {
		// 409, not 404 and not 400: the request was well-formed and the item exists, it is simply not
		// in a state that can be cancelled. The reason distinguishes "no such item" from "this one
		// already finished", which an operator needs to tell a stale row from a live one.
		http.Error(w, reason, http.StatusConflict)
		return
	}
	// The refreshed row, so a client does not have to re-list to see the cancel it just caused — the
	// same contract the sibling action keeps.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "reason": reason, "item": s.auditItemRow(core.ExchangeID(id))})
}

// handleScannerAuditItemAction serves POST /api/scanner/audit-items/{id}/again — Burp's
// `auditItemContextMenuAuditAgain`.
//
// A verb in the path rather than a PUT of a desired state, because this is not a state change: it
// starts an audit that sends real traffic to the target. Naming the action is what makes the manifest
// able to classify it riskAttack, which is what makes an unattended caller confirm before invoking
// it — a PATCH that happened to launch a scan would be classified as a local write by inspection.
//
// It re-audits through the same runAudit both existing audit endpoints use, so a re-audit and a first
// audit cannot disagree about what they run or how they report it. AuditWithin builds a fresh
// admission ledger, which is the whole point of the action: an operator who clicks audit again means
// it, and collapsing the work as already-covered would answer the click with silence.
func (s *Server) handleScannerAuditItemAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/scanner/audit-items/"), "/")
	idStr, action, ok := strings.Cut(rest, "/")
	// The path is resolved before the method is checked, so a bogus segment answers 404 "no such
	// action" whatever the verb — a truer answer than "wrong verb" for a URL that names nothing. The
	// route manifest marks this pathValidatedFirst so its 405 test sends a valid segment.
	if !ok || (action != "again" && action != "cancel") {
		http.Error(w, "no such audit-item action; the two are POST /api/scanner/audit-items/{id}/again "+
			"and POST /api/scanner/audit-items/{id}/cancel",
			http.StatusNotFound)
		return
	}
	if action == "cancel" {
		s.cancelAuditItem(w, r, idStr)
		return
	}
	// `err != nil` only. Exchange ids are a dense counter from zero, so 0 names the first capture of
	// the session and refusing it would make the very first row the one that cannot be re-audited —
	// the same reasoning handleAuditByPath states at length.
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange id", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The body is optional, exactly as it is on /api/audit/{id}: absent means the server default, and
	// only a present-but-malformed body is an error.
	var req scannerAuditReq
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil && derr != io.EOF {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	cfg, named, unapplied, cerr := s.resolveAuditConfig(req.Config)
	if cerr != nil {
		http.Error(w, cerr.Error(), http.StatusBadRequest)
		return
	}
	body := s.runAudit(r.Context(), core.ExchangeID(id), cfg, named, unapplied)
	// The refreshed queue row, so a client does not have to re-list to see the attempt it just caused.
	// Nil rather than an invented row when the ledger has already evicted it — which a cap of 500 and
	// a busy sweep make possible in principle — because a fabricated row would misreport the state of
	// the very item the caller acted on.
	body["audited_again"] = true
	body["item"] = s.auditItemRow(core.ExchangeID(id))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}

// auditItemRow returns one item's queue row, or nil when the ledger does not hold it.
//
// A linear scan over the retained rows rather than a lookup method on the ledger: the ledger's public
// surface is deliberately "the queue, bounded and ordered", and adding a by-id accessor to serve one
// convenience field on one response would widen it for a caller that runs once per operator click
// over at most DefaultAuditItemCap rows.
func (s *Server) auditItemRow(id core.ExchangeID) *scanner.AuditItem {
	for _, it := range s.auditItems.Items(0) {
		if it.ExchangeID == id {
			row := it
			return &row
		}
	}
	return nil
}

// withAuditItems attaches the server's audit queue to a configuration, so every audit this process
// runs lands in one queue.
//
// One helper rather than three assignments, because the failure mode is silent: an audit path that
// forgot the field would run correctly and simply never appear in the queue, and a queue missing the
// audits from one entry point is worse than no queue at all — it reads as "nothing audited that
// exchange".
//
// The exception is the configuration that asks not to be queued — Burp's
// `scanner/issues_reported/store_issues_within_queue_items` set to false. The engine never builds
// the queue itself, so "the caller may attach it" is the only enforcement point the key has; a
// configuration that set it false skips the attachment without any other behaviour changing.
func (s *Server) withAuditItems(cfg scanner.AuditConfig) scanner.AuditConfig {
	if cfg.StoreQueueItems.Set && cfg.StoreQueueItems.Value == 0 {
		return cfg
	}
	cfg.Items = s.auditItems
	return cfg
}
