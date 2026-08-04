// The dashboard's shared vocabulary: one shape for every operator-facing count, and a registry of
// the long-running work that produces them.
//
// # The gap this closes (DASH-03)
//
// Three subsystems had already worked out, independently, that a count must say what it did not
// look at. CoverageTracker partitions the passive check set into never-dispatched / ran-clean /
// ran-and-found / errored. AuditOutcome partitions every `(dispatch unit, check)` pair into nine
// named dispositions. DOMBudgetReport derives Truncated from the list of bounds that fired. Each is
// right, and each invented its own words for the same idea.
//
// A dashboard assembled from three vocabularies is a dashboard where the honesty is a per-feature
// accident: whichever pane was written last is the one whose counts carry their caveats, and the
// next pane starts from zero. Breakdown is the one shape all three project into, so "shows what it
// did not look at" is a property of the surface rather than of each author's diligence.
//
// # Why there is no total
//
// Found is in the summary's Unit — issues, findings, URLs. Skipped, Errored and Gated are in its
// WorkUnit — units of scanning work that never produced a verdict. They are deliberately different
// units and deliberately never summed: "12 issues plus 3 checks that never ran" is not a number,
// and offering a Total() would invite exactly that addition. Nothing in this package computes one.
//
// What the three caveat buckets buy instead is Complete(). When all three are zero, the found count
// is the whole answer. When they are not, it is a floor, and Reasons names every bucket that made it
// one. That is the entire content of the requirement: "12 issues" must never read as "that's all
// there is".
//
// # Why the JSON is asymmetric with the struct
//
// Breakdown.MarshalJSON writes all four buckets with no omitempty, plus the derived unaccounted,
// complete and summary. A zero Breakdown therefore still emits `{"found":0,"skipped":0,...}` rather
// than `{}`. That is the point: a UI that renders whatever keys it is given cannot silently lose a
// caveat because the caveat happened to be zero this time, and a pane written against the wire shape
// gets the four buckets whether its author thought about them or not.
package dash

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Bucket names one of the four buckets a Breakdown partitions work into, so a Reason can say which
// bucket it explains without the caller re-deriving it from context.
type Bucket string

const (
	// BucketFound is the count the summary headlines — the thing that was actually found.
	BucketFound Bucket = "found"
	// BucketSkipped is work that never ran: no implementation, nothing addressable, or an input
	// that was not there to look at.
	BucketSkipped Bucket = "skipped"
	// BucketErrored is work that ran and failed, so it produced no verdict either way. Kept apart
	// from Skipped because a check erroring on every response is a broken check, and a check that
	// was never dispatched is a wiring gap — different things to fix.
	BucketErrored Bucket = "errored"
	// BucketGated is work a limit, a budget, a scope rule or an opt-in refused before it ran. This
	// is the bucket that distinguishes "stopped looking" from "found nothing": a non-zero Gated
	// means the engine declined work it could otherwise have done.
	BucketGated Bucket = "gated"
)

// BucketAll is the four, in the order a Breakdown reports them, so a caller can render a legend
// without hard-coding the set — the same reason ScanSkipAll and DispositionAll exist.
var BucketAll = [4]Bucket{BucketFound, BucketSkipped, BucketErrored, BucketGated}

// Reason is one line explaining part of one bucket. The count travels with the explanation for the
// same reason SkipCount and DispositionCount carry theirs: a bare histogram makes the reader
// re-derive what a bucket means, and a reader who gets that wrong reads a bound as a clean result.
type Reason struct {
	Bucket Bucket `json:"bucket"`
	Detail string `json:"detail"`
	Count  uint64 `json:"count"`
}

// Breakdown is the shape every operator-facing count on the dashboard has.
//
// The zero value is "found nothing, and looked everywhere" — Complete() is true. That is the safe
// direction only because the caveat buckets are filled in by projection from a report that already
// tracked them; a summary built by hand with no thought given to the three caveats will claim
// completeness, which is why NewSummary refuses to let a non-complete breakdown travel without a
// named reason and why nothing here fabricates buckets from a bare integer.
type Breakdown struct {
	// Found is how many of the thing were found, in the summary's Unit.
	Found uint64
	// Skipped, Errored and Gated are units of work that produced no verdict, in the summary's
	// WorkUnit. See the Bucket constants for which is which.
	Skipped uint64
	Errored uint64
	Gated   uint64
}

// Unaccounted is the work the found count does not speak for. Non-zero means the count is a floor.
func (b Breakdown) Unaccounted() uint64 { return b.Skipped + b.Errored + b.Gated }

// Complete reports whether the found count is the whole answer rather than a floor.
func (b Breakdown) Complete() bool { return b.Unaccounted() == 0 }

// Add folds another breakdown in, for summarising several runs as one count.
func (b Breakdown) Add(o Breakdown) Breakdown {
	return Breakdown{
		Found:   b.Found + o.Found,
		Skipped: b.Skipped + o.Skipped,
		Errored: b.Errored + o.Errored,
		Gated:   b.Gated + o.Gated,
	}
}

// Get returns one bucket by name, so a caller iterating BucketAll does not need a switch. An
// unknown bucket returns 0 and false rather than 0 — the two answers are different, and collapsing
// them is how a renamed bucket starts reading as an empty one.
func (b Breakdown) Get(bucket Bucket) (uint64, bool) {
	switch bucket {
	case BucketFound:
		return b.Found, true
	case BucketSkipped:
		return b.Skipped, true
	case BucketErrored:
		return b.Errored, true
	case BucketGated:
		return b.Gated, true
	}
	return 0, false
}

// Summary formats the count with its caveats. Every non-zero caveat is named: the point of the
// breakdown is lost if the human-readable form collapses it back into the found count alone.
func (b Breakdown) Summary() string {
	if b.Complete() {
		return fmt.Sprintf("%d found, and nothing was skipped, errored or gated", b.Found)
	}
	var why []string
	if b.Skipped > 0 {
		why = append(why, fmt.Sprintf("%d skipped", b.Skipped))
	}
	if b.Errored > 0 {
		why = append(why, fmt.Sprintf("%d errored", b.Errored))
	}
	if b.Gated > 0 {
		why = append(why, fmt.Sprintf("%d gated", b.Gated))
	}
	return fmt.Sprintf("%d found, but %s — this is a floor, not a total", b.Found, strings.Join(why, ", "))
}

// breakdownWire is the JSON shape. Separate from Breakdown so the derived fields cannot be set by a
// caller and then disagree with the buckets they are derived from.
type breakdownWire struct {
	Found       uint64 `json:"found"`
	Skipped     uint64 `json:"skipped"`
	Errored     uint64 `json:"errored"`
	Gated       uint64 `json:"gated"`
	Unaccounted uint64 `json:"unaccounted"`
	Complete    bool   `json:"complete"`
	Summary     string `json:"summary"`
}

// MarshalJSON writes all four buckets unconditionally — see the package docs on why the zero value
// still emits them — plus the three derived fields, so a UI never has to compute completeness and
// never has the chance to compute it differently from Go.
func (b Breakdown) MarshalJSON() ([]byte, error) {
	return json.Marshal(breakdownWire{
		Found:       b.Found,
		Skipped:     b.Skipped,
		Errored:     b.Errored,
		Gated:       b.Gated,
		Unaccounted: b.Unaccounted(),
		Complete:    b.Complete(),
		Summary:     b.Summary(),
	})
}

// UnmarshalJSON reads the four buckets and discards the derived fields, so a round trip through
// JSON gives back an equal Breakdown. Without this the custom marshaller would decode into a zero
// value — a silent "everything was complete" for anything that persists or replays a summary.
func (b *Breakdown) UnmarshalJSON(data []byte) error {
	var w breakdownWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	b.Found, b.Skipped, b.Errored, b.Gated = w.Found, w.Skipped, w.Errored, w.Gated
	return nil
}

// Summary is one named count on the dashboard: what was found, in what units, what work it does not
// speak for, and why.
type Summary struct {
	// Label is the operator-facing name of the count, e.g. "Issues".
	Label string `json:"label"`
	// Unit is what Breakdown.Found counts, e.g. "issues".
	Unit string `json:"unit"`
	// WorkUnit is what the three caveat buckets count, e.g. "passive checks". Named separately
	// because it is a different unit — see the package docs on why there is no total.
	WorkUnit string `json:"work_unit"`
	// Breakdown is the count itself. Always marshalled in full.
	Breakdown Breakdown `json:"breakdown"`
	// Reasons explains the non-zero caveat buckets. NewSummary guarantees this is non-empty
	// whenever Breakdown is not Complete.
	Reasons []Reason `json:"reasons"`
}

// unattributedDetail is what an unexplained caveat is labelled as. It exists so that a projection
// which forgot to supply reasons produces a visibly unattributed caveat rather than a nameless one:
// the count still refuses to read as complete, and the word "unattributed" is the bug report.
const unattributedDetail = "unattributed: work was not done and the projection did not say why"

// NewSummary builds a summary, refusing to let a caveat travel nameless.
//
// A breakdown that is not Complete with no reasons supplied gets a single unattributed reason
// covering the whole shortfall. Synthesising one is not a cover-up — it is the alternative to a
// non-zero Skipped/Errored/Gated the UI can render with no explanation next to it, which is the
// failure this whole type exists to prevent. The synthetic reason names itself as unattributed so
// the missing projection is visible rather than papered over.
func NewSummary(label, unit, workUnit string, b Breakdown, reasons ...Reason) Summary {
	kept := make([]Reason, 0, len(reasons))
	for _, r := range reasons {
		if r.Count > 0 {
			kept = append(kept, r)
		}
	}
	if !b.Complete() && len(kept) == 0 {
		kept = append(kept, Reason{
			Bucket: BucketGated,
			Detail: unattributedDetail,
			Count:  b.Unaccounted(),
		})
	}
	return Summary{Label: label, Unit: unit, WorkUnit: workUnit, Breakdown: b, Reasons: kept}
}

// Line formats the summary for logs and the CLI.
func (s Summary) Line() string {
	return fmt.Sprintf("%s: %s (%s found; caveats in %s)", s.Label, s.Breakdown.Summary(), s.Unit, s.WorkUnit)
}
