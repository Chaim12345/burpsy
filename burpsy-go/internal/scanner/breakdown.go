// Projections from this package's three coverage vocabularies onto the dashboard's shared one.
//
// # Why projections rather than a rewrite
//
// CoverageReport, AuditOutcome and SessionOutcome each already record what they did not look at, in
// the words their own subsystem needs: a passive check has a CoverageState, an audited
// `(dispatch unit, check)` pair has one of nine Dispositions, a session has failure breakers and
// budgets. Those vocabularies are load-bearing — DispositionAll's nine buckets are the parity
// contract with `burp.Zq5`, and collapsing them to four here would be losing the very detail the
// audit engine exists to keep.
//
// So nothing is replaced. These are lossy, deliberately one-way projections onto dash.Breakdown,
// used only where a *dashboard summary* is being rendered. The full report stays available and stays
// the authority; this is the four-bucket view of it.
//
// # The one judgement call in the mapping
//
// DispositionAlreadyCovered is **not** gated. A check refused because an identical
// `(dispatch unit, check)` already ran this session *did* run — against an earlier item covering the
// same unit. ItemState.CompletedAudit already makes exactly this argument for exactly this reason:
// counting scope collapse as work-not-done would make the engine's largest saving look like a
// coverage regression. So it contributes to no caveat bucket at all.
//
// Every other refusal is gated, and the two that are not refusals — a check with no implementation,
// and a probe that could not be sent — are skipped and errored respectively.
//
// This puts Breakdown deliberately at odds with AuditOutcome.NotAdmitted, which *does* count
// AlreadyCovered. Both are right, because they measure different things: NotAdmitted is the engine's
// admission accounting, where a refused pair is one that did not pass the gate, and Breakdown answers
// whether the operator's count is a floor. A collapsed pair did not pass the gate *and* does not make
// the count a floor. The disagreement is load-bearing rather than an oversight, so
// TestSessionAlreadyCoveredIsReportedButIsNotACaveat pins both halves — "fixing" one to match the
// other fails a test instead of quietly breaking whichever requirement it served.
package scanner

import (
	"fmt"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// Breakdown projects passive-check runtime coverage onto the dashboard's shape.
//
// Found is findings, in findings. The three caveat buckets are units of passive scanning work:
//
//   - Skipped: checks that were never dispatched, plus scans that had no exchange or no response to
//     look at.
//   - Errored: checks whose evaluator returned an error instead of a verdict.
//   - Gated: scans a policy refused before any check ran — the host was out of scope, or no check
//     set was loaded.
//
// Checks that ran clean contribute to nothing, which is correct and is the whole point: a set where
// every check ran and none fired projects to a complete breakdown with Found == 0, and that reads as
// "looked everywhere, found nothing" rather than as a gap.
func (r CoverageReport) Breakdown() dash.Breakdown {
	var b dash.Breakdown
	for _, c := range r.Checks {
		switch c.State() {
		case CoverageStateRanAndFound:
			b.Found += c.Findings
		case CoverageStateErrored:
			b.Errored++
		case CoverageStateNeverDispatched:
			b.Skipped++
		}
	}
	for _, s := range ScanSkipAll {
		n := r.skipCount(s)
		if n == 0 {
			continue
		}
		switch s {
		case ScanSkipNoChecksLoaded, ScanSkipOutOfScope:
			b.Gated += n
		case ScanSkipExchangeNotFound, ScanSkipResponseNotFound:
			b.Skipped += n
		}
	}
	return b
}

// skipCount reads one skip reason's count out of the report. Snapshot builds Skips in ScanSkipAll
// order, but this matches on the explanation rather than trusting the position: a report that arrived
// over the wire, or from a future Snapshot that reorders, must not silently attribute one reason's
// count to another.
func (r CoverageReport) skipCount(s ScanSkip) uint64 {
	for _, sc := range r.Skips {
		if sc.Reason == s.Explanation() {
			return sc.Count
		}
	}
	return 0
}

// BreakdownReasons names every non-zero caveat in Breakdown, so a summary built from it can never
// show an unexplained gap.
//
// Errored carries the last observed error text, because "3 checks errored" is not actionable and "3
// checks errored, most recently: invalid regex construct" is.
func (r CoverageReport) BreakdownReasons() []dash.Reason {
	out := make([]dash.Reason, 0, 6)
	var neverDispatched, errored uint64
	lastError := ""
	for _, c := range r.Checks {
		switch c.State() {
		case CoverageStateNeverDispatched:
			neverDispatched++
		case CoverageStateErrored:
			errored++
			if c.LastError != "" {
				lastError = c.LastError
			}
		}
	}
	if neverDispatched > 0 {
		out = append(out, dash.Reason{
			Bucket: dash.BucketSkipped,
			Detail: "loaded passive checks with no evidence they were ever handed a response",
			Count:  neverDispatched,
		})
	}
	if errored > 0 {
		detail := "passive checks that errored instead of returning a verdict"
		if lastError != "" {
			detail = fmt.Sprintf("%s; most recently: %s", detail, lastError)
		}
		out = append(out, dash.Reason{Bucket: dash.BucketErrored, Detail: detail, Count: errored})
	}
	for _, s := range ScanSkipAll {
		n := r.skipCount(s)
		if n == 0 {
			continue
		}
		bucket := dash.BucketSkipped
		if s == ScanSkipNoChecksLoaded || s == ScanSkipOutOfScope {
			bucket = dash.BucketGated
		}
		out = append(out, dash.Reason{Bucket: bucket, Detail: s.Explanation(), Count: n})
	}
	return out
}

// Breakdown projects one item's audit outcome onto the dashboard's shape.
//
// Found is findings. The caveat buckets are `(dispatch unit, check)` pairs, except RequestsRefused
// which counts probes:
//
//   - Skipped: checks with no implementation or no addressable dispatch unit.
//   - Errored: checks whose probe could not be sent or read, plus findings dropped for want of a
//     probe response — a finding the engine discarded is a check that produced no usable verdict.
//   - Gated: every admission-side refusal, plus probes the scope refused. See the package docs on
//     why DispositionAlreadyCovered is deliberately absent from all three.
//
// An item refused before any dispatch — out of scope, or nothing auditable — has Considered() == 0
// and no counters set, which would project to a complete, empty breakdown. That single case is
// handled explicitly: the refusal is one gated unit of work, named by Error.
func (o AuditOutcome) Breakdown() dash.Breakdown {
	if o.Error != "" {
		return dash.Breakdown{Gated: 1}
	}
	return dash.Breakdown{
		Found:   uint64(o.Findings),
		Skipped: uint64(o.Skipped),
		Errored: uint64(o.SendFailures) + uint64(o.FindingsDropped),
		Gated: uint64(o.NotRun) +
			uint64(o.RequestBudgetSpent) +
			uint64(o.UnitAbandoned) +
			uint64(o.ItemFailed) +
			uint64(o.SessionPaused) +
			uint64(o.RequestsRefused),
	}
}

// BreakdownReasons names every non-zero caveat on one item's outcome, reusing the dispositions'
// own Explanation lines rather than restating them here — two wordings of one refusal would
// eventually disagree.
func (o AuditOutcome) BreakdownReasons() []dash.Reason {
	if o.Error != "" {
		return []dash.Reason{{Bucket: dash.BucketGated, Detail: o.Error, Count: 1}}
	}
	out := make([]dash.Reason, 0, 8)
	for _, d := range o.Dispositions() {
		if d.Count == 0 || d.Disposition == DispositionRan || d.Disposition == DispositionAlreadyCovered {
			continue
		}
		bucket := dash.BucketGated
		switch d.Disposition {
		case DispositionUnsupported:
			bucket = dash.BucketSkipped
		case DispositionSendFailed:
			bucket = dash.BucketErrored
		}
		out = append(out, dash.Reason{Bucket: bucket, Detail: d.Reason, Count: uint64(d.Count)})
	}
	if o.RequestsRefused > 0 {
		out = append(out, dash.Reason{
			Bucket: dash.BucketGated,
			Detail: "probes refused because the request's own path fell outside the engagement scope",
			Count:  uint64(o.RequestsRefused),
		})
	}
	if o.FindingsDropped > 0 {
		out = append(out, dash.Reason{
			Bucket: dash.BucketErrored,
			Detail: "findings discarded because the check that produced them never saw a probe response",
			Count:  uint64(o.FindingsDropped),
		})
	}
	return out
}

// Breakdown projects a whole audit session onto the dashboard's shape by folding its items.
//
// Findings come from the session total rather than from summing the items', because that is the
// number the session reports and two sources for one count is how they drift.
func (o *SessionOutcome) Breakdown() dash.Breakdown {
	if o == nil {
		return dash.Breakdown{}
	}
	var b dash.Breakdown
	for _, it := range o.Items {
		ib := it.Outcome.Breakdown()
		ib.Found = 0 // the session's own total is the authority; see the doc comment
		b = b.Add(ib)
	}
	b.Found = uint64(o.Findings)
	return b
}

// BreakdownReasons names the session's caveats, aggregated by explanation so a sweep over 200
// exchanges reports "600 checks not admitted: the time budget was spent" once rather than 200 times.
//
// The two session-level flags are added last: a paused or timed-out session is a fact about the run
// that no individual item's disposition states, and a sweep that reported only per-item counts would
// let "this host stopped answering" read as "these items happened to be bounded".
func (o *SessionOutcome) BreakdownReasons() []dash.Reason {
	if o == nil {
		return nil
	}
	// Insertion order is kept deliberately: the reasons come out in DispositionAll order for the
	// first item that saw each, which is the order the audit engine tests them in.
	type key struct {
		bucket dash.Bucket
		detail string
	}
	var order []key
	totals := map[key]uint64{}
	for _, it := range o.Items {
		for _, r := range it.Outcome.BreakdownReasons() {
			k := key{r.Bucket, r.Detail}
			if _, seen := totals[k]; !seen {
				order = append(order, k)
			}
			totals[k] += r.Count
		}
	}
	out := make([]dash.Reason, 0, len(order)+3)
	for _, k := range order {
		out = append(out, dash.Reason{Bucket: k.bucket, Detail: k.detail, Count: totals[k]})
	}
	if o.FailedItems > 0 {
		out = append(out, dash.Reason{
			Bucket: dash.BucketErrored,
			Detail: "audit items the item-level failure breaker failed",
			Count:  uint64(o.FailedItems),
		})
	}
	if o.Paused {
		out = append(out, dash.Reason{
			Bucket: dash.BucketGated,
			Detail: "the session-level failure breaker paused the run before every item was reached",
			Count:  1,
		})
	}
	if o.TimedOut {
		out = append(out, dash.Reason{
			Bucket: dash.BucketGated,
			Detail: "the wall-clock budget was spent before every item was audited",
			Count:  1,
		})
	}
	return out
}
