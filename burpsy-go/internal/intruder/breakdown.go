// Projection from an attack report onto the dashboard's shared count shape.
//
// The report already carries every bound it hit — Truncated, BucketsTruncated, Unbucketed,
// DetailLimit — for exactly the reason dash.Breakdown exists: an attack that sent 128 of 4096
// planned requests has not told you the other 3968 were clean. This is the four-bucket view of that,
// used where a dashboard summary is rendered; AttackReport stays the authority and stays unchanged.
package intruder

import (
	"fmt"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// Breakdown projects the report onto the dashboard's shape.
//
// Found is responses, in responses. The caveats are planned requests:
//
//   - Errored: attempts whose send failed or that a guard refused.
//   - Skipped: attempts the plan held but that never went out — a cancelled context, most often.
//   - Gated: combinations the request bound refused before they were planned, plus attempts absent
//     from the result buckets because the bucket cap was reached.
//
// An inexact combination count contributes nothing to Gated, because a bucket built from an estimate
// is not a count. BreakdownReasons names that case instead, so the shortfall is stated rather than
// either guessed at or dropped.
func (r *AttackReport) Breakdown() dash.Breakdown {
	if r == nil {
		return dash.Breakdown{}
	}
	b := dash.Breakdown{
		Found:   uint64(r.Sent),
		Errored: uint64(r.Failed),
	}
	if undispatched := r.Planned - r.Sent - r.Failed; undispatched > 0 {
		b.Skipped = uint64(undispatched)
	}
	if r.Truncated {
		if r.CombinationsExact && r.Combinations > uint64(r.Planned) {
			b.Gated += r.Combinations - uint64(r.Planned)
		} else {
			// One, not zero. The size of the shortfall is unknown, but its existence is not, and a
			// gated bucket of zero would let a truncated attack marshal as Complete — the summary
			// would then read "clean" beside a reason saying it was cut short.
			b.Gated++
		}
	}
	if r.Unbucketed > 0 {
		b.Gated += uint64(r.Unbucketed)
	}
	return b
}

// BreakdownReasons names every non-zero caveat, plus the one case the buckets cannot express: a
// truncated attack whose full combination count is only an estimate.
func (r *AttackReport) BreakdownReasons() []dash.Reason {
	if r == nil {
		return nil
	}
	out := make([]dash.Reason, 0, 5)
	if r.Failed > 0 {
		out = append(out, dash.Reason{
			Bucket: dash.BucketErrored,
			Detail: "attempts whose request could not be sent or read, or that the scope refused",
			Count:  uint64(r.Failed),
		})
	}
	if undispatched := r.Planned - r.Sent - r.Failed; undispatched > 0 {
		out = append(out, dash.Reason{
			Bucket: dash.BucketSkipped,
			Detail: "planned attempts that never went out; the attack ended before reaching them",
			Count:  uint64(undispatched),
		})
	}
	if r.Truncated {
		if r.CombinationsExact && r.Combinations > uint64(r.Planned) {
			out = append(out, dash.Reason{
				Bucket: dash.BucketGated,
				Detail: fmt.Sprintf("payload combinations the %d-request bound refused to plan", r.MaxRequests),
				Count:  r.Combinations - uint64(r.Planned),
			})
		} else {
			// Count 1 rather than 0: the shortfall is real and must keep the summary from reading as
			// complete, even though its size is not known exactly.
			out = append(out, dash.Reason{
				Bucket: dash.BucketGated,
				Detail: fmt.Sprintf("the %d-request bound cut the attack short; the full combination count is too large to state exactly", r.MaxRequests),
				Count:  1,
			})
		}
	}
	if r.Unbucketed > 0 {
		out = append(out, dash.Reason{
			Bucket: dash.BucketGated,
			Detail: "responses absent from the result buckets because the bucket cap was reached",
			Count:  uint64(r.Unbucketed),
		})
	}
	return out
}
