package scanner

// TE.0 / chunk-extension / 0.CL-Expect differentials and the post-timing canary confirmation
// (burpsy-react-ui-0vzb.40 remainder).
//
// Where the landed CL.0 probe shows an endpoint that reads NO body, these shapes show the
// same takeover under a framing disagreement: the request carries framing headers and a body
// in which a complete-under-one-rule terminator is followed by a smuggled canary request. A
// back end whose rule ends the body earlier re-parses the canary; its 404 answer takes the
// scanner's own follow-up response slot on the scanner's own connection.
//
// The safety invariant is the CL.0 one (its rider still governs): keep-alive batches on
// scanner-owned connections only, the canary is a harmless 404 path, and a batch that cannot
// be read cleanly makes the technique UNMEASURABLE - inconclusive, never a finding, never an
// error. The control is the consistently framed twin pair sent under the same keep-alive
// discipline; a control whose follow-up slot ALSO carries the canary makes the observation
// ambiguous, and an ambiguous control is unmeasurable, not a finding.

import (
	"context"
	"fmt"
	"strings"
)

// te0Terminators are the zero-chunk spellings the TE.0 differential tries, the
// extension-terminated chunk first: it is the shape strict chunk parsers disagree about, so
// landing it proves the most. The evidence names which terminator landed.
var te0Terminators = []struct {
	name string // the evidence label, quoting the terminator's first line
	body string
}{
	{`chunk-extension terminator "0;burpsy=x"`, "0;burpsy=x\r\n\r\n"},
	{`plain terminator "0"`, "0\r\n\r\n"},
}

// prefixDifferential runs one smuggled-prefix shape: the attack pair [attack, follow] and the
// consistently framed control pair [control, follow], each as its own keep-alive batch on a
// scanner-owned connection. hit reports the canary's marker taking the follow-up's response
// slot on the attack pair. ok is false when anything is unreadable OR the control's slot
// carries the marker too - an ambiguous control makes the technique unmeasurable (integrator
// rider), which is neither a finding nor an error.
func (r *smugglingRun) prefixDifferential(ctx context.Context, attack, control []byte, marker string) (hit bool, attackFollow, controlFollow string, ok bool) {
	follow := smugglingGet(r.path, r.authority)
	attackPair, err := r.gate.SendKeepAlive(ctx, [][]byte{attack, follow})
	if err != nil || len(attackPair) != 2 || !pipelinedReadClean(attackPair) {
		return false, "", "", false
	}
	controlPair, err := r.gate.SendKeepAlive(ctx, [][]byte{control, follow})
	if err != nil || len(controlPair) != 2 || !pipelinedReadClean(controlPair) {
		return false, "", "", false
	}
	attackFollow = smugglingStatusLine(attackPair[1].Response)
	controlFollow = smugglingStatusLine(controlPair[1].Response)
	if !strings.Contains(string(attackPair[1].Response), marker) {
		return false, attackFollow, controlFollow, true
	}
	if strings.Contains(string(controlPair[1].Response), marker) {
		return false, attackFollow, controlFollow, false
	}
	return true, attackFollow, controlFollow, true
}

// confirmWithCanary runs the TE.0 differential under the framing a timing hit just confirmed:
// the same Transfer-Encoding spelling, the canary riding after each zero-chunk terminator in
// turn. Its return is appended to the timing finding's evidence on a hit; a miss or an
// unmeasurable shape returns "" and the timing finding stands unchanged - the differential
// can only strengthen a confirmed hit, never weaken it (no coverage loss).
func (r *smugglingRun) confirmWithCanary(ctx context.Context, v teVariant) string {
	for _, t := range te0Terminators {
		if err := ctx.Err(); err != nil {
			return ""
		}
		canary := newSmuggledCanary(r.authority)
		if canary.request == nil {
			return ""
		}
		attack := smugglingRequest(r.path, r.authority, v.header,
			len(t.body)+len(canary.request), t.body+string(canary.request))
		// The control is complete under both rules: a zero-chunk body with its exact length.
		control := smugglingRequest(r.path, r.authority, v.header, 5, "0\r\n\r\n")
		hit, attackFollow, controlFollow, ok := r.prefixDifferential(ctx, attack, control, canary.marker)
		if !ok || !hit {
			continue
		}
		return fmt.Sprintf("; the smuggled-prefix differential under the same framing CONFIRMED it (TE.0): "+
			"a chunked body ending with the %s hid a request for /%s inside what the front end forwarded "+
			"as body, and the canary's answer (%s) took the scanner's own follow-up slot while the "+
			"consistently framed control pair answered normally (%s)",
			t.name, canary.marker, attackFollow, controlFollow)
	}
	return ""
}

// expectSkipBodyProbe is the 0.CL/Expect shape: an Expect-bearing POST whose declared body is
// the canary itself. A back end that answers on the Expect without reading the body re-parses
// the canary as its next request. The control carries NO Expect header: an Expect-bearing
// control would be answered under the same body-skipping rule, and its plain form body would
// itself be left to re-parse - a consistently framed control is one BOTH hops read.
func (r *smugglingRun) expectSkipBodyProbe(ctx context.Context) (hit bool, evidence string, ok bool) {
	canary := newSmuggledCanary(r.authority)
	if canary.request == nil {
		return false, "", false
	}
	attack := smugglingRequest(r.path, r.authority, "Expect: 100-continue", len(canary.request), string(canary.request))
	control := smugglingRequest(r.path, r.authority, "", 3, "x=1")
	hit, attackFollow, controlFollow, ok := r.prefixDifferential(ctx, attack, control, canary.marker)
	if !ok || !hit {
		return false, "", ok
	}
	evidence = fmt.Sprintf("POST with Expect: 100-continue and a Content-Length body that is itself a request for /%s, "+
		"then an ordinary follow-up on the same connection:\n"+
		"attack pair: the follow-up's response slot carried the canary's answer (%s)\n"+
		"control pair: the consistently framed twin was answered normally (%s)",
		canary.marker, attackFollow, controlFollow)
	return true, evidence, true
}
