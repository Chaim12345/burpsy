package scanner

// CL.0 and client-side desync detection (burpsy-react-ui-0vzb.40), the response-differential
// half of the smuggling remainder.
//
// The technique: POST the endpoint a request whose declared Content-Length body is itself a
// complete request for a canary path, then send an ordinary follow-up down the SAME keep-alive
// connection. A server (or front end) that answers the POST without reading its body parses
// the body bytes as the next request: the canary's answer — a 404 with a marker body — arrives
// in the follow-up's response slot. A consistently framed control pair (same shape, plain form
// body) shows the follow-up getting its own answer, so the canary is attributable to the
// smuggled prefix and not to the endpoint.
//
// SAFETY INVARIANT (integrator rider): the probe must NEVER leave a poisoned response for a
// third party's connection. The smuggled prefix is answered on the scanner's own connection and
// its answer is consumed by the scanner's own follow-up; the canary is a harmless 404 path, so
// even where a pooling front end relays the desync to a shared back-end connection, the worst
// residue is one 404 answered to a request nobody made — no redirect, no data, no stored
// state. If the pair cannot be read cleanly (a member refused, paced out, or unanswered), the
// technique is inconclusive: no finding, no error.
//
// The check is confined to scanner-owned connections by construction: AuthorisedSender's batch
// sends dial a fresh connection per batch and close it when the batch ends.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// smuggledCanary is a fresh canary request line + the marker its answer carries.
type smuggledCanary struct {
	request []byte // the complete smuggled request: GET <path> HTTP/1.1 + Host + blank line
	marker  string // path fragment the 404 answer's status line and body carry
}

// newSmuggledCanary mints a canary GET to a path no real endpoint serves.
func newSmuggledCanary(authority string) smuggledCanary {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return smuggledCanary{}
	}
	marker := "burpsy-" + hex.EncodeToString(b[:]) + "-canary-404"
	return smuggledCanary{
		request: []byte("GET /" + marker + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"),
		marker:  marker,
	}
}

// smuggledPrefixProbe runs the attack pair and the control pair over keep-alive batches and
// reports whether the canary's answer took the follow-up's response slot on the attack pair
// only. ok is false when either batch could not be read cleanly (refusal, pacing decline,
// missing response): the technique is then inconclusive, never a pass and never a fail.
// cl0Result is one endpoint's smuggled-prefix outcome, shared by the rows that read it.
type cl0Result struct {
	hit, ok  bool
	evidence string
}

// cachedSmuggledPrefixProbe runs smuggledPrefixProbe once per scanner, authority and path.
func (r *smugglingRun) cachedSmuggledPrefixProbe(ctx context.Context) (bool, string, bool) {
	key := r.authority + "|" + r.path
	if v, ok := r.cc.Scanner.cl0Probes.Load(key); ok {
		c := v.(cl0Result)
		return c.hit, c.evidence, c.ok
	}
	hit, evidence, ok := r.smuggledPrefixProbe(ctx)
	if ok {
		r.cc.Scanner.cl0Probes.Store(key, cl0Result{hit: hit, ok: ok, evidence: evidence})
	}
	return hit, evidence, ok
}

func (r *smugglingRun) smuggledPrefixProbe(ctx context.Context) (hit bool, evidence string, ok bool) {
	canary := newSmuggledCanary(r.authority)
	if canary.request == nil {
		return false, "", false
	}
	attack := smugglingRequest(r.path, r.authority, "", len(canary.request), string(canary.request))
	follow := smugglingGet(r.path, r.authority)
	attackPair, err := r.gate.SendKeepAlive(ctx, [][]byte{attack, follow})
	if err != nil || len(attackPair) != 2 || !pipelinedReadClean(attackPair) {
		return false, "", false
	}
	// Control: the follow-up request sent alone, on a connection of its own. Its answer is what
	// the follow-up's slot NORMALLY carries - the endpoint's own page, not the canary's 404 -
	// which is what makes the canary in the attack pair's second slot attributable to the
	// smuggled prefix and not to the endpoint.
	controlPair, err := r.gate.SendKeepAlive(ctx, [][]byte{follow})
	if err != nil || len(controlPair) != 1 || !pipelinedReadClean(controlPair) {
		return false, "", false
	}
	attackFollow := string(attackPair[1].Response)
	controlFollow := string(controlPair[0].Response)
	if !strings.Contains(attackFollow, canary.marker) {
		return false, "", true // the body stayed a body: no desync here
	}
	if strings.Contains(controlFollow, canary.marker) {
		return false, "", true // the endpoint itself answers with the marker: not this class
	}
	evidence = fmt.Sprintf("POST with a Content-Length body that is itself a request for /%s, then an ordinary follow-up on the same connection:\n"+
		"attack pair: the follow-up's response slot carried the canary's answer (%s)\n"+
		"control: the same follow-up sent alone was answered normally (%s)",
		canary.marker, smugglingStatusLine(attackPair[1].Response), smugglingStatusLine(controlPair[0].Response))
	return true, evidence, true
}

// pipelinedReadClean reports whether every member of a batch was sent and answered: no refusal,
// no pacing decline, a complete response. A member that never raced says nothing about the
// target, so a dirty batch makes the technique inconclusive.
func pipelinedReadClean(pair []sender.PipelinedExchange) bool {
	for _, ex := range pair {
		if !ex.ResponseComplete || len(ex.Response) == 0 {
			return false
		}
	}
	return true
}

// smugglingGet renders a plain GET for the follow-up request.
func smugglingGet(path, authority string) []byte {
	return []byte("GET " + path + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")
}

// checkClientSideDesync probes the endpoint with the smuggled-prefix pair and reports the
// "Client-side desync" row when the canary's answer took the follow-up's slot.
//
// The scanner owns only the client-side connection. Directly against the origin the poisoned
// answer is consumed by the scanner's own follow-up; behind a front end that pools back-end
// connections and honours Content-Length, the smuggled canary's 404 can instead wait on a SHARED
// back-end connection and reach another user's request. That is why the row runs only under
// CheckExtendedActive, and why the probe is sent once per endpoint (cachedSmuggledPrefixProbe),
// however many rows read it.
func checkClientSideDesync(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	if err := cc.RequireEgress(); err != nil {
		return nil, err
	}
	r := &smugglingRun{
		cc:        cc,
		gate:      cc.Scanner.probeGate(ctx, cc.Exchange),
		path:      cc.Exchange.Path,
		authority: smugglingAuthority(cc.Exchange.Host, cc.Exchange.Port, cc.Exchange.TLS),
	}
	if r.gate == nil {
		return nil, fmt.Errorf("client-side desync: no authorised sender: %w", errCapabilityMissing)
	}
	hit, evidence, ok := r.cachedSmuggledPrefixProbe(ctx)
	if !ok || !hit {
		return nil, nil
	}
	detail := "The endpoint answered a POST without reading its declared Content-Length body and " +
		"then parsed the body bytes as a separate request on the same connection: a smuggled request " +
		"for a canary path was executed and its 404 answer arrived in the response slot of the " +
		"scanner's own follow-up request, while a consistently framed control pair showed no such " +
		"answer. A browser can be made to send the poisoning POST cross-origin (fetch with a body is " +
		"not preflighted when its content type is simple), so the desync is deliverable to other " +
		"users of the same front-end connection pool."
	return []*Finding{buildHeaderFinding(cc, "Client-side desync", "high", "firm", evidence, detail)}, nil
}
