package scanner

// The reset request's two account-level verdicts, read from the same declared-identity flow as the
// token rows (checks_pwreset.go): whether its answer tells which accounts exist, and whether it can
// be repeated without limit.
//
// # Username enumeration
//
// The declared identity's reset request is answered twice (the captured request's baseline answer
// and one more request), and the same request with three invented identities of the same shape (an
// e-mail keeps its domain, inventIdentity) is answered three times, interleaved: invented, known,
// invented, invented. Every answer is fingerprinted after masking the submitted identities, the
// tokens the answers carry, and dynamic values (authFingerprint). Reported (firm) only when each side
// is internally identical, the sides differ, and no answer shows throttling or a server failure. The
// two internal agreements are the control: a page that varies on its own never gets that far, and an
// answer that merely echoes the submitted address is masked away. A throttled answer on either side
// leaves the verdict undecided, because a per-account limit answers the known identity differently
// for a reason that is not its existence.
//
// It is the login check's row ("Username enumeration", CWE-204): an observable discrepancy that
// discloses whether an account exists, here through the reset form instead of the login form.
//
// # Password reset requests not rate limited
//
// Every reset request the prober sent for the declared identity (the baseline, the enumeration
// request, the poisoning probes, the token samples, the fresh token) is read, and plain reset
// requests are added until there are pwrRateMin. Reported (firm, low) only when a mailbox is
// configured, EVERY one of those requests delivered its own message to the identity's test inbox,
// and none was answered with a sign of throttling (throttleSignal: HTTP 429/503, Retry-After or a
// rate-limit header, "too many"/"try again later" wording). Delivery is required, not just an
// accepting answer: an application that throttles silently answers every request alike and stops
// sending mail, and that is not reported. Nothing is inferred beyond the count sent: the finding
// states how many requests in how many seconds were all delivered.
//
// Classified CWE-799 (Improper Control of Interaction Frequency) and CWE-640: a reset request is not
// an authentication attempt, so the login row's CWE-307 does not describe it.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

const (
	// pwrRateMin is how many delivered reset requests for one account, none throttled, the rate
	// verdict needs. Per-account reset limits in practice engage at a handful per window.
	pwrRateMin = 10
	// pwrEnumInvented is how many invented identities the enumeration probe sends.
	pwrEnumInvented = 3
)

// identityPoint is the query/body point that carries the declared identity.
func (p *pwrProber) identityPoint(raw string) (bcheck.InsertionPoint, bool) {
	points, _ := bcheck.EnumerateWith([]byte(raw), []string{"query", "body"}, bcheck.EnumerateOptions{})
	for _, pt := range points {
		if strings.EqualFold(strings.TrimSpace(pwrDecode(pt.BaseValue)), strings.TrimSpace(p.identity)) {
			return pt, true
		}
	}
	return bcheck.InsertionPoint{}, false
}

// pwrUnusable is an answer that says nothing about the account: nothing came back, or the server failed.
func pwrUnusable(r ProbeResponse) bool { return r.Status == 0 || r.Status >= 500 }

func (p *pwrProber) enumeration(ctx context.Context, first *pwrIssuance) (*Finding, error) {
	pt, ok := p.identityPoint(p.raw)
	if !ok {
		return nil, nil
	}
	invented := make([]string, pwrEnumInvented)
	for i := range invented {
		invented[i] = inventIdentity(p.identity)
	}
	sendInvented := func(id string) (ProbeResponse, error) {
		req, err := pt.Apply([]byte(p.raw), id, false)
		if err != nil {
			return ProbeResponse{}, err
		}
		return p.send(ctx, string(req))
	}
	knownR := []ProbeResponse{first.resp}
	var otherR []ProbeResponse
	for i, id := range invented {
		r, err := sendInvented(id)
		if err != nil {
			return nil, err
		}
		otherR = append(otherR, r)
		if i == 0 {
			is, err := p.issue(ctx, p.raw, nil, false)
			if err != nil {
				return nil, err
			}
			knownR = append(knownR, is.resp)
		}
	}
	// Masked alike on both sides: the submitted identities, and every token-shaped value any of the
	// answers carries (a per-request CSRF token is not a difference between accounts; a token that
	// only a known account's answer carries still leaves its key behind, which is one).
	submitted := append([]string{p.identity}, invented...)
	for _, r := range append(append([]ProbeResponse(nil), knownR...), otherR...) {
		for _, t := range pwrTokensInText(r.Body) {
			submitted = append(submitted, t.value)
		}
	}
	for _, r := range append(append([]ProbeResponse(nil), knownR...), otherR...) {
		if pwrUnusable(r) {
			return nil, nil
		}
		if sig := throttleSignal(r); sig != "" {
			p.notes = append(p.notes, "enumeration undecided: an answer was throttled ("+sig+")")
			return nil, nil
		}
	}
	kfp := authFingerprint(knownR[0], submitted)
	for _, r := range knownR[1:] {
		if authFingerprint(r, submitted) != kfp {
			return nil, nil // the declared identity's own answer is not stable
		}
	}
	ofp := authFingerprint(otherR[0], submitted)
	for _, r := range otherR[1:] {
		if authFingerprint(r, submitted) != ofp {
			return nil, nil // invented identities are not answered alike
		}
	}
	if kfp == ofp {
		return nil, nil
	}
	kb := maskDynamic(maskSubmitted(knownR[0].Body, submitted))
	ob := maskDynamic(maskSubmitted(otherR[0].Body, submitted))
	evidence := fmt.Sprintf("the reset request for the declared test identity %q was answered HTTP %d (%d of %d identical) "+
		"and the same request for %d invented identities of the same shape HTTP %d (%d of %d identical), and the two "+
		"answers differ: %s.", p.identity, knownR[0].Status, len(knownR), len(knownR), len(otherR), otherR[0].Status,
		len(otherR), len(otherR), describeDifference(knownR[0], otherR[0], kb, ob, submitted))
	detail := fmt.Sprintf("The password-reset request at %s answers differently for an account that exists than for one "+
		"that does not, after masking the submitted address, so anyone can test which addresses have accounts. The "+
		"invented identities were %s.", exchangeURL(p.cc.Exchange), strings.Join(invented, ", "))
	f := buildHeaderFinding(p.cc, IssueUsernameEnumeration, "low", "firm", evidence, detail)
	f.Param = pt.Name
	f.Solution = "Answer the reset request identically whether or not the account exists (the same status, body " +
		"and timing), and send the message only when it does."
	return f, nil
}

// rateUndecided: a reset request sent so far was throttled, or delivered no message (it may have been
// dropped silently, which is a limit too).
func (p *pwrProber) rateUndecided() bool {
	for _, is := range p.issued {
		if sig := throttleSignal(is.resp); sig != "" {
			p.notes = append(p.notes, "reset requests are throttled ("+sig+")")
			return true
		}
		if is.mailText == "" {
			return true
		}
	}
	return false
}

func (p *pwrProber) rateLimit(ctx context.Context) (*Finding, error) {
	if p.mail == nil {
		return nil, nil // delivery is the evidence; without the inbox nothing is decided
	}
	if p.rateUndecided() {
		return nil, nil
	}
	for len(p.issued) < pwrRateMin {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := p.issue(ctx, p.raw, nil, false); err != nil {
			return nil, err
		}
		if p.rateUndecided() {
			return nil, nil
		}
	}
	n := len(p.issued)
	span := p.issued[n-1].recv.Sub(p.issued[0].sent).Round(time.Second)
	statuses := map[int]int{}
	for _, is := range p.issued {
		statuses[is.resp.Status]++
	}
	var st []string
	for code, c := range statuses {
		st = append(st, fmt.Sprintf("HTTP %d x%d", code, c))
	}
	sort.Strings(st)
	evidence := fmt.Sprintf("%d reset requests for the test identity %s in %s (%s): every one delivered its own message "+
		"to the test inbox, and none was answered with a sign of throttling (no 429/503, Retry-After or rate-limit "+
		"header, no \"too many\" or \"try again\" wording).", n, p.identity, span, strings.Join(st, ", "))
	detail := fmt.Sprintf("The password-reset request at %s can be repeated for one account without limit: %s An attacker "+
		"can flood any user's inbox with reset messages, and every extra request is one more live token when tokens are "+
		"guessable. Only %d requests were sent; a limit above that is not ruled out.", exchangeURL(p.cc.Exchange), evidence, n)
	f := buildHeaderFinding(p.cc, pwrNoRateLimit, "low", "firm", evidence, detail)
	f.Solution = "Limit reset requests per account and per client (for example a few per hour), answering the excess " +
		"without sending mail, and keep the answer identical to the normal one so the limit does not enumerate accounts."
	return f, nil
}
