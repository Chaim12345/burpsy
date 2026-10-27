package scanner

// Race-condition (single-packet) check (burpsy-react-ui-0vzb.8, scanner side; the synchronized
// send machinery is internal/sender's SendSynchronizedGroup, delivered by the sender bead).
//
// Burp ships this attack as the Turbo Intruder single-packet technique: replay one captured
// state-changing request as a synchronized group and count the successes. A one-per-actor
// business limit — one redemption per coupon, one transfer per authorisation, one vote per
// ballot — written as check-then-set lets more than one group member through, where the same
// requests sent one at a time succeed exactly once.
//
// The check proves that divergence, and only that divergence:
//
//   - Candidate gate: a state-changing method on a path or body carrying single-use semantics
//     (redeem, coupon, transfer, vote...), and a parameter the check can mint fresh values into
//     so each phase races an attempt of its own. Anything else is not a candidate.
//   - Sequential control: two sends, one fresh token, one after the other. A genuinely
//     single-use endpoint answers success then refusal. Two successes mean the endpoint accepts
//     repeats — nothing to race. Two refusals mean the check's token is not accepted — the
//     control cannot establish what success looks like. Both are inconclusive, not findings.
//   - Synchronized group: one group racing a second fresh token. More successes than the
//     control's one is the finding; one or zero is not.
//   - A pacing decline anywhere in the group makes the whole phase inconclusive: a request the
//     pacer held back was never raced, so the count says nothing. Inconclusive is silent — no
//     finding, no error.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// IssueRaceConditionSinglePacket is burpsy's own row; see BurpsyNativeRows.
const IssueRaceConditionSinglePacket = "Race condition (single-packet)"

// raceEnabled is the check's own switch.
func raceEnabled(c *ScanConfig) bool { return c != nil && c.CheckRaceConditions }

// raceGroupSize is the group's member count: enough that a check-then-set window admits several,
// well under the pacer's atomic-admission ceiling.
const raceGroupSize = 6

// raceEndpointHints are the path/body markers of a one-per-actor limit.
var raceEndpointHints = []string{
	"redeem", "coupon", "voucher", "otp", "transfer", "withdraw", "vote", "claim", "invite", "use-once",
}

// raceTokenParams are the parameter names the check can mint a fresh single-use value into.
var raceTokenParams = []string{
	"coupon", "voucher", "code", "otp", "pin", "token", "ticket", "invite", "claim",
}

// raceCandidate reports whether the captured request is worth racing: state-changing, and the
// path or body reads as a one-per-actor limit.
func raceCandidate(raw string) bool {
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	line, _, _ := strings.Cut(head, "\r\n")
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	switch fields[0] {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	hay := strings.ToLower(fields[1] + "\n" + body)
	for _, hint := range raceEndpointHints {
		if strings.Contains(hay, hint) {
			return true
		}
	}
	return false
}

// raceMint returns a fresh token value for one phase of the check.
func raceMint(tag string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "race-" + tag
	}
	return "race-" + tag + "-" + hex.EncodeToString(b[:])
}

// raceFreshCopy returns the raw request with the first single-use-looking parameter's value
// replaced by token — in the query string or in a JSON body member — so each phase races an
// attempt of its own. ok is false when no such parameter exists.
func raceFreshCopy(raw, token string) (out string, ok bool) {
	for _, name := range raceTokenParams {
		query := regexp.MustCompile(`(?i)([?&]` + regexp.QuoteMeta(name) + `=)[^&\s]*`)
		if query.MatchString(raw) {
			return query.ReplaceAllString(raw, `${1}`+token), true
		}
		jsonMember := regexp.MustCompile(`(?i)("` + regexp.QuoteMeta(name) + `"\s*:\s*")[^"]*(")`)
		if jsonMember.MatchString(raw) {
			return jsonMember.ReplaceAllString(raw, `${1}`+token+`${2}`), true
		}
	}
	return "", false
}

// racePaced reports whether any group member was held back by the pacer — the whole group is
// inconclusive when one was, because a member that never raced says nothing about the limit.
func racePaced(results []sender.AuthorisedResult) bool {
	for _, r := range results {
		if r.Failure == sender.SendFailurePacing {
			return true
		}
	}
	return false
}

// raceStatusCount counts group members answered with the success status.
func raceStatusCount(results []sender.AuthorisedResult, status int) int {
	n := 0
	for _, r := range results {
		if r.Err == nil && r.Status != nil && *r.Status == status {
			n++
		}
	}
	return n
}

// checkRaceConditions runs the control pair and the synchronized group against one candidate.
func checkRaceConditions(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" || !raceCandidate(raw) {
		return nil, nil
	}
	control, ok := raceFreshCopy(raw, raceMint("control"))
	if !ok {
		return nil, nil
	}
	group, ok := raceFreshCopy(raw, raceMint("group"))
	if !ok {
		return nil, nil
	}
	gate := cc.Scanner.probeGate(ctx, cc.Exchange)
	if gate == nil {
		return nil, fmt.Errorf("race condition: no authorised sender: %w", errCapabilityMissing)
	}

	// Sequential control: what does one actor get, one request at a time?
	first, err := gate.Send(ctx, []byte(control))
	if err != nil || first.Err != nil || first.Status == nil {
		return nil, nil
	}
	second, err := gate.Send(ctx, []byte(control))
	if err != nil || second.Err != nil || second.Status == nil {
		return nil, nil
	}
	success := *first.Status
	if *second.Status == success {
		// The endpoint accepted the same token twice: repeatable, not single-use.
		return nil, nil
	}

	// Synchronized group: one fresh token, every member released together.
	raws := make([][]byte, raceGroupSize)
	for i := range raws {
		raws[i] = []byte(group)
	}
	results, err := gate.SendSynchronizedGroup(ctx, raws)
	if err != nil || len(results) != raceGroupSize || racePaced(results) {
		// Unavailable, short, or pacing-held: the group never raced, so the count is silent.
		return nil, nil
	}
	wins := raceStatusCount(results, success)
	if wins < 2 {
		return nil, nil
	}
	evidence := fmt.Sprintf("sequential control, one fresh token: HTTP %d then HTTP %d\nsynchronized group of %d, one fresh token: HTTP %d x%d",
		success, *second.Status, raceGroupSize, success, wins)
	detail := "The endpoint enforces a single-use limit as check-then-set with a window between the " +
		"check and the record: the same request sent one at a time succeeded exactly once, but a " +
		"synchronized group of six — every member's last byte released together — succeeded " +
		fmt.Sprintf("%d times with one token. ", wins) +
		"An attacker replays a state-changing request as one synchronized burst to redeem a coupon " +
		"more than once, move the same funds twice, or vote past the limit."
	f := buildHeaderFinding(cc, IssueRaceConditionSinglePacket, "high", "firm", evidence, detail)
	return []*Finding{f}, nil
}

// withRaceConditions adds this check to the runner of the descriptor it rides ("Broken access
// control": what the attack defeats is a one-per-actor limit).
func withRaceConditions(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		innerF, innerErr := inner(ctx, cc)
		var rcF []*Finding
		var rcErr error
		if raceEnabled(cc.Config) {
			rcF, rcErr = checkRaceConditions(ctx, cc)
		}
		out := append(innerF, rcF...)
		switch {
		case len(rcF) > 0:
			return out, nil
		case innerErr != nil:
			return innerF, innerErr
		case rcErr != nil:
			return innerF, rcErr
		}
		return out, nil
	}
}
