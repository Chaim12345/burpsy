package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
)

// The declined prompt's wire mapping is the only thing an operator is told about it.
//
// With Burp's ninth action implemented, a prompt is asked, the operator answers, and the
// answer is either "recovered" (the session the operator established is now on the wire) or
// "declined" (the request was not sent). Those are opposite facts and the console renders
// them differently, so the mapping has to be right rather than merely present.
//
// The failure this test exists against is the one the coordinator's own kinds exist to
// prevent: a decline read as RecoveryAlreadyValid would tell the operator the session was
// fine all along, which is the opposite of what they were asked and answered. And the
// assertion is on the wire rather than on the outcome struct, because the outcome is
// internal — "prompt_declined" as a RecoveryOutcomeKind says nothing about whether a client
// can read it, and only the wire can be wrong in the way that reaches an operator.
func TestADeclinedBrowserRecoveryPromptAnswersPromptDeclinedNotRecovered(t *testing.T) {
	outcome := session.RecoveryOutcome{
		Kind: session.RecoveryPromptDeclined,
		Actions: []session.ActionRan{{
			Index: 1, Kind: session.ActionPromptForBrowserRecovery,
			Label:  "Prompt the user for in-browser session recovery",
			Detail: "the operator was asked to recover the session in the browser and declined; the request was not sent",
		}},
	}

	status, resp := loginOutcomeResponse(outcome)
	if status != http.StatusOK {
		t.Fatalf("a declined prompt answered %d, want 200 — the operator answered a working control, "+
			"they did not break anything, and a 5xx would tell them they had", status)
	}

	if resp.Outcome != "prompt_declined" {
		t.Fatalf("outcome = %q, want prompt_declined — reporting a declined prompt as anything else "+
			"(recovered, already_valid) tells the operator a session was established when none was",
			resp.Outcome)
	}
	// The trace is present, because the console shows the operator what the rule asked and
	// what happened to it, and an outcome with no trace is a refusal to explain itself.
	if len(resp.Actions) != 1 {
		t.Fatalf("the declined outcome carries %d action trace entries, want the 1 that asked: %+v",
			len(resp.Actions), resp.Actions)
	}
	if !strings.Contains(resp.Actions[0].Detail, "declined") {
		t.Fatalf("the trace entry does not say the prompt was declined: %+v", resp.Actions[0])
	}
	if resp.Actions[0].Kind == "" || resp.Actions[0].Label == "" {
		t.Fatalf("the trace entry is missing its wire name or label: %+v", resp.Actions[0])
	}
	// And it survives the encode the console actually reads.
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Outcome string           `json:"outcome"`
		Actions []map[string]any `json:"actions"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Outcome != "prompt_declined" {
		t.Fatalf("on the wire the outcome reads %q, want prompt_declined", decoded.Outcome)
	}
	if len(decoded.Actions) != 1 || decoded.Actions[0]["detail"] == nil {
		t.Fatalf("on the wire the trace did not survive: %s", raw)
	}
}

// An already-valid response is what a decline used to be reported as. Pinning the two apart
// on the wire is what makes the regression above impossible to reintroduce silently: a mapping
// that answered RecoveryAlreadyValid for a prompt would still answer 200 here, and this test
// is what notices.
func TestAnAlreadyValidRecoveryAndADeclinedPromptAreDifferentAnswers(t *testing.T) {
	_, valid := loginOutcomeResponse(session.RecoveryOutcome{Kind: session.RecoveryAlreadyValid})
	_, declined := loginOutcomeResponse(session.RecoveryOutcome{Kind: session.RecoveryPromptDeclined})
	if valid.Outcome == declined.Outcome {
		t.Fatalf("both outcomes answer %q; a prompt the operator declined must never read as a "+
			"session that was already fine — that is the opposite of what happened", valid.Outcome)
	}
	if valid.Outcome != "already_valid" {
		t.Fatalf("the already-valid outcome reads %q on the wire, want already_valid", valid.Outcome)
	}
}

// A RecoveryOutcomeKind this mapping does not know must keep its honest refusal. The
// unmapped_outcome arm is what makes adding a kind visible — this test guards the guard, so a
// future kind cannot be answered as a success by an arm that stopped checking.
func TestAnUnmappedRecoveryOutcomeStillRefusesRatherThanReportingSuccess(t *testing.T) {
	status, resp := loginOutcomeResponse(session.RecoveryOutcome{Kind: session.RecoveryOutcomeKind(99)})
	if status == http.StatusOK {
		t.Fatalf("an unmapped recovery kind answered 200 (%+v); a kind this mapping does not know "+
			"must be refused, or adding one to the coordinator is silent", resp)
	}
	if resp.Outcome != "unmapped_outcome" {
		t.Fatalf("outcome = %q, want unmapped_outcome", resp.Outcome)
	}
	if !strings.Contains(resp.Error, "no wire mapping") {
		t.Fatalf("the refusal does not say what is missing: %q", resp.Error)
	}
}
