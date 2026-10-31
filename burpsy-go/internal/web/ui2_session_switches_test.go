package web

import (
	"encoding/json"
	"github.com/burpsy-go/burpsy/internal/session"
	"net/url"
	"strings"
	"testing"
)

func TestUI2SessionSwitchSingleBoolAndCopy(t *testing.T) {
	for _, op := range []string{"action_disable", "action_stop_off", "action_enable", "action_stop_on"} {
		s := newTestServerWithCoordinator(t)
		id := actionSeed(t, s)
		index := "0"
		if op == "action_enable" || op == "action_stop_on" {
			index = "1"
		}
		expected, _, _ := s.sessionCoordinator.RuleSnapshot(session.RuleID(id))
		before := session.RuleDigest(expected)
		a := expected.Actions[0]
		if index == "1" {
			a = expected.Actions[1]
		}
		switch op {
		case "action_disable":
			a.Enabled = false
		case "action_enable":
			a.Enabled = true
		case "action_stop_on":
			a.Stop = true
		case "action_stop_off":
			a.Stop = false
		}
		f := actionForm(s, id, op, index)
		rid, tok, sheet := ui2ConfirmReview(t, s, f)
		if session.RuleDigest(s.sessionCoordinator.Rule(session.RuleID(id))) != before {
			t.Fatal("switch mint touched live rule")
		}
		if strings.Contains(sheet, "CANARY-FIRST") || strings.Contains(sheet, "CANARY-SECOND") {
			t.Fatal("switch review leaks secret")
		}
		ui2PostSessionRules(t, s, "run", url.Values{"review_id": {rid}, "token": {tok}})
		got, _ := json.Marshal(s.sessionCoordinator.Rule(session.RuleID(id)))
		want, _ := json.Marshal(expected)
		if string(got) != string(want) {
			t.Fatalf("%s changed more than one bool: got %s want %s", op, got, want)
		}
	}
}
func TestUI2SessionSwitchRefusals(t *testing.T) {
	for _, tc := range []struct{ op, index, extra, word string }{{"action_enable", "0", "", "already true"}, {"action_stop_on", "0", "", "already true"}, {"action_disable", "1", "", "already false"}, {"action_stop_off", "1", "", "already false"}, {"action_disable", "0", "action_value", "permitted switch field"}, {"action_disable", "0", "target", "permitted switch field"}} {
		s := newTestServerWithCoordinator(t)
		id := actionSeed(t, s)
		f := actionForm(s, id, tc.op, tc.index)
		if tc.extra != "" {
			f.Set(tc.extra, "bad")
		}
		out := ui2PostSessionRules(t, s, "confirm", f)
		if !strings.Contains(out.Body.String(), tc.word) {
			t.Fatalf("switch refusal missing %s", tc.word)
		}
	}
	s := newTestServerWithCoordinator(t)
	id := actionSeed(t, s)
	s.sessionCoordinator.Rule(session.RuleID(id)).Actions[0].ExtensionSession = "opaque-secret"
	out := ui2PostSessionRules(t, s, "confirm", actionForm(s, id, "action_disable", "0"))
	if !strings.Contains(out.Body.String(), "label-only") {
		t.Fatal("label-only switch accepted")
	}
	f := actionForm(s, id, "action_disable", "1")
	f.Set("form_base", "stale")
	out = ui2PostSessionRules(t, s, "confirm", f)
	if !strings.Contains(out.Body.String(), "changed since this action form") {
		t.Fatal("stale switch form accepted")
	}
}
func TestUI2SessionSwitchDisabledStopCopy(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	id := actionSeed(t, s)
	_, _, sheet := ui2ConfirmReview(t, s, actionForm(s, id, "action_stop_on", "1"))
	if !strings.Contains(sheet, "stop flag is inert while this action is disabled") || !strings.Contains(sheet, "no later actions today") {
		t.Fatal("disabled stop copy claims active effect")
	}
	_, _, sheet = ui2ConfirmReview(t, s, actionForm(s, id, "action_disable", "0"))
	if !strings.Contains(sheet, "rule will run no actions") || !strings.Contains(sheet, "removes its own stop barrier") {
		t.Fatal("zero-enabled or barrier copy missing")
	}
	_, _, sheet = ui2ConfirmReview(t, s, actionForm(s, id, "action_stop_off", "0"))
	if !strings.Contains(sheet, "earlier stops or action outcomes can still prevent") {
		t.Fatal("stop-off guarantees execution")
	}
}
