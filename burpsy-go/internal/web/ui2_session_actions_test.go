package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
)

func actionForm(s *Server, id int64, op string, index string) url.Values {
	_, base, _ := s.sessionCoordinator.RuleSnapshot(session.RuleID(id))
	return url.Values{"rule_op": {op}, "rule_id": {ui2RuleIDStr(id)}, "form_base": {base}, "action_index": {index}}
}
func actionSeed(t *testing.T, s *Server) int64 {
	return ui2SeedSessionRule(t, s, map[string]any{"name": "ordered", "enabled": true, "actions": []map[string]any{{"kind": "set_header", "enabled": true, "stop": true, "name": "X-One", "value": "CANARY-FIRST"}, {"kind": "set_cookie", "enabled": false, "name": "session", "value": "CANARY-SECOND"}}})
}
func actionApply(t *testing.T, s *Server, f url.Values) string {
	t.Helper()
	id, tok, sheet := ui2ConfirmReview(t, s, f)
	out := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {tok}})
	if !strings.Contains(out.Body.String(), "rule actions updated") {
		t.Fatalf("apply: %s", out.Body.String())
	}
	return sheet
}
func TestUI2SessionActionsFormBindsSnapshotAndWithholdsContent(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	id := actionSeed(t, s)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/session", nil))
	body := rec.Body.String()
	_, base, _ := s.sessionCoordinator.RuleSnapshot(session.RuleID(id))
	if !strings.Contains(body, `name="form_base" value="`+base+`"`) || !strings.Contains(body, "1. Set a specific header value") {
		t.Fatal("action forms missing snapshot or labels")
	}
	for _, secret := range []string{"CANARY-FIRST", "CANARY-SECOND"} {
		if strings.Contains(body, secret) {
			t.Fatalf("page leaks %s", secret)
		}
	}
	if strings.Contains(body, `name="action_enabled"`) || strings.Contains(body, `name="action_stop"`) {
		t.Fatal("deferred switches became editable")
	}
}
func TestUI2SessionActionsEditKeepAndClear(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	id := actionSeed(t, s)
	f := actionForm(s, id, "action_edit", "0")
	f.Set("action_name", "X-Renamed")
	f.Set("action_value_mode", "keep")
	before := session.RuleDigest(s.sessionCoordinator.Rule(session.RuleID(id)))
	rid, tok, sheet := ui2ConfirmReview(t, s, f)
	if session.RuleDigest(s.sessionCoordinator.Rule(session.RuleID(id))) != before {
		t.Fatal("mint mutated live rule")
	}
	if strings.Contains(sheet, "CANARY-FIRST") || !strings.Contains(sheet, "THIS RULE IS ON") {
		t.Fatal("review redaction or live effect warning missing")
	}
	ui2PostSessionRules(t, s, "run", url.Values{"review_id": {rid}, "token": {tok}})
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	a := rule.Actions[0]
	if a.Name != "X-Renamed" || a.Value != "CANARY-FIRST" || !a.Enabled || !a.Stop || !rule.Enabled || rule.Actions[1].Value != "CANARY-SECOND" {
		t.Fatalf("edit lost fields: %+v", a)
	}
	f = actionForm(s, id, "action_edit", "0")
	f.Set("action_name", "X-Renamed")
	f.Set("action_value_mode", "clear")
	actionApply(t, s, f)
	if s.sessionCoordinator.Rule(session.RuleID(id)).Actions[0].Value != "" {
		t.Fatal("clear did not clear")
	}
}
func TestUI2SessionActionsStaleFormAndRunRefuse(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	id := actionSeed(t, s)
	f := actionForm(s, id, "action_remove", "0")
	actionApply(t, s, actionForm(s, id, "action_up", "1"))
	out := ui2PostSessionRules(t, s, "confirm", f)
	if !strings.Contains(out.Body.String(), "changed since this action form opened") {
		t.Fatal("stale form earned review")
	}
	f = actionForm(s, id, "action_remove", "0")
	rid, tok, _ := ui2ConfirmReview(t, s, f)
	actionApply(t, s, actionForm(s, id, "action_up", "1"))
	before := session.RuleDigest(s.sessionCoordinator.Rule(session.RuleID(id)))
	out = ui2PostSessionRules(t, s, "run", url.Values{"review_id": {rid}, "token": {tok}})
	if session.RuleDigest(s.sessionCoordinator.Rule(session.RuleID(id))) != before || !strings.Contains(out.Body.String(), "changed") {
		t.Fatal("stale run wrote")
	}
}
func TestUI2SessionActionsAppendMoveRemoveAndLastRefusal(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	id := actionSeed(t, s)
	f := actionForm(s, id, "action_append", "")
	f.Set("action", "set_param")
	f.Set("action_name", "p")
	f.Set("action_value", "new")
	f.Set("action_in", "body")
	actionApply(t, s, f)
	actionApply(t, s, actionForm(s, id, "action_up", "2"))
	r := s.sessionCoordinator.Rule(session.RuleID(id))
	if len(r.Actions) != 3 || r.Actions[1].Kind != session.ActionSetParam || r.Actions[1].In != "body" || !r.Actions[0].Stop || r.Actions[2].Enabled {
		t.Fatal("append or move lost order or switches")
	}
	actionApply(t, s, actionForm(s, id, "action_remove", "1"))
	actionApply(t, s, actionForm(s, id, "action_remove", "1"))
	out := ui2PostSessionRules(t, s, "confirm", actionForm(s, id, "action_remove", "0"))
	if !strings.Contains(out.Body.String(), "cannot remove the last action") {
		t.Fatal("last removal allowed")
	}
}
func TestUI2SessionActionsSecretModesRefuse(t *testing.T) {
	for _, tc := range []struct{ mode, value string }{{"", ""}, {"replace", redactedValue}, {"replace", ""}, {"keep", "new"}, {"clear", "new"}} {
		s := newTestServerWithCoordinator(t)
		id := actionSeed(t, s)
		f := actionForm(s, id, "action_edit", "0")
		f.Set("action_name", "X")
		f.Set("action_value_mode", tc.mode)
		f.Set("action_value", tc.value)
		out := ui2PostSessionRules(t, s, "confirm", f)
		if !strings.Contains(out.Body.String(), "Not applied:") {
			t.Fatalf("invalid mode accepted %+v", tc)
		}
	}
}
func TestUI2SessionActionsLabelOnlyFieldsPreserved(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	id := actionSeed(t, s)
	live := s.sessionCoordinator.Rule(session.RuleID(id))
	live.Actions[1].ExtensionSession = "opaque-canary"
	if ui2SessionActionEditable(live.Actions[1]) {
		t.Fatal("unfamiliar field action editable")
	}
	old, _ := json.Marshal(live.Actions[1])
	f := actionForm(s, id, "action_edit", "1")
	f.Set("action_name", "bad")
	f.Set("action_value_mode", "clear")
	out := ui2PostSessionRules(t, s, "confirm", f)
	if !strings.Contains(out.Body.String(), "label-only") {
		t.Fatal("label-only edit allowed")
	}
	actionApply(t, s, actionForm(s, id, "action_up", "1"))
	now, _ := json.Marshal(s.sessionCoordinator.Rule(session.RuleID(id)).Actions[0])
	if string(old) != string(now) {
		t.Fatalf("move changed opaque action: %s != %s", old, now)
	}
}

func TestUI2SessionActionsReplaceScriptAndValidation(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	id := actionSeed(t, s)
	for _, kind := range []string{"replace", "run_script"} {
		f := actionForm(s, id, "action_append", "")
		f.Set("action", kind)
		if kind == "replace" {
			f.Set("action_match", "CANARY-MATCH")
			f.Set("action_replacement", "CANARY-REPLACEMENT")
		} else {
			f.Set("action_script", "request.headers['X-Test']='CANARY-SCRIPT';")
		}
		actionApply(t, s, f)
	}
	f := actionForm(s, id, "action_edit", "2")
	f.Set("action_match_mode", "keep")
	f.Set("action_replacement_mode", "clear")
	actionApply(t, s, f)
	if a := s.sessionCoordinator.Rule(session.RuleID(id)).Actions[2]; a.Match != "CANARY-MATCH" || a.Replacement != "" {
		t.Fatal("replace keep/clear lost content")
	}
	for _, field := range []string{"action_match", "action_script"} {
		index := "2"
		if field == "action_script" {
			index = "3"
		}
		f := actionForm(s, id, "action_edit", index)
		f.Set(field+"_mode", "clear")
		if field == "action_match" {
			f.Set("action_replacement_mode", "keep")
		}
		out := ui2PostSessionRules(t, s, "confirm", f)
		if !strings.Contains(out.Body.String(), field+" cannot be cleared") {
			t.Fatal("required content cleared or wrong refusal")
		}
	}
	f = actionForm(s, id, "action_edit", "2")
	f.Set("action_match_mode", "replace")
	f.Set("action_match", "[")
	f.Set("action_regex", "1")
	f.Set("action_replacement_mode", "keep")
	out := ui2PostSessionRules(t, s, "confirm", f)
	if !strings.Contains(out.Body.String(), "does not compile") {
		t.Fatal("bad regex earned review")
	}
	f = actionForm(s, id, "action_edit", "3")
	f.Set("action_script_mode", "replace")
	f.Set("action_script", "if (")
	out = ui2PostSessionRules(t, s, "confirm", f)
	if !strings.Contains(out.Body.String(), "Not applied:") {
		t.Fatal("bad script earned review")
	}
	f = actionForm(s, id, "action_edit", "0")
	f.Set("action_value_mode", "keep")
	f.Set("action_name", "X")
	f.Set("action_stop", "1")
	out = ui2PostSessionRules(t, s, "confirm", f)
	if !strings.Contains(out.Body.String(), "does not belong") {
		t.Fatal("foreign field silently accepted")
	}
}

func TestUI2SessionActionsEditorOutsideTableAndReviewScroll(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	actionSeed(t, s)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/session", nil))
	b := rec.Body.String()
	if strings.Index(b, `id="session-action-editors"`) < strings.Index(b, "</table>") {
		t.Fatal("action editor trapped inside narrow table")
	}
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/app.js", nil))
	if !strings.Contains(rec.Body.String(), "sessionMain.scrollTop = 0") {
		t.Fatal("session main scroll not reset")
	}
	if !strings.Contains(rec.Body.String(), "document.body.dataset.view === 'session' && document.querySelector('#rows[data-review]')") {
		t.Fatal("session review can begin under sticky header")
	}
}

func TestUI2SessionActionsAppendCannotKeepOrSetSwitches(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	id := actionSeed(t, s)
	for _, k := range []string{"action_value_mode", "action_enabled", "action_stop"} {
		f := actionForm(s, id, "action_append", "")
		f.Set("action", "set_header")
		f.Set("action_name", "X-New")
		f.Set("action_value", "synthetic")
		f.Set(k, "keep")
		out := ui2PostSessionRules(t, s, "confirm", f)
		if !strings.Contains(out.Body.String(), "not available for a new action") {
			t.Fatalf("new action accepted %s", k)
		}
	}
}
