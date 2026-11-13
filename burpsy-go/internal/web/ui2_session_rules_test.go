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

// The ui2 session-rules page controls (add / toggle / edit / remove) ride the confirm gate the
// Triage way: exact minted bytes held server-side, single-use, and - for PUT - an
// expected_base precondition checked inside one coordinator lock hold. These pins cover the
// flows, the preservation contract of the full-replace PUT, and every refusal the page must
// surface instead of papering over.

func ui2PostSessionRules(t *testing.T, s *Server, action string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/session/rules/"+action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func ui2RuleIDStr(v int64) string { return strings.TrimSpace(string(mustJSONNum(v))) }

func mustJSONNum(v int64) []byte { b, _ := json.Marshal(v); return b }

// ui2SeedSessionRule installs a rule straight through the API mux (unguarded in tests) and
// returns its id.
func ui2SeedSessionRule(t *testing.T, s *Server, body map[string]any) int64 {
	t.Helper()
	rec := postJSON(t, s, "/api/session/rules", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("seed POST /api/session/rules = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var out struct {
		Rule struct {
			ID int64 `json:"id"`
		} `json:"rule"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Rule.ID == 0 {
		t.Fatalf("seed response unreadable: %q err=%v", rec.Body.String(), err)
	}
	return out.Rule.ID
}

// ui2ConfirmReview runs the confirm step and returns the minted review id + token.
func ui2ConfirmReview(t *testing.T, s *Server, form url.Values) (string, string, string) {
	t.Helper()
	rec := ui2PostSessionRules(t, s, "confirm", form)
	body := rec.Body.String()
	if strings.Contains(body, "Not applied:") {
		t.Fatalf("confirm refused: %s", body[:ui2MinFor(600, len(body))])
	}
	id, token := ui2ReviewFields(t, body)
	return id, token, body
}

func ui2MinFor(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// nontrivialRuleBody is a rule carrying every field the page does NOT edit: macro steps,
// validity, scope_params, max_attempts at 2^53+1 (a literal float64 decoding rounds away, so it
// pins the merge's number precision), and a tools scope. An edit that drops or rounds any of
// these is the silent-reset the full-replace PUT contract forbids.
func nontrivialRuleBody() map[string]any {
	return map[string]any{
		"name":         "login-original",
		"enabled":      true,
		"scope_tools":  []string{"proxy"},
		"scope_params": []string{"csrf_token"},
		"max_attempts": 9007199254740993,
		"validity":     map[string]any{"mode": "never"},
		"steps": []map[string]any{{
			"method": "GET", "url": "https://fixture.test/login",
			"headers": [][2]string{{"X-Fixture", "1"}}, "body": "",
		}},
	}
}

func TestUI2SessionRuleAddCreatesDisabledJarRule(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	_, _, sheet := ui2ConfirmReview(t, s, url.Values{
		"rule_op": {"add"}, "name": {"jar rule"}, "tools": {"proxy"},
		"action": {session.ActionKindName(session.ActionAddCookiesFromJar)},
	})
	if !strings.Contains(sheet, "created turned off") || !strings.Contains(sheet, "proxy") {
		t.Errorf("review sheet misses the created-off or tools wording: %s", sheet[:ui2MinFor(600, len(sheet))])
	}
	id, token := ui2ReviewFields(t, sheet)
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "rule added (turned off)") {
		t.Fatalf("run note missing: %s", rec.Body.String()[:ui2MinFor(400, len(rec.Body.String()))])
	}
	recGet := get(t, s, "/api/session/rules")
	var resp struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(recGet.Body.Bytes(), &resp); err != nil || len(resp.Rules) != 1 {
		t.Fatalf("GET rules = %s", recGet.Body.String())
	}
	rule := resp.Rules[0]
	if rule["enabled"] != false {
		t.Errorf("added rule is not off: %v", rule["enabled"])
	}
	actions, _ := rule["actions"].([]any)
	if len(actions) != 1 {
		t.Fatalf("actions = %v, want the one jar action", actions)
	}
	if k := actions[0].(map[string]any)["kind"]; k != session.ActionKindName(session.ActionAddCookiesFromJar) {
		t.Errorf("action kind = %v", k)
	}
	tools, _ := rule["scope_tools"].([]any)
	if len(tools) != 1 || tools[0] != "proxy" {
		t.Errorf("scope_tools = %v, want [proxy]", tools)
	}
}

func TestUI2SessionRuleAddWithoutToolsOmitsScopeToolsKey(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	_, _, _ = ui2ConfirmReview(t, s, url.Values{"rule_op": {"add"}, "name": {"all-tools rule"}, "action": {session.ActionKindName(session.ActionAddCookiesFromJar)}})
	// The held body must not carry scope_tools at all: absent is "every tool", and an explicit
	// empty list is the restriction the engine refuses - writing one would mint a dead rule.
	var entry ui2SessionRuleReview
	s.ui2SessionRuleReviews.Range(func(_, v any) bool { entry = v.(ui2SessionRuleReview); return false })
	var held map[string]any
	if err := json.Unmarshal(entry.body, &held); err != nil {
		t.Fatalf("held body unreadable: %v", err)
	}
	if _, present := held["scope_tools"]; present {
		t.Errorf("no-tools add wrote scope_tools: %s", entry.body)
	}
	if held["enabled"] != false {
		t.Errorf("held body enabled = %v, want false", held["enabled"])
	}
}

func TestUI2SessionRuleEditPreservesUneditedFields(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	form := url.Values{
		"rule_op": {"edit"}, "rule_id": {ui2RuleIDStr(ruleID)},
		"name": {"login-renamed"}, "tools_mode": {"selected"}, "tools": {"proxy"},
	}
	_, _, sheet := ui2ConfirmReview(t, s, form)
	if !strings.Contains(sheet, "login-renamed") || !strings.Contains(sheet, "kept unchanged") {
		t.Errorf("edit sheet wording: %s", sheet[:ui2MinFor(600, len(sheet))])
	}
	var entry ui2SessionRuleReview
	s.ui2SessionRuleReviews.Range(func(_, v any) bool { entry = v.(ui2SessionRuleReview); return false })
	if !entry.domain {
		t.Fatalf("edit must be held as a domain install, not a wire PUT (the DTO round-trip drops Action.Validity and Action.ExtensionSession)")
	}
	raw := string(entry.body)
	// The exact 2^53+1 literal must ride the merge byte-for-byte; a float64 round-trip writes
	// ...992 instead.
	if !strings.Contains(raw, `"max_attempts":9007199254740993`) {
		t.Errorf("max_attempts literal not preserved: %s", raw)
	}
	// Domain marshal keys: the merge never re-encodes through the DTO, so the held bytes carry
	// the storage shape (macro, not the DTO's steps).
	for _, key := range []string{`"macro"`, `"validity"`, `"scope_params"`, `"scope_tools"`} {
		if !strings.Contains(raw, key) {
			t.Errorf("held body missing %s: %s", key, raw)
		}
	}
	// The compare-and-update precondition rides the entry and is shown on the sheet in full:
	// 64 hex chars of the digest the swap binds.
	if len(entry.expectedBase) != 64 {
		t.Fatalf("entry lacks the full 64-hex expected_base: %q", entry.expectedBase)
	}
	if !strings.Contains(sheet, entry.expectedBase) {
		t.Errorf("the sheet elides the precondition digest; the exact-change projection must show it in full")
	}
	if !strings.Contains(sheet, "fixture.test/login") {
		t.Errorf("the sheet truncates the preserved fields; the exact-call projection must show them in full")
	}
	id, token := ui2ReviewFields(t, sheet)
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "rule updated") {
		t.Fatalf("run note: %s", rec.Body.String()[:ui2MinFor(300, len(rec.Body.String()))])
	}
	got := s.sessionCoordinator.Rule(session.RuleID(ruleID))
	if got.Name != "login-renamed" {
		t.Errorf("name = %q", got.Name)
	}
	if len(got.Steps) != 1 || got.MaxAttempts != 9007199254740993 || len(got.ScopeParams) != 1 || len(got.ScopeTools) != 1 {
		t.Errorf("preservation broke: steps=%d max=%d params=%v tools=%v", len(got.Steps), got.MaxAttempts, got.ScopeParams, got.ScopeTools)
	}
}

func TestUI2SessionRuleEditAllToolsDropsScopeToolsKey(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	id, token, _ := ui2ConfirmReview(t, s, url.Values{
		"rule_op": {"edit"}, "rule_id": {ui2RuleIDStr(ruleID)}, "name": {"login-original"}, "tools_mode": {"all"},
	})
	var entry ui2SessionRuleReview
	s.ui2SessionRuleReviews.Range(func(_, v any) bool { entry = v.(ui2SessionRuleReview); return false })
	if strings.Contains(string(entry.body), `"scope_tools"`) {
		t.Errorf("all-tools edit kept scope_tools: %s", entry.body)
	}
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "rule updated") {
		t.Fatalf("run: %s", rec.Body.String()[:ui2MinFor(300, len(rec.Body.String()))])
	}
	if got := s.sessionCoordinator.Rule(session.RuleID(ruleID)); len(got.ScopeTools) != 0 {
		t.Errorf("ScopeTools = %v, want unrestricted", got.ScopeTools)
	}
}

func TestUI2SessionRuleEditZeroToolsSelectedRefused(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	rec := ui2PostSessionRules(t, s, "confirm", url.Values{
		"rule_op": {"edit"}, "rule_id": {ui2RuleIDStr(ruleID)}, "name": {"x"}, "tools_mode": {"selected"},
	})
	if !strings.Contains(rec.Body.String(), "applies to nothing") {
		t.Fatalf("zero-tools edit not refused in words: %s", rec.Body.String()[:ui2MinFor(400, len(rec.Body.String()))])
	}
	if s.sessionCoordinator.Rule(session.RuleID(ruleID)).Name != "login-original" {
		t.Error("a refused edit touched the rule")
	}
}

func TestUI2SessionRuleToggleAppliesAndNamesConsequence(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, map[string]any{
		"name":    "jar-login",
		"enabled": false,
		"actions": []map[string]any{{"kind": session.ActionKindName(session.ActionAddCookiesFromJar), "enabled": true}},
	})
	_, _, sheet := ui2ConfirmReview(t, s, url.Values{
		"rule_op": {"toggle"}, "rule_id": {ui2RuleIDStr(ruleID)}, "target_enabled": {"true"},
	})
	// The consequence must say what enabling DOES - attach the jar's cookies, nothing when the
	// jar is empty - and name the scope it runs on, not just list an action kind.
	if !strings.Contains(sheet, "session cookie jar") || !strings.Contains(sheet, "nothing is attached") {
		t.Errorf("toggle-on sheet misses the cookie consequence: %s", sheet[:ui2MinFor(800, len(sheet))])
	}
	if !strings.Contains(sheet, "tools:") {
		t.Errorf("toggle-on sheet misses the tools scope: %s", sheet[:ui2MinFor(800, len(sheet))])
	}
	id, token := ui2ReviewFields(t, sheet)
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "rule turned on") {
		t.Fatalf("run note: %s", rec.Body.String()[:ui2MinFor(300, len(rec.Body.String()))])
	}
	if !s.sessionCoordinator.Rule(session.RuleID(ruleID)).Enabled {
		t.Error("rule still off after a confirmed toggle")
	}
}

func TestUI2SessionRuleStaleBaseConflictRefusesAndKeepsNewer(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	id, token, _ := ui2ConfirmReview(t, s, url.Values{
		"rule_op": {"toggle"}, "rule_id": {ui2RuleIDStr(ruleID)}, "target_enabled": {"false"},
	})
	// The rule moves between review and apply: someone else renames it.
	moved := nontrivialRuleBody()
	moved["name"] = "login-moved-elsewhere"
	recPut := putJSON(t, s, "/api/session/rules/"+ui2RuleIDStr(ruleID), moved)
	if recPut.Code != http.StatusOK {
		t.Fatalf("mid-review PUT = %d: %s", recPut.Code, recPut.Body.String())
	}
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	body := rec.Body.String()
	if !strings.Contains(body, "changed since you reviewed") {
		t.Fatalf("stale apply not refused in words: %s", body[:ui2MinFor(400, len(body))])
	}
	got := s.sessionCoordinator.Rule(session.RuleID(ruleID))
	if got.Name != "login-moved-elsewhere" || !got.Enabled {
		t.Errorf("the stale apply clobbered the newer state: name=%q enabled=%v", got.Name, got.Enabled)
	}
}

func TestUI2SessionRuleDeletedBeforeApplyGets404(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	id, token, _ := ui2ConfirmReview(t, s, url.Values{
		"rule_op": {"toggle"}, "rule_id": {ui2RuleIDStr(ruleID)}, "target_enabled": {"false"},
	})
	s.sessionCoordinator.RemoveRule(session.RuleID(ruleID))
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "no longer exists") {
		t.Fatalf("deleted rule not answered in words: %s", rec.Body.String()[:ui2MinFor(400, len(rec.Body.String()))])
	}
}

func TestUI2SessionRuleRemoveFlow(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	_, _, sheet := ui2ConfirmReview(t, s, url.Values{"rule_op": {"remove"}, "rule_id": {ui2RuleIDStr(ruleID)}})
	if !strings.Contains(sheet, "Remove rule") || !strings.Contains(sheet, "permanently") {
		t.Errorf("remove sheet: %s", sheet[:ui2MinFor(400, len(sheet))])
	}
	id, token := ui2ReviewFields(t, sheet)
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "rule removed") {
		t.Fatalf("run note: %s", rec.Body.String()[:ui2MinFor(300, len(rec.Body.String()))])
	}
	if s.sessionCoordinator.Rule(session.RuleID(ruleID)) != nil {
		t.Error("rule survived a confirmed remove")
	}
}

func TestUI2SessionRuleHostileNameEscapedEverywhere(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	hostile := `<script>alert(1)</script>`
	_, _, sheet := ui2ConfirmReview(t, s, url.Values{"rule_op": {"add"}, "name": {hostile}, "action": {session.ActionKindName(session.ActionAddCookiesFromJar)}})
	if strings.Contains(sheet, "<script>alert(1)</script>") {
		t.Errorf("review sheet renders the name raw")
	}
	id, token := ui2ReviewFields(t, sheet)
	ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	rec := get(t, s, "/ui2/session")
	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Errorf("session page renders the stored name raw")
	}
	if !strings.Contains(rec.Body.String(), "&lt;script&gt;") {
		t.Errorf("session page does not show the escaped name")
	}
}

func TestUI2SessionRuleRunRejectsUnknownAndReusedReview(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {"bogus"}, "token": {"bogus"}})
	if !strings.Contains(rec.Body.String(), "unknown or was already used") {
		t.Fatalf("bogus review not refused: %s", rec.Body.String()[:ui2MinFor(300, len(rec.Body.String()))])
	}
	id, token, _ := ui2ConfirmReview(t, s, url.Values{"rule_op": {"add"}, "name": {"single-use"}, "action": {session.ActionKindName(session.ActionAddCookiesFromJar)}})
	ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	rec2 := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec2.Body.String(), "unknown or was already used") {
		t.Fatalf("reused review not refused: %s", rec2.Body.String()[:ui2MinFor(300, len(rec2.Body.String()))])
	}
	recGet := get(t, s, "/api/session/rules")
	if n := strings.Count(recGet.Body.String(), `"name":"single-use"`); n != 1 {
		t.Errorf("single-use rule count = %d", n)
	}
	// A foreign token against a live review id: mint one, spend with the wrong token.
	id2, _, _ := ui2ConfirmReview(t, s, url.Values{"rule_op": {"add"}, "name": {"foreign-token"}, "action": {session.ActionKindName(session.ActionAddCookiesFromJar)}})
	rec3 := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id2}, "token": {"deadbeefdeadbeefdeadbeefdeadbeef"}})
	if !strings.Contains(rec3.Body.String(), "does not match this confirmation") {
		t.Fatalf("foreign token not refused: %s", rec3.Body.String()[:ui2MinFor(300, len(rec3.Body.String()))])
	}
}

// The API-level precondition: a PUT carrying a wrong expected_base answers 409, the right one
// applies, and an absent one keeps the historical unconditional PUT.
func TestSessionRulePutExpectedBasePrecondition(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	recGet := get(t, s, "/api/session/rules")
	var resp struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(recGet.Body.Bytes(), &resp); err != nil || len(resp.Rules) != 1 {
		t.Fatalf("GET rules: %s", recGet.Body.String())
	}
	dto := resp.Rules[0]
	dto["name"] = "via-stale-base"
	dto["expected_base"] = "bogus"
	if rec := putJSON(t, s, "/api/session/rules/"+ui2RuleIDStr(ruleID), dto); rec.Code != http.StatusConflict {
		t.Fatalf("stale expected_base = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if got := s.sessionCoordinator.Rule(session.RuleID(ruleID)).Name; got != "login-original" {
		t.Errorf("stale-base PUT changed the name to %q", got)
	}
	dto["name"] = "via-correct-base"
	dto["expected_base"] = session.RuleDigest(s.sessionCoordinator.Rule(session.RuleID(ruleID)))
	if rec := putJSON(t, s, "/api/session/rules/"+ui2RuleIDStr(ruleID), dto); rec.Code != http.StatusOK {
		t.Fatalf("correct expected_base = %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.sessionCoordinator.Rule(session.RuleID(ruleID)).Name; got != "via-correct-base" {
		t.Errorf("correct-base PUT did not apply: %q", got)
	}
	delete(dto, "expected_base")
	dto["name"] = "via-plain-put"
	if rec := putJSON(t, s, "/api/session/rules/"+ui2RuleIDStr(ruleID), dto); rec.Code != http.StatusOK {
		t.Fatalf("plain PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.sessionCoordinator.Rule(session.RuleID(ruleID)).Name; got != "via-plain-put" {
		t.Errorf("plain PUT did not apply: %q", got)
	}
}

// A PUT body carrying a key this version does not know is accepted, not 400-refused (the
// strict-decode probe only applies to agent callers); the console PUT contract documents this.
func TestSessionRulePutToleratesUnknownKey(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	recGet := get(t, s, "/api/session/rules")
	var resp struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(recGet.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET rules: %s", recGet.Body.String())
	}
	dto := resp.Rules[0]
	dto["future_field"] = 5
	if rec := putJSON(t, s, "/api/session/rules/"+ui2RuleIDStr(ruleID), dto); rec.Code != http.StatusOK {
		t.Fatalf("unknown-key PUT = %d: %s", rec.Code, rec.Body.String())
	}
}

// The add form's action is an explicit pick: without it the confirm refuses and nothing is
// minted, so no default action can ever be created silently.
func TestUI2SessionRuleAddRefusedWithoutActionChoice(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	rec := ui2PostSessionRules(t, s, "confirm", url.Values{"rule_op": {"add"}, "name": {"no-action-pick"}})
	if !strings.Contains(rec.Body.String(), "choose the rule") {
		t.Fatalf("add without action pick not refused in words: %s", rec.Body.String()[:ui2MinFor(400, len(rec.Body.String()))])
	}
	count := 0
	s.ui2SessionRuleReviews.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Errorf("a review was minted without the action pick")
	}
	recGet := get(t, s, "/api/session/rules")
	if strings.Contains(recGet.Body.String(), "no-action-pick") {
		t.Error("the refused add created a rule")
	}
}

// Remove carries the same compare-and-update precondition as edit/toggle: a rule that changed
// between review and apply is not removed.
func TestUI2SessionRuleRemoveStaleBaseRefusesAndKeepsRule(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	id, token, sheet := ui2ConfirmReview(t, s, url.Values{"rule_op": {"remove"}, "rule_id": {ui2RuleIDStr(ruleID)}})
	if !strings.Contains(sheet, "still exactly what this review shows") {
		t.Errorf("remove sheet misses the precondition wording: %s", sheet[:ui2MinFor(800, len(sheet))])
	}
	moved := nontrivialRuleBody()
	moved["name"] = "login-moved-before-remove"
	if rec := putJSON(t, s, "/api/session/rules/"+ui2RuleIDStr(ruleID), moved); rec.Code != http.StatusOK {
		t.Fatalf("mid-review PUT = %d", rec.Code)
	}
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "changed since you reviewed") {
		t.Fatalf("stale remove not refused in words: %s", rec.Body.String()[:ui2MinFor(400, len(rec.Body.String()))])
	}
	if got := s.sessionCoordinator.Rule(session.RuleID(ruleID)); got == nil || got.Name != "login-moved-before-remove" {
		t.Fatalf("the stale remove landed: %+v", got)
	}
}

// The API-level DELETE precondition: ?expected_base= stale answers 409, fresh removes, absent
// keeps the legacy unconditional delete.
func TestSessionRuleDeleteExpectedBasePrecondition(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	del := func(url string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodDelete, url, nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		return rec
	}
	if rec := del("/api/session/rules/" + ui2RuleIDStr(ruleID) + "?expected_base=bogus"); rec.Code != http.StatusConflict {
		t.Fatalf("stale-base DELETE = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if s.sessionCoordinator.Rule(session.RuleID(ruleID)) == nil {
		t.Fatal("stale-base DELETE removed the rule")
	}
	base := session.RuleDigest(s.sessionCoordinator.Rule(session.RuleID(ruleID)))
	if rec := del("/api/session/rules/" + ui2RuleIDStr(ruleID) + "?expected_base=" + base); rec.Code != http.StatusOK {
		t.Fatalf("fresh-base DELETE = %d: %s", rec.Code, rec.Body.String())
	}
	if s.sessionCoordinator.Rule(session.RuleID(ruleID)) != nil {
		t.Fatal("fresh-base DELETE did not remove the rule")
	}
	legacy := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	if rec := del("/api/session/rules/" + ui2RuleIDStr(legacy)); rec.Code != http.StatusOK {
		t.Fatalf("legacy DELETE = %d: %s", rec.Code, rec.Body.String())
	}
	if s.sessionCoordinator.Rule(session.RuleID(legacy)) != nil {
		t.Fatal("legacy DELETE did not remove the rule")
	}
}

// A toggle/edit review projects the FULL held body - but a full body can carry credentials
// (a set-cookie action's value, a macro step's login form body, an Authorization header).
// The sheet must withhold those values while the token still binds them, and the names and
// the expected_base precondition must stay visible (reviewer catch: only-redactSecrets misses
// a secret sitting in a generic "value" member).
func TestUI2SessionRuleReviewRedactsCarriedCredentials(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2SeedSessionRule(t, s, map[string]any{
		"name": "secret-carrying", "enabled": false, "scope_tools": []string{"proxy"},
		"actions": []any{
			map[string]any{"kind": "set_cookie", "name": "sessid", "value": "SECRET-COOKIE-VALUE-9f3", "enabled": true},
			map[string]any{"kind": "replace", "match": "SECRET-OLDTOKEN-MATCH-04", "replacement": "SECRET-REPLACEMENT-03", "enabled": true},
		},
		"steps": []any{
			map[string]any{"method": "POST", "url": "http://fixture:SECRET-URLPW-66@127.0.0.1:19999/login?next=/home&token=SECRET-URLTOKEN-77#access_token=SECRET-FRAG-TOK-08&state=visible-state", "body": "user=u&password=SECRET-LOGIN-PW-55", "headers": []any{
				[]any{"Authorization", "Bearer SECRET-AUTH-TOKEN-11"},
				[]any{"X-Normal", "visible"},
			}},
		},
	})
	_, _, sheet := ui2ConfirmReview(t, s, url.Values{"rule_op": {"toggle"}, "rule_id": {ui2RuleIDStr(ruleID)}, "target_enabled": {"true"}})

	for _, secret := range []string{"SECRET-COOKIE-VALUE-9f3", "SECRET-LOGIN-PW-55", "SECRET-AUTH-TOKEN-11", "SECRET-REPLACEMENT-03", "SECRET-OLDTOKEN-MATCH-04", "SECRET-URLPW-66", "SECRET-URLTOKEN-77", "SECRET-FRAG-TOK-08"} {
		if strings.Contains(sheet, secret) {
			t.Fatalf("review sheet leaks a carried credential %q", secret)
		}
	}
	if !strings.Contains(sheet, "sessid") || !strings.Contains(sheet, "X-Normal") || !strings.Contains(sheet, "visible") ||
		!strings.Contains(sheet, "127.0.0.1:19999") || !strings.Contains(sheet, "next=") ||
		!strings.Contains(sheet, "state=visible-state") {
		t.Errorf("redaction must withhold only the values - names and non-secret data stay visible")
	}
	if !strings.Contains(sheet, "«redacted»") {
		t.Errorf("sheet must mark withheld values")
	}
	// The binding is intact: the held bytes still carry every credential, dispatched verbatim.
	var entry ui2SessionRuleReview
	s.ui2SessionRuleReviews.Range(func(_, v any) bool { entry = v.(ui2SessionRuleReview); return false })
	raw := string(entry.body)
	for _, secret := range []string{"SECRET-COOKIE-VALUE-9f3", "SECRET-LOGIN-PW-55", "SECRET-AUTH-TOKEN-11", "SECRET-REPLACEMENT-03", "SECRET-OLDTOKEN-MATCH-04", "SECRET-URLPW-66", "SECRET-URLTOKEN-77", "SECRET-FRAG-TOK-08"} {
		if !strings.Contains(raw, secret) {
			t.Errorf("held body must keep the bound bytes (%q)", secret)
		}
	}
	// The precondition itself is not a credential: the full 64-hex digest the
	// compare-and-update binds renders on the sheet in full.
	if !entry.domain || len(entry.expectedBase) != 64 {
		t.Fatalf("domain install must hold the full 64-hex expected_base, got domain=%v base=%q", entry.domain, entry.expectedBase)
	}
	if !strings.Contains(sheet, entry.expectedBase) {
		t.Errorf("sheet must render the full precondition digest, not an elided form")
	}
}

// Phone layout pins (the 390px overlap was caught live in UAT: the inline toggle form covered
// the remove button): the session rules table carries the rules-t class and the layout's small
// screen block stacks the action-cell forms and drops the two wide columns.
func TestUI2SessionRulesPhoneLayoutPinned(t *testing.T) {
	tpl, err := ui2FS.ReadFile("ui2/session.html")
	if err != nil {
		t.Fatalf("read session.html: %v", err)
	}
	if !strings.Contains(string(tpl), `<table class="rules-t">`) {
		t.Error("session.html rules table lacks the rules-t class the phone CSS keys on")
	}
	layout, err := ui2FS.ReadFile("ui2/layout.html")
	if err != nil {
		t.Fatalf("read layout.html: %v", err)
	}
	for _, pin := range []string{"table.rules-t td.sa form { display:block", "table.rules-t td:nth-child(4)"} {
		if !strings.Contains(string(layout), pin) {
			t.Errorf("layout.html phone block missing %q", pin)
		}
	}
}

// The live-refresh preservation contract: the note element carries the id app.js looks for, the
// review sheet root carries data-review="1", and app.js holds the session refresh to the pill for
// both - a swap would strand a pending review's one-time token or erase a refusal the operator
// has not read.
func TestUI2SessionLiveRefreshPreservationPinned(t *testing.T) {
	tpl, err := ui2FS.ReadFile("ui2/session.html")
	if err != nil {
		t.Fatalf("read session.html: %v", err)
	}
	if !strings.Contains(string(tpl), `id="session-note"`) {
		t.Error("session.html note lacks the id the live guard looks for")
	}
	confirm, err := ui2FS.ReadFile("ui2/session_confirm.html")
	if err != nil {
		t.Fatalf("read session_confirm.html: %v", err)
	}
	if !strings.Contains(string(confirm), `data-review="1"`) {
		t.Error("session_confirm.html root lacks data-review")
	}
	appjs, err := ui2FS.ReadFile("ui2/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	body := string(appjs)
	if !strings.Contains(body, `rows.dataset.review === '1'`) || !strings.Contains(body, `rows.querySelector('#session-note')`) {
		t.Error("app.js session branch does not guard review sheet + note")
	}
	// The session view must be inside the dirty/focused/open-editor guard list at all.
	head := body[:strings.Index(body, "function liveGuarded")+2000]
	if !strings.Contains(head, `|| what === 'session'`) {
		t.Error("liveGuarded does not cover the session page")
	}
}

// The add form offers exactly the kinds the page can create - no implicit default, every
// per-kind block hidden with its controls disabled in the markup (so a plain post from any
// browser carries only the chosen kind's fields), and the copy names only the kinds and
// shapes that genuinely stay in the console.
func TestUI2SessionRuleAddFormOffersThePageKinds(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	rec := get(t, s, "/ui2/session")
	body := rec.Body.String()
	for _, kind := range []string{
		"add_cookies_from_jar", "set_cookie", "set_header", "set_param",
		"replace", "run_script", "prompt_for_browser_recovery",
	} {
		if !strings.Contains(body, `value="`+kind+`"`) {
			t.Errorf("the add form does not offer %s", kind)
		}
	}
	for _, blocked := range []string{"run_macro", "run_post_request_macro", "check_validity", "invoke_extension"} {
		if strings.Contains(body, `value="`+blocked+`"`) {
			t.Errorf("the add form offers %s, which stays in the console", blocked)
		}
	}
	for _, kind := range []string{"set_cookie", "set_header", "set_param", "replace", "run_script"} {
		i := strings.Index(body, `data-kind="`+kind+`" hidden`)
		if i < 0 {
			t.Fatalf("the %s block is not hidden in the markup", kind)
		}
		j := len(body)
		if k := strings.Index(body[i+1:], `<span class="kind-fields"`); k >= 0 {
			j = i + 1 + k
		}
		for _, field := range []string{`name="action_`} {
			k := strings.Index(body[i:j], field)
			if k < 0 || !strings.Contains(body[i:j][k:], "disabled") {
				t.Errorf("the %s block's fields are not disabled in the markup", kind)
			}
		}
	}
	if !strings.Contains(body, "Macro, validity and extension fields stay in the console. Existing rules offer ordered action-list controls below.") {
		t.Error("the form copy does not name exactly the deferred kinds and shapes")
	}
}

// Every page kind mints a review that names the chosen action, applies through the gate, and
// lands on the stored rule with its own fields - created turned off, one action.
func TestUI2SessionRuleAddPageKindsApply(t *testing.T) {
	cases := []struct {
		name    string
		form    url.Values
		summary string
		check   func(t *testing.T, a map[string]any)
	}{
		{"set_cookie", url.Values{"action": {"set_cookie"}, "action_name": {"sid"}, "action_value": {"CANARY-cookie"}},
			`set the &#34;sid&#34; cookie`, func(t *testing.T, a map[string]any) {
				if a["name"] != "sid" || a["value"] != "CANARY-cookie" {
					t.Errorf("set_cookie fields = %v", a)
				}
			}},
		{"set_header", url.Values{"action": {"set_header"}, "action_name": {"X-Fixture"}, "action_value": {"CANARY-header"}},
			`set the &#34;X-Fixture&#34; header`, func(t *testing.T, a map[string]any) {
				if a["name"] != "X-Fixture" || a["value"] != "CANARY-header" {
					t.Errorf("set_header fields = %v", a)
				}
			}},
		{"set_param", url.Values{"action": {"set_param"}, "action_name": {"tok"}, "action_value": {"CANARY-param"}, "action_in": {"body"}},
			`set the &#34;tok&#34; parameter in the form body`, func(t *testing.T, a map[string]any) {
				if a["name"] != "tok" || a["value"] != "CANARY-param" || a["in"] != "body" {
					t.Errorf("set_param fields = %v", a)
				}
			}},
		{"replace", url.Values{"action": {"replace"}, "action_match": {"old-[0-9]+"}, "action_replacement": {"CANARY-repl"}, "action_regex": {"1"}},
			"replace what the regular expression matches", func(t *testing.T, a map[string]any) {
				if a["match"] != "old-[0-9]+" || a["replacement"] != "CANARY-repl" || a["regex"] != true {
					t.Errorf("replace fields = %v", a)
				}
			}},
		{"run_script", url.Values{"action": {"run_script"}, "action_script": {"request.headers['X-Fixture'] = 'CANARY-script';"}},
			"run a pre-request script", func(t *testing.T, a map[string]any) {
				if a["script"] != "request.headers['X-Fixture'] = 'CANARY-script';" {
					t.Errorf("run_script fields = %v", a)
				}
			}},
		{"prompt_for_browser_recovery", url.Values{"action": {"prompt_for_browser_recovery"}},
			"prompt for in-browser session recovery", func(t *testing.T, a map[string]any) {
				if a["kind"] != "prompt_for_browser_recovery" {
					t.Errorf("prompt fields = %v", a)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerWithCoordinator(t)
			tc.form.Set("rule_op", "add")
			tc.form.Set("name", "fixture rule")
			id, token, sheet := ui2ConfirmReview(t, s, tc.form)
			if !strings.Contains(sheet, tc.summary) {
				t.Errorf("the review summary does not name the action: want %q", tc.summary)
			}
			if !strings.Contains(sheet, "created turned off") {
				t.Error("the review sheet drops the created-off wording")
			}
			rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
			if !strings.Contains(rec.Body.String(), "rule added (turned off)") {
				t.Fatalf("run refused: %s", rec.Body.String()[:ui2MinFor(400, len(rec.Body.String()))])
			}
			recGet := get(t, s, "/api/session/rules")
			var resp struct {
				Rules []map[string]any `json:"rules"`
			}
			if err := json.Unmarshal(recGet.Body.Bytes(), &resp); err != nil || len(resp.Rules) != 1 {
				t.Fatalf("GET rules = %s", recGet.Body.String())
			}
			rule := resp.Rules[0]
			if rule["enabled"] != false {
				t.Errorf("added rule is not off: %v", rule["enabled"])
			}
			actions, _ := rule["actions"].([]any)
			if len(actions) != 1 {
				t.Fatalf("actions = %v, want the one page action", actions)
			}
			action := actions[0].(map[string]any)
			if action["kind"] != tc.form.Get("action") {
				t.Errorf("action kind = %v", action["kind"])
			}
			tc.check(t, action)
		})
	}
}

// A field the chosen kind does not use never reaches the call: a normal browser cannot send
// one (the other kinds' controls stay disabled), so its presence means a crafted or stale
// post and the add is refused with the field and kind named, minting nothing.
func TestUI2SessionRuleAddForeignFieldRefused(t *testing.T) {
	for _, tc := range []struct {
		name, form, wantField string
	}{
		{"match on set_cookie", "action_match", "action_match"},
		{"script on set_header", "action_script", "action_script"},
		{"name on the jar action", "action_name", "action_name"},
		{"value on the prompt action", "action_value", "action_value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerWithCoordinator(t)
			kind := map[string]string{
				"action_match": "set_cookie", "action_script": "set_header",
				"action_name": "add_cookies_from_jar", "action_value": "prompt_for_browser_recovery",
			}[tc.form]
			rec := ui2PostSessionRules(t, s, "confirm", url.Values{
				"rule_op": {"add"}, "name": {"x"}, "action": {kind}, tc.form: {"bogus"},
			})
			body := rec.Body.String()
			if !strings.Contains(body, "Not applied:") || !strings.Contains(body, "does not belong") || !strings.Contains(body, tc.wantField) {
				t.Errorf("foreign field not refused by name: %s", body[:ui2MinFor(400, len(body))])
			}
			if strings.Contains(body, `name="token"`) {
				t.Error("a refused add minted a token")
			}
		})
	}
}

// Kinds the page cannot create are refused naming what stays in the console, minting nothing.
func TestUI2SessionRuleAddConsoleKindsRefused(t *testing.T) {
	for _, kind := range []string{"run_macro", "run_post_request_macro", "check_validity", "invoke_extension", "nonsense", ""} {
		t.Run(kind, func(t *testing.T) {
			s := newTestServerWithCoordinator(t)
			rec := ui2PostSessionRules(t, s, "confirm", url.Values{
				"rule_op": {"add"}, "name": {"x"}, "action": {kind},
			})
			body := rec.Body.String()
			if !strings.Contains(body, "Not applied:") || !strings.Contains(body, "written in the console") {
				t.Errorf("kind %q not refused naming the console: %s", kind, body[:ui2MinFor(300, len(body))])
			}
			if strings.Contains(body, `name="token"`) {
				t.Error("a refused add minted a token")
			}
		})
	}
}

// An invalid call never earns a review sheet: the engine's own validators run at mint, so
// the refusal is the engine's wording and nothing is minted.
func TestUI2SessionRuleAddInvalidCallsMintNothing(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{"set_cookie without a name", url.Values{"action": {"set_cookie"}, "action_value": {"v"}}, "cookie name"},
		{"set_header without a name", url.Values{"action": {"set_header"}, "action_value": {"v"}}, "header name"},
		{"set_param without a name", url.Values{"action": {"set_param"}, "action_value": {"v"}}, "parameter name"},
		{"set_param in refused", url.Values{"action": {"set_param"}, "action_name": {"p"}, "action_in": {"sideways"}}, "in must be query or body"},
		{"replace without a match", url.Values{"action": {"replace"}, "action_replacement": {"v"}}, "match"},
		{"replace bad regex", url.Values{"action": {"replace"}, "action_match": {"old-["}, "action_regex": {"1"}}, "does not compile"},
		{"run_script empty", url.Values{"action": {"run_script"}}, "script is empty"},
		{"run_script uncompilable", url.Values{"action": {"run_script"}, "action_script": {"function {{"}}, "does not compile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerWithCoordinator(t)
			tc.form.Set("rule_op", "add")
			tc.form.Set("name", "x")
			rec := ui2PostSessionRules(t, s, "confirm", tc.form)
			body := rec.Body.String()
			if !strings.Contains(body, "Not applied:") || !strings.Contains(body, tc.want) {
				t.Errorf("invalid call not refused with %q: %s", tc.want, body[:ui2MinFor(400, len(body))])
			}
			if strings.Contains(body, `name="token"`) {
				t.Error("an invalid add minted a token")
			}
		})
	}
}

// A value naming a macro-extracted placeholder is refused at mint: a page-created rule has
// no macro, so nothing could ever extract it and the placeholder would go out verbatim.
func TestUI2SessionRuleAddPlaceholderRefused(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	rec := ui2PostSessionRules(t, s, "confirm", url.Values{
		"rule_op": {"add"}, "name": {"x"}, "action": {"set_cookie"},
		"action_name": {"sid"}, "action_value": {"{{csrf}}"},
	})
	body := rec.Body.String()
	if !strings.Contains(body, "Not applied:") || !strings.Contains(body, "csrf") {
		t.Errorf("placeholder not refused by name: %s", body[:ui2MinFor(400, len(body))])
	}
	if strings.Contains(body, `name="token"`) {
		t.Error("a placeholder-carrying add minted a token")
	}
}

// The review sheet withholds every secret-carrying value while the token binds it: the
// canary never renders, the redaction label shows, and the stored rule proves the held
// bytes carried the real value.
func TestUI2SessionRuleAddReviewWithholdsValuesButHoldsThem(t *testing.T) {
	canary := "CANARY-9f3e2d-secret"
	cases := []struct {
		name string
		form url.Values
	}{
		{"set_cookie", url.Values{"action": {"set_cookie"}, "action_name": {"sid"}, "action_value": {canary}}},
		{"set_header", url.Values{"action": {"set_header"}, "action_name": {"Authorization"}, "action_value": {canary}}},
		{"set_param", url.Values{"action": {"set_param"}, "action_name": {"tok"}, "action_value": {canary}}},
		{"replace", url.Values{"action": {"replace"}, "action_match": {canary}, "action_replacement": {"x-" + canary}}},
		{"run_script", url.Values{"action": {"run_script"}, "action_script": {"request.headers['X'] = '" + canary + "';"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerWithCoordinator(t)
			tc.form.Set("rule_op", "add")
			tc.form.Set("name", "fixture rule")
			id, token, sheet := ui2ConfirmReview(t, s, tc.form)
			if strings.Contains(sheet, canary) {
				t.Errorf("the review sheet renders the withheld value")
			}
			if !strings.Contains(sheet, redactedValue) {
				t.Errorf("the review sheet shows no redaction label: %s", sheet[:ui2MinFor(600, len(sheet))])
			}
			rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
			if !strings.Contains(rec.Body.String(), "rule added (turned off)") {
				t.Fatalf("run refused: %s", rec.Body.String()[:ui2MinFor(400, len(rec.Body.String()))])
			}
			recGet := get(t, s, "/api/session/rules")
			if !strings.Contains(recGet.Body.String(), canary) {
				t.Errorf("the stored rule does not carry the value the token bound")
			}
		})
	}
}

// ui2MakeAdvancedRule seeds a plain rule through the API and then installs the fields the
// wire can never carry - per-action validity, extension session state, and credential-valued
// actions - through the coordinator directly, the way project files and raw engine-JSON
// clients install them. Returns the rule id.
func ui2MakeAdvancedRule(t *testing.T, s *Server) int64 {
	t.Helper()
	ruleID := ui2SeedSessionRule(t, s, nontrivialRuleBody())
	snap, _, ok := s.sessionCoordinator.RuleSnapshot(session.RuleID(ruleID))
	if !ok {
		t.Fatalf("seeded rule %d not in the coordinator", ruleID)
	}
	// After NormaliseActions the materialized list is [check_validity -> else run_macro].
	if len(snap.Actions) == 0 {
		t.Fatalf("stored rule carries no materialized actions")
	}
	snap.Actions[0].Validity = &session.ValidityRule{BodyContains: "logged-out-marker"}
	if len(snap.Actions[0].Else) > 0 {
		snap.Actions[0].Else[0].ExtensionSession = "EXT-STATE-CANARY-05"
	}
	snap.Actions = append(snap.Actions,
		&session.Action{Kind: session.ActionSetCookie, Enabled: true, Name: "session", Value: "SECRET-COOKIE-CANARY-01"},
		&session.Action{Kind: session.ActionReplace, Enabled: true, Match: "SECRET-MATCH-CANARY-02", Replacement: "SECRET-REPL-CANARY-03"},
		&session.Action{Kind: session.ActionRunScript, Enabled: true, Script: "var t = 'SECRET-SCRIPT-CANARY-04';"},
	)
	if err := s.sessionCoordinator.UpdateRule(session.RuleID(ruleID), snap); err != nil {
		t.Fatalf("installing the advanced rule: %v", err)
	}
	return ruleID
}

// The regression this slice repairs: a confirmed toggle must not drop the per-action fields
// the wire DTO cannot carry. Pins the full stored shape by digest, not by field spot-checks.
func TestUI2SessionRuleTogglePreservesAdvancedActionFields(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2MakeAdvancedRule(t, s)
	stored := s.sessionCoordinator.Rule(session.RuleID(ruleID))
	if stored.Actions[0].Validity == nil || len(stored.Actions) != 4 {
		t.Fatalf("advanced rule did not install as intended: %+v", stored.Actions)
	}
	id, token, _ := ui2ConfirmReview(t, s, url.Values{
		"rule_op": {"toggle"}, "rule_id": {ui2RuleIDStr(ruleID)}, "target_enabled": {"false"},
	})
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "rule turned off") {
		t.Fatalf("run note: %s", rec.Body.String()[:ui2MinFor(300, len(rec.Body.String()))])
	}
	// Expected shape: the pre-toggle rule with Enabled flipped, nothing else moved.
	want, _, _ := s.sessionCoordinator.RuleSnapshot(session.RuleID(ruleID))
	want.Enabled = false
	got := s.sessionCoordinator.Rule(session.RuleID(ruleID))
	if session.RuleDigest(got) != session.RuleDigest(want) {
		t.Errorf("toggle moved more than Enabled:\ngot  %s\nwant %s", string(mustJSON(got)), string(mustJSON(want)))
	}
	if got.Actions[0].Validity == nil || got.Actions[0].Else[0].ExtensionSession != "EXT-STATE-CANARY-05" {
		t.Errorf("the per-action fields the wire drops were not preserved: %+v", got.Actions[0])
	}
}

func TestUI2SessionRuleRenamePreservesAdvancedActionFields(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2MakeAdvancedRule(t, s)
	id, token, _ := ui2ConfirmReview(t, s, url.Values{
		"rule_op": {"edit"}, "rule_id": {ui2RuleIDStr(ruleID)}, "name": {"advanced-renamed"}, "tools_mode": {"selected"}, "tools": {"proxy"},
	})
	rec := ui2PostSessionRules(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "rule updated") {
		t.Fatalf("run note: %s", rec.Body.String()[:ui2MinFor(300, len(rec.Body.String()))])
	}
	want, _, _ := s.sessionCoordinator.RuleSnapshot(session.RuleID(ruleID))
	want.Name = "advanced-renamed"
	got := s.sessionCoordinator.Rule(session.RuleID(ruleID))
	if session.RuleDigest(got) != session.RuleDigest(want) {
		t.Errorf("rename moved more than Name:\ngot  %s\nwant %s", string(mustJSON(got)), string(mustJSON(want)))
	}
}

// Pin D1: minting a review never mutates the stored rule - the merge works on a deep copy, so
// a review the operator abandons leaves the rule byte-identical.
func TestUI2SessionRuleMintedReviewDoesNotTouchStoredRule(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2MakeAdvancedRule(t, s)
	before := session.RuleDigest(s.sessionCoordinator.Rule(session.RuleID(ruleID)))
	if _, _, sheet := ui2ConfirmReview(t, s, url.Values{
		"rule_op": {"toggle"}, "rule_id": {ui2RuleIDStr(ruleID)}, "target_enabled": {"false"},
	}); !strings.Contains(sheet, "Review before applying") {
		t.Fatalf("mint did not produce a sheet: %s", sheet[:ui2MinFor(300, len(sheet))])
	}
	// Never run: the review expires on its own.
	if after := session.RuleDigest(s.sessionCoordinator.Rule(session.RuleID(ruleID))); after != before {
		t.Errorf("minting a review changed the stored rule: %s -> %s", before, after)
	}
	if s.sessionCoordinator.Rule(session.RuleID(ruleID)).Enabled != true {
		t.Error("the minted toggle flipped the live rule before confirmation")
	}
}

// Pin D4/D5: the exact-change projection of a domain install withholds the credential carriers
// in the DOMAIN shape (kind is the enum number there, not the wire name) plus extension session
// state, while per-action validity criteria stay visible under an explicit honesty label.
func TestUI2SessionRuleDomainProjectionWithholdsDomainCarriers(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	ruleID := ui2MakeAdvancedRule(t, s)
	_, _, sheet := ui2ConfirmReview(t, s, url.Values{
		"rule_op": {"toggle"}, "rule_id": {ui2RuleIDStr(ruleID)}, "target_enabled": {"false"},
	})
	for _, canary := range []string{"SECRET-COOKIE-CANARY-01", "SECRET-MATCH-CANARY-02", "SECRET-REPL-CANARY-03", "SECRET-SCRIPT-CANARY-04", "EXT-STATE-CANARY-05"} {
		if strings.Contains(sheet, canary) {
			t.Errorf("the exact-change sheet renders %s in the clear", canary)
		}
	}
	if !strings.Contains(sheet, redactedValue) {
		t.Errorf("the sheet shows no redaction marker at all: %s", sheet[:ui2MinFor(800, len(sheet))])
	}
	if !strings.Contains(sheet, "extension_session") {
		t.Errorf("the sheet hides that extension session state exists - it should show the key with a withheld value")
	}
	if !strings.Contains(sheet, "logged-out-marker") {
		t.Errorf("per-action validity criteria must stay visible (they are match criteria, not credentials)")
	}
	if !strings.Contains(sheet, "per-action validity criteria are shown as stored") {
		t.Errorf("the honesty label for visible validity criteria is missing")
	}
}
