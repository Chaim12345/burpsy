package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// burpsy-react-ui-ydmj at the API: a run_script action round-trips through the session-rules route with
// its script intact, the palette offers the kind, and a script that does not compile is refused when
// the rule is posted rather than failing every request the rule covers.
func TestARunScriptActionRoundTripsThroughTheSessionRulesAPI(t *testing.T) {
	s := newTestServer()
	script := `request.headers["X-Sig"] = burpsy.sha256Hex(request.url);`
	rule := map[string]any{
		"name": "sign", "enabled": true,
		"steps": []any{}, "validity": nil,
		"actions": []map[string]any{{"kind": "run_script", "enabled": true, "script": script}},
	}
	if rec := postJSON(t, s, "/api/session/rules", rule); rec.Code/100 != 2 {
		t.Fatalf("POST rule = %d: %s", rec.Code, rec.Body.String())
	}

	rec := get(t, s, "/api/session/rules")
	var resp struct {
		Rules []struct {
			Actions []struct {
				Kind   string `json:"kind"`
				Script string `json:"script"`
			} `json:"actions"`
		} `json:"rules"`
		ActionKinds []struct {
			Kind string `json:"kind"`
		} `json:"action_kinds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rules) != 1 || len(resp.Rules[0].Actions) != 1 || resp.Rules[0].Actions[0].Script != script {
		t.Fatalf("the script did not round-trip: %s", rec.Body.String())
	}
	offered := false
	for _, k := range resp.ActionKinds {
		offered = offered || k.Kind == "run_script"
	}
	if !offered {
		t.Error("the action palette does not offer run_script, so the editor cannot create one")
	}

	rule["name"] = "broken"
	rule["actions"] = []map[string]any{{"kind": "run_script", "enabled": true, "script": "request.headers[ ="}}
	if rec := postJSON(t, s, "/api/session/rules", rule); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "compile") {
		t.Errorf("a script that does not compile = %d %q, want 400 saying so", rec.Code, rec.Body.String())
	}
}
