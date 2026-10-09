package web

import (
	"net/http"
	"strings"
	"testing"
)

// burpsy-react-ui-8gk8 at the API: a run-macro action's update choices round-trip through the
// session-rules route under Burp's key names, an absent update_with_cookies stays absent (the whole
// jar), and a malformed choice is refused when the rule is posted.
func TestRunMacroUpdateChoicesRoundTripThroughTheSessionRulesAPI(t *testing.T) {
	s := newTestServer()
	rule := map[string]any{
		"name": "csrf", "enabled": true,
		"steps":    []any{map[string]any{"method": "GET", "url": "https://app.test/login", "headers": []any{}, "body": ""}},
		"validity": nil,
		"actions": []map[string]any{
			{"kind": "run_macro", "enabled": true, "update_with_params": true, "match_params": "specified_params",
				"params": []string{"csrf"}, "tolerate_url_mismatch": true, "update_with_cookies": false},
			{"kind": "run_macro", "enabled": true},
		},
	}
	if rec := postJSON(t, s, "/api/session/rules", rule); rec.Code/100 != 2 {
		t.Fatalf("POST rule = %d: %s", rec.Code, rec.Body.String())
	}
	body := get(t, s, "/api/session/rules").Body.String()
	for _, want := range []string{`"update_with_params":true`, `"match_params":"specified_params"`, `"params":["csrf"]`,
		`"tolerate_url_mismatch":true`, `"update_with_cookies":false`} {
		if !strings.Contains(body, want) {
			t.Errorf("GET lacks %s: %s", want, body)
		}
	}
	if strings.Count(body, `"update_with_cookies"`) != 1 {
		t.Errorf("the second action states no cookie choice and must read back without one: %s", body)
	}

	rule["name"] = "broken"
	rule["actions"] = []map[string]any{{"kind": "run_macro", "enabled": true, "match_cookies": "every"}}
	if rec := postJSON(t, s, "/api/session/rules", rule); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "match_cookies") {
		t.Errorf("a malformed match_cookies = %d %q, want 400 naming it", rec.Code, rec.Body.String())
	}
}
