package web

import (
	"strings"
	"testing"
)

// Burp's custom-parameter fields on an extraction (burpsy-react-ui-355h) round-trip through the
// session-rules route.
func TestExtractionCustomParameterFieldsRoundTrip(t *testing.T) {
	s := newTestServer()
	rule := map[string]any{
		"name": "custom", "enabled": true, "validity": nil,
		"steps": []any{map[string]any{"method": "GET", "url": "https://app.test/login", "headers": []any{}, "body": "",
			"extract": []any{map[string]any{"name": "csrf", "how": map[string]any{"regex": map[string]any{"pattern": `v="([^"]*)"`, "group": 1}},
				"prefix": "tok-", "suffix": ";v=1", "url_encoded": false}}}},
	}
	if rec := postJSON(t, s, "/api/session/rules", rule); rec.Code/100 != 2 {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body.String())
	}
	body := get(t, s, "/api/session/rules").Body.String()
	for _, want := range []string{`"prefix":"tok-"`, `"suffix":";v=1"`, `"url_encoded":false`} {
		if !strings.Contains(body, want) {
			t.Errorf("GET lacks %s: %s", want, body)
		}
	}
}
