package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/burpsy-go/burpsy/internal/intercept"
)

type ruleListView struct {
	Wired  bool `json:"wired"`
	Active bool `json:"active"`
	Rules  []struct {
		Field    string `json:"field"`
		Category string `json:"category"`
		Match    string `json:"string_match"`
		Enabled  bool   `json:"enabled"`
		Comment  string `json:"comment"`
		Action   string `json:"action"`
	} `json:"rules"`
}

// A pass rule survives the PUT/GET round trip, and an unknown action is refused at save time.
func TestInterceptRuleActionRoundTrip(t *testing.T) {
	s := newTestServer()
	body := map[string]any{
		"active": true,
		"rules": []map[string]any{
			{"field": "host", "category": "literal", "string_match": "noisy.test", "enabled": true, "comment": "t", "action": "pass"},
			{"field": "host", "category": "literal", "string_match": "api.test", "enabled": true, "comment": "", "action": "hold"},
		},
	}
	if rec := putJSON(t, s, "/api/intercept/rules/requests", body); rec.Code != http.StatusOK {
		t.Fatalf("PUT rules: status = %d (%s)", rec.Code, rec.Body.String())
	}
	rec := get(t, s, "/api/intercept/rules/requests")
	var got ruleListView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	if len(got.Rules) != 2 || got.Rules[0].Action != "pass" || got.Rules[1].Action != "hold" {
		t.Errorf("round trip actions = %v, want [pass hold]", got.Rules)
	}

	bad := map[string]any{
		"active": true,
		"rules": []map[string]any{
			{"field": "host", "category": "literal", "string_match": "x", "enabled": true, "action": "maybe"},
		},
	}
	if rec := putJSON(t, s, "/api/intercept/rules/requests", bad); rec.Code != http.StatusBadRequest {
		t.Errorf("PUT unknown action: status = %d, want 400", rec.Code)
	}
}

// Forwarding with hold_response arms the engine from the held request's own attributes:
// the next matching response is held even with the response list off.
func TestForwardHoldResponseArmsFromTheHeldRequest(t *testing.T) {
	s := newTestServer()
	s.intercept.SetEnabled(true)
	if err := s.intercept.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	h := s.intercept.Hold(&intercept.Message{
		Direction: intercept.DirectionRequest, Host: "shop.test", Port: 80,
		Method: "GET", Path: "/cart", Raw: []byte("GET /cart HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
	})
	if h == nil {
		t.Fatalf("request not held: enable the engine or drop the unconditional assumption")
	}
	if rec := postJSON(t, s, "/api/intercept/"+strconv.FormatUint(h.ID, 10)+"/forward", map[string]any{"hold_response": true}); rec.Code != http.StatusOK {
		t.Fatalf("forward with hold_response: status = %d (%s)", rec.Code, rec.Body.String())
	}
	resp := &intercept.Message{
		Direction: intercept.DirectionResponse, Host: "shop.test", Port: 80,
		Method: "GET", Path: "/cart", Raw: []byte("HTTP/1.1 200 OK\r\n\r\n"),
	}
	if held := s.intercept.Hold(resp); held == nil {
		t.Errorf("armed response passed with the response list off")
	}
}

// hold_response on a missing id 404s without forwarding anything.
func TestForwardHoldResponseOnMissingIdIs404(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/intercept/999/forward", map[string]any{"hold_response": true}); rec.Code != http.StatusNotFound {
		t.Errorf("forward hold_response on missing id: status = %d, want 404", rec.Code)
	}
}
