package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Burp's "Use custom scope" for out-of-scope request handling (burpsy-react-ui-47ed), through
// POST /api/scope action "drop_scope" and the GET that reports it.
func TestTheCustomDropScopeRoundTripsThroughTheAPI(t *testing.T) {
	s := newTestServer()
	if body := get(t, s, "/api/scope").Body.String(); !strings.Contains(body, `"drop_scope":{"mode":"suite","rules":[]}`) {
		t.Fatalf("a fresh server must report the suite scope with an empty rule array: %s", body)
	}

	s.scope.Add(core.NewScopeRule(core.ScopeInclude, "suite.test"))
	rec := postJSON(t, s, "/api/scope", map[string]any{"action": "drop_scope", "mode": "custom",
		"drop_rules": []map[string]any{{"action": "include", "pattern": "custom.test"}}})
	if rec.Code != http.StatusOK {
		t.Fatalf("set custom: %d %s", rec.Code, rec.Body.String())
	}
	if body := get(t, s, "/api/scope").Body.String(); !strings.Contains(body,
		`"drop_scope":{"mode":"custom","rules":[{"kind":"Include","host":"custom.test","enabled":true}]}`) {
		t.Errorf("GET does not report the custom drop scope: %s", body)
	}

	// The engine the proxy asks: with the switch on, the custom scope alone decides.
	postJSON(t, s, "/api/scope", map[string]any{"action": "drop_out_of_scope", "enabled": true})
	if s.scope.AuthoriseRequest("suite.test", 80, "/", false) || !s.scope.AuthoriseRequest("custom.test", 80, "/", false) {
		t.Error("the drop gate did not follow the custom scope")
	}
	// A composed request must be in suite scope and in the custom scope.
	if err := s.scope.AuthoriseRaw("suite.test", 80, false, []byte("GET / HTTP/1.1\r\n\r\n")); err == nil ||
		!strings.Contains(err.Error(), "custom scope") {
		t.Errorf("AuthoriseRaw for a host outside the custom drop scope = %v, want a refusal naming it", err)
	}

	for _, body := range []map[string]any{
		{"action": "drop_scope", "mode": "custom", "drop_rules": []map[string]any{{"action": "exclude", "pattern": "x.test"}}},
		{"action": "drop_scope", "mode": "sometimes"},
		{"action": "drop_scope", "mode": "custom", "drop_rules": []map[string]any{{"action": "allow", "pattern": "x.test"}}},
	} {
		if rec := postJSON(t, s, "/api/scope", body); rec.Code != http.StatusBadRequest {
			t.Errorf("POST %v = %d, want 400", body, rec.Code)
		}
	}
	if _, use := s.scope.DropScope(); !use {
		t.Error("a refused drop_scope change took the custom scope out of force")
	}

	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "drop_scope", "mode": "suite"}); rec.Code != http.StatusOK {
		t.Fatalf("back to suite: %d %s", rec.Code, rec.Body.String())
	}
	if _, use := s.scope.DropScope(); use || !s.scope.AuthoriseRequest("suite.test", 80, "/", false) {
		t.Error("choosing the suite scope did not put the drop gate back on the suite scope")
	}
	// Burp keeps the custom rules while the suite scope is chosen, and choosing custom again with no
	// rules puts them back in force.
	if body := get(t, s, "/api/scope").Body.String(); !strings.Contains(body,
		`"drop_scope":{"mode":"suite","rules":[{"kind":"Include","host":"custom.test","enabled":true}]}`) {
		t.Errorf("the custom rules were not kept under the suite scope: %s", body)
	}
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "drop_scope", "mode": "custom"}); rec.Code != http.StatusOK {
		t.Fatalf("custom again: %d %s", rec.Code, rec.Body.String())
	}
	if s.scope.AuthoriseRequest("suite.test", 80, "/", false) || !s.scope.AuthoriseRequest("custom.test", 80, "/", false) {
		t.Error("choosing custom again did not put the kept rules back in force")
	}
}

// Choosing "custom" before any custom rule exists is refused: there is nothing to put in force.
func TestCustomDropScopeWithNoRulesYetIsRefused(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "drop_scope", "mode": "custom"}); rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", rec.Code)
	}
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "drop_scope", "mode": "custom", "drop_rules": []any{}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an explicit empty rule list: status %d, want 400", rec.Code)
	}
}
