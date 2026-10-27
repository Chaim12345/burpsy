package web

import (
	"net/http"
	"testing"
)

// Posting a rule identical to one already in scope succeeds and leaves one rule: two copies decide
// nothing more, and gave the Scope page two rows with one identity (burpsy-react-ui-scope-duplicate-rules).
// A rule differing in any arm (here the path) is still added.
func TestPostingAnIdenticalScopeRuleTwiceKeepsOne(t *testing.T) {
	s := newTestServer()
	for i := 0; i < 2; i++ {
		if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "127.0.0.1"}); rec.Code != http.StatusOK {
			t.Fatalf("POST %d = %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	if n := len(s.scope.Rules()); n != 1 {
		t.Fatalf("two identical includes left %d rules, want 1", n)
	}
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "127.0.0.1", "path": "/admin"}); rec.Code != http.StatusOK {
		t.Fatalf("POST with a path = %d: %s", rec.Code, rec.Body.String())
	}
	if n := len(s.scope.Rules()); n != 2 {
		t.Errorf("a rule differing by path was not added: %d rules, want 2", n)
	}
}
