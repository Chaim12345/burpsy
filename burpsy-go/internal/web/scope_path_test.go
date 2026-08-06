package web

import (
	"encoding/json"
	"net/http"
	"testing"
)

// ---- Path- and port-scoped scope rules ----------------------------------------------------------
//
// core.Scope has supported both shapes since it was written and the site map honours them, but the
// endpoint only ever built bare host rules, so neither was reachable from the UI. Burp scopes by
// full URL; without this burpsy could not express "this host, but not /admin".

type scopeRuleJSON struct {
	Kind string  `json:"kind"`
	Host *string `json:"host"`
	Path *string `json:"path,omitempty"`
	Port *uint16 `json:"port,omitempty"`
}

func getScopeRules(t *testing.T, s *Server) []scopeRuleJSON {
	t.Helper()
	rec := get(t, s, "/api/scope")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/scope: status = %d", rec.Code)
	}
	var body struct {
		Rules []scopeRuleJSON `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode scope: %v", err)
	}
	return body.Rules
}

// The shape that motivated this: authorise a host, then carve one path back out of it.
func TestAPathScopedExcludeCanBeCreatedThroughTheAPI(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "shop.test"}); rec.Code != http.StatusOK {
		t.Fatalf("include: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "exclude", "pattern": "shop.test", "path": "/admin"}); rec.Code != http.StatusOK {
		t.Fatalf("path exclude: status = %d (%s)", rec.Code, rec.Body.String())
	}

	// The engine must actually honour it, not merely store it.
	if !s.scope.Contains("shop.test", 80, "/login", false) {
		t.Error("/login should be in scope; only /admin was excluded")
	}
	if s.scope.Contains("shop.test", 80, "/admin/users", false) {
		t.Error("/admin/users should be out of scope; a path-scoped exclude covers it")
	}

	// And the UI has to be able to see what a rule covers, or it cannot show or remove it.
	rules := getScopeRules(t, s)
	var found bool
	for _, r := range rules {
		if r.Kind == "Exclude" && r.Path != nil && *r.Path == "/admin" {
			found = true
		}
	}
	if !found {
		t.Errorf("the path-scoped rule is not reported by GET /api/scope: %+v", rules)
	}
}

// Removal is the reason RemoveScoped exists. Two rules on one host differing only in path is the
// ordinary case, and matching on host alone deleted whichever came first.
func TestRemovingAHostRuleDoesNotTakeItsPathScopedSiblingWithIt(t *testing.T) {
	s := newTestServer()
	postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "shop.test"})
	postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "shop.test", "path": "/api"})

	if n := len(getScopeRules(t, s)); n != 2 {
		t.Fatalf("setup: %d rules, want 2", n)
	}

	// Remove the *path-scoped* one, naming its path. This direction is what discriminates: matching on
	// host alone walks the rule list and deletes the first rule carrying that pattern, which is the
	// host-wide rule — the opposite of what was asked. Removing the host-wide rule instead would pass
	// under both implementations purely because it happens to be first in the list, so testing only
	// that direction proves nothing.
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "remove", "pattern": "shop.test", "path": "/api"}); rec.Code != http.StatusOK {
		t.Fatalf("remove: status = %d (%s)", rec.Code, rec.Body.String())
	}

	rules := getScopeRules(t, s)
	if len(rules) != 1 {
		t.Fatalf("%d rules remain, want 1", len(rules))
	}
	if rules[0].Path != nil {
		t.Errorf("the path-scoped rule was asked for but the host-wide rule survived instead; what remains is %+v", rules[0])
	}
}

// A prefix that cannot match anything is refused rather than stored. The worst outcome for a scope
// rule is the operator believing a restriction is in force when it silently matches nothing.
func TestAScopePathThatCannotMatchIsRefused(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "shop.test", "path": "admin"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — a path prefix without a leading slash matches no request path", rec.Code)
	}
	if n := len(getScopeRules(t, s)); n != 0 {
		t.Errorf("a refused rule was stored anyway: %d rules", n)
	}
}

// Port scoping, the other shape the engine had and the API could not reach.
func TestAPortScopedRuleCanBeCreatedAndOnlyCoversThatPort(t *testing.T) {
	s := newTestServer()
	port := uint16(8443)
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "shop.test", "port": port}); rec.Code != http.StatusOK {
		t.Fatalf("include with port: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if !s.scope.Contains("shop.test", 8443, "/", true) {
		t.Error("port 8443 should be in scope")
	}
	if s.scope.Contains("shop.test", 443, "/", true) {
		t.Error("port 443 should not be in scope; the rule named 8443")
	}
}
