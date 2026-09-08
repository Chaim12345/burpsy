package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// POST /api/session/rules/{id}/move is the write path for rule precedence: MatchingRule runs the
// first enabled rule whose scope covers a host, walking the coordinator's order slice, so the move
// endpoint — not PUT, which deliberately keeps a rule's position — is what changes which login wins
// for a host two rules cover. These tests pin the wire contract: 200 with the new position, 404 for
// an unknown id, 400 for a move past either edge, and a persisted order that survives a restart.

func TestSessionRuleMoveSwapsTwoRulesAndTheMatcherFollowsTheNewOrder(t *testing.T) {
	srv := sessionTestServer()
	create := func(name string) wireSessionRule {
		var created struct {
			Rule wireSessionRule `json:"rule"`
		}
		code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
			"name":    name,
			"enabled": true,
			// allow_all so both rules cover every host and the matcher's answer is decided purely
			// by position — the property the move exists to change.
			"scope":    map[string]any{"allow_all": true, "rules": []any{}},
			"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
			"validity": map[string]any{"status_is": 200},
		}, &created)
		if code != http.StatusOK {
			t.Fatalf("POST rule %q = %d, want 200", name, code)
		}
		return created.Rule
	}
	first := create("first login")
	second := create("second login")
	_ = first // the move names only the second rule; the first exists so two rules are in the order

	if got := srv.sessionCoordinator.MatchingRule("target.test"); got == nil || got.Name != "first login" {
		t.Fatalf("MatchingRule picked %v before the move; the first-created rule must win", got)
	}

	var moved struct {
		Position int `json:"position"`
	}
	code := postJSONInto(t, srv, "/api/session/rules/"+itoa(uint64(*second.ID))+"/move", map[string]any{"offset": -1}, &moved)
	if code != http.StatusOK {
		t.Fatalf("POST move = %d, want 200", code)
	}
	if moved.Position != 0 {
		t.Fatalf("move answered position %d, want 0", moved.Position)
	}
	if got := srv.sessionCoordinator.MatchingRule("target.test"); got == nil || got.Name != "second login" {
		t.Fatalf("MatchingRule picked %v after the move; the moved rule must now own the host", got)
	}
}

func TestSessionRuleMoveOnAnUnknownRuleIs404(t *testing.T) {
	srv := sessionTestServer()
	rec := postJSON(t, srv, "/api/session/rules/4242/move", map[string]any{"offset": -1})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST move on an unknown rule = %d, want 404", rec.Code)
	}
}

func TestSessionRuleMovePastTheTopIs400NamingTheEdge(t *testing.T) {
	srv := sessionTestServer()
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":     "only rule",
		"enabled":  true,
		"scope":    map[string]any{"allow_all": true, "rules": []any{}},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	}, &created)

	rec := postJSON(t, srv, "/api/session/rules/"+itoa(uint64(*created.Rule.ID))+"/move", map[string]any{"offset": -1})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST move past the top = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "edge") {
		t.Fatalf("move past the top said %q; the operator must be told the move hit an edge, not just 'bad request'", rec.Body.String())
	}
}

func TestSessionRuleMoveRejectsOtherMethods(t *testing.T) {
	srv := sessionTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/session/rules/1/move", nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on /move = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodPost {
		t.Fatalf("Allow header = %q, want POST", allow)
	}
}

func TestSessionRuleMoveOrderSurvivesAPersistRoundTrip(t *testing.T) {
	srv := sessionTestServer()
	create := func(name string) wireSessionRule {
		var created struct {
			Rule wireSessionRule `json:"rule"`
		}
		postJSONInto(t, srv, "/api/session/rules", map[string]any{
			"name":     name,
			"enabled":  true,
			"scope":    map[string]any{"allow_all": true, "rules": []any{}},
			"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
			"validity": map[string]any{"status_is": 200},
		}, &created)
		return created.Rule
	}
	create("first login")
	second := create("second login")
	postJSONInto(t, srv, "/api/session/rules/"+itoa(uint64(*second.ID))+"/move", map[string]any{"offset": -1}, &struct{}{})

	// AllRules is what SaveSessionRules persists (persistSessionRules), and a load path calls
	// RestoreRule in the saved order — so this slice IS the persisted order.
	all := srv.sessionCoordinator.AllRules()
	if len(all) != 2 {
		t.Fatalf("%d rules after the move, want 2", len(all))
	}
	if all[0].Name != "second login" {
		t.Fatalf("persisted order starts with %q; the moved rule must be first so a restart restores it at the same precedence", all[0].Name)
	}
	if t.Failed() {
		b, _ := json.Marshal(all)
		t.Fatalf("full order: %s", b)
	}
}
