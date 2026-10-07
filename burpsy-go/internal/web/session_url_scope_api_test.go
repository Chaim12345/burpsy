package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/session"
)

// The URL-scope editor's wire contract (burpsy-react-ui-7nh2). The rule editor offers Burp's three
// radio settings — Include all URLs / Use suite scope / Use custom scope — and the custom arms
// (path prefix, port, scheme) beside the host list.
//
// The test that earns its place here is the round trip, because every other failure in this area is
// loud. A scope that will not save is a 400 the operator reads; a scope that saves and comes back
// blank is silent, and the form then shows the operator a rule their rule no longer is. The second
// save from that form writes the blanks over the stored arms, so the loss is not even undone by
// reloading without touching it.

// scopeDTO is the shape the editor sends and reads for one rule's scope block.
type scopeDTO struct {
	AllowAll bool   `json:"allow_all"`
	Mode     string `json:"mode"`
	Path     string `json:"path"`
	Port     *int   `json:"port"`
	Protocol string `json:"protocol"`
	Rules    []struct {
		Kind string  `json:"kind"`
		Host *string `json:"host"`
	} `json:"rules"`
}

// saveRule posts one rule definition and returns the id it was given.
func saveRule(t *testing.T, srv *Server, body map[string]any) int64 {
	t.Helper()
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	if code := postJSONInto(t, srv, "/api/session/rules", body, &created); code != http.StatusOK {
		t.Fatalf("POST /api/session/rules = %d, want 200", code)
	}
	if created.Rule.ID == nil {
		t.Fatal("the created rule came back with no id")
	}
	return *created.Rule.ID
}

// readRule finds one rule in the list the editor loads and decodes its scope block. The list is
// the route the UI actually reads — /api/session/rules/{id} is PUT-only — so this asserts the
// round trip through the same wire the editor sees rather than through a test-only shape.
func readRule(t *testing.T, srv *Server, id int64) (wireSessionRule, scopeDTO) {
	t.Helper()
	rec := get(t, srv, "/api/session/rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/session/rules = %d, want 200", rec.Code)
	}
	var listed wireSessionRulesResp
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode rules list: %v", err)
	}
	for _, r := range listed.Rules {
		if r.ID == nil || *r.ID != id {
			continue
		}
		var scope scopeDTO
		if len(r.Scope) > 0 {
			if err := json.Unmarshal(r.Scope, &scope); err != nil {
				t.Fatalf("decode rule %d scope %s: %v", id, r.Scope, err)
			}
		}
		return r, scope
	}
	t.Fatalf("rule %d is missing from GET /api/session/rules", id)
	return wireSessionRule{}, scopeDTO{}
}

// A custom scope with every arm stated comes back with every arm still stated. Without this the
// editor reopens on "Include all URLs" and the next save drops the arms.
func TestACustomURLScopeSurvivesTheWireRoundTrip(t *testing.T) {
	srv := sessionTestServer()
	port := 8443
	id := saveRule(t, srv, map[string]any{
		"name":    "api login",
		"enabled": true,
		"scope": map[string]any{
			"allow_all": false,
			"mode":      "custom",
			"path":      "/api",
			"port":      port,
			"protocol":  "https",
			"rules":     []any{map[string]any{"kind": "Include", "host": "app.test"}},
		},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://app.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})

	_, scope := readRule(t, srv, id)
	if scope.Mode != "custom" {
		t.Fatalf("scope.mode came back %q, want \"custom\"; the editor would reopen on Include all URLs", scope.Mode)
	}
	if scope.Path != "/api" {
		t.Errorf("scope.path came back %q, want \"/api\"", scope.Path)
	}
	if scope.Port == nil || *scope.Port != port {
		t.Errorf("scope.port came back %v, want %d", scope.Port, port)
	}
	if scope.Protocol != "https" {
		t.Errorf("scope.protocol came back %q, want \"https\"", scope.Protocol)
	}
	if scope.AllowAll {
		t.Error("allow_all came back true for a custom scope; the arms would be ignored on the next load")
	}
	if len(scope.Rules) != 1 || scope.Rules[0].Host == nil || *scope.Rules[0].Host != "app.test" {
		t.Errorf("scope.rules came back %+v, want the one Include host app.test", scope.Rules)
	}

	// The round trip that loses data: edit-and-save what was just read back. The second save must be
	// byte-for-byte the same rule, or the form is quietly rewriting the scope it is showing.
	if code := putJSONInto(t, srv, fmt.Sprintf("/api/session/rules/%d", id), map[string]any{
		"name":     "api login",
		"enabled":  true,
		"scope":    json.RawMessage(mustScopeJSON(t, scope)),
		"steps":    []any{map[string]any{"method": "POST", "url": "https://app.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	}, nil); code != http.StatusOK {
		t.Fatalf("PUT rules with the scope just read back = %d, want 200", code)
	}
	_, again := readRule(t, srv, id)
	if again.Mode != "custom" || again.Path != "/api" || again.Port == nil || *again.Port != port || again.Protocol != "https" {
		t.Fatalf("the arms were lost by a save of the very scope that was read back: got %+v", again)
	}
}

// A suite-scoped rule round-trips as suite mode. It carries no hosts of its own, so the flag must
// follow the mode rather than the (empty) host list — reading allow_all:false here would send the
// editor into custom mode with nothing in it.
func TestASuiteScopedRuleSurvivesTheWireRoundTrip(t *testing.T) {
	srv := sessionTestServer()
	id := saveRule(t, srv, map[string]any{
		"name":    "suite login",
		"enabled": true,
		"scope": map[string]any{
			"allow_all": true,
			"mode":      "suite",
			"rules":     []any{},
		},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://app.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})

	_, scope := readRule(t, srv, id)
	if scope.Mode != "suite" {
		t.Fatalf("scope.mode came back %q, want \"suite\"", scope.Mode)
	}
	if !scope.AllowAll {
		t.Error("allow_all came back false for a suite-scoped rule; the editor would reopen it as an empty custom scope")
	}
}

// Burp's arms are independent, so a custom scope stating only a path is a real rule and must save.
// It used to be refused as a scope "with no hosts", which is a refusal about a different axis.
func TestACustomScopeStatingOnlyAPathIsAccepted(t *testing.T) {
	srv := sessionTestServer()
	id := saveRule(t, srv, map[string]any{
		"name":    "path only",
		"enabled": true,
		"scope": map[string]any{
			"allow_all": false,
			"mode":      "custom",
			"path":      "/api",
			"rules":     []any{},
		},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://app.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})

	rule := srv.sessionCoordinator.Rule(session.RuleID(id))
	if rule == nil {
		t.Fatal("the path-only rule was not installed")
	}
	if !rule.MatchCustomArms(session.RequestIdentity{Host: "app.test", Path: "/api/x"}) {
		t.Error("the saved rule does not cover a request under its own path arm")
	}
	if rule.MatchCustomArms(session.RequestIdentity{Host: "app.test", Path: "/other"}) {
		t.Error("the saved rule covers a request outside its path arm")
	}
}

// The refusal the scope validator has always raised still stands: a scope that was *stated* and
// states nothing in any axis can only be read as "restrict this rule to nothing". Widening the
// refusal for the arms must not have removed it.
func TestAStatedScopeWithNoArmsAtAllIsStillRefused(t *testing.T) {
	srv := sessionTestServer()
	rec := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":    "custom but empty",
		"enabled": true,
		"scope": map[string]any{
			"allow_all": false,
			"mode":      "custom",
			"rules":     []any{},
		},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://app.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with a stated scope that states nothing = %d, want 400", rec.Code)
	}
}

// The login probe is matched on the probe's full URL, not its host — the same identity the rule
// editor scopes by. A rule scoped to /api must not answer for a probe to /logout, because that
// answer is what decides whether the operator's credentials get replayed.
func TestTheLoginProbeIdentityCarriesThePathTheRuleScopesBy(t *testing.T) {
	srv := sessionTestServer()
	id := saveRule(t, srv, map[string]any{
		"name":    "api login",
		"enabled": true,
		"scope": map[string]any{
			"allow_all": false,
			"mode":      "custom",
			"path":      "/api",
			"rules":     []any{map[string]any{"kind": "Include", "host": "app.test"}},
		},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://app.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})

	rule := srv.sessionCoordinator.Rule(session.RuleID(id))
	if got := srv.sessionCoordinator.MatchingRuleForRequest(
		session.RequestIdentity{Host: "app.test", Path: "/api/orders", Port: 443, TLS: true}, nil, nil); got != rule {
		t.Fatalf("an /api request matched %v, want the path-scoped rule", got)
	}
	if got := srv.sessionCoordinator.MatchingRuleForRequest(
		session.RequestIdentity{Host: "app.test", Path: "/logout", Port: 443, TLS: true}, nil, nil); got != nil {
		t.Fatalf("a /logout request matched %v; the rule's own editor excludes it", got)
	}
}

// The console installs its Target scope as the coordinator's suite verdict, so a suite-scoped rule
// is reachable from the in-package match sites too. With the scope narrowed to one host, a
// suite-mode rule must answer for that host and for no other.
func TestTheConsoleInstallsItsTargetScopeAsTheSuiteVerdict(t *testing.T) {
	// Include app.test only, so "the Target scope includes it" is a real verdict rather than the
	// default-allow an empty scope gives.
	scope := core.NewScope()
	scope.AddInclude("app.test")
	srv := NewServer(core.NewTrafficStore(), scope)
	id := saveRule(t, srv, map[string]any{
		"name":    "suite login",
		"enabled": true,
		"scope":   map[string]any{"allow_all": true, "mode": "suite", "rules": []any{}},
		"steps":   []any{map[string]any{"method": "POST", "url": "https://app.test/login", "headers": []any{}, "body": ""}},
	})

	rule := srv.sessionCoordinator.Rule(session.RuleID(id))
	if got := srv.sessionCoordinator.MatchingRuleForRequest(
		session.RequestIdentity{Host: "app.test", Path: "/account", Port: 443, TLS: true}, nil, nil); got != rule {
		t.Fatalf("a suite-scoped rule did not match a host the Target scope includes: got %v", got)
	}
	if got := srv.sessionCoordinator.MatchingRuleForRequest(
		session.RequestIdentity{Host: "elsewhere.test", Path: "/account", Port: 443, TLS: true}, nil, nil); got != nil {
		t.Fatalf("a suite-scoped rule matched a host the Target scope excludes: got %v", got)
	}
}

func mustScopeJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}
