package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- Import/export of the operator's configuration surfaces -------------------------------------
//
// Burp treats match/replace rules, scope and session handling rules as portable state: an operator
// moves them between engagements as a file. burpsy had no such surface — every rule lived in the
// running process and died with it. These tests pin the round trip through one bundle:
// export carries every surface, import applies the whole bundle to a clean server, and an invalid
// bundle is refused without applying any part of it (a half-imported configuration is worse than
// none, because the operator cannot tell which rules are theirs).

// putJSON performs a PUT like postJSON does a POST.
func putJSON(t *testing.T, s *Server, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func postJSONRaw(t *testing.T, s *Server, path string, rawBody string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(rawBody))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// seedEverySurface fills all three configurable surfaces on s and asserts each took.
func seedEverySurface(t *testing.T, s *Server) {
	t.Helper()
	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": "api.example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("seed scope rule: status = %d, body %s", rec.Code, rec.Body.String())
	}
	put := putJSON(t, s, "/api/intercept/rules/requests", map[string]any{
		"active": true,
		"rules":  []map[string]any{{"field": "path", "category": "literal", "string_match": "/noise/", "enabled": true, "comment": ""}},
	})
	if put.Code != http.StatusOK {
		t.Fatalf("seed intercept rule: status = %d, body %s", put.Code, put.Body.String())
	}
	session := postJSON(t, s, "/api/session/rules", map[string]any{
		"name":     "global login",
		"enabled":  true,
		"scope":    map[string]any{"allow_all": true, "rules": []any{}},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})
	if session.Code != http.StatusOK {
		t.Fatalf("seed session rule: status = %d, body %s", session.Code, session.Body.String())
	}
}

type exportedBundle struct {
	Version int `json:"version"`
	Scope   struct {
		Rules []scopeRuleView `json:"rules"`
	} `json:"scope"`
	Intercept map[string]struct {
		Active bool                `json:"active"`
		Rules  []interceptRuleSpec `json:"rules"`
	} `json:"intercept"`
	SessionRules []sessionRuleDto `json:"session_rules"`
}

func TestExportCarriesScopeInterceptAndSessionRules(t *testing.T) {
	s := newTestServer()
	seedEverySurface(t, s)

	rec := get(t, s, "/api/config/export")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/export = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var bundle exportedBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode export: %v; body %s", err, rec.Body.String())
	}

	if len(bundle.Scope.Rules) != 1 || bundle.Scope.Rules[0].Host == nil || *bundle.Scope.Rules[0].Host != "api.example.com" {
		t.Fatalf("export scope = %+v; want exactly the seeded api.example.com rule — an operator who exports and finds nothing has lost their engagement setup", bundle.Scope.Rules)
	}
	reqs, ok := bundle.Intercept["requests"]
	if !ok || len(reqs.Rules) != 1 || reqs.Rules[0].Match != "/noise/" {
		t.Fatalf("export intercept.requests = %+v; want the seeded /noise/ rule", reqs)
	}
	if len(bundle.SessionRules) != 1 || bundle.SessionRules[0].Name != "global login" {
		t.Fatalf("export session rules = %+v; want the seeded global-login rule", bundle.SessionRules)
	}
}

func TestImportAppliesTheWholeBundleToACleanServer(t *testing.T) {
	clean := newTestServer()
	donor := newTestServer()
	seedEverySurface(t, donor)

	exported := get(t, donor, "/api/config/export")
	if exported.Code != http.StatusOK {
		t.Fatalf("donor export = %d", exported.Code)
	}

	rec := postJSONRaw(t, clean, "/api/config/import", exported.Body.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/config/import = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	var scope struct {
		Rules []scopeRuleView `json:"rules"`
	}
	if err := json.Unmarshal(get(t, clean, "/api/scope").Body.Bytes(), &scope); err != nil {
		t.Fatalf("decode imported scope: %v", err)
	}
	if len(scope.Rules) != 1 || scope.Rules[0].Host == nil || *scope.Rules[0].Host != "api.example.com" {
		t.Fatalf("imported scope = %+v; want api.example.com — import that drops scope silently strands every later send", scope.Rules)
	}

	var intercept struct {
		Rules []interceptRuleSpec `json:"rules"`
	}
	if err := json.Unmarshal(get(t, clean, "/api/intercept/rules/requests").Body.Bytes(), &intercept); err != nil {
		t.Fatalf("decode imported intercept rules: %v", err)
	}
	if len(intercept.Rules) != 1 || intercept.Rules[0].Match != "/noise/" {
		t.Fatalf("imported intercept requests = %+v; want the /noise/ rule", intercept.Rules)
	}

	var session sessionRulesResp
	if err := json.Unmarshal(get(t, clean, "/api/session/rules").Body.Bytes(), &session); err != nil {
		t.Fatalf("decode imported session rules: %v", err)
	}
	if len(session.Rules) != 1 || session.Rules[0].Name != "global login" {
		t.Fatalf("imported session rules = %+v; want global login", session.Rules)
	}
}

func TestImportRefusesABundleWithAnInvalidRuleAndAppliesNothing(t *testing.T) {
	clean := newTestServer()
	bundle := `{
	  "version": 1,
	  "scope": {"rules": [{"kind": "Include", "host": "half-applied.test"}]},
	  "intercept": {},
	  "session_rules": [{"name": "", "enabled": true, "steps": [], "validity": null}]
	}`
	rec := postJSONRaw(t, clean, "/api/config/import", bundle)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import with an unnamed session rule = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	var scope struct {
		Rules []scopeRuleView `json:"rules"`
		Empty bool            `json:"empty"`
	}
	if err := json.Unmarshal(get(t, clean, "/api/scope").Body.Bytes(), &scope); err != nil {
		t.Fatalf("decode scope after refused import: %v", err)
	}
	if !scope.Empty || len(scope.Rules) != 0 {
		t.Fatalf("scope after a refused import = %+v; a partial import would leave the operator unable to tell which rules are really configured", scope.Rules)
	}
}
