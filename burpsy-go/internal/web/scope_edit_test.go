package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The scope rule edit (k5l): Burp's configPanelTargetScope carries "Add a new item", "Edit the
// selected item", "Remove the selected item" as first-class buttons on both the include and
// exclude tables. burpsy had add/remove/clear/toggle only — fixing a typo or narrowing a host
// meant deleting the rule and retyping every arm.

func TestTheScopeEditReplacesExactlyTheNamedTuple(t *testing.T) {
	s := newTestServer()

	// Two rules on one host differing only in path — the ordinary case the identity must respect.
	for _, body := range []string{
		`{"action":"include","pattern":"example.com","path":"/api"}`,
		`{"action":"include","pattern":"example.com"}`,
	} {
		if rec := postJSONRaw(t, s, "/api/scope", body); rec.Code != http.StatusOK {
			t.Fatalf("seed %s = %d: %s", body, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}

	// Narrow the host-wide rule: old tuple is (include, example.com, no path), replacement is
	// api.example.com. The path-scoped sibling must be untouched.
	rec := postJSONRaw(t, s, "/api/scope", `{
		"action":"edit",
		"old_pattern":"example.com","old_kind":"include",
		"pattern":"api.example.com","kind":"include"
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("edit = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	hosts := scopeHosts(t, s)
	if len(hosts) != 2 {
		t.Fatalf("two rules after the edit, got %v", hosts)
	}
	var sawNew, sawSibling bool
	for _, h := range hosts {
		if h.pattern == "api.example.com" && h.path == nil {
			sawNew = true
		}
		if h.pattern == "example.com" && h.path != nil && *h.path == "/api" {
			sawSibling = true
		}
	}
	if !sawNew || !sawSibling {
		t.Fatalf("the edit should replace only the named tuple; rules: %+v", hosts)
	}
}

// An edit that changes kind works: exclude(h) can become include(h) in place.
func TestTheScopeEditCanChangeKind(t *testing.T) {
	s := newTestServer()
	if rec := postJSONRaw(t, s, "/api/scope", `{"action":"exclude","pattern":"old.test"}`); rec.Code != http.StatusOK {
		t.Fatalf("seed = %d", rec.Code)
	}

	rec := postJSONRaw(t, s, "/api/scope", `{
		"action":"edit",
		"old_pattern":"old.test","old_kind":"exclude",
		"pattern":"new.test","kind":"include"
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("edit = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	rules := scopeRules(t, s)
	if len(rules) != 1 || rules[0].Kind != "Include" || rules[0].Host == nil || *rules[0].Host != "new.test" {
		t.Fatalf("the edit should swap kind and host in place, got %+v", rules)
	}
}

// Editing a rule that is not there is a 404 naming the miss — a silent append would leave the
// table with BOTH the unchanged original and the "edited" copy after refetch.
func TestTheScopeEditRefusesWhenNothingMatches(t *testing.T) {
	s := newTestServer()
	if rec := postJSONRaw(t, s, "/api/scope", `{"action":"include","pattern":"keepme.test"}`); rec.Code != http.StatusOK {
		t.Fatalf("seed = %d", rec.Code)
	}

	rec := postJSONRaw(t, s, "/api/scope", `{
		"action":"edit",
		"old_pattern":"ghost.test","old_kind":"include",
		"pattern":"replacement.test","kind":"include"
	}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("editing a missing rule should be 404, got %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "No matching rule") {
		t.Fatalf("the refusal should name the miss, got: %s", strings.TrimSpace(rec.Body.String()))
	}

	// The table still holds exactly the seed rule.
	if hosts := scopeHosts(t, s); len(hosts) != 1 || hosts[0].pattern != "keepme.test" {
		t.Fatalf("a refused edit must not change the table, got %+v", hosts)
	}
}

type scopeRuleRow struct {
	Kind     string  `json:"kind"`
	Host     *string `json:"host"`
	Path     *string `json:"path"`
	Protocol *string `json:"protocol"`
}

func scopeRules(t *testing.T, s *Server) []scopeRuleRow {
	t.Helper()
	rec := get(t, s, "/api/scope")
	_ = httptest.NewRecorder
	if rec.Code != http.StatusOK {
		t.Fatalf("GET scope = %d", rec.Code)
	}
	var view struct {
		Rules []scopeRuleRow `json:"rules"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&view); err != nil {
		t.Fatalf("decode scope: %v", err)
	}
	return view.Rules
}

func scopeHosts(t *testing.T, s *Server) []scopeHostRow {
	t.Helper()
	rules := scopeRules(t, s)
	out := make([]scopeHostRow, 0, len(rules))
	for _, r := range rules {
		pattern := ""
		if r.Host != nil {
			pattern = *r.Host
		}
		out = append(out, scopeHostRow{pattern: pattern, path: r.Path, protocol: r.Protocol})
	}
	return out
}

type scopeHostRow struct {
	pattern  string
	path     *string
	protocol *string
}
