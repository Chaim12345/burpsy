package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- The site map says what is in scope ---------------------------------------------------------
//
// The map records every host the proxy saw, including third parties nobody authorised. A map that
// draws an unauthorised host identically to an authorised one invites an operator to right-click it
// and attack it, so every node carries the scope decision and the UI dims the ones that are out.
//
// Host and path nodes answer the question differently on purpose, and these pin that difference: a
// host asks "is any path here worth considering" (MayContainHost), a path asks the real per-request
// question (Contains). Getting that backwards greys out a whole host because one of its paths is
// excluded — the bug these tests exist to prevent.

type scopeNodeResp struct {
	Segment  string          `json:"segment"`
	Path     string          `json:"path"`
	InScope  bool            `json:"in_scope"`
	Children []scopeNodeResp `json:"children"`
}

type scopeTreeResp struct {
	Tree []scopeNodeResp `json:"tree"`
}

func scopeSitemapGet(t *testing.T, s *Server) scopeTreeResp {
	t.Helper()
	rec := get(t, s, "/api/sitemap")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/sitemap: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var v scopeTreeResp
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode sitemap response %q: %v", rec.Body.String(), err)
	}
	return v
}

func findScopeNode(nodes []scopeNodeResp, path string) *scopeNodeResp {
	for i := range nodes {
		if nodes[i].Path == path {
			return &nodes[i]
		}
		if found := findScopeNode(nodes[i].Children, path); found != nil {
			return found
		}
	}
	return nil
}

// With an include rule naming one host, traffic to any other host is captured and shown, but marked
// out of scope. Both facts matter: the row still exists (it is evidence), and it is not a target.
func TestAHostOutsideTheIncludeRulesIsShownButMarkedOutOfScope(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("shop.test")
	addTraffic(t, s.store, "shop.test", "GET", "/login")
	addTraffic(t, s.store, "cdn.other.test", "GET", "/analytics.js")

	v := scopeSitemapGet(t, s)

	shop := findScopeNode(v.Tree, "shop.test")
	if shop == nil {
		t.Fatal("no shop.test host node")
	}
	if !shop.InScope {
		t.Error("shop.test in_scope = false, want true — it is the included host")
	}

	cdn := findScopeNode(v.Tree, "cdn.other.test")
	if cdn == nil {
		t.Fatal("cdn.other.test is missing from the map entirely; out-of-scope traffic is still evidence and must be shown, only dimmed")
	}
	if cdn.InScope {
		t.Error("cdn.other.test in_scope = true, want false — nothing includes it")
	}
}

// An exclude scoped to a path takes that path out of scope without taking the host with it. This is
// why a host node asks MayContainHost rather than Contains on "/": asking about one arbitrary path
// cannot answer a question about the whole host.
func TestAPathScopedExcludeDimsOnlyThatPathNotTheWholeHost(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("shop.test")
	s.scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "shop.test", "/admin"))
	addTraffic(t, s.store, "shop.test", "GET", "/login")
	addTraffic(t, s.store, "shop.test", "GET", "/admin/users")

	v := scopeSitemapGet(t, s)

	host := findScopeNode(v.Tree, "shop.test")
	if host == nil {
		t.Fatal("no shop.test host node")
	}
	if !host.InScope {
		t.Error("shop.test in_scope = false, want true — one excluded path must not grey out the host whose other paths are authorised")
	}

	login := findScopeNode(v.Tree, "/login")
	if login == nil {
		t.Fatal("no /login node")
	}
	if !login.InScope {
		t.Error("/login in_scope = false, want true — it is not excluded")
	}

	admin := findScopeNode(v.Tree, "/admin")
	if admin == nil {
		t.Fatal("no /admin node")
	}
	if admin.InScope {
		t.Error("/admin in_scope = true, want false — a path-scoped exclude covers it")
	}
}

// An empty scope is default-allow, matching Scope.Contains. Every node reads in scope, so a fresh
// session does not open with the entire map greyed out.
func TestAnEmptyScopeLeavesEveryNodeInScope(t *testing.T) {
	s := newTestServer()
	addTraffic(t, s.store, "shop.test", "GET", "/login")

	v := scopeSitemapGet(t, s)

	host := findScopeNode(v.Tree, "shop.test")
	if host == nil || !host.InScope {
		t.Error("with no scope rules the host must read in scope; an empty scope contains everything")
	}
	login := findScopeNode(v.Tree, "/login")
	if login == nil || !login.InScope {
		t.Error("with no scope rules every path must read in scope")
	}
}
