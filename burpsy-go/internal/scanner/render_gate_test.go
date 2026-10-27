package scanner

import (
	"net/url"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// burpsy-react-ui-browser-render-unscoped: the gate a scanner render runs under authorises each
// subrequest against the engagement scope, not only the page it was pointed at.
func TestRenderScopeGateAuthorisesSubrequestsAgainstTheEngagementScope(t *testing.T) {
	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPort(core.ScopeInclude, "app.test", 8080))
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "app.test", "/admin"))
	g, err := newRenderScopeGate(scope, "http://app.test:8080/page")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.AllowURL(mustURL(t, "http://app.test:8080/static/app.js?v=1")); err != nil {
		t.Errorf("in-scope subresource refused: %v", err)
	}
	for _, raw := range []string{"http://cdn.other.test/lib.js", "http://app.test:9090/x", "http://app.test:8080/admin/users", "ftp://app.test:8080/"} {
		if err := g.AllowURL(mustURL(t, raw)); err == nil {
			t.Errorf("%s was allowed", raw)
		}
	}
	if err := g.AllowAuthority("cdn.other.test", 443, true); err == nil {
		t.Error("an out-of-scope CONNECT authority was allowed")
	}
	if err := g.AllowAuthority("app.test", 8080, false); err != nil {
		t.Errorf("the in-scope authority was refused: %v", err)
	}
}

// With no declared scope a render may reach only the page's own origin — not every host the page
// names, which is what an empty scope's default-allow would otherwise grant.
func TestRenderScopeGateWithoutADeclaredScopeIsOriginOnly(t *testing.T) {
	for _, scope := range []*core.Scope{nil, core.NewScope()} {
		g, err := newRenderScopeGate(scope, "https://app.test/page")
		if err != nil {
			t.Fatal(err)
		}
		if err := g.AllowURL(mustURL(t, "https://app.test:443/other?q=1")); err != nil {
			t.Errorf("same-origin subresource refused: %v", err)
		}
		for _, raw := range []string{"https://cdn.other.test/lib.js", "http://app.test/x", "https://app.test:8443/x"} {
			if err := g.AllowURL(mustURL(t, raw)); err == nil {
				t.Errorf("scope=%v: %s was allowed", scope != nil, raw)
			}
		}
		if err := g.AllowAuthority("cdn.other.test", 443, true); err == nil {
			t.Error("a cross-origin CONNECT was allowed without a declared scope")
		}
	}
}
