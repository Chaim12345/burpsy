package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-repeater-hostlevel-scope: a single Repeater send was gated by MayContainHost
// alone, which skips path-scoped excludes by design, and s.sender is the plain sender — so a path the
// operator excluded (a logout, a delete endpoint, a production-only prefix) went on the wire from a
// single send while the proxy, Intruder and a single-connection group send all refused it.
func TestRepeaterSingleSendHonoursAPathScopedExclude(t *testing.T) {
	host, port, stats := groupTarget(t)
	s := newTestServer()
	includeInScope(t, s, host)
	s.scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/logout"))

	// The host-level pre-filter is open, so only a per-request decision can refuse what follows.
	if !s.scope.MayContainHost(host, port, false) {
		t.Fatalf("MayContainHost refuses %s, so this test could not tell a per-request gate from a host-level one", host)
	}

	item := groupItem("", host, port, "/logout")
	delete(item, "tab_id")
	rec := postJSON(t, s, "/api/repeater/send", item)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("send /logout = %d (%s), want 403: the path is excluded by scope", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/logout") {
		t.Errorf("the refusal %q does not name the rule that refused it", rec.Body.String())
	}
	if conns, paths := stats(); conns != 0 || len(paths) != 0 {
		t.Fatalf("the target accepted %d connections and saw %v; an excluded path reached the wire", conns, paths)
	}
	if n := len(s.store.Exchanges()); n != 0 {
		t.Errorf("a refused send was recorded as %d exchanges", n)
	}

	// Positive control: an in-scope path on the same host goes out, so the refusal above is the
	// path check and not a send that never works.
	ok := groupItem("", host, port, "/account")
	delete(ok, "tab_id")
	if rec := postJSON(t, s, "/api/repeater/send", ok); rec.Code != http.StatusOK {
		t.Fatalf("send /account = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if _, paths := stats(); len(paths) != 1 || paths[0] != "/account" {
		t.Errorf("target saw %v, want exactly [/account]", paths)
	}
}

// The transforms are applied before the gate and the gate judges the result: an excluded path is
// refused whatever query string rides on it, because the scope reads the path of the bytes sent.
func TestRepeaterSingleSendJudgesTheRequestLineNotTheTarget(t *testing.T) {
	host, port, stats := groupTarget(t)
	s := newTestServer()
	includeInScope(t, s, host)
	s.scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/admin"))

	// The target names the root, which is in scope; the request line names the excluded path.
	item := groupItem("", host, port, "/admin/delete?id=1")
	delete(item, "tab_id")
	if rec := postJSON(t, s, "/api/repeater/send", item); rec.Code != http.StatusForbidden {
		t.Fatalf("send = %d (%s), want 403", rec.Code, rec.Body.String())
	}
	if conns, paths := stats(); conns != 0 || len(paths) != 0 {
		t.Errorf("the target accepted %d connections and saw %v", conns, paths)
	}
}
