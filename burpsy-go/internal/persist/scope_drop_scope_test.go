package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The custom drop scope (burpsy-react-ui-47ed) survives a restart through Restore, the path the
// process takes at startup, and "Use suite scope" restores as the suite scope with the custom rules
// kept for the next time they are chosen.
func TestTheCustomDropScopeSurvivesARestore(t *testing.T) {
	p := newTestStore(t)
	custom := core.NewScope()
	custom.AddInclude("api.shop.test")
	path := "/admin"
	rule, err := core.NewScopeRuleFrom(core.ScopeExclude, "api.shop.test", &path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	custom.Add(rule)
	p.SaveScopeDropOutOfScope(true)
	p.SaveScopeDropScope(custom, true)

	restored := core.NewScope()
	if err := p.Restore(nil, nil, restored, nil, nil, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, use := restored.DropScope()
	if got == nil || !use {
		t.Fatal("the custom drop scope came back as the suite scope")
	}
	if !got.Contains("api.shop.test", 443, "/x", true) || got.Contains("api.shop.test", 443, "/admin/a", true) ||
		got.Contains("other.test", 80, "/", false) {
		t.Errorf("the restored custom scope decides differently from the saved one: %d rule(s)", len(got.Rules()))
	}

	p.SaveScopeDropScope(custom, false)
	again := core.NewScope()
	if err := p.Restore(nil, nil, again, nil, nil, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if kept, use := again.DropScope(); use || kept == nil || len(kept.Rules()) != 2 {
		t.Errorf("after choosing the suite scope: in force %v, kept rules %v; want the suite scope with both rules kept", use, kept)
	}
}
