package core

import (
	"fmt"
	"testing"
)

// Decide must give Contains' answer for every request, or a "why" endpoint built on it would explain
// a decision the proxy did not make.
func TestDecideAgreesWithContains(t *testing.T) {
	p := func(s string) *string { return &s }
	port := func(n uint16) *uint16 { return &n }
	mk := func(kind ScopeRuleKind, pattern string, path *string, pt *uint16, proto *string, enabled bool) *ScopeRule {
		r, err := NewScopeRuleFrom(kind, pattern, path, pt, proto)
		if err != nil {
			t.Fatalf("rule %q: %v", pattern, err)
		}
		r.Enabled = enabled
		return r
	}
	ruleSets := map[string][]*ScopeRule{
		"empty":            nil,
		"include host":     {mk(ScopeInclude, "app.test", nil, nil, nil, true)},
		"include+exclude":  {mk(ScopeInclude, "*.app.test", nil, nil, nil, true), mk(ScopeExclude, "admin.app.test", nil, nil, nil, true)},
		"path exclude":     {mk(ScopeInclude, "app.test", nil, nil, nil, true), mk(ScopeExclude, "app.test", p("/admin"), nil, nil, true)},
		"port include":     {mk(ScopeInclude, "app.test", nil, port(8443), nil, true)},
		"https only":       {mk(ScopeInclude, "app.test", nil, nil, p("https"), true)},
		"disabled include": {mk(ScopeInclude, "app.test", nil, nil, nil, false)},
		"exclude only":     {mk(ScopeExclude, "evil.test", nil, nil, nil, true)},
		"regex path":       {mk(ScopeInclude, "app.test", p(ScopeRegexArm+"^/api/v[0-9]+/"), nil, nil, true)},
	}
	hosts := []string{"app.test", "admin.app.test", "x.app.test", "evil.test", "other.test"}
	ports := []uint16{80, 443, 8443}
	paths := []string{"/", "/admin", "/admin/x", "/api/v2/users", "/apiv/x"}
	checked := 0
	for name, rules := range ruleSets {
		s := NewScope()
		for _, r := range rules {
			s.Add(r)
		}
		for _, h := range hosts {
			for _, pt := range ports {
				for _, path := range paths {
					for _, tls := range []bool{false, true} {
						want := s.Contains(h, pt, path, tls)
						got := s.Decide(h, pt, path, tls)
						if got.InScope != want {
							t.Fatalf("%s: %s:%d%s tls=%v: Decide=%v (%s) Contains=%v", name, h, pt, path, tls, got.InScope, got.Reason, want)
						}
						if (got.Reason == ScopeReasonIncluded || got.Reason == ScopeReasonExcluded) != (got.Rule != nil) {
							t.Fatalf("%s: reason %s with rule %v", name, got.Reason, got.Rule)
						}
						checked++
					}
				}
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d cases checked", checked)
	}
	s := NewScope()
	s.Add(mk(ScopeInclude, "app.test", nil, nil, nil, true))
	if d := s.Decide("app.test", 80, "/", false); d.Rule == nil || d.Rule.Pattern != "app.test" || d.Reason != ScopeReasonIncluded {
		t.Fatalf("the matching include rule is not named: %+v", d)
	}
	_ = fmt.Sprint
}
