package core

import "testing"

func TestScopeAddAndRules(t *testing.T) {
	s := NewScope()
	s.AddInclude("*.example.com")
	s.AddExclude("admin.example.com")

	rules := s.Rules()
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
	if rules[0].Kind != ScopeInclude || rules[0].Pattern != "*.example.com" {
		t.Errorf("rule[0] = %+v, want include *.example.com", rules[0])
	}
	if rules[1].Kind != ScopeExclude || rules[1].Pattern != "admin.example.com" {
		t.Errorf("rule[1] = %+v, want exclude admin.example.com", rules[1])
	}
}

func TestScopeContains(t *testing.T) {
	s := NewScope()
	s.AddInclude("*.example.com")
	s.AddExclude("blocked.example.com")

	if !s.Contains("www.example.com", 80, "/", false) {
		t.Error("www.example.com should be in scope")
	}
	if s.Contains("blocked.example.com", 80, "/", false) {
		t.Error("blocked.example.com should be out of scope")
	}
	if s.Contains("other.org", 80, "/", false) {
		t.Error("other.org should be out of scope")
	}
}

func TestScopeAllowEverything(t *testing.T) {
	s := NewScopeAllowEverything()
	if !s.Contains("anything.anywhere", 443, "/x", true) {
		t.Error("allow-everything scope rejected a host")
	}
}
