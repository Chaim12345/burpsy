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

func TestScopeRemoveDeletesFirstMatchingRule(t *testing.T) {
	s := NewScope()
	s.AddInclude("a.example.com")
	s.AddInclude("b.example.com")
	s.AddInclude("a.example.com")

	if !s.Remove(ScopeInclude, "a.example.com") {
		t.Fatal("Remove should report that a rule was removed")
	}
	rules := s.Rules()
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2 after removing one duplicate", len(rules))
	}
	if rules[0].Pattern != "b.example.com" {
		t.Errorf("first remaining rule = %q, want b.example.com", rules[0].Pattern)
	}
}

func TestScopeRemoveReportsFalseWhenNoRuleMatches(t *testing.T) {
	s := NewScope()
	s.AddInclude("a.example.com")

	if s.Remove(ScopeExclude, "a.example.com") {
		t.Error("removing an exclude that is not present should report false")
	}
	if s.Remove(ScopeInclude, "nope.example.com") {
		t.Error("removing an include that is not present should report false")
	}
}

func TestScopeClearRemovesAllRules(t *testing.T) {
	s := NewScope()
	s.AddInclude("a.example.com")
	s.AddExclude("b.example.com")
	s.Clear()

	rules := s.Rules()
	if len(rules) != 0 {
		t.Fatalf("rules = %d, want 0 after Clear", len(rules))
	}
}

func TestScopeWithOnlyExcludesAllowsEverythingElse(t *testing.T) {
	s := NewScope()
	s.AddExclude("blocked.example.com")

	if s.Contains("blocked.example.com", 80, "/", false) {
		t.Error("an excluded host should be out of scope even with no include rules")
	}
	if !s.Contains("anything.else", 80, "/", false) {
		t.Error("with no include rules, a non-excluded host should be in scope")
	}
}

func TestProtocolScopedIncludeOnlyAdmitsItsOwnScheme(t *testing.T) {
	s := NewScope()
	httpsOnly := NewScopeRule(ScopeInclude, "example.test")
	scheme := "https"
	httpsOnly.Protocol = &scheme
	s.Add(httpsOnly)

	if !s.Contains("example.test", 443, "/", true) {
		t.Error("an https-scoped include must admit an https request to example.test")
	}
	if s.Contains("example.test", 80, "/", false) {
		t.Error("an https-scoped include admitted plain http; a protocol arm that matches both schemes is decorative and lies on the Scope page")
	}
}

func TestProtocolScopedExcludeRemovesOnlyItsScheme(t *testing.T) {
	s := NewScope()
	s.AddInclude("example.test")
	httpsExclusion := NewScopeRule(ScopeExclude, "example.test")
	scheme := "https"
	httpsExclusion.Protocol = &scheme
	s.Add(httpsExclusion)

	if !s.Contains("example.test", 80, "/", false) {
		t.Error("excluding only https from example.test must leave http authorised")
	}
	if s.Contains("example.test", 443, "/", true) {
		t.Error("an https-scoped exclude failed to keep https out of scope for example.test")
	}
}

func TestRuleWithoutProtocolArmMatchesBothSchemes(t *testing.T) {
	s := NewScope()
	s.AddInclude("example.test")

	if !s.Contains("example.test", 443, "/", true) || !s.Contains("example.test", 80, "/", false) {
		t.Error("a rule with no protocol arm must match both schemes; every rule built before the arm existed relies on this")
	}
}
