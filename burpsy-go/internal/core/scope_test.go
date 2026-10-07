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

// ---- MayContainHost: the host-level pre-filter ------------------------------------------------

func TestMayContainHostEmptyScopeAllowsEverything(t *testing.T) {
	s := NewScope()
	if !s.MayContainHost("anything.anywhere", 443, true) {
		t.Error("with no include rules an empty scope must keep every host possible; an empty scope contains everything")
	}
}

func TestMayContainHostIncludeMatchesHost(t *testing.T) {
	s := NewScope()
	s.AddInclude("shop.test")
	if !s.MayContainHost("shop.test", 443, true) {
		t.Error("an included host must be possible")
	}
}

func TestMayContainHostHostMatchingNoIncludeRuleIsNotPossible(t *testing.T) {
	s := NewScope()
	s.AddInclude("shop.test")
	if s.MayContainHost("cdn.other.test", 443, true) {
		t.Error("a host matching no include rule must not be possible once any include rule exists; Contains refuses it and the host gate must agree")
	}
}

func TestMayContainHostAgreesWithContainsOnIncludeRules(t *testing.T) {
	s := NewScope()
	s.AddInclude("shop.test")
	if s.MayContainHost("cdn.other.test", 80, false) != s.Contains("cdn.other.test", 80, "/", false) {
		t.Error("MayContainHost and Contains disagree about a host outside the include rules; Repeater/Intruder would send a host the real gate refuses")
	}
}

func TestMayContainHostWholeHostExcludePutsHostBeyondReach(t *testing.T) {
	s := NewScope()
	s.AddInclude("shop.test")
	s.AddExclude("shop.test")
	if s.MayContainHost("shop.test", 443, true) {
		t.Error("a whole-host exclude must take the host out of reach even though an include names it")
	}
}

func TestMayContainHostPathScopedExcludeLeavesTheHostPossible(t *testing.T) {
	s := NewScope()
	s.AddInclude("shop.test")
	s.Add(NewScopeRuleWithPath(ScopeExclude, "shop.test", "/admin"))
	if !s.MayContainHost("shop.test", 443, true) {
		t.Error("a path-scoped exclude removes /admin, not the host; the pre-filter must stay open so the host's other paths can be attacked")
	}
}

func TestMayContainHostPathScopedIncludeLeavesTheHostPossible(t *testing.T) {
	s := NewScope()
	s.Add(NewScopeRuleWithPath(ScopeInclude, "shop.test", "/v1/"))
	if !s.MayContainHost("shop.test", 443, true) {
		t.Error("a path-scoped include authorises its paths, so the host is worth considering even though Contains on \"/\" is false")
	}
}

func TestMayContainHostOnlyExcludeRuleLeavesOtherHostsPossible(t *testing.T) {
	s := NewScope()
	s.AddExclude("blocked.test")
	if s.MayContainHost("blocked.test", 80, false) {
		t.Error("a whole-host exclude must take the excluded host out of the pre-filter")
	}
	if !s.MayContainHost("anything.else", 80, false) {
		t.Error("with no include rules, a host that is not excluded must stay possible even when another host is excluded")
	}
}

// ---- disabled rules (burpsy-react-ui-1xb) -------------------------------------------------------
//
// A disabled rule is stored and shown but inert. The dangerous direction is the zero value:
// ScopeRule is built as a struct literal in tests and persistence, and a bool field added
// without a default would make every such rule disabled — including the excludes, so an
// engagement's scope would silently widen to everything on the first restart. NewScopeRule
// sets Enabled = true precisely so the zero value never reaches live traffic.

// A disabled include stops including: without it the host was admitted by that rule, with it
// the same host falls out of scope (there are no other include rules to admit it).
func TestDisablingAnIncludeRuleTakesItsHostsOutOfScope(t *testing.T) {
	s := NewScope()
	s.AddInclude("example.test")
	if !s.Contains("example.test", 80, "/", false) {
		t.Fatal("setup: the host should be in scope before the rule is disabled")
	}

	if !s.SetRuleEnabled(ScopeInclude, "example.test", nil, nil, false) {
		t.Fatal("SetRuleEnabled should report that the rule was found and disabled")
	}
	if s.Contains("example.test", 80, "/", false) {
		t.Error("a disabled include must not admit its host; Contains left example.test in scope")
	}
	if s.Rules()[0].Enabled {
		t.Error("the rule still reports enabled after SetRuleEnabled(false)")
	}

	// Toggling back is the point of the switch — the rule comes back exactly as it was.
	if !s.SetRuleEnabled(ScopeInclude, "example.test", nil, nil, true) {
		t.Fatal("SetRuleEnabled should report that the rule was found and re-enabled")
	}
	if !s.Contains("example.test", 80, "/", false) {
		t.Error("re-enabling the include did not restore the host to scope")
	}
}

// The dangerous direction: a disabled exclude must stop excluding. If it did not, the disable
// switch would be decorative and the zero-value hazard would be invisible. The disabled rule
// stops matching, but the include list below it is unchanged — Contains' semantics are
// "excludes always win over includes", not "disabling an exclude overrides the include
// list" — so a host that was excluded AND was on no include rule is still not admitted by
// the disable alone. The test pins exactly what the toggle changed: the rule no longer
// matches, and re-enabling restores the fence.
func TestDisablingAnExcludeRuleLetsItsHostsBackIn(t *testing.T) {
	s := NewScope()
	// A scope whose include list admits the host, with the exclude carving it back out: this
	// is the ordinary shape where disabling the exclude must widen scope back.
	s.AddInclude("*.example.test")
	s.AddExclude("secret.example.test")
	if s.Contains("secret.example.test", 80, "/", false) {
		t.Fatal("setup: the excluded host should be out of scope while the exclude is active")
	}

	if !s.SetRuleEnabled(ScopeExclude, "secret.example.test", nil, nil, false) {
		t.Fatal("SetRuleEnabled should report that the exclude was found and disabled")
	}
	if !s.Contains("secret.example.test", 80, "/", false) {
		t.Error("with the include list admitting it, a disabled exclude must stop excluding and secret.example.test must come back into scope")
	}
}

// The gate is on Matches itself, not on Contains' call sites — MayContainHost calls
// rule.Matches directly, so a gate anywhere else would let the host-level pre-filter and the
// per-request authorisation disagree about whether an include exists (the exact class of bug
// burpsy-react-ui-cj7x fixed). One decision, two call sites, one answer.
func TestMayContainHostSeesADisabledRuleTheSameWayContainsDoes(t *testing.T) {
	s := NewScope()
	s.AddInclude("example.test")
	if !s.MayContainHost("example.test", 80, false) {
		t.Fatal("setup: the host should pass the pre-filter before the rule is disabled")
	}

	s.SetRuleEnabled(ScopeInclude, "example.test", nil, nil, false)
	if s.MayContainHost("example.test", 80, false) {
		t.Error("MayContainHost admitted a host whose only include rule is disabled — the pre-filter and Contains disagree")
	}
	if s.Contains("example.test", 80, "/", false) {
		t.Error("Contains admitted the same host — disable did not reach the matching path at all")
	}
}

// The tuple identity is exact, as RemoveScoped's is: toggling a path-scoped sibling must not
// touch the host-wide rule (or vice versa), and toggling by a tuple nothing carries is a
// miss, not a silent edit of the first rule that happens to share the host.
func TestSetRuleEnabledMatchesTheTupleExactly(t *testing.T) {
	s := NewScope()
	s.AddInclude("shop.test")
	pathScoped := NewScopeRuleWithPath(ScopeInclude, "shop.test", "/api")
	s.Add(pathScoped)

	// Disable the path-scoped one only.
	if !s.SetRuleEnabled(ScopeInclude, "shop.test", pathScoped.PathPrefix, nil, false) {
		t.Fatal("SetRuleEnabled should have found the path-scoped rule")
	}
	rules := s.Rules()
	if !rules[0].Enabled {
		t.Error("the host-wide rule was disabled by a toggle aimed at its path-scoped sibling")
	}
	if rules[1].Enabled {
		t.Error("the path-scoped rule did not take the disable")
	}

	// A tuple no rule carries misses rather than editing something else.
	if s.SetRuleEnabled(ScopeInclude, "shop.test", nil, nil, true) && !s.Rules()[0].Enabled {
		t.Error("the miss path reported success")
	}
	if s.SetRuleEnabled(ScopeExclude, "shop.test", nil, nil, false) {
		t.Error("toggling an exclude that does not exist should report no match")
	}
}
