package core

import "testing"

// Protocol is an arm of a scope rule's identity: two rules may share kind, pattern, path and
// port and differ only in scheme (http vs https on one host:port is an ordinary scope). A
// remove or toggle that matched only the four other arms would hit whichever sibling came
// first — enabling or deleting a rule the operator did not name, which silently widens an
// engagement's authorised surface. These tests pin the identity in both insertion orders.

func protoScopeRules(t *testing.T) (httpRule, httpsRule *ScopeRule) {
	t.Helper()
	h := "127.0.0.1"
	p := uint16(18101)
	http := "http"
	https := "https"
	var err error
	if httpRule, err = NewScopeRuleFrom(ScopeInclude, h, nil, &p, &http); err != nil {
		t.Fatalf("http rule: %v", err)
	}
	if httpsRule, err = NewScopeRuleFrom(ScopeInclude, h, nil, &p, &https); err != nil {
		t.Fatalf("https rule: %v", err)
	}
	return httpRule, httpsRule
}

func TestRemoveScopedPicksTheNamedProtocolSiblingFirstOrder(t *testing.T) {
	s := NewScope()
	httpRule, httpsRule := protoScopeRules(t)
	s.Add(httpRule)
	s.Add(httpsRule)
	if got := s.RemoveScoped(ScopeInclude, "127.0.0.1", nil, httpRule.Port, &[]string{"https"}[0]); got != ScopeMatchDone {
		t.Fatalf("RemoveScoped(https) = %v, want ScopeMatchDone", got)
	}
	rules := s.Rules()
	if len(rules) != 1 || rules[0].Protocol == nil || *rules[0].Protocol != "http" {
		t.Fatalf("remaining rules = %+v, want only the http sibling", rules)
	}
}

func TestRemoveScopedPicksTheNamedProtocolSiblingReverseOrder(t *testing.T) {
	s := NewScope()
	httpRule, httpsRule := protoScopeRules(t)
	s.Add(httpsRule)
	s.Add(httpRule)
	if got := s.RemoveScoped(ScopeInclude, "127.0.0.1", nil, httpRule.Port, &[]string{"http"}[0]); got != ScopeMatchDone {
		t.Fatalf("RemoveScoped(http) = %v, want ScopeMatchDone", got)
	}
	rules := s.Rules()
	if len(rules) != 1 || rules[0].Protocol == nil || *rules[0].Protocol != "https" {
		t.Fatalf("remaining rules = %+v, want only the https sibling", rules)
	}
}

func TestSetRuleEnabledPicksTheNamedProtocolSibling(t *testing.T) {
	s := NewScope()
	httpRule, httpsRule := protoScopeRules(t)
	s.Add(httpRule)
	s.Add(httpsRule)
	if got := s.SetRuleEnabled(ScopeInclude, "127.0.0.1", nil, httpRule.Port, &[]string{"https"}[0], false); got != ScopeMatchDone {
		t.Fatalf("SetRuleEnabled(https, false) = %v, want ScopeMatchDone", got)
	}
	rules := s.Rules()
	if !rules[0].Enabled {
		t.Error("the http sibling was disabled by a toggle aimed at the https rule - the first-match bug")
	}
	if rules[1].Enabled {
		t.Error("the https rule did not take the disable")
	}
}

// An unnamed protocol over several protocol-differentiated siblings is refused as ambiguous:
// nothing changes, and the caller is told to name the protocol rather than have one guessed.
func TestUnnamedProtocolOverSiblingsIsAmbiguous(t *testing.T) {
	s := NewScope()
	httpRule, httpsRule := protoScopeRules(t)
	s.Add(httpRule)
	s.Add(httpsRule)
	if got := s.SetRuleEnabled(ScopeInclude, "127.0.0.1", nil, httpRule.Port, nil, false); got != ScopeMatchAmbiguous {
		t.Fatalf("SetRuleEnabled without protocol = %v, want ScopeMatchAmbiguous", got)
	}
	if got := s.RemoveScoped(ScopeInclude, "127.0.0.1", nil, httpRule.Port, nil); got != ScopeMatchAmbiguous {
		t.Fatalf("RemoveScoped without protocol = %v, want ScopeMatchAmbiguous", got)
	}
	rules := s.Rules()
	if len(rules) != 2 || !rules[0].Enabled || !rules[1].Enabled {
		t.Fatalf("an ambiguous call changed the scope: %+v", rules)
	}
}

// Compatibility: a tuple only one rule carries still applies without a protocol, exactly as
// before protocol joined the identity.
func TestUnnamedProtocolOverAUniqueRuleStillApplies(t *testing.T) {
	s := NewScope()
	httpRule, _ := protoScopeRules(t)
	s.Add(httpRule)
	if got := s.SetRuleEnabled(ScopeInclude, "127.0.0.1", nil, httpRule.Port, nil, false); got != ScopeMatchDone {
		t.Fatalf("toggle over a unique tuple = %v, want ScopeMatchDone", got)
	}
	if got := s.RemoveScoped(ScopeInclude, "127.0.0.1", nil, httpRule.Port, nil); got != ScopeMatchDone {
		t.Fatalf("remove over a unique tuple = %v, want ScopeMatchDone", got)
	}
	if len(s.Rules()) != 0 {
		t.Fatal("the unique rule was not removed")
	}
}

// A named protocol no sibling carries is a miss, not a fallback to first-match.
func TestNamedProtocolWithNoMatchIsNone(t *testing.T) {
	s := NewScope()
	httpRule, _ := protoScopeRules(t)
	s.Add(httpRule)
	if got := s.RemoveScoped(ScopeInclude, "127.0.0.1", nil, httpRule.Port, &[]string{"https"}[0]); got != ScopeMatchNone {
		t.Fatalf("RemoveScoped(https) against an http-only rule = %v, want ScopeMatchNone", got)
	}
	if len(s.Rules()) != 1 {
		t.Fatal("the miss removed the http rule")
	}
}
