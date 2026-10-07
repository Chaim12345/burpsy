package session

import (
	"testing"

	"go.uber.org/zap"
)

// Burp's parameter scope (session-handling-rules.html, burpsy-react-ui-9hip): a rule can be
// restricted to requests carrying named parameters — the canonical rule being "update the CSRF
// token wherever it appears". The host axis already existed; this is the request-content axis.

// An unrestricted rule (no ScopeParams) applies to every parameter set, including nil — a rule
// built before the field existed must not silently stop matching.
func TestAnUnrestrictedRuleMatchesAnyParameters(t *testing.T) {
	r := NewSessionRule("login", []string{"app.test"}, nil)
	if !r.MatchParams(nil) {
		t.Error("a rule with no parameter scope refused a request with no parameters; empty scope must mean everywhere")
	}
	if !r.MatchParams([]string{"csrf_token", "user"}) {
		t.Error("a rule with no parameter scope refused a request carrying parameters")
	}
}

// A parameter-scoped rule matches when the request carries every named parameter.
func TestAParameterScopedRuleMatchesWhenAllNamesArePresent(t *testing.T) {
	r := NewSessionRule("csrf", nil, nil)
	r.ScopeParams = []string{"csrf_token"}
	if !r.MatchParams([]string{"user", "csrf_token"}) {
		t.Error("the rule refused a request carrying the named parameter")
	}
}

// The restriction bites: a request missing the parameter is not covered.
func TestAParameterScopedRuleRefusesARequestWithoutTheParameter(t *testing.T) {
	r := NewSessionRule("csrf", nil, nil)
	r.ScopeParams = []string{"csrf_token"}
	if r.MatchParams([]string{"user", "password"}) {
		t.Error("a request without csrf_token matched a rule scoped to csrf_token")
	}
	if r.MatchParams(nil) {
		t.Error("a parameter-less request matched a rule scoped to csrf_token")
	}
}

// Multiple names are a conjunction: every one must be present.
func TestAParameterScopedRuleRequiresEveryNamedParameter(t *testing.T) {
	r := NewSessionRule("csrf", nil, nil)
	r.ScopeParams = []string{"csrf_token", "session_id"}
	if r.MatchParams([]string{"csrf_token"}) {
		t.Error("a request carrying only one of two required parameters matched")
	}
	if !r.MatchParams([]string{"session_id", "csrf_token", "extra"}) {
		t.Error("a request carrying both required parameters (plus extras) did not match; extras must not matter")
	}
}

// Case-insensitive: HTTP parameter names have no case contract, and Burp treats csrf_token and
// CSRF_Token as the same parameter here.
func TestParameterScopeComparesCaseInsensitively(t *testing.T) {
	r := NewSessionRule("csrf", nil, nil)
	r.ScopeParams = []string{"CSRF_Token"}
	if !r.MatchParams([]string{"csrf_token"}) {
		t.Error("csrf_token did not satisfy a scope named CSRF_Token; the comparison must be case-insensitive")
	}
}

// MatchingRuleFor honours the axis end to end: with two rules over one host, the parameter-
// scoped one wins only for requests carrying its parameter.
func TestMatchingRuleForAppliesTheParameterScope(t *testing.T) {
	c := NewCoordinator(zap.NewNop())

	// Valid rules need one step each — a rule with no macro is refused at AddRule.
	mkStep := func() MacroStep { return MacroStep{Method: "GET", URL: "https://app.test/login"} }

	// The scoped rule is added SECOND: Burp processes session rules in order, first match
	// wins, so the ordering that tests the fall-through is the general rule first.
	general := NewSessionRule("general login", []string{"app.test"}, []MacroStep{mkStep()})
	if _, err := c.AddRule(general); err != nil {
		t.Fatalf("AddRule general: %v", err)
	}

	csrf := NewSessionRule("csrf refresh", []string{"app.test"}, []MacroStep{mkStep()})
	csrf.ScopeParams = []string{"csrf_token"}
	if _, err := c.AddRule(csrf); err != nil {
		t.Fatalf("AddRule csrf: %v", err)
	}

	// A request carrying the parameter: the general rule claims it first in order, and the
	// scoped rule never sees it — the param axis is a RESTRICTION on a rule, not a priority.
	// Prove the axis restricts by placing the scoped rule first instead:
	c2 := NewCoordinator(zap.NewNop())
	csrfFirst := NewSessionRule("csrf refresh", []string{"app.test"}, []MacroStep{mkStep()})
	csrfFirst.ScopeParams = []string{"csrf_token"}
	if _, err := c2.AddRule(csrfFirst); err != nil {
		t.Fatalf("AddRule csrf-first: %v", err)
	}
	generalSecond := NewSessionRule("general login", []string{"app.test"}, []MacroStep{mkStep()})
	if _, err := c2.AddRule(generalSecond); err != nil {
		t.Fatalf("AddRule general-second: %v", err)
	}

	// Scoped first + carries the parameter: the scoped rule claims it.
	if got := c2.MatchingRuleFor("app.test", []string{"csrf_token"}); got != csrfFirst {
		t.Fatalf("MatchingRuleFor picked %v for a request carrying csrf_token; the scoped rule is first in order and must claim it", got)
	}
	// Scoped first + does NOT carry it: the scoped rule is skipped — this is the axis
	// restricting, the half without which the field is decorative — and the general rule
	// takes over.
	if got := c2.MatchingRuleFor("app.test", []string{"user"}); got != generalSecond {
		t.Fatalf("MatchingRuleFor picked %v for a request without csrf_token; the scoped rule must fall through to the general rule", got)
	}
	// No parameter information: the scoped rule must not be chosen on evidence the caller
	// does not have — the general rule answers.
	if got := c2.MatchingRule("app.test"); got != generalSecond {
		t.Fatalf("MatchingRule (no params) picked %v; a scoped rule must be unreachable without parameter evidence", got)
	}
}
