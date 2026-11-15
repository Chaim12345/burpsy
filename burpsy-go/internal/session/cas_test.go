package session

import (
	"errors"
	"testing"

	"go.uber.org/zap"
)

// UpdateRuleIfUnchanged is the lock-held compare-and-update the ui2 session-rules page spends
// its confirmation tokens on: a toggle or edit the operator reviewed must apply only if the
// rule is still exactly what they reviewed. These cases pin each refusal and the happy path.

func jarActionRule(name string) *SessionRule {
	return &SessionRule{
		Name:       name,
		Enabled:    true,
		ScopeTools: []string{"proxy"},
		Actions:    []*Action{{Kind: ActionAddCookiesFromJar}},
	}
}

func TestUpdateRuleIfUnchangedAppliesWhenBaseMatches(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	id, err := c.AddRule(jarActionRule("login-a"))
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	base := RuleDigest(c.Rule(id))
	next := jarActionRule("login-a-renamed")
	next.Enabled = false
	if err := c.UpdateRuleIfUnchanged(id, base, next); err != nil {
		t.Fatalf("UpdateRuleIfUnchanged: %v", err)
	}
	got := c.Rule(id)
	if got.Name != "login-a-renamed" || got.Enabled {
		t.Fatalf("rule not updated: %+v", got)
	}
}

func TestUpdateRuleIfUnchangedRefusesStaleBase(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	id, err := c.AddRule(jarActionRule("login-b"))
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	stale := RuleDigest(c.Rule(id))
	if err := c.UpdateRule(id, jarActionRule("login-b-moved")); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	err = c.UpdateRuleIfUnchanged(id, stale, jarActionRule("login-b-clobber"))
	if !errors.Is(err, ErrRuleChanged) {
		t.Fatalf("err = %v, want ErrRuleChanged", err)
	}
	if got := c.Rule(id).Name; got != "login-b-moved" {
		t.Fatalf("stale apply clobbered the rule: name %q", got)
	}
}

func TestUpdateRuleIfUnchangedRefusesMissingRule(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	err := c.UpdateRuleIfUnchanged(RuleID(77), "any", jarActionRule("ghost"))
	if !errors.Is(err, ErrNoSuchRule) {
		t.Fatalf("err = %v, want ErrNoSuchRule", err)
	}
}

func TestUpdateRuleIfUnchangedValidatesBeforeMatching(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	id, err := c.AddRule(jarActionRule("login-c"))
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	// An action-less, step-less rule fails ValidateRule (the engine refuses an empty default
	// macro): the precondition must never see it, matching base or not.
	bad := &SessionRule{Name: "login-c-empty"}
	err = c.UpdateRuleIfUnchanged(id, RuleDigest(c.Rule(id)), bad)
	if err == nil || errors.Is(err, ErrRuleChanged) || errors.Is(err, ErrNoSuchRule) {
		t.Fatalf("err = %v, want a validation error", err)
	}
	if got := c.Rule(id).Name; got != "login-c" {
		t.Fatalf("invalid apply touched the rule: name %q", got)
	}
}

func TestDeleteRuleIfUnchanged(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	id, err := c.AddRule(jarActionRule("login-del"))
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	stale := RuleDigest(c.Rule(id))
	if err := c.UpdateRule(id, jarActionRule("login-del-moved")); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	// Stale base: the removal refuses and the moved rule survives.
	if err := c.DeleteRuleIfUnchanged(id, stale); !errors.Is(err, ErrRuleChanged) {
		t.Fatalf("stale delete err = %v, want ErrRuleChanged", err)
	}
	if c.Rule(id) == nil {
		t.Fatal("stale-base delete removed the rule")
	}
	if err := c.DeleteRuleIfUnchanged(RuleID(99), stale); !errors.Is(err, ErrNoSuchRule) {
		t.Fatalf("missing delete err = %v, want ErrNoSuchRule", err)
	}
	if err := c.DeleteRuleIfUnchanged(id, RuleDigest(c.Rule(id))); err != nil {
		t.Fatalf("fresh delete: %v", err)
	}
	if c.Rule(id) != nil {
		t.Fatal("fresh-base delete did not remove the rule")
	}
}
