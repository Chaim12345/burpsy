package session

import (
	"errors"
	"testing"

	"go.uber.org/zap"
)

// A restored rule keeps the id it was saved with, and the id sequence continues *above* every
// restored id.
//
// The bug this pins: Restore installed saved rules through AddRule, which mints a fresh id from the
// coordinator's own counter. A rule saved as id 7 came back as id 1, so `POST
// /api/session/rules/7/run` — in a note, a log line, a shell history — then ran a different rule's
// login macro and reported success for it.
func TestRestoreRuleKeepsThePersistedID(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	saved := ruleAt(t, 7, "prod login", "https://app.test/login")

	if err := c.RestoreRule(saved); err != nil {
		t.Fatalf("RestoreRule: %v", err)
	}
	if got := saved.ID; got != 7 {
		t.Fatalf("the restored rule now has id %d, want the id it was saved with (7)", got)
	}
	if c.Rule(7) == nil {
		t.Fatal("Rule(7) is nil: the rule was installed at some other id")
	}
	if c.Rule(1) != nil {
		t.Fatalf("Rule(1) is %q: the restore renumbered the rule from 7 down to 1, which is the bug",
			c.Rule(1).Name)
	}

	// The counter must not be able to hand out an id a restored rule already holds — the same
	// collision, arriving later.
	fresh, err := c.AddRule(NewSessionRule("added after the restore", nil, []MacroStep{{Method: "GET", URL: "https://app.test/x"}}))
	if err != nil {
		t.Fatalf("AddRule after restore: %v", err)
	}
	if fresh <= 7 {
		t.Fatalf("AddRule minted id %d after a rule was restored at 7; a new rule must never land on or "+
			"below a restored id", fresh)
	}
	if c.Rule(7).Name != "prod login" {
		t.Fatalf("id 7 now names %q; the added rule overwrote the restored one", c.Rule(7).Name)
	}
}

// The evaluation order is the caller's call order, not id order — because `order` is what
// MatchingRule walks to decide which login macro owns a host, and the first match wins.
func TestRestoreRuleKeepsTheCallOrderEvenWhenIDsDescend(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	// Ids deliberately out of ascending order: if anything sorted or renumbered, this is what shows it.
	for _, r := range []*SessionRule{
		ruleAt(t, 9, "second in the file", "https://app.test/b"),
		ruleAt(t, 4, "first in the file", "https://app.test/a"),
	} {
		if err := c.RestoreRule(r); err != nil {
			t.Fatalf("RestoreRule %q: %v", r.Name, err)
		}
	}
	all := c.AllRules()
	if len(all) != 2 {
		t.Fatalf("restored %d rules, want 2", len(all))
	}
	if all[0].ID != 9 || all[1].ID != 4 {
		t.Fatalf("evaluation order is %d,%d; want the order the rules were restored in (9,4)",
			all[0].ID, all[1].ID)
	}
	// Both rules cover every host (no scope), so "which rule owns app.test" is decided purely by the
	// order — which is exactly the property a restart must not change.
	if got := c.MatchingRule("app.test"); got == nil || got.ID != 9 {
		t.Fatalf("MatchingRule picked %v; the first rule in the restored order must win", got)
	}
}

// A duplicate id is refused loudly, and the rule already installed survives untouched.
func TestRestoreRuleRefusesADuplicateID(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	if err := c.RestoreRule(ruleAt(t, 3, "the real login", "https://app.test/login")); err != nil {
		t.Fatalf("RestoreRule: %v", err)
	}

	err := c.RestoreRule(ruleAt(t, 3, "a second rule with the same id", "https://app.test/other"))
	if err == nil {
		t.Fatal("restoring a second rule at id 3 succeeded: one of the two silently won")
	}
	if !errors.Is(err, ErrDuplicateRuleID) {
		t.Fatalf("error is %v; a caller has to be able to tell an id collision from a rule that no "+
			"longer validates, so it must wrap ErrDuplicateRuleID", err)
	}
	if c.Rule(3).Name != "the real login" {
		t.Fatalf("id 3 now names %q; the refused rule was installed anyway", c.Rule(3).Name)
	}
	if n := len(c.AllRules()); n != 1 {
		t.Fatalf("the coordinator holds %d rules, want 1", n)
	}
}

// A rule carrying no id is refused rather than renumbered: renumbering is the very thing that makes a
// recorded RuleID name the wrong rule.
func TestRestoreRuleRefusesAnUnsavedID(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	unsaved := NewSessionRule("never saved", nil, []MacroStep{{Method: "GET", URL: "https://app.test/x"}})

	err := c.RestoreRule(unsaved)
	if err == nil {
		t.Fatal("a rule with id 0 was restored; it can only have been given an id it was never saved with")
	}
	var re *RuleError
	if !errors.As(err, &re) {
		t.Fatalf("error is %T (%v); refusals name the rule so a list says which entry to fix", err, err)
	}
	if len(c.AllRules()) != 0 {
		t.Fatal("the refused rule was installed anyway")
	}
}

// A restored rule earns the same validation a freshly-typed one does — a rule saved before a check
// existed must still be refused, not installed because it came from storage.
func TestRestoreRuleStillValidates(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	broken := ruleAt(t, 2, "no steps", "https://app.test/login")
	broken.Steps = nil

	err := c.RestoreRule(broken)
	if err == nil {
		t.Fatal("a rule with no macro steps was restored; validation was skipped for the storage path")
	}
	if errors.Is(err, ErrDuplicateRuleID) {
		t.Fatalf("a validation failure was reported as an id collision: %v", err)
	}
}

// ruleAt builds a valid rule already carrying an id, which is the shape a rule comes back from
// storage in.
func ruleAt(t *testing.T, id RuleID, name, url string) *SessionRule {
	t.Helper()
	r := NewSessionRule(name, nil, []MacroStep{{Method: "POST", URL: url}})
	r.ID = id
	return r
}
