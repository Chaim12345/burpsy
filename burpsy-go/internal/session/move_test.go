package session

import (
	"errors"
	"testing"

	"go.uber.org/zap"
)

// MoveRule is the only write path that can change rule precedence: MatchingRule returns the first
// enabled rule whose scope covers a host, walking `order`, so position is which login wins for a
// host two rules cover. These tests pin the move semantics — id-preserving, adjacency-exact,
// refused (not clamped) at either edge — because a silently clamped move reports success and
// changes nothing, the worst answer an operator can be given.

func TestMoveRuleSwapsAdjacentRulesSoTheMovedRuleNowOwnsTheHost(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	if _, err := c.AddRule(NewSessionRule("first", nil, []MacroStep{{Method: "GET", URL: "https://app.test/a"}})); err != nil {
		t.Fatalf("AddRule first: %v", err)
	}
	second, err := c.AddRule(NewSessionRule("second", nil, []MacroStep{{Method: "GET", URL: "https://app.test/b"}}))
	if err != nil {
		t.Fatalf("AddRule second: %v", err)
	}

	// Both rules carry no scope, so they cover every host and MatchingRule is decided purely by
	// position: "second" was minted last, so "first" owns every host before the move.
	if got := c.MatchingRule("app.test"); got == nil || got.Name != "first" {
		t.Fatalf("MatchingRule picked %v before the move; the first rule must own the host", got)
	}

	pos, err := c.MoveRule(second, -1)
	if err != nil {
		t.Fatalf("MoveRule up: %v", err)
	}
	if pos != 0 {
		t.Fatalf("MoveRule reported position %d, want 0", pos)
	}

	// The id did not change and the same rule now wins — the whole point of moving rather than
	// delete-and-re-add, which would have minted a fresh id and broken every saved reference.
	if c.AllRules()[0].ID != second {
		t.Fatalf("evaluation order head is %d, want the moved rule %d", c.AllRules()[0].ID, second)
	}
	if got := c.MatchingRule("app.test"); got == nil || got.Name != "second" {
		t.Fatalf("MatchingRule picked %v after the move; the moved rule must now own the host", got)
	}
}

func TestMoveRuleDownMovesTheRuleAndUpdatesItsPosition(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	first, _ := c.AddRule(NewSessionRule("first", nil, []MacroStep{{Method: "GET", URL: "https://app.test/a"}}))
	c.AddRule(NewSessionRule("second", nil, []MacroStep{{Method: "GET", URL: "https://app.test/b"}}))
	c.AddRule(NewSessionRule("third", nil, []MacroStep{{Method: "GET", URL: "https://app.test/c"}}))

	pos, err := c.MoveRule(first, 1)
	if err != nil {
		t.Fatalf("MoveRule down: %v", err)
	}
	if pos != 1 {
		t.Fatalf("MoveRule reported position %d, want 1", pos)
	}
	all := c.AllRules()
	if all[0].Name != "second" || all[1].Name != "first" || all[2].Name != "third" {
		t.Fatalf("order is %s,%s,%s; want second,first,third", all[0].Name, all[1].Name, all[2].Name)
	}
}

func TestMoveRulePastEitherEdgeIsRefusedNotSilentlyClamped(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	first, _ := c.AddRule(NewSessionRule("first", nil, []MacroStep{{Method: "GET", URL: "https://app.test/a"}}))
	last, _ := c.AddRule(NewSessionRule("last", nil, []MacroStep{{Method: "GET", URL: "https://app.test/z"}}))

	if _, err := c.MoveRule(first, -1); !errors.Is(err, ErrRuleAtEdge) {
		t.Fatalf("moving the top rule up returned %v; it must be refused with ErrRuleAtEdge, not clamped", err)
	}
	if _, err := c.MoveRule(last, 1); !errors.Is(err, ErrRuleAtEdge) {
		t.Fatalf("moving the bottom rule down returned %v; it must be refused with ErrRuleAtEdge, not clamped", err)
	}

	// The refused moves must have changed nothing — a clamp that "succeeded" but moved nothing
	// would leave the table showing one order while the engine evaluates another.
	all := c.AllRules()
	if all[0].Name != "first" || all[1].Name != "last" {
		t.Fatalf("refused moves changed the order to %s,%s; a refusal must be a no-op", all[0].Name, all[1].Name)
	}
}

func TestMoveRuleOfAnUnknownIDIsErrNoSuchRule(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	c.AddRule(NewSessionRule("only", nil, []MacroStep{{Method: "GET", URL: "https://app.test/a"}}))

	if _, err := c.MoveRule(RuleID(999), -1); !errors.Is(err, ErrNoSuchRule) {
		t.Fatalf("MoveRule on an unknown id returned %v, want ErrNoSuchRule", err)
	}
}

func TestMoveRuleWithZeroOffsetIsAReadReportingTheCurrentPosition(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	c.AddRule(NewSessionRule("first", nil, []MacroStep{{Method: "GET", URL: "https://app.test/a"}}))
	second, _ := c.AddRule(NewSessionRule("second", nil, []MacroStep{{Method: "GET", URL: "https://app.test/b"}}))

	pos, err := c.MoveRule(second, 0)
	if err != nil {
		t.Fatalf("MoveRule offset 0: %v", err)
	}
	if pos != 1 {
		t.Fatalf("MoveRule offset 0 reported position %d, want 1", pos)
	}
}

func TestMoveRuleKeepsTheRuleIDStableAcrossTheMove(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	c.AddRule(NewSessionRule("first", nil, []MacroStep{{Method: "GET", URL: "https://app.test/a"}}))
	second, _ := c.AddRule(NewSessionRule("second", nil, []MacroStep{{Method: "GET", URL: "https://app.test/b"}}))
	c.AddRule(NewSessionRule("third", nil, []MacroStep{{Method: "GET", URL: "https://app.test/c"}}))

	if _, err := c.MoveRule(second, 1); err != nil {
		t.Fatalf("MoveRule: %v", err)
	}
	if c.Rule(second) == nil || c.Rule(second).Name != "second" {
		t.Fatalf("Rule(%d) after the move is %v; a move must never renumber a rule, because every "+
			"saved /run URL and note names the rule by id", second, c.Rule(second))
	}
}
