package intercept

import "testing"

// 80tg item 1: interception rules could not combine with AND or OR. Burp's proxy.html:246-268 gives
// every rule a boolean operator and folds left to right: "Each rule is combined to the rules above
// in order, using the selected boolean operator."
//
// Without it a conjunction cannot be written at all. "Hold requests to host A AND path /admin" is
// two rules that evaluate as a disjunction, so the operator either over-holds or writes one brittle
// rule enumerating both facts in a single matcher.

func holdRule(field Field, match string) Rule {
	r, err := NewRule(field, CategoryLiteral, match, true, "", RuleActionHold)
	if err != nil {
		panic(err)
	}
	return *r
}

func passRule(field Field, match string) Rule {
	r, err := NewRule(field, CategoryLiteral, match, true, "", RuleActionPass)
	if err != nil {
		panic(err)
	}
	return *r
}

func andRule(field Field, match string) Rule {
	r := holdRule(field, match)
	r.Op = RuleOpAnd
	return r
}

// engineWith builds an active request-direction list holding exactly these rules, in this order.
//
// Through SetRules rather than by writing the field, so the tests exercise the same path an
// operator's saved list takes — a private-field shortcut here would pass while the wire dropped
// the operator.
func engineWith(t *testing.T, rules ...Rule) *Engine {
	t.Helper()
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionRequest, true, rules); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	return e
}

func ruleMsg(host, path string) *Message {
	return &Message{Direction: DirectionRequest, Host: host, Port: 443, TLS: true, Path: path, Method: "GET"}
}

// The core property: a two-rule conjunction holds only when BOTH facts match.
func TestATwoRuleConjunctionHoldsOnlyWhenBothFactsMatch(t *testing.T) {
	e := engineWith(t,
		holdRule(FieldHost, "a.test"),
		andRule(FieldPath, "/admin"),
	)

	if !e.shouldHold(DirectionRequest, ruleMsg("a.test", "/admin")) {
		t.Error("host a.test and path /admin did not hold; both rules matched and the second is an AND")
	}
	// The two near-misses are the whole point of the column, and each is a case the old
	// first-match-wins evaluation got wrong in a different direction.
	if e.shouldHold(DirectionRequest, ruleMsg("a.test", "/public")) {
		t.Error("host a.test and path /public held; the AND rule did not match, so nothing below can rescue it")
	}
	if e.shouldHold(DirectionRequest, ruleMsg("b.test", "/admin")) {
		t.Error("host b.test and path /admin held; the first rule did not match, so the whole conjunction fails")
	}
}

// The default is not a special case: an all-OR list folds to the old first-matching-rule behaviour
// exactly, so every list written before the column existed is unchanged.
func TestAnAllOrListStillBehavesAsFirstMatchingRuleWins(t *testing.T) {
	e := engineWith(t,
		holdRule(FieldHost, "a.test"),
		holdRule(FieldPath, "/public"),
	)

	if !e.shouldHold(DirectionRequest, ruleMsg("a.test", "/admin")) {
		t.Error("the first rule matches and nothing else was consulted; the OR fold must short-circuit there")
	}
	if !e.shouldHold(DirectionRequest, ruleMsg("b.test", "/public")) {
		t.Error("only the second rule matches; it must still hold")
	}
	if e.shouldHold(DirectionRequest, ruleMsg("b.test", "/admin")) {
		t.Error("neither rule matches and the list must pass")
	}
}

// An OR list of hold and pass is what makes "hold this host, but let that path through"
// expressible — the per-rule action (35i4) combined with the disjunction.
func TestAPassRuleInAnOrListOverridesAnEarlierHold(t *testing.T) {
	e := engineWith(t,
		holdRule(FieldHost, "a.test"),
		passRule(FieldPath, "/health"),
	)

	if e.shouldHold(DirectionRequest, ruleMsg("a.test", "/health")) {
		t.Error("a pass rule below a hold did not pass; the first MATCHING rule decides, not the first rule")
	}
	if !e.shouldHold(DirectionRequest, ruleMsg("a.test", "/admin")) {
		t.Error("a path with no pass rule is held, which is what the list says")
	}
}

// The ORDER matters and is the operator's: a conjunction above a disjunction cannot be rescued by
// the disjunction below it, because the AND already failed.
func TestAnAndChainCannotBeRescuedByAnOrBelowIt(t *testing.T) {
	e := engineWith(t,
		holdRule(FieldHost, "a.test"),
		andRule(FieldPath, "/admin"),
		holdRule(FieldURL, "/admin/panel"),
	)

	if e.shouldHold(DirectionRequest, ruleMsg("a.test", "/public")) {
		t.Error("the AND failed and a later OR rule rescued it; a conjunction is not a disjunction " +
			"with extra steps")
	}
	if !e.shouldHold(DirectionRequest, ruleMsg("a.test", "/admin")) {
		t.Error("both conjunction rules matched and nothing should have stopped the hold")
	}
}

// A three-rule chain, which is where a fold and a first-match loop genuinely differ.
func TestAThreeRuleChainHoldsOnlyWhenEveryRuleMatches(t *testing.T) {
	e := engineWith(t,
		holdRule(FieldHost, "a.test"),
		andRule(FieldPath, "/admin"),
		andRule(FieldMethod, "POST"),
	)

	if !e.shouldHold(DirectionRequest, &Message{Direction: DirectionRequest, Host: "a.test", Port: 443, TLS: true, Path: "/admin", Method: "POST"}) {
		t.Error("all three matched and it did not hold")
	}
	// First-match-wins would have held every one of these on the first rule alone.
	if e.shouldHold(DirectionRequest, &Message{Direction: DirectionRequest, Host: "a.test", Port: 443, TLS: true, Path: "/admin", Method: "GET"}) {
		t.Error("the method rule did not match but the message held; first-match-wins is still in force")
	}
}

// AND on the FIRST rule is ignored rather than refused: there is nothing above it to combine with,
// so it stands alone and the rest of the list folds normally around it. An operator who typed an AND
// on the top row gets the list they can see working, not an empty queue and not an error.
func TestAndOnTheFirstRuleIsIgnoredRatherThanRefused(t *testing.T) {
	first := holdRule(FieldHost, "a.test")
	first.Op = RuleOpAnd
	e := engineWith(t, first, holdRule(FieldPath, "/admin"))

	// The first rule is now standalone. A message satisfying either it or the second holds, which is
	// the only reading under which the list an operator is looking at does anything.
	if !e.shouldHold(DirectionRequest, ruleMsg("a.test", "/anything")) {
		t.Error("the first rule matches and nothing holds; an AND on the top row emptied the list " +
			"instead of being ignored")
	}
	if !e.shouldHold(DirectionRequest, ruleMsg("b.test", "/admin")) {
		t.Error("only the second rule matches and it did not hold; the ignored AND left the list empty")
	}
	if e.shouldHold(DirectionRequest, ruleMsg("b.test", "/other")) {
		t.Error("neither rule matches and the message held")
	}
}

// A disabled rule is not part of the chain at all, so the operator is left with whatever the
// remaining rules say. An operator disabling one row of a conjunction expects the hold to widen,
// not to vanish.
func TestADisabledRuleLeavesTheChainRatherThanBreakingIt(t *testing.T) {
	disabled := andRule(FieldPath, "/admin")
	disabled.Enabled = false
	e := engineWith(t, holdRule(FieldHost, "a.test"), disabled)

	if !e.shouldHold(DirectionRequest, ruleMsg("a.test", "/anything")) {
		t.Error("disabling the AND rule emptied the list; a disabled rule is not a failing one")
	}
}

// An unrecognised operator reads as OR rather than refusing the whole list: a saved document
// written by a newer burpsy, or with a typo, must not stop interception working.
func TestAnUnrecognisedOperatorReadsAsOr(t *testing.T) {
	if got := ParseRuleOp("AND"); got != RuleOpAnd {
		t.Errorf("ParseRuleOp(\"AND\") = %v, want and; the spelling is case-insensitive", got)
	}
	if got := ParseRuleOp(" and "); got != RuleOpAnd {
		t.Errorf("ParseRuleOp(\" and \") = %v, want and; surrounding space should not matter", got)
	}
	if got := ParseRuleOp("nonsense"); got != RuleOpOr {
		t.Errorf("ParseRuleOp(\"nonsense\") = %v, want or; an unknown operator must not stop the list", got)
	}
	if got := ParseRuleOp(""); got != RuleOpOr {
		t.Errorf("ParseRuleOp(\"\") = %v, want or — this is the value every pre-existing rule decodes to", got)
	}
	// And the zero value is OR, so a Rule built without the field behaves as before.
	var zero Rule
	if zero.Op != RuleOpOr {
		t.Errorf("the zero RuleOp is %v, want or; every list written before the column must fold the same", zero.Op)
	}
}
