package web

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/intercept"
)

// The member axes' wire round trip (burpsy-react-ui-ajpn).
//
// The engine tests (internal/intercept/member_rule_test.go) prove the matching. What they cannot
// prove is that a rule written in the console survives the trip there and back: a member name that
// the spec drops on the way in is a rule that silently matches nothing, and one that the spec drops
// on the way out is a rule whose editor shows a blank name the moment it is saved — both of which
// look, to the operator, like the rule was never written.

func TestAMemberRuleSurvivesTheWireInBothDirections(t *testing.T) {
	specs := []interceptRuleSpec{
		{Field: "request_cookie", Category: "literal", Match: "abc123", Member: "session", Enabled: true, Action: "hold"},
		{Field: "response_header", Category: "regex", Match: "^text/", Member: "Content-Type", Enabled: true, Action: "hold"},
	}
	rules, err := specToRules(specs)
	if err != nil {
		t.Fatalf("specToRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
	for i, want := range []string{"session", "Content-Type"} {
		if rules[i].Member != want {
			t.Errorf("rule %d member = %q, want %q — the member name was dropped on the way in, so "+
				"the rule matches nothing and nothing says why", i, rules[i].Member, want)
		}
	}

	back := rulesToSpecs([]*intercept.Rule{&rules[0], &rules[1]})
	for i, want := range []string{"session", "Content-Type"} {
		if back[i].Member != want {
			t.Errorf("spec %d member = %q after the round trip, want %q — the editor would show a "+
				"blank member for a rule that has one", i, back[i].Member, want)
		}
	}
}

func TestAMemberNameOnANonMemberFieldIsRefusedAtTheWire(t *testing.T) {
	// The route must refuse rather than store a rule whose member is read by nothing. A stored
	// rule that ignores part of its own text is the decorative-control defect this project treats
	// as worse than a missing feature.
	_, err := specToRules([]interceptRuleSpec{
		{Field: "host", Category: "literal", Match: "app.test", Member: "session", Enabled: true},
	})
	if err == nil {
		t.Error("a member name on a host rule was accepted. Only a header or cookie field can carry " +
			"one, and accepting it would leave a rule whose member is silently ignored")
	}
	if err != nil && !strings.Contains(err.Error(), "session") {
		t.Errorf("the refusal does not name the member that caused it: %v", err)
	}
}
