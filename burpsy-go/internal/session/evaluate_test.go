package session

import "testing"

// HARD-01 finding #12: Evaluate used to be an if-chain that returned on the first field set, so a
// rule naming both status_is and body_not_contains silently ignored the second condition once the
// first matched. This is the exact DTO shape an operator would submit for "logged in AND no login
// page still showing".
func TestEvaluateANDsEveryFieldSetOnTheRuleRatherThanOnlyTheFirst(t *testing.T) {
	status := 200
	rule := &ValidityRule{StatusIs: &status, BodyNotContains: "Please log in"}

	// The status matches but the login page is still in the body: must be Invalid, not Valid.
	if got := rule.Evaluate(200, nil, []byte("<html>Please log in</html>")); got != Invalid {
		t.Fatalf("got %v, want Invalid — body_not_contains must not be discarded once status_is matched", got)
	}
	// Both conditions hold: Valid.
	if got := rule.Evaluate(200, nil, []byte("<html>Welcome back</html>")); got != Valid {
		t.Fatalf("got %v, want Valid when both fields hold", got)
	}
	// The status alone fails: Invalid regardless of the body.
	if got := rule.Evaluate(302, nil, []byte("<html>Welcome back</html>")); got != Invalid {
		t.Fatalf("got %v, want Invalid when status_is fails", got)
	}
}

// An indeterminate field (no status observed) must not be silently overridden by an otherwise-Valid
// body check — the whole rule stays Indeterminate rather than guessing.
func TestEvaluateStaysIndeterminateWhenOneOfSeveralFieldsCannotBeJudged(t *testing.T) {
	status := 200
	rule := &ValidityRule{StatusIs: &status, BodyContains: "Welcome"}
	got := rule.Evaluate(0, nil, []byte("Welcome"))
	if got != Indeterminate {
		t.Fatalf("got %v, want Indeterminate", got)
	}
}

// The all-zero rule (an operator's {} DTO default) must still fail closed.
func TestEvaluateOnAnEmptyRuleIsIndeterminate(t *testing.T) {
	rule := &ValidityRule{}
	if got := rule.Evaluate(200, nil, []byte("anything")); got != Indeterminate {
		t.Fatalf("got %v, want Indeterminate for an all-zero rule", got)
	}
}
