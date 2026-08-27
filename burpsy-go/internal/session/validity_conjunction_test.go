package session

import "testing"

// ---- a validity rule must evaluate every clause it states -------------------------------
//
// `ValidityRule.Evaluate` was a first-stated-field-wins if-chain: each clause returned
// unconditionally, so in a rule stating more than one condition only the first was read.
//
// This is not a cosmetic parsing bug. `recovery.go` gates re-login on
// `Evaluate(...) == Valid` in four places (:198, :325, :375, :381), so a rule whose second
// half was skipped could report a logged-out page as a live session. The scanner then never
// re-authenticated and an authenticated scan silently became an unauthenticated one — while
// the audit still reported `state=audited, skipped=0`.

func statusPtr(v int) *int { return &v }

// The exact case from the parity audit: "200 AND not the login page", against a logged-out
// login page that answers 200. This is the assertion that fails against the old if-chain.
func TestAFlatRuleEvaluatesEveryStatedClause(t *testing.T) {
	rule := &ValidityRule{
		StatusIs:        statusPtr(200),
		BodyNotContains: "Please log in",
	}
	body := []byte("<html><body>Please log in to continue</body></html>")

	got := rule.Evaluate(200, map[string]string{}, body)
	if got == Valid {
		t.Fatal("a logged-out login page reported a VALID session: status_is matched and " +
			"body_not_contains was never evaluated. recovery.go would skip re-login and the " +
			"whole scan would run unauthenticated while reporting skipped=0")
	}
	if got != Invalid {
		t.Fatalf("Evaluate = %d, want Invalid — the body clause positively disproves the session", got)
	}
}

// The same rule against a genuinely logged-in response must still be Valid, or the fix has
// simply made every rule fail closed — which would break authenticated scanning in the other
// direction and be just as wrong.
func TestTheSameRuleStillAcceptsAGenuineSession(t *testing.T) {
	rule := &ValidityRule{
		StatusIs:        statusPtr(200),
		BodyNotContains: "Please log in",
	}
	body := []byte("<html><body>Welcome back, admin</body></html>")

	if got := rule.Evaluate(200, map[string]string{}, body); got != Valid {
		t.Fatalf("Evaluate = %d, want Valid — both stated clauses hold", got)
	}
}

// A single-clause rule must behave exactly as it did before. This is the compatibility guard:
// the fix is only safe because it changes nothing for rules that state one condition, and
// those are the overwhelming majority of what exists in persisted config.
func TestSingleClauseRulesAreUnchanged(t *testing.T) {
	cases := []struct {
		name string
		rule *ValidityRule
		st   int
		hdrs map[string]string
		body string
		want ValidityState
	}{
		{"status matches", &ValidityRule{StatusIs: statusPtr(200)}, 200, nil, "", Valid},
		{"status differs", &ValidityRule{StatusIs: statusPtr(200)}, 302, nil, "", Invalid},
		{"no status measured", &ValidityRule{StatusIs: statusPtr(200)}, 0, nil, "", Indeterminate},
		{"body contains", &ValidityRule{BodyContains: "admin"}, 200, nil, "hi admin", Valid},
		{"body missing", &ValidityRule{BodyContains: "admin"}, 200, nil, "hi guest", Invalid},
		{"body not-contains ok", &ValidityRule{BodyNotContains: "login"}, 200, nil, "welcome", Valid},
		{"body not-contains hit", &ValidityRule{BodyNotContains: "login"}, 200, nil, "login here", Invalid},
		{"header present", &ValidityRule{HeaderPresent: "X-User"}, 200, map[string]string{"x-user": "a"}, "", Valid},
		{"header missing", &ValidityRule{HeaderPresent: "X-User"}, 200, map[string]string{}, "", Invalid},
		{"header absent ok", &ValidityRule{HeaderAbsent: "X-Login"}, 200, map[string]string{}, "", Valid},
		{"header absent hit", &ValidityRule{HeaderAbsent: "X-Login"}, 200, map[string]string{"X-Login": "1"}, "", Invalid},
		{"nothing stated", &ValidityRule{}, 200, nil, "anything", Indeterminate},
		{"nil rule", nil, 200, nil, "anything", Indeterminate},
	}
	for _, c := range cases {
		if got := c.rule.Evaluate(c.st, c.hdrs, []byte(c.body)); got != c.want {
			t.Errorf("%s: Evaluate = %d, want %d", c.name, got, c.want)
		}
	}
}

// A definite Invalid outranks an Indeterminate, matching All{}'s precedence. A clause that
// positively disproves the session is more informative than one that could not be decided,
// and reporting Indeterminate here would let recovery.go treat a known-dead session as
// merely unknown.
func TestADefiniteInvalidOutranksAnIndeterminate(t *testing.T) {
	rule := &ValidityRule{
		StatusIs:     statusPtr(200), // status 0 below -> Indeterminate
		BodyContains: "admin",        // absent -> Invalid
	}
	if got := rule.Evaluate(0, nil, []byte("logged out")); got != Invalid {
		t.Fatalf("Evaluate = %d, want Invalid — a proven-false clause must not be softened "+
			"to Indeterminate by an unmeasured one", got)
	}
}

// An explicit All{} and the flat conjunction must agree on the same input, because the flat
// form is now defined as All{} over its stated clauses. If these ever diverge, one of the two
// paths has grown its own semantics.
func TestTheFlatFormAgreesWithAnExplicitAllBlock(t *testing.T) {
	flat := &ValidityRule{StatusIs: statusPtr(200), BodyNotContains: "Please log in"}
	explicit := &ValidityRule{All: []*ValidityRule{
		{StatusIs: statusPtr(200)},
		{BodyNotContains: "Please log in"},
	}}
	inputs := []struct {
		st   int
		body string
	}{
		{200, "Please log in to continue"},
		{200, "Welcome back"},
		{302, "Welcome back"},
		{0, "Welcome back"},
		{500, "Please log in"},
	}
	for _, in := range inputs {
		f := flat.Evaluate(in.st, nil, []byte(in.body))
		e := explicit.Evaluate(in.st, nil, []byte(in.body))
		if f != e {
			t.Errorf("status=%d body=%q: flat=%d explicit All{}=%d — the two spellings must agree",
				in.st, in.body, f, e)
		}
	}
}

// Combinators still compose, and now compose *alongside* leaf clauses rather than being
// shadowed by them. Under the old chain a rule with both a leaf and an Any{} block never
// reached the Any{}.
func TestCombinatorsComposeWithLeafClauses(t *testing.T) {
	rule := &ValidityRule{
		StatusIs: statusPtr(200),
		Any: []*ValidityRule{
			{BodyContains: "dashboard"},
			{BodyContains: "account"},
		},
	}
	if got := rule.Evaluate(200, nil, []byte("your account page")); got != Valid {
		t.Errorf("status 200 + Any{} satisfied = %d, want Valid", got)
	}
	if got := rule.Evaluate(200, nil, []byte("nothing familiar")); got != Invalid {
		t.Errorf("status 200 + Any{} unsatisfied = %d, want Invalid — the Any{} block must be "+
			"reached, not shadowed by the leaf clause", got)
	}
	if got := rule.Evaluate(403, nil, []byte("your account page")); got != Invalid {
		t.Errorf("status 403 + Any{} satisfied = %d, want Invalid — the leaf clause must still count", got)
	}
}

// Not{} negates, and Indeterminate stays Indeterminate under negation — the negation of
// "could not be determined" is still "could not be determined", not "true".
func TestNotNegatesButPreservesIndeterminate(t *testing.T) {
	rule := &ValidityRule{Not: &ValidityRule{BodyContains: "Please log in"}}
	if got := rule.Evaluate(200, nil, []byte("Please log in")); got != Invalid {
		t.Errorf("Not{body contains login} on a login page = %d, want Invalid", got)
	}
	if got := rule.Evaluate(200, nil, []byte("Welcome")); got != Valid {
		t.Errorf("Not{body contains login} on a session page = %d, want Valid", got)
	}
	unknown := &ValidityRule{Not: &ValidityRule{StatusIs: statusPtr(200)}}
	if got := unknown.Evaluate(0, nil, nil); got != Indeterminate {
		t.Errorf("Not{unmeasured} = %d, want Indeterminate", got)
	}
}
