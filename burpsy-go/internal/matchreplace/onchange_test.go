package matchreplace

import "testing"

func mustLiveRule(t *testing.T, match, replace string) *Rule {
	t.Helper()
	r, err := NewRule(TargetRequestBody, CategoryLiteral, match, replace, "test")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	return r
}

// The panel refreshes on real movement only: a rule added, or a replacement set that differs.
// A replacement that reads identical - including one decoded fresh from the same JSON, so the
// compiled patterns are different pointers - announces nothing.
func TestRuleSetAnnouncesRealMovementAndStaysSilentOtherwise(t *testing.T) {
	rs := NewRuleSet()
	calls := 0
	rs.OnChange(func() { calls++ })

	rs.SetRules(nil)
	if calls != 0 {
		t.Fatalf("replacing an empty set with an empty set announced %d times", calls)
	}

	rs.SetRules([]*Rule{mustLiveRule(t, "a", "b")})
	if calls != 1 {
		t.Fatalf("an arriving rule announced %d times, want 1", calls)
	}

	// The same rule, rebuilt: same meaning, different pointers everywhere.
	rs.SetRules([]*Rule{mustLiveRule(t, "a", "b")})
	if calls != 1 {
		t.Fatalf("an identical replacement set announced %d times, want still 1", calls)
	}

	rs.SetRules([]*Rule{mustLiveRule(t, "a", "c")})
	if calls != 2 {
		t.Fatalf("a changed replacement announced %d times, want 2", calls)
	}

	rs.AddRule(mustLiveRule(t, "x", "y"))
	if calls != 3 {
		t.Fatalf("an added rule announced %d times, want 3", calls)
	}

	off, err := NewRule(TargetRequestBody, CategoryLiteral, "x", "y", "test")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	off.Enabled = false
	rs.SetRules([]*Rule{mustLiveRule(t, "a", "c"), off})
	if calls != 4 {
		t.Fatalf("a toggle inside the replacement set announced %d times, want 4", calls)
	}
}
