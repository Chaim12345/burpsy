package session

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

// A rule with a validity check that validates only every Nth request. Burp's
// `validate_every_num_requests` (us12), whose docs give the reason: "this helps you to avoid making
// unnecessary requests in cases where the application rarely invalidates your session".
//
// What the interval changes is observable as which branch the check takes: a check that did not run
// takes the valid branch without stating a verdict, while one that ran evaluates the response it was
// handed and takes the invalid branch. Each branch is instrumented by a SetHeader action whose
// runner is a counter, so the measurement is the executor's own walk and not a reimplementation of
// it.

func TestAValidityCheckWithAnIntervalSkipsAllButEveryNthRequest(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := &SessionRule{
		ID:          2,
		Name:        "every third",
		Enabled:     true,
		MaxAttempts: 1,
		Steps:       []MacroStep{{Method: "POST", URL: "http://app.test/login"}},
		Actions: []*Action{{
			Kind:          ActionCheckValidity,
			Enabled:       true,
			ValidateEvery: 3,
			Validity:      &ValidityRule{BodyContains: "welcome"},
			Then:          []*Action{{Kind: ActionAddCookiesFromJar, Enabled: true}},
			Else: []*Action{
				{Kind: ActionSetHeader, Enabled: true, Name: "X-Checked", Value: "yes"},
			},
		}},
	}
	c.RestoreRule(rule)

	// The check's own trace says whether it ran: it records "not checking" when it does not.
	ran, skipped := 0, 0
	for i := 0; i < 10; i++ {
		res := c.runActions(rule, MacroStep{Method: "GET", URL: "http://app.test/x"}, nil, func(step MacroStep) (*StepResult, error) {
			return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
		})
		if actionRanContains(res.Trace, "not checking the session") {
			skipped++
		} else {
			ran++
		}
	}
	if skipped != 7 || ran != 3 {
		t.Errorf("of 10 requests the check ran %d and skipped %d, want 3 and 7 (every third): the "+
			"field exists to avoid the probe, so a wrong count is the whole cost of getting it wrong",
			ran, skipped)
	}
}

func TestAValidityCheckWithNoIntervalRunsEveryRequest(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := &SessionRule{
		ID:          3,
		Name:        "every request",
		Enabled:     true,
		MaxAttempts: 1,
		Steps:       []MacroStep{{Method: "POST", URL: "http://app.test/login"}},
		Actions: []*Action{{
			Kind:     ActionCheckValidity,
			Enabled:  true,
			Validity: &ValidityRule{BodyContains: "welcome"},
			Then:     []*Action{{Kind: ActionAddCookiesFromJar, Enabled: true}},
			Else: []*Action{
				{Kind: ActionSetHeader, Enabled: true, Name: "X-Checked", Value: "yes"},
			},
		}},
	}
	c.RestoreRule(rule)

	ran := 0
	for i := 0; i < 4; i++ {
		res := c.runActions(rule, MacroStep{Method: "GET", URL: "http://app.test/x"}, nil, func(step MacroStep) (*StepResult, error) {
			return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
		})
		if !actionRanContains(res.Trace, "not checking the session") {
			ran++
		}
	}
	if ran != 4 {
		t.Errorf("a check with no interval ran %d times in 4 requests, want 4: zero is the pre-field "+
			"behaviour and every rule written before this field means it", ran)
	}
}

func TestAnIntervalOfOneRunsEveryRequest(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := &SessionRule{
		ID:          4,
		Name:        "every one",
		Enabled:     true,
		MaxAttempts: 1,
		Steps:       []MacroStep{{Method: "POST", URL: "http://app.test/login"}},
		Actions: []*Action{{
			Kind:          ActionCheckValidity,
			Enabled:       true,
			ValidateEvery: 1,
			Validity:      &ValidityRule{BodyContains: "welcome"},
			Then:          []*Action{{Kind: ActionAddCookiesFromJar, Enabled: true}},
			Else: []*Action{
				{Kind: ActionSetHeader, Enabled: true, Name: "X-Checked", Value: "yes"},
			},
		}},
	}
	c.RestoreRule(rule)

	ran := 0
	for i := 0; i < 3; i++ {
		res := c.runActions(rule, MacroStep{Method: "GET", URL: "http://app.test/x"}, nil, func(step MacroStep) (*StepResult, error) {
			return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
		})
		if !actionRanContains(res.Trace, "not checking the session") {
			ran++
		}
	}
	if ran != 3 {
		t.Errorf("an interval of 1 ran %d times in 3 requests, want 3", ran)
	}
}

// The skipped request is not "valid": a rule that never checked cannot claim a verdict, and
// walking the invalid branch anyway would fire a login macro every Nth request for a session that
// is almost always fine — the cost the field exists to avoid.
func TestASkippedCheckTakesTheValidBranch(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := &SessionRule{
		ID:          5,
		Name:        "skip says nothing",
		Enabled:     true,
		MaxAttempts: 1,
		Steps:       []MacroStep{{Method: "POST", URL: "http://app.test/login"}},
		Actions: []*Action{{
			Kind:          ActionCheckValidity,
			Enabled:       true,
			ValidateEvery: 2,
			Validity:      &ValidityRule{BodyContains: "welcome"},
			Then:          []*Action{{Kind: ActionAddCookiesFromJar, Enabled: true}},
			Else: []*Action{
				{Kind: ActionSetHeader, Enabled: true, Name: "X-Checked", Value: "yes"},
			},
		}},
	}
	c.RestoreRule(rule)

	// Request 1 of 2 is skipped. The response the caller holds would call the session INVALID
	// (no "welcome"), so if the check ran it would take the invalid branch.
	res := c.runActions(rule, MacroStep{Method: "GET", URL: "http://app.test/x"},
		&StepResult{Status: 401, Headers: map[string]string{}, Body: []byte("login form")},
		func(step MacroStep) (*StepResult, error) {
			return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
		})
	if !actionRanContains(res.Trace, "not checking the session") {
		t.Errorf("the first of two requests did not skip: %+v", res.Trace)
	}
	for _, entry := range res.Trace {
		if actionRanIsKind(entry, ActionSetHeader) {
			t.Error("the skipped request took the invalid branch: a check that did not run cannot claim " +
				"the session is invalid, and taking that branch would fire the recovery actions the " +
				"interval exists to avoid")
		}
	}
}

// A negative interval is refused, not read as "always" or "never": "validate never" is a rule that
// has silently stopped protecting the session.
func TestANegativeValidateEveryIsRefused(t *testing.T) {
	rule := &SessionRule{
		Name: "negative",
		Actions: []*Action{{
			Kind:          ActionCheckValidity,
			Enabled:       true,
			ValidateEvery: -1,
		}},
	}
	err := ValidateRule(rule)
	if err == nil {
		t.Fatal("a negative interval was accepted: it would have to be read as something, and both " +
			"the readings are wrong (never = a rule that stopped validating; always = not what was typed)")
	}
	if !strings.Contains(err.Error(), "validate every") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
}

// The counter is per RULE, not per action: Burp's field counts the requests the rule handles, so
// two checks on one rule share one count and advance it once per request. With intervals of 2 and 3
// on the same rule, a per-action counter would check on requests 2,3,4,6 while a per-rule count
// checks on 2,3,4,6 as well — so the distinguishing case is two checks with the SAME interval, where
// a shared count makes the second one share the first one's due/not-due decision.
func TestTheCounterIsPerRuleSoTwoChecksShareOneCount(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := &SessionRule{
		ID:          6,
		Name:        "two checks",
		Enabled:     true,
		MaxAttempts: 1,
		Steps:       []MacroStep{{Method: "POST", URL: "http://app.test/login"}},
		Actions: []*Action{
			{Kind: ActionCheckValidity, Enabled: true, ValidateEvery: 2, Validity: &ValidityRule{BodyContains: "welcome"}, Then: []*Action{{Kind: ActionAddCookiesFromJar, Enabled: true}}},
			{Kind: ActionCheckValidity, Enabled: true, ValidateEvery: 2, Validity: &ValidityRule{BodyContains: "welcome"}, Then: []*Action{{Kind: ActionAddCookiesFromJar, Enabled: true}}},
		},
	}
	c.RestoreRule(rule)

	// Each request must report the same due/not-due decision for both checks, because they share
	// one count. A per-action counter would advance twice per request and the two would disagree
	// about which request is the second of the pair.
	ran, skipped := 0, 0
	for i := 0; i < 6; i++ {
		res := c.runActions(rule, MacroStep{Method: "GET", URL: "http://app.test/x"}, nil, func(step MacroStep) (*StepResult, error) {
			return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
		})
		skips := 0
		for _, entry := range res.Trace {
			if strings.Contains(entry.Detail, "not checking the session") {
				skips++
			}
		}
		if skips == 2 {
			skipped++
		} else if skips == 0 {
			ran++
		} else {
			t.Fatalf("request %d: one check skipped and one ran, which a shared counter cannot produce", i+1)
		}
	}
	if ran != 3 || skipped != 3 {
		t.Errorf("of 6 requests %d ran both checks and %d skipped both, want 3 and 3: the two checks "+
			"share the rule's request count, so they must agree on every request", ran, skipped)
	}
}

// actionRanContains reports whether any traced action mentions needle.
func actionRanContains(trace []ActionRan, needle string) bool {
	for _, entry := range trace {
		if strings.Contains(entry.Detail, needle) {
			return true
		}
	}
	return false
}

// actionRanIsKind reports whether the trace contains an action of the given kind.
func actionRanIsKind(entry ActionRan, kind ActionKind) bool {
	return entry.Kind == kind
}
