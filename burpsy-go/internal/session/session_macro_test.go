package session

import (
	"testing"

	"go.uber.org/zap"
)

func TestRunMacroThreadsCookiesAndExtractions(t *testing.T) {
	c := NewCoordinator(zap.NewNop())

	status200 := 200
	rule := NewSessionRule("login", []string{"example.com"}, []MacroStep{
		{Method: "POST", URL: "https://example.com/login", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Body: "user=alice&pass=wonderland"},
		{Method: "GET", URL: "https://example.com/profile?t={{csrf}}"},
	})
	rule.Validity = &ValidityRule{StatusIs: &status200}
	csrf, err := NewExtraction("csrf", "body", `name="csrf" value="([a-z0-9]+)"`, 1)
	if err != nil {
		t.Fatalf("NewExtraction: %v", err)
	}
	rule.Extractions = []*Extraction{csrf}

	var seenBodies []string
	runner := func(step MacroStep) (*StepResult, error) {
		seenBodies = append(seenBodies, step.Body)
		switch step.URL {
		case "https://example.com/login":
			return &StepResult{
				Status:  200,
				Headers: map[string]string{"Set-Cookie": "session=abc123; Path=/"},
				Body:    []byte(`<input name="csrf" value="tok789">`),
			}, nil
		case "https://example.com/profile?t=tok789":
			return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("hello alice")}, nil
		default:
			t.Fatalf("unexpected step URL %q", step.URL)
			return nil, nil
		}
	}

	sent, results, state := c.RunMacro(rule, runner)
	if state != Valid {
		t.Fatalf("expected valid macro, got %v", state)
	}
	if len(sent) != 2 || len(results) != 2 {
		t.Fatalf("expected 2 steps/results, got %d/%d", len(sent), len(results))
	}
	if results[0] == nil || results[0].Status != 200 {
		t.Fatalf("first step result = %+v, want status 200", results[0])
	}
	// The second step must have run with the extracted token interpolated.
	if got := sent[1].URL; got != "https://example.com/profile?t=tok789" {
		t.Fatalf("second step URL = %q, want extraction applied", got)
	}
	// The first step's Set-Cookie must have been absorbed into the jar.
	if cookie := c.CookieHeader("example.com", 443, true, "/"); cookie == "" {
		t.Fatal("expected jar to hold the absorbed session cookie")
	}
}

func TestRunMacroSkipsOutOfScopeAndFailedSteps(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	status200 := 200
	rule := NewSessionRule("scoped", []string{"example.com"}, []MacroStep{
		{Method: "GET", URL: "https://example.com/a"},
		{Method: "GET", URL: "https://other.example/b"}, // out of scope
	})
	rule.Validity = &ValidityRule{StatusIs: &status200}
	calls := 0
	runner := func(step MacroStep) (*StepResult, error) {
		calls++
		return &StepResult{Status: 200, Headers: map[string]string{}, Body: nil}, nil
	}

	sent, results, state := c.RunMacro(rule, runner)
	if calls != 1 {
		t.Fatalf("runner called %d times, want 1 (out-of-scope step must not be sent)", calls)
	}
	if len(sent) != 2 || len(results) != 2 {
		t.Fatalf("expected 2 entries, got %d/%d", len(sent), len(results))
	}
	if results[1] != nil {
		t.Fatalf("out-of-scope step result = %+v, want nil sentinel", results[1])
	}
	// Validity is still read from the last successful step.
	if state != Valid {
		t.Fatalf("expected valid, got %v", state)
	}
}

func TestRunMacroNilRuleIsIndeterminate(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	_, results, state := c.RunMacro(nil, func(MacroStep) (*StepResult, error) { return nil, nil })
	if state != Indeterminate || len(results) != 0 {
		t.Fatalf("nil rule: state=%v results=%d, want Indeterminate and none", state, len(results))
	}
}
