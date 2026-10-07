package session

// RunMacroDetailed is the Test-macro wire row (burpsy-react-ui-7zdm), and its one job is to tell
// the operator the truth about a macro before they rely on it. The tripwire property: the detailed
// dry-run must step, thread cookies, gate on scope, interpolate and extract exactly as RunMacro
// does — an operator tests one macro and runs another if the two loops drift. Each test here runs
// the same scenario through both entry points and requires them to agree.

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestDetailedDryRunAgreesWithRunMacroOnTheSameScenario(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := NewSessionRule("agree", []string{"example.com"}, []MacroStep{
		{Method: "GET", URL: "https://example.com/login?u=admin&p=secret"},
		{Method: "GET", URL: "https://example.com/token"},
	})
	ex, err := NewExtraction("tok", "body", `"token":"([^"]+)"`, 1)
	if err != nil {
		t.Fatalf("extraction: %v", err)
	}
	ex.Step = 1 // the token arrives on the /token step (index 1), not the login step
	rule.Extractions = append(rule.Extractions, ex)

	var sentByRun []MacroStep
	runner := func(step MacroStep) (*StepResult, error) {
		sentByRun = append(sentByRun, step)
		if strings.HasSuffix(step.URL, "/token") {
			return &StepResult{Status: 200, Body: []byte(`{"token":"tok-42"}`)}, nil
		}
		return &StepResult{Status: 200, Body: []byte(`{"ok":true}`)}, nil
	}

	sentA, resultsA, stateA := c.RunMacro(rule, runner)
	sentByRun = nil
	report := c.RunMacroDetailed(rule, runner)
	// Same steps sent, same results, same state.
	if len(report.Steps) != len(sentA) || len(sentA) != len(resultsA) {
		t.Fatalf("step counts disagree: RunMacro sent %d/results %d, detailed has %d rows", len(sentA), len(resultsA), len(report.Steps))
	}
	if stateA != report.Status {
		t.Fatalf("state disagrees: RunMacro=%v detailed=%v", stateA, report.Status)
	}
	for i := range sentA {
		if sentA[i].URL != report.Steps[i].Sent.URL || sentA[i].Method != report.Steps[i].Sent.Method {
			t.Fatalf("step %d sent URL disagrees: RunMacro=%q detailed=%q", i, sentA[i].URL, report.Steps[i].Sent.URL)
		}
		if (resultsA[i] == nil) != (report.Steps[i].Response == nil) {
			t.Fatalf("step %d response presence disagrees", i)
		}
		if resultsA[i] != nil && resultsA[i].Status != report.Steps[i].Response.Status {
			t.Fatalf("step %d status disagrees: RunMacro=%d detailed=%d", i, resultsA[i].Status, report.Steps[i].Response.Status)
		}
	}
	// And the detail the dry-run exists for: the extraction lifted the token on step 1.
	if len(report.Steps[1].Extractions) != 1 || report.Steps[1].Extractions[0].Value != "tok-42" {
		t.Fatalf("step 1 extraction report = %+v, want tok-42 resolved", report.Steps[1].Extractions)
	}
}

func TestDetailedDryRunReportsSkipsAndOutScopeInsteadOfCollapsing(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	// A two-step macro whose second step points at a host the rule's scope does not cover.
	rule := NewSessionRule("scoped", []string{"example.com"}, []MacroStep{
		{Method: "GET", URL: "https://example.com/first"},
		{Method: "GET", URL: "https://other.invalid/second"},
	})
	calls := 0
	runner := func(step MacroStep) (*StepResult, error) {
		calls++
		return &StepResult{Status: 200, Body: []byte("ok")}, nil
	}

	report := c.RunMacroDetailed(rule, runner)
	if calls != 1 {
		t.Fatalf("runner called %d times, want 1 (out-of-scope step must not be sent)", calls)
	}
	if report.Steps[1].Skipped != "out of scope" {
		t.Fatalf("step 1 Skipped = %q, want the out-of-scope reason — a dry-run that hides why a step did not run hides the test", report.Steps[1].Skipped)
	}
	if report.Steps[1].Response != nil {
		t.Fatal("a skipped step carries a response in the report")
	}
}

func TestDetailedDryRunShowsSetCookiesAndSentCookieThreading(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := NewSessionRule("cookies", []string{"example.com"}, []MacroStep{
		{Method: "GET", URL: "https://example.com/login"},
		{Method: "GET", URL: "https://example.com/next"},
	})
	responses := []*StepResult{
		{Status: 200, Headers: map[string]string{"Set-Cookie": "sid=abc123; Path=/"}, Body: []byte("logged in")},
		{Status: 200, Body: []byte("next page")},
	}
	n := 0
	runner := func(step MacroStep) (*StepResult, error) {
		res := responses[n]
		n++
		return res, nil
	}

	report := c.RunMacroDetailed(rule, runner)
	if len(report.Steps[0].SetCookies) != 1 || report.Steps[0].SetCookies[0] != "sid=abc123; Path=/" {
		t.Fatalf("step 0 SetCookies = %v, want the response's cookie", report.Steps[0].SetCookies)
	}
	// Step 2's sent form must show the cookie the first step's response put in the jar — the
	// threading a dry-run exists to make visible.
	if !strings.Contains(report.Steps[1].SentCookie, "sid=abc123") {
		t.Fatalf("step 1 SentCookie = %q, want the jar's sid cookie threaded in", report.Steps[1].SentCookie)
	}
}
