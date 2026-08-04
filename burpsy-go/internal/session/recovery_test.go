package session

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeSender is the Go stand-in for the Rust test_support::FakeSender: a runner whose responses are
// scripted per URL, with call order recorded and an optional artificial delay so a collapsing test
// can be made deterministic. Sending an unscripted URL fails loudly.
type fakeSender struct {
	mu      sync.Mutex
	scripts map[string][][]interface{} // []interface{}: [delay, *StepResult, error]
	calls   []MacroStep
}

func newFakeSender() *fakeSender {
	return &fakeSender{scripts: make(map[string][][]interface{})}
}

func (f *fakeSender) script(url string, result *StepResult, err error) {
	f.scriptDelay(url, 0, result, err)
}

func (f *fakeSender) scriptDelay(url string, d time.Duration, result *StepResult, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts[url] = append(f.scripts[url], []interface{}{d, result, err})
}

func (f *fakeSender) callCount(url string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.calls {
		if s.URL == url {
			n++
		}
	}
	return n
}

func (f *fakeSender) totalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeSender) sentSteps(url string) []MacroStep {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []MacroStep
	for _, s := range f.calls {
		if s.URL == url {
			out = append(out, s)
		}
	}
	return out
}

func (f *fakeSender) send(step MacroStep) (*StepResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, step)
	queue := f.scripts[step.URL]
	if len(queue) == 0 {
		f.mu.Unlock()
		return nil, errors.New("fakeSender: no script queued for " + step.URL)
	}
	next := queue[0]
	f.scripts[step.URL] = queue[1:]
	delay, ok := next[0].(time.Duration)
	f.mu.Unlock()
	if !ok {
		panic("fakeSender: script slot 0 not a duration")
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	if err, _ := next[2].(error); err != nil {
		return nil, err
	}
	resp, _ := next[1].(*StepResult)
	return resp, nil
}

func (f *fakeSender) runner() MacroStepRunner { return f.send }

func validResponse() *StepResult {
	return &StepResult{Status: 200, Headers: map[string]string{"X-Auth": "1"}, Body: []byte("welcome")}
}

func invalidResponse() *StepResult {
	return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("please log in")}
}

func authRule(hosts []string, steps []MacroStep, maxAttempts int) *SessionRule {
	rule := NewSessionRule("login", hosts, steps)
	rule.Validity = &ValidityRule{HeaderPresent: "X-Auth"}
	if maxAttempts >= 1 {
		rule.MaxAttempts = maxAttempts
	}
	return rule
}

func getStep(url string) MacroStep { return MacroStep{Method: "GET", URL: url} }

// mustAddRule installs a rule that the test intends to be valid. AddRule validates, so a fixture that
// drifts into something the coordinator refuses fails here with the reason rather than as a
// mystifying "no rule applies" further down.
func mustAddRule(t *testing.T, c *Coordinator, rule *SessionRule) RuleID {
	t.Helper()
	id, err := c.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule(%q): %v", rule.Name, err)
	}
	return id
}

func TestHandleRecoveryAlreadyValidDoesNotTriggerALogin(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())
	mustAddRule(t, c, authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3))

	outcome := c.HandleRecovery(getStep("https://example.com/account"), validResponse(), fake.runner())
	if outcome.Kind != RecoveryAlreadyValid {
		t.Fatalf("outcome = %+v, want AlreadyValid", outcome)
	}
	if fake.totalCalls() != 0 {
		t.Fatalf("no send should happen when the response is already valid, got %d calls", fake.totalCalls())
	}
}

func TestHandleRecoveryRunsMacroExactlyOnceThenRetriesOriginal(t *testing.T) {
	fake := newFakeSender()
	// A two-step macro: login sets a session cookie, the dashboard confirms the login is valid.
	fake.script("https://example.com/login", &StepResult{Status: 302, Headers: map[string]string{"Location": "/dashboard"}, Body: nil}, nil)
	fake.script("https://example.com/dashboard", validResponse(), nil)
	fake.script("https://example.com/account", validResponse(), nil)

	c := NewCoordinator(zap.NewNop())
	mustAddRule(t, c, authRule([]string{"example.com"}, []MacroStep{
		getStep("https://example.com/login"),
		getStep("https://example.com/dashboard"),
	}, 3))

	outcome := c.HandleRecovery(getStep("https://example.com/account"), invalidResponse(), fake.runner())
	if fake.callCount("https://example.com/login") != 1 {
		t.Fatalf("the login macro must run exactly once, got %d", fake.callCount("https://example.com/login"))
	}
	if fake.callCount("https://example.com/dashboard") != 1 {
		t.Fatalf("the second macro step must run exactly once, got %d", fake.callCount("https://example.com/dashboard"))
	}
	if fake.callCount("https://example.com/account") != 1 {
		t.Fatalf("the original request must be retried exactly once, got %d", fake.callCount("https://example.com/account"))
	}
	if outcome.Kind != RecoveryRecovered || outcome.LoginAttempts != 1 {
		t.Fatalf("outcome = %+v, want Recovered with login_attempts 1", outcome)
	}
}

func TestHandleRecoveryGivesUpAfterMaxAttempts(t *testing.T) {
	fake := newFakeSender()
	for i := 0; i < 3; i++ {
		fake.script("https://example.com/login", invalidResponse(), nil)
	}
	c := NewCoordinator(zap.NewNop())
	mustAddRule(t, c, authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3))

	outcome := c.HandleRecovery(getStep("https://example.com/account"), invalidResponse(), fake.runner())
	if fake.callCount("https://example.com/login") != 3 {
		t.Fatalf("the macro must stop at the stated attempt limit, not run unboundedly; got %d", fake.callCount("https://example.com/login"))
	}
	if fake.callCount("https://example.com/account") != 0 {
		t.Fatalf("the original request is never retried if login never succeeded, got %d", fake.callCount("https://example.com/account"))
	}
	if outcome.Kind != RecoveryGaveUp || outcome.LoginAttempts != 3 {
		t.Fatalf("outcome = %+v, want GaveUp with 3 attempts", outcome)
	}
}

func TestTransportFailureDuringMacroIsMacroFailedAndNotRetried(t *testing.T) {
	fake := newFakeSender()
	fake.script("https://example.com/login", nil, errors.New("connection reset"))
	c := NewCoordinator(zap.NewNop())
	mustAddRule(t, c, authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3))

	outcome := c.HandleRecovery(getStep("https://example.com/account"), invalidResponse(), fake.runner())
	if fake.callCount("https://example.com/login") != 1 {
		t.Fatalf("a transport failure must not be retried the way an invalid response is; got %d", fake.callCount("https://example.com/login"))
	}
	if outcome.Kind != RecoveryMacroFailed || outcome.Attempt != 1 {
		t.Fatalf("outcome = %+v, want MacroFailed with attempt 1", outcome)
	}
	if outcome.Failure == nil || outcome.Failure.StepIndex != 0 || !strings.Contains(outcome.Failure.Error, "connection reset") {
		t.Fatalf("failure = %+v, want step 0 with 'connection reset'", outcome.Failure)
	}
}

func TestLoginCookieIsAttachedToTheRetriedOriginalRequest(t *testing.T) {
	fake := newFakeSender()
	fake.script("https://example.com/login", &StepResult{
		Status:  200,
		Headers: map[string]string{"Set-Cookie": "session=abc123", "X-Auth": "1"},
		Body:    nil,
	}, nil)
	fake.script("https://example.com/account", validResponse(), nil)

	c := NewCoordinator(zap.NewNop())
	mustAddRule(t, c, authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3))
	outcome := c.HandleRecovery(getStep("https://example.com/account"), invalidResponse(), fake.runner())
	if outcome.Kind != RecoveryRecovered {
		t.Fatalf("outcome = %+v, want Recovered", outcome)
	}

	sent := fake.sentSteps("https://example.com/account")
	if len(sent) != 1 {
		t.Fatalf("expected one retried request, got %d", len(sent))
	}
	if got := sent[0].Headers["Cookie"]; got != "session=abc123" {
		t.Fatalf("retried request cookie = %q, want the session cookie captured during login", got)
	}
}

func TestNConcurrentInvalidObservationsCauseOneLoginNotN(t *testing.T) {
	const n = 8
	fake := newFakeSender()
	fake.scriptDelay("https://example.com/login", 50*time.Millisecond, validResponse(), nil)
	for i := 0; i < n; i++ {
		fake.script("https://example.com/account", validResponse(), nil)
	}

	c := NewCoordinator(zap.NewNop())
	mustAddRule(t, c, authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3))

	ready := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]RecoveryOutcome, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ready <- struct{}{}
			<-release
			results[i] = c.HandleRecovery(getStep("https://example.com/account"), invalidResponse(), fake.runner())
		}(i)
	}
	for i := 0; i < n; i++ {
		<-ready
	}
	close(release)
	wg.Wait()

	if got := fake.callCount("https://example.com/login"); got != 1 {
		t.Fatalf("N concurrent session-invalid observations must collapse into one login, not %d", got)
	}
	for i, o := range results {
		if o.Kind != RecoveryRecovered {
			t.Fatalf("caller %d: outcome = %+v, want Recovered", i, o)
		}
	}
}

func TestResponseForTargetNoRuleCoversIsReportedNotLoggedInto(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())
	mustAddRule(t, c, authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3))

	outcome := c.HandleRecovery(getStep("https://elsewhere.test/account"), invalidResponse(), fake.runner())
	if outcome.Kind != RecoveryNoRuleApplies || outcome.URL != "https://elsewhere.test/account" {
		t.Fatalf("outcome = %+v, want NoRuleApplies for the unmatched target", outcome)
	}
	if fake.totalCalls() != 0 {
		t.Fatalf("nothing may be sent for an unmatched target, got %d calls", fake.totalCalls())
	}
}

func csrfRule() *SessionRule {
	rule := authRule([]string{"example.com"}, []MacroStep{
		getStep("https://example.com/login-form"),
		{Method: "POST", URL: "https://example.com/login?t={{csrf}}", Headers: map[string]string{"X-CSRF": "{{csrf}}"}, Body: "user=a&csrf={{csrf}}"},
	}, 3)
	csrf, err := NewExtraction("csrf", "body", `name="csrf" value="([^"]+)"`, 1)
	if err != nil {
		panic(err)
	}
	rule.Extractions = []*Extraction{csrf}
	return rule
}

func formPage(token string) *StepResult {
	return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte(`<form><input name="csrf" value="` + token + `"></form>`)}
}

func TestUpdateMacroPromotesLastSuccessfulRunKeepingPlaceholders(t *testing.T) {
	fake := newFakeSender()
	fake.script("https://example.com/login-form", formPage("tok-9f3a"), nil)
	fake.script("https://example.com/login?t=tok-9f3a", validResponse(), nil)
	fake.script("https://example.com/account", validResponse(), nil)

	c := NewCoordinator(zap.NewNop())
	id := mustAddRule(t, c, csrfRule())

	if got := c.UpdateMacro(id); got.Kind != UpdateMacroNothingObserved {
		t.Fatalf("UpdateMacro before any successful login = %+v, want NothingObserved", got)
	}

	outcome := c.HandleRecovery(getStep("https://example.com/account"), invalidResponse(), fake.runner())
	if outcome.Kind != RecoveryRecovered {
		t.Fatalf("outcome = %+v, want Recovered", outcome)
	}

	updated := c.UpdateMacro(id)
	if updated.Kind != UpdateMacroUpdated {
		t.Fatalf("UpdateMacro after success = %+v, want Updated", updated)
	}
	if len(updated.Steps) != 2 {
		t.Fatalf("expected 2 promoted steps, got %d", len(updated.Steps))
	}
	// The one-time token this run extracted must not have been baked into the stored macro.
	if got := c.Rule(id).Steps[1].URL; got != "https://example.com/login?t={{csrf}}" {
		t.Fatalf("promoted step URL = %q, want the placeholder restored", got)
	}
	if got := c.Rule(id).Steps[1].Body; got != "user=a&csrf={{csrf}}" {
		t.Fatalf("promoted step body = %q, want the placeholder restored", got)
	}
	if got := c.Rule(id).Steps[1].Headers["X-CSRF"]; got != "{{csrf}}" {
		t.Fatalf("promoted step header = %q, want the placeholder restored", got)
	}
}

func TestUpdateMacroOnUnknownRuleSaysSo(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	if got := c.UpdateMacro(42); got.Kind != UpdateMacroNoSuchRule {
		t.Fatalf("UpdateMacro(42) = %+v, want NoSuchRule", got)
	}
}

func TestOnlyASuccessfulRunIsObservedForPromotion(t *testing.T) {
	fake := newFakeSender()
	for i := 0; i < 3; i++ {
		fake.script("https://example.com/login", invalidResponse(), nil)
	}
	c := NewCoordinator(zap.NewNop())
	id := mustAddRule(t, c, authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3))

	outcome := c.HandleRecovery(getStep("https://example.com/account"), invalidResponse(), fake.runner())
	if outcome.Kind != RecoveryGaveUp {
		t.Fatalf("outcome = %+v, want GaveUp", outcome)
	}
	if got := c.UpdateMacro(id); got.Kind != UpdateMacroNothingObserved {
		t.Fatalf("promoting the steps of a run that never logged in = %+v, want NothingObserved", got)
	}
}

func TestEnsureLoggedInReturnsLoginOutcomeDirectly(t *testing.T) {
	fake := newFakeSender()
	fake.script("https://example.com/login", validResponse(), nil)
	c := NewCoordinator(zap.NewNop())
	rule := authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3)
	mustAddRule(t, c, rule)

	out := c.EnsureLoggedIn(rule, fake.runner())
	if out.Kind != LoginSucceeded || out.Attempts != 1 {
		t.Fatalf("outcome = %+v, want Succeeded with 1 attempt", out)
	}
}

func TestUntemplateIsTheInverseOfResolve(t *testing.T) {
	values := map[string]string{"csrf": "tok-1"}
	step := MacroStep{
		Method:  "POST",
		URL:     "https://t.test/act?csrf={{csrf}}",
		Headers: map[string]string{"X-CSRF": "{{csrf}}"},
		Body:    "user=a&csrf={{csrf}}",
	}
	sent := resolveStep(step, values)
	if got := sent.URL; got != "https://t.test/act?csrf=tok-1" {
		t.Fatalf("resolved URL = %q", got)
	}
	back := untemplateStep(sent, values)
	if !reflect.DeepEqual(back, step) {
		t.Fatalf("untemplate(resolve(step)) != step\n got: %+v\nwant: %+v", back, step)
	}
}
