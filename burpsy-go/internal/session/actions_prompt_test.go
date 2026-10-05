package session

import (
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// ---- "Prompt the user for in-browser session recovery" (burpsy-react-ui-dq1g) ---------------------
//
// Burp's ninth session-rule action, Zgr9.java:12 (build 51467), with its own editor (Zrvt.java:72).
// burpsy's counterpart is a console modal rather than a popup window: the task blocks on the
// SessionPrompter seam until the operator answers, and the walk resumes only on success. These
// tests pin the three things that make the action real rather than decorative: the prompt is
// actually asked, the task is actually suspended until the answer lands, and the walk stops
// without sending when the answer is not a recovery.

// fakePrompter is the console's prompt surface for tests: a scripted answer, the rules it was
// asked about, and an optional gate so a test can hold the prompt open and observe the
// suspension itself.
type fakePrompter struct {
	mu        sync.Mutex
	recovered bool
	err       error
	asked     []string
	gate      chan struct{} // when non-nil, every prompt blocks until it is closed
}

func (f *fakePrompter) PromptForBrowserRecovery(ruleName string, requestURL string) (bool, error) {
	f.mu.Lock()
	f.asked = append(f.asked, ruleName)
	f.mu.Unlock()
	if f.gate != nil {
		<-f.gate
	}
	return f.recovered, f.err
}

func (f *fakePrompter) askCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

// promptAction is the action under test: enabled, no fields of its own.
func promptAction() *Action { return &Action{Kind: ActionPromptForBrowserRecovery, Enabled: true} }

// promptRule builds a rule whose action list is the prompt followed by a set-header action, so a
// test can tell a walk that stopped at the prompt from one that ran past it: the header action
// leaves evidence in the trace and in the request.
func promptRule(actions ...*Action) *SessionRule {
	rule := NewSessionRule("ask the operator", []string{"example.com"}, nil)
	rule.Actions = actions
	return rule
}

// TestAPromptForBrowserRecoveryBlocksUntilTheOperatorAnswers is the suspension itself, which is
// the whole claim the action exists to make. HandleRecovery must not return until the operator
// answers, and nothing may be sent in the meantime — a request that goes out during the prompt
// is the decorative-control failure this action is designed to prevent.
func TestAPromptForBrowserRecoveryBlocksUntilTheOperatorAnswers(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())
	prompter := &fakePrompter{recovered: true, gate: make(chan struct{})}
	c.SetSessionPrompter(prompter)

	rule := promptRule(promptAction())
	mustAddRule(t, c, rule)

	fake.script("https://example.com/act", validResponse(), nil)

	done := make(chan RecoveryOutcome, 1)
	go func() {
		done <- c.HandleRecovery("", getStep("https://example.com/act"), invalidResponse(), fake.runner())
	}()

	// The prompt is asked, and stays asked: half a second is an eternity against a fake sender, so
	// an outcome that arrives this early means the task was never suspended.
	select {
	case outcome := <-done:
		t.Fatalf("HandleRecovery returned %v before the operator answered — the task was not "+
			"suspended while the prompt was pending", outcome.Kind)
	case <-time.After(100 * time.Millisecond):
	}
	if got := prompter.askCount(); got != 1 {
		t.Fatalf("the prompter was asked %d time(s), want 1 — the action must ask the console, not "+
			"guess", got)
	}
	if sent := fake.sentSteps("https://example.com/act"); len(sent) != 0 {
		t.Fatalf("sent %d request(s) while the prompt was pending; the request must wait for the "+
			"operator's answer", len(sent))
	}

	// The answer lands and the task resumes.
	close(prompter.gate)
	select {
	case outcome := <-done:
		if outcome.Kind != RecoveryRuleApplied {
			t.Fatalf("outcome = %v (trace: %s), want RecoveryRuleApplied — the walk resumed after "+
				"the prompt and the request was re-sent", outcome.Kind, describeTrace(outcome.Actions))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandleRecovery did not return after the operator answered — the task stayed " +
			"suspended after the prompt was resolved")
	}
}

// TestAPromptForBrowserRecoveryThatSucceedsResumesTheWalk pins the resume half: the actions
// after the prompt run, and the request goes out — with the jar as the operator's browser left
// it, which is the same mechanism Burp's own prompt relies on.
func TestAPromptForBrowserRecoveryThatSucceedsResumesTheWalk(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())
	c.SetSessionPrompter(&fakePrompter{recovered: true})

	rule := promptRule(promptAction(), setHeaderAction("X-After", "1"))
	mustAddRule(t, c, rule)

	fake.script("https://example.com/act", validResponse(), nil)
	outcome := c.HandleRecovery("", getStep("https://example.com/act"), invalidResponse(), fake.runner())

	if outcome.Kind != RecoveryRuleApplied {
		t.Fatalf("outcome = %v (trace: %s), want RecoveryRuleApplied — a successful prompt resumes "+
			"the walk rather than reporting a recovery no macro performed", outcome.Kind, describeTrace(outcome.Actions))
	}
	var resumed bool
	for _, a := range outcome.Actions {
		if a.Kind == ActionPromptForBrowserRecovery && strings.Contains(a.Detail, "resumed") {
			resumed = true
		}
	}
	if !resumed {
		t.Errorf("the trace does not say the walk resumed: %s", describeTrace(outcome.Actions))
	}
	sent := fake.sentSteps("https://example.com/act")
	if len(sent) != 1 {
		t.Fatalf("sent %d request(s), want 1 — the request must go out after the operator recovers "+
			"the session", len(sent))
	}
	if got := sent[0].Headers["X-After"]; got != "1" {
		t.Errorf("X-After = %q, want 1 — the action after the prompt did not run, so the walk did "+
			"not actually resume", got)
	}
}

// TestAPromptForBrowserRecoveryThatIsDeclinedStopsTheWalk pins the gate half. The operator's
// decline means "the session is not recovered", and a request that goes out anyway makes the
// action a lie — the decorative-control failure this whole unit exists to prevent.
func TestAPromptForBrowserRecoveryThatIsDeclinedStopsTheWalk(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())
	c.SetSessionPrompter(&fakePrompter{recovered: false})

	rule := promptRule(promptAction(), setHeaderAction("X-After", "1"))
	mustAddRule(t, c, rule)

	fake.script("https://example.com/act", validResponse(), nil)
	outcome := c.HandleRecovery("", getStep("https://example.com/act"), invalidResponse(), fake.runner())

	if outcome.Kind != RecoveryPromptDeclined {
		t.Fatalf("outcome = %v (trace: %s), want RecoveryPromptDeclined — a declined prompt must "+
			"not read as AlreadyValid, which says the opposite of what happened",
			outcome.Kind, describeTrace(outcome.Actions))
	}
	var said bool
	for _, a := range outcome.Actions {
		if a.Kind == ActionPromptForBrowserRecovery && strings.Contains(a.Detail, "declined") {
			said = true
		}
	}
	if !said {
		t.Errorf("the trace does not say the operator declined: %s", describeTrace(outcome.Actions))
	}
	// The action after the prompt is skipped, and the request is not re-sent: the walk stopped at
	// the gate, which is the action working as written.
	if sent := fake.sentSteps("https://example.com/act"); len(sent) != 0 {
		t.Errorf("sent %d request(s) after a decline; the request must not go out", len(sent))
	}
	var skipped bool
	for _, a := range outcome.Actions {
		if a.Kind == ActionSetHeader && strings.Contains(a.Skipped, "no further actions") {
			skipped = true
		}
	}
	if !skipped {
		t.Errorf("the action after a declined prompt was not skipped: %s", describeTrace(outcome.Actions))
	}
}

// TestAPromptForBrowserRecoveryWithNoConsoleStopsTheWalkAndSaysSo is the headless case: a
// process with nobody at the console must not silently send the request the operator put the
// action there to gate. The walk stops and the trace says the operator was never asked — a
// different fact from a decline, and the distinction is the operator's to read.
func TestAPromptForBrowserRecoveryWithNoConsoleStopsTheWalkAndSaysSo(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())
	// Deliberately no SetSessionPrompter: nil is the state a headless run is in.

	if c.PrompterAttached() {
		t.Fatal("PrompterAttached() is true on a fresh coordinator; the no-console case cannot be tested")
	}

	rule := promptRule(promptAction())
	mustAddRule(t, c, rule)

	fake.script("https://example.com/act", validResponse(), nil)
	outcome := c.HandleRecovery("", getStep("https://example.com/act"), invalidResponse(), fake.runner())

	if outcome.Kind != RecoveryPromptDeclined {
		t.Fatalf("outcome = %v (trace: %s), want RecoveryPromptDeclined — with no console to ask, "+
			"the gate holds and the request must not be reported as already valid",
			outcome.Kind, describeTrace(outcome.Actions))
	}
	var said string
	for _, a := range outcome.Actions {
		if a.Kind == ActionPromptForBrowserRecovery {
			said = a.Detail
		}
	}
	if !strings.Contains(said, "no console is attached") {
		t.Errorf("the trace does not say the operator was never asked: %q", said)
	}
	if sent := fake.sentSteps("https://example.com/act"); len(sent) != 0 {
		t.Errorf("sent %d request(s) with no console attached; the request must not go out", len(sent))
	}
}

// TestAPromptForBrowserRecoveryWithChildrenIsRefused pins the validator's half of the acceptance
// criteria: only a validity check has conditional sub-actions, and a prompt that carried a branch
// would be a rule whose editor shows one thing and whose executor ignores it.
func TestAPromptForBrowserRecoveryWithChildrenIsRefused(t *testing.T) {
	rule := NewSessionRule("misplaced children", []string{"example.com"}, nil)
	rule.Actions = []*Action{{
		Kind: ActionPromptForBrowserRecovery, Enabled: true,
		Then: []*Action{promptAction()},
	}}

	err := ValidateRule(rule)
	if err == nil || !strings.Contains(err.Error(), "conditional sub-actions") {
		t.Fatalf("ValidateRule = %v, want a refusal naming the conditional sub-actions", err)
	}
}
