package session

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

// ---- The action list (burpsy-react-ui-ayi) ------------------------------------------------------
//
// Each test here fails without the action model, and each one is about a thing an operator could not
// do before: write a rule that is not a login macro, put two actions in one rule in a stated order,
// carry a value a macro extracted into the outgoing request, or turn off the rest of a list from
// inside an action.
//
// The migration tests are the other half. A rule nobody has edited must run exactly what it ran
// before actions existed, and the cheapest way to check that is not to re-assert the old outcomes
// (recovery_test.go already does, and it passes unchanged) but to assert that the synthesised list
// *is* the old flow.

// stepsWithPrefix is sentSteps for a request an action rewrote. An action that changes the URL makes
// the exact-string lookup miss, and a test that asserts "nothing was sent" would then pass because
// the rewrite worked — the opposite of what it means.
func (f *fakeSender) stepsWithPrefix(prefix string) []MacroStep {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []MacroStep
	for _, s := range f.calls {
		if strings.HasPrefix(s.URL, prefix) {
			out = append(out, s)
		}
	}
	return out
}

func setHeaderAction(name, value string) *Action {
	return &Action{Kind: ActionSetHeader, Enabled: true, Name: name, Value: value}
}

func setParamAction(name, value, in string) *Action {
	return &Action{Kind: ActionSetParam, Enabled: true, Name: name, Value: value, In: in}
}

func runMacroAction() *Action { return &Action{Kind: ActionRunMacro, Enabled: true} }

// TestARuleOfStandingActionsNeedsNoMacro is the capability that was missing at its simplest: a rule
// that is not a login. Before the action list the only thing a rule could be was "check validity,
// then replay the macro", so a rule that merely sets a header was unrepresentable — and the
// validation refused it outright for having no macro steps.
func TestARuleOfStandingActionsNeedsNoMacro(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())

	rule := NewSessionRule("stamp a header", []string{"example.com"}, nil)
	rule.Actions = []*Action{setHeaderAction("X-Operator", "burpsy")}
	mustAddRule(t, c, rule)

	// The rule states no validity rule, so the actions have to speak for themselves: the request
	// must go out rewritten and the outcome must say a rewrite happened, not that a session was
	// established.
	fake.script("https://example.com/account", validResponse(), nil)
	outcome := c.HandleRecovery("", getStep("https://example.com/account"), invalidResponse(), fake.runner())

	if outcome.Kind != RecoveryRuleApplied {
		t.Fatalf("outcome = %v, want RecoveryRuleApplied — no login was attempted, and reporting a "+
			"recovery would tell the operator a session was established", outcome.Kind)
	}
	sent := fake.sentSteps("https://example.com/account")
	if len(sent) != 1 {
		t.Fatalf("sent %d request(s), want 1 — the rewritten request was not re-sent, so the header "+
			"never reached the target", len(sent))
	}
	if got := sent[0].Headers["X-Operator"]; got != "burpsy" {
		t.Errorf("the target received X-Operator %q, want burpsy", got)
	}
	if len(outcome.Actions) == 0 {
		t.Error("the outcome carries no action trace, so the operator cannot see which actions ran")
	}
}

// TestTheTokenFromAMacroReachesTheNextAction is the CSRF recipe, which is the reason this unit
// exists: "run a macro to fetch a token, then set that token as a named parameter on the outgoing
// request". Before the action list an operator could run the macro and had nowhere to put the token.
func TestTheTokenFromAMacroReachesTheNextAction(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())

	rule := NewSessionRule("refresh the CSRF token", []string{"example.com"}, []MacroStep{
		{Method: "GET", URL: "https://example.com/token"},
	})
	rule.Validity = &ValidityRule{HeaderPresent: "X-Auth"}
	ext, err := NewExtraction("csrf", "body", `token=(.+)`, 1)
	if err != nil {
		t.Fatalf("NewExtraction: %v", err)
	}
	rule.Extractions = []*Extraction{ext}
	rule.Actions = []*Action{
		runMacroAction(),
		setParamAction("csrf", "{{csrf}}", "query"),
	}
	mustAddRule(t, c, rule)

	fake.script("https://example.com/token",
		&StepResult{Status: 200, Headers: map[string]string{"X-Auth": "1"}, Body: []byte("token=abc123")}, nil)
	// The retried original, scripted under the URL the actions produced rather than the one the request
	// arrived with: a fake keyed by the original would fail with "no script queued" and read as a
	// broken action, and the rewrite is the thing under test. The rule's check says valid, so the
	// walk reports Recovered.
	fake.script("https://example.com/act?csrf=abc123", validResponse(), nil)

	outcome := c.HandleRecovery("", getStep("https://example.com/act"), invalidResponse(), fake.runner())
	if outcome.Kind != RecoveryRecovered {
		t.Fatalf("outcome = %v (trace: %s), want RecoveryRecovered", outcome.Kind, describeTrace(outcome.Actions))
	}
	// Prefix-matched, because the action under test is the one that rewrote the URL.
	sent := fake.stepsWithPrefix("https://example.com/act")
	if len(sent) != 1 {
		t.Fatalf("sent %d request(s) to /act, want 1", len(sent))
	}
	if !strings.Contains(sent[0].URL, "csrf=abc123") {
		t.Errorf("the target received %q; the token the macro extracted never reached the action that "+
			"was supposed to write it — which is the half of the recipe that did not exist before",
			sent[0].URL)
	}
}

// TestActionsSeeEachOtherSPreviousWrites pins the meaning of "in sequence": a Replace after a
// SetParam rewrites the parameter the first action set, not the request as it arrived. If each action
// were applied to the original, the order would be decorative.
func TestActionsSeeEachOthersPreviousWrites(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())

	rule := NewSessionRule("set then rewrite", []string{"example.com"}, nil)
	rule.Actions = []*Action{
		setParamAction("role", "user", "query"),
		{Kind: ActionReplace, Enabled: true, Match: "role=user", Replacement: "role=admin"},
	}
	mustAddRule(t, c, rule)

	fake.script("https://example.com/act?role=admin", validResponse(), nil)
	c.HandleRecovery("", getStep("https://example.com/act"), nil, fake.runner())

	// Matched by prefix: the action rewrote the URL, so the exact-string lookup the other tests use
	// would find nothing and the assertion would pass for the wrong reason.
	sent := fake.stepsWithPrefix("https://example.com/act")
	if len(sent) != 1 {
		t.Fatalf("sent %d request(s), want 1", len(sent))
	}
	if !strings.Contains(sent[0].URL, "role=admin") {
		t.Errorf("target received %q, want the Replace action to have rewritten the parameter the "+
			"SetParam action just set", sent[0].URL)
	}
}

// TestAnActionThatStopsTheListReallyStopsIt — Burp's "unless one of the actions specifies that no
// further actions should be applied to the request". The trace has to say so, because a stop that
// only shows as a missing trace entry is indistinguishable from an action that crashed.
func TestAnActionThatStopsTheListReallyStopsIt(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())

	rule := NewSessionRule("stop early", []string{"example.com"}, nil)
	rule.Actions = []*Action{
		{Kind: ActionSetHeader, Enabled: true, Name: "X-First", Value: "1", Stop: true},
		setHeaderAction("X-Second", "2"),
	}
	mustAddRule(t, c, rule)

	fake.script("https://example.com/act", validResponse(), nil)
	outcome := c.HandleRecovery("", getStep("https://example.com/act"), nil, fake.runner())

	sent := fake.sentSteps("https://example.com/act")
	if len(sent) != 1 {
		t.Fatalf("sent %d request(s), want 1", len(sent))
	}
	if got := sent[0].Headers["X-First"]; got != "1" {
		t.Errorf("X-First = %q, want 1", got)
	}
	if got, present := sent[0].Headers["X-Second"]; present {
		t.Errorf("X-Second = %q; an action carrying \"no further actions\" was ignored", got)
	}
	var saidSo bool
	for _, a := range outcome.Actions {
		if strings.Contains(a.Skipped, "no further actions") {
			saidSo = true
		}
	}
	if !saidSo {
		t.Errorf("the trace does not say the list was stopped: %s", describeTrace(outcome.Actions))
	}
}

// TestIndeterminateTakesTheNotValidBranch states the direction this fails in. The pre-action code
// treated anything that was not Valid as a reason to try logging in, on the stated grounds that
// reading "I could not tell whether this session is alive" as "it is fine" is the wrong way to fail.
// A rule whose check cannot decide must keep trying to authenticate.
func TestIndeterminateTakesTheNotValidBranch(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())

	rule := NewSessionRule("recover when unsure", []string{"example.com"}, []MacroStep{
		getStep("https://example.com/login"),
	})
	// A status the rule requires, observed against a response that has no status at all: Evaluate
	// answers Indeterminate, not Invalid and not Valid — the state a request whose response never
	// arrived leaves behind, and the one this direction of failure is about.
	rule.Validity = &ValidityRule{StatusIs: intPtr(200)}
	rule.Actions = []*Action{{
		Kind: ActionCheckValidity, Enabled: true,
		Else: []*Action{runMacroAction()},
	}}
	mustAddRule(t, c, rule)

	fake.script("https://example.com/login", validResponse(), nil)
	fake.script("https://example.com/act", validResponse(), nil)

	unmeasured := &StepResult{Status: 0}
	outcome := c.HandleRecovery("", getStep("https://example.com/act"), unmeasured, fake.runner())

	if fake.callCount("https://example.com/login") != 1 {
		t.Errorf("the macro ran %d time(s); an indeterminate check must take the not-valid branch and "+
			"try to re-authenticate", fake.callCount("https://example.com/login"))
	}
	if outcome.Kind != RecoveryRecovered {
		t.Errorf("outcome = %v (trace: %s), want RecoveryRecovered", outcome.Kind, describeTrace(outcome.Actions))
	}
}

// TestTheJarCanBeAddedAsAnExplicitStep: the jar attach used to be implicit in the send path, so a
// rule could not say *when* it happened relative to a macro — which matters when a macro rewrites
// the cookie the request should carry.
func TestTheJarCanBeAddedAsAnExplicitStep(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())
	// A raw response, because that is the shape the jar absorbs: the header-line form is what a
	// response actually is, and the map-shaped variant can carry only one Set-Cookie.
	c.AbsorbResponseCookies("example.com", 443, true,
		[]byte("HTTP/1.1 200 OK\r\nSet-Cookie: SESSION=live\r\n\r\n"))

	rule := NewSessionRule("carry the jar", []string{"example.com"}, nil)
	rule.Actions = []*Action{{Kind: ActionAddCookiesFromJar, Enabled: true}}
	mustAddRule(t, c, rule)

	fake.script("https://example.com/act", validResponse(), nil)
	c.HandleRecovery("", getStep("https://example.com/act"), nil, fake.runner())

	sent := fake.sentSteps("https://example.com/act")
	if len(sent) != 1 {
		t.Fatalf("sent %d request(s), want 1", len(sent))
	}
	if got := sent[0].Headers["Cookie"]; !strings.Contains(got, "SESSION=live") {
		t.Errorf("Cookie header = %q; the add-cookies-from-jar action did not attach the jar", got)
	}
}

// TestAnInvokeExtensionActionWithNoHostSaysSo: an operator who names an extension on a build with no
// extension host must be told nothing was invoked. The alternative — a rule that reports success
// while sending the request it would have sent anyway — is the decorative-control failure.
func TestAnInvokeExtensionActionWithNoHostSaysSo(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())

	rule := NewSessionRule("ask an extension", []string{"example.com"}, nil)
	rule.Actions = []*Action{
		{Kind: ActionInvokeExtension, Enabled: true, Extension: "session.sign"},
		setHeaderAction("X-After", "1"),
	}
	mustAddRule(t, c, rule)

	fake.script("https://example.com/act", validResponse(), nil)
	outcome := c.HandleRecovery("", getStep("https://example.com/act"), nil, fake.runner())

	var refusal string
	for _, a := range outcome.Actions {
		if a.Kind == ActionInvokeExtension {
			refusal = a.Detail
		}
	}
	if refusal == "" || !strings.Contains(refusal, "no extension host") {
		t.Errorf("the trace does not report that nothing was invoked: %s", describeTrace(outcome.Actions))
	}
	// And the walk continues past it: one action that cannot run must not silently disable the rest
	// of the rule, which is the difference between a partial rule and a rule that stopped working.
	sent := fake.sentSteps("https://example.com/act")
	if len(sent) != 1 || sent[0].Headers["X-After"] != "1" {
		t.Errorf("the actions after a refused extension invocation did not run")
	}
}

// ---- migration -----------------------------------------------------------------------------------

// TestTheSynthesisedListIsThePreActionFlow is the migration's whole claim, asserted directly rather
// than through the outcomes the old tests already cover: a rule with no explicit actions runs a
// validity check whose else-branch runs the macro, and nothing else.
func TestTheSynthesisedListIsThePreActionFlow(t *testing.T) {
	rule := authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3)

	actions := rule.EffectiveActions()
	if len(actions) != 1 || actions[0].Kind != ActionCheckValidity {
		t.Fatalf("synthesised %d action(s) starting with %v, want one validity check",
			len(actions), actions[0].Kind)
	}
	if len(actions[0].Then) != 0 {
		t.Errorf("the synthesised check has %d then-branch action(s); a valid session ran nothing before",
			len(actions[0].Then))
	}
	if len(actions[0].Else) != 1 || actions[0].Else[0].Kind != ActionRunMacro {
		t.Fatalf("the synthesised check's else branch is %v, want exactly one run-a-macro action",
			actions[0].Else)
	}
}

// TestAddRuleMaterialisesTheActionList: the conversion happens once, at the door, so nothing
// downstream has to remember that an empty list means something.
func TestAddRuleMaterialisesTheActionList(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := authRule([]string{"example.com"}, []MacroStep{getStep("https://example.com/login")}, 3)
	id := mustAddRule(t, c, rule)

	stored := c.Rule(id)
	if stored == nil || len(stored.Actions) == 0 {
		t.Fatal("the rule reached the coordinator with no action list, so every reader would have to " +
			"know that an empty list means the pre-action flow")
	}
	if stored.Actions[0].Kind != ActionCheckValidity {
		t.Errorf("materialised list starts with %v, want the validity check", stored.Actions[0].Kind)
	}
}

// ---- validation ----------------------------------------------------------------------------------

// TestAValueNamingAValueNothingExtractsIsRefused: the CSRF action's value is a placeholder, so it is
// the one field in a rule that could name a value that never arrives. On the wire it would go out
// verbatim (or empty), which reads as the target rejecting a real attempt.
func TestAValueNamingAValueNothingExtractsIsRefused(t *testing.T) {
	rule := NewSessionRule("typo", []string{"example.com"}, []MacroStep{getStep("https://example.com/login")})
	rule.Validity = &ValidityRule{HeaderPresent: "X-Auth"}
	ext, err := NewExtraction("csrf", "body", `token=(.+)`, 1)
	if err != nil {
		t.Fatalf("NewExtraction: %v", err)
	}
	rule.Extractions = []*Extraction{ext}
	rule.Actions = []*Action{
		runMacroAction(),
		setParamAction("csrf", "{{csrff}}", "query"),
	}

	err = ValidateRule(rule)
	if err == nil {
		t.Fatal("a rule whose action value names {{csrff}}, which nothing extracts, was accepted")
	}
	if !strings.Contains(err.Error(), "{{csrff}}") {
		t.Errorf("the refusal does not name the placeholder: %v", err)
	}
}

// TestAKindOnlyFieldOnTheRightKindIsRefused: a conditional branch on an action that is not a check
// would be silently ignored, which is a rule whose editor shows one thing and whose executor does
// another.
func TestAKindOnlyFieldOnTheRightKindIsRefused(t *testing.T) {
	rule := NewSessionRule("misplaced children", []string{"example.com"}, nil)
	rule.Actions = []*Action{{
		Kind: ActionSetHeader, Enabled: true, Name: "X-A", Value: "1",
		Else: []*Action{setHeaderAction("X-B", "2")},
	}}

	err := ValidateRule(rule)
	if err == nil || !strings.Contains(err.Error(), "conditional sub-actions") {
		t.Fatalf("ValidateRule = %v, want a refusal naming the conditional sub-actions", err)
	}
}

func TestAnActionMissingItsKindsRequiredFieldIsRefused(t *testing.T) {
	rule := NewSessionRule("nameless header", []string{"example.com"}, nil)
	rule.Actions = []*Action{{Kind: ActionSetHeader, Enabled: true, Value: "1"}}

	err := ValidateRule(rule)
	if err == nil || !strings.Contains(err.Error(), "header name") {
		t.Fatalf("ValidateRule = %v, want a refusal naming the missing header name", err)
	}
}

// TestEveryActionKindHasAWireName walks the enum, so a kind added without a name is a failure here
// rather than a rule that reads back as a different action. Same shape as the target round-trip test
// in internal/web.
func TestEveryActionKindHasAWireName(t *testing.T) {
	if ActionKindCount == 0 {
		t.Fatal("ActionKindCount is zero, so the enum is empty and this test asserts nothing")
	}
	for i := 0; i < int(ActionKindCount); i++ {
		kind := ActionKind(i)
		name := ActionKindName(kind)
		if strings.HasPrefix(name, "unrecognised") {
			t.Errorf("action kind %d has no wire name", i)
		}
		back, err := ParseActionKind(name)
		if err != nil || back != kind {
			t.Errorf("kind %d names %q on the wire and parses back as %v (%v)", i, name, back, err)
		}
		if ActionKindLabel(kind) == "" {
			t.Errorf("action kind %d has no label", i)
		}
	}
	if _, err := ParseActionKind("no_such_action"); err == nil {
		t.Error("an unknown action kind was accepted; a rule would then read back as a different action")
	}
}

func intPtr(v int) *int { return &v }

func describeTrace(trace []ActionRan) string {
	var b strings.Builder
	for _, a := range trace {
		b.WriteString("\n    ")
		b.WriteString(a.Label)
		if a.Detail != "" {
			b.WriteString(": ")
			b.WriteString(a.Detail)
		}
		if a.Skipped != "" {
			b.WriteString(" [skipped: ")
			b.WriteString(a.Skipped)
			b.WriteString("]")
		}
	}
	return b.String()
}

// TestASetCookieActionReachesTheWire pins the action against the send path that used to erase it.
//
// The action wrote its cookie into the request's Cookie header and the trace said so, but
// sendWithJar re-derives that whole header from the cookie jar on the way out (applyJar drops any
// Cookie header it finds, by design, so a recorded macro step's stale capture cannot reach the
// wire). A set_cookie action is not a stale capture — it is the operator stating what this request
// carries — and it was being deleted between the trace and the target. Found live, not by reading:
// the trace said "set cookie flavour=oatmeal" and the target received `Cookie: sid=sess-abc123`.
//
// Asserted on what the sender received, never on the walk's own request, because the whole defect
// lived downstream of the walk: a test reading w.request would have passed throughout.
func TestASetCookieActionReachesTheWire(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())

	// A jar cookie for the same host, so this also pins the part that makes the action useful rather
	// than merely present: the rule's own cookie has to ride *alongside* the session, not replace it.
	c.jarMgr.AbsorbSetCookie("example.com", 443, true, "sid=sess-abc123; Path=/")

	rule := NewSessionRule("stamp a cookie", []string{"example.com"}, nil)
	rule.Actions = []*Action{
		{Kind: ActionSetCookie, Enabled: true, Name: "flavour", Value: "oatmeal"},
	}
	mustAddRule(t, c, rule)

	fake.script("https://example.com/account", validResponse(), nil)
	outcome := c.HandleRecovery("", getStep("https://example.com/account"), invalidResponse(), fake.runner())

	sent := fake.sentSteps("https://example.com/account")
	if len(sent) != 1 {
		t.Fatalf("sent %d request(s), want 1 — outcome %v; the rewritten request was never re-sent, "+
			"so no cookie could have reached the target", len(sent), outcome.Kind)
	}
	got := sent[0].Headers["Cookie"]
	if !strings.Contains(got, "flavour=oatmeal") {
		t.Errorf("the target received Cookie %q, which does not carry the cookie the rule set. The "+
			"action reported success and the send path dropped it — a rule action that does nothing "+
			"while saying it did is worse than one that is absent, because the operator stops looking.", got)
	}
	if !strings.Contains(got, "sid=sess-abc123") {
		t.Errorf("the target received Cookie %q, which lost the jar's session cookie. A set_cookie "+
			"action must add to the session, not replace it, or the request goes out unauthenticated.", got)
	}
}

// TestAnActionThatOnlyRewritesHeadersIsStillSent pins the aliasing defect that made a whole class of
// rule silent.
//
// MacroStep is a struct whose Headers is a map, so `before := w.request` shares the map and every
// "did this action change anything" comparison in the walk was comparing a map with itself. recover()
// reads the same answer at the whole-walk level and returns AlreadyValid *without sending* when
// nothing changed — so a rule whose actions only touch headers did all its work and never put it on
// the wire.
//
// The request here starts with a header already on it, and that is the entire point: with nil
// headers the walk allocates a fresh map and the comparison accidentally succeeds, which is why
// TestARuleOfStandingActionsNeedsNoMacro passed throughout and this defect survived. Any test whose
// fixture starts from an empty header map cannot see it.
func TestAnActionThatOnlyRewritesHeadersIsStillSent(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())

	rule := NewSessionRule("stamp a header", []string{"example.com"}, nil)
	rule.Actions = []*Action{setHeaderAction("X-CSRF", "tok-9f3a")}
	mustAddRule(t, c, rule)

	probe := getStep("https://example.com/account")
	probe.Headers = map[string]string{"User-Agent": "burpsy-test"}

	fake.script("https://example.com/account", validResponse(), nil)
	outcome := c.HandleRecovery("", probe, invalidResponse(), fake.runner())

	if outcome.Kind == RecoveryAlreadyValid {
		t.Fatalf("outcome = RecoveryAlreadyValid: the walk reported that its actions changed nothing, " +
			"so the rewritten request was never sent. The rule set a header and the operator is told " +
			"the session was already fine.")
	}
	sent := fake.sentSteps("https://example.com/account")
	if len(sent) != 1 {
		t.Fatalf("sent %d request(s), want 1 — outcome %v", len(sent), outcome.Kind)
	}
	if got := sent[0].Headers["X-CSRF"]; got != "tok-9f3a" {
		t.Errorf("the target received X-CSRF %q, want tok-9f3a", got)
	}
	// The pre-existing header must survive: an action that set one header and dropped another would
	// satisfy the assertion above while breaking the request.
	if got := sent[0].Headers["User-Agent"]; got != "burpsy-test" {
		t.Errorf("the target received User-Agent %q, want the one the request arrived with", got)
	}
	if len(outcome.Actions) != 1 || !outcome.Actions[0].Changed {
		t.Errorf("the trace reports %+v; the set-header action changed the request and must say so, "+
			"because Changed is what recover() uses to decide whether to send at all", outcome.Actions)
	}
}
