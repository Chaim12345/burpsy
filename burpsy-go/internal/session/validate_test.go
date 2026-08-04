package session

import (
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// These mirror the *intent* of crates/session/src/rule.rs's own tests: every mistake the Rust crate
// refuses at construction time has to be refused here too, and the refusal has to name the rule and
// the step so the message is something an operator can act on.

func validSpec() *SessionRule {
	rule := NewSessionRule("admin login", nil, []MacroStep{getStep("https://target.test/login")})
	status := 200
	rule.Validity = &ValidityRule{StatusIs: &status}
	return rule
}

func TestARuleWithNoScopeAppliesEverywhere(t *testing.T) {
	rule := validSpec()
	if err := ValidateRule(rule); err != nil {
		t.Fatalf("a rule with no scope must be valid: %v", err)
	}
	// The bug this pins: an unscoped rule used to match nothing at all, so a rule the operator created
	// without a host restriction was enabled, listed, and silently dead.
	for _, host := range []string{"target.test", "anything.test", ""} {
		if !rule.MatchHost(host) {
			t.Fatalf("MatchHost(%q) = false; a rule with no scope hosts applies everywhere", host)
		}
	}
}

func TestAScopedRuleOnlyMatchesTheHostsItNames(t *testing.T) {
	rule := NewSessionRule("scoped", []string{"staging.test"}, []MacroStep{getStep("https://staging.test/login")})
	if !rule.MatchHost("staging.test") {
		t.Fatal("a scoped rule must match the host it names")
	}
	if rule.MatchHost("prod.test") {
		t.Fatal("a scoped rule must not match a host it does not name")
	}
	if rule.MatchHost("") {
		t.Fatal("a scoped rule cannot claim a target whose host could not be read")
	}
}

func TestAScopeStatedButEmptyIsRefusedBecauseItWouldSilentlyDisableTheRule(t *testing.T) {
	rule := validSpec()
	// Stated and empty: the operator asked for "restrict this to nothing", which matches nothing.
	err := ValidateRuleStatedScope(rule, true)
	if err == nil {
		t.Fatal("a stated but empty scope must be refused")
	}
	if !strings.Contains(err.Error(), "matches nothing") {
		t.Fatalf("error = %q, want it to say the scope matches nothing", err)
	}
	var re *RuleError
	if !errors.As(err, &re) || re.Rule != "admin login" {
		t.Fatalf("error must be a *RuleError naming the rule, got %#v", err)
	}
	// Not stated at all is the "applies everywhere" case and stays fine.
	if err := ValidateRuleStatedScope(rule, false); err != nil {
		t.Fatalf("an omitted scope must apply everywhere, got %v", err)
	}
}

func TestAnUnnamedRuleAZeroAttemptBoundAndAnEmptyMacroAreAllRefused(t *testing.T) {
	unnamed := validSpec()
	unnamed.Name = "   "
	err := ValidateRule(unnamed)
	if err == nil || !strings.Contains(err.Error(), "needs a name") {
		t.Fatalf("error = %v, want it to say a rule needs a name", err)
	}
	var re *RuleError
	if !errors.As(err, &re) || re.Rule != "<unnamed>" {
		t.Fatalf("an unnamed rule must be reported as %q, got %#v", "<unnamed>", err)
	}

	zeroAttempts := validSpec()
	zeroAttempts.MaxAttempts = 0
	if err := ValidateRule(zeroAttempts); err == nil || !strings.Contains(err.Error(), "at least 1") {
		t.Fatalf("error = %v, want max_attempts to be refused below 1", err)
	}

	empty := validSpec()
	empty.Steps = nil
	if err := ValidateRule(empty); err == nil || !strings.Contains(err.Error(), "no steps") {
		t.Fatalf("error = %v, want an empty macro to be refused", err)
	}
}

func TestAStepWithNoMethodOrNoHostIsRefusedAtConfigurationTime(t *testing.T) {
	noMethod := validSpec()
	noMethod.Steps[0].Method = " "
	if err := ValidateRule(noMethod); err == nil || !strings.Contains(err.Error(), "empty method") {
		t.Fatalf("error = %v, want a step with no method to be refused", err)
	}

	noHost := validSpec()
	noHost.Steps[0].URL = "/login"
	err := ValidateRule(noHost)
	if err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("error = %v, want a hostless step url to be refused", err)
	}
	if !strings.Contains(err.Error(), "step 0") {
		t.Fatalf("error = %q, want the step index named", err)
	}
}

func TestAPlaceholderNoEarlierStepExtractsIsRefused(t *testing.T) {
	rule := validSpec()
	rule.Steps = []MacroStep{
		getStep("https://target.test/login"),
		getStep("https://target.test/act?csrf={{csrf}}"),
	}
	err := ValidateRule(rule)
	if err == nil {
		t.Fatal("a reference to a value nothing extracts must be refused")
	}
	if !strings.Contains(err.Error(), "{{csrf}}") || !strings.Contains(err.Error(), "step 1") {
		t.Fatalf("error = %q, want it to name step 1 and {{csrf}}", err)
	}
}

func TestAPlaceholderDefinedByAnEarlierStepIsAccepted(t *testing.T) {
	rule := validSpec()
	rule.Steps = []MacroStep{
		getStep("https://target.test/login"),
		{Method: "POST", URL: "https://target.test/act?csrf={{csrf}}", Headers: map[string]string{"X-CSRF": "{{csrf}}"}, Body: "csrf={{csrf}}"},
	}
	rule.Extractions = []*Extraction{mustExtraction(t, "csrf", "body", `tok-([a-z0-9]+)`, 1, 0)}
	if err := ValidateRule(rule); err != nil {
		t.Fatalf("a value produced before it is used must be accepted: %v", err)
	}
}

func TestAStepCannotReferToAValueExtractedFromItsOwnResponse(t *testing.T) {
	// Resolution happens immediately before a step is sent, so its own response does not exist yet.
	rule := validSpec()
	rule.Steps = []MacroStep{getStep("https://target.test/act?csrf={{csrf}}")}
	rule.Extractions = []*Extraction{mustExtraction(t, "csrf", "body", `tok-([a-z0-9]+)`, 1, 0)}
	err := ValidateRule(rule)
	if err == nil || !strings.Contains(err.Error(), "no earlier step extracts") {
		t.Fatalf("error = %v, want a self-reference to be refused", err)
	}
}

func TestTwoExtractionsWithTheSameNameAreRefused(t *testing.T) {
	rule := validSpec()
	rule.Steps = []MacroStep{
		getStep("https://target.test/a"),
		getStep("https://target.test/b"),
	}
	rule.Extractions = []*Extraction{
		mustExtraction(t, "csrf", "body", `a-(.+)`, 1, 0),
		mustExtraction(t, "csrf", "body", `b-(.+)`, 1, 1),
	}
	err := ValidateRule(rule)
	if err == nil || !strings.Contains(err.Error(), "already extracts") {
		t.Fatalf("error = %v, want a duplicate extraction name to be refused", err)
	}
	// Which step clashed with which is the actionable part of the message.
	if !strings.Contains(err.Error(), "step 1") || !strings.Contains(err.Error(), "step 0 already") {
		t.Fatalf("error = %q, want it to name the second step and the first", err)
	}
}

func TestAnExtractionReadingAStepThatDoesNotExistIsRefused(t *testing.T) {
	rule := validSpec()
	rule.Extractions = []*Extraction{mustExtraction(t, "csrf", "body", `tok-(.+)`, 1, 3)}
	err := ValidateRule(rule)
	if err == nil || !strings.Contains(err.Error(), "reads step 3") {
		t.Fatalf("error = %v, want an out-of-range extraction step to be refused", err)
	}
}

func TestAnUncompiledOrUnusableExtractionPatternIsRefusedAndNamesItsStep(t *testing.T) {
	// Hand-built and never compiled: it would run and silently return nothing.
	rule := validSpec()
	rule.Extractions = []*Extraction{{Name: "csrf", From: "body", Pattern: `tok-(.+)`, Group: 1}}
	err := ValidateRule(rule)
	if err == nil || !strings.Contains(err.Error(), "uncompiled pattern") {
		t.Fatalf("error = %v, want an uncompiled extraction to be refused", err)
	}

	// A pattern the operator typed that cannot compile is their mistake, reported as such.
	broken := validSpec()
	broken.Extractions = []*Extraction{{Name: "csrf", From: "body", Pattern: `([unclosed`, Group: 1}}
	err = ValidateRule(broken)
	if err == nil || !strings.Contains(err.Error(), "unusable pattern") {
		t.Fatalf("error = %v, want an uncompilable pattern to be refused", err)
	}
	if !strings.Contains(err.Error(), "step 0") {
		t.Fatalf("error = %q, want the step index named", err)
	}
}

func TestAnExtractionNameNoPlaceholderCouldReferToIsRefused(t *testing.T) {
	rule := validSpec()
	rule.Extractions = []*Extraction{mustExtraction(t, "session token", "body", `tok-(.+)`, 1, 0)}
	err := ValidateRule(rule)
	if err == nil || !strings.Contains(err.Error(), "no {{placeholder}} could refer to") {
		t.Fatalf("error = %v, want an unreferable extraction name to be refused", err)
	}
}

func TestPlaceholdersAreFoundAcrossUrlHeadersAndBodyAndBracesThatNameNothingAreIgnored(t *testing.T) {
	step := MacroStep{
		Method:  "POST",
		URL:     "https://t.test/{{a}}",
		Headers: map[string]string{"X-One": "{{b}}", "{{c}}": "v"},
		Body:    "x={{a}}&y={{b}}",
	}
	got := placeholderNames(step)
	want := map[string]bool{"a": true, "b": true, "c": true}
	if len(got) != 3 {
		t.Fatalf("placeholderNames = %v, want exactly a, b, c once each", got)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("placeholderNames = %v, unexpected %q", got, n)
		}
	}
	// `{{}}` and `{{ a }}` name nothing an extraction could ever be called, so reporting them as
	// undefined references would be an error the operator has no way to satisfy.
	if got := placeholderNames(MacroStep{URL: "https://t.test/{{}}/{{ a }}/{{ok}}"}); len(got) != 1 || got[0] != "ok" {
		t.Fatalf("placeholderNames = %v, want only the referable token", got)
	}
}

func TestAddRuleAndUpdateRuleBothRefuseAnInvalidRule(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	bad := validSpec()
	bad.MaxAttempts = 0
	if _, err := c.AddRule(bad); err == nil {
		t.Fatal("AddRule must validate: an unrunnable rule cannot be installed")
	}
	if len(c.AllRules()) != 0 {
		t.Fatalf("a refused rule must not be installed, got %d rules", len(c.AllRules()))
	}

	id := mustAddRule(t, c, validSpec())
	edit := validSpec()
	edit.Steps[0].URL = "/relative"
	if err := c.UpdateRule(id, edit); err == nil {
		t.Fatal("UpdateRule must validate: an edit can install an unrunnable rule as easily as a create")
	}
	// The rule that was working is still the one installed.
	if got := c.Rule(id).Steps[0].URL; got != "https://target.test/login" {
		t.Fatalf("stored step url = %q, want the refused edit not to have been applied", got)
	}
	if err := c.UpdateRule(RuleID(999), validSpec()); !errors.Is(err, ErrNoSuchRule) {
		t.Fatalf("UpdateRule on an unknown id = %v, want ErrNoSuchRule", err)
	}
}

func TestAnExtractionRunsOnlyAgainstItsOwnStepsResponse(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	status := 200
	rule := NewSessionRule("two tokens", nil, []MacroStep{
		getStep("https://t.test/first"),
		getStep("https://t.test/second"),
		getStep("https://t.test/use?a={{a}}&b={{b}}"),
	})
	rule.Validity = &ValidityRule{StatusIs: &status}
	// Both patterns would match both responses. Only the step each is attached to may feed it, or
	// which value a {{name}} carries would depend on which response happened to match first.
	rule.Extractions = []*Extraction{
		mustExtraction(t, "a", "body", `tok=(\w+)`, 1, 0),
		mustExtraction(t, "b", "body", `tok=(\w+)`, 1, 1),
	}
	if err := ValidateRule(rule); err != nil {
		t.Fatalf("ValidateRule: %v", err)
	}

	var sentURLs []string
	runner := func(step MacroStep) (*StepResult, error) {
		sentURLs = append(sentURLs, step.URL)
		switch {
		case strings.HasSuffix(step.URL, "/first"):
			return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("tok=one")}, nil
		case strings.HasSuffix(step.URL, "/second"):
			return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("tok=two")}, nil
		default:
			return &StepResult{Status: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
		}
	}
	sent, _, state := c.RunMacro(rule, runner)
	if state != Valid {
		t.Fatalf("state = %v, want Valid", state)
	}
	if got := sent[2].URL; got != "https://t.test/use?a=one&b=two" {
		t.Fatalf("third step url = %q, want each extraction to carry its own step's value", got)
	}
	if len(sentURLs) != 3 {
		t.Fatalf("sent %d steps, want 3 (an unscoped rule must not skip its own macro)", len(sentURLs))
	}
}

// mustExtraction builds a compiled extraction bound to `step`, failing the test on a pattern that does
// not compile.
func mustExtraction(t *testing.T, name, from, pattern string, group, step int) *Extraction {
	t.Helper()
	ex, err := NewExtraction(name, from, pattern, group)
	if err != nil {
		t.Fatalf("NewExtraction(%q): %v", name, err)
	}
	ex.Step = step
	return ex
}
