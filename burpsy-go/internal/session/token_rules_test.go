package session

// The project-level extraction+injection set (burpsy-react-ui-xe82): a value lifted from ANY
// observed response - no login macro - is injected into later matching requests across tools.
// These tests pin the acceptance flow end to end at coordinator level: a token extracted from a
// login response is injected into a subsequent Repeater/scanner request without the operator
// pasting it.

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

func tokenRuleForTest(t *testing.T) *TokenRule {
	t.Helper()
	ex, err := NewExtraction("csrf", "body", `name="csrf" value="([^"]+)"`, 1)
	if err != nil {
		t.Fatalf("build extraction: %v", err)
	}
	return &TokenRule{
		Name: "login csrf", Enabled: true,
		// The explicit every-host choice: these tests pin capture/injection mechanics, and the
		// origin binding (not the scope) is what now bounds where a captured value can travel.
		ScopeHosts:   []string{"*"},
		Extract:      *ex,
		InjectHeader: "X-CSRF-Token",
		InjectValue:  "{{csrf}}",
	}
}

func TestTokenRuleCapturesFromAResponseAndInjectsIntoLaterRequests(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	ruleID, err := c.AddTokenRule(tokenRuleForTest(t))
	if err != nil {
		t.Fatalf("add token rule: %v", err)
	}

	// The login response carries the token; no macro ran, this is ordinary observed traffic.
	c.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "proxy"}, 200,
		map[string]string{}, []byte(`<form><input name="csrf" value="tok-123"></form>`), nil)

	if got, ok := c.TokenValue(ruleID); !ok || got != "tok-123" {
		t.Fatalf("the login response's token was not captured: %q, %v", got, ok)
	}

	// A later Repeater request to the same host gains the header without the operator pasting it.
	step := MacroStep{Method: "POST", URL: "http://app.test/transfer", Headers: map[string]string{}, Body: "amount=10"}
	out := c.ApplyTokenRules("repeater", step)
	if got := out.Headers["X-CSRF-Token"]; got != "tok-123" {
		t.Errorf("the captured token was not injected: %q", got)
	}
	// ... and so does a scanner probe.
	out = c.ApplyTokenRules("scanner", step)
	if got := out.Headers["X-CSRF-Token"]; got != "tok-123" {
		t.Errorf("the captured token was not injected for the scanner: %q", got)
	}
}

func TestTokenRuleTemplateWrapsTheValue(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := tokenRuleForTest(t)
	rule.InjectHeader, rule.InjectValue = "Authorization", "Bearer {{csrf}}"
	if _, err := c.AddTokenRule(rule); err != nil {
		t.Fatalf("add token rule: %v", err)
	}
	c.HandleResponseFor(RequestIdentity{Host: "app.test"}, 200, nil, []byte(`name="csrf" value="tok-9"`), nil)
	out := c.ApplyTokenRules("repeater", MacroStep{Method: "GET", URL: "http://app.test/api", Headers: map[string]string{}})
	if got := out.Headers["Authorization"]; got != "Bearer tok-9" {
		t.Errorf("the template was not resolved around the value: %q", got)
	}
}

func TestTokenRuleInjectsAQueryParam(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := tokenRuleForTest(t)
	rule.InjectHeader, rule.InjectValue, rule.InjectParam = "", "", "csrf"
	if _, err := c.AddTokenRule(rule); err != nil {
		t.Fatalf("add token rule: %v", err)
	}
	c.HandleResponseFor(RequestIdentity{Host: "app.test"}, 200, nil, []byte(`name="csrf" value="tok-q"`), nil)

	added := c.ApplyTokenRules("repeater", MacroStep{Method: "GET", URL: "http://app.test/do", Headers: map[string]string{}})
	if !strings.Contains(added.URL, "csrf=tok-q") {
		t.Errorf("the param was not added: %q", added.URL)
	}
	replaced := c.ApplyTokenRules("repeater", MacroStep{Method: "GET", URL: "http://app.test/do?csrf=stale&x=1", Headers: map[string]string{}})
	if strings.Contains(replaced.URL, "stale") || !strings.Contains(replaced.URL, "csrf=tok-q") || !strings.Contains(replaced.URL, "x=1") {
		t.Errorf("a stale param was not replaced cleanly: %q", replaced.URL)
	}
}

func TestTokenRuleScopeAndSilence(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := tokenRuleForTest(t)
	rule.ScopeHosts = []string{"app.test"}
	rule.ScopeTools = []string{"repeater"}
	ruleID, err := c.AddTokenRule(rule)
	if err != nil {
		t.Fatalf("add token rule: %v", err)
	}
	c.HandleResponseFor(RequestIdentity{Host: "app.test"}, 200, nil, []byte(`name="csrf" value="tok-1"`), nil)
	// A response from a host outside the scope must not overwrite the value.
	c.HandleResponseFor(RequestIdentity{Host: "other.test"}, 200, nil, []byte(`name="csrf" value="WRONG"`), nil)
	if got, _ := c.TokenValue(ruleID); got != "tok-1" {
		t.Fatalf("an out-of-scope response overwrote the value: %q", got)
	}
	// The scanner is outside this rule's tools scope: the request goes out untouched.
	out := c.ApplyTokenRules("scanner", MacroStep{Method: "GET", URL: "http://app.test/x", Headers: map[string]string{}})
	if _, ok := out.Headers["X-CSRF-Token"]; ok {
		t.Errorf("a tool outside the rule's scope was injected")
	}
	// A disabled rule neither captures nor injects.
	rule.Enabled = false
	c2 := NewCoordinator(zap.NewNop())
	if _, err := c2.AddTokenRule(rule); err != nil {
		t.Fatalf("add disabled rule: %v", err)
	}
	c2.HandleResponseFor(RequestIdentity{Host: "app.test"}, 200, nil, []byte(`name="csrf" value="tok-2"`), nil)
	if _, ok := c2.TokenValue(rule.ID); ok {
		t.Errorf("a disabled rule captured a value")
	}
	// No value captured yet: the request goes out unchanged rather than gaining an invented header.
	c3 := NewCoordinator(zap.NewNop())
	if _, err := c3.AddTokenRule(tokenRuleForTest(t)); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	out = c3.ApplyTokenRules("repeater", MacroStep{Method: "GET", URL: "http://app.test/x", Headers: map[string]string{}})
	if _, ok := out.Headers["X-CSRF-Token"]; ok {
		t.Errorf("a header was injected with no captured value behind it")
	}
}

func TestApplyTokenRulesToRawRequestSplicesIntoTheOriginalBytes(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	if _, err := c.AddTokenRule(tokenRuleForTest(t)); err != nil {
		t.Fatalf("add token rule: %v", err)
	}
	c.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "proxy"}, 200,
		map[string]string{}, []byte(`<form><input name="csrf" value="tok-777"></form>`), nil)

	// An existing header line is replaced; every other byte - order, the version, the body -
	// is the operator's own.
	raw := []byte("POST /transfer HTTP/1.1\r\nHost: app.test\r\nX-CSRF-Token: stale\r\nX-Custom: keep me\r\nContent-Length: 9\r\n\r\namount=10")
	out := c.ApplyTokenRulesToRawRequest("repeater", raw, "app.test", 80, false)
	want := "POST /transfer HTTP/1.1\r\nHost: app.test\r\nX-CSRF-Token: tok-777\r\nX-Custom: keep me\r\nContent-Length: 9\r\n\r\namount=10"
	if string(out) != want {
		t.Errorf("the splice did not preserve the operator's bytes:\ngot  %q\nwant %q", out, want)
	}

	// A header the request did not carry is appended, not invented into the middle.
	raw2 := []byte("GET /balance HTTP/1.1\r\nHost: app.test\r\n\r\n")
	out2 := c.ApplyTokenRulesToRawRequest("repeater", raw2, "app.test", 80, false)
	want2 := "GET /balance HTTP/1.1\r\nHost: app.test\r\nX-CSRF-Token: tok-777\r\n\r\n"
	if string(out2) != want2 {
		t.Errorf("the appended header did not land at the end of the head:\ngot  %q\nwant %q", out2, want2)
	}
}

func TestApplyTokenRulesToRawRequestSetsAQueryParam(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	rule := tokenRuleForTest(t)
	rule.InjectHeader, rule.InjectValue, rule.InjectParam = "", "", "csrf"
	if _, err := c.AddTokenRule(rule); err != nil {
		t.Fatalf("add token rule: %v", err)
	}
	c.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "proxy"}, 200,
		map[string]string{}, []byte(`<form><input name="csrf" value="tok-888"></form>`), nil)

	raw := []byte("GET /transfer?amount=10&csrf=stale HTTP/1.1\r\nHost: app.test\r\n\r\n")
	out := c.ApplyTokenRulesToRawRequest("scanner", raw, "app.test", 80, false)
	want := "GET /transfer?amount=10&csrf=tok-888 HTTP/1.1\r\nHost: app.test\r\n\r\n"
	if string(out) != want {
		t.Errorf("the query injection did not land in the request-target:\ngot  %q\nwant %q", out, want)
	}
}

func TestApplyTokenRulesToRawRequestStaysSilentWithoutAValueOrScope(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	if _, err := c.AddTokenRule(tokenRuleForTest(t)); err != nil {
		t.Fatalf("add token rule: %v", err)
	}
	raw := []byte("POST /transfer HTTP/1.1\r\nHost: app.test\r\n\r\namount=10")

	// Nothing captured yet: the request goes out untouched, not under an empty header.
	if out := c.ApplyTokenRulesToRawRequest("repeater", raw, "app.test", 80, false); string(out) != string(raw) {
		t.Errorf("a request was rewritten with no value captured: %q", out)
	}

	// A captured value does not reach a tool the rule does not cover.
	rule := tokenRuleForTest(t)
	rule.ScopeTools = []string{"scanner"}
	c2 := NewCoordinator(zap.NewNop())
	if _, err := c2.AddTokenRule(rule); err != nil {
		t.Fatalf("add scoped rule: %v", err)
	}
	// The tools scope gates capture as it gates injection, so the value here is lifted from a
	// scanner-attributed response; a proxy response would not have overwritten it.
	c2.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "scanner"}, 200,
		map[string]string{}, []byte(`<form><input name="csrf" value="tok-999"></form>`), nil)
	if out := c2.ApplyTokenRulesToRawRequest("repeater", raw, "app.test", 80, false); string(out) != string(raw) {
		t.Errorf("a rule reached a tool outside its scope: %q", out)
	}
	// ... and the covered tool gets it.
	out := c2.ApplyTokenRulesToRawRequest("scanner", raw, "app.test", 80, false)
	if !strings.Contains(string(out), "X-CSRF-Token: tok-999") {
		t.Errorf("the covered tool did not receive the injection: %q", out)
	}
}

// --- The integrator's remediation pins (xe82 hold ruling). Each was RED against the
// pre-remediation tree (efa9c1be) with the leak shape named in the ruling; each is green now. ---

// 1. Two rules sharing one extraction name keep separate captured values, keyed by rule ID.
func TestTokenRuleValuesAreIsolatedByRuleIdentity(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	mk := func(name, pattern, header string) *TokenRule {
		ex, err := NewExtraction(name, "body", pattern, 1)
		if err != nil {
			t.Fatalf("extraction: %v", err)
		}
		return &TokenRule{Name: name + " rule", Enabled: true, ScopeHosts: []string{"*"},
			Extract: *ex, InjectHeader: header, InjectValue: "{{" + name + "}}"}
	}
	idA, err := c.AddTokenRule(mk("csrf", `name="csrf" value="([^"]+)"`, "X-CSRF-Token"))
	if err != nil {
		t.Fatalf("add a: %v", err)
	}
	idB, err := c.AddTokenRule(mk("csrf", `name="csrf2" value="([^"]+)"`, "X-Audit-Token"))
	if err != nil {
		t.Fatalf("add b: %v", err)
	}
	c.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "proxy"}, 200, nil,
		[]byte(`name="csrf" value="tok-session" name="csrf2" value="tok-audit"`), nil)
	if got, _ := c.TokenValue(idA); got != "tok-session" {
		t.Fatalf("rule A's value: %q", got)
	}
	if got, _ := c.TokenValue(idB); got != "tok-audit" {
		t.Fatalf("rule B's value: %q", got)
	}
	// A later response re-issues only A's value: B's must not move.
	c.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "proxy"}, 200, nil,
		[]byte(`name="csrf" value="tok-session-2"`), nil)
	if got, _ := c.TokenValue(idA); got != "tok-session-2" {
		t.Errorf("rule A's value did not refresh: %q", got)
	}
	if got, _ := c.TokenValue(idB); got != "tok-audit" {
		t.Errorf("rule B's value was clobbered by rule A's later capture: %q", got)
	}
	out := c.ApplyTokenRules("repeater", MacroStep{Method: "GET", URL: "http://app.test/x", Headers: map[string]string{}})
	if out.Headers["X-Audit-Token"] != "tok-audit" || out.Headers["X-CSRF-Token"] != "tok-session-2" {
		t.Errorf("the injected headers came from the wrong rules: %v", out.Headers)
	}
}

// 2. A rule naming no hosts is refused; "*" is the explicit, working every-host choice.
func TestTokenRuleRefusesAnEmptyHostScope(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	ex, err := NewExtraction("csrf", "body", `v="([^"]+)"`, 1)
	if err != nil {
		t.Fatalf("extraction: %v", err)
	}
	bare := &TokenRule{Name: "wide", Enabled: true, Extract: *ex, InjectHeader: "X-CSRF", InjectValue: "{{csrf}}"}
	if _, err := c.AddTokenRule(bare); err == nil {
		t.Fatalf("a rule naming no hosts was accepted; it would capture and inject everywhere by default")
	}
	// The deliberate choice installs and works - bounded by the origin binding, not by accident.
	rule := &TokenRule{Name: "wide", Enabled: true, ScopeHosts: []string{"*"}, Extract: *ex, InjectHeader: "X-CSRF", InjectValue: "{{csrf}}"}
	if _, err := c.AddTokenRule(rule); err != nil {
		t.Fatalf("the explicit all-hosts choice was refused: %v", err)
	}
	c.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "proxy"}, 200, nil, []byte(`v="tok-1"`), nil)
	out := c.ApplyTokenRules("repeater", MacroStep{Method: "GET", URL: "http://app.test/x", Headers: map[string]string{}})
	if out.Headers["X-CSRF"] != "tok-1" {
		t.Errorf("the explicit all-hosts rule did not inject on the capture origin: %q", out.Headers["X-CSRF"])
	}
}

// 3. Editing or removing a rule drops its captured value at once; nothing stale survives.
func TestTokenRuleEditAndRemovalDropTheCapturedValue(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	mk := func(name string) *TokenRule {
		ex, err := NewExtraction("csrf", "body", `v="([^"]+)"`, 1)
		if err != nil {
			t.Fatalf("extraction: %v", err)
		}
		return &TokenRule{Name: name, Enabled: true, ScopeHosts: []string{"app.test"},
			Extract: *ex, InjectHeader: "X-CSRF", InjectValue: "{{csrf}}"}
	}
	id, err := c.AddTokenRule(mk("a"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	step := MacroStep{Method: "GET", URL: "http://app.test/x", Headers: map[string]string{}}

	c.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "proxy"}, 200, nil, []byte(`v="tok-1"`), nil)
	if err := c.UpdateTokenRule(id, mk("a2")); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got, ok := c.TokenValue(id); ok {
		t.Errorf("an edited rule kept the value the pre-edit rule captured: %q", got)
	}
	if out := c.ApplyTokenRules("repeater", step); out.Headers["X-CSRF"] != "" {
		t.Errorf("an edited rule still injects the value the pre-edit rule captured: %q", out.Headers["X-CSRF"])
	}

	c.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "proxy"}, 200, nil, []byte(`v="tok-2"`), nil)
	if !c.RemoveTokenRule(id) {
		t.Fatalf("remove: rule missing")
	}
	if got, ok := c.TokenValue(id); ok {
		t.Errorf("a removed rule kept its value: %q", got)
	}
	restored := mk("a3")
	restored.ID = id
	if err := c.RestoreTokenRule(restored); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if out := c.ApplyTokenRules("repeater", step); out.Headers["X-CSRF"] != "" {
		t.Errorf("a removed-then-restored rule resurrected the removed rule's value: %q", out.Headers["X-CSRF"])
	}
}

// 4. A captured value never crosses the origin it was captured from - scheme, host, port -
// whatever the scope would allow. Default-port spellings of one origin are that origin.
func TestTokenRuleValueNeverCrossesTheCaptureOrigin(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	ex, err := NewExtraction("csrf", "body", `v="([^"]+)"`, 1)
	if err != nil {
		t.Fatalf("extraction: %v", err)
	}
	rule := &TokenRule{Name: "wide", Enabled: true, ScopeHosts: []string{"*"}, Extract: *ex, InjectHeader: "X-CSRF", InjectValue: "{{csrf}}"}
	if _, err := c.AddTokenRule(rule); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Captured from https://app.test:443 (the port implied by the scheme).
	c.HandleResponseFor(RequestIdentity{Host: "app.test", TLS: true, Tool: "proxy"}, 200, nil, []byte(`v="tok-1"`), nil)

	injects := func(rawURL string) string {
		return c.ApplyTokenRules("repeater", MacroStep{Method: "GET", URL: rawURL, Headers: map[string]string{}}).Headers["X-CSRF"]
	}
	if got := injects("https://app.test/x"); got != "tok-1" {
		t.Errorf("the same origin did not receive its value: %q", got)
	}
	if got := injects("https://app.test:443/x"); got != "tok-1" {
		t.Errorf("the same origin with the default port spelled out did not receive its value: %q", got)
	}
	for _, u := range []string{"http://app.test/x", "https://app.test:8443/x", "https://other.test/x", "app.test/x"} {
		if got := injects(u); got != "" {
			t.Errorf("a value captured from https://app.test:443 was injected into %s", u)
		}
	}
}
