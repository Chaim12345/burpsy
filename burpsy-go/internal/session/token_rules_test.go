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
		Extract:      *ex,
		InjectHeader: "X-CSRF-Token",
		InjectValue:  "{{csrf}}",
	}
}

func TestTokenRuleCapturesFromAResponseAndInjectsIntoLaterRequests(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	if _, err := c.AddTokenRule(tokenRuleForTest(t)); err != nil {
		t.Fatalf("add token rule: %v", err)
	}

	// The login response carries the token; no macro ran, this is ordinary observed traffic.
	c.HandleResponseFor(RequestIdentity{Host: "app.test", Tool: "proxy"}, 200,
		map[string]string{}, []byte(`<form><input name="csrf" value="tok-123"></form>`), nil)

	if got, ok := c.TokenValue("csrf"); !ok || got != "tok-123" {
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
	if _, err := c.AddTokenRule(rule); err != nil {
		t.Fatalf("add token rule: %v", err)
	}
	c.HandleResponseFor(RequestIdentity{Host: "app.test"}, 200, nil, []byte(`name="csrf" value="tok-1"`), nil)
	// A response from a host outside the scope must not overwrite the value.
	c.HandleResponseFor(RequestIdentity{Host: "other.test"}, 200, nil, []byte(`name="csrf" value="WRONG"`), nil)
	if got, _ := c.TokenValue("csrf"); got != "tok-1" {
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
	if _, ok := c2.TokenValue("csrf"); ok {
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
