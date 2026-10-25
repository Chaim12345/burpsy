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
