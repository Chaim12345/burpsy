package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// burpsy-react-ui-ydmj end to end through a session rule: the script captures a token from the response
// the rule is reacting to, keeps it in the rule's store, and the request that actually goes out carries
// it and a signature — then a LATER request, with no response to read, still carries the stored token.
func TestAPreRequestScriptActionRewritesTheRequestThatIsSent(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())
	rule := NewSessionRule("jwt + hmac", []string{"example.com"}, nil)
	rule.Actions = []*Action{{Kind: ActionRunScript, Enabled: true, Script: `
		if (response && response.body.indexOf("{") === 0) {
			store.set("jwt", JSON.parse(response.body).token);
		}
		request.headers["Authorization"] = "Bearer " + store.get("jwt");
		request.headers["X-Sig"] = burpsy.hmacSha256Hex("k", request.method + " " + request.url);
	`}}
	mustAddRule(t, c, rule)

	fake.script("https://example.com/me", validResponse(), nil)
	c.HandleRecovery("", getStep("https://example.com/me"), &StepResult{Status: 200, Body: []byte(`{"token":"tok-1"}`)}, fake.runner())
	sent := fake.sentSteps("https://example.com/me")
	if len(sent) != 1 {
		t.Fatalf("sent %d, want 1", len(sent))
	}
	if sent[0].Headers["Authorization"] != "Bearer tok-1" {
		t.Errorf("Authorization on the wire = %q", sent[0].Headers["Authorization"])
	}
	m := hmac.New(sha256.New, []byte("k"))
	m.Write([]byte("GET https://example.com/me"))
	if want := hex.EncodeToString(m.Sum(nil)); sent[0].Headers["X-Sig"] != want {
		t.Errorf("X-Sig = %q, want %q", sent[0].Headers["X-Sig"], want)
	}

	// A later request with no response to read: the token captured above is still in the rule's store.
	fake.script("https://example.com/orders", validResponse(), nil)
	c.HandleRecovery("", getStep("https://example.com/orders"), nil, fake.runner())
	later := fake.sentSteps("https://example.com/orders")
	if len(later) != 1 || later[0].Headers["Authorization"] != "Bearer tok-1" {
		t.Errorf("the next request did not carry the stored token: %+v", later)
	}
}

// A script that fails leaves the request as it was and the trace says why; the rest of the rule still
// runs.
func TestAFailingScriptActionLeavesTheRequestAndSaysWhy(t *testing.T) {
	fake := newFakeSender()
	c := NewCoordinator(zap.NewNop())
	rule := NewSessionRule("broken", []string{"example.com"}, nil)
	rule.Actions = []*Action{
		{Kind: ActionRunScript, Enabled: true, Script: `request.headers["X-Half"]="1"; throw new Error("no key")`},
		setHeaderAction("X-After", "1"),
	}
	mustAddRule(t, c, rule)
	fake.script("https://example.com/a", validResponse(), nil)
	outcome := c.HandleRecovery("", getStep("https://example.com/a"), nil, fake.runner())
	sent := fake.sentSteps("https://example.com/a")
	if len(sent) != 1 || sent[0].Headers["X-Half"] != "" || sent[0].Headers["X-After"] != "1" {
		t.Errorf("sent = %+v: want the half-applied header absent and the next action applied", sent)
	}
	if !strings.Contains(describeTrace(outcome.Actions), "no key") {
		t.Errorf("the trace does not carry the script's error: %s", describeTrace(outcome.Actions))
	}
}

// Refused at install: a script that does not compile, and a script on an action that is not a script.
func TestAScriptActionIsValidatedWhenTheRuleIsInstalled(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	bad := NewSessionRule("syntax", []string{"example.com"}, nil)
	bad.Actions = []*Action{{Kind: ActionRunScript, Enabled: true, Script: "request.headers[ ="}}
	if _, err := c.AddRule(bad); err == nil || !strings.Contains(err.Error(), "compile") {
		t.Errorf("a script with a syntax error was installed: %v", err)
	}
	stray := NewSessionRule("stray", []string{"example.com"}, nil)
	stray.Actions = []*Action{{Kind: ActionSetHeader, Enabled: true, Name: "X", Value: "1", Script: "log(1)"}}
	if _, err := c.AddRule(stray); err == nil {
		t.Error("a script on a set-header action was accepted; it would read as though it ran")
	}
}
