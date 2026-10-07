package intercept

import "testing"

// A member rule driven through the ENGINE, not just the Rule constructor (burpsy-react-ui-ajpn).
//
// This test exists because a mutation check found the hole it covers: dropping the `Member` field
// from Engine.SetRules — the copy that turns an incoming rule into the compiled one the lists
// hold — left the whole suite green. Every other test builds a *Rule and matches it directly, so
// nothing exercised the path an operator's saved rule actually travels: the API decodes the spec,
// SetRules compiles it, the proxy consults the list. A member silently lost in that copy is a rule
// that reads correctly in the editor and matches nothing on the wire, which is the exact defect
// class this feature is about.

func TestAMemberRuleHoldsThroughTheEngineNotJustTheConstructor(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)

	rule, err := NewMemberRule(FieldRequestCookie, "session", CategoryLiteral, "abc123", true, "", RuleActionHold)
	if err != nil {
		t.Fatalf("NewMemberRule: %v", err)
	}
	// SetRules takes Rule VALUES, which is the copy under test.
	if err := e.SetRules(DirectionRequest, true, []Rule{*rule}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	withCookie := &Message{
		Direction: DirectionRequest, Host: "a.test", Port: 80, Method: "GET", Path: "/admin",
		Raw: []byte("GET /admin HTTP/1.1\r\nHost: a.test\r\nCookie: session=abc123; theme=dark\r\n\r\n"),
	}
	if !e.shouldHold(DirectionRequest, withCookie) {
		t.Error("a request-cookie rule did not hold a request carrying that cookie after a trip " +
			"through SetRules. The member name is being dropped when the rule is compiled, so the " +
			"rule reads correctly in the editor and matches nothing on the wire")
	}

	// The member scoping survives the copy too: a request with a DIFFERENT cookie value must not
	// hold, or the compiled rule is matching the whole Cookie header rather than the named member.
	otherCookie := &Message{
		Direction: DirectionRequest, Host: "a.test", Port: 80, Method: "GET", Path: "/admin",
		Raw: []byte("GET /admin HTTP/1.1\r\nHost: a.test\r\nCookie: session=zzz; theme=abc123\r\n\r\n"),
	}
	if e.shouldHold(DirectionRequest, otherCookie) {
		t.Error("a request-cookie rule on `session` held a request whose THEME cookie carried the " +
			"value. After the trip through SetRules the member is being ignored and the whole " +
			"Cookie header matched, so the rule fires on the wrong traffic")
	}
}

func TestAResponseHeaderRuleHoldsThroughTheEngine(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)

	rule, err := NewMemberRule(FieldResponseHeader, "X-Powered-By", CategoryLiteral, "Express", true, "", RuleActionHold)
	if err != nil {
		t.Fatalf("NewMemberRule: %v", err)
	}
	if err := e.SetRules(DirectionResponse, true, []Rule{*rule}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	framed := &Message{
		Direction: DirectionResponse, Host: "a.test", Port: 80, Method: "GET", Path: "/",
		Raw: []byte("HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\n\r\nok"),
	}
	if !e.shouldHold(DirectionResponse, framed) {
		t.Error("a response-header rule did not hold the response carrying that header")
	}
	quiet := &Message{
		Direction: DirectionResponse, Host: "a.test", Port: 80, Method: "GET", Path: "/",
		Raw: []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nok"),
	}
	if e.shouldHold(DirectionResponse, quiet) {
		t.Error("a response-header rule held a response without that header")
	}
}
