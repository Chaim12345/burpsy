package intercept

import (
	"strings"
	"testing"
)

// ---- the member fields (ajpn): a rule cannot name an individual header or a cookie without them ----
//
// Burp's rule dialog offers 18 match types through an 18-case factory (Zero.java:16-62, build
// 51467): Zpkq = the header list (request and response), Zpky = the cookie NAME, Zpkc = the cookie
// VALUE, each with request/response ordinals over the shared base Zpkg.java:12-40. The two rules an
// operator most often writes to catch a privilege-escalation flow — "requests carrying
// X-Forwarded-For" and "responses setting Set-Cookie: admin" — were not expressible at all before
// these fields existed.

func ruleWith(t *testing.T, field Field, member, match string) *Rule {
	t.Helper()
	r, err := newRule(Rule{Field: field, Category: CategoryLiteral, StringMatch: match, Member: member, Enabled: true})
	if err != nil {
		t.Fatalf("newRule(%v, member=%q, match=%q): %v", field, member, match, err)
	}
	return r
}

func requestMessage() *Message {
	raw := []byte("POST /admin HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: 10.0.0.1\r\nCookie: session=abc123; theme=dark\r\n\r\nbody")
	return &Message{Direction: DirectionRequest, Host: "app.test", Port: 80, Method: "POST", Path: "/admin", Raw: raw}
}

func responseMessage() *Message {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: admin=1; Path=/\r\nX-Trace: live\r\n\r\n<h1>ok</h1>")
	return &Message{Direction: DirectionResponse, Host: "app.test", Port: 80, Status: intPtr(200), Raw: raw}
}

func intPtr(v int) *int { return &v }

func TestARuleNamesARequestHeaderAndMatchesItsValue(t *testing.T) {
	r := ruleWith(t, FieldRequestHeader, "X-Forwarded-For", "10.0.0.1")
	if !r.Match(requestMessage()) {
		t.Error("a request-header rule naming X-Forwarded-For with the value present did not match: " +
			"the field says which list and the member says which header, so this is the whole feature")
	}
	if r.Match(responseMessage()) {
		t.Error("a REQUEST-header rule matched a response that does not carry the header: " +
			"HasField must gate the direction before any lookup")
	}
}

func TestARuleNamesAResponseHeaderAndMatchesItsValue(t *testing.T) {
	r := ruleWith(t, FieldResponseHeader, "Set-Cookie", "admin=1")
	if !r.Match(responseMessage()) {
		t.Error("a response-header rule naming Set-Cookie with the value present did not match")
	}
	// The member name folds: an operator who types "set-cookie" must get the same rule.
	r2 := ruleWith(t, FieldResponseHeader, "set-cookie", "admin=1")
	if !r2.Match(responseMessage()) {
		t.Error("the member name did not fold: header names are case-insensitive (RFC 9110 §5.1)")
	}
}

func TestARuleNamesARequestCookieAndMatchesItsValue(t *testing.T) {
	r := ruleWith(t, FieldRequestCookie, "session", "abc123")
	if !r.Match(requestMessage()) {
		t.Error("a request-cookie rule naming session=abc123 did not match: the Cookie header's " +
			"pairs are the list and the member picks one")
	}
	// A DIFFERENT cookie in the same jar must not match — the member is the whole point.
	r2 := ruleWith(t, FieldRequestCookie, "theme", "light")
	if r2.Match(requestMessage()) {
		t.Error("a cookie rule naming theme=light matched a message whose theme cookie is dark: " +
			"matching the first pair would report a match the operator never asked for")
	}
}

func TestARuleNamesAResponseCookieAndMatchesItsValue(t *testing.T) {
	r := ruleWith(t, FieldResponseCookie, "admin", "1")
	if !r.Match(responseMessage()) {
		t.Error("a response-cookie rule naming admin=1 did not match the Set-Cookie line")
	}
}

func TestAMemberFieldWithNoMemberIsRefusedNotSilentlyUnmatchable(t *testing.T) {
	// A member field with an empty Member has nothing to read. It is REFUSED rather than accepted
	// as a rule that matches nothing: a rule that sits in the list looking configured and can
	// never fire is the failure this field exists to prevent, and the operator cannot tell it
	// apart from a target that never sends the header. The wire layer refuses it too
	// (specToRules), so the two cannot disagree about whether such a rule is valid.
	if _, err := newRule(Rule{Field: FieldRequestHeader, Category: CategoryLiteral, StringMatch: "anything", Enabled: true}); err == nil {
		t.Error("a header rule with no member name was accepted: it can never match, and nothing " +
			"on screen would tell the operator that")
	}
}

func TestAMemberOnANonMemberFieldIsRefused(t *testing.T) {
	for _, field := range []Field{FieldHost, FieldPath, FieldMethod, FieldURL, FieldStatusCode, FieldContentType, FieldRequestBody, FieldResponseBody, FieldPort, FieldProtocol, FieldExtension} {
		if _, err := newRule(Rule{Field: field, Category: CategoryLiteral, StringMatch: "x", Member: "Cookie", Enabled: true}); err == nil {
			t.Errorf("a member name on field %v was accepted: the engine would silently ignore it and "+
				"match the field's whole value, which is a match the operator never asked for", field)
		}
	}
}

func TestAMemberFieldNeedsAMember(t *testing.T) {
	if _, err := newRule(Rule{Field: FieldRequestHeader, Category: CategoryLiteral, StringMatch: "x", Enabled: true}); err == nil {
		t.Error("a request_header rule with no member was accepted: a rule that names no header has " +
			"nothing to match against and would sit there looking configured")
	}
}

// The enum-walk tripwire: a Field added without a String name, a ParseField branch, a HasField
// entry and a value path fails here, rather than shipping as a wire value the console cannot name.
func TestEveryFieldIsRepresentableEndToEnd(t *testing.T) {
	for f := FieldHost; f <= FieldResponseCookie; f++ {
		name := f.String()
		if name == "" || strings.Contains(name, "unknown") {
			t.Errorf("field %d has no String name: a wire value the console cannot render", f)
		}
		got, err := ParseField(name)
		if err != nil || got != f {
			t.Errorf("ParseField(%q) did not round-trip to field %d: the wire name and the enum disagree", name, f)
		}
		if !DirectionRequest.HasField(f) && !DirectionResponse.HasField(f) {
			t.Errorf("field %v is supplied by neither direction: a rule naming it can never match, "+
				"silently — the dead-weight rule HasField exists to expose", f)
		}
	}
}

func TestHasFieldSplitsTheMemberFieldsByDirection(t *testing.T) {
	if !DirectionRequest.HasField(FieldRequestHeader) || !DirectionRequest.HasField(FieldRequestCookie) {
		t.Error("a request cannot supply its own header/cookie fields: the direction split is broken")
	}
	if !DirectionResponse.HasField(FieldResponseHeader) || !DirectionResponse.HasField(FieldResponseCookie) {
		t.Error("a response cannot supply its own header/cookie fields: the direction split is broken")
	}
	if DirectionResponse.HasField(FieldRequestHeader) || DirectionRequest.HasField(FieldResponseCookie) {
		t.Error("a member field crossed its direction: a response list matching a request header is " +
			"a rule the operator wrote wrong, and HasField must say so")
	}
}
