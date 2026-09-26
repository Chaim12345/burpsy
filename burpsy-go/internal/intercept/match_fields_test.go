package intercept

import (
	"strings"
	"testing"
)

// burpsy-react-ui-1cuc: Burp's rule dialog offers 18 match types per direction; burpsy exposed seven.
// "Hold requests to port 8443" and "hold the response whose body contains X" could not be written at
// all. Port- and protocol-scoped interception is how an operator holds one service's traffic without
// stopping the rest of a session, and body matching is the only way to hold the one response that
// matters in a high-volume stream.

// Every new field round-trips through its wire name, because a field that decodes under one spelling
// and reports under another is a rule that silently stops matching after a save.
func TestTheNewMatchFieldsRoundTripThroughTheirWireNames(t *testing.T) {
	for _, tc := range []struct {
		wire string
		want Field
	}{
		{"port", FieldPort},
		{"protocol", FieldProtocol},
		{"request_body", FieldRequestBody},
		{"response_body", FieldResponseBody},
	} {
		got, err := ParseField(tc.wire)
		if err != nil {
			t.Errorf("ParseField(%q): %v", tc.wire, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseField(%q) = %v, want %v", tc.wire, got, tc.want)
		}
		if got.String() != tc.wire {
			t.Errorf("Field(%v).String() = %q, want %q; the wire name and the report must be one "+
				"spelling or a saved rule stops matching itself", got, got.String(), tc.wire)
		}
	}
}

// The seven that already existed must not move. A Field is a wire VALUE, and an operator's saved
// rule names one, so re-numbering the constants would silently re-point every rule already written.
func TestTheOriginalSevenFieldsKeepTheirNumbers(t *testing.T) {
	for i, want := range []Field{
		FieldHost, FieldPath, FieldExtension, FieldMethod,
		FieldURL, FieldStatusCode, FieldContentType,
	} {
		if int(want) != i {
			t.Errorf("field %v has value %d, want %d; the four new fields are APPENDED so an existing "+
				"saved rule keeps naming the same field", want, int(want), i)
		}
	}
	// And the new ones come after them, in the order they were added.
	for i, want := range []Field{FieldPort, FieldProtocol, FieldRequestBody, FieldResponseBody} {
		if int(want) != 7+i {
			t.Errorf("field %v has value %d, want %d", want, int(want), 7+i)
		}
	}
}

// Port and protocol are request-shaped facts the message already carries, and they are the two an
// operator reaches for when holding one service's traffic out of a shared session.
func TestPortAndProtocolAreMatchable(t *testing.T) {
	m := &Message{
		Direction: DirectionRequest, Host: "a.test", Port: 8443, TLS: true,
		Method: "GET", Path: "/admin",
	}
	if got := m.FieldValue(FieldPort); got != "8443" {
		t.Errorf("FieldValue(Port) = %q, want 8443; \"hold requests to port 8443\" is the rule this adds",
			got)
	}
	if got := m.FieldValue(FieldProtocol); got != "https" {
		t.Errorf("FieldValue(Protocol) = %q, want https", got)
	}
	// Plain http over the default port, so the rule is not answering only for TLS.
	plain := &Message{Direction: DirectionRequest, Host: "a.test", Port: 80, Path: "/"}
	if got := plain.FieldValue(FieldProtocol); got != "http" {
		t.Errorf("FieldValue(Protocol) = %q on a plain request, want http", got)
	}
	// And a port of 0 is absent rather than a port named "0", which no listener has.
	if got := (&Message{Direction: DirectionRequest}).FieldValue(FieldPort); got != "" {
		t.Errorf("FieldValue(Port) = %q with no port recorded, want empty; 0 is not a port an operator "+
			"could have written a rule about", got)
	}
}

// A body is the field a rule about CONTENT needs, and the two halves must not be confused: a request
// rule matching on the request body must not fire on the response's, or holding "responses whose body
// contains token" would also hold the requests.
func TestRequestBodyAndResponseBodyReadTheirOwnHalf(t *testing.T) {
	m := &Message{
		Direction: DirectionRequest, Host: "a.test", Port: 80, Method: "POST", Path: "/x",
		Raw: []byte("POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 22\r\n\r\nname=bob&role=admin"),
	}
	body := m.FieldValue(FieldRequestBody)
	if !strings.Contains(body, "name=bob") {
		t.Errorf("FieldValue(RequestBody) = %q, want the request body", body)
	}
	if strings.Contains(body, "HTTP/1.1") {
		t.Errorf("FieldValue(RequestBody) = %q; the request LINE is not the body, and a rule matching it "+
			"would fire on every request to the same path", body)
	}
	if got := m.FieldValue(FieldResponseBody); got != "" {
		t.Errorf("FieldValue(ResponseBody) = %q on a REQUEST message, want empty", got)
	}

	r := &Message{
		Direction: DirectionResponse, Host: "a.test", Port: 80, Method: "GET", Path: "/x",
		Raw: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 25\r\n\r\n<html>stack trace</html>"),
	}
	rb := r.FieldValue(FieldResponseBody)
	if !strings.Contains(rb, "stack trace") {
		t.Errorf("FieldValue(ResponseBody) = %q, want the response body", rb)
	}
	if got := r.FieldValue(FieldRequestBody); got != "" {
		t.Errorf("FieldValue(RequestBody) = %q on a RESPONSE message, want empty", got)
	}
}

// A rule that can never match is dead weight, and dead weight must be distinguishable from a target
// that simply never sent it. A request has no status code, no content type and no response body.
func TestAFieldADirectionCannotSupplyIsVisiblyDeadWeight(t *testing.T) {
	req := &Message{Direction: DirectionRequest, Host: "a.test"}
	// Even carrying every field, a request cannot answer these — and that is the point: the shape
	// decides, not what happens to be set on the struct.
	status := 500
	req.Status = &status
	req.ContentType = "text/html"

	for _, f := range []Field{FieldStatusCode, FieldContentType, FieldResponseBody} {
		if got := req.FieldValue(f); got != "" {
			t.Errorf("FieldValue(%v) = %q on a REQUEST; the field is dead weight there and a rule "+
				"naming it can never match, which must be visible rather than silent", f, got)
		}
		if DirectionRequest.HasField(f) {
			t.Errorf("DirectionRequest.HasField(%v) = true", f)
		}
	}
	// The request's OWN body is matchable, so the check is a split and not a blanket refusal.
	if !DirectionRequest.HasField(FieldRequestBody) {
		t.Error("a request cannot match on its own body, which is the field a content rule most wants")
	}
	if DirectionResponse.HasField(FieldRequestBody) {
		t.Error("a response cannot match on a request body")
	}
	// And the shared fields work in both lists.
	for _, f := range []Field{FieldHost, FieldPath, FieldPort, FieldProtocol, FieldMethod, FieldURL} {
		if !DirectionRequest.HasField(f) || !DirectionResponse.HasField(f) {
			t.Errorf("%v is not supplied by both directions; host, path, port, protocol, method and url "+
				"are facts of the exchange rather than of one half", f)
		}
	}
}

// A body rule has to survive the client that does not use CRLF, or it works in a test and never
// against a real target — which reads as configured and is not.
func TestABodyRuleReadsAMessageThatUsesBareLineFeeds(t *testing.T) {
	m := &Message{
		Direction: DirectionRequest, Host: "a.test", Port: 80, Method: "POST", Path: "/x",
		Raw: []byte("POST /x HTTP/1.1\nHost: a.test\nContent-Length: 4\n\nbody"),
	}
	if got := m.FieldValue(FieldRequestBody); got != "body" {
		t.Errorf("FieldValue(RequestBody) = %q for bare-LF framing, want \"body\"; a body rule that only "+
			"works against CRLF is a rule that never fires in production", got)
	}
}

// And bytes that are not an HTTP message at all — a WebSocket frame — supply neither half, rather
// than answering with a fragment of the frame.
func TestANonHTTPMessageSuppliesNoBody(t *testing.T) {
	frame := &Message{Direction: DirectionWebSocketToClient, Opcode: "text", Raw: []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}}
	if got := frame.FieldValue(FieldRequestBody); got != "" {
		t.Errorf("FieldValue(RequestBody) = %q on a WebSocket FRAME; the bytes are not an HTTP message "+
			"and a rule matching part of a frame is a rule that fires on frame data", got)
	}
	if got := frame.FieldValue(FieldResponseBody); got != "" {
		t.Errorf("FieldValue(ResponseBody) = %q on a WebSocket frame", got)
	}
}

// The round trip that matters: an operator writes "hold responses whose body contains <token>", and
// the rule holds exactly those.
func TestARuleOnAResponseBodyHoldsTheResponseThatCarriesTheText(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	bodyRule, err := NewRule(FieldResponseBody, CategoryLiteral, "stack trace", true, "", RuleActionHold)
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	if err := e.SetRules(DirectionResponse, true, []Rule{*bodyRule}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	withTrace := &Message{
		Direction: DirectionResponse, Host: "a.test", Port: 80, Method: "GET", Path: "/boom",
		Raw: []byte("HTTP/1.1 500 OK\r\nContent-Length: 22\r\n\r\n<html>stack trace</html>"),
	}
	if !e.shouldHold(DirectionResponse, withTrace) {
		t.Error("a response carrying the text did not hold; \"hold the response that matters in a " +
			"high-volume stream\" is the rule this adds")
	}
	quiet := &Message{
		Direction: DirectionResponse, Host: "a.test", Port: 80, Method: "GET", Path: "/fine",
		Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nall fine"),
	}
	if e.shouldHold(DirectionResponse, quiet) {
		t.Error("a response without the text held; the rule matched more than it names")
	}
	// And the request list is untouched by a response-body rule — it was never in that list.
	if e.shouldHold(DirectionRequest, &Message{
		Direction: DirectionRequest, Host: "a.test", Port: 80, Method: "GET", Path: "/boom",
		Raw: []byte("GET /boom HTTP/1.1\r\nHost: a.test\r\n\r\n"),
	}) {
		t.Error("a response-body rule held a REQUEST; the two lists are separate")
	}
}
