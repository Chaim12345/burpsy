package session

import (
	"net/url"
	"strings"
	"testing"
)

// A macro step built from a history row (burpsy-react-ui-escl). Burp's Macro Recorder is "select the
// items you need from the Proxy history list", so the contract is that a captured request becomes a
// step that the runner can send — same method, same target, same headers, same body — addressed
// against the exchange the row came from.
//
// The tests below are mostly about the ways that conversion can produce something *plausible*: a URL
// with a dropped port, a body with a normalised newline, a header that appeared twice and silently
// became one. Each of those produces a macro that runs, does something slightly different from what
// the operator selected, and reports success.

func TestAStepFromHistoryKeepsTheMethodTargetHeadersAndBody(t *testing.T) {
	raw := "POST /login?next=/home HTTP/1.1\r\n" +
		"Host: shop.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 27\r\n" +
		"\r\n" +
		"user=alice&password=hunter2"

	step, err := MacroStepFromRequest([]byte(raw), "shop.test", 443, true)
	if err != nil {
		t.Fatalf("MacroStepFromRequest: %v", err)
	}
	if step.Method != "POST" {
		t.Errorf("Method = %q, want POST", step.Method)
	}
	// The query string is part of the target and must survive: a login that posts to /login?next=…
	// is a different request from one that posts to /login, and dropping the query is exactly how a
	// macro that "mostly works" stops working.
	if step.URL != "https://shop.test/login?next=/home" {
		t.Errorf("URL = %q, want https://shop.test/login?next=/home (no :443, Burp omits the default port)", step.URL)
	}
	if got := step.Headers["Content-Type"]; got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want the captured value", got)
	}
	if got := step.Headers["Host"]; got != "shop.test" {
		t.Errorf("Host = %q, want the captured value; the client's headers are part of what is replayed", got)
	}
	if step.Body != "user=alice&password=hunter2" {
		t.Errorf("Body = %q, want the captured bytes", step.Body)
	}
}

// The URL must be absolute, because that is what a macro step is for and what validate.go requires.
// Asserted by parsing rather than by string comparison, so a future change to the spelling that
// still addresses the right origin does not fail this test for no reason.
func TestAStepFromHistoryIsAddressedAtTheExchangeItCameFrom(t *testing.T) {
	for _, tc := range []struct {
		name    string
		host    string
		port    uint16
		tls     bool
		wantURL string
	}{
		{"https default port", "shop.test", 443, true, "https://shop.test/cart"},
		{"http default port", "shop.test", 80, false, "http://shop.test/cart"},
		{"https non-default", "shop.test", 8443, true, "https://shop.test:8443/cart"},
		{"http non-default", "shop.test", 8080, false, "http://shop.test:8080/cart"},
		// An IPv6 literal is the one authority a naive concatenation gets wrong: without brackets
		// the parser reads "::1:8080" as the host and the port is lost.
		{"ipv6 literal", "::1", 8080, false, "http://[::1]:8080/cart"},
		{"ipv6 literal default port", "2606:4700::1111", 443, true, "https://[2606:4700::1111]/cart"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step, err := MacroStepFromRequest([]byte("GET /cart HTTP/1.1\r\nHost: x\r\n\r\n"), tc.host, tc.port, tc.tls)
			if err != nil {
				t.Fatalf("MacroStepFromRequest: %v", err)
			}
			if step.URL != tc.wantURL {
				t.Fatalf("URL = %q, want %q", step.URL, tc.wantURL)
			}
			u, err := url.Parse(step.URL)
			if err != nil {
				t.Fatalf("the step's URL does not parse: %v", err)
			}
			if u.Hostname() != strings.Trim(tc.host, "[]") {
				t.Errorf("parsed host = %q, want %q", u.Hostname(), tc.host)
			}
			if u.Path != "/cart" {
				t.Errorf("parsed path = %q, want /cart", u.Path)
			}
		})
	}
}

// A body is copied, not re-encoded: whatever the client sent is what the macro will send.
func TestAStepFromHistoryKeepsABodyByteForByte(t *testing.T) {
	body := "{\"a\":1}\n\n{\"b\":2}" // contains a blank line, which must not split the message
	raw := "POST /api HTTP/1.1\r\nHost: x\r\n\r\n" + body
	step, err := MacroStepFromRequest([]byte(raw), "x.test", 80, false)
	if err != nil {
		t.Fatalf("MacroStepFromRequest: %v", err)
	}
	if step.Body != body {
		t.Fatalf("Body = %q, want %q — the first blank line is the head/body boundary, not every one", step.Body, body)
	}
}

// A request with no body gets no body, and the absent blank line is not mistaken for one.
func TestAStepFromHistoryWithNoBodyIsAccepted(t *testing.T) {
	step, err := MacroStepFromRequest([]byte("GET / HTTP/1.1\r\nHost: x\r\n"), "x.test", 80, false)
	if err != nil {
		t.Fatalf("MacroStepFromRequest: %v", err)
	}
	if step.Body != "" {
		t.Errorf("Body = %q, want empty", step.Body)
	}
	if got := step.Headers["Host"]; got != "x" {
		t.Errorf("Host = %q, want x; a head with no blank line is still a head", got)
	}
}

// A repeated header cannot be held in the step's single-valued map. First-wins is the documented
// choice: the alternative is a step whose header value came from the second copy while the operator
// read the first in history.
func TestARepeatedHeaderKeepsTheFirstValue(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nX-Thing: first\r\nX-Thing: second\r\n\r\n"
	step, err := MacroStepFromRequest([]byte(raw), "x.test", 80, false)
	if err != nil {
		t.Fatalf("MacroStepFromRequest: %v", err)
	}
	if got := step.Headers["X-Thing"]; got != "first" {
		t.Errorf("X-Thing = %q, want the first value", got)
	}
}

// Refuse-by-default: a message with no request line, a target that is not origin-form, or no host to
// address it against is refused rather than turned into a step that fails at login time.
func TestAMessageThatCannotBeAStepIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		host string
	}{
		{"empty", "", "x.test"},
		{"no request line", "\r\nHost: x\r\n\r\n", "x.test"},
		{"request line with no target", "GET\r\nHost: x\r\n\r\n", "x.test"},
		// Absolute-form is what a proxy's *client* sends; a stored message is origin-form. Seeing
		// one here means these are not the bytes this function expects, and concatenating them onto
		// a scheme and host would address somewhere unintended.
		{"absolute-form target", "GET http://other.test/x HTTP/1.1\r\nHost: x\r\n\r\n", "x.test"},
		{"no host to address", "GET /x HTTP/1.1\r\n\r\n", "  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MacroStepFromRequest([]byte(tc.raw), tc.host, 80, false); err == nil {
				t.Fatal("a message that cannot be a step was accepted")
			}
		})
	}
}

// A bare-LF capture is accepted: this tree's captures are CRLF-framed, but a hand-written request or
// one assembled by a test is not, and refusing it would be pedantry rather than safety.
func TestABareLineFeedCaptureIsAccepted(t *testing.T) {
	step, err := MacroStepFromRequest([]byte("GET /x HTTP/1.1\nHost: x\n\nbody"), "x.test", 80, false)
	if err != nil {
		t.Fatalf("MacroStepFromRequest: %v", err)
	}
	if step.URL != "http://x.test/x" || step.Headers["Host"] != "x" || step.Body != "body" {
		t.Fatalf("step = %+v, want the same result a CRLF capture gives", step)
	}
}

// The lowercased method a client may have sent is normalised. A macro step's method goes into a
// request line, and the runner does not re-case it; "get" would be sent as "get".
func TestALowercaseMethodIsNormalised(t *testing.T) {
	step, err := MacroStepFromRequest([]byte("get /x HTTP/1.1\r\n\r\n"), "x.test", 80, false)
	if err != nil {
		t.Fatalf("MacroStepFromRequest: %v", err)
	}
	if step.Method != "GET" {
		t.Errorf("Method = %q, want GET", step.Method)
	}
}
