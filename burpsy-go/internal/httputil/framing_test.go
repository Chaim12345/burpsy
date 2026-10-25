package httputil

// burpsy-react-ui-0vzb.24: a response whose headers contain one malformed line is still a response.
// A CRLF injection into a header value produces exactly that line — the injected "\r\n" splits the
// field, and the fragment after it (no colon, or a name with a space) is what net/textproto's
// ReadMIMEHeader refuses with "malformed MIME header line". Refusing discarded head and body as one
// error, and the injected bytes ARE the evidence such a probe exists to collect.

import (
	"bufio"
	"strings"
	"testing"
)

func readBody(t *testing.T, raw string) ([]byte, error) {
	t.Helper()
	br := bufio.NewReader(strings.NewReader(raw))
	head, err := ReadResponseHead(br)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	return ReadResponseBody(br, head)
}

func TestReadResponseBodyToleratesAMalformedHeaderLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{
			"a CRLF-split field leaves a colon-less line",
			"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: x\r\ninjected\r\nX-Other: v\r\n\r\nhello",
			"hello",
		},
		{
			"a header name with a space",
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nBad Header: v\r\n\r\nok",
			"ok",
		},
		{
			"chunked framing still applies past the malformed line",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\ninjected\r\n\r\n2\r\nok\r\n0\r\n\r\n",
			"2\r\nok\r\n0\r\n\r\n",
		},
		{
			"an unframed body still reads to the end",
			"HTTP/1.0 200 OK\r\ninjected\r\n\r\nclose-delimited",
			"close-delimited",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := readBody(t, tc.raw)
			if err != nil {
				t.Fatalf("a malformed header line must not discard the response: %v", err)
			}
			if string(body) != tc.want {
				t.Fatalf("body = %q, want %q", body, tc.want)
			}
		})
	}
}

func TestResponseFramingPredicatesSeePastAMalformedLine(t *testing.T) {
	chunked := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\ninjected\r\n\r\n")
	if !ResponseIsChunked(chunked) {
		t.Fatal("a chunked response with a malformed header line must still read as chunked")
	}
	if ResponseIsFrameless(chunked) {
		t.Fatal("a chunked response is not frameless, malformed line or not")
	}
	frameless := []byte("HTTP/1.1 200 OK\r\ninjected\r\n\r\n")
	if !ResponseIsFrameless(frameless) {
		t.Fatal("an unframed response with a malformed header line reads close-delimited, which is what frameless names")
	}
	framed := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\ninjected\r\n\r\n")
	if ResponseIsFrameless(framed) {
		t.Fatal("a Content-Length response with a malformed header line is still framed")
	}
}

// The framing fields themselves still govern: a bad Content-Length is an error about Content-Length,
// not silently another framing.
func TestReadResponseBodyStillRejectsANonNumericContentLength(t *testing.T) {
	_, err := readBody(t, "HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\nhello")
	if err == nil || !strings.Contains(err.Error(), "Content-Length") {
		t.Fatalf("a non-numeric Content-Length must still be named, got %v", err)
	}
}
