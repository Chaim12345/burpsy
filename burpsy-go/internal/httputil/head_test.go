package httputil

import (
	"bytes"
	"testing"
)

// The head API (burpsy-react-ui-6858 slice A): the head searches and header reads of the
// proxy, sender and intruder packages funnel here, so their edge cases live in exactly one
// place; the rest of the tree's searches are slice B.

func TestSplitHeadBodyKeepsTheSeparatorItFound(t *testing.T) {
	head, body, sep, ok := SplitHeadBody([]byte("HTTP/1.1 200 OK\r\nA: b\r\n\r\nBODY"))
	if !ok || string(head) != "HTTP/1.1 200 OK\r\nA: b" || string(body) != "BODY" || string(sep) != "\r\n\r\n" {
		t.Errorf("CRLF split = %q %q %q %v", head, body, sep, ok)
	}
	head, body, sep, ok = SplitHeadBody([]byte("GET / HTTP/1.1\nA: b\n\nBODY"))
	if !ok || string(sep) != "\n\n" || string(body) != "BODY" {
		t.Errorf("LF split = %q %q %q %v", head, body, sep, ok)
	}
	if _, _, _, ok := SplitHeadBody([]byte("no terminator")); ok {
		t.Error("a message with no terminator split")
	}
	// The FIRST terminator wins: a body containing a blank line is not a second head.
	_, body, _, _ = SplitHeadBody([]byte("A: b\r\n\r\nx\r\n\r\ny"))
	if string(body) != "x\r\n\r\ny" {
		t.Errorf("body after first terminator = %q", body)
	}
}

func TestCutHeadIsStrictCRLF(t *testing.T) {
	if _, _, ok := CutHead([]byte("A: b\n\nBODY")); ok {
		t.Error("CutHead accepted a bare-LF terminator: on the wire that is not one")
	}
	head, body, ok := CutHead([]byte("A: b\r\n\r\nBODY"))
	if !ok || string(head) != "A: b" || string(body) != "BODY" {
		t.Errorf("CutHead = %q %q %v", head, body, ok)
	}
}

func TestHeadEndCountsPastTheSeparatorItFound(t *testing.T) {
	if got := HeadEnd([]byte("A: b\r\n\r\nBODY")); got != 8 {
		t.Errorf("CRLF HeadEnd = %d, want 8", got)
	}
	if got := HeadEnd([]byte("A: b\n\nBODY")); got != 6 {
		t.Errorf("LF HeadEnd = %d, want 6", got)
	}
	if got := HeadEnd([]byte("none")); got != -1 {
		t.Errorf("HeadEnd without terminator = %d, want -1", got)
	}
}

func TestHeadLinesSkipsTheStartLineAndToleratesLF(t *testing.T) {
	lines := HeadLines([]byte("GET / HTTP/1.1\r\nA: b\nC: d"))
	if len(lines) != 2 || !bytes.Equal(lines[0], []byte("A: b")) || !bytes.Equal(lines[1], []byte("C: d")) {
		t.Errorf("lines = %q", lines)
	}
	// A trailing line ending yields a trailing empty line; readers skip empty lines, as the
	// proxy's retired copy did.
	lines = HeadLines([]byte("GET / HTTP/1.1\r\nA: b\r\n"))
	if len(lines) != 2 || !bytes.Equal(lines[1], []byte{}) {
		t.Errorf("trailing newline gave %q", lines)
	}
	if lines := HeadLines([]byte("one-line")); lines != nil {
		t.Errorf("a start line alone gave %q", lines)
	}
}

func TestHeaderValueFindsTheFirstMatchCaseInsensitively(t *testing.T) {
	head := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\ncontent-type: ignored\r\nX-Trace:  abc \r\n\r\n")
	if v, ok := HeaderValue(head, "content-TYPE"); !ok || v != "text/html" {
		t.Errorf("first match = %q %v", v, ok)
	}
	if v, ok := HeaderValue(head, "x-trace"); !ok || v != "abc" {
		t.Errorf("value is trimmed: %q %v", v, ok)
	}
	if _, ok := HeaderValue(head, "absent"); ok {
		t.Error("an absent header reported present")
	}
	// The start line is not a header: an absolute-form request target's colon must not match.
	if _, ok := HeaderValue([]byte("GET http://content-type:80/x HTTP/1.1\r\n\r\n"), "content-type"); ok {
		t.Error("the request line was read as a header")
	}
	// A field name with whitespace before its colon still matches; a different name does not.
	if v, ok := HeaderValue([]byte("HTTP/1.1 200 OK\r\nA : b\r\n\r\n"), "a"); !ok || v != "b" {
		t.Errorf("spaced colon = %q %v", v, ok)
	}
}

func TestSplitHeadBodyPrefersCRLFOverAnEarlierBareLF(t *testing.T) {
	head, body, sep, ok := SplitHeadBody([]byte("HTTP/1.1 200 OK\n\nA: b\r\n\r\nBODY"))
	if !ok || string(head) != "HTTP/1.1 200 OK\n\nA: b" || string(body) != "BODY" || string(sep) != "\r\n\r\n" {
		t.Errorf("mixed terminators = %q %q %q %v, want the split at the CRLF terminator", head, body, sep, ok)
	}
}

func TestHeaderValueExactKeepsTheStrictShape(t *testing.T) {
	head := []byte("HTTP/1.1 200 OK\r\nContent-Encoding : gzip\r\n  Content-Encoding: br\r\nContent-Encoding : identity\r\nX: y")
	if _, ok := HeaderValueExact(head, "Content-Encoding"); ok {
		t.Error("a field name padded with a space before its colon was recognized")
	}
	if _, ok := HeaderValueExact([]byte("HTTP/1.1 200 OK\r\n  Content-Encoding: gzip\r\n"), "Content-Encoding"); ok {
		t.Error("a field name indented with leading whitespace was recognized")
	}
	if _, ok := HeaderValueExact([]byte("HTTP/1.1 200 OK\r\nContent-Encoding : gzip\r\n"), "Content-Encoding"); ok {
		t.Error("a field name padded with a Unicode space (NBSP) was recognized")
	}
	// Case still does not matter, and the value keeps its TrimSpace.
	v, ok := HeaderValueExact([]byte("HTTP/1.1 200 OK\r\ncOnTeNt-eNcOdInG:  gzip \r\n"), "content-encoding")
	if !ok || v != "gzip" {
		t.Errorf("plain mixed-case read = %q %v, want gzip true", v, ok)
	}
	// First match wins, as the retired copy's line scan did.
	v, ok = HeaderValueExact([]byte("HTTP/1.1 200 OK\r\nX: one\r\nX: two\r\n"), "X")
	if !ok || v != "one" {
		t.Errorf("first-match = %q %v, want one true", v, ok)
	}
}

// The start-line drop is the contract the header reads rely on: every call site passes a head
// whose line 0 is the request or status line (audited at burpsy-react-ui-6858 P3: unpack and
// applyResponseRules pass SplitHeadBody heads of full messages; the invisible Host read passes
// requestHead of the full request; headerInt/headerHasToken take the buffered request head;
// the alt-svc read takes resp[:headEnd] of the upstream response; headIsEventStream and
// sender's keepalive take response heads whose status line keepalive validates first). If this
// drop ever changed, a first-line header would silently become visible to every read.
func TestHeadLinesAlwaysDropsTheFirstLine(t *testing.T) {
	lines := HeadLines([]byte("Host: x\r\nAccept: y"))
	if len(lines) != 1 || string(lines[0]) != "Accept: y" {
		t.Errorf("HeadLines = %q, want just [Accept: y] - the first line is never a header", lines)
	}
}
