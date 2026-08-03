package matchreplace

import (
	"bytes"
	"strings"
	"testing"
)

func newBodyRule(t *testing.T, match, replace string) *Rule {
	t.Helper()
	r, err := NewRule(TargetRequestBody, CategoryLiteral, match, replace, "test")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	return r
}

// An update_content_length=true rewrite fixes the Content-Length header to the new body size.
func TestApplyUpdateContentLengthRewritesHeader(t *testing.T) {
	raw := []byte("POST / HTTP/1.1\r\nContent-Length: 3\r\nHost: a\r\n\r\nfoo")
	rs := NewRuleSet()
	rs.SetRules([]*Rule{newBodyRule(t, "foo", "foobar")})
	rs.SetUpdateContentLength(true)

	out := rs.Apply(DirRequest, raw)
	if !bytes.Contains(out, []byte("Content-Length: 6")) {
		t.Errorf("output %q does not fix Content-Length to 6", out)
	}
	if !bytes.HasSuffix(out, []byte("\r\n\r\nfoobar")) {
		t.Errorf("output %q does not keep the rewritten body", out)
	}
}

// When update_content_length is off, Apply rewrites the body but leaves the header alone.
func TestApplyWithoutUpdateContentLengthLeavesHeader(t *testing.T) {
	raw := []byte("POST / HTTP/1.1\r\nContent-Length: 3\r\nHost: a\r\n\r\nfoo")
	rs := NewRuleSet()
	rs.SetRules([]*Rule{newBodyRule(t, "foo", "foobar")})

	out := rs.Apply(DirRequest, raw)
	if !bytes.Contains(out, []byte("Content-Length: 3")) {
		t.Errorf("output %q should keep the original Content-Length", out)
	}
}

// A body rewrite with no Content-Length header gets one appended when the flag is on.
func TestApplyAppendsContentLengthWhenMissing(t *testing.T) {
	raw := []byte("POST / HTTP/1.1\r\nHost: a\r\n\r\nfoo")
	rs := NewRuleSet()
	rs.SetRules([]*Rule{newBodyRule(t, "foo", "foobar")})
	rs.SetUpdateContentLength(true)

	out := rs.Apply(DirRequest, raw)
	if !bytes.Contains(out, []byte("Content-Length: 6")) {
		t.Errorf("output %q should append Content-Length: 6", out)
	}
}

// A rule that matches nothing leaves the raw bytes untouched.
func TestApplyWithNoMatchReturnsRaw(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	rs := NewRuleSet()
	rs.SetRules([]*Rule{newBodyRule(t, "nope", "foobar")})
	rs.SetUpdateContentLength(true)

	out := rs.Apply(DirRequest, raw)
	if !bytes.Equal(out, raw) {
		t.Errorf("output %q should equal input %q", out, raw)
	}
}

// SetUpdateContentLength / UpdateContentLength round-trip.
func TestUpdateContentLengthFlagRoundTrip(t *testing.T) {
	rs := NewRuleSet()
	if rs.UpdateContentLength() {
		t.Error("flag should default to false")
	}
	rs.SetUpdateContentLength(true)
	if !rs.UpdateContentLength() {
		t.Error("flag should be true after SetUpdateContentLength(true)")
	}
	rs.SetUpdateContentLength(false)
	if rs.UpdateContentLength() {
		t.Error("flag should be false after SetUpdateContentLength(false)")
	}
}

// Regression for the C2 buffer-overwrite: when Content-Length is the last header
// and the recomputed length is longer than the original, the old
// `append(line[:colon+1], " "+length)` wrote past the header into the shared
// backing array, corrupting the separator and body. The rewritten rule builds a
// fresh slice, so the body on the wire must survive byte-for-byte.
func TestApplyContentLengthLastHeaderLongerValueNoCorruption(t *testing.T) {
	big := strings.Repeat("x", 1_000_000) // original body "x" → 1,000,000 ⇒ new CL "1000000" is 4 digits longer
	raw := []byte("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx")
	rs := NewRuleSet()
	rs.SetRules([]*Rule{newBodyRule(t, "x", big)})
	rs.SetUpdateContentLength(true)

	out := rs.Apply(DirRequest, raw)

	if !bytes.Contains(out, []byte("Content-Length: 1000000")) {
		t.Fatalf("output does not fix Content-Length to 1000000: %q", out[:120])
	}
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(out, sep)
	if idx < 0 {
		t.Fatalf("output %q has no header/body separator", out[:120])
	}
	body := out[idx+len(sep):]
	if string(body) != big {
		t.Fatalf("body corrupted: got %d bytes, want %d intact; head=%q", len(body), len(big), body[:min(len(body), 20)])
	}
	if !bytes.HasSuffix(out, []byte("Content-Length: 1000000\r\n\r\n"+big)) {
		t.Fatalf("output tail does not match expectation")
	}
}
