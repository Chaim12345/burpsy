package core

import (
	"errors"
	"strings"
	"testing"
)

// These mirror crates/core/src/edit.rs's own tests one for one, so the two
// implementations are held to the same claims rather than merely looking alike.

// Mirrors splits_and_rebuilds_a_plain_request.
func TestAPlainRequestSplitsAndRebuildsByteIdentically(t *testing.T) {
	raw := []byte("GET /a?b=1 HTTP/1.1\r\nHost: x.test\r\nAccept: */*\r\n\r\n")
	e, err := ParseRequestEdit(raw)
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if e.Method != "GET" {
		t.Errorf("method = %q, want GET", e.Method)
	}
	if e.Path != "/a" {
		t.Errorf("path = %q, want /a", e.Path)
	}
	if e.Query != "b=1" {
		t.Errorf("query = %q, want b=1", e.Query)
	}
	if got := e.Header("host"); got != "x.test" {
		t.Errorf("Header(host) = %q, want x.test", got)
	}
	if got := string(e.ToRaw()); got != string(raw) {
		t.Errorf("round trip must be byte-identical:\n got %q\nwant %q", got, raw)
	}
}

// Mirrors absolute_form_target_is_split_into_origin_and_path. This is the case
// the bcheck-local editor never handled: it kept "http://x.test/a" as the path,
// so a rebuilt request went out with an absolute-form target to an origin that
// expects origin-form.
func TestAnAbsoluteFormTargetIsSplitIntoOriginAndPath(t *testing.T) {
	e, err := ParseRequestEdit([]byte("GET http://x.test/a?b=1 HTTP/1.1\r\nHost: x.test\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if e.Origin != "http://x.test" {
		t.Errorf("origin = %q, want http://x.test", e.Origin)
	}
	if e.Path != "/a" {
		t.Errorf("path = %q, want /a", e.Path)
	}
	if got := e.URL(); got != "http://x.test/a?b=1" {
		t.Errorf("URL() = %q, want http://x.test/a?b=1", got)
	}
	if got := string(e.ToRaw()); !strings.HasPrefix(got, "GET /a?b=1 HTTP/1.1") {
		t.Errorf("rebuilt request = %q, want an origin-form target", got)
	}
}

// An authority with no path at all still has to yield a usable target.
func TestAnAbsoluteFormTargetWithNoPathBecomesRoot(t *testing.T) {
	e, err := ParseRequestEdit([]byte("GET http://x.test HTTP/1.1\r\nHost: x.test\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if e.Origin != "http://x.test" || e.Path != "/" {
		t.Errorf("origin/path = %q/%q, want http://x.test and /", e.Origin, e.Path)
	}
}

// Mirrors content_length_is_recomputed_after_a_body_change. The bug this
// prevents: append to the body, leave Content-Length at 3, and the server reads
// a truncated body while the check believes it sent the full payload.
func TestContentLengthIsRecomputedAfterABodyChange(t *testing.T) {
	e, err := ParseRequestEdit([]byte("POST /f HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\na=1"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	e.Body = append(e.Body, "&b=2"...)
	out := string(e.ToRaw())
	if !strings.Contains(out, "Content-Length: 7") {
		t.Errorf("rebuilt request = %q, want Content-Length: 7", out)
	}
	if !strings.HasSuffix(out, "a=1&b=2") {
		t.Errorf("rebuilt request = %q, want it to end with the full body", out)
	}
	if n := strings.Count(out, "Content-Length"); n != 1 {
		t.Errorf("Content-Length appears %d times, want exactly 1 — a duplicate length header is ambiguous", n)
	}
}

// Mirrors chunked_bodies_are_decoded_and_re_emitted_length_delimited. The
// bcheck-local editor kept the framing, so `4\r\nWiki\r\n...` would have been
// sent as literal body content under a Content-Length.
func TestChunkedBodiesAreDecodedAndReEmittedLengthDelimited(t *testing.T) {
	raw := []byte("POST /f HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
	e, err := ParseRequestEdit(raw)
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if got := string(e.Body); got != "Wikipedia" {
		t.Errorf("body = %q, want %q — chunk framing must not survive", got, "Wikipedia")
	}
	out := string(e.ToRaw())
	if !strings.Contains(out, "Content-Length: 9") {
		t.Errorf("rebuilt request = %q, want Content-Length: 9", out)
	}
	if strings.Contains(strings.ToLower(out), "transfer-encoding") {
		t.Errorf("rebuilt request = %q, still carries a framing header alongside the length", out)
	}
	if !strings.HasSuffix(out, "Wikipedia") {
		t.Errorf("rebuilt request = %q, want the decoded body at the end", out)
	}
}

// A chunk stream that stops mid-chunk keeps whatever decoded cleanly, which is
// the same tolerance the message parser applies.
func TestATruncatedChunkStreamKeepsWhatDecodedCleanly(t *testing.T) {
	e, err := ParseRequestEdit([]byte("POST /f HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWi"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if got := string(e.Body); got != "Wi" {
		t.Errorf("body = %q, want %q", got, "Wi")
	}
}

// A chunk extension after ';' is not part of the size.
func TestAChunkExtensionIsIgnored(t *testing.T) {
	e, err := ParseRequestEdit([]byte("POST /f HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4;a=b\r\nWiki\r\n0\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if got := string(e.Body); got != "Wiki" {
		t.Errorf("body = %q, want %q", got, "Wiki")
	}
}

// Mirrors add_query_picks_question_mark_then_ampersand.
func TestAddQueryPicksQuestionMarkThenAmpersand(t *testing.T) {
	e, err := ParseRequestEdit([]byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	e.AddQuery("p=1")
	if got := e.Target(); got != "/a?p=1" {
		t.Errorf("target = %q, want /a?p=1", got)
	}
	e.AddQuery("q=2")
	if got := e.Target(); got != "/a?p=1&q=2" {
		t.Errorf("target = %q, want /a?p=1&q=2", got)
	}
	// A leading separator on the clause must not be doubled.
	e.AddQuery("&r=3")
	if got := e.Target(); got != "/a?p=1&q=2&r=3" {
		t.Errorf("target = %q, want /a?p=1&q=2&r=3", got)
	}
	e.AddQuery("?")
	if got := e.Target(); got != "/a?p=1&q=2&r=3" {
		t.Errorf("target = %q, want an empty clause to be ignored", got)
	}
}

// Mirrors set_header_replaces_all_duplicates_add_header_keeps_them.
func TestSetHeaderReplacesAllDuplicatesWhileAddHeaderKeepsThem(t *testing.T) {
	e, err := ParseRequestEdit([]byte("GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\nX-A: 2\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	e.SetHeader("X-A", "9")
	if n := countHeader(e, "X-A"); n != 1 {
		t.Errorf("X-A appears %d times after SetHeader, want 1", n)
	}
	if got := e.Header("x-a"); got != "9" {
		t.Errorf("Header(x-a) = %q, want 9", got)
	}
	e.AddHeader("X-B", "1")
	e.AddHeader("X-B", "2")
	if n := countHeader(e, "X-B"); n != 2 {
		t.Errorf("X-B appears %d times after two AddHeaders, want 2", n)
	}
	// Setting an absent header appends it.
	e.SetHeader("X-C", "3")
	if got := e.Header("X-C"); got != "3" {
		t.Errorf("Header(X-C) = %q, want 3", got)
	}
}

// Header order is preserved: replacing a value must not move it to the end.
func TestSetHeaderKeepsThePositionOfTheHeaderItReplaces(t *testing.T) {
	e, err := ParseRequestEdit([]byte("GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\nX-Z: 9\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	e.SetHeader("X-A", "2")
	if e.Headers[1][0] != "X-A" || e.Headers[2][0] != "X-Z" {
		t.Errorf("header order = %v, want Host, X-A, X-Z preserved", e.Headers)
	}
}

// Mirrors bare_lf_line_endings_parse.
func TestBareLFLineEndingsParse(t *testing.T) {
	e, err := ParseRequestEdit([]byte("GET /a HTTP/1.1\nHost: x\n\nbody"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if e.Path != "/a" {
		t.Errorf("path = %q, want /a", e.Path)
	}
	if got := string(e.Body); got != "body" {
		t.Errorf("body = %q, want %q — the blank-line separator must not be glued onto the body", got, "body")
	}
}

// Mirrors a_get_with_no_body_gets_no_content_length.
func TestAGetWithNoBodyGetsNoContentLength(t *testing.T) {
	e, err := ParseRequestEdit([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if out := string(e.ToRaw()); strings.Contains(out, "Content-Length") {
		t.Errorf("rebuilt request = %q, want no Content-Length on a bodiless GET", out)
	}
}

// Mirrors a_post_with_an_empty_body_keeps_an_explicit_zero_length.
func TestAPostWithAnEmptyBodyKeepsAnExplicitZeroLength(t *testing.T) {
	e, err := ParseRequestEdit([]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if out := string(e.ToRaw()); !strings.Contains(out, "Content-Length: 0") {
		t.Errorf("rebuilt request = %q, want an explicit Content-Length: 0", out)
	}
}

// A request with no terminator is refused, not silently treated as all head.
// Rebuilding from a head we guessed at would send an attack whose result would
// then be believed.
func TestARequestWithNoHeaderTerminatorIsRefused(t *testing.T) {
	_, err := ParseRequestEdit([]byte("GET / HTTP/1.1\r\nHost: x"))
	if !errors.Is(err, ErrNoHeaderTerminator) {
		t.Errorf("err = %v, want ErrNoHeaderTerminator", err)
	}
}

// A start line missing its target is refused rather than rebuilt as nonsense.
func TestAStartLineWithoutATargetIsRefused(t *testing.T) {
	if _, err := ParseRequestEdit([]byte("GET\r\n\r\n")); !errors.Is(err, ErrNoTarget) {
		t.Errorf("err = %v, want ErrNoTarget", err)
	}
	if _, err := ParseRequestEdit([]byte("\r\n\r\n")); !errors.Is(err, ErrNoMethod) {
		t.Errorf("err = %v, want ErrNoMethod", err)
	}
}

// URL falls back to the Host header when the target was origin-form, which is
// what makes {base.request.url} answerable for a request that never carried an
// absolute target.
func TestURLFallsBackToTheHostHeader(t *testing.T) {
	e, err := ParseRequestEdit([]byte("GET /a?b=1 HTTP/1.1\r\nHost: x.test\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestEdit: %v", err)
	}
	if got := e.URL(); got != "http://x.test/a?b=1" {
		t.Errorf("URL() = %q, want http://x.test/a?b=1", got)
	}
	if got := e.File(); got != "/a?b=1" {
		t.Errorf("File() = %q, want /a?b=1", got)
	}
}

func countHeader(e *RequestEdit, name string) int {
	n := 0
	for _, h := range e.Headers {
		if h[0] == name {
			n++
		}
	}
	return n
}

// A URL in a query value is not an absolute-form request target.
//
// The parser used to search the whole target for "://", so a redirect or callback parameter turned
// its own value into the origin: Path became whatever followed the value's first slash and the
// query was discarded entirely. Every downstream consumer then saw a different request from the one
// captured, and the insertion-point enumerator reported no query points and no declines - silently,
// on exactly the parameters worth testing.
func TestAUrlInsideAQueryValueIsNotAnAbsoluteFormTarget(t *testing.T) {
	cases := []struct {
		name, target, wantPath, wantQuery, wantOrigin, wantTarget string
	}{
		{"redirect parameter", "/r?next=https://example.com/x", "/r", "next=https://example.com/x", "",
			"/r?next=https://example.com/x"},
		{"no path after the value's host", "/r?next=https://example.com", "/r", "next=https://example.com", "",
			"/r?next=https://example.com"},
		{"scheme-relative value", "/r?next=//example.com/x", "/r", "next=//example.com/x", "",
			"/r?next=//example.com/x"},
		{"two urls", "/r?a=http://a.test/1&b=https://b.test/2", "/r", "a=http://a.test/1&b=https://b.test/2", "",
			"/r?a=http://a.test/1&b=https://b.test/2"},
		// Target() deliberately renders origin-form for an absolute-form capture; the origin is
		// carried separately. Asserted here so the round-trip check above cannot be read as a claim
		// about absolute-form requests.
		{"genuine absolute form still works", "http://proxy.test/p?q=1", "/p", "q=1", "http://proxy.test", "/p?q=1"},
		{"absolute form with no path", "https://proxy.test", "/", "", "https://proxy.test", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := ParseRequestEdit([]byte("GET " + tc.target + " HTTP/1.1\r\nHost: h\r\n\r\n"))
			if err != nil {
				t.Fatalf("ParseRequestEdit: %v", err)
			}
			if e.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q: a rewritten path sends every probe to the wrong endpoint",
					e.Path, tc.wantPath)
			}
			if e.Query != tc.wantQuery {
				t.Errorf("Query = %q, want %q: a discarded query leaves no insertion points to test",
					e.Query, tc.wantQuery)
			}
			if e.Origin != tc.wantOrigin {
				t.Errorf("Origin = %q, want %q", e.Origin, tc.wantOrigin)
			}
			// An origin-form target must round-trip exactly, or the request the scanner sends is
			// not the request it captured.
			if got := e.Target(); got != tc.wantTarget {
				t.Errorf("Target() = %q, want %q", got, tc.wantTarget)
			}
		})
	}
}

func TestIsSchemeTokenAcceptsOnlyRFC3986Schemes(t *testing.T) {
	for _, ok := range []string{"http", "https", "a", "a1", "a+b", "a-b", "a.b", "coap+ws"} {
		if !isSchemeToken(ok) {
			t.Errorf("isSchemeToken(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "1a", "/r?next=https", "a_b", "a b", "-a", "a/b"} {
		if isSchemeToken(bad) {
			t.Errorf("isSchemeToken(%q) = true, want false: a non-scheme prefix must not make a "+
				"target look absolute-form", bad)
		}
	}
}
