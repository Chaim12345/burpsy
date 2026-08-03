package bcheck

import (
	"reflect"
	"strings"
	"testing"
)

// req parses a raw request for the enumerator, failing the test if it cannot.
func req(t *testing.T, raw string) []byte {
	t.Helper()
	return []byte(raw)
}

func names(ps []InsertionPoint) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p.Kind)+":"+p.Name)
	}
	return out
}

func TestAnyEnumeratesQueryHeadersAndCookiesInAFixedOrder(t *testing.T) {
	r := req(t, "GET /s?q=cat&page=2 HTTP/1.1\r\nHost: x.test\r\nUser-Agent: burpsy\r\nCookie: sid=abc; theme=dark\r\n\r\n")
	ps, _ := Enumerate(r, []string{"any"})
	want := []string{"query:q", "query:page", "header:User-Agent", "cookie:sid", "cookie:theme"}
	if !reflect.DeepEqual(names(ps), want) {
		t.Errorf("points = %v, want %v (Host and Cookie must not appear as header points)", names(ps), want)
	}
	if ps[0].BaseValue != "cat" {
		t.Errorf("ps[0].BaseValue = %q, want %q", ps[0].BaseValue, "cat")
	}
	if ps[4].BaseValue != "dark" {
		t.Errorf("ps[4].BaseValue = %q, want %q", ps[4].BaseValue, "dark")
	}
}

func TestAQueryClauseWithNoEqualsIsNotAPoint(t *testing.T) {
	// `?debug` has no value; inventing `?debug=payload` would send a parameter
	// the application was never given, under the original's name.
	r := req(t, "GET /s?debug&q=1 HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"query"})
	if !reflect.DeepEqual(names(ps), []string{"query:q"}) {
		t.Errorf("points = %v, want [query:q]", names(ps))
	}
}

func TestAFormBodyYieldsOnePointPerField(t *testing.T) {
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\na=1&user=bo")
	ps, _ := Enumerate(r, []string{"body"})
	if !reflect.DeepEqual(names(ps), []string{"body:a", "body:user"}) {
		t.Errorf("points = %v, want [body:a body:user]", names(ps))
	}
	if ps[1].BaseValue != "bo" {
		t.Errorf("ps[1].BaseValue = %q, want %q", ps[1].BaseValue, "bo")
	}
}

func TestJSONStringValuesArePointsAndNumbersAreNot(t *testing.T) {
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 46\r\n\r\n{\"user\":\"bo\",\"age\":31,\"tags\":[\"a\",\"b\"],\"ok\":true}")
	ps, _ := Enumerate(r, []string{"body"})
	want := []string{"body:user", "body:tags[0]", "body:tags[1]"}
	if !reflect.DeepEqual(names(ps), want) {
		t.Errorf("points = %v, want %v (a payload spliced into `31` or `true` makes the body unparsable)", names(ps), want)
	}
	if ps[2].BaseValue != "b" {
		t.Errorf("ps[2].BaseValue = %q, want %q", ps[2].BaseValue, "b")
	}
}

func TestAMultipartBodyYieldsNoPoints(t *testing.T) {
	// We do not model multipart framing, and a payload spliced blind into it
	// produces a body the server rejects before the application sees the payload.
	r := req(t, "POST /u HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 40\r\n\r\n--B\r\nContent-Disposition: form-data\r\n\r\nv\r\n")
	ps, _ := Enumerate(r, []string{"any"})
	for _, p := range ps {
		if p.Kind == IpBody {
			t.Errorf("multipart body produced a body point %q; framing is not modelled", p.Name)
		}
	}
}

func TestAppendingToAQueryPointLeavesEveryOtherParameterByteIdentical(t *testing.T) {
	r := req(t, "GET /s?q=cat&page=2&sort=asc HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"query"})
	out, err := ps[1].Apply(r, "'", true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !strings.Contains(string(out), "GET /s?q=cat&page=2'&sort=asc") {
		t.Errorf("query = %q, want %q", string(out), "GET /s?q=cat&page=2'&sort=asc")
	}
}

func TestReplacingOverwritesOnlyTheTargetedValue(t *testing.T) {
	r := req(t, "GET /s?q=cat&page=2 HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"query"})
	out, err := ps[0].Apply(r, "X", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !strings.Contains(string(out), "GET /s?q=X&page=2") {
		t.Errorf("query = %q, want %q", string(out), "GET /s?q=X&page=2")
	}
}

func TestAPayloadCarryingSeparatorsCannotSplitAParameter(t *testing.T) {
	// Raw, `evil&admin=1` would become a second parameter and the check would
	// be testing a request nobody wrote.
	r := req(t, "GET /s?q=cat HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"query"})
	out, err := ps[0].Apply(r, "evil&admin=1", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !strings.Contains(string(out), "GET /s?q=evil%26admin%3D1") {
		t.Errorf("query = %q, want %q", string(out), "GET /s?q=evil%26admin%3D1")
	}
}

func TestAHeaderPayloadIsNotPercentEscaped(t *testing.T) {
	// There is no k=v container in a header value, so escaping would only
	// corrupt the payload.
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\nX-Probe: base\r\n\r\n")
	ps, _ := Enumerate(r, []string{"header"})
	out, err := ps[0].Apply(r, " a=b&c ", true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !strings.Contains(string(out), "X-Probe: base a=b&c ") {
		t.Errorf("X-Probe = %q, want %q", string(out), "X-Probe: base a=b&c ")
	}
}

func TestACookiePayloadTouchesOneCookieAndKeepsTheSeparators(t *testing.T) {
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\nCookie: sid=abc; theme=dark\r\n\r\n")
	ps, _ := Enumerate(r, []string{"cookie"})
	out, err := ps[0].Apply(r, "';", true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !strings.Contains(string(out), "Cookie: sid=abc'%3B; theme=dark") {
		t.Errorf("cookie = %q, want %q", string(out), "Cookie: sid=abc'%3B; theme=dark")
	}
}

func TestAJSONPayloadIsEscapedSoTheBodyStaysWellFormed(t *testing.T) {
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"user\":\"bo\",\"role\":\"u\"}")
	ps, _ := Enumerate(r, []string{"body"})
	out, err := ps[0].Apply(r, `"}); drop`, true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	body := string(out)
	if !strings.HasSuffix(body, `{"user":"bo\"}); drop","role":"u"}`) {
		t.Errorf("body = %q, want %q", body, `{"user":"bo\"}); drop","role":"u"}`)
	}
}

func TestTheContentLengthFollowsABodyPayload(t *testing.T) {
	// A stale length truncates the probe server-side, so the payload never
	// arrives whole.
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1")
	ps, _ := Enumerate(r, []string{"body"})
	out, err := ps[0].Apply(r, "234", true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "Content-Length: 6") {
		t.Errorf("Content-Length not rewritten: %q", s)
	}
	if !strings.HasSuffix(s, "a=1234") {
		t.Errorf("body = %q, want suffix %q", s, "a=1234")
	}
}

func TestQualifiersSelectWhichFamiliesAreEnumerated(t *testing.T) {
	r := req(t, "POST /s?q=1 HTTP/1.1\r\nHost: x\r\nX-A: v\r\nCookie: c=1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\nb=2")
	ps, _ := Enumerate(r, []string{"query", "body"})
	if !reflect.DeepEqual(names(ps), []string{"query:q", "body:b"}) {
		t.Errorf("points = %v, want [query:q body:b]", names(ps))
	}
}

func TestARequestWithNowhereToInjectYieldsNoPoints(t *testing.T) {
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, declined := Enumerate(r, []string{"any"})
	if len(ps) != 0 || len(declined) != 0 {
		t.Errorf("points = %v declined = %v, want both empty", ps, declined)
	}
}

func TestAMultipartBodyIsReportedAsDeclinedNotSilentlyEmpty(t *testing.T) {
	// The old behaviour (before the Declined type existed) returned no points
	// and no record of the refusal, so a `given body insertion point` check
	// against a multipart form reported "tested, found nothing" while testing
	// nothing at all — the silent false negative.
	r := req(t, "POST /u HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 40\r\n\r\n--B\r\nContent-Disposition: form-data\r\n\r\nv\r\n")
	ps, declined := Enumerate(r, []string{"body"})
	if len(ps) != 0 {
		t.Errorf("points = %v, want none (multipart framing is not spliced into)", names(ps))
	}
	if len(declined) != 1 {
		t.Fatalf("declined = %d, want 1 (the refusal is recorded, not swallowed)", len(declined))
	}
	if declined[0].What != "request body" {
		t.Errorf("declined.What = %q, want %q", declined[0].What, "request body")
	}
	if !strings.Contains(declined[0].Reason, "multipart") {
		t.Errorf("declined.Reason = %q, want it to name what was refused", declined[0].Reason)
	}
}

func TestANonUTF8BodyIsReportedAsDeclined(t *testing.T) {
	raw := append([]byte("POST /u HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\n"), 0xff, 0xfe, 0xfd)
	ps, declined := Enumerate(raw, []string{"body"})
	if len(ps) != 0 {
		t.Errorf("points = %v, want none", names(ps))
	}
	if len(declined) != 1 {
		t.Fatalf("declined = %d, want 1", len(declined))
	}
	if !strings.Contains(declined[0].Reason, "UTF-8") {
		t.Errorf("declined.Reason = %q, want it to name the encoding problem", declined[0].Reason)
	}
}

func TestAFormBodyIsEnumeratedWithNoDecline(t *testing.T) {
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1")
	ps, declined := Enumerate(r, []string{"body"})
	if !reflect.DeepEqual(names(ps), []string{"body:a"}) {
		t.Errorf("points = %v, want [body:a]", names(ps))
	}
	if len(declined) != 0 {
		t.Errorf("declined = %v, want none (a modelled container is not declined)", declined)
	}
}

func TestSpliceAtAMidCodepointOffsetFloorsToTheCharBoundary(t *testing.T) {
	// "é" is two bytes (0xC3 0xA9), so the char boundaries of "aéb" are
	// {0,1,3,4}. Offsets 1 and 2 are not both legal: 1 is the boundary before
	// é, 2 lands inside it. Flooring moves an interior offset to the preceding
	// boundary rather than producing invalid UTF-8.
	s := "a\u00e9b" // a, é (2 bytes), b — len 4
	if got := spliceStr(s, 1, 2, "X"); got != "aX\u00e9b" {
		t.Errorf("spliceStr(s,1,2,\"X\") = %q, want %q (end=2 floors to 1, so é survives)", got, "aX\u00e9b")
	}
	if got := spliceStr(s, 2, 3, "X"); got != "aXb" {
		t.Errorf("spliceStr(s,2,3,\"X\") = %q, want %q (start=2 floors to 1, so é is replaced)", got, "aXb")
	}
}

func TestSplicePastAMultiByteCharDoesNotCorruptIt(t *testing.T) {
	s := "\u00e9ab" // é (2 bytes), a, b — len 4
	if got := spliceStr(s, 3, 4, "X"); got != "\u00e9aX" {
		t.Errorf("spliceStr(s,3,4,\"X\") = %q, want %q (the trailing byte splice leaves é whole)", got, "\u00e9aX")
	}
}

func TestParseInsertionPointGiven(t *testing.T) {
	src := `
given query or header insertion point then
  send payload called payload:
    appending: ` + "`{insertion_point_base_value}`" + `
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if c.Given != "insertion point" {
		t.Errorf("given = %q, want %q", c.Given, "insertion point")
	}
	want := []string{"query", "header"}
	if !reflect.DeepEqual(c.InsertionKinds, want) {
		t.Errorf("InsertionKinds = %v, want %v", c.InsertionKinds, want)
	}
}

func TestParseBareInsertionPointGiven(t *testing.T) {
	src := `
given insertion point then
  report issue:
    severity: low
    confidence: certain
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if c.Given != "insertion point" {
		t.Errorf("given = %q, want %q", c.Given, "insertion point")
	}
	if !reflect.DeepEqual(c.InsertionKinds, []string{"any"}) {
		t.Errorf("InsertionKinds = %v, want [any]", c.InsertionKinds)
	}
}
