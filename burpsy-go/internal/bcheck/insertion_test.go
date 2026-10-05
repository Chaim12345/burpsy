package bcheck

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
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

func baseValues(ps []InsertionPoint) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.BaseValue)
	}
	return out
}

// postBody builds a POST whose Content-Length actually matches the body, so a
// test never depends on what a parser does with a stale length.
func postBody(ctype, body string) []byte {
	return []byte(fmt.Sprintf("POST /u HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", ctype, len(body), body))
}

// bodyOf returns the body of a raw request. SplitN with n=2 matters: a
// multipart body contains blank lines of its own.
func bodyOf(t *testing.T, raw []byte) string {
	t.Helper()
	half := strings.SplitN(string(raw), "\r\n\r\n", 2)
	if len(half) != 2 {
		t.Fatalf("spliced request has no header/body separator, so nothing was sent as a body: %q", raw)
	}
	return half[1]
}

// twoPartForm is a well-formed multipart body: a plain field and a file part.
const twoPartForm = "--B\r\n" +
	"Content-Disposition: form-data; name=\"user\"\r\n" +
	"\r\n" +
	"bo\r\n" +
	"--B\r\n" +
	"Content-Disposition: form-data; name=\"avatar\"; filename=\"a.txt\"\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"hello\r\n" +
	"--B--\r\n"

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

func TestAMultipartBodyYieldsAPointPerPartContentNameAndFilename(t *testing.T) {
	// A multipart form's parameters are the parts. Falling back to one
	// entire-body point would report "the body is injectable" without ever
	// saying which field, which is not a finding.
	r := postBody("multipart/form-data; boundary=B", twoPartForm)
	ps, declined := Enumerate(r, []string{"body"})
	want := []string{"body:user", "multipart_attr:user name", "body:avatar", "multipart_attr:avatar name", "multipart_attr:avatar filename"}
	if !reflect.DeepEqual(names(ps), want) {
		t.Errorf("points = %v, want %v (each part contributes its content and each Content-Disposition attribute it declares)", names(ps), want)
	}
	wantBase := []string{"bo", "user", "hello", "avatar", "a.txt"}
	if !reflect.DeepEqual(baseValues(ps), wantBase) {
		t.Errorf("BaseValues = %v, want %v (the raw wire value, with an attribute's quotes stripped)", baseValues(ps), wantBase)
	}
	if len(declined) != 0 {
		t.Errorf("declined = %v, want none (multipart framing is modelled now, so nothing about this body is skipped)", declined)
	}
}

func TestAMultipartPartWithNoNameAttributeIsLabelledByItsPartIndex(t *testing.T) {
	// A nameless part is still a place a payload goes, so it gets a label a
	// finding can be attributed to rather than being dropped.
	body := "--B\r\n" +
		"Content-Disposition: form-data; name=\"user\"\r\n\r\nbo\r\n" +
		"--B\r\n" +
		"Content-Type: text/plain\r\n\r\nraw\r\n" +
		"--B--\r\n"
	r := postBody("multipart/form-data; boundary=B", body)
	ps, _ := Enumerate(r, []string{"body"})
	want := []string{"body:user", "multipart_attr:user name", "body:part[1]"}
	if !reflect.DeepEqual(names(ps), want) {
		t.Errorf("points = %v, want %v (the nameless part is labelled by its own 0-based index, and declares no attribute to inject into)", names(ps), want)
	}
	if ps[2].BaseValue != "raw" {
		t.Errorf("part[1].BaseValue = %q, want %q (the label is synthesised, the value is still read off the wire)", ps[2].BaseValue, "raw")
	}
}

func TestAPayloadSplicedIntoOneMultipartPartLeavesTheWholeBodyParseable(t *testing.T) {
	// The point of splicing one part rather than the whole body: a real
	// multipart parser must still find every part, and the payload must reach
	// the application as the bytes the check wrote.
	r := postBody("multipart/form-data; boundary=B", twoPartForm)
	ps, _ := Enumerate(r, []string{"body"})
	const payload = `<script>alert("x")</script>`
	out, err := ps[0].Apply(r, payload, false)
	if err != nil {
		t.Fatalf("a payload with no boundary delimiter in it is spliceable, but Apply refused it: %v", err)
	}
	mr := multipart.NewReader(strings.NewReader(bodyOf(t, out)), "B")

	first, err := mr.NextPart()
	if err != nil {
		t.Fatalf("the spliced body no longer reads as a part list, so the server would reject it before the payload was seen: %v", err)
	}
	if first.FormName() != "user" {
		t.Errorf("first part is named %q, want %q (the splice must not disturb the part's own headers)", first.FormName(), "user")
	}
	got, err := io.ReadAll(first)
	if err != nil {
		t.Fatalf("reading the spliced part failed, so its content is not recoverable: %v", err)
	}
	if string(got) != payload {
		t.Errorf("the application would receive %q, not the %q the check wrote: a part's content has no escape, so it must arrive verbatim", got, payload)
	}

	second, err := mr.NextPart()
	if err != nil {
		t.Fatalf("the sibling part disappeared from the spliced body: %v", err)
	}
	if second.FormName() != "avatar" || second.FileName() != "a.txt" {
		t.Errorf("sibling part is %q/%q, want avatar/a.txt (splicing one point must leave every other byte alone)", second.FormName(), second.FileName())
	}
	if sib, _ := io.ReadAll(second); string(sib) != "hello" {
		t.Errorf("sibling part content = %q, want %q (a finding is only attributable if nothing else moved)", sib, "hello")
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Errorf("the part list did not end where it should (err = %v); a spliced body that grew a part is framing the check invented", err)
	}
}

func TestAMultipartAttributeSpliceBackslashEscapesQuotesAndBackslashes(t *testing.T) {
	// A part's `name` lives in a MIME quoted-string. An unescaped quote would
	// end the attribute and the header would mean something the check did not write.
	r := postBody("multipart/form-data; boundary=B", twoPartForm)
	ps, _ := Enumerate(r, []string{"body"})
	if ps[1].Name != "user name" {
		t.Fatalf("ps[1] is %q, want the `user name` attribute point", ps[1].Name)
	}
	out, err := ps[1].Apply(r, `a"b\c`, false)
	if err != nil {
		t.Fatalf("a quote and a backslash are escapable in a quoted-string, so Apply should not refuse them: %v", err)
	}
	const wantAttr = `name="a\"b\\c"`
	if !strings.Contains(bodyOf(t, out), wantAttr) {
		t.Errorf("body = %q, want it to carry %s so the quoted-string still closes where it started and the header keeps meaning what the check wrote", bodyOf(t, out), wantAttr)
	}
}

func TestAMultipartPartContentRefusesAPayloadCarryingTheBoundaryDelimiter(t *testing.T) {
	// A part's content has no escape, so a payload that would start the next
	// part cannot be written into one. Rewriting it would send bytes the check
	// never wrote; refusing says so out loud.
	r := postBody("multipart/form-data; boundary=B", twoPartForm)
	ps, _ := Enumerate(r, []string{"body"})
	if _, err := ps[0].Apply(r, "x\r\n--Bevil", false); err == nil {
		t.Error("Apply accepted a payload containing CRLF + the boundary delimiter; that payload re-frames every part after it, so the request under test is no longer the one the check described")
	}
}

func TestANestedPointInsideAMultipartPartRefusesTheBoundaryDelimiter(t *testing.T) {
	// The outer container decides what a payload may contain, and the check
	// happens on the value that is actually spliced — not on the payload. XML
	// escaping leaves a CRLF and the delimiter bytes themselves intact, so a
	// nested point whose rebuilt inner value would re-frame its part has to be
	// refused for exactly the reason its parent is.
	body := "--B\r\n" +
		"Content-Disposition: form-data; name=\"doc\"\r\n" +
		"\r\n" +
		"<r><v>seed</v></r>\r\n" +
		"--B--\r\n"
	r := postBody("multipart/form-data; boundary=B", body)
	ps, _ := Enumerate(r, []string{"body"})
	var nested *InsertionPoint
	for i := range ps {
		if ps[i].coding == codingNested {
			nested = &ps[i]
		}
	}
	if nested == nil {
		t.Fatalf("no nested point inside the part's XML value: %v", names(ps))
	}
	if _, err := nested.Apply(r, "ok", false); err != nil {
		t.Fatalf("an ordinary payload must still splice into the nested value, but Apply refused it: %v", err)
	}
	if _, err := nested.Apply(r, "x\r\n--Bevil", false); err == nil {
		t.Error("a nested payload that rebuilds to CRLF + the delimiter was accepted; it re-frames the part exactly as a raw one would, so the refusal must survive the inner escape")
	}
}

func TestAMultipartAttributeRefusesACarriageReturnLineFeedOrNUL(t *testing.T) {
	// There is no spelling of a line break inside a MIME quoted-string, so
	// these payloads end the header line instead of landing in the value.
	r := postBody("multipart/form-data; boundary=B", twoPartForm)
	ps, _ := Enumerate(r, []string{"body"})
	for _, bad := range []string{"a\rb", "a\nb", "a\x00b"} {
		if _, err := ps[1].Apply(r, bad, false); err == nil {
			t.Errorf("Apply accepted %q into a Content-Disposition attribute; that byte cannot appear in a quoted-string, so the header would end early and the probe would not be the one described", bad)
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

func TestACookiePayloadArrivesVerbatimAndTouchesOneClause(t *testing.T) {
	// A cookie value is an opaque octet run (codingCookieValue), not a
	// percent-encoded form pair: whatever the check writes is what the server's
	// cookie reader hands the application. Go's r.Cookie does not decode, so a
	// percent-escaped `=` would arrive as `%3D` and an event-handler payload
	// would be dead on arrival — the corruption the form codec produced here
	// before. The `=` must travel raw, and the sibling clause must be untouched.
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\nCookie: sid=abc; theme=dark\r\n\r\n")
	ps, _ := Enumerate(r, []string{"cookie"})
	out, err := ps[0].Apply(r, `<svg onload=alert(1)>`, true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !strings.Contains(string(out), "Cookie: sid=abc<svg onload=alert(1)>; theme=dark") {
		t.Errorf("cookie = %q, want the payload verbatim in sid's clause with theme=dark intact", string(out))
	}
}

func TestACookiePayloadCarryingAClauseTerminatorIsRefusedNotEscaped(t *testing.T) {
	// `;` ends the cookie clause. There is no spelling of a terminator inside the
	// value, and percent-escaping it would hand the server a payload other than
	// the one the check wrote — so the point refuses it, exactly like the
	// multipart container refuses a boundary. The old behaviour, escaping it to
	// %3B, produced a wire value whose reflection could not carry a marker and
	// whose meaning the server read differently from the check's own analysis.
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\nCookie: sid=abc; theme=dark\r\n\r\n")
	ps, _ := Enumerate(r, []string{"cookie"})
	if _, err := ps[0].Apply(r, "';", true); err == nil {
		t.Fatal("a payload containing `;` was applied; it would end sid's clause and splice itself into the cookie list, so it must be refused")
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

func TestASyntheticHeaderPointIsEmittedOnlyForHeadersTheBaseRequestLacks(t *testing.T) {
	r := req(t, "GET /s HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, declined := Enumerate(r, []string{"synthetic_header"})
	if !reflect.DeepEqual(names(ps), []string{"synthetic_header:Referer", "synthetic_header:User-Agent"}) {
		t.Errorf("points = %v, want a Referer and a User-Agent point when the request carries neither", names(ps))
	}
	if len(declined) != 0 {
		t.Errorf("declined = %v, want none", declined)
	}
	if ps[0].BaseValue != "" {
		t.Errorf("Referer BaseValue = %q, want empty (the header does not exist on the wire)", ps[0].BaseValue)
	}

	hasBoth := req(t, "GET /s HTTP/1.1\r\nHost: x\r\nUser-Agent: burpsy/1\r\nReferer: https://a.example/ref\r\n\r\n")
	ps2, _ := Enumerate(hasBoth, []string{"synthetic_header"})
	if len(ps2) != 0 {
		t.Errorf("points = %v, want none when both headers are already carried (a second identical probe could not be attributed)", names(ps2))
	}

	hasUA := req(t, "GET /s HTTP/1.1\r\nHost: x\r\nuser-agent: burpsy/1\r\n\r\n")
	ps3, _ := Enumerate(hasUA, []string{"synthetic_header"})
	if !reflect.DeepEqual(names(ps3), []string{"synthetic_header:Referer"}) {
		t.Errorf("points = %v, want only the absent Referer (the case-insensitive compare must see user-agent)", names(ps3))
	}
}

func TestApplyToASyntheticHeaderAddsOnlyThatHeaderWithThePayloadUntouched(t *testing.T) {
	r := req(t, "GET /s?q=1 HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"synthetic_header"})
	out, err := ps[0].Apply(r, "https://fuzz.example/ref/", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := "GET /s?q=1 HTTP/1.1\r\nHost: x\r\nReferer: https://fuzz.example/ref/\r\n\r\n"
	if string(out) != want {
		t.Errorf("applied request = %q, want %q (the fresh header appends after the existing ones, the payload unescaped)", out, want)
	}

	out2, err := ps[1].Apply(r, "burpsy", true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !strings.Contains(string(out2), "User-Agent: burpsy\r\n") {
		t.Errorf("appending on a synthetic point = %q, want the bare payload (there is no base value to keep)", out2)
	}
}

func TestARelocateBodyToQueryPointMovesThePairIntoTheQueryString(t *testing.T) {
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\na=1&user=bo")
	ps, _ := Enumerate(r, []string{"relocate_body_to_query"})
	if !reflect.DeepEqual(names(ps), []string{"relocate_body_to_query:a", "relocate_body_to_query:user"}) {
		t.Fatalf("points = %v, want one per form body field", names(ps))
	}
	if ps[1].BaseValue != "bo" {
		t.Errorf("user BaseValue = %q, want %q", ps[1].BaseValue, "bo")
	}
	out, err := ps[1].Apply(r, "or '1'='1", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "POST /f?user=or%20'1'%3D'1 HTTP/1.1") {
		t.Errorf("request line = %q, want the pair in the query, escaped (%q stays raw, it is not a separator), under its own name", s, "'")
	}
	if strings.Contains(s, "user=bo") {
		t.Errorf("request = %q, want the wire value itself gone from the body", s)
	}
	if !strings.Contains(s, "\r\n\r\na=1") {
		t.Errorf("body = %q, want the switched pair removed and the remaining field intact", s)
	}
}

func TestARelocateQueryToBodyPointMovesThePairIntoAnEmptyFormBody(t *testing.T) {
	r := req(t, "POST /f?user=bo&page=2 HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n")
	ps, _ := Enumerate(r, []string{"relocate_query_to_body"})
	if !reflect.DeepEqual(names(ps), []string{"relocate_query_to_body:user", "relocate_query_to_body:page"}) {
		t.Fatalf("points = %v, want one per query pair", names(ps))
	}
	out, err := ps[0].Apply(r, "x&y=z", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "POST /f?page=2 HTTP/1.1") {
		t.Errorf("request line = %q, want only the untouched pair left in the query (user alone must exist in the body)", s)
	}
	parsed, err := core.ParseRequestEdit(out)
	if err != nil {
		t.Fatalf("applied request no longer parses: %v", err)
	}
	if got := string(parsed.Body); got != "user=x%26y%3Dz" {
		t.Errorf("body = %q, want the escaped payload appended as k=v form encoding", got)
	}
	if ct := parsed.Header("content-type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want it preserved unchanged", ct)
	}
}

func TestARelocateQueryToBodyOntoAMultipartBodyIsDeclinedNotClean(t *testing.T) {
	r := req(t, "POST /u?user=bo HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 40\r\n\r\n--B\r\nContent-Disposition: form-data\r\n\r\nv\r\n")
	ps, declined := Enumerate(r, []string{"relocate_query_to_body"})
	if len(ps) != 0 {
		t.Errorf("points = %v, want none (a relocated pair would corrupt the multipart framing)", names(ps))
	}
	if len(declined) != 1 {
		t.Fatalf("declined = %d, want 1 (the refusal is recorded, not a clean empty list)", len(declined))
	}
	if !strings.Contains(declined[0].What, "relocation") {
		t.Errorf("declined.What = %q, want it to name the relocation family", declined[0].What)
	}
	if !strings.Contains(declined[0].Reason, "form") {
		t.Errorf("declined.Reason = %q, want it to say the body is not a form target", declined[0].Reason)
	}
}

func TestARelocateBodyToQueryFromAMultipartBodySimplyHasNoPairs(t *testing.T) {
	// The direction asymmetry: body→query reads the *source* through the form
	// parser, and a multipart body is not a form, so it has no relocatable
	// pairs and yields nothing — while query→body reads the *target* and must
	// decline. Neither claim is "tested, found nothing".
	r := req(t, "POST /u?user=bo HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 40\r\n\r\n--B\r\nContent-Disposition: form-data\r\n\r\nv\r\n")
	ps, declined := Enumerate(r, []string{"relocate_body_to_query"})
	if len(ps) != 0 {
		t.Errorf("points = %v, want none (a multipart body has no k=v pairs to relocate, whatever its parts are)", names(ps))
	}
	if len(declined) != 0 {
		t.Errorf("declined = %v, want none (the source does not parse as a form, so there is nothing to relocate)", declined)
	}
}

func TestARequestWithNoKVPairsYieldsNoRelocationPointsAndNoDeclines(t *testing.T) {
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, declined := Enumerate(r, []string{"relocate_body_to_query", "relocate_query_to_body"})
	if len(ps) != 0 {
		t.Errorf("points = %v, want none", names(ps))
	}
	if len(declined) != 0 {
		t.Errorf("declined = %v, want none (having no pairs to relocate is the normal no-points case)", declined)
	}
}

func TestTheContentLengthAgreesAfterARelocationSplicesTheBody(t *testing.T) {
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\na=1&user=bo")
	ps, _ := Enumerate(r, []string{"relocate_body_to_query"})
	out, err := ps[1].Apply(r, "zz", true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	parsed, err := core.ParseRequestEdit(out)
	if err != nil {
		t.Fatalf("applied request no longer parses: %v; raw %q", err, out)
	}
	want := strconv.Itoa(len(parsed.Body))
	if cl := parsed.Header("content-length"); cl != want {
		t.Errorf("Content-Length = %q, want %q to match the %d-byte body left after the pair moved", cl, want, len(parsed.Body))
	}
	if got := string(parsed.Body); got != "a=1" {
		t.Errorf("body = %q, want %q (the switched pair removed, the rest intact)", got, "a=1")
	}
	if !strings.Contains(string(out), "/f?user=bozz") {
		t.Errorf("request = %q, want appending to carry the base value to the switched location as %q", out, "user=bozz")
	}
}

func TestAppendingToAHeaderPointStillKeepsTheBaseValueAndStaysRaw(t *testing.T) {
	// The existing header-value kinds must not regress now that Apply also
	// handles synthetic and relocation points: appending keeps the wire base
	// value and a header payload is still never percent-escaped.
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\nX-Flag: on\r\n\r\n")
	ps, _ := Enumerate(r, []string{"header"})
	out, err := ps[0].Apply(r, "&x=1", true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !strings.Contains(string(out), "X-Flag: on&x=1") {
		t.Errorf("X-Flag = %q, want the base value kept with the unescaped payload appended", out)
	}
}

func TestARequestWithNowhereToInjectYieldsNoPoints(t *testing.T) {
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, declined := Enumerate(r, []string{"any"})
	if len(ps) != 0 || len(declined) != 0 {
		t.Errorf("points = %v declined = %v, want both empty", ps, declined)
	}
}

func TestAMultipartBodyWithNoBoundaryParameterIsDeclinedNotSilentlyEmpty(t *testing.T) {
	// The delimiter is the whole framing. Without it there is no way to know
	// where a part begins, and a blind splice would invent framing the server
	// rejects before the application sees the payload — so it is recorded as
	// skipped rather than reported as tested-and-clean.
	r := postBody("multipart/form-data", twoPartForm)
	ps, declined := Enumerate(r, []string{"body"})
	if len(ps) != 0 {
		t.Errorf("points = %v, want none (the parts cannot be located without a boundary)", names(ps))
	}
	if len(declined) != 1 {
		t.Fatalf("declined = %d, want exactly 1 (the refusal is recorded, not swallowed into a clean empty result)", len(declined))
	}
	if declined[0].What != "request body" {
		t.Errorf("declined.What = %q, want %q so the operator knows which place was skipped", declined[0].What, "request body")
	}
	if !strings.Contains(declined[0].Reason, "multipart") {
		t.Errorf("declined.Reason = %q, want it to name multipart framing as the thing that could not be read", declined[0].Reason)
	}
}

func TestAMultipartBodyWhosePartListNeverClosesIsDeclined(t *testing.T) {
	// A part list with no closing `--B--` was only half read. Splicing into a
	// half-read list is guessing at framing, which is the one thing the
	// enumerator refuses to do.
	r := postBody("multipart/form-data; boundary=B", "--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n")
	ps, declined := Enumerate(r, []string{"body"})
	if len(ps) != 0 {
		t.Errorf("points = %v, want none (the part list was never closed, so its parts are not trustworthy ranges)", names(ps))
	}
	if len(declined) != 1 {
		t.Fatalf("declined = %d, want exactly 1", len(declined))
	}
	if !strings.Contains(declined[0].Reason, "multipart") {
		t.Errorf("declined.Reason = %q, want it to name multipart framing", declined[0].Reason)
	}
}

func TestAPlainTextBodyIsDeclinedWithoutClaimingItWasMultipartOrXML(t *testing.T) {
	// A body in no modelled container is still skipped rather than reported
	// clean — but the reason has to name what was actually there, or the
	// operator reads a decline about a container the request never carried.
	r := postBody("text/plain", "not a container at all")
	ps, declined := Enumerate(r, []string{"body"})
	if len(ps) != 0 {
		t.Errorf("points = %v, want none (plain text has no parameter structure to target)", names(ps))
	}
	if len(declined) != 1 {
		t.Fatalf("declined = %d, want exactly 1", len(declined))
	}
	low := strings.ToLower(declined[0].Reason)
	if strings.Contains(low, "multipart") || strings.Contains(low, "xml") {
		t.Errorf("declined.Reason = %q, but this body is neither multipart nor XML; a decline that misnames the container misdirects whoever reads it", declined[0].Reason)
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

func TestURLPathFilenameAndFoldersAreEnumeratedAsSeparatePoints(t *testing.T) {
	r := req(t, "GET /api/users/42/profile.json?x=1 HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"url_path_filename", "url_path_folder"})
	if !reflect.DeepEqual(names(ps), []string{"url_path_filename:filename", "url_path_folder:folder", "url_path_folder:folder", "url_path_folder:folder"}) {
		t.Fatalf("points = %v", names(ps))
	}
	if ps[0].BaseValue != "profile.json" {
		t.Errorf("filename BaseValue = %q, want %q", ps[0].BaseValue, "profile.json")
	}
	wantFolders := []string{"api", "users", "42"}
	for i, want := range wantFolders {
		if ps[i+1].BaseValue != want {
			t.Errorf("folder[%d] BaseValue = %q, want %q", i, ps[i+1].BaseValue, want)
		}
	}
}

func TestURLPathFilenameOnRootIsAnEmptyPoint(t *testing.T) {
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"url_path_filename", "url_path_folder"})
	if !reflect.DeepEqual(names(ps), []string{"url_path_filename:filename"}) {
		t.Fatalf("points = %v, want one empty filename point and no folders", names(ps))
	}
	if ps[0].BaseValue != "" {
		t.Errorf("BaseValue = %q, want empty", ps[0].BaseValue)
	}
}

func TestApplyToAFolderPointOnlyChangesThatSegment(t *testing.T) {
	r := req(t, "GET /api/users/42/profile.json HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"url_path_folder"})
	out, err := ps[1].Apply(r, "'", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "/api/'/42/profile.json") {
		t.Fatalf("got %q", out)
	}
}

func TestApplyToAFilenamePointPercentEscapesASlash(t *testing.T) {
	r := req(t, "GET /api/users/42/profile.json HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"url_path_filename"})
	out, err := ps[0].Apply(r, "../etc/passwd", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "/api/users/42/..%2Fetc%2Fpasswd") {
		t.Fatalf("got %q", out)
	}
}

func TestParamNameURLTargetsTheNameNotTheValue(t *testing.T) {
	r := req(t, "GET /s?q=cat HTTP/1.1\r\nHost: x\r\n\r\n")
	ps, _ := Enumerate(r, []string{"param_name_url"})
	if !reflect.DeepEqual(names(ps), []string{"param_name_url:q"}) {
		t.Fatalf("points = %v", names(ps))
	}
	out, err := ps[0].Apply(r, "x", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "/s?qx=cat") {
		t.Fatalf("got %q, want the name mutated and the value untouched", out)
	}
}

func TestParamNameBodyOnlyAppliesToAFormBody(t *testing.T) {
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\na=1&user=bo")
	ps, _ := Enumerate(r, []string{"param_name_body"})
	if !reflect.DeepEqual(names(ps), []string{"param_name_body:a", "param_name_body:user"}) {
		t.Fatalf("points = %v", names(ps))
	}

	jsonReq := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"user\":\"bo\"}")
	jsonPs, _ := Enumerate(jsonReq, []string{"param_name_body"})
	if len(jsonPs) != 0 {
		t.Fatalf("json body should yield no param_name_body points, got %v", names(jsonPs))
	}
}

func TestEntireBodyIsOnePointCoveringTheWholeBody(t *testing.T) {
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"user\":\"bo\"}")
	ps, _ := Enumerate(r, []string{"entire_body"})
	if len(ps) != 1 {
		t.Fatalf("points = %v, want exactly one", names(ps))
	}
	if ps[0].BaseValue != `{"user":"bo"}` {
		t.Errorf("BaseValue = %q", ps[0].BaseValue)
	}
	out, err := ps[0].Apply(r, `{"x":1}`, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "\r\n\r\n{\"x\":1}") {
		t.Fatalf("got %q", out)
	}
}

func TestARelocateQueryToCookiePointMovesThePairIntoTheCookieHeader(t *testing.T) {
	r := req(t, "POST /f?user=bo&page=2 HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n")
	ps, _ := Enumerate(r, []string{"relocate_query_to_cookie"})
	if !reflect.DeepEqual(names(ps), []string{"relocate_query_to_cookie:user", "relocate_query_to_cookie:page"}) {
		t.Fatalf("points = %v, want one per query pair", names(ps))
	}
	out, err := ps[0].Apply(r, "x&y=z", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "POST /f?page=2 HTTP/1.1") {
		t.Errorf("request line = %q, want only the untouched pair left in the query (user alone must move to the cookie)", s)
	}
	parsed, err := core.ParseRequestEdit(out)
	if err != nil {
		t.Fatalf("applied request no longer parses: %v", err)
	}
	// The relocated pair becomes a Cookie clause value, which is an opaque octet
	// run (codingCookieValue): `&` and `=` are not cookie delimiters and arrive
	// verbatim — the server's cookie reader does not decode, so escaping them
	// would hand it a payload other than the one the check wrote.
	if got := parsed.Header("cookie"); got != "user=x&y=z" {
		t.Errorf("cookie = %q, want the payload verbatim as a cookie value", got)
	}
	if ct := parsed.Header("content-type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want it preserved unchanged", ct)
	}
	// A request with no cookies must still accept a relocated pair.
	noCookie := req(t, "POST /f?user=bo HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n")
	ps2, _ := Enumerate(noCookie, []string{"relocate_query_to_cookie"})
	out2, err := ps2[0].Apply(noCookie, "v", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	parsed2, err := core.ParseRequestEdit(out2)
	if err != nil {
		t.Fatalf("applied request no longer parses: %v", err)
	}
	if got := parsed2.Header("cookie"); got != "user=v" {
		t.Errorf("cookie = %q, want a Cookie header created when the base request had none", got)
	}
}

func TestARelocateCookieToQueryPointMovesThePairIntoTheQueryString(t *testing.T) {
	r := req(t, "GET /s HTTP/1.1\r\nHost: x\r\nCookie: sid=abc; theme=dark\r\n\r\n")
	ps, _ := Enumerate(r, []string{"relocate_cookie_to_query"})
	if !reflect.DeepEqual(names(ps), []string{"relocate_cookie_to_query:sid", "relocate_cookie_to_query:theme"}) {
		t.Fatalf("points = %v, want one per cookie", names(ps))
	}
	out, err := ps[0].Apply(r, "evil", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "sid=evil") {
		t.Errorf("request = %q, want the pair in the query under its own name", s)
	}
	parsed, err := core.ParseRequestEdit(out)
	if err != nil {
		t.Fatalf("applied request no longer parses: %v", err)
	}
	if got := parsed.Header("cookie"); got != "theme=dark" {
		t.Errorf("cookie = %q, want the moved pair gone and the remaining cookie intact", got)
	}
}

func TestARelocateCookieToQueryPreservesTheSeparatorBetweenRemainingCookies(t *testing.T) {
	// Three cookies: removing a middle one must keep the other two separated by
	// a single delimiter, not merge them into one clause.
	r := req(t, "GET /s HTTP/1.1\r\nHost: x\r\nCookie: a=1; b=2; c=3\r\n\r\n")
	ps, _ := Enumerate(r, []string{"relocate_cookie_to_query"})
	if ps[1].Name != "b" {
		t.Fatalf("points = %v, want b as the middle cookie", names(ps))
	}
	out, err := ps[1].Apply(r, "X", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	parsed, err := core.ParseRequestEdit(out)
	if err != nil {
		t.Fatalf("applied request no longer parses: %v", err)
	}
	if got := parsed.Header("cookie"); got != "a=1; c=3" {
		t.Errorf("cookie = %q, want the middle clause removed while keeping the survivors separated", got)
	}
}

func TestARelocateBodyToCookiePointMovesThePairIntoTheCookieHeader(t *testing.T) {
	r := req(t, "POST /f HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\na=1&user=bo")
	ps, _ := Enumerate(r, []string{"relocate_body_to_cookie"})
	if !reflect.DeepEqual(names(ps), []string{"relocate_body_to_cookie:a", "relocate_body_to_cookie:user"}) {
		t.Fatalf("points = %v, want one per form body field", names(ps))
	}
	out, err := ps[1].Apply(r, "zz", true)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	parsed, err := core.ParseRequestEdit(out)
	if err != nil {
		t.Fatalf("applied request no longer parses: %v", err)
	}
	if got := string(parsed.Body); got != "a=1" {
		t.Errorf("body = %q, want the switched pair removed and the rest intact", got)
	}
	if got := parsed.Header("cookie"); got != "user=bozz" {
		t.Errorf("cookie = %q, want the base value carried to the switched location as %q", got, "user=bozz")
	}
}

func TestARelocateCookieToBodyPointMovesThePairIntoAFormBody(t *testing.T) {
	r := req(t, "GET /s HTTP/1.1\r\nHost: x\r\nCookie: sid=abc; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n")
	ps, _ := Enumerate(r, []string{"relocate_cookie_to_body"})
	if !reflect.DeepEqual(names(ps), []string{"relocate_cookie_to_body:sid", "relocate_cookie_to_body:theme"}) {
		t.Fatalf("points = %v, want one per cookie", names(ps))
	}
	out, err := ps[0].Apply(r, "x&y=z", false)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	parsed, err := core.ParseRequestEdit(out)
	if err != nil {
		t.Fatalf("applied request no longer parses: %v", err)
	}
	if got := string(parsed.Body); got != "sid=x%26y%3Dz" {
		t.Errorf("body = %q, want the escaped payload appended as k=v form encoding", got)
	}
	if got := parsed.Header("cookie"); got != "theme=dark" {
		t.Errorf("cookie = %q, want the moved pair gone and the remaining cookie intact", got)
	}
}

func TestARelocateCookieToBodyOntoAMultipartBodyIsDeclinedNotClean(t *testing.T) {
	r := req(t, "POST /u?x=1 HTTP/1.1\r\nHost: x\r\nCookie: sid=abc\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: 40\r\n\r\n--B\r\nContent-Disposition: form-data\r\n\r\nv\r\n")
	ps, declined := Enumerate(r, []string{"relocate_cookie_to_body"})
	if len(ps) != 0 {
		t.Errorf("points = %v, want none (a relocated pair would corrupt the multipart framing)", names(ps))
	}
	if len(declined) != 1 {
		t.Fatalf("declined = %d, want 1 (the refusal is recorded, not a clean empty list)", len(declined))
	}
	if !strings.Contains(declined[0].What, "relocation") {
		t.Errorf("declined.What = %q, want it to name the relocation family", declined[0].What)
	}
	if !strings.Contains(declined[0].Reason, "form") {
		t.Errorf("declined.Reason = %q, want it to say the body is not a form target", declined[0].Reason)
	}
}

func TestAnyDoesNotReachTheFiveGoOnlyKinds(t *testing.T) {
	r := req(t, "GET /api/users/42/profile.json?x=1 HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n")
	ps, _ := Enumerate(r, []string{"any"})
	for _, p := range ps {
		switch p.Kind {
		case IpParamNameURL, IpParamNameBody, IpEntireBody, IpURLPathFilename, IpURLPathFolder:
			t.Fatalf("kind %q reached through any", p.Kind)
		}
	}
}

// ---------------------------------------------------------------------------
// Nested expansion tests

// A base64-wrapped JSON value must splice the payload into the *decoded* JSON
// and re-encode, not into the base64 text. Regression: nestedDecode treated
// nestedBase64JSON as identity while nestedEncode re-encoded, so Apply spliced
// JSON-relative offsets into the base64 text and produced a doubly-encoded
// corrupt value.
func TestApplySplicesNestedBase64JSONIntoTheDecodedJSON(t *testing.T) {
	r := req(t, "GET /?p=eyJ0b2tlbiI6InNlZWQifQ%3D%3D HTTP/1.1\r\nHost: x\r\n\r\n")
	points, _ := EnumerateWithLimit(r, []string{"query"}, -1)
	if len(points) != 2 {
		t.Fatalf("want flat + nested points, got %d", len(points))
	}
	out, err := points[1].Apply(r, `p"y`, false)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	want := "GET /?p=" + percentEscape(base64.StdEncoding.EncodeToString([]byte(`{"token":"p\"y"}`))) + " HTTP/1.1"
	if string(out) != want+"\r\nHost: x\r\n\r\n" {
		t.Errorf("nested splice mismatch:\n got %q\nwant %q", out, want)
	}
}

// ---------------------------------------------------------------------------

func Test_tryDecodeNested_JSON(t *testing.T) {
	inner, kind, ok := tryDecodeNested(`{"x":"hello","y":1}`)
	if !ok || kind != nestedJSON {
		t.Fatalf("got ok=%v kind=%v, want ok=true kind=nestedJSON", ok, kind)
	}
	if inner != `{"x":"hello","y":1}` {
		t.Fatalf("inner = %q", inner)
	}
}

func Test_tryDecodeNested_base64json(t *testing.T) {
	// base64 of {"x":1}
	inner, kind, ok := tryDecodeNested("eyJ4IjoxfQ==")
	if !ok || kind != nestedBase64JSON {
		t.Fatalf("got ok=%v kind=%v, want ok=true kind=nestedBase64JSON", ok, kind)
	}
	if inner != `{"x":1}` {
		t.Fatalf("inner = %q", inner)
	}
}

func Test_tryDecodeNested_base64raw(t *testing.T) {
	// base64 of "hello world"
	inner, kind, ok := tryDecodeNested("aGVsbG8gd29ybGQ=")
	if !ok || kind != nestedBase64 {
		t.Fatalf("got ok=%v kind=%v, want ok=true kind=nestedBase64", ok, kind)
	}
	if inner != "hello world" {
		t.Fatalf("inner = %q", inner)
	}
}

func Test_tryDecodeNested_XML(t *testing.T) {
	inner, kind, ok := tryDecodeNested("<root><a>text</a></root>")
	if !ok || kind != nestedXML {
		t.Fatalf("got ok=%v kind=%v, want ok=true kind=nestedXML", ok, kind)
	}
	if inner != "<root><a>text</a></root>" {
		t.Fatalf("inner = %q", inner)
	}
}

func Test_tryDecodeNested_rejects_plain(t *testing.T) {
	if _, _, ok := tryDecodeNested("hello"); ok {
		t.Fatal("plain text should not be treated as nested")
	}
	if _, _, ok := tryDecodeNested(""); ok {
		t.Fatal("empty string should not be treated as nested")
	}
	if _, _, ok := tryDecodeNested("not-base64!@#$"); ok {
		t.Fatal("garbage should not be treated as nested")
	}
}

func Test_innerSpans_JSON(t *testing.T) {
	spans := innerSpans(nestedJSON, `{"x":"hello","y":"world"}`)
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
	// The first string value "hello" is at byte 6..11 (inside quotes).
	if spans[0] != [2]int{6, 11} {
		t.Fatalf("span[0] = %v, want [6,11]", spans[0])
	}
	// The second string value "world" is at byte 18..23 (inside quotes).
	if spans[1] != [2]int{18, 23} {
		t.Fatalf("span[1] = %v, want [18,23]", spans[1])
	}
}

func Test_innerSpans_base64(t *testing.T) {
	spans := innerSpans(nestedBase64, "anything")
	if len(spans) != 1 || spans[0] != [2]int{0, 8} {
		t.Fatalf("got %v, want [0,8]", spans)
	}
}

func Test_innerSpans_XML(t *testing.T) {
	spans := innerSpans(nestedXML, "<root>hello <em>world</em></root>")
	// Text nodes: "hello " at 6..12, but trailing whitespace is trimmed from
	// a text-node span (see trimTrailingWS), so the first span is 6..11, not
	// 6..12. "world" has no trailing whitespace to trim, so 16..21 stands.
	if len(spans) != 2 {
		t.Fatalf("got %d spans: %v", len(spans), spans)
	}
	if spans[0] != [2]int{6, 11} {
		t.Fatalf("span[0] = %v, want [6,11]", spans[0])
	}
	if spans[1] != [2]int{16, 21} {
		t.Fatalf("span[1] = %v, want [16,21]", spans[1])
	}
}

func Test_containerDecodeEncode_roundtrip(t *testing.T) {
	// containerEncode escapes '+', '=' and '&' because those bytes decide how
	// a k=v container is parsed; containerDecode must reverse exactly that, so
	// the round trip runs encode-then-decode over a logical value, not
	// decode-then-encode over a string that already contains raw separators
	// (which is not something containerEncode could ever have produced).
	original := "a+b=c&d=e"
	encoded := containerEncode(codingForm, original)
	decoded := containerDecode(codingForm, encoded)
	if decoded != original {
		t.Fatalf("round-trip failed: %q → %q → %q", original, encoded, decoded)
	}
}

func Test_nestedDecodeEncode_base64_roundtrip(t *testing.T) {
	decoded, err := nestedDecode(nestedBase64, "aGVsbG8=")
	if err != nil {
		t.Fatal(err)
	}
	if decoded != "hello" {
		t.Fatalf("decoded = %q, want %q", decoded, "hello")
	}
	encoded := nestedEncode(nestedBase64, decoded)
	if encoded != "aGVsbG8=" {
		t.Fatalf("encoded = %q, want %q", encoded, "aGVsbG8=")
	}
}

func Test_expandNested_query_param_json(t *testing.T) {
	r := req(t, "GET /?data=%7B%22x%22%3A%22payload%22%7D HTTP/1.1\r\nHost: x\r\n\r\n")
	points, _ := Enumerate(r, []string{"query"})
	var nestedFound int
	for _, p := range points {
		if p.coding == codingNested {
			nestedFound++
			if p.nested != nestedJSON {
				t.Errorf("nested kind = %v, want nestedJSON", p.nested)
			}
		}
	}
	if nestedFound == 0 {
		t.Fatal("expected at least one nested point for a JSON query param")
	}
}

func Test_expandNested_query_param_base64json(t *testing.T) {
	// data=eyJ4IjoiMSJ9  →  base64 of {"x":"1"}. The inner value must be a
	// JSON *string* — innerSpans only targets string values (see its doc
	// comment), so a base64→JSON fixture with only numeric fields can never
	// produce a nested point by design.
	r := req(t, "GET /?data=eyJ4IjoiMSJ9 HTTP/1.1\r\nHost: x\r\n\r\n")
	points, _ := Enumerate(r, []string{"query"})
	var nestedFound int
	for _, p := range points {
		if p.coding == codingNested {
			nestedFound++
			if p.nested != nestedBase64JSON {
				t.Errorf("nested kind = %v, want nestedBase64JSON", p.nested)
			}
		}
	}
	if nestedFound == 0 {
		t.Fatal("expected at least one nested point for a base64→JSON query param")
	}
}

func Test_expandNested_cookie_param_json(t *testing.T) {
	// Cookie: session={"id":"42"}, percent-encoded. Same string-value
	// requirement as the base64json case above.
	r := req(t, "GET / HTTP/1.1\r\nHost: x\r\nCookie: session=%7B%22id%22%3A%2242%22%7D\r\n\r\n")
	points, _ := Enumerate(r, []string{"cookie"})
	var nestedFound int
	for _, p := range points {
		if p.coding == codingNested {
			nestedFound++
			if p.nested != nestedJSON {
				t.Errorf("nested kind = %v, want nestedJSON", p.nested)
			}
		}
	}
	if nestedFound == 0 {
		t.Fatal("expected at least one nested point for a JSON cookie param")
	}
}

func Test_applyNested_json_replaces_inner_string(t *testing.T) {
	// Request with query param data={"x":"old","y":"keep"}
	// Enumerate gives a nested point targeting the first string value "old".
	r := req(t, "GET /?data=%7B%22x%22%3A%22old%22%2C%22y%22%3A%22keep%22%7D HTTP/1.1\r\nHost: x\r\n\r\n")
	points, _ := Enumerate(r, []string{"query"})
	for _, p := range points {
		if p.coding != codingNested || p.nested != nestedJSON {
			continue
		}
		if p.Name != "data" {
			continue
		}
		// Payload to inject.
		newReq, err := p.Apply(r, "INJECTED", false)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		newPoints, _ := Enumerate(newReq, []string{"query"})
		for _, np := range newPoints {
			if np.Name == "data" {
				decoded, err := percentDecode(np.BaseValue), error(nil)
				if err != nil {
					t.Fatalf("percentDecode: %v", err)
				}
				if !strings.Contains(decoded, "INJECTED") {
					t.Errorf("applied value %q does not contain INJECTED (decoded=%s)", np.BaseValue, decoded)
				}
				// Ensure the other value survived.
				if !strings.Contains(decoded, "keep") {
					t.Errorf("other value 'keep' lost after apply (decoded=%s)", decoded)
				}
				return
			}
		}
		t.Fatal("data param not found in applied request")
	}
	t.Fatal("no nested JSON point found to apply")
}

func Test_applyNested_base64json_re_encodes(t *testing.T) {
	// data=eyJ4IjoiMSJ9  →  base64 of {"x":"1"} (must be a string value).
	r := req(t, "GET /?data=eyJ4IjoiMSJ9 HTTP/1.1\r\nHost: x\r\n\r\n")
	points, _ := Enumerate(r, []string{"query"})
	for _, p := range points {
		if p.coding != codingNested || p.nested != nestedBase64JSON {
			continue
		}
		if p.Name != "data" {
			continue
		}
		newReq, err := p.Apply(r, "injected", false)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		newPoints, _ := Enumerate(newReq, []string{"query"})
		for _, np := range newPoints {
			if np.Name == "data" {
				lvl1 := containerDecode(codingForm, np.BaseValue)
				lvl2, err := nestedDecode(nestedBase64, lvl1)
				if err != nil {
					t.Fatalf("nested decode: %v", err)
				}
				if !strings.Contains(lvl2, "injected") {
					t.Errorf("decoded inner %q does not contain 'injected'", lvl2)
				}
				// Verify it's valid base64 round-trip.
				reEncoded := nestedEncode(nestedBase64, lvl2)
				if reEncoded != lvl1 {
					t.Errorf("base64 round-trip mismatch: %q vs %q", reEncoded, lvl1)
				}
				return
			}
		}
		t.Fatal("data param not found in applied request")
	}
	t.Fatal("no nested base64→JSON point found to apply")
}

func Test_applyNested_appending(t *testing.T) {
	// data={"x":"hello"}
	r := req(t, "GET /?data=%7B%22x%22%3A%22hello%22%7D HTTP/1.1\r\nHost: x\r\n\r\n")
	points, _ := Enumerate(r, []string{"query"})
	for _, p := range points {
		if p.coding != codingNested || p.nested != nestedJSON || p.Name != "data" {
			continue
		}
		newReq, err := p.Apply(r, "_appended", true)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		newPoints, _ := Enumerate(newReq, []string{"query"})
		for _, np := range newPoints {
			if np.Name == "data" {
				decoded := containerDecode(codingForm, np.BaseValue)
				if !strings.Contains(decoded, "hello_appended") {
					t.Errorf("expected appended value, got %q", decoded)
				}
				return
			}
		}
		t.Fatal("data param not found after append")
	}
	t.Fatal("no nested JSON point found for append")
}

func Test_applyNested_xml(t *testing.T) {
	// data=<root><msg>old</msg></root>   (percent-encoded)
	encoded := percentEscape("<root><msg>old</msg></root>")
	r := req(t, "GET /?data="+encoded+" HTTP/1.1\r\nHost: x\r\n\r\n")
	points, _ := Enumerate(r, []string{"query"})
	for _, p := range points {
		if p.coding != codingNested || p.nested != nestedXML || p.Name != "data" {
			continue
		}
		newReq, err := p.Apply(r, "new", false)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		newPoints, _ := Enumerate(newReq, []string{"query"})
		for _, np := range newPoints {
			if np.Name == "data" {
				decoded := containerDecode(codingForm, np.BaseValue)
				if !strings.Contains(decoded, "new") {
					t.Errorf("expected 'new' in XML text node, got %q", decoded)
				}
				if !strings.Contains(decoded, "<msg>") {
					t.Errorf("XML structure lost, got %q", decoded)
				}
				return
			}
		}
		t.Fatal("data param not found after XML apply")
	}
	t.Fatal("no nested XML point found")
}

func Test_expandNested_max_bound(t *testing.T) {
	// Build a query with many JSON params to test the 400-point cap. Each
	// value must carry a JSON string field, not a number, or innerSpans finds
	// nothing to nest into.
	var qs []string
	for i := 0; i < 100; i++ {
		qs = append(qs, "p"+strconv.Itoa(i)+"=%7B%22a%22%3A%221%22%7D")
	}
	r := req(t, "GET /?"+strings.Join(qs, "&")+" HTTP/1.1\r\nHost: x\r\n\r\n")
	// Uncapped: this test is about expandNested's own 400-point bound, which the
	// per-request cap would otherwise mask.
	points, _ := EnumerateWithLimit(r, []string{"query"}, -1)
	nestedCount := 0
	for _, p := range points {
		if p.coding == codingNested {
			nestedCount++
		}
	}
	// 100 params × 1 nested point each = 100 (well under 400).
	if nestedCount < 100 {
		t.Errorf("got %d nested points, want at least 100", nestedCount)
	}
	// Verify no nested point exceeds the length limit.
	for _, p := range points {
		if p.coding == codingNested && len(p.BaseValue) > maxNestedValueLen {
			t.Errorf("nested point BaseValue exceeds maxNestedValueLen")
		}
	}
}

func Test_xmlPoints_namesEachTextNodeAfterItsElementAndRecordsItsSpan(t *testing.T) {
	pts := xmlPoints("<a>one</a><b>two</b>")
	if len(pts) != 2 {
		t.Fatalf("got %d points %v, want one per text node: both `one` and `two` are values an application reads", len(pts), pts)
	}
	if pts[0].name != "a" || pts[0].start != 3 || pts[0].end != 6 {
		t.Errorf("point[0] = %+v, want name a spanning [3,6); a span that is not the exact bytes of `one` splices over the tags around it", pts[0])
	}
	if pts[1].name != "b" || pts[1].start != 13 || pts[1].end != 16 {
		t.Errorf("point[1] = %+v, want name b spanning [13,16)", pts[1])
	}
}

func Test_xmlPoints_skipsAWhitespaceOnlyTextNode(t *testing.T) {
	// Whitespace between tags is layout, not a value: a payload spliced there
	// is not reaching any field the application reads.
	if pts := xmlPoints("<a>   </a>"); len(pts) != 0 {
		t.Fatalf("got %v, want no points for a text node that is only whitespace", pts)
	}
}

func TestAnXMLBodyYieldsAPointPerTextNodeAndAttributeValueNamedByElementPath(t *testing.T) {
	// XML fields used to fall back to one entire-body point, which reports
	// "the body is injectable" without naming the element — not a finding.
	// Repeated siblings need distinguishing for the same reason.
	r := postBody("application/xml", `<order id="7"><item>bolt</item><item>nut</item></order>`)
	ps, declined := Enumerate(r, []string{"body"})
	want := []string{"xml:order@id", "xml:order/item", "xml:order/item[1]"}
	if !reflect.DeepEqual(names(ps), want) {
		t.Errorf("points = %v, want %v (an attribute is named `path@attr`, and the second `item` is indexed so two findings cannot collapse into one name)", names(ps), want)
	}
	wantBase := []string{"7", "bolt", "nut"}
	if !reflect.DeepEqual(baseValues(ps), wantBase) {
		t.Errorf("BaseValues = %v, want %v (the value already on the wire, without its quotes or surrounding tags)", baseValues(ps), wantBase)
	}
	if len(declined) != 0 {
		t.Errorf("declined = %v, want none (an XML body is a modelled container now)", declined)
	}
}

func TestAnXMLBodyIsRecognisedByItsOwnShapeNotOnlyByContentType(t *testing.T) {
	// The same document posted as text/plain is the same document; requiring
	// the header would leave those bodies untested.
	r := postBody("text/plain", `<order><item>bolt</item></order>`)
	ps, declined := Enumerate(r, []string{"body"})
	if !reflect.DeepEqual(names(ps), []string{"xml:order/item"}) {
		t.Errorf("points = %v, want [body:order/item]", names(ps))
	}
	if len(declined) != 0 {
		t.Errorf("declined = %v, want none", declined)
	}
}

func TestAPayloadSplicedIntoAnXMLTextNodeKeepsTheDocumentParseable(t *testing.T) {
	// The escape has to survive a round trip: a real parser must still read the
	// document, and it must hand the application back exactly the bytes the
	// check wrote, not the entities they were spelled with on the wire.
	r := postBody("application/xml", `<order id="7"><item>bolt</item><item>nut</item></order>`)
	ps, _ := Enumerate(r, []string{"body"})
	if ps[1].Name != "order/item" {
		t.Fatalf("ps[1] is %q, want the first item's text node", ps[1].Name)
	}
	const payload = `x<y>&"z'`
	out, err := ps[1].Apply(r, payload, false)
	if err != nil {
		t.Fatalf("every byte of this payload is escapable in XML, so Apply should not refuse it: %v", err)
	}
	var got struct {
		ID    string   `xml:"id,attr"`
		Items []string `xml:"item"`
	}
	if err := xml.Unmarshal([]byte(bodyOf(t, out)), &got); err != nil {
		t.Fatalf("the spliced document no longer parses, so the server would reject it before the payload was seen: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("the spliced document has %d items, want 2: the splice reshaped the tree instead of filling one value", len(got.Items))
	}
	if got.Items[0] != payload {
		t.Errorf("the application would receive %q, not the %q the check wrote: the entities must decode back to the payload byte for byte", got.Items[0], payload)
	}
	if got.Items[1] != "nut" || got.ID != "7" {
		t.Errorf("sibling item = %q and id = %q, want nut/7: splicing one point must leave every other value alone", got.Items[1], got.ID)
	}
}

func TestAPayloadSplicedIntoAnXMLAttributeKeepsTheAttributeQuoted(t *testing.T) {
	// A bare quote in an attribute value ends the attribute, and everything
	// after it becomes markup the check never wrote.
	r := postBody("application/xml", `<order id="7"><item>bolt</item></order>`)
	ps, _ := Enumerate(r, []string{"body"})
	if ps[0].Name != "order@id" {
		t.Fatalf("ps[0] is %q, want the id attribute point", ps[0].Name)
	}
	out, err := ps[0].Apply(r, `9" evil="1`, false)
	if err != nil {
		t.Fatalf("a quote is escapable in an attribute value, so Apply should not refuse it: %v", err)
	}
	var got struct {
		ID   string `xml:"id,attr"`
		Evil string `xml:"evil,attr"`
	}
	if err := xml.Unmarshal([]byte(bodyOf(t, out)), &got); err != nil {
		t.Fatalf("the spliced document no longer parses: %v", err)
	}
	if got.ID != `9" evil="1` {
		t.Errorf("id decoded to %q, want the payload verbatim", got.ID)
	}
	if got.Evil != "" {
		t.Errorf("the splice grew a second attribute evil=%q; the payload broke out of the value it was written into", got.Evil)
	}
}

func Test_percentDecode_literal_plus(t *testing.T) {
	// '+' is NOT decoded as space (matches percentEscape which escapes '+').
	got := percentDecode("a+b")
	if got != "a+b" {
		t.Fatalf("percentDecode(\"a+b\") = %q, want %q", got, "a+b")
	}
}

// A clause like `=2` has a value but no name. Enumerating it would produce an insertion
// point whose Name is the empty string, and a finding reported against `""` names no
// parameter at all — the same unattributable result the one-point-at-a-time rule exists to
// prevent. Such a clause is skipped, exactly like a clause with no `=`.
func Test_kvPairs_skips_a_clause_with_an_empty_name(t *testing.T) {
	const q = "a=1&=2&b=3"
	pairs := kvPairs(q, '&')
	if len(pairs) != 2 {
		t.Fatalf("got %d pairs, want 2; the nameless `=2` clause must not become an insertion point", len(pairs))
	}
	for _, kv := range pairs {
		if name := q[kv.name[0]:kv.name[1]]; name == "" {
			t.Errorf("a pair with an empty name survived: value %q", q[kv.value[0]:kv.value[1]])
		}
	}
	if got := q[pairs[0].name[0]:pairs[0].name[1]]; got != "a" {
		t.Errorf("first pair name = %q, want \"a\"", got)
	}
	if got := q[pairs[1].name[0]:pairs[1].name[1]]; got != "b" {
		t.Errorf("second pair name = %q, want \"b\"", got)
	}

	// A clause that is nothing but `=` is the degenerate case of the same rule.
	if pairs := kvPairs("=2", '&'); len(pairs) != 0 {
		t.Errorf("a lone nameless clause yielded %d pairs, want 0", len(pairs))
	}
}

// ---------------------------------------------------------------------------
// Per-request insertion-point cap
// ---------------------------------------------------------------------------

// queryWith builds a GET whose query carries n distinct scalar parameters.
func queryWith(t *testing.T, n int) []byte {
	t.Helper()
	var qs []string
	for i := 0; i < n; i++ {
		qs = append(qs, "p"+strconv.Itoa(i)+"=v")
	}
	return req(t, "GET /?"+strings.Join(qs, "&")+" HTTP/1.1\r\nHost: x\r\n\r\n")
}

func TestARequestUnderTheCapIsUnaffected(t *testing.T) {
	const want = 5
	points, declined := EnumerateWithLimit(queryWith(t, want), []string{"query"}, DefaultMaxInsertionPoints)
	if len(points) != want {
		t.Errorf("got %d points, want %d; a request below the cap must not be truncated", len(points), want)
	}
	for _, d := range declined {
		if strings.Contains(d.What, "per-request limit") {
			t.Errorf("a request below the cap declined points anyway: %s", d.Describe())
		}
	}
}

func TestARequestOverTheCapIsTruncatedAtExactlyTheCapAndTheExcessIsDeclined(t *testing.T) {
	const (
		cap   = 10
		total = 25
	)
	points, declined := EnumerateWithLimit(queryWith(t, total), []string{"query"}, cap)
	if len(points) != cap {
		t.Fatalf("got %d points, want exactly %d", len(points), cap)
	}
	// The excess must be recorded, not silently dropped: a truncation nobody can
	// see reads as "this request had only 10 places to inject".
	var found *Declined
	for i := range declined {
		if strings.Contains(declined[i].What, "per-request limit") {
			found = &declined[i]
		}
	}
	if found == nil {
		t.Fatalf("the %d dropped points were not declined; declined = %v", total-cap, declined)
	}
	if !strings.Contains(found.Reason, strconv.Itoa(total-cap)) {
		t.Errorf("the decline does not say how many points were dropped (want %d): %q", total-cap, found.Reason)
	}
	if !strings.Contains(found.Reason, strconv.Itoa(cap)) {
		t.Errorf("the decline does not name the limit it hit (want %d): %q", cap, found.Reason)
	}
}

func TestNestedExpansionCannotPushThePointCountPastTheCap(t *testing.T) {
	// Each param's value decodes to JSON with one string field, so uncapped this
	// request yields 20 flat + 20 nested points.
	const cap = 6
	var qs []string
	for i := 0; i < 20; i++ {
		qs = append(qs, "p"+strconv.Itoa(i)+"=%7B%22a%22%3A%221%22%7D")
	}
	r := req(t, "GET /?"+strings.Join(qs, "&")+" HTTP/1.1\r\nHost: x\r\n\r\n")
	points, declined := EnumerateWithLimit(r, []string{"query"}, cap)
	if len(points) != cap {
		t.Fatalf("got %d points, want exactly %d; nested expansion escaped the cap", len(points), cap)
	}
	if len(declined) == 0 {
		t.Error("nested expansion was truncated without a decline")
	}
}

func TestANegativeLimitLiftsTheCap(t *testing.T) {
	const total = DefaultMaxInsertionPoints + 12
	points, declined := EnumerateWithLimit(queryWith(t, total), []string{"query"}, -1)
	if len(points) != total {
		t.Errorf("got %d points, want %d; a negative limit must not cap", len(points), total)
	}
	if len(declined) != 0 {
		t.Errorf("an uncapped enumeration declined %v", declined)
	}
}

func TestEnumerateAppliesTheDefaultCap(t *testing.T) {
	points, declined := Enumerate(queryWith(t, DefaultMaxInsertionPoints+7), []string{"query"})
	if len(points) != DefaultMaxInsertionPoints {
		t.Errorf("got %d points, want %d", len(points), DefaultMaxInsertionPoints)
	}
	if len(declined) == 0 {
		t.Error("Enumerate truncated at the default cap without declining the excess")
	}
}
