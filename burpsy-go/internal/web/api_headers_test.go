package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- uninteresting headers (W6 #81/#82) ----------------------------------------------------
//
// Both panels were state 0: `grep -rin 'uninteresting'` over the tree returned nothing.
//
// The setting only earns its place if the Comparer actually consults it, so the tests that matter
// are the ones driving /api/tools/compare — a settings panel that stores a list nothing reads is the
// decorative-control defect this project has already found once.

func putUninteresting(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/headers/uninteresting", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

type compareResult struct {
	Identical         bool `json:"identical"`
	IdenticalIgnoring bool `json:"identical_ignoring_uninteresting"`
	UninterestingOps  int  `json:"uninteresting_ops"`
	Ops               []struct {
		Kind          string `json:"kind"`
		Uninteresting bool   `json:"uninteresting"`
		AOffset       int    `json:"a_offset"`
		ALen          int    `json:"a_len"`
	} `json:"ops"`
	Applied []string `json:"uninteresting_headers_applied"`
}

func compareTwo(t *testing.T, s *Server, a, b string, response bool) compareResult {
	t.Helper()
	body, err := json.Marshal(map[string]any{"a": a, "b": b, "response": response})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/tools/compare", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/tools/compare = %d: %s", rec.Code, rec.Body.String())
	}
	var out compareResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return out
}

// Two responses differing only in Date. The bytes differ, so `identical` must stay false — but the
// operator's question, "did anything meaningful change", is answered by identical_ignoring.
func TestTwoResponsesDifferingOnlyInADiscountedHeaderAreReportedAsSuch(t *testing.T) {
	ts := newTestServer()

	// Same length values, so the diff is a clean replace inside the Date line. Different lengths are
	// covered by the delete/insert cases below.
	a := "HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:01 GMT\r\nContent-Length: 2\r\n\r\nhi"
	b := "HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:02 GMT\r\nContent-Length: 2\r\n\r\nhi"

	got := compareTwo(t, ts, a, b, true)
	if got.Identical {
		t.Error("identical=true for messages whose bytes differ — that would be a false claim")
	}
	if !got.IdenticalIgnoring {
		t.Errorf("identical_ignoring_uninteresting=false; ops=%+v", got.Ops)
	}
	if got.UninterestingOps == 0 {
		t.Error("no ops were marked uninteresting, so Date is not being discounted")
	}
	// Date is a default, so it must be in force without any PUT having happened.
	var sawDate bool
	for _, h := range got.Applied {
		if h == "date" {
			sawDate = true
		}
	}
	if !sawDate {
		t.Errorf("applied list %v does not contain \"date\"; the response defaults are not in force",
			got.Applied)
	}
}

// The other direction, and the one that protects against over-eager discounting: a real body
// difference must never be discounted, even when a discounted header also differs.
func TestARealDifferenceIsNotDiscountedEvenAlongsideADiscountedOne(t *testing.T) {
	ts := newTestServer()

	a := "HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:01 GMT\r\nContent-Length: 2\r\n\r\nhi"
	b := "HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:02 GMT\r\nContent-Length: 2\r\n\r\nHI"

	got := compareTwo(t, ts, a, b, true)
	if got.IdenticalIgnoring {
		t.Error("identical_ignoring_uninteresting=true while the body differs — a real difference " +
			"was discounted, which is the failure that would make this setting dangerous")
	}
}

// Header names are case-insensitive per RFC 9110 §5.1, so a message spelling it "DATE" must be
// discounted by a list holding "date", and an operator typing "ETag" must get the same behaviour as
// one typing "etag".
func TestHeaderMatchingIsCaseInsensitiveOnBothSides(t *testing.T) {
	ts := newTestServer()
	if rec := putUninteresting(t, ts, `{"response":["X-Trace-Id"]}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	a := "HTTP/1.1 200 OK\r\nX-TRACE-ID: aaaa\r\n\r\n"
	b := "HTTP/1.1 200 OK\r\nX-TRACE-ID: bbbb\r\n\r\n"
	if got := compareTwo(t, ts, a, b, true); !got.IdenticalIgnoring {
		t.Errorf("a differently-cased header was not discounted; ops=%+v", got.Ops)
	}
}

// A line in the *body* that looks like a header must not be discounted. This is the specific reason
// the scan stops at the blank line: a JSON body with a "date" field is not a header, and treating it
// as one would discount a genuine content difference.
func TestABodyLineThatLooksLikeAHeaderIsNotDiscounted(t *testing.T) {
	ts := newTestServer()

	a := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\ndate: 2026-01-01"
	b := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\ndate: 2026-01-02"

	got := compareTwo(t, ts, a, b, true)
	if got.IdenticalIgnoring {
		t.Error("a difference in the body was discounted because the line looked like a header")
	}
	if got.UninterestingOps != 0 {
		t.Errorf("%d ops discounted in a body", got.UninterestingOps)
	}
}

// The request list is empty by default, so nothing about a request is discounted until the operator
// says so. Nothing the operator controls is noise by default.
func TestTheRequestListIsEmptyByDefault(t *testing.T) {
	ts := newTestServer()

	rec := get(t, ts, "/api/headers/uninteresting")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	var out uninterestingHeadersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Request) != 0 {
		t.Errorf("request defaults are %v, want empty", out.Request)
	}
	if len(out.Response) == 0 {
		t.Error("response defaults are empty")
	}
	if len(out.AppliesTo) == 0 {
		t.Error("applies_to is empty, so the panel cannot say what the setting affects")
	}

	// And a request-side comparison discounts nothing by default.
	a := "GET / HTTP/1.1\r\nHost: a.test\r\nDate: Mon, 01 Jan 2026 00:00:01 GMT\r\n\r\n"
	b := "GET / HTTP/1.1\r\nHost: a.test\r\nDate: Mon, 01 Jan 2026 00:00:02 GMT\r\n\r\n"
	if got := compareTwo(t, ts, a, b, false); got.IdenticalIgnoring {
		t.Error("a request-side Date difference was discounted, but the request list is empty by " +
			"default — the wrong list is being consulted")
	}
}

// Set-Cookie must not be a default. On a security tool a changed cookie can be the finding, and
// defaulting it to "ignore" would hide exactly what an operator is hunting.
func TestSetCookieIsNotDiscountedByDefault(t *testing.T) {
	ts := newTestServer()
	for _, name := range defaultUninterestingResponseHeaders {
		if name == "set-cookie" {
			t.Fatal("set-cookie is a default; a rotated or fixated session token would be dimmed " +
				"out of a comparison without the operator ever choosing that")
		}
	}

	a := "HTTP/1.1 200 OK\r\nSet-Cookie: sid=aaaa\r\n\r\n"
	b := "HTTP/1.1 200 OK\r\nSet-Cookie: sid=bbbb\r\n\r\n"
	if got := compareTwo(t, ts, a, b, true); got.IdenticalIgnoring {
		t.Error("a Set-Cookie difference was discounted by default")
	}
}

// Omitting a direction from a PUT must leave it alone. Without pointer fields, a caller updating
// only the response list would silently clear the request one.
func TestOmittingADirectionFromAPutLeavesItAlone(t *testing.T) {
	ts := newTestServer()

	if rec := putUninteresting(t, ts, `{"request":["x-req"],"response":["x-res"]}`); rec.Code != http.StatusOK {
		t.Fatalf("seeding: %d", rec.Code)
	}
	// Now update only the response side.
	rec := putUninteresting(t, ts, `{"response":["x-res-2"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	var out uninterestingHeadersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Request) != 1 || out.Request[0] != "x-req" {
		t.Errorf("request list is %v; omitting it must not clear it", out.Request)
	}
	if len(out.Response) != 1 || out.Response[0] != "x-res-2" {
		t.Errorf("response list is %v, want [x-res-2]", out.Response)
	}

	// An explicit empty array, by contrast, must clear.
	rec = putUninteresting(t, ts, `{"request":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Request) != 0 {
		t.Errorf("request list is %v after an explicit empty array", out.Request)
	}
}

// Pasting a whole header line is the obvious operator mistake, and taking the name before the colon
// is friendlier than refusing. Names are also normalised and de-duplicated.
func TestNamesAreNormalisedFromWhateverTheOperatorPastes(t *testing.T) {
	ts := newTestServer()
	rec := putUninteresting(t, ts,
		`{"response":["Date: Mon, 01 Jan 2026 00:00:00 GMT","  ETag  ","etag","","X-Foo"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	var out uninterestingHeadersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"date", "etag", "x-foo"}
	if strings.Join(out.Response, ",") != strings.Join(want, ",") {
		t.Errorf("normalised to %v, want %v (lower-cased, trimmed, de-duplicated, empties dropped, "+
			"sorted)", out.Response, want)
	}
}

// LF-only line endings must work: a pasted message has usually been through an editor.
func TestBareLFLineEndingsAreHandled(t *testing.T) {
	ts := newTestServer()
	a := "HTTP/1.1 200 OK\nDate: Mon, 01 Jan 2026 00:00:01 GMT\n\nhi"
	b := "HTTP/1.1 200 OK\nDate: Mon, 01 Jan 2026 00:00:02 GMT\n\nhi"
	if got := compareTwo(t, ts, a, b, true); !got.IdenticalIgnoring {
		t.Errorf("LF-only message was not discounted; ops=%+v", got.Ops)
	}
}

// Identical messages must report both verdicts true and discount nothing — there is nothing to
// discount, and a non-zero count would be reporting work that did not happen.
func TestIdenticalMessagesReportBothVerdictsTrue(t *testing.T) {
	ts := newTestServer()
	msg := "HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:01 GMT\r\n\r\nhi"
	got := compareTwo(t, ts, msg, msg, true)
	if !got.Identical || !got.IdenticalIgnoring {
		t.Errorf("identical=%v ignoring=%v for two identical messages", got.Identical, got.IdenticalIgnoring)
	}
	if got.UninterestingOps != 0 {
		t.Errorf("%d discounted ops for identical messages", got.UninterestingOps)
	}
}

// Non-HTTP input must be diffed, not rejected. The Comparer takes whatever the operator pastes.
func TestNonHTTPInputIsStillCompared(t *testing.T) {
	ts := newTestServer()
	got := compareTwo(t, ts, "just some text", "just some texa", true)
	if got.Identical {
		t.Error("identical=true for differing text")
	}
	if got.UninterestingOps != 0 {
		t.Errorf("%d ops discounted in non-HTTP input", got.UninterestingOps)
	}
}

// The lists must survive an export/import round trip. A new configuration surface the importer
// accepts and the exporter never writes is the defect fixed in 58d4611 and again for the WebSocket
// directions; this is the guard against a third instance.
func TestUninterestingHeadersSurviveAnExportImportRoundTrip(t *testing.T) {
	donor := newTestServer()
	if rec := putUninteresting(t, donor, `{"request":["x-donor-req"],"response":["x-donor-res"]}`); rec.Code != http.StatusOK {
		t.Fatalf("seeding: %d", rec.Code)
	}

	exported := get(t, donor, "/api/config/export")
	if exported.Code != http.StatusOK {
		t.Fatalf("export = %d", exported.Code)
	}
	if !strings.Contains(exported.Body.String(), "uninteresting_headers") {
		t.Fatal("the exported bundle has no uninteresting_headers section")
	}

	recipient := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(exported.Body.String()))
	rec := httptest.NewRecorder()
	recipient.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body.String())
	}

	if got := recipient.uninteresting.headers(false); len(got) != 1 || got[0] != "x-donor-req" {
		t.Errorf("request list after import is %v", got)
	}
	if got := recipient.uninteresting.headers(true); len(got) != 1 || got[0] != "x-donor-res" {
		t.Errorf("response list after import is %v — note the donor's list REPLACES the "+
			"recipient's defaults, which is what makes a round trip reproduce the donor", got)
	}
}

// A bundle predating the section must leave the recipient's lists alone rather than clearing them.
func TestABundleWithoutTheSectionLeavesTheListsAlone(t *testing.T) {
	recipient := newTestServer()
	before := recipient.uninteresting.headers(true)

	req := httptest.NewRequest(http.MethodPost, "/api/config/import",
		strings.NewReader(`{"version":1,"scope":{"rules":[]}}`))
	rec := httptest.NewRecorder()
	recipient.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body.String())
	}

	after := recipient.uninteresting.headers(true)
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Errorf("the response list changed from %v to %v on a bundle that never mentioned it",
			before, after)
	}
}

func TestUninterestingHeadersRejectsOtherMethods(t *testing.T) {
	ts := newTestServer()
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/headers/uninteresting", strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		ts.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", method, rec.Code)
		}
	}
}
