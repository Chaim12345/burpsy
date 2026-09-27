package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The Search box on the history endpoint (burpsy-react-ui-ngcj). Burp's doc for that box makes one
// load-bearing promise — "The search applies to the underlying data, regardless of any filters you
// have applied" — and these tests pin the three things that promise means here that nothing else in
// the tree could deliver:
//
//   - the scan reaches RESPONSE bytes, which the old client-side filter never saw (it matched five
//     columns of a fetched row) and the DSL's body field still cannot see (it reads the request's
//     bytes only);
//   - the scan reaches row-only columns, like the recorded page title and a comment on a row that
//     has no bytes to look at;
//   - the three modifiers Burp's dialog gives the box (case, regex, negative) take effect on the
//     list, not just in the suite dialog they were built for.
//
// The fixtures are named for the question each one answers, and the negative test pins the
// sharpest edge: negation must answer "the term is absent from THIS row's data", never from
// another row's — which is what scanning message 0 on a request-less row would have reported.

// addHistorySearchRow stores an exchange built for one search question and returns its id.
func addHistorySearchRow(t *testing.T, s *Server, row core.Exchange, request, response string) core.ExchangeID {
	t.Helper()
	if request != "" {
		id, err := s.store.Put([]byte(request), core.DirectionRequest)
		if err != nil {
			t.Fatalf("put request: %v", err)
		}
		row.Request = core.MsgPtr(id)
	}
	if response != "" {
		id, err := s.store.Put([]byte(response), core.DirectionResponse)
		if err != nil {
			t.Fatalf("put response: %v", err)
		}
		row.Response = &id
	}
	s.store.AddExchange(&row)
	exchanges := s.store.Exchanges()
	return exchanges[len(exchanges)-1].ID
}

// runHistorySearch performs GET /api/history with a Search box query and returns the decoded rows.
func runHistorySearch(t *testing.T, s *Server, search string) []ExchangeView {
	t.Helper()
	path := "/api/history?limit=50&search=" + strings.ReplaceAll(search, " ", "%20")
	rec := get(t, s, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, body = %s", path, rec.Code, rec.Body.String())
	}
	var rows []ExchangeView
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode history rows: %v", err)
	}
	return rows
}

func rowByPath(t *testing.T, rows []ExchangeView, path string) *ExchangeView {
	t.Helper()
	for i := range rows {
		if rows[i].Path == path {
			return &rows[i]
		}
	}
	t.Fatalf("no row with path %q in the %d rows returned", path, len(rows))
	return nil
}

func TestTheHistorySearchReachesResponseBytesNoRowColumnCarries(t *testing.T) {
	s := newTestServer()
	addHistorySearchRow(t, s, core.Exchange{
		Host: "bytes.test", Port: 443, TLS: true, Method: "GET", Path: "/body-hit",
		Status: ptrStatus(200), ResponseLen: 40, Source: core.SourceProxy,
	}, "GET /body-hit HTTP/1.1\r\nHost: bytes.test\r\n\r\n", pageWithTitle("untitled", "page-body-with-no-needle"))
	addHistorySearchRow(t, s, core.Exchange{
		Host: "bytes.test", Port: 443, TLS: true, Method: "GET", Path: "/body-needle",
		Status: ptrStatus(200), ResponseLen: 40, Source: core.SourceProxy,
	}, "GET /body-needle HTTP/1.1\r\nHost: bytes.test\r\n\r\n", pageWithTitle("untitled", "the response-body-needle lives here"))

	rows := runHistorySearch(t, s, "response-body-needle")
	if len(rows) != 1 {
		t.Fatalf("the search returned %d rows, want the one row whose RESPONSE BODY carries the term — the old client-side filter matched five columns and the DSL's body field reads the request only, so either of those mechanisms passing this test would mean it was never wired", len(rows))
	}
	if rows[0].Path != "/body-needle" {
		t.Fatalf("matched row is %q, want /body-needle", rows[0].Path)
	}
}

func TestTheHistorySearchReachesRowColumnsTheBytesNeverCarried(t *testing.T) {
	s := newTestServer()
	comment := "found-by-its-comment"
	addHistorySearchRow(t, s, core.Exchange{
		Host: "columns.test", Port: 443, TLS: true, Method: "GET", Path: "/commented",
		Status: ptrStatus(200), ResponseLen: 0, Notes: &comment, Source: core.SourceProxy,
	}, "GET /commented HTTP/1.1\r\nHost: columns.test\r\n\r\n", "")
	addHistorySearchRow(t, s, core.Exchange{
		Host: "columns.test", Port: 443, TLS: true, Method: "GET", Path: "/titled",
		Status: ptrStatus(200), ResponseLen: 0, Title: "The Title Column Itself", Source: core.SourceProxy,
	}, "", "")

	rows := runHistorySearch(t, s, "comment")
	if len(rows) != 1 || rows[0].Path != "/commented" {
		t.Fatalf("a search for a comment found %d rows (paths %s), want exactly the commented row — the row-column half of the haystack exists because no bytes scan can see a note", len(rows), pathsOf(rows))
	}
	rows = runHistorySearch(t, s, "Title Column Itself")
	if len(rows) != 1 || rows[0].Path != "/titled" {
		t.Fatalf("a search for a page title found %d rows, want exactly the titled row — the title is recorded on the row at capture time precisely so listing would never read bodies; the search must honour that decision", len(rows))
	}
}

func TestTheHistorySearchHonoursTheCaseRegexAndNegativeModifiers(t *testing.T) {
	s := newTestServer()
	addHistorySearchRow(t, s, core.Exchange{
		Host: "mods.test", Port: 443, TLS: true, Method: "GET", Path: "/case-hit",
		Status: ptrStatus(200), ResponseLen: 0, Source: core.SourceProxy,
	}, "", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nCamelCaseNeedle")
	addHistorySearchRow(t, s, core.Exchange{
		Host: "mods.test", Port: 443, TLS: true, Method: "GET", Path: "/other",
		Status: ptrStatus(200), ResponseLen: 0, Source: core.SourceProxy,
	}, "", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nnothing")

	// Case-insensitive by default, the box's Burp-checkbox contract.
	if rows := runHistorySearch(t, s, "camelcaseneedle"); len(rows) != 1 || rows[0].Path != "/case-hit" {
		t.Fatalf("case-insensitive search found %d rows, want the one row carrying CamelCaseNeedle", len(rows))
	}
	// Case-sensitive narrows to nothing: the term as typed is not in the bytes.
	rec := get(t, s, "/api/history?limit=50&search=camelcaseneedle&search_case=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("case-sensitive search failed to serve: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "case-hit") {
		t.Fatal("a case-sensitive search for 'camelcaseneedle' still matched a row whose bytes carry 'CamelCaseNeedle' — the checkbox was not wired to the scan")
	}
	// Regex: the pattern, not the literal.
	if rows := runHistorySearch(t, s, "Camel[CD]aseNeedle"); len(rows) != 0 {
		t.Fatalf("a literal search for 'Camel[CD]aseNeedle' matched %d rows — the pattern should be a literal here and match nothing", len(rows))
	}
	rec = get(t, s, "/api/history?limit=50&search=Camel[CD]aseNeedle&search_regex=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("regex search failed to serve: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "case-hit") {
		t.Fatal("a regex search for Camel[CD]aseNeedle did not match the row whose bytes carry CamelCaseNeedle — the regex checkbox was not wired to the scan")
	}
	// Negative: the rows without the term.
	rec = get(t, s, "/api/history?limit=50&search=needle&search_negate=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("negative search failed to serve: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/other") || strings.Contains(rec.Body.String(), "case-hit") {
		t.Fatal("a negative search for 'needle' must list exactly the rows that do NOT carry it — instead it listed the wrong half of the capture")
	}
}

func TestTheHistorySearchAppliesBeforeTheCapSoACappedListIsATruthfulSlice(t *testing.T) {
	s := newTestServer()
	// Three rows carrying the term, plus two older rows without it. A cap of 2 must still find
	// ALL three term rows, because Burp's promise is that the search applies to the underlying
	// data — a cap applied before the search would silently hide a hit.
	for _, path := range []string{"/hit-1", "/hit-2", "/hit-3"} {
		addHistorySearchRow(t, s, core.Exchange{
			Host: "cap.test", Port: 443, TLS: true, Method: "GET", Path: path,
			Status: ptrStatus(200), ResponseLen: 0, Source: core.SourceProxy,
		}, "", fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nneedle in %s", path))
	}
	for _, path := range []string{"/miss-1", "/miss-2"} {
		addHistorySearchRow(t, s, core.Exchange{
			Host: "cap.test", Port: 443, TLS: true, Method: "GET", Path: path,
			Status: ptrStatus(200), ResponseLen: 0, Source: core.SourceProxy,
		}, "", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nnothing")
	}
	rec := get(t, s, "/api/history?limit=2&search=needle")
	if rec.Code != http.StatusOK {
		t.Fatalf("capped search failed to serve: %d %s", rec.Code, rec.Body.String())
	}
	var rows []ExchangeView
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("a cap of 2 returned %d rows, want the cap honoured (2) — the cap is a page of the SEARCH RESULT, not a page of the capture that happens to be searched", len(rows))
	}
	for _, row := range rows {
		if !strings.HasPrefix(row.Path, "/hit") {
			t.Fatalf("row %q is not a hit — the cap sliced into rows the search should have excluded", row.Path)
		}
	}
}

func TestTheHistorySearchSkipsToolTrafficLikeTheUnsearchedListDoes(t *testing.T) {
	s := newTestServer()
	addHistorySearchRow(t, s, core.Exchange{
		Host: "tools.test", Port: 443, TLS: true, Method: "GET", Path: "/proxied",
		Status: ptrStatus(200), ResponseLen: 0, Source: core.SourceProxy,
	}, "", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nneedle")
	addHistorySearchRow(t, s, core.Exchange{
		Host: "tools.test", Port: 443, TLS: true, Method: "GET", Path: "/sent-by-repeater",
		Status: ptrStatus(200), ResponseLen: 0, Source: core.SourceRepeater,
	}, "", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nneedle")

	rows := runHistorySearch(t, s, "needle")
	if len(rows) != 1 || rows[0].Path != "/proxied" {
		t.Fatalf("the search returned %d rows (paths %s), want only the proxied row — a search that surfaced tool traffic would make the Search box a second Logger and the two lists would disagree about what history is", len(rows), pathsOf(rows))
	}
}

// ---- helpers ------------------------------------------------------------------------------------

func ptrStatus(code uint16) *uint16 { return &code }

func pageWithTitle(title, body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><title>%s</title></head><body>%s</body></html>", title, body)
}

func pathsOf(rows []ExchangeView) string {
	paths := make([]string, 0, len(rows))
	for _, row := range rows {
		paths = append(paths, row.Path)
	}
	return strings.Join(paths, ", ")
}
