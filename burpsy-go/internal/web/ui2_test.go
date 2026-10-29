package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// getUI2 drives one request through s.mux (the same surface the 405 sweep uses) and returns
// the recorder. The cross-site gate is not in play here, matching every other handler test.
func getUI2(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func TestUI2ShellServesLayoutWithHistoryRows(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /alpha HTTP/1.1\r\nHost: a.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	seedUI2Exchange(t, s, "POST /beta?x=1 HTTP/1.1\r\nHost: b.test\r\n\r\n", "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnope")

	rec := getUI2(t, s, "/ui2/history")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui2/history = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"burpsy", "/ui2/htmx.min.js", "/alpha", "/beta?x=1", "a.test", "b.test", "404", "#rows"} {
		if !strings.Contains(body, want) {
			t.Errorf("shell is missing %q", want)
		}
	}
	// Newest first: /beta (second seed) must appear before /alpha in the document.
	if strings.Index(body, "/beta") > strings.Index(body, "/alpha") {
		t.Errorf("rows are not newest-first: /beta at %d, /alpha at %d", strings.Index(body, "/beta"), strings.Index(body, "/alpha"))
	}
}

func TestUI2HistoryFragmentIsReturnedForHXRequest(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /x HTTP/1.1\r\nHost: h.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	req := httptest.NewRequest(http.MethodGet, "/ui2/history", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fragment = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<!doctype html>") {
		t.Errorf("HX-Request got the full shell, want only the rows fragment")
	}
	if !strings.Contains(body, "/x") {
		t.Errorf("fragment is missing the row")
	}
}

func TestUI2HistorySearchAndPagingAreServerSide(t *testing.T) {
	s := newTestServer()
	for i := range 30 {
		path := "/item/" + string(rune('a'+i))
		seedUI2Exchange(t, s, "GET "+path+" HTTP/1.1\r\nHost: page.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	}
	// search narrows: only /item/a matches "item/a"
	rec := getUI2(t, s, "/ui2/history?search=item%2Fa")
	body := rec.Body.String()
	if !strings.Contains(body, "/item/a") || strings.Contains(body, "/item/b") {
		t.Errorf("search did not narrow to /item/a: %s", body)
	}
	if !strings.Contains(body, "1 of 30 rows") {
		t.Errorf("meta line should report 1 of 30, got: %s", firstMetaLine(body))
	}
	// paging: limit=10 offset=0 shows 10 rows and a sentinel for offset 10
	rec = getUI2(t, s, "/ui2/history?limit=10")
	body = rec.Body.String()
	if got := strings.Count(body, "<tr hx-get"); got != 10 {
		t.Errorf("limit=10 rendered %d rows, want 10", got)
	}
	if !strings.Contains(body, `"offset": 10`) {
		t.Errorf("no infinite-scroll sentinel for offset 10 in: %s", body)
	}
	// last page: offset=25 limit=10 -> 5 rows, no sentinel
	rec = getUI2(t, s, "/ui2/history?limit=10&offset=25")
	body = rec.Body.String()
	if got := strings.Count(body, "<tr hx-get"); got != 5 {
		t.Errorf("offset=25 limit=10 rendered %d rows, want 5", got)
	}
	if strings.Contains(body, `"offset": 30`) {
		t.Errorf("last page must not carry a sentinel")
	}
}

func TestUI2HistoryAppendFragmentIsRowsOnly(t *testing.T) {
	s := newTestServer()
	for i := range 30 {
		seedUI2Exchange(t, s, fmt.Sprintf("GET /a/%d HTTP/1.1\r\nHost: h.test\r\n\r\n", i), "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	}
	req := httptest.NewRequest(http.MethodGet, "/ui2/history?limit=10&offset=10", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("append = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<!doctype") || strings.Contains(body, `<div id="rows">`) {
		t.Errorf("append fragment carries the whole block, want rows only")
	}
	if got := strings.Count(body, "<tr hx-get"); got != 10 {
		t.Errorf("append carried %d rows, want 10", got)
	}
	if !strings.Contains(body, `class="sentinel-row"`) || !strings.Contains(body, `"offset": 20`) {
		t.Errorf("append must carry the next sentinel pointing at offset 20")
	}
}

func TestUI2HistoryDetailRendersRequestAndResponse(t *testing.T) {
	s := newTestServer()
	id := seedUI2Exchange(t, s, "GET /detail HTTP/1.1\r\nHost: d.test\r\nX-Marker: abc\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	rec := getUI2(t, s, "/ui2/history/"+itoa64(uint64(id)))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"GET /detail", "X-Marker: abc", "hello", "d.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail pane missing %q", want)
		}
	}
	if rec := getUI2(t, s, "/ui2/history/9999"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec.Code)
	}
	if rec := getUI2(t, s, "/ui2/history/notanumber"); rec.Code != http.StatusBadRequest {
		t.Errorf("non-numeric id = %d, want 400", rec.Code)
	}
}

func TestUI2HistoryEscapesAttackerBytes(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /<script>alert(1)</script> HTTP/1.1\r\nHost: x.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok")
	for _, path := range []string{"/ui2/history", "/ui2/history?search=script"} {
		body := getUI2(t, s, path).Body.String()
		if strings.Contains(body, "<script>alert(1)</script>") {
			t.Errorf("%s rendered raw attacker markup", path)
		}
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Errorf("%s did not escape the path", path)
		}
	}
}

func TestUI2IssuesGroupsFindingsByNameAndHost(t *testing.T) {
	s := newTestServer()
	seedUI2Finding(t, s, "Reflected XSS", "high", "a.test", "/search")
	seedUI2Finding(t, s, "Reflected XSS", "high", "a.test", "/login")
	seedUI2Finding(t, s, "Missing HSTS", "low", "b.test", "/")

	rec := getUI2(t, s, "/ui2/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui2/issues = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Reflected XSS") || !strings.Contains(body, "Missing HSTS") {
		t.Errorf("issues page missing issue names")
	}
	if !strings.Contains(body, "sev-high") || !strings.Contains(body, "sev-low") {
		t.Errorf("severity class missing")
	}
	if !strings.Contains(body, "2×") {
		t.Errorf("merged group should show 2 occurrences, body: %s", body)
	}
	if !strings.Contains(body, "3 findings") {
		t.Errorf("meta should count 3 findings: %s", firstMetaLine(body))
	}
}

func TestUI2IssueDetailShowsEvidenceAndOccurrences(t *testing.T) {
	s := newTestServer()
	id := seedUI2Finding(t, s, "Hardcoded secret", "critical", "a.test", "/config")
	rec := getUI2(t, s, "/ui2/issues/"+itoa64(id))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Hardcoded secret", "critical", "a.test", "Evidence", "/config"} {
		if !strings.Contains(body, want) {
			t.Errorf("issue detail missing %q", want)
		}
	}
	if rec := getUI2(t, s, "/ui2/issues/4242"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown issue = %d, want 404", rec.Code)
	}
}

func TestUI2AssetsAreServedAndCatchAllStaysOldUI(t *testing.T) {
	s := newTestServer()
	for _, path := range []string{"/ui2/htmx.min.js", "/ui2/sse.min.js"} {
		rec := getUI2(t, s, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
			t.Errorf("%s Content-Type = %q, want javascript", path, ct)
		}
		if rec.Body.Len() < 1000 {
			t.Errorf("%s served %d bytes, vendored file looks truncated", path, rec.Body.Len())
		}
	}
	// An unknown /ui2/ asset name matches no registered pattern, so it falls through to the
	// SPA catch-all (200 HTML) — asserted so the fallthrough is deliberate, not a gap.
	if rec := getUI2(t, s, "/ui2/nope.js"); rec.Code != http.StatusOK {
		t.Errorf("unknown /ui2/ asset = %d, want the SPA catch-all's 200", rec.Code)
	}
	// The old UI catch-all must be untouched: / still serves the SPA shell.
	rec := getUI2(t, s, "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<") {
		t.Errorf("GET / = %d, the SPA catch-all regressed", rec.Code)
	}
}

func TestUI2RoutesRejectWrongVerbs(t *testing.T) {
	s := newTestServer()
	for _, path := range []string{"/ui2/history", "/ui2/issues", "/ui2/htmx.min.js"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, rec.Code)
		}
	}
}

// seedUI2Exchange stores one request/response pair as a proxy-sourced exchange and returns its id.
func seedUI2Exchange(t *testing.T, s *Server, request, response string) core.ExchangeID {
	t.Helper()
	reqID, err := s.store.Put([]byte(request), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := s.store.Put([]byte(response), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	status := uint16(0)
	if len(response) >= 12 {
		if n, err := strconv.Atoi(strings.TrimSpace(response[9:12])); err == nil {
			status = uint16(n)
		}
	}
	host := "h.test"
	for _, line := range strings.Split(request, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
		}
	}
	ex := &core.Exchange{
		Host: host, Port: 80, Method: firstLineMethod(request), Path: firstLinePath(request),
		Status: &status, Request: core.MsgPtr(reqID), Response: &respID, Source: core.SourceProxy,
	}
	s.store.AddExchange(ex)
	return ex.ID
}

// seedUI2Finding files one finding and returns its id. Evidence is included because the
// detail pane's whole point is showing it.
func seedUI2Finding(t *testing.T, s *Server, name, severity, host, path string) uint64 {
	t.Helper()
	exID := seedUI2Exchange(t, s, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	reqID, _ := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	id := s.findings.Add(core.NewFinding{
		Name:     name,
		Severity: core.ParseSeverity(severity),
		Target:   core.FindingTarget{Host: host, Port: 443, TLS: true, Path: path},
		Evidence: "excerpt: AKIA…REDACTED",
		Occurrences: []core.Occurrence{{
			ExchangeID: exID,
			Request:    core.MsgPtr(reqID),
		}},
	})
	return id
}

func firstMetaLine(body string) string {
	i := strings.Index(body, `class="meta"`)
	if i < 0 {
		return body
	}
	rest := body[i:]
	if j := strings.Index(rest, "</p>"); j >= 0 {
		return rest[:j]
	}
	return rest
}
