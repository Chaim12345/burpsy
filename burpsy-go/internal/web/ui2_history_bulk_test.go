package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func ui2HistoryCount(t *testing.T, s *Server) int {
	t.Helper()
	var rows []map[string]any
	if err := json.Unmarshal(getUI2(t, s, "/api/history?limit=1000").Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func ui2ID(id core.ExchangeID) string { return strconv.FormatUint(uint64(id), 10) }

func TestUI2HistoryFiltersNarrowRows(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /ok-row HTTP/1.1\r\nHost: a.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	seedUI2Exchange(t, s, "POST /missing-row HTTP/1.1\r\nHost: a.test\r\n\r\n", "HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\n.")
	full := getUI2(t, s, "/ui2/history?status=4").Body.String()
	if !strings.Contains(full, `id="hfilter"`) || !strings.Contains(full, "/missing-row") || strings.Contains(full, "/ok-row") {
		t.Fatalf("status filter did not narrow the rows or the toolbar is missing")
	}
	if body := getUI2(t, s, "/ui2/history?method=GET").Body.String(); !strings.Contains(body, "/ok-row") || strings.Contains(body, "/missing-row") {
		t.Fatalf("method filter did not narrow the rows")
	}
}

func TestUI2HistoryExportCSVGuardsFormulas(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /=cmd HTTP/1.1\r\nHost: =evil.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	rec := getUI2(t, s, "/ui2/history/export.csv")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export = %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.HasPrefix(body, `"ID","Timestamp","Method","Host","Port","Path","Extension","Query","TLS","Edited","Status","Length","MIME","Duration","Comment"`) {
		t.Fatalf("CSV header differs from historyToCSV: %q", body[:ui2Min(200, len(body))])
	}
	if !strings.Contains(body, `"'=evil.test"`) {
		t.Fatalf("formula guard missing: %s", body)
	}
}

func ui2PostHAR(t *testing.T, s *Server, file []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if file != nil {
		fw, _ := mw.CreateFormFile("har", "x.har")
		_, _ = fw.Write(file)
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/ui2/history/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func TestUI2HistoryImportHAR(t *testing.T) {
	s := newTestServer()
	har := `{"log":{"version":"1.2","entries":[{"startedDateTime":"2024-01-01T00:00:00Z","time":5,
"request":{"method":"GET","url":"http://har.test/imported","httpVersion":"HTTP/1.1","headers":[{"name":"Host","value":"har.test"}],"queryString":[]},
"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[],"content":{"size":2,"mimeType":"text/plain","text":"ok"}}}]}}`
	if body := ui2PostHAR(t, s, []byte(har)).Body.String(); !strings.Contains(body, "Imported 1 HAR entry") {
		t.Fatalf("import did not report the entry: %s", body)
	}
	if !strings.Contains(getUI2(t, s, "/ui2/history").Body.String(), "/imported") {
		t.Fatal("imported row missing from history")
	}
	if body := ui2PostHAR(t, s, nil).Body.String(); !strings.Contains(body, "choose a .har file") {
		t.Fatalf("an upload without a file was not refused: %s", body)
	}
}

func TestUI2HistoryGotoAndCompare(t *testing.T) {
	s := newTestServer()
	a := seedUI2Exchange(t, s, "GET /left HTTP/1.1\r\nHost: c.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	b := seedUI2Exchange(t, s, "GET /right HTTP/1.1\r\nHost: c.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	if body := getUI2(t, s, "/ui2/history/goto?id="+ui2ID(b)).Body.String(); !strings.Contains(body, `data-goto="`+ui2ID(b)+`"`) || !strings.Contains(body, "/right") {
		t.Fatalf("goto did not render the entry: %s", body[:ui2Min(300, len(body))])
	}
	if body := getUI2(t, s, "/ui2/history/goto?id=999").Body.String(); !strings.Contains(body, "no exchange #999") {
		t.Fatal("goto to a missing id was not named")
	}
	body := getUI2(t, s, "/ui2/history/compare?ids="+ui2ID(a)+","+ui2ID(b)).Body.String()
	if !strings.Contains(body, "GET /left") || !strings.Contains(body, "GET /right") || !strings.Contains(body, `hx-post="/ui2/comparer/run"`) {
		t.Fatalf("compare did not seed A and B: %s", body[:ui2Min(400, len(body))])
	}
}

func TestUI2HistoryBulkURLsAndOrganizer(t *testing.T) {
	s := newTestServer()
	a := seedUI2Exchange(t, s, "GET /one HTTP/1.1\r\nHost: u.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	b := seedUI2Exchange(t, s, "GET /two HTTP/1.1\r\nHost: u.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	ids := url.Values{"ids": {ui2ID(a) + "," + ui2ID(b)}}
	if body := postUI2Form(t, s, "/ui2/history/bulk/urls", ids).Body.String(); !strings.Contains(body, "http://u.test/one\nhttp://u.test/two") {
		t.Fatalf("copy URLs: %s", body)
	}
	if body := postUI2Form(t, s, "/ui2/history/bulk/organizer", ids).Body.String(); !strings.Contains(body, "Added 2 exchanges to Organizer") {
		t.Fatalf("organizer: %s", body)
	}
	if n := len(s.organizer.List()); n != 2 {
		t.Fatalf("organizer holds %d items, want 2", n)
	}
	if body := postUI2Form(t, s, "/ui2/history/bulk/organizer", url.Values{"ids": {ui2ID(a)}, "extra": {"1"}}).Body.String(); !strings.Contains(body, "extra is not a single permitted field") {
		t.Fatalf("a smuggled field was not refused: %s", body)
	}
}

func TestUI2HistoryBulkDeleteReviewedRun(t *testing.T) {
	s := newTestServer()
	a := seedUI2Exchange(t, s, "GET /keep HTTP/1.1\r\nHost: d.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	b := seedUI2Exchange(t, s, "GET /drop HTTP/1.1\r\nHost: d.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	review := postUI2Form(t, s, "/ui2/history/bulk/delete-confirm", url.Values{"ids": {ui2ID(b)}}).Body.String()
	if !strings.Contains(review, `DELETE /api/history/rows {&#34;ids&#34;:[`+ui2ID(b)+`]}`) || !strings.Contains(review, "data-arm-on-load") {
		t.Fatalf("review does not show the full bound body: %s", review)
	}
	token := extractHiddenInput(t, review, "token")
	// A tampered id list fails the token digest and removes nothing.
	tampered := postUI2Form(t, s, "/ui2/history/bulk/delete-run", url.Values{"ids": {ui2ID(a)}, "token": {token}}).Body.String()
	if !strings.Contains(tampered, "not applied") || ui2HistoryCount(t, s) != 2 {
		t.Fatalf("tampered delete was not refused: %s", tampered)
	}
	review = postUI2Form(t, s, "/ui2/history/bulk/delete-confirm", url.Values{"ids": {ui2ID(b)}}).Body.String()
	run := postUI2Form(t, s, "/ui2/history/bulk/delete-run", url.Values{"ids": {extractHiddenInput(t, review, "ids")}, "token": {extractHiddenInput(t, review, "token")}})
	if !strings.Contains(run.Body.String(), "Deleted 1 of 1") || ui2HistoryCount(t, s) != 1 {
		t.Fatalf("reviewed delete did not apply: %s", run.Body.String())
	}
	if empty := postUI2Form(t, s, "/ui2/history/bulk/delete-run", url.Values{"ids": {""}, "token": {"x"}}).Body.String(); !strings.Contains(empty, "selection is empty") || ui2HistoryCount(t, s) != 1 {
		t.Fatalf("an empty id list reached the clear-everything call: %s", empty)
	}
}

func TestUI2HistoryBulkClearReviewedRun(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /x HTTP/1.1\r\nHost: e.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	if bad := postUI2Form(t, s, "/ui2/history/bulk/clear-run", url.Values{"token": {"forged"}}).Body.String(); !strings.Contains(bad, "not applied") || ui2HistoryCount(t, s) != 1 {
		t.Fatalf("a forged clear token was not refused: %s", bad)
	}
	review := postUI2Form(t, s, "/ui2/history/bulk/clear-confirm", url.Values{}).Body.String()
	run := postUI2Form(t, s, "/ui2/history/bulk/clear-run", url.Values{"token": {extractHiddenInput(t, review, "token")}}).Body.String()
	if !strings.Contains(run, "History cleared") || ui2HistoryCount(t, s) != 0 {
		t.Fatalf("reviewed clear did not apply: %s", run)
	}
}

func TestUI2HistoryBulkAuditReview(t *testing.T) {
	s := newTestServer()
	a := seedUI2Exchange(t, s, "GET /audit HTTP/1.1\r\nHost: f.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	review := postUI2Form(t, s, "/ui2/history/bulk/audit-confirm", url.Values{"ids": {ui2ID(a)}}).Body.String()
	if !strings.Contains(review, "POST /api/audit/selected {&#34;exchange_ids&#34;:["+ui2ID(a)+"]}") {
		t.Fatalf("audit review does not show the bound body: %s", review)
	}
	run := postUI2Form(t, s, "/ui2/history/bulk/audit-run", url.Values{"ids": {ui2ID(a) + ",999"}, "token": {extractHiddenInput(t, review, "token")}}).Body.String()
	if !strings.Contains(run, "not applied") {
		t.Fatalf("an edited audit selection was not refused: %s", run)
	}
}

func TestUI2HistoryBulkScopeReviewedRun(t *testing.T) {
	s := newTestServer()
	a := seedUI2Exchange(t, s, "GET / HTTP/1.1\r\nHost: s1.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	b := seedUI2Exchange(t, s, "GET / HTTP/1.1\r\nHost: s2.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	review := postUI2Form(t, s, "/ui2/history/bulk/scope-confirm", url.Values{"ids": {ui2ID(a) + "," + ui2ID(b)}}).Body.String()
	if !strings.Contains(review, "s1.test") || !strings.Contains(review, "s2.test") {
		t.Fatalf("scope review does not list every host: %s", review)
	}
	rid := extractHiddenInput(t, review, "review_id")
	if bad := postUI2Form(t, s, "/ui2/history/bulk/scope-run", url.Values{"review_id": {rid}, "token": {"wrong"}}).Body.String(); !strings.Contains(bad, "does not match") {
		t.Fatalf("a wrong review token was not refused: %s", bad)
	}
	review = postUI2Form(t, s, "/ui2/history/bulk/scope-confirm", url.Values{"ids": {ui2ID(a) + "," + ui2ID(b)}}).Body.String()
	run := postUI2Form(t, s, "/ui2/history/bulk/scope-run", url.Values{"review_id": {extractHiddenInput(t, review, "review_id")}, "token": {extractHiddenInput(t, review, "token")}}).Body.String()
	if !strings.Contains(run, "Added 2 hosts to scope") {
		t.Fatalf("reviewed scope add did not apply: %s", run)
	}
	if !s.scope.Contains("s2.test", 80, "/", false) {
		t.Fatal("s2.test is not in scope after the run")
	}
}

func TestUI2HistoryExtractorColumns(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /tok HTTP/1.1\r\nHost: x.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\ncsrf=abc123;")
	page := getUI2(t, s, "/ui2/history/extractors").Body.String()
	base := extractHiddenInput(t, page[strings.Index(page, `/ui2/history/extractors/add`):], "base")
	if stale := postUI2Form(t, s, "/ui2/history/extractors/add", url.Values{"base": {"stale"}, "name": {"csrf"}, "from": {"body"}, "header": {""}, "how": {"regex"}, "pattern": {"csrf=([a-z0-9]+)"}, "group": {"1"}, "json_path": {""}}).Body.String(); !strings.Contains(stale, "changed since this page loaded") {
		t.Fatalf("a stale base was not refused: %s", stale)
	}
	add := postUI2Form(t, s, "/ui2/history/extractors/add", url.Values{"base": {base}, "name": {"csrf"}, "from": {"body"}, "header": {""}, "how": {"regex"}, "pattern": {"csrf=([a-z0-9]+)"}, "group": {"1"}, "json_path": {""}}).Body.String()
	if !strings.Contains(add, "Added the csrf column") {
		t.Fatalf("add: %s", add)
	}
	rows := getUI2(t, s, "/ui2/history").Body.String()
	if !strings.Contains(rows, `<th scope="col" class="c-x0">csrf</th>`) || !strings.Contains(rows, ">abc123</td>") {
		t.Fatalf("extractor column missing from history rows")
	}
}
