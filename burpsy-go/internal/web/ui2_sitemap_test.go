package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// ---- helpers ---------------------------------------------------------------------------------

func smGet(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w
}

func smPost(s *Server, path string, form url.Values) string {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w.Body.String()
}

// smRecordBody stores one exchange whose response carries body.
func smRecordBody(t *testing.T, s *Server, host, path, body string) {
	t.Helper()
	reqID, _ := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+body), core.DirectionResponse)
	status := uint16(200)
	s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: 80,
		Method: "GET", Path: path, Status: &status, Mime: "text/html", Source: core.SourceProxy})
}

// smReview drives the confirm step and returns the run form's fields, failing on a refusal.
func smReview(t *testing.T, s *Server, key, op string, form url.Values) (url.Values, string) {
	t.Helper()
	out := smPost(s, "/ui2/sitemap/review/confirm?"+url.Values{"key": {key}, "op": {op}}.Encode(), form)
	if strings.Contains(out, "Not applied:") {
		t.Fatalf("confirm refused: %s", out)
	}
	run := url.Values{}
	for _, k := range []string{"review_id", "token"} {
		m := regexp.MustCompile(`name="` + k + `" value="([^"]*)"`).FindStringSubmatch(out)
		if len(m) != 2 {
			t.Fatalf("sheet missing %s: %s", k, out)
		}
		run.Set(k, m[1])
	}
	return run, out
}

// ---- page, filters, lazy children ------------------------------------------------------------

func TestUI2SitemapFiltersNarrowTheTree(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	recordCompleteExchange(t, s, "h.test", "/api/users")

	all := smGet(t, s, "/ui2/sitemap").Body.String()
	if !strings.Contains(all, ">login<") || !strings.Contains(all, ">api<") {
		t.Fatalf("unfiltered tree misses a node: %s", all)
	}
	narrowed := smGet(t, s, "/ui2/sitemap?q=users").Body.String()
	if strings.Contains(narrowed, ">login<") || !strings.Contains(narrowed, ">users<") {
		t.Fatalf("q=users did not narrow to the users branch (open): %s", narrowed)
	}
	if !strings.Contains(narrowed, `value="users"`) || !strings.Contains(narrowed, "Clear filters") {
		t.Fatal("the filter bar does not round-trip its state")
	}
	if body := smGet(t, s, "/ui2/sitemap?status=4").Body.String(); !strings.Contains(body, "No path matches this filter") {
		t.Fatalf("status=4 should empty a map of 200s: %s", body)
	}
	if body := smGet(t, s, "/ui2/sitemap?type=json&type=html").Body.String(); !strings.Contains(body, ">login<") ||
		!strings.Contains(body, `value="html" checked`) {
		t.Fatalf("type=html must keep html nodes and check its box: %s", body)
	}
}

func TestUI2SitemapChildrenLoadsLazily(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/api/users")
	page := smGet(t, s, "/ui2/sitemap").Body.String()
	if strings.Contains(page, ">users<") {
		t.Fatal("a depth-2 node rendered inline; it should load lazily")
	}
	kids := smGet(t, s, "/ui2/sitemap/children?key="+url.QueryEscape(sitemapPathKey("h.test", "/api")))
	if kids.Code != http.StatusOK || !strings.Contains(kids.Body.String(), ">users<") {
		t.Fatalf("children = %d: %s", kids.Code, kids.Body.String())
	}
	branch := smGet(t, s, "/ui2/sitemap/children?mode=branch&key="+url.QueryEscape(sitemapHostKey("h.test"))).Body.String()
	if !strings.Contains(branch, ">users<") || !strings.Contains(branch, `class="sm-node`) {
		t.Fatalf("branch mode did not expand the whole host: %s", branch)
	}
	if w := smGet(t, s, "/ui2/sitemap/children"); w.Code != http.StatusBadRequest {
		t.Fatalf("children without key = %d, want 400", w.Code)
	}
}

func TestUI2SitemapDetailAndMessage(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	detail := smGet(t, s, "/ui2/sitemap/detail?key="+url.QueryEscape(sitemapPathKey("h.test", "/login"))).Body.String()
	for _, want := range []string{"Requests under this node (1)", "/ui2/sitemap/message?id=", "Filter history", "http://h.test/login", "Issues (0)"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail omits %q: %s", want, detail)
		}
	}
	id := regexp.MustCompile(`/ui2/sitemap/message\?id=(\d+)`).FindStringSubmatch(detail)[1]
	msg := smGet(t, s, "/ui2/sitemap/message?id="+id)
	if msg.Code != http.StatusOK || !strings.Contains(msg.Body.String(), "/login") || !strings.Contains(msg.Body.String(), "hello") {
		t.Fatalf("message = %d: %s", msg.Code, msg.Body.String())
	}
	// The full page with sel renders the same pane server-side (bookmarkable selection).
	if page := smGet(t, s, "/ui2/sitemap?sel="+url.QueryEscape(sitemapPathKey("h.test", "/login"))).Body.String(); !strings.Contains(page, "Requests under this node (1)") {
		t.Fatal("sel= did not render the detail pane")
	}
	if w := smGet(t, s, "/ui2/sitemap/message?id=nope"); w.Code != http.StatusBadRequest {
		t.Fatalf("message with a non-numeric id = %d, want 400", w.Code)
	}
}

// ---- writes ----------------------------------------------------------------------------------

func TestUI2SitemapDeleteBranchThroughReview(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/api/users")
	recordCompleteExchange(t, s, "h.test", "/login")
	run, sheet := smReview(t, s, sitemapPathKey("h.test", "/api"), "delete-branch", url.Values{})
	for _, want := range []string{"DELETE /api/sitemap", `&#34;kind&#34;: &#34;branch&#34;`, `&#34;path&#34;: &#34;/api&#34;`, "disabled data-arm-on-load", `method="post"`} {
		if !strings.Contains(sheet, want) {
			t.Fatalf("review sheet omits %q: %s", want, sheet)
		}
	}
	out := smPost(s, "/ui2/sitemap/review/run", run)
	if !strings.Contains(out, "Suppressed branch h.test/api") || !strings.Contains(out, `hx-swap-oob="true"`) {
		t.Fatalf("run outcome: %s", out)
	}
	tree := get(t, s, "/api/sitemap").Body.String()
	if strings.Contains(tree, `"segment":"api"`) || !strings.Contains(tree, `"segment":"login"`) {
		t.Fatalf("the branch was not suppressed exactly: %s", tree)
	}
	// Single use: the same review cannot run twice.
	if again := smPost(s, "/ui2/sitemap/review/run", run); !strings.Contains(again, "unknown or was already used") {
		t.Fatalf("replayed review was not refused: %s", again)
	}
}

func TestUI2SitemapReviewRunRefusesWrongToken(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	run, _ := smReview(t, s, sitemapHostKey("h.test"), "delete-host", url.Values{})
	run.Set("token", strings.Repeat("0", 32))
	if out := smPost(s, "/ui2/sitemap/review/run", run); !strings.Contains(out, "Not applied:") {
		t.Fatalf("wrong token accepted: %s", out)
	}
	if !strings.Contains(get(t, s, "/api/sitemap").Body.String(), `"segment":"h.test"`) {
		t.Fatal("a refused review still deleted the host")
	}
}

func TestUI2SitemapPassiveSweepThroughReview(t *testing.T) {
	s := newTestServer()
	s = s.WithPassiveScanner(scanner.NewPassiveScanner(s.store, zap.NewNop())).WithFindings(core.NewFindingStore())
	recordCompleteExchange(t, s, "h.test", "/app.js")
	recordCompleteExchange(t, s, "h.test", "/page")
	run, sheet := smReview(t, s, sitemapHostKey("h.test"), "passive", url.Values{"extensions": {"js"}})
	if !strings.Contains(sheet, "POST /api/scanner/passive-branch") || !strings.Contains(sheet, `not (extension = \&#34;js\&#34;)`) {
		t.Fatalf("passive review omits the exact filter: %s", sheet)
	}
	if out := smPost(s, "/ui2/sitemap/review/run", run); !strings.Contains(out, "&#34;filtered&#34;: 1") {
		t.Fatalf("passive sweep did not apply the reviewed filter: %s", out)
	}
}

func TestUI2SitemapReviewConfirmRefusesStrayFields(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	key := sitemapHostKey("h.test")
	// A crawl takes no form fields: the seed comes from the live node, never from the client.
	out := smPost(s, "/ui2/sitemap/review/confirm?"+url.Values{"key": {key}, "op": {"crawl"}}.Encode(), url.Values{"seeds": {"http://evil.test/"}})
	if !strings.Contains(out, "Not applied:") || strings.Contains(out, "review_id") {
		t.Fatalf("stray field accepted: %s", out)
	}
	// delete-branch does not apply to a host row.
	if out := smPost(s, "/ui2/sitemap/review/confirm?"+url.Values{"key": {key}, "op": {"delete-branch"}}.Encode(), nil); !strings.Contains(out, "does not apply") {
		t.Fatalf("delete-branch on a host row was not refused: %s", out)
	}
	// The crawl review shows the full body it would launch.
	_, sheet := smReview(t, s, key, "crawl", url.Values{})
	if !strings.Contains(sheet, "POST /api/crawl") || !strings.Contains(sheet, "http://h.test:80/") || !strings.Contains(sheet, "retention_query") {
		t.Fatalf("crawl review omits the body: %s", sheet)
	}
}

// ---- engagement, analyzer, crawl paths --------------------------------------------------------

func TestUI2SitemapEngagementAndExport(t *testing.T) {
	s := newTestServer()
	smRecordBody(t, s, "h.test", "/c", "<html><!-- secret note --></html>")
	page := smGet(t, s, "/ui2/sitemap?view=engagement&kind=comments").Body.String()
	if !strings.Contains(page, "secret note") || !strings.Contains(page, "/ui2/sitemap/export?kind=comments") {
		t.Fatalf("find comments: %s", page)
	}
	csvRec := smGet(t, s, "/ui2/sitemap/export?kind=comments")
	if !strings.Contains(csvRec.Header().Get("Content-Type"), "text/csv") || !strings.Contains(csvRec.Body.String(), "secret note") {
		t.Fatalf("export: %q %s", csvRec.Header().Get("Content-Type"), csvRec.Body.String())
	}
	if w := smGet(t, s, "/ui2/sitemap/export?kind=bogus"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind export = %d, want 400", w.Code)
	}
}

func TestUI2SitemapAnalyzerAndPaths(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/search?q=1")
	an := smGet(t, s, "/ui2/sitemap?view=analyzer&host=h.test").Body.String()
	if !strings.Contains(an, "Dynamic URLs (1)") || !strings.Contains(an, "format=html") {
		t.Fatalf("analyzer: %s", an)
	}
	if paths := smGet(t, s, "/ui2/sitemap?view=paths").Body.String(); !strings.Contains(paths, "No crawl has run") {
		t.Fatalf("paths: %s", paths)
	}
}

func TestUI2SitemapPrescanExclude(t *testing.T) {
	if got := ui2SitemapPrescanExclude([]string{"js", "png"}, true); got != `not (params = 0 and (extension = "js" or extension = "png"))` {
		t.Fatalf("exclude = %s", got)
	}
	if got := ui2SitemapPrescanExclude(ui2SitemapParseExtensions(" .JS, bad/ext ,css"), false); got != `not (extension = "js" or extension = "css")` {
		t.Fatalf("exclude = %s", got)
	}
}
