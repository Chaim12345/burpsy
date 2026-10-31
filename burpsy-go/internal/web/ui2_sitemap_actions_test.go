package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- helpers -----------------------------------------------------------------------------------

// sitemapScopePost posts f to /ui2/sitemap/scope/<action><rawQuery> through the real mux, the
// way the row's htmx form does.
func sitemapScopePost(s *Server, action, rawQuery string, f url.Values) string {
	r := httptest.NewRequest("POST", "/ui2/sitemap/scope/"+action+rawQuery, strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w.Body.String()
}

// sitemapConfirmReview drives the confirm step and lifts the run form's hidden fields out of
// the review sheet, failing if the sheet is a refusal instead.
func sitemapConfirmReview(t *testing.T, s *Server, key string) (url.Values, string) {
	t.Helper()
	out := sitemapScopePost(s, "confirm", "?key="+url.QueryEscape(key), url.Values{})
	if strings.Contains(out, "Not applied:") {
		t.Fatalf("confirm refused: %s", out)
	}
	run := url.Values{}
	for _, k := range []string{"token", "pattern", "port", "protocol", "path"} {
		m := regexp.MustCompile(`name="` + k + `" value="([^"]*)"`).FindStringSubmatch(out)
		if len(m) != 2 {
			t.Fatalf("sheet missing hidden %s: %s", k, out)
		}
		run.Set(k, m[1])
	}
	return run, out
}

// sitemapHostKey / sitemapPathKey build the node keys the recorded test traffic produces
// (recordCompleteExchange stores port 80, plain http).
func sitemapHostKey(host string) string       { return nodeKey(host, 80, false, "") }
func sitemapPathKey(host, path string) string { return nodeKey(host, 80, false, path) }
func sitemapPage(t *testing.T, s *Server) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/sitemap", nil))
	return w.Body.String()
}

// ---- Add to scope --------------------------------------------------------------------------------

// The page carries a per-row review action, and the review/run cycle lands exactly the rule the
// sheet showed: host, port, scheme, and - for a path row - the path prefix.
func TestUI2SitemapAddToScopeHostRow(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")

	run, sheet := sitemapConfirmReview(t, s, sitemapHostKey("h.test"))
	for _, want := range []string{"h.test", "80", "http", "any path on this host", "POST /api/scope", "one-time"} {
		if !strings.Contains(sheet, want) {
			t.Fatalf("review sheet omits %q: %s", want, sheet)
		}
	}
	out := sitemapScopePost(s, "run", "", run)
	if !strings.Contains(out, "Scope rule added: host h.test, port 80, http only") {
		t.Fatalf("run outcome missing: %s", out)
	}
	if !s.scope.Contains("h.test", 80, "/login", false) {
		t.Fatal("reviewed rule did not land")
	}
	if s.scope.Contains("other.test", 80, "/", false) {
		t.Fatal("the include rule over-matched: unrelated hosts must stay out of scope")
	}
	if s.scope.Contains("h.test", 443, "/login", true) {
		t.Fatal("the reviewed rule was http:80 only; it must not authorise the https:443 sibling")
	}
}

func TestUI2SitemapAddToScopePathRowCarriesPrefix(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/api/users")
	recordCompleteExchange(t, s, "h.test", "/other")

	run, sheet := sitemapConfirmReview(t, s, sitemapPathKey("h.test", "/api"))
	if !strings.Contains(sheet, "/api") {
		t.Fatalf("review sheet omits the path prefix: %s", sheet)
	}
	if out := sitemapScopePost(s, "run", "", run); !strings.Contains(out, "path prefix /api") {
		t.Fatalf("run outcome omits the path prefix: %s", out)
	}
	if !s.scope.Contains("h.test", 80, "/api/users", false) {
		t.Fatal("path-prefix rule does not cover its own branch")
	}
	if s.scope.Contains("h.test", 80, "/other", false) {
		t.Fatal("path-prefix rule leaked onto a sibling branch")
	}
}

// ---- guards: tamper, replay, drift, unknown row --------------------------------------------------

// A hidden field edited after the review must burn the token and change nothing.
func TestUI2SitemapScopeRunRefusesTamperedField(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	run, _ := sitemapConfirmReview(t, s, sitemapHostKey("h.test"))
	run.Set("pattern", "evil.test")
	out := sitemapScopePost(s, "run", "", run)
	if strings.Contains(out, "Scope rule added") || !strings.Contains(out, "Not applied:") {
		t.Fatalf("tampered field accepted: %s", out)
	}
	// With zero rules the scope is allow-all, so Contains cannot witness a change; the rule
	// list can: a refused call must leave it empty.
	if len(s.scope.Rules()) != 0 {
		t.Fatal("a refused call still changed the scope")
	}
}

// The confirmation is one-time: a replay of the same run form is refused and adds nothing.
func TestUI2SitemapScopeRunRefusesReplay(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	run, _ := sitemapConfirmReview(t, s, sitemapHostKey("h.test"))
	if out := sitemapScopePost(s, "run", "", run); !strings.Contains(out, "Scope rule added") {
		t.Fatalf("first run failed: %s", out)
	}
	out := sitemapScopePost(s, "run", "", run)
	if strings.Contains(out, "Scope rule added") || !strings.Contains(out, "Not applied:") {
		t.Fatalf("replay accepted: %s", out)
	}
}

// The run step answers to the sheet's fields alone: a query string or an extra field is a
// refusal, never a smuggled parameter.
func TestUI2SitemapScopeRunFieldContract(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	run, _ := sitemapConfirmReview(t, s, sitemapHostKey("h.test"))
	f := copyValues(run)
	f.Set("extra", "x")
	if out := sitemapScopePost(s, "run", "", f); !strings.Contains(out, "Not applied:") {
		t.Fatalf("extra field accepted: %s", out)
	}
	f = copyValues(run)
	f.Del("port")
	if out := sitemapScopePost(s, "run", "", f); !strings.Contains(out, "Not applied:") {
		t.Fatalf("missing field accepted: %s", out)
	}
	if out := sitemapScopePost(s, "run", "?key=smuggled", copyValues(run)); !strings.Contains(out, "Not applied:") {
		t.Fatalf("query field accepted: %s", out)
	}
	if len(s.scope.Rules()) != 0 {
		t.Fatal("a refused call still changed the scope")
	}
}

// A row that vanished between page load and click is a named refusal, and nothing is minted.
func TestUI2SitemapScopeConfirmUnknownRowRefused(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	out := sitemapScopePost(s, "confirm", "?key="+url.QueryEscape(sitemapHostKey("gone.test")), url.Values{})
	if !strings.Contains(out, "row is gone") || strings.Contains(out, `name="token"`) {
		t.Fatalf("unknown row not refused cleanly: %s", out)
	}
}

// The confirm step takes no form fields at all: only the row key crosses, in the query.
func TestUI2SitemapScopeConfirmFieldContract(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	key := sitemapHostKey("h.test")
	f := url.Values{"pattern": {"forged.test"}}
	out := sitemapScopePost(s, "confirm", "?key="+url.QueryEscape(key), f)
	if !strings.Contains(out, "no form fields") {
		t.Fatalf("forged form field accepted at confirm: %s", out)
	}
	if len(s.scope.Rules()) != 0 {
		t.Fatal("confirm mutated scope")
	}
	out = sitemapScopePost(s, "confirm", "?key="+url.QueryEscape(key)+"&other=1", url.Values{})
	if !strings.Contains(out, "exactly one site-map row key") {
		t.Fatalf("extra query field accepted: %s", out)
	}
}

// If the map drifts after the review, the reviewed rule is still exactly what runs - the
// sheet says so, and the token binds it.
func TestUI2SitemapScopeDriftStillRunsReviewedRule(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	run, sheet := sitemapConfirmReview(t, s, sitemapHostKey("h.test"))
	if !strings.Contains(sheet, "the reviewed rule is still what runs") {
		t.Fatalf("drift disclosure missing from the sheet: %s", sheet)
	}
	recordCompleteExchange(t, s, "later.test", "/new")
	if out := sitemapScopePost(s, "run", "", run); !strings.Contains(out, "Scope rule added: host h.test") {
		t.Fatalf("drift changed what ran: %s", out)
	}
	rules := s.scope.Rules()
	if len(rules) != 1 || rules[0].Pattern != "h.test" {
		t.Fatalf("the landed rules are not the reviewed one: %+v", rules)
	}
}

// ---- Send to Repeater -----------------------------------------------------------------------------

// The row's link loads the newest stored request under it into the editor, verbatim.
func TestUI2SitemapRepeaterLoadsNewestStoredRequest(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/first")
	recordCompleteExchange(t, s, "h.test", "/first") // same node: second capture is newer
	recordCompleteExchange(t, s, "h.test", "/other")

	// Host row resolves the newest exchange anywhere beneath it.
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/sitemap/repeater?key="+url.QueryEscape(sitemapHostKey("h.test")), nil))
	page := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(page, "GET /other HTTP/1.1") {
		t.Fatalf("newest request not drafted: code %d", w.Code)
	}
	for _, want := range []string{"stored exchange #2", "not a byte-exact replay", `hx-post="/ui2/repeater/send"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("repeater page omits %q", want)
		}
	}

	// A path row scopes the draft to its own node, not the host's newest.
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/sitemap/repeater?key="+url.QueryEscape(sitemapPathKey("h.test", "/first")), nil))
	if page := w.Body.String(); !strings.Contains(page, "GET /first HTTP/1.1") || !strings.Contains(page, "stored exchange #1") {
		t.Fatalf("path-row draft is not the node's own newest: %s", page)
	}
}

// The rendered row link round-trips: the exact href the page emits (NUL key included) is the
// URL the handler resolves - this is what keeps the encoding honest.
func TestUI2SitemapRepeaterLinkRoundTrips(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")
	page := sitemapPage(t, s)
	if !strings.Contains(page, "Add to scope") || !strings.Contains(page, "Send to Repeater") {
		t.Fatalf("row actions missing from the page: %s", page)
	}
	m := regexp.MustCompile(`href="(/ui2/sitemap/repeater\?key=[^"]*%00[^"]*)"`).FindStringSubmatch(page)
	if len(m) != 2 {
		t.Fatalf("no percent-encoded path-row repeater link rendered: %s", page)
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", m[1], nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "GET /login HTTP/1.1") {
		t.Fatalf("emitted link does not resolve: code %d", w.Code)
	}
	// And the confirm form's action carries the same key through a non-URL attribute.
	if !strings.Contains(page, `hx-post="/ui2/sitemap/scope/confirm?key=http%3A%2F%2Fh.test%3A80%00%2Flogin"`) {
		t.Fatalf("confirm form key not urlquery-encoded: %s", page)
	}
}

// A row with nothing captured under it gets the disabled treatment on the page and a named
// refusal from the handler - never an empty editor.
func TestUI2SitemapRepeaterRefusals(t *testing.T) {
	s := newTestServer()
	recordCompleteExchange(t, s, "h.test", "/login")

	// Unknown key.
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/sitemap/repeater?key="+url.QueryEscape(sitemapHostKey("gone.test")), nil))
	if !strings.Contains(w.Body.String(), "row is gone") {
		t.Fatalf("unknown key not refused: %s", w.Body.String())
	}

	// Request-less tunnel: the node exists with an exchange, but there is no request to load.
	respID, err := s.store.Put([]byte("HTTP/1.1 200 Connection established\r\n\r\n"), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	s.store.AddExchange(&core.Exchange{Response: &respID, Host: "tunnel.test", Port: 443, TLS: true, Method: "CONNECT", Path: "/", Source: core.SourceProxy})
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/sitemap/repeater?key="+url.QueryEscape(nodeKey("tunnel.test", 443, true, "")), nil))
	if page := w.Body.String(); !strings.Contains(page, "no stored request") {
		t.Fatalf("request-less exchange not refused: %s", page)
	}

	// Bytes a textarea cannot carry unchanged: named refusal, nothing loaded.
	badID, err := s.store.Put([]byte("GET /bin HTTP/1.1\r\nHost: bin.test\r\n\r\n\xff\xfe"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	s.store.AddExchange(&core.Exchange{Request: &badID, Host: "bin.test", Port: 80, Method: "GET", Path: "/bin", Source: core.SourceProxy})
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui2/sitemap/repeater?key="+url.QueryEscape(sitemapHostKey("bin.test")), nil))
	page := w.Body.String()
	if !strings.Contains(page, "invalid UTF-8") || strings.Contains(page, "<textarea") {
		t.Fatalf("unsafe bytes reached the editor or refusal unnamed: %s", page)
	}
}

// The page marks rows with nothing under them instead of offering a dead link.
func TestUI2SitemapPageMarksEmptyRows(t *testing.T) {
	s := newTestServer()
	// An inserted-only node has a row with no captures.
	rec := postJSON(t, s, "/api/sitemap", map[string]any{"host": "empty.test", "port": 80, "path": "/hint"})
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated && rec.Code != http.StatusAccepted {
		t.Fatalf("insert failed: %d %s", rec.Code, rec.Body.String())
	}
	page := sitemapPage(t, s)
	if !strings.Contains(page, "no request") {
		t.Fatalf("empty row not marked: %s", page)
	}
}

func copyValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
