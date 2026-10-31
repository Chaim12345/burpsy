package web

import (
	"encoding/json"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ui2Pages is every migrated /ui2/ page route. Each must answer 200 with the shell on a
// plain GET and with a fragment on an HX-Request, and must never 500 on the bench-like
// empty state these tests use.
var ui2Pages = []struct {
	path   string
	view   string
	marker string
}{
	{"/ui2/dashboard", "dashboard", "Coverage"},
	{"/ui2/scope", "scope", "scope rules"},
	{"/ui2/intercept", "intercept", "interception"},
	{"/ui2/logger", "logger", "Logger is empty"},
	{"/ui2/ws", "ws", "No WebSocket connections"},
	{"/ui2/proxy", "proxy", "Listeners"},
	{"/ui2/extensions", "extensions", "JSON-RPC API"},
	{"/ui2/scanner", "scanner", "Scan configurations"},
	{"/ui2/advisories", "advisories", "definitions ·"},
	{"/ui2/organizer", "organizer", "Organizer is empty"},
	{"/ui2/session", "session", "Session handling rules"},
	{"/ui2/sitemap", "sitemap", "exchanges ·"},
	{"/ui2/comparer", "comparer", "Compare"},
	{"/ui2/repeater", "repeater", "Request to send"},
	{"/ui2/settings", "settings", "Project"},
	{"/ui2/intruder", "intruder", "New attack"},
	{"/ui2/sequencer", "sequencer", "Captures"},
	{"/ui2/collaborator", "collaborator", "Channel"},
	{"/ui2/history", "history", "#rows"},
	{"/ui2/issues", "issues", "findings"},
}

func TestUI2EveryPageRendersShellAndFragment(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /p HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	seedUI2Finding(t, s, "Test finding", "high", "p.test", "/p")
	for _, pg := range ui2Pages {
		t.Run(pg.path, func(t *testing.T) {
			rec := getUI2(t, s, pg.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d: %s", pg.path, rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
			}
			body := rec.Body.String()
			if !strings.Contains(body, "<!doctype html") {
				t.Errorf("plain GET did not return the shell")
			}
			if !strings.Contains(body, pg.marker) {
				t.Errorf("shell missing marker %q", pg.marker)
			}
			if !strings.Contains(body, "/ui2/htmx.min.js") || !strings.Contains(body, "/ui2/app.js") {
				t.Errorf("shell missing its script tags")
			}
			// htmx fragment request must not return the whole document.
			req := httptest.NewRequest(http.MethodGet, pg.path, nil)
			req.Header.Set("HX-Request", "true")
			frag := httptest.NewRecorder()
			s.mux.ServeHTTP(frag, req)
			if frag.Code != http.StatusOK {
				t.Fatalf("HX GET %s = %d", pg.path, frag.Code)
			}
			if strings.Contains(frag.Body.String(), "<!doctype html") {
				t.Errorf("HX GET returned the full shell, want the fragment only")
			}
		})
	}
}

func TestUI2NavContainsEveryPage(t *testing.T) {
	s := newTestServer()
	body := getUI2(t, s, "/ui2/dashboard").Body.String()
	for _, pg := range ui2Pages {
		if !strings.Contains(body, `href="`+pg.path+`"`) {
			t.Errorf("nav is missing a link to %s", pg.path)
		}
	}
}

func TestUI2DecoderRunHashesInput(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/ui2/decoder/run", strings.NewReader("op=hash&arg=md5&input=hello"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("decoder run = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	// md5("hello") = 5d41402abc4b2a76b9719d911017c592
	if !strings.Contains(rec.Body.String(), "5d41402abc4b2a76b9719d911017c592") {
		t.Errorf("decoder run did not return the md5 of 'hello': %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
}

func TestUI2ComparerRunDiffs(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/ui2/comparer/run", strings.NewReader("a=aaa&b=aab"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("comparer run = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Diff") {
		t.Errorf("comparer did not render a diff section")
	}
}

func TestUI2InterceptActionUnknown(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/bogus", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /ui2/intercept/bogus = %d, want 400", rec.Code)
	}
}

func TestUI2PagesRejectWrongVerbs(t *testing.T) {
	s := newTestServer()
	for _, path := range []string{"/ui2/dashboard", "/ui2/sitemap", "/ui2/settings"} {
		req := httptest.NewRequest(http.MethodDelete, path, nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE %s = %d, want 405", path, rec.Code)
		}
	}
}

func ui2Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestUI2DecoderRunSendsEncodingField(t *testing.T) {
	s := newTestServer()
	// base64 of "hello" decodes to "hello"; with the wrong field name the API's guesser
	// path would run instead — this pins that "encoding" is what gets posted (issue #375).
	req := httptest.NewRequest(http.MethodPost, "/ui2/decoder/run", strings.NewReader("op=decode&arg=base64&input=aGVsbG8="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("decoder run = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "map[error:") {
		t.Errorf("error rendered as raw Go map (issue #372): %s", body[:ui2Min(200, len(body))])
	}
	if !strings.Contains(body, "hello") {
		t.Errorf("decode base64 of aGVsbG8= did not yield 'hello': %s", body[:ui2Min(300, len(body))])
	}
}

func TestUI2RepeaterSendDerivesTargetFromHostHeader(t *testing.T) {
	s := newTestServer()
	raw := "GET /x HTTP/1.1\r\nHost: derived.test:8080\r\n\r\n"
	// No target field: the handler must derive derived.test:8080 from the Host header.
	// The send will fail to dial, but the error must not be "empty target" and must be
	// plain text, not map[error:...] (issues #370 and #372).
	req := httptest.NewRequest(http.MethodPost, "/ui2/repeater/send", strings.NewReader("raw="+urlQueryEscape(raw)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("repeater send page = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "map[") {
		t.Errorf("error rendered as raw Go map (issue #372): %s", body[:ui2Min(200, len(body))])
	}
	if strings.Contains(body, "empty target") {
		t.Errorf("target was not derived from the Host header — still 'empty target' (issue #370)")
	}
}

func TestUI2HostFromRequest(t *testing.T) {
	cases := map[string]string{
		"GET /x HTTP/1.1\r\nHost: a.test:8080\r\n\r\n":               "a.test:8080",
		"GET http://b.test:9000/p HTTP/1.1\r\nHost: ignored\r\n\r\n": "b.test:9000",
		"GET / HTTP/1.1\r\n\r\n":                                     "",
	}
	for raw, want := range cases {
		if got := ui2HostFromRequest(raw); got != want {
			t.Errorf("ui2HostFromRequest(%q) = %q, want %q", raw, got, want)
		}
	}
}

func urlQueryEscape(s string) string {
	replacer := strings.NewReplacer("%", "%25", "&", "%26", "=", "%3D", "+", "%2B", "\r", "%0D", "\n", "%0A", " ", "%20")
	return replacer.Replace(s)
}

// TestUI2HostFromRequestLFEndings: an htmx form post delivers the textarea's raw request with
// LF newlines, not the CRLF a request file has. Host derivation must work either way or every
// Repeater send from the browser loses its target.
func TestUI2HostFromRequestLFEndings(t *testing.T) {
	cases := map[string]string{
		"GET /x HTTP/1.1\nHost: lf.test:8080\n\n":             "lf.test:8080",
		"GET http://abs.test:9000/p HTTP/1.1\nHost: nope\n\n": "abs.test:9000",
		"GET / HTTP/1.1\n\n":                                  "",
	}
	for raw, want := range cases {
		if got := ui2HostFromRequest(raw); got != want {
			t.Errorf("ui2HostFromRequest(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestUI2RepeaterSendDerivesTargetFromLFHostHeader posts the request the way the browser's form
// actually sends it — LF newlines — and expects the target derived all the same.
func TestUI2RepeaterSendDerivesTargetFromLFHostHeader(t *testing.T) {
	s := newTestServer()
	raw := "GET /x HTTP/1.1\nHost: lf-derived.test:8080\n\n"
	req := httptest.NewRequest(http.MethodPost, "/ui2/repeater/send", strings.NewReader("raw="+urlQueryEscape(raw)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("repeater send page = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "empty target") {
		t.Errorf("target was not derived from the LF-delimited Host header — still 'empty target'")
	}
}

// TestUI2DashboardRendersSummariesAndTasks exercises the dashboard template against the real
// response model with data in it: the coverage rows must show their breakdown reasons and the
// task table its state (the template once referenced fields the structs never had, and the rows
// rendered silently empty).
func TestUI2DashboardRendersSummariesAndTasks(t *testing.T) {
	s := newTestServer()
	running := s.Tasks().Start(dash.KindCrawl, "https://shop.test/", 10)
	running.Advance(4)

	body := getUI2(t, s, "/ui2/dashboard").Body.String()
	if !strings.Contains(body, "shop.test/") {
		t.Errorf("task target not rendered: %s", body[:ui2Min(400, len(body))])
	}
	if !strings.Contains(body, "running") {
		t.Errorf("task state not rendered: %s", body[:ui2Min(400, len(body))])
	}
	// The summaries always carry at least the Tasks row; its reason detail must be visible.
	if !strings.Contains(body, "<td class=\"meta\">") {
		t.Errorf("no breakdown/reason cell rendered: %s", body[:ui2Min(400, len(body))])
	}
}

// TestUI2ProxyRendersMatchReplaceRules: the rules table must read the wire shape
// {config:{rules:[...]}} with rule_type/string_match/string_replace — the template once looked
// for fields the API never sends and the table rendered silently empty.
func TestUI2ProxyRendersMatchReplaceRules(t *testing.T) {
	s := newTestServer()
	s.matchReplace.AddRule(&matchreplace.Rule{
		Enabled: true, Target: matchreplace.TargetRequestHeader, Category: matchreplace.CategoryLiteral,
		StringMatch: "secret-cookie-marker", StringReplace: "redacted-marker",
	})
	body := getUI2(t, s, "/ui2/proxy").Body.String()
	for _, want := range []string{"secret-cookie-marker", "redacted-marker", "request_header"} {
		if !strings.Contains(body, want) {
			t.Errorf("rules table does not render %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
}

// TestUI2DetailViewsUseTheSplitLayout: the shell must give the views that render into #detail
// the split class — without it #detail stays display:none and the issue/intruder detail the
// operator clicked is invisible.
func TestUI2DetailViewsUseTheSplitLayout(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"/ui2/history", "/ui2/issues", "/ui2/intruder"} {
		body := getUI2(t, s, p).Body.String()
		if !strings.Contains(body, `<main class="split">`) {
			t.Errorf("%s did not render the split layout (detail pane hidden)", p)
		}
	}
}

// TestUI2RepeaterSendRendersStructuredResult: a successful send renders the response
// bytes, the duration badge and a link to the stored exchange — never a raw Go map
// dump of the API JSON (the success-path sibling of the issue-#372 error-path fix).
func TestUI2RepeaterSendRendersStructuredResult(t *testing.T) {
	s := newTestServer()
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("victim-ok"))
	}))
	t.Cleanup(victim.Close)
	target := strings.TrimPrefix(victim.URL, "http://")
	raw := "GET /feedback HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	req := httptest.NewRequest(http.MethodPost, "/ui2/repeater/send",
		strings.NewReader("target="+urlQueryEscape(target)+"&raw="+urlQueryEscape(raw)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("repeater send page = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "map[") {
		t.Errorf("success rendered as raw Go map: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, "victim-ok") {
		t.Errorf("response bytes missing from the pane")
	}
	if !strings.Contains(body, "/ui2/history/") || !strings.Contains(body, "stored exchange #") {
		t.Errorf("no link to the stored exchange: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, "ms</span>") {
		t.Errorf("duration badge missing")
	}
}

// TestUI2DecoderAndComparerRenderStructuredResults: tools results render as display
// text — decoded output, readable line diff — never a Go map dump of the API JSON.
func TestUI2DecoderAndComparerRenderStructuredResults(t *testing.T) {
	s := newTestServer()
	post := func(path, body string) string {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, rec.Code)
		}
		return rec.Body.String()
	}
	dec := post("/ui2/decoder/run", "op=decode&arg=base64&input=aGVsbG8gd29ybGQ=")
	if strings.Contains(dec, "map[") || !strings.Contains(dec, "hello world") {
		t.Errorf("decoder result not structured: %s", dec[:ui2Min(300, len(dec))])
	}
	cmp := post("/ui2/comparer/run", "a="+urlQueryEscape("line one\nline two")+"&b="+urlQueryEscape("line one\nline 2"))
	if strings.Contains(cmp, "map[") {
		t.Errorf("comparer result is a Go map dump: %s", cmp[:ui2Min(300, len(cmp))])
	}
	// Byte-granularity diff: the shared prefix "line " stays context; the differing
	// tails render as -/+ lines.
	if !strings.Contains(cmp, "- two") || !strings.Contains(cmp, "&#43; 2") || !strings.Contains(cmp, "  line one") {
		t.Errorf("comparer diff not rendered as readable lines: %s", cmp[:ui2Min(400, len(cmp))])
	}

	// Multibyte safety through the actual handler (reviewer cases): output must be
	// valid UTF-8 with no replacement characters when the input was valid.
	for name, bodies := range map[string][2]string{
		"greek":  {"αβγ", "αβδ"},
		"hebrew": {"שלום", "שלונ"},
		"emoji":  {"a😀b", "a😃b"},
	} {
		body := post("/ui2/comparer/run", "a="+urlQueryEscape(bodies[0])+"&b="+urlQueryEscape(bodies[1]))
		if !utf8.ValidString(body) || strings.Contains(body, "�") {
			t.Errorf("%s diff renders invalid UTF-8: %s", name, body[:ui2Min(300, len(body))])
		}
	}
	// Identical buffers.
	same := post("/ui2/comparer/run", "a="+urlQueryEscape("same")+"&b="+urlQueryEscape("same"))
	if !strings.Contains(same, "buffers are identical") {
		t.Errorf("identical buffers not reported: %s", same[:ui2Min(200, len(same))])
	}
	// Hostile input: invalid UTF-8 bytes must be repaired with an explicit
	// disclosure, never silently diffed in a mismatched byte space.
	hostile := post("/ui2/comparer/run", "a="+urlQueryEscape("ok\xffbad")+"&b="+urlQueryEscape("okgood"))
	if !strings.Contains(hostile, "invalid UTF-8") {
		t.Errorf("invalid-UTF-8 repair not disclosed: %s", hostile[:ui2Min(400, len(hostile))])
	}
	// Engine limit: two large dissimilar buffers force a coarse truncated
	// alignment, and the page must say so.
	big := make([]byte, 0, 20000)
	for i := 0; i < 2000; i++ {
		big = append(big, byte('a'+i%26))
	}
	bigA, bigB := string(big), strings.Repeat("z", 20000)
	tr := post("/ui2/comparer/run", "a="+urlQueryEscape(bigA)+"&b="+urlQueryEscape(bigB))
	if strings.Contains(tr, "map[") {
		t.Errorf("truncated compare is a Go map dump")
	}
	if !strings.Contains(tr, "truncated") {
		t.Errorf("truncated alignment not disclosed: %s", tr[:ui2Min(300, len(tr))])
	}

	// Segments must reconstruct both sides exactly and never split a rune.
	segsOf := func(t *testing.T, a, b string) []ui2DiffSeg {
		t.Helper()
		diff := diffBytes([]byte(a), []byte(b))
		raw, err := json.Marshal(diff.Ops)
		if err != nil {
			t.Fatal(err)
		}
		var ops []any
		if err := json.Unmarshal(raw, &ops); err != nil {
			t.Fatal(err)
		}
		segs, corruptRepaired := ui2CompareSegs(a, b, ops)
		if corruptRepaired {
			t.Fatalf("corrupt-segment repair flagged for well-formed engine ops (a=%q b=%q)", a, b)
		}
		var sa, sb strings.Builder
		for _, s := range segs {
			if !utf8.ValidString(s.text) {
				t.Fatalf("segment splits a rune: %q (a=%q b=%q)", s.text, a, b)
			}
			switch s.prefix {
			case "  ":
				sa.WriteString(s.text)
				sb.WriteString(s.text)
			case "- ":
				sa.WriteString(s.text)
			case "+ ":
				sb.WriteString(s.text)
			}
		}
		if sa.String() != a {
			t.Fatalf("side A does not reconstruct: got %q want %q", sa.String(), a)
		}
		if sb.String() != b {
			t.Fatalf("side B does not reconstruct: got %q want %q", sb.String(), b)
		}
		return segs
	}
	countRune := func(segs []ui2DiffSeg, r string) int {
		n := 0
		for _, s := range segs {
			n += strings.Count(s.text, r)
		}
		return n
	}
	// Reviewer repros: adjacent ops must not duplicate a character.
	rep1 := segsOf(t, "c😀c", "acן")
	if n := countRune(rep1, "😀"); n != 1 {
		t.Errorf("deleted emoji rendered %d times, want 1: %v", n, rep1)
	}
	rep2 := segsOf(t, "ןbc", "c😃b")
	if n := countRune(rep2, "😃"); n != 1 {
		t.Errorf("inserted emoji rendered %d times, want 1: %v", n, rep2)
	}
	// Adjacent replace/delete/insert chains.
	segsOf(t, "a😀b😃c", "a😃b😀c")
	segsOf(t, "xκόσμεy", "κοσμεx")
	segsOf(t, "😀😃😀", "😃😀😃")
	// Deterministic multibyte fuzz through the real engine: reconstruction
	// invariants on every pair (the reviewer's 400-pair class).
	pool := []string{"a", "b", "c", "\n", "ש", "ל", "ו", "ם", "נ", "α", "β", "γ", "δ", "ό", "😀", "😃", "🙂", "é", "€", "𝕏"}
	rng := rand.New(rand.NewSource(20261031))
	for i := 0; i < 400; i++ {
		mk := func() string {
			var sb strings.Builder
			for j := 0; j < 1+rng.Intn(8); j++ {
				sb.WriteString(pool[rng.Intn(len(pool))])
			}
			return sb.String()
		}
		segsOf(t, mk(), mk())
	}
	// Direct renderer checks: grouping keeps whole runes and tight context.
	mkOps := func(ops ...any) []any { return ops }
	op := func(kind string, ao, al, bo, bl int) map[string]any {
		return map[string]any{"kind": kind, "a_offset": float64(ao), "a_len": float64(al), "b_offset": float64(bo), "b_len": float64(bl)}
	}
	gr := ui2RenderCompare("κόσμε", "κοσμε", map[string]any{"ops": mkOps(op("equal", 0, 2, 0, 2), op("replace", 2, 2, 2, 2), op("equal", 4, 6, 4, 6))}, false)
	if !utf8.ValidString(gr) || !strings.Contains(gr, "- ό") || !strings.Contains(gr, "+ ο") || !strings.Contains(gr, "  σμε") {
		t.Errorf("greek diff broken: %q", gr)
	}
	em := ui2RenderCompare("a🙂b", "a😀b", map[string]any{"ops": mkOps(op("equal", 0, 1, 0, 1), op("equal", 1, 2, 1, 2), op("replace", 3, 2, 3, 2), op("equal", 5, 1, 5, 1))}, false)
	if !utf8.ValidString(em) || !strings.Contains(em, "- 🙂") || !strings.Contains(em, "+ 😀") {
		t.Errorf("emoji diff broken: %q", em)
	}

}

// TestUI2AdvisoryDetailRendersHTMLFragmentNotRawJSON covers the Definitions detail pane:
// a row click must render a readable fragment (name, severity, paragraphs), not the raw
// JSON payload the row used to htmx-inject into #detail.
func TestUI2AdvisoryDetailRendersHTMLFragmentNotRawJSON(t *testing.T) {
	s := newTestServer()

	// Discover a real definition from the API instead of hardcoding a catalogue index.
	rec := get(t, s, "/api/advisories")
	var cat struct {
		Advisories []struct {
			TypeIndex string `json:"type_index"`
			Name      string `json:"name"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cat); err != nil {
		t.Fatalf("catalogue decode: %v", err)
	}
	if len(cat.Advisories) == 0 {
		t.Fatal("embedded catalogue is empty")
	}
	first := cat.Advisories[0]

	frag := get(t, s, "/ui2/advisories/"+first.TypeIndex)
	if frag.Code != http.StatusOK {
		t.Fatalf("fragment status = %d, body %q", frag.Code, frag.Body.String())
	}
	if ct := frag.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("fragment content type = %q", ct)
	}
	body := frag.Body.String()
	if !strings.Contains(body, "<h3>"+first.Name) {
		t.Fatalf("fragment lacks the definition name as a heading: %q", body[:min(len(body), 300)])
	}
	if strings.Contains(body, `"type_index"`) || strings.Contains(body, `"name":`) {
		t.Fatalf("fragment still shows raw JSON: %q", body[:min(len(body), 300)])
	}

	// The catalogue's own markup must never reach the pane as text or as HTML: paragraphs
	// come from PlainParagraphs, so no raw catalogue tags survive in either direction.
	apiRec := get(t, s, "/api/advisories/"+first.TypeIndex)
	var apiView struct {
		Description           string   `json:"description"`
		DescriptionParagraphs []string `json:"description_paragraphs"`
	}
	if err := json.Unmarshal(apiRec.Body.Bytes(), &apiView); err != nil {
		t.Fatalf("detail decode: %v", err)
	}
	if len(apiView.DescriptionParagraphs) > 0 && !strings.Contains(body, apiView.DescriptionParagraphs[0]) {
		t.Fatalf("fragment lacks the first plain description paragraph %q", apiView.DescriptionParagraphs[0])
	}
	if strings.Contains(apiView.Description, "<") && strings.Contains(body, apiView.Description) {
		t.Fatal("fragment contains the raw catalogue markup verbatim")
	}

	// Miss cases: unknown index, non-hex index.
	if r := get(t, s, "/ui2/advisories/ffffffff"); r.Code != http.StatusNotFound {
		t.Fatalf("unknown index status = %d", r.Code)
	}
	if r := get(t, s, "/ui2/advisories/nothex"); r.Code != http.StatusNotFound {
		t.Fatalf("non-hex index status = %d", r.Code)
	}

	// Absent catalogue is a stated server state, not an empty page.
	s.advisories = nil
	if r := get(t, s, "/ui2/advisories/"+first.TypeIndex); r.Code != http.StatusNotFound ||
		!strings.Contains(r.Body.String(), "No issue-definition catalogue is loaded") {
		t.Fatalf("nil catalogue: status %d body %q", r.Code, r.Body.String())
	}
}

// TestUI2AdvisoriesPageRowsTargetTheHTMLFragment pins the list row wiring: rows must
// hx-get the fragment route, not the JSON API with a forced Accept header.
func TestUI2AdvisoriesPageRowsTargetTheHTMLFragment(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/ui2/advisories")
	body := rec.Body.String()
	if strings.Contains(body, `hx-get="/api/advisories/`) {
		t.Fatal("rows still hx-get the JSON API")
	}
	if strings.Contains(body, "hx-headers") {
		t.Fatal("rows still force Accept: application/json")
	}
	if !strings.Contains(body, `hx-get="/ui2/advisories/`) {
		t.Fatal("rows do not hx-get the fragment route")
	}
}

// TestUI2AdvisoriesPageRendersEveryCatalogueRow pins finding: the list template must
// render one row per catalogue entry. It used to read .severity where the wire shape
// carries typical_severity, which errored template execution on the first row and
// silently truncated the page to a single partial row.
func TestUI2AdvisoriesPageRendersEveryCatalogueRow(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/ui2/advisories")
	if rec.Code != http.StatusOK {
		t.Fatalf("page status = %d", rec.Code)
	}
	body := rec.Body.String()
	rows := strings.Count(body, `hx-get="/ui2/advisories/`)
	var cat struct {
		Matched int `json:"matched"`
	}
	if err := json.Unmarshal(get(t, s, "/api/advisories").Body.Bytes(), &cat); err != nil {
		t.Fatalf("catalogue decode: %v", err)
	}
	if rows != cat.Matched {
		t.Fatalf("page renders %d rows, catalogue has %d matched definitions", rows, cat.Matched)
	}
	if strings.Contains(body, "Catalogue not loaded") {
		t.Fatal("page fell back to the empty-catalogue message with a loaded catalogue")
	}
	// The detail pane is display:none unless main carries .split - a Definitions row
	// tap must be visible, so the view must opt into the split layout like Issues.
	if !strings.Contains(body, `<main class="split">`) {
		t.Fatal("advisories view lacks the split layout - row detail would render into a hidden pane")
	}
	// Severity badges must carry real values, not empty cells from a missing field.
	var counts struct {
		SeverityCounts map[string]int `json:"severity_counts"`
	}
	if err := json.Unmarshal(get(t, s, "/api/advisories").Body.Bytes(), &counts); err != nil {
		t.Fatalf("severity decode: %v", err)
	}
	high := strings.Count(body, `sev sev-high">HIGH</td>`)
	if high != counts.SeverityCounts["HIGH"] {
		t.Fatalf("page shows %d HIGH row badges, catalogue has %d", high, counts.SeverityCounts["HIGH"])
	}
}

// TestUI2ComparerIdenticalAfterRepairDiscloses: when invalid UTF-8 repair makes the two
// buffers equal, the rendered result must not say a bare "buffers are identical" - the
// repair disclosure is part of the statement.
func TestUI2ComparerIdenticalAfterRepairDiscloses(t *testing.T) {
	s := newTestServer()
	post := func(body string) string {
		req := httptest.NewRequest(http.MethodPost, "/ui2/comparer/run", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("comparer run = %d", rec.Code)
		}
		return rec.Body.String()
	}
	// a carries a lone 0xFF byte; repair turns it into U+FFFD, matching b exactly.
	body := post("a=%FF&b=" + urlQueryEscape("�"))
	if !strings.Contains(body, "buffers are identical") {
		t.Fatalf("identical result missing: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, "identical only after invalid UTF-8") {
		t.Fatalf("identical-after-repair rendered without the repair disclosure: %s", body[:ui2Min(400, len(body))])
	}
	// A genuinely identical pair must NOT grow the qualifier.
	clean := post("a=same&b=same")
	if !strings.Contains(clean, "buffers are identical") || strings.Contains(clean, "identical only after") {
		t.Fatalf("clean identical pair mislabeled: %s", clean[:ui2Min(300, len(clean))])
	}
}

// TestUI2CompareSegsCorruptOpsRepairAndDisclose: defensive paths for corrupt,
// non-contiguous ops must repair split UTF-8 for display (flagged for disclosure)
// and must emit uncovered tail bytes rather than dropping them.
func TestUI2CompareSegsCorruptOpsRepairAndDisclose(t *testing.T) {
	mkOps := func(list ...map[string]any) []any {
		ops := make([]any, 0, len(list))
		for _, o := range list {
			ops = append(ops, o)
		}
		return ops
	}
	numMap := func(kind string, ao, al, bo, bl int) map[string]any {
		return map[string]any{"kind": kind, "a_offset": float64(ao), "a_len": float64(al), "b_offset": float64(bo), "b_len": float64(bl)}
	}

	// Non-contiguous ops: a gap covers the first half of the emoji (invalid UTF-8),
	// and the second group's own range starts mid-rune.
	a, b := "x😀y", "zy"
	segs, corruptRepaired := ui2CompareSegs(a, b, mkOps(
		numMap("replace", 0, 1, 0, 1),
		numMap("equal", 3, 3, 1, 1),
	))
	if !corruptRepaired {
		t.Fatal("corrupt ops did not flag repair for disclosure")
	}
	for _, s := range segs {
		if !utf8.ValidString(s.text) {
			t.Fatalf("corrupt-ops segment emitted invalid UTF-8: %q", s.text)
		}
	}
	rendered := ui2RenderCompare(a, b, map[string]any{"identical": false, "ops": mkOps(
		numMap("replace", 0, 1, 0, 1),
		numMap("equal", 3, 3, 1, 1),
	)}, false)
	if !strings.Contains(rendered, "corrupt diff ops") {
		t.Fatalf("corrupt-op repair not disclosed in render: %q", rendered)
	}

	// Ops that stop early: the uncovered tail must be emitted, and valid tails
	// must not trip the repair flag.
	segs, corruptRepaired = ui2CompareSegs("hello", "hel", mkOps(numMap("equal", 0, 3, 0, 3)))
	if corruptRepaired {
		t.Fatal("valid tail wrongly flagged as corrupt repair")
	}
	var tail string
	for _, s := range segs {
		tail += s.prefix + s.text + "|"
	}
	if !strings.Contains(tail, "- lo|") {
		t.Fatalf("uncovered tail dropped: %q", tail)
	}
}

// TestUI2ExtensionsAPIRowsRenderMethodNames pins finding: the JSON-RPC API table
// read .method/.description where the wire shape carries name/direction/call/params,
// rendering 21 empty rows. Rows must carry the real method names, never blank cells.
func TestUI2ExtensionsAPIRowsRenderMethodNames(t *testing.T) {
	s := newTestServer()
	var apis struct {
		Methods []struct {
			Name string `json:"name"`
		} `json:"methods"`
	}
	if err := json.Unmarshal(get(t, s, "/api/extensions/apis").Body.Bytes(), &apis); err != nil {
		t.Fatalf("apis decode: %v", err)
	}
	if len(apis.Methods) == 0 {
		t.Fatal("no API methods registered to render")
	}
	body := get(t, s, "/ui2/extensions").Body.String()
	if strings.Contains(body, "<td></td>") {
		t.Fatal("extensions page renders empty method cells")
	}
	for _, m := range apis.Methods {
		if !strings.Contains(body, "<td>"+m.Name+"</td>") {
			t.Fatalf("method %q missing from the rendered API table", m.Name)
		}
	}
	if strings.Contains(body, "No API methods registered") {
		t.Fatal("empty-state message shown despite registered methods")
	}
}

// TestUI2AdvisoryShadowIndexDisclosed pins the collision behavior: Burp's own
// catalogue ships two shadow-index pairs (e.g. Bambda shadowed by BCheck at
// 09000000). The list must mark shadowed rows and the detail fragment must
// disclose the shadow, so a row tap can never present the neighbour's identity
// under the tapped row's name.
func TestUI2AdvisoryShadowIndexDisclosed(t *testing.T) {
	s := newTestServer()
	var cat struct {
		Advisories []struct {
			TypeIndex string `json:"type_index"`
			Name      string `json:"name"`
			Shadowed  bool   `json:"shadowed,omitempty"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(get(t, s, "/api/advisories").Body.Bytes(), &cat); err != nil {
		t.Fatalf("catalogue decode: %v", err)
	}
	shadowed := map[string]string{} // type_index -> name
	owner := map[string]string{}
	for _, a := range cat.Advisories {
		if a.Shadowed {
			shadowed[a.TypeIndex] = a.Name
		} else {
			owner[a.TypeIndex+a.Name] = a.Name
		}
	}
	if len(shadowed) != 2 {
		t.Fatalf("expected the catalogue's two known shadow-index pairs, got %v", shadowed)
	}
	for idx, name := range shadowed {
		// The fragment resolves the index's OWNER and discloses the shadow.
		body := get(t, s, "/ui2/advisories/"+idx).Body.String()
		if !strings.Contains(body, "Shared index:") || !strings.Contains(body, name) {
			t.Fatalf("fragment for %s lacks shadow disclosure naming %q: %q", idx, name, body[:ui2Min(400, len(body))])
		}
		h3 := body[strings.Index(body, "<h3>")+4:]
		h3 = h3[:strings.Index(h3, "</h3>")]
		if strings.Contains(h3, name) {
			t.Fatalf("fragment heading presents shadowed %q as the index identity", name)
		}
		// The list row carries the marker next to the shadowed name.
		page := get(t, s, "/ui2/advisories").Body.String()
		i := strings.Index(page, ">"+name+"<")
		if i < 0 {
			if j := strings.Index(page, name+" <span"); j >= 0 {
				i = j
			} else {
				t.Fatalf("shadowed row %q not found on the list page", name)
			}
		}
		if !strings.Contains(page[i:i+len(name)+220], "shared index") {
			t.Fatalf("shadowed row %q lacks the shared-index marker", name)
		}
	}
}

// TestUI2SequencerAnalyseRendersReadableReport: the pasted-token analysis must render
// grade/verdict/entropy/per-test outcomes as text, never a Go map dump, and must carry
// the partial-analysis disclosures (FIPS untested, per-position not computed, warnings).
func TestUI2SequencerAnalyseRendersReadableReport(t *testing.T) {
	s := newTestServer()
	var toks []string
	for i := 0; i < 40; i++ {
		toks = append(toks, fmt.Sprintf("sess%03d", i))
	}
	body := "tokens=" + urlQueryEscape(strings.Join(toks, "\n")) + "&encoding=raw"
	req := httptest.NewRequest(http.MethodPost, "/ui2/sequencer/analyse", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyse = %d", rec.Code)
	}
	out := rec.Body.String()
	if strings.Contains(out, "map[") {
		t.Fatalf("sequencer report is a Go map dump: %s", out[:ui2Min(300, len(out))])
	}
	for _, want := range []string{"Grade:", "Verdict:", "Extended tests:", "Warnings:", "FIPS 140-2:", "not computed"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q: %s", want, out[:ui2Min(500, len(out))])
		}
	}
}

// A sample too small for the effective-entropy battery must say so in words,
// with the engine's reason — never a printed "<nil>" where the figure would be
// (chosen.bits is null when computed is false; the first renderer printed it).
// The WS page used to read .history.frames and .exchange_id/.url — none of
// which exist on the wire (rows/exchange/host+port+path) — so every connection
// row rendered blank cells and every frame table rendered "No frames" even with
// frames in the store. Real loopback proxying through a live listener caught it.
func TestUI2WSRendersConnectionsAndFrames(t *testing.T) {
	s := newTestServer()
	s.store.AddExchange(&core.Exchange{ID: 0, Host: "127.0.0.1", Port: 18094, Path: "/ws"})
	s.store.AddWsMessage(&core.WsMessage{Exchange: 0, FromClient: true, Opcode: core.WsOpcodeText}, []byte("hello via burpsy relay"))
	rec := get(t, s, "/ui2/ws")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui2/ws = %d", rec.Code)
	}
	out := rec.Body.String()
	for _, want := range []string{"ws://127.0.0.1:18094/ws", "client_to_server"} {
		if !strings.Contains(out, want) {
			t.Errorf("ws page lacks %q", want)
		}
	}
	if strings.Contains(out, "No frames.") {
		t.Fatalf("ws page claims no frames with a frame in the store")
	}
	if strings.Contains(out, "No WebSocket connections relayed.") {
		t.Fatalf("ws page claims no connections with a message in the store")
	}
}

func TestUI2SequencerAnalyseInsufficientSampleNamesTheMiss(t *testing.T) {
	s := newTestServer()
	body := "tokens=" + urlQueryEscape("aaaa\nbbbb") + "&encoding=raw"
	req := httptest.NewRequest(http.MethodPost, "/ui2/sequencer/analyse", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyse = %d", rec.Code)
	}
	out := rec.Body.String()
	if strings.Contains(out, "<nil>") {
		t.Fatalf("report prints <nil> for an uncomputed figure: %s", out[:ui2Min(500, len(out))])
	}
	if !strings.Contains(out, "Effective entropy: not computed on this sample") {
		t.Fatalf("report does not name the uncomputed figure: %s", out[:ui2Min(500, len(out))])
	}
}

// The provenance lines tell the operator what the tokens went through before
// any figure was computed: which encoding was used and whether it was detected,
// and what padding did (or deliberately did not do) to short tokens.
func TestUI2SequencerAnalyseReportCarriesProvenance(t *testing.T) {
	s := newTestServer()
	var toks []string
	for i := 0; i < 40; i++ {
		toks = append(toks, fmt.Sprintf("sess%03d", i))
	}
	toks[3] = "s3" // one short token, so the padding policy is observable
	body := "tokens=" + urlQueryEscape(strings.Join(toks, "\n")) + "&encoding=raw"
	req := httptest.NewRequest(http.MethodPost, "/ui2/sequencer/analyse", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyse = %d", rec.Code)
	}
	out := rec.Body.String()
	for _, want := range []string{"Encoding: raw", "Padding: none"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks provenance %q: %s", want, out[:ui2Min(500, len(out))])
		}
	}
}

// ---- Intercept per-item edit/forward/drop -----------------------------------------------------

// ui2HoldRequest parks one request in the engine's held queue so the per-item ui2 actions have
// something to resolve.
func ui2HoldRequest(t *testing.T, s *Server, raw string) *intercept.Held {
	t.Helper()
	s.intercept.SetEnabled(true)
	if err := s.intercept.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	h := s.intercept.Hold(&intercept.Message{
		Direction: intercept.DirectionRequest,
		Host:      "a.test",
		Port:      80,
		Method:    "POST",
		Path:      "/x",
		Raw:       []byte(raw),
	})
	if h == nil {
		t.Fatalf("unconditional request list did not hold")
	}
	return h
}

// ---- Logger capture controls -------------------------------------------------------------------

// ui2LoggerAction posts one capture action and returns the re-rendered fragment.
func ui2LoggerAction(t *testing.T, s *Server, action, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/logger/"+action, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// The Logger page surfaces the capture axis: every tool's recording state, a toggle per tool, the
// off-capture disclosure, and the not-captured counters.
func TestUI2LoggerPageShowsCaptureAxis(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/ui2/logger", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui2/logger = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"deliberately not recorded", "not-captured counters", "capture-repeater-off", "capture-proxy-off", "capture-scanner-off"} {
		if !strings.Contains(body, want) {
			t.Errorf("logger page lacks %q", want)
		}
	}
}

// Turning a tool off flips its recording through the API and the re-rendered fragment says off;
// turning it back on restores it. Requests recorded while off land in the not-captured counter
// instead of the log.
func TestUI2LoggerCaptureToggleRoundTrip(t *testing.T) {
	s := newTestServer()
	rec := ui2LoggerAction(t, s, "capture-repeater-off", "search=")
	if rec.Code != http.StatusOK {
		t.Fatalf("capture off = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	body := rec.Body.String()
	if !strings.Contains(body, "capture-repeater-on") {
		t.Errorf("fragment after turning off lacks the turn-on button")
	}
	if strings.Contains(body, "capture-repeater-off") {
		t.Errorf("fragment after turning off still offers to turn repeater off")
	}
	// API agrees.
	api := httptest.NewRecorder()
	s.mux.ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/tools/log?limit=1", nil))
	var log struct {
		Capturing  map[string]bool   `json:"capturing"`
		Uncaptured map[string]uint64 `json:"uncaptured"`
	}
	if err := json.Unmarshal(api.Body.Bytes(), &log); err != nil {
		t.Fatalf("api body: %v", err)
	}
	if log.Capturing["repeater"] {
		t.Errorf("api still records repeater after the page turned it off")
	}
	// A request recorded while off is counted as not captured, not logged.
	s.toolLog.Record(toollog.ToolRepeater, "127.0.0.1", 18101, false, http.MethodGet, "/", 200, nil, 1, "", nil)
	api2 := httptest.NewRecorder()
	s.mux.ServeHTTP(api2, httptest.NewRequest(http.MethodGet, "/api/tools/log?limit=1", nil))
	if err := json.Unmarshal(api2.Body.Bytes(), &log); err != nil {
		t.Fatalf("api body 2: %v", err)
	}
	if log.Uncaptured["repeater"] != 1 {
		t.Errorf("uncaptured[repeater] = %d, want 1", log.Uncaptured["repeater"])
	}
	// The page shows the counter.
	page := ui2LoggerAction(t, s, "capture-repeater-on", "search=")
	if page.Code != http.StatusOK {
		t.Fatalf("capture on = %d", page.Code)
	}
	pbody := page.Body.String()
	if !strings.Contains(pbody, "capture-repeater-off") || !strings.Contains(pbody, "1 not captured") {
		t.Errorf("fragment after turning on lacks the restored toggle or the not-captured counter")
	}
	api3 := httptest.NewRecorder()
	s.mux.ServeHTTP(api3, httptest.NewRequest(http.MethodGet, "/api/tools/log?limit=1", nil))
	if err := json.Unmarshal(api3.Body.Bytes(), &log); err != nil {
		t.Fatalf("api body 3: %v", err)
	}
	if !log.Capturing["repeater"] {
		t.Errorf("api still not recording repeater after the page turned it back on")
	}
}

// Unknown actions and unknown tool names are refused with 400, never silently mapped.
func TestUI2LoggerActionRejectsUnknown(t *testing.T) {
	s := newTestServer()
	for _, action := range []string{"bogus", "capture-repeater", "capture-nosuchtool-on", "capture-repeater-sideways"} {
		if rec := ui2LoggerAction(t, s, action, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("action %q = %d, want 400", action, rec.Code)
		}
	}
}

// The page surfaces the capture filter: what the server enforces, the filtered counter, and the
// disclosure that this decides what gets recorded.
func TestUI2LoggerPageShowsCaptureFilter(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/logger", nil))
	body := rec.Body.String()
	for _, want := range []string{"Capture filter", "decides what gets recorded", "no capture filter", `name="status" value="2"`, `name="mime"`, "apply capture filter"} {
		if !strings.Contains(body, want) {
			t.Errorf("logger page lacks %q", want)
		}
	}
}

// Applying a filter from the page sets the server's capture filter; rows it refuses are not
// recorded and the filtered counter advances; rows it keeps land in the table.
func TestUI2LoggerFilterSetRecordsSelectively(t *testing.T) {
	s := newTestServer()
	rec := ui2LoggerAction(t, s, "filter-set", "status=2&term=keepme&search=")
	if rec.Code != http.StatusOK {
		t.Fatalf("filter-set = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	body := rec.Body.String()
	if !strings.Contains(body, "2xx") || !strings.Contains(body, "keepme") {
		t.Errorf("fragment does not echo the filter now in force: %s", body[:ui2Min(300, len(body))])
	}
	// The API agrees the filter is in force.
	api := httptest.NewRecorder()
	s.mux.ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/tools/log?limit=1", nil))
	var log struct {
		Filter struct {
			Status []int  `json:"status"`
			Term   string `json:"term"`
		} `json:"filter"`
		FilteredTotal uint64 `json:"filtered_total"`
	}
	if err := json.Unmarshal(api.Body.Bytes(), &log); err != nil {
		t.Fatalf("api body: %v", err)
	}
	if len(log.Filter.Status) != 1 || log.Filter.Status[0] != 2 || log.Filter.Term != "keepme" {
		t.Errorf("api filter = %+v, want status [2] term keepme", log.Filter)
	}
	// A non-matching row is refused and counted; a matching one is recorded.
	s.toolLog.Record(toollog.ToolRepeater, "127.0.0.1", 18101, false, http.MethodGet, "/other", 200, nil, 1, "", nil)
	s.toolLog.Record(toollog.ToolRepeater, "127.0.0.1", 18101, false, http.MethodGet, "/keepme", 200, nil, 1, "", nil)
	s.toolLog.Record(toollog.ToolRepeater, "127.0.0.1", 18101, false, http.MethodGet, "/keepme-404", 404, nil, 1, "", nil)
	api2 := httptest.NewRecorder()
	s.mux.ServeHTTP(api2, httptest.NewRequest(http.MethodGet, "/api/tools/log?limit=10", nil))
	var log2 struct {
		Entries       []toolLogEntry `json:"entries"`
		FilteredTotal uint64         `json:"filtered_total"`
	}
	if err := json.Unmarshal(api2.Body.Bytes(), &log2); err != nil {
		t.Fatalf("api body 2: %v", err)
	}
	if log2.FilteredTotal != 2 {
		t.Errorf("filtered_total = %d, want 2 (term mismatch + status mismatch)", log2.FilteredTotal)
	}
	if len(log2.Entries) != 1 || log2.Entries[0].Path != "/keepme" {
		t.Errorf("entries = %+v, want only /keepme", log2.Entries)
	}
	// The page carries the counter.
	page := httptest.NewRecorder()
	s.mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/ui2/logger", nil))
	if !strings.Contains(page.Body.String(), "2 filtered so far") {
		t.Errorf("page lacks the filtered counter")
	}
}

// An invalid filter is refused with the API's reason on the page, and the filter in force is
// unchanged.
func TestUI2LoggerFilterInvalidKeepsOldAndSaysWhy(t *testing.T) {
	s := newTestServer()
	if rec := ui2LoggerAction(t, s, "filter-set", "term=ok&search="); rec.Code != http.StatusOK {
		t.Fatalf("seed filter-set = %d", rec.Code)
	}
	rec := ui2LoggerAction(t, s, "filter-set", "term=%5B&regex=on&search=")
	if rec.Code != http.StatusOK {
		t.Fatalf("invalid filter-set = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Filter not applied") {
		t.Errorf("fragment lacks the refusal note: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, "term &#34;ok&#34;") && !strings.Contains(body, `term "ok"`) {
		t.Errorf("the previous filter does not survive the refused one: %s", body[:ui2Min(300, len(body))])
	}
}

// Clearing from the page resets the filter: everything is recorded again.
func TestUI2LoggerFilterClear(t *testing.T) {
	s := newTestServer()
	ui2LoggerAction(t, s, "filter-set", "status=2&search=")
	rec := ui2LoggerAction(t, s, "filter-clear", "search=")
	if rec.Code != http.StatusOK {
		t.Fatalf("filter-clear = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no capture filter") {
		t.Errorf("fragment after clear does not say the filter is gone")
	}
	api := httptest.NewRecorder()
	s.mux.ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/tools/log?limit=1", nil))
	if !strings.Contains(api.Body.String(), `"status":[]`) {
		t.Errorf("api still carries a status filter after clear: %s", api.Body.String()[:ui2Min(400, api.Body.Len())])
	}
}

// A status class outside 2-5 is refused, never silently recorded into the filter.
func TestUI2LoggerFilterRejectsBadStatusClass(t *testing.T) {
	s := newTestServer()
	if rec := ui2LoggerAction(t, s, "filter-set", "status=9"); rec.Code != http.StatusBadRequest {
		t.Errorf("status=9 = %d, want 400", rec.Code)
	}
}

// The search carryover survives a toggle: the re-rendered fragment keeps filtering by it.
func TestUI2LoggerActionKeepsSearch(t *testing.T) {
	s := newTestServer()
	rec := ui2LoggerAction(t, s, "capture-decoder-off", "search=needleterm")
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "needleterm") {
		t.Errorf("re-rendered fragment dropped the search carryover")
	}
}

// ---- Scope editing -----------------------------------------------------------------------------

// ui2ScopeConfirm posts the confirm step and extracts the minted one-time token from the review
// fragment, mirroring the scanner launch helper.
func ui2ScopeConfirm(t *testing.T, s *Server, form string) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/scope/confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	body := rec.Body.String()
	mark := `name="token" value="`
	i := strings.Index(body, mark)
	if i < 0 {
		return "", body
	}
	rest := body[i+len(mark):]
	return rest[:strings.IndexByte(rest, '"')], body
}

// ui2ScopeRun posts the run step with a token and returns the re-rendered fragment.
func ui2ScopeRun(t *testing.T, s *Server, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/scope/run", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// ui2ScopeState reads the API's scope state the way the page does.
func ui2ScopeState(t *testing.T, s *Server) (rules []struct {
	Kind    string  `json:"kind"`
	Host    *string `json:"host"`
	Port    *uint16 `json:"port"`
	Enabled bool    `json:"enabled"`
}, drop bool) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scope", nil))
	var sc struct {
		Rules []struct {
			Kind    string  `json:"kind"`
			Host    *string `json:"host"`
			Port    *uint16 `json:"port"`
			Enabled bool    `json:"enabled"`
		} `json:"rules"`
		DropOutOfScope bool `json:"drop_out_of_scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sc); err != nil {
		t.Fatalf("api scope body: %v", err)
	}
	return sc.Rules, sc.DropOutOfScope
}

// ui2ScopeApply runs the full two-step the page drives: confirm mints, run spends.
func ui2ScopeApply(t *testing.T, s *Server, form string) *httptest.ResponseRecorder {
	t.Helper()
	token, body := ui2ScopeConfirm(t, s, form)
	if token == "" {
		t.Fatalf("confirm minted no token: %s", body[:ui2Min(300, len(body))])
	}
	return ui2ScopeRun(t, s, "token="+url.QueryEscape(token)+"&"+form)
}

// The Scope page carries its editing controls and the persistence/reach disclosure, and every
// control posts to the confirm step first.
func TestUI2ScopePageShowsControls(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/scope", nil))
	body := rec.Body.String()
	for _, want := range []string{"decides where the proxy", "persist", `value="rule-add"`, `value="drop-switch"`, `hx-post="/ui2/scope/confirm"`} {
		if !strings.Contains(body, want) {
			t.Errorf("scope page lacks %q", want)
		}
	}
	// On a phone the table keeps its action buttons reachable: the mobile stylesheet drops the
	// Path/Protocol columns of the scope table and lets the actions cell wrap. The full page
	// carries the chrome's stylesheet, so the rules must be in this response.
	for _, want := range []string{`table class="scope-t"`, "table.scope-t td.sa", "table.scope-t td:nth-child(4)"} {
		if !strings.Contains(body, want) {
			t.Errorf("scope page lacks the mobile-reachability markup %q", want)
		}
	}
}

// The first click mints a one-time confirmation for the exact /api/scope call and renders the
// review step; nothing changes from it.
func TestUI2ScopeConfirmMintsReviewStep(t *testing.T) {
	s := newTestServer()
	token, body := ui2ScopeConfirm(t, s, "scope_action=rule-add&kind=include&pattern=app.test&port=8443")
	if token == "" {
		t.Fatalf("review step carries no token: %s", body[:ui2Min(300, len(body))])
	}
	for _, want := range []string{"Review before applying", "POST /api/scope", "Confirm and apply", "one-time", "persist"} {
		if !strings.Contains(body, want) {
			t.Errorf("review step lacks %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
	if !strings.Contains(body, "app.test") {
		t.Errorf("preview does not show the call body")
	}
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 0 {
		t.Errorf("the confirm click alone changed scope: %+v", rules)
	}
}

// The confirmed run applies the reviewed call: add lands with its port, toggling flips it, the
// drop switch moves both ways, removing deletes, and a second removal carries the API's refusal.
func TestUI2ScopeRuleLifecycle(t *testing.T) {
	s := newTestServer()
	rec := ui2ScopeApply(t, s, "scope_action=rule-add&kind=include&pattern=127.0.0.1&port=18101")
	if rec.Code != http.StatusOK {
		t.Fatalf("rule-add run = %d", rec.Code)
	}
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 1 || rules[0].Kind != "Include" || !rules[0].Enabled || rules[0].Port == nil || *rules[0].Port != 18101 {
		t.Fatalf("api rules = %+v, want one enabled Include on port 18101", rules)
	}
	if !strings.Contains(rec.Body.String(), `td class="sa"`) {
		t.Errorf("the rendered rule row lacks the wrapping actions cell")
	}
	ui2ScopeApply(t, s, "scope_action=rule-toggle&kind=include&pattern=127.0.0.1&port=18101&enabled=false")
	rules, _ = ui2ScopeState(t, s)
	if len(rules) != 1 || rules[0].Enabled {
		t.Errorf("rule still enabled after the page turned it off")
	}
	ui2ScopeApply(t, s, "scope_action=rule-toggle&kind=include&pattern=127.0.0.1&port=18101&enabled=true")
	rules, _ = ui2ScopeState(t, s)
	if len(rules) != 1 || !rules[0].Enabled {
		t.Errorf("rule still disabled after the page turned it on")
	}
	_, drop := ui2ScopeState(t, s)
	if drop {
		t.Fatal("drop_out_of_scope already on")
	}
	ui2ScopeApply(t, s, "scope_action=drop-switch&enabled=true")
	_, drop = ui2ScopeState(t, s)
	if !drop {
		t.Errorf("drop_out_of_scope still false after the page turned it on")
	}
	ui2ScopeApply(t, s, "scope_action=drop-switch&enabled=false")
	_, drop = ui2ScopeState(t, s)
	if drop {
		t.Errorf("drop_out_of_scope still true after the page turned it off")
	}
	ui2ScopeApply(t, s, "scope_action=rule-remove&kind=include&pattern=127.0.0.1&port=18101")
	rules, _ = ui2ScopeState(t, s)
	if len(rules) != 0 {
		t.Fatalf("rules after remove = %+v, want none", rules)
	}
	rec = ui2ScopeApply(t, s, "scope_action=rule-remove&kind=include&pattern=127.0.0.1&port=18101")
	if !strings.Contains(rec.Body.String(), "Not applied") || !strings.Contains(rec.Body.String(), "No matching rule") {
		t.Errorf("second removal lacks the refusal note: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
}

// Two rows that differ only in scheme are distinguishable and individually addressable from the
// page: each row's forms carry its protocol, the review step names it, and the mobile detail
// line shows path and protocol while the columns are hidden on a phone.
func TestUI2ScopeProtocolSiblingsAreAddressable(t *testing.T) {
	s := newTestServer()
	for _, proto := range []string{"http", "https"} {
		if rec := ui2ScopeApply(t, s, "scope_action=rule-add&kind=include&pattern=127.0.0.1&port=18101&protocol="+proto); rec.Code != http.StatusOK {
			t.Fatalf("add %s = %d", proto, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/scope", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `name="protocol" value="https"`) {
		t.Errorf("the https row's forms do not carry its protocol")
	}
	if !strings.Contains(body, `name="protocol" value="http"`) {
		t.Errorf("the http row's forms do not carry its protocol")
	}
	if !strings.Contains(body, `class="meta scope-sd"`) || !strings.Contains(body, "protocol: https") {
		t.Errorf("the mobile detail line with the per-row path/protocol is missing")
	}
	// The review step for the https row's toggle names the protocol in the exact call.
	token, review := ui2ScopeConfirm(t, s, "scope_action=rule-toggle&kind=include&pattern=127.0.0.1&port=18101&protocol=https&enabled=false")
	if token == "" {
		t.Fatalf("no token minted: %s", review[:ui2Min(300, len(review))])
	}
	if !strings.Contains(review, "https") {
		t.Errorf("the review step omits the protocol: %s", review[:ui2Min(400, len(review))])
	}
	// Applying it flips only the https rule.
	ui2ScopeRun(t, s, "token="+url.QueryEscape(token)+"&scope_action=rule-toggle&kind=include&pattern=127.0.0.1&port=18101&protocol=https&enabled=false")
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 2 {
		t.Fatalf("rules = %+v, want the pair", rules)
	}
	// The API read carries protocol per rule; check each sibling's state through a raw decode.
	raw := httptest.NewRecorder()
	s.mux.ServeHTTP(raw, httptest.NewRequest(http.MethodGet, "/api/scope", nil))
	var sc struct {
		Rules []struct {
			Protocol *string `json:"protocol"`
			Enabled  bool    `json:"enabled"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw.Body.Bytes(), &sc); err != nil {
		t.Fatalf("api body: %v", err)
	}
	for _, r := range sc.Rules {
		if r.Protocol != nil && *r.Protocol == "http" && !r.Enabled {
			t.Errorf("the http sibling was disabled by a toggle aimed at the https row")
		}
		if r.Protocol != nil && *r.Protocol == "https" && r.Enabled {
			t.Errorf("the https row did not take the disable")
		}
	}
}

// The gate's refusals surface on the page: a run with no token, a spent token, and a body the
// token was not minted for all fail honestly, and none of them change scope.
func TestUI2ScopeRunRefusals(t *testing.T) {
	s := newTestServer()
	// Missing token.
	rec := ui2ScopeRun(t, s, "scope_action=drop-switch&enabled=true")
	if !strings.Contains(rec.Body.String(), "Not applied") || !strings.Contains(rec.Body.String(), "confirmation required") {
		t.Errorf("tokenless run lacks the refusal note: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	if _, drop := ui2ScopeState(t, s); drop {
		t.Errorf("a tokenless run changed drop_out_of_scope")
	}
	// Spent token: one good apply, then the same token again.
	form := "scope_action=drop-switch&enabled=true"
	token, _ := ui2ScopeConfirm(t, s, form)
	if token == "" {
		t.Fatal("no token minted")
	}
	ui2ScopeRun(t, s, "token="+url.QueryEscape(token)+"&"+form)
	rec = ui2ScopeRun(t, s, "token="+url.QueryEscape(token)+"&"+form)
	if !strings.Contains(rec.Body.String(), "Not applied") {
		t.Errorf("a spent token did not fail the second run: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	// Tampered body: the token was minted for drop on, not for a rule add.
	rec = ui2ScopeRun(t, s, "token="+url.QueryEscape(token)+"&scope_action=rule-add&kind=include&pattern=evil.test")
	if !strings.Contains(rec.Body.String(), "Not applied") {
		t.Errorf("a tampered body did not fail: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 0 {
		t.Errorf("the tampered run changed scope: %+v", rules)
	}
}

// ---- Scope edit-in-place -----------------------------------------------------------------------

// The edit review step mints a one-time confirmation for the exact edit call: old identity and
// new values both visible in the preview.
func TestUI2ScopeEditConfirmMintsReviewStep(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("example.com")
	token, body := ui2ScopeConfirm(t, s, "scope_action=rule-edit&old_kind=include&old_pattern=example.com&kind=include&pattern=example.org&port=8443")
	if token == "" {
		t.Fatalf("review step carries no token: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, "Review before applying") || !strings.Contains(body, "one-time") {
		t.Errorf("review framing missing: %s", body[:ui2Min(300, len(body))])
	}
	for _, want := range []string{"old_pattern", "example.com", "example.org"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview does not show %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
}

// Bad edit input is refused before any token: unknown kind, bad port, empty identity.
func TestUI2ScopeEditConfirmRejectsBadInput(t *testing.T) {
	s := newTestServer()
	for _, form := range []string{
		"scope_action=rule-edit&old_kind=sideways&old_pattern=x&kind=include&pattern=y",
		"scope_action=rule-edit&old_kind=include&old_pattern=x&kind=include&pattern=y&port=99999",
		"scope_action=rule-edit&old_kind=include&kind=include&pattern=y",
	} {
		token, body := ui2ScopeConfirm(t, s, form)
		if token != "" {
			t.Errorf("%s still minted a token", form)
		}
		if !strings.Contains(body, "Not applied") {
			t.Errorf("%s: fragment does not say what is wrong: %s", form, body[:ui2Min(300, len(body))])
		}
	}
}

// The confirmed edit replaces the rule atomically: the new tuple is in force, the old one gone.
func TestUI2ScopeEditRunReplacesRule(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("example.com")
	rec := ui2ScopeApply(t, s, "scope_action=rule-edit&old_kind=include&old_pattern=example.com&kind=exclude&pattern=example.org&port=8443")
	if strings.Contains(rec.Body.String(), "Not applied") {
		t.Fatalf("edit refused: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 1 {
		t.Fatalf("expected exactly one rule after the replacement, got %d", len(rules))
	}
	rule := rules[0]
	if !strings.EqualFold(rule.Kind, "exclude") || rule.Host == nil || *rule.Host != "example.org" || rule.Port == nil || *rule.Port != 8443 {
		t.Errorf("replacement rule wrong: %+v", rule)
	}
}

// An edit aimed at a rule that no longer exists is refused by the API with its reason, and the
// rules in force are the ones the page shows.
func TestUI2ScopeEditRunStaleTupleRefused(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("example.com")
	token, body := ui2ScopeConfirm(t, s, "scope_action=rule-edit&old_kind=include&old_pattern=example.com&kind=include&pattern=example.org")
	if token == "" {
		t.Fatalf("no token minted: %s", body[:ui2Min(200, len(body))])
	}
	s.scope.Remove(core.ScopeInclude, "example.com")
	rec := ui2ScopeRun(t, s, "token="+url.QueryEscape(token)+"&scope_action=rule-edit&old_kind=include&old_pattern=example.com&kind=include&pattern=example.org")
	if !strings.Contains(rec.Body.String(), "No matching rule found") {
		t.Errorf("stale edit does not carry the refusal: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 0 {
		t.Errorf("a refused edit still changed scope: %+v", rules)
	}
}

// The page renders a per-row edit affordance carrying the row's full identity.
func TestUI2ScopePageShowsEditAffordance(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("example.com")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/scope", nil))
	body := rec.Body.String()
	for _, want := range []string{`value="rule-edit"`, `name="old_kind"`, `name="old_pattern" value="example.com"`, "review replacement", `class="scope-edit-close"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

// ---- Crawl launch -----------------------------------------------------------------------------

// ui2CrawlLaunchToken posts the crawl form and extracts the minted one-time token from the
// review fragment.
func ui2CrawlLaunchToken(t *testing.T, s *Server, form string) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/crawl-launch", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("crawl-launch = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	body := rec.Body.String()
	mark := `name="token" value="`
	i := strings.Index(body, mark)
	if i < 0 {
		return "", body
	}
	rest := body[i+len(mark):]
	return rest[:strings.IndexByte(rest, '"')], body
}

// The first click mints a one-time confirmation for the exact crawl call and renders the review
// step; nothing launches from it.
func TestUI2CrawlLaunchMintsReviewStep(t *testing.T) {
	s := newTestServer()
	token, body := ui2CrawlLaunchToken(t, s, "seeds=http%3A%2F%2Ftarget.example%2F&config=")
	if token == "" {
		t.Fatalf("review step carries no token: %s", body[:ui2Min(300, len(body))])
	}
	for _, want := range []string{"Review before crawl", "POST /api/crawl", "Confirm and crawl", "one-time", "scope refuses"} {
		if !strings.Contains(body, want) {
			t.Errorf("review step lacks %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
	if !strings.Contains(body, "seeds") {
		t.Errorf("preview does not show the call body")
	}
}

func TestUI2CrawlLaunchNoSeedSaysSo(t *testing.T) {
	s := newTestServer()
	token, body := ui2CrawlLaunchToken(t, s, "seeds=+&config=")
	if token != "" {
		t.Errorf("a seedless form still minted a token")
	}
	if !strings.Contains(body, "at least one seed URL is required") {
		t.Errorf("fragment does not say what is missing: %s", body[:ui2Min(300, len(body))])
	}
}

// The confirmed dispatch spends the token on the real crawl call; the page names the accepted
// task and offers the watch view for it.
func TestUI2CrawlRunSpendsTokenAndRendersOutcome(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	token, _ := ui2CrawlLaunchToken(t, s, "seeds=http%3A%2F%2F127.0.0.1%3A1%2F&config=")
	if token == "" {
		t.Fatalf("no token minted")
	}
	req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/crawl-run",
		strings.NewReader("seeds=http%3A%2F%2F127.0.0.1%3A1%2F&config=&token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{"Crawl accepted", "task", "watch this crawl", `/ui2/scanner/crawl-watch`} {
		if !strings.Contains(body, want) {
			t.Errorf("outcome lacks %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
}

// The watch view renders the retained run's live state and refreshes only on demand: a
// check-now control re-requests the same view, and the page says it does not update by itself.
func TestUI2CrawlWatchRendersRetainedRun(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	token, _ := ui2CrawlLaunchToken(t, s, "seeds=http%3A%2F%2F127.0.0.1%3A1%2F&config=")
	if token == "" {
		t.Fatalf("no token minted")
	}
	req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/crawl-run",
		strings.NewReader("seeds=http%3A%2F%2F127.0.0.1%3A1%2F&config=&token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	m := regexp.MustCompile(`task (\d+)`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("accepted outcome names no task: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/ui2/scanner/crawl-watch?task="+m[1], nil))
	body := rec2.Body.String()
	for _, want := range []string{"state", "phase", "fetched", "check now", "updates itself", "data-task=", "/api/crawl/live?task="} {
		if !strings.Contains(body, want) {
			t.Errorf("watch view lacks %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
}

// A watch aimed at a task that is not retained carries the API's own refusal as a note.
func TestUI2CrawlWatchUnknownTask(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/scanner/crawl-watch?task=999", nil))
	if !strings.Contains(rec.Body.String(), "No crawl 999 is retained") {
		t.Errorf("unknown task does not carry the refusal: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
}

// The live-refresh wiring: the shell names its view for view-scoped dispatch and no
// longer connects the vendored SSE extension (its named-event path can never fire on the
// server's unnamed frames); app.js owns the single stream, the generation guard that
// drops stale live answers, and the scrolled-operator pill.
func TestUI2LiveRefreshWiring(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/history", nil))
	page := rec.Body.String()
	if !strings.Contains(page, `data-view="history"`) {
		t.Errorf("history shell does not name its view: %s", page[:ui2Min(200, len(page))])
	}
	for _, gone := range []string{"sse-connect", "sse-swap", "sse.min.js"} {
		if strings.Contains(page, gone) {
			t.Errorf("history shell still carries dead extension wiring %q", gone)
		}
	}
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/ui2/app.js", nil))
	js := rec2.Body.String()
	for _, want := range []string{"EventSource('/api/events')", "view === 'history'", "view === 'issues'", "X-Live-Refresh", "shouldSwap = false", "livepill", "liveTrailing"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks live-refresh piece %q", want)
		}
	}
	for _, gone := range []string{"htmx:sseMessage", "crawlWatchES"} {
		if strings.Contains(js, gone) {
			t.Errorf("app.js still carries dead wiring %q", gone)
		}
	}
	// Hover and selection must not render identically: a live swap moves the rows under a
	// parked cursor, and if hover shares selection's shade the list shows two
	// "selected-looking" rows - one of them only hovered.
	if !strings.Contains(page, "tr:hover { background:var(--line); }") {
		t.Errorf("hover shade is not distinct from selection")
	}
	if !strings.Contains(page, "tr.selected { background:var(--sel); box-shadow:inset 3px 0 0 var(--accent); }") {
		t.Errorf("selection lost its distinct marker")
	}
}

// Operator-facing feedback wiring: the shell carries the busy badge and the polite notice
// region outside every swap target, and app.js counts issued requests by htmx's own pairing
// guarantee, excludes live traffic, keeps failure wording neutral, and no longer listens for
// the unmatchable targetError on the live path.
func TestUI2OperatorFeedbackWiring(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/history", nil))
	page := rec.Body.String()
	for _, want := range []string{`id="busybadge"`, `id="notice" role="status" aria-live="polite"`} {
		if !strings.Contains(page, want) {
			t.Errorf("shell lacks feedback element %q", want)
		}
	}
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/ui2/app.js", nil))
	js := rec2.Body.String()
	for _, want := range []string{"htmx:beforeSend", "busybadge", "noticeSay", "Couldn't confirm the result. Check the current state before retrying."} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks feedback piece %q", want)
		}
	}
	if strings.Contains(js, "'htmx:targetError', 'htmx:abort'") {
		t.Errorf("live busy clearing still listens for the unmatchable targetError")
	}
	if !strings.Contains(js, "it fires before any send and its detail") {
		t.Errorf("the targetError exclusion lost its reason")
	}
}

// Truncated column headers expand in place on phone like body cells do: the
// shell carries the th.cell-x style, and app.js wires tap plus keyboard
// toggling, focusability only while truncated, aria state, and a guard that
// keeps interactive headers on their own behavior.
func TestUI2HeaderExpansionWiring(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/history", nil))
	page := rec.Body.String()
	if !strings.Contains(page, "thead th.cell-x") {
		t.Errorf("shell lacks the th.cell-x expansion style")
	}
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/ui2/app.js", nil))
	js := rec2.Body.String()
	for _, want := range []string{"ui2SyncExpandableHeaders", "ui2ToggleHeader", "keydown", "aria-expanded", "hx-get", "matchMedia('(max-width: 640px)')"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks header expansion piece %q", want)
		}
	}
	if !strings.Contains(page, "thead th.cell-x { white-space:normal; overflow-wrap:break-word;") {
		t.Errorf("expanded headings no longer wrap at word boundaries")
	}
}

// The header expansion's phone gate and its CSS must share one boundary: the
// th.cell-x and th[tabindex] rules live inside the 640px media block (the 560px
// block is livepill wrapping only), and app.js observes the same 640px query.
func TestUI2HeaderExpansionBoundaryPinned(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/proxy", nil))
	page := rec.Body.String()
	start := strings.Index(page, "@media (max-width: 640px)")
	if start < 0 {
		t.Fatalf("shell lost the 640px media block")
	}
	rest := page[start:]
	end := strings.Index(rest[len("@media (max-width: 640px)"):], "@media")
	block := rest
	if end >= 0 {
		block = rest[:end+len("@media (max-width: 640px)")]
	}
	for _, want := range []string{"thead th.cell-x", "thead th[tabindex]"} {
		if !strings.Contains(block, want) {
			t.Errorf("header expansion style %q escaped the 640px media block", want)
		}
	}
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/ui2/app.js", nil))
	js := rec2.Body.String()
	if !strings.Contains(js, "matchMedia('(max-width: 640px)')") {
		t.Errorf("app.js header gate no longer observes the 640px boundary")
	}
	if strings.Contains(js, "matchMedia('(max-width: 560px)')") {
		t.Errorf("app.js header gate drifted to the livepill boundary")
	}
}

// A crawl whose seed the engagement scope refuses does not start; the page carries the scope's
// refusal rather than a launched task.
func TestUI2CrawlRunOutOfScopeRendersRefusal(t *testing.T) {
	s := newTestServer()
	// An include rule for another host, so the seed is outside the engagement scope (an
	// empty scope is Burp's default-allow and would crawl it).
	s.scope.AddInclude("someone-else.test")
	token, _ := ui2CrawlLaunchToken(t, s, "seeds=http%3A%2F%2Ftarget.example%2F&config=")
	if token == "" {
		t.Fatalf("no token minted")
	}
	req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/crawl-run",
		strings.NewReader("seeds=http%3A%2F%2Ftarget.example%2F&config=&token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "Crawl failed") || !strings.Contains(body, "outside the engagement scope") {
		t.Errorf("refusal not rendered: %s", body[:ui2Min(400, len(body))])
	}
	if strings.Contains(body, "Crawl accepted") {
		t.Errorf("an out-of-scope crawl rendered as accepted")
	}
}

// ---- Scanner configuration --------------------------------------------------------------------

// ui2ScanConfigConfirmToken posts the configuration form and extracts the minted one-time token
// and the reviewed patch from the confirm fragment.
func ui2ScanConfigConfirmToken(t *testing.T, s *Server, form string) (token, patch, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/config-confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("config-confirm = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	body = rec.Body.String()
	if i := strings.Index(body, `name="token" value="`); i >= 0 {
		rest := body[i+len(`name="token" value="`):]
		token = rest[:strings.IndexByte(rest, '"')]
	}
	if i := strings.Index(body, `name="patch" value="`); i >= 0 {
		rest := body[i+len(`name="patch" value="`):]
		// A browser decodes the attribute's entities on submit; the extraction must too.
		patch = html.UnescapeString(rest[:strings.IndexByte(rest, '"')])
	}
	return token, patch, body
}

// ui2ScanConfigCurrentForm builds the form a browser submits when the operator changes nothing:
// every currently-on family checked, timeouts left as displayed. skip names one family to leave
// unchecked.
func ui2ScanConfigCurrentForm(t *testing.T, s *Server, skip string) string {
	t.Helper()
	view := s.ui2ScanConfigView()
	if len(view) == 0 {
		t.Fatalf("no live scanner configuration")
	}
	parts := []string{}
	for _, key := range ui2ScanConfigBoolKeys {
		if on, _ := view[key].(bool); on && key != skip {
			parts = append(parts, key+"=on")
		}
	}
	return strings.Join(parts, "&")
}

// The page's key list is exactly the endpoint's: a switch the endpoint refuses, or an accepted
// key the page hides, would both make the review step lie about the call.
func TestUI2ScanConfigKeysMatchTheEndpoint(t *testing.T) {
	if len(ui2ScanConfigBoolKeys) != len(scannerConfigBoolKeys) {
		t.Fatalf("page lists %d keys, endpoint accepts %d", len(ui2ScanConfigBoolKeys), len(scannerConfigBoolKeys))
	}
	for _, key := range ui2ScanConfigBoolKeys {
		if scannerConfigBoolKeys[key] == nil {
			t.Errorf("page offers %s, which PUT /api/scanner/config refuses", key)
		}
	}
}

// The review step names the exact changed keys and mints a one-time token bound to the PUT.
func TestUI2ScanConfigConfirmNamesChanges(t *testing.T) {
	s := newTestServerWithScanner(t)
	// The current state with one family unchecked and a new timeout: exactly two changes.
	form := ui2ScanConfigCurrentForm(t, s, "check_xss") + "&timeout_ms=1234"
	token, patch, body := ui2ScanConfigConfirmToken(t, s, form)
	if token == "" {
		t.Fatalf("review step carries no token: %s", body[:ui2Min(300, len(body))])
	}
	for _, want := range []string{"Review configuration changes", "PUT /api/scanner/config", "Confirm and apply", "one-time"} {
		if !strings.Contains(body, want) {
			t.Errorf("review step lacks %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
	if !strings.Contains(body, "xss: on -&gt; off") {
		t.Errorf("change list does not name the xss switch: %s", body[:ui2Min(600, len(body))])
	}
	if !strings.Contains(body, "timeout_ms: ") {
		t.Errorf("change list does not name the timeout change")
	}
	if !strings.Contains(patch, "check_xss") || !strings.Contains(patch, "timeout_ms") {
		t.Errorf("reviewed patch does not carry the changed keys: %s", patch)
	}
	if strings.Contains(patch, "check_sqli") {
		t.Errorf("patch carries an unchanged family: %s", patch)
	}
}

// A form identical to the running configuration mints nothing and says why; a bad timeout is
// refused before any token.
func TestUI2ScanConfigConfirmNoChangeOrBadValue(t *testing.T) {
	s := newTestServerWithScanner(t)
	token, _, body := ui2ScanConfigConfirmToken(t, s, ui2ScanConfigCurrentForm(t, s, ""))
	if token != "" {
		t.Errorf("an unchanged form still minted a token")
	}
	if !strings.Contains(body, "nothing changed") {
		t.Errorf("fragment does not say nothing changed: %s", body[:ui2Min(300, len(body))])
	}
	token, _, body = ui2ScanConfigConfirmToken(t, s, ui2ScanConfigCurrentForm(t, s, "")+"&timeout_ms=-5")
	if token != "" {
		t.Errorf("a negative timeout still minted a token")
	}
	if !strings.Contains(body, "non-negative") {
		t.Errorf("fragment does not refuse the negative timeout: %s", body[:ui2Min(300, len(body))])
	}
}

// The confirmed dispatch spends the token on the reviewed PUT; the live configuration then
// carries the change.
func TestUI2ScanConfigRunAppliesReviewedPatch(t *testing.T) {
	s := newTestServerWithScanner(t)
	token, patch, _ := ui2ScanConfigConfirmToken(t, s, ui2ScanConfigCurrentForm(t, s, "check_xss"))
	if token == "" {
		t.Fatalf("no token minted")
	}
	form := "token=" + token + "&patch=" + url.QueryEscape(patch)
	req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/config-run", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "Configuration applied") {
		t.Fatalf("outcome does not confirm the change: %s", body[:ui2Min(400, len(body))])
	}
	view := s.ui2ScanConfigView()
	if on, _ := view["check_xss"].(bool); on {
		t.Errorf("live configuration still carries check_xss=on after the reviewed PATCH: %v", view["check_xss"])
	}
}

// The re-rendered page after a config run reflects the applied state, not the state from before
// the dispatch (the model must be built after the PUT, not before).
func TestUI2ScanConfigRunPageShowsAppliedState(t *testing.T) {
	s := newTestServerWithScanner(t)
	token, patch, _ := ui2ScanConfigConfirmToken(t, s, ui2ScanConfigCurrentForm(t, s, "check_xss"))
	body := ui2ScanConfigRun(t, s, "token="+token+"&patch="+url.QueryEscape(patch))
	if !strings.Contains(body, "Configuration applied") {
		t.Fatalf("run refused: %s", body[:ui2Min(300, len(body))])
	}
	if strings.Contains(body, `name="check_xss" checked`) {
		t.Errorf("page shows check_xss on after applying it off")
	}
	// And the way back: re-checking renders checked after applying on.
	token, patch, _ = ui2ScanConfigConfirmToken(t, s, "check_xss=on")
	body = ui2ScanConfigRun(t, s, "token="+token+"&patch="+url.QueryEscape(patch))
	if !strings.Contains(body, "Configuration applied") || !strings.Contains(body, `name="check_xss" checked`) {
		t.Errorf("page does not show check_xss on after restoring it")
	}
}

// ui2ScanConfigRun posts the run form and returns the re-rendered page.
func ui2ScanConfigRun(t *testing.T, s *Server, form string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/config-run", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec.Body.String()
}

// A lost patch, a tampered patch, and a replayed token are each refused with their reason; a
// tampered attempt burns its token, so the reviewed call cannot be smuggled in afterwards.
func TestUI2ScanConfigRunRefusesLostTamperedAndReplayed(t *testing.T) {
	s := newTestServerWithScanner(t)

	// Missing patch: refused without dispatching, so the same token still spends afterwards.
	// Each scenario flips a different family, because a spend changes the live configuration.
	token1, patch1, _ := ui2ScanConfigConfirmToken(t, s, ui2ScanConfigCurrentForm(t, s, "check_xss"))
	if token1 == "" {
		t.Fatalf("no token minted")
	}
	body := ui2ScanConfigRun(t, s, "token="+token1)
	if !strings.Contains(body, "lost") || strings.Contains(body, "Configuration applied") {
		t.Errorf("missing patch not refused: %s", body[:ui2Min(300, len(body))])
	}
	body = ui2ScanConfigRun(t, s, "token="+token1+"&patch="+url.QueryEscape(patch1))
	if !strings.Contains(body, "Configuration applied") {
		t.Errorf("the reviewed patch was refused after a missing-patch attempt: %s", body[:ui2Min(300, len(body))])
	}

	// Tampered patch: the token is bound to the reviewed body, so an altered one is refused -
	// and the attempt burns the token, so the reviewed body cannot follow it.
	token2, patch2, _ := ui2ScanConfigConfirmToken(t, s, ui2ScanConfigCurrentForm(t, s, "check_sqli"))
	tampered := strings.Replace(patch2, "false", "true", 1)
	body = ui2ScanConfigRun(t, s, "token="+token2+"&patch="+url.QueryEscape(tampered))
	if strings.Contains(body, "Configuration applied") {
		t.Errorf("a tampered patch was applied")
	}
	body = ui2ScanConfigRun(t, s, "token="+token2+"&patch="+url.QueryEscape(patch2))
	if strings.Contains(body, "Configuration applied") {
		t.Errorf("the reviewed patch went through after a tampered attempt")
	}

	// Replay: a spent token does not spend twice.
	token3, patch3, _ := ui2ScanConfigConfirmToken(t, s, ui2ScanConfigCurrentForm(t, s, "check_xxe"))
	body = ui2ScanConfigRun(t, s, "token="+token3+"&patch="+url.QueryEscape(patch3))
	if !strings.Contains(body, "Configuration applied") {
		t.Fatalf("the reviewed patch was refused: %s", body[:ui2Min(300, len(body))])
	}
	body = ui2ScanConfigRun(t, s, "token="+token3+"&patch="+url.QueryEscape(patch3))
	if strings.Contains(body, "Configuration applied") {
		t.Errorf("a replayed token applied the patch twice")
	}
	if !strings.Contains(body, "confirmation required") {
		t.Errorf("replay refusal does not say why: %s", body[:ui2Min(300, len(body))])
	}
}

// Bad input is refused at the confirm step before any token is minted: wrong kind, bad port,
// unknown action.
func TestUI2ScopeConfirmRejectsBadInput(t *testing.T) {
	s := newTestServer()
	for _, form := range []string{
		"scope_action=rule-add&kind=sideways&pattern=x",
		"scope_action=rule-add&kind=include&pattern=x&port=99999",
		"scope_action=rule-add&kind=include&pattern=x&port=abc",
		"scope_action=bogus",
	} {
		token, body := ui2ScopeConfirm(t, s, form)
		if token != "" {
			t.Errorf("%s still minted a token", form)
		}
		if !strings.Contains(body, "Not applied") {
			t.Errorf("%s: fragment does not say what is wrong: %s", form, body[:ui2Min(300, len(body))])
		}
	}
}

// ---- Scanner launch ---------------------------------------------------------------------------

// ui2ScannerLaunchToken posts the launch form and extracts the minted one-time token from the
// review fragment.
func ui2ScannerLaunchToken(t *testing.T, s *Server, form string) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/launch", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("launch = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	body := rec.Body.String()
	mark := `name="token" value="`
	i := strings.Index(body, mark)
	if i < 0 {
		return "", body
	}
	rest := body[i+len(mark):]
	return rest[:strings.IndexByte(rest, '"')], body
}

// The first click mints a one-time confirmation for the exact audit call and renders the review
// step; nothing launches from it.
func TestUI2ScannerLaunchMintsReviewStep(t *testing.T) {
	s := newTestServer()
	token, body := ui2ScannerLaunchToken(t, s, "exchange_id=0&config=")
	if token == "" {
		t.Fatalf("review step carries no token: %s", body[:ui2Min(300, len(body))])
	}
	for _, want := range []string{"Review before launch", "POST /api/scanner/audit", "Confirm and launch", "active attack probes", "out-of-scope", "unauditable", "one-time"} {
		if !strings.Contains(body, want) {
			t.Errorf("review step lacks %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
	// The preview names the exact call body the token is bound to.
	if !strings.Contains(body, "exchange_id") {
		t.Errorf("preview does not show the call body")
	}
}

func TestUI2ScannerLaunchBadExchangeSaysSo(t *testing.T) {
	s := newTestServer()
	token, body := ui2ScannerLaunchToken(t, s, "exchange_id=abc&config=")
	if token != "" {
		t.Errorf("a malformed exchange id still minted a token")
	}
	if !strings.Contains(body, "an exchange id is required") {
		t.Errorf("fragment does not say what is missing: %s", body[:ui2Min(300, len(body))])
	}
}

// The confirmed dispatch spends the token on the real audit call. An id naming no captured
// exchange answers unauditable with its reason, and the page carries that reason.
func TestUI2ScannerRunSpendsTokenAndRendersOutcome(t *testing.T) {
	s := newTestServer()
	token, _ := ui2ScannerLaunchToken(t, s, "exchange_id=999&config=")
	if token == "" {
		t.Fatal("no token minted")
	}
	form := "token=" + url.QueryEscape(token) + "&exchange_id=999&config="
	run := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/run", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		return rec
	}
	rec := run()
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Audit outcome") {
		t.Errorf("page lacks the audit outcome block: %s", body[:ui2Min(400, len(body))])
	}
	if !strings.Contains(body, "refused:") {
		t.Errorf("unauditable exchange did not surface its refusal on the page: %s", body[:ui2Min(600, len(body))])
	}
	// The same token cannot be spent twice.
	rec2 := run()
	if !strings.Contains(rec2.Body.String(), "Launch failed") {
		t.Errorf("a spent token did not fail the second launch")
	}
}

func TestUI2ScannerRunWithoutTokenFails(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/ui2/scanner/run", strings.NewReader("exchange_id=999&config="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Launch failed") {
		t.Errorf("a tokenless dispatch was not refused on the page")
	}
}

// ---- Intercept rule-list toggles ------------------------------------------------------------

// The page's rule toggle flips the list's active flag through the API and carries the stored
// rules across unchanged.
func TestUI2InterceptRuleTogglePreservesRules(t *testing.T) {
	s := newTestServer()
	s.intercept.SetEnabled(true)
	body := map[string]any{
		"active": true,
		"rules": []map[string]any{
			{"field": "host", "category": "literal", "string_match": "noisy.test", "enabled": true, "comment": "keep me", "action": "pass"},
			{"field": "path", "category": "literal", "string_match": "/admin", "enabled": false, "comment": "", "action": "hold"},
		},
	}
	if rec := putJSON(t, s, "/api/intercept/rules/requests", body); rec.Code != http.StatusOK {
		t.Fatalf("PUT rules: status = %d (%s)", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/rules-requests-off", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rules-requests-off = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	if !strings.Contains(rec.Body.String(), "Request rules OFF") {
		t.Errorf("refreshed fragment does not show the list off: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}

	got := get(t, s, "/api/intercept/rules/requests")
	var state struct {
		Active bool `json:"active"`
		Count  int  `json:"count"`
		Rules  []struct {
			Match   string `json:"string_match"`
			Enabled bool   `json:"enabled"`
			Comment string `json:"comment"`
			Action  string `json:"action"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	if state.Active {
		t.Errorf("list still active after the off toggle")
	}
	if state.Count != 2 || state.Rules[0].Match != "noisy.test" || state.Rules[0].Comment != "keep me" ||
		state.Rules[0].Action != "pass" || !state.Rules[0].Enabled ||
		state.Rules[1].Match != "/admin" || state.Rules[1].Enabled {
		t.Errorf("toggle rewrote the stored rules: %+v", state)
	}

	// An inactive list holds nothing; toggling back on restores the stored rules' decisions.
	if s.intercept.Hold(&intercept.Message{Direction: intercept.DirectionRequest, Host: "a.test", Port: 80, Method: "GET", Path: "/admin", Raw: []byte("GET /admin HTTP/1.1\r\n\r\n")}) != nil {
		t.Errorf("inactive list held a request")
	}
	req2 := httptest.NewRequest(http.MethodPost, "/ui2/intercept/rules-requests-on", nil)
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("rules-requests-on = %d: %s", rec2.Code, rec2.Body.String()[:ui2Min(200, rec2.Body.Len())])
	}
	if !strings.Contains(rec2.Body.String(), "Request rules ON") {
		t.Errorf("refreshed fragment does not show the list back on")
	}
	got2 := get(t, s, "/api/intercept/rules/requests")
	var state2 struct {
		Active bool `json:"active"`
		Count  int  `json:"count"`
	}
	if err := json.Unmarshal(got2.Body.Bytes(), &state2); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	if !state2.Active || state2.Count != 2 {
		t.Errorf("on toggle: active=%v count=%d, want active with 2 rules", state2.Active, state2.Count)
	}
}

// With the response list the same toggle rides its own direction, and the page discloses what
// an empty active list means.
func TestUI2InterceptRuleToggleResponsesAndEmptyListDisclosure(t *testing.T) {
	s := newTestServer()
	s.intercept.SetEnabled(true)
	if err := s.intercept.SetRules(intercept.DirectionResponse, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/intercept", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui2/intercept = %d", rec.Code)
	}
	for _, want := range []string{"empty list holds every response", "Turn response rules off"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("page lacks disclosure %q", want)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/rules-responses-off", nil)
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("rules-responses-off = %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "holds nothing while off") {
		t.Errorf("off fragment lacks the holds-nothing disclosure")
	}
	l := s.intercept.Rules(intercept.DirectionResponse)
	if l.Active {
		t.Errorf("response list still active after the off toggle")
	}
}

func TestUI2InterceptRuleToggleMalformed(t *testing.T) {
	s := newTestServer()
	for _, action := range []string{"rules-bogus-on", "rules-requests", "rules-requests-maybe", "rules-"} {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ui2/intercept/"+action, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST /ui2/intercept/%s = %d, want 400", action, rec.Code)
		}
	}
}

func TestUI2InterceptForwardHeldEdited(t *testing.T) {
	s := newTestServer()
	h := ui2HoldRequest(t, s, "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\r\nold!")
	form := url.Values{
		"raw":                {"POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\r\nedited-body"},
		"fix_content_length": {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward-<id> = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	action, raw, _, userEdited := h.Wait()
	if action != intercept.ActionForward {
		t.Errorf("held action = %v, want forward", action)
	}
	if !strings.Contains(string(raw), "edited-body") {
		t.Errorf("forwarded bytes do not carry the operator's edit: %q", raw)
	}
	if !strings.Contains(string(raw), "Content-Length: 11") {
		t.Errorf("fix_content_length did not recompute the header for the edited body: %q", raw)
	}
	if !userEdited {
		t.Errorf("an edited forward was not marked user-edited")
	}
	if n := len(s.intercept.Held()); n != 0 {
		t.Errorf("%d messages still held after the forward", n)
	}
	if !strings.Contains(rec.Body.String(), "Nothing held.") {
		t.Errorf("refreshed queue still lists a held item")
	}
}

func TestUI2InterceptForwardHeldEditedLFOnly(t *testing.T) {
	// What htmx actually submits: the textarea normalized every CRLF to LF.
	s := newTestServer()
	h := ui2HoldRequest(t, s, "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\r\nold!")
	form := url.Values{
		"raw":                {"POST /x HTTP/1.1\nHost: a.test\nContent-Length: 4\nX-Operator-Edit: ui2\n\nedited\nbody"},
		"fix_content_length": {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward-<id> with LF-only raw = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	_, raw, _, _ := h.Wait()
	got := string(raw)
	if !strings.Contains(got, "POST /x HTTP/1.1\r\nHost: a.test\r\n") {
		t.Errorf("head left LF-only, which many servers never answer: %q", got)
	}
	if !strings.Contains(got, "\r\n\r\nedited\nbody") {
		t.Errorf("body did not keep the operator's own line endings: %q", got)
	}
	if !strings.Contains(got, "Content-Length: 11") {
		t.Errorf("fix_content_length did not recompute for the edited body: %q", got)
	}
}

func TestUI2InterceptForwardHeldUnchangedRoundTrip(t *testing.T) {
	// Open the editor, change nothing, Forward: the textarea returns the bytes with CRs
	// stripped, and that round-trip must ship the original bytes, not the flattened copy.
	s := newTestServer()
	original := "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n\r\na\r\nb"
	h := ui2HoldRequest(t, s, original)
	form := url.Values{"raw": {"POST /x HTTP/1.1\nHost: a.test\nContent-Length: 5\n\na\nb"}}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unchanged round-trip forward = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	action, raw, _, userEdited := h.Wait()
	if action != intercept.ActionForward {
		t.Errorf("held action = %v, want forward", action)
	}
	if string(raw) != original {
		t.Errorf("an unchanged round-trip rewrote the held bytes: %q", raw)
	}
	if userEdited {
		t.Errorf("an unchanged round-trip was marked user-edited")
	}
}

func TestUI2InterceptForwardHeldUntouched(t *testing.T) {
	s := newTestServer()
	original := "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n"
	h := ui2HoldRequest(t, s, original)
	form := url.Values{"fix_content_length": {"on"}}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("forward-<id> without raw = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	action, raw, _, userEdited := h.Wait()
	if action != intercept.ActionForward {
		t.Errorf("held action = %v, want forward", action)
	}
	if string(raw) != original {
		t.Errorf("a forward without the raw field changed the bytes: %q", raw)
	}
	if userEdited {
		t.Errorf("a forward without the raw field was marked user-edited")
	}
}

func ui2HoldWebSocket(t *testing.T, s *Server, opcode, raw string) *intercept.Held {
	t.Helper()
	s.intercept.SetEnabled(true)
	if err := s.intercept.SetRules(intercept.DirectionWebSocketToServer, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	h := s.intercept.Hold(&intercept.Message{
		Direction: intercept.DirectionWebSocketToServer,
		Host:      "a.test",
		Port:      80,
		Path:      "/ws",
		Opcode:    opcode,
		Raw:       []byte(raw),
	})
	if h == nil {
		t.Fatalf("unconditional WebSocket list did not hold")
	}
	return h
}

// The page exposes the two WebSocket rule lists with the same reversible switch as the
// request/response lists, and the toggle keeps the stored rules intact.
func TestUI2InterceptRuleToggleWebSocketDirections(t *testing.T) {
	s := newTestServer()
	s.intercept.SetEnabled(true)
	body := map[string]any{
		"active": true,
		"rules": []map[string]any{
			{"field": "host", "category": "literal", "string_match": "noisy.test", "enabled": true, "comment": "keep me", "action": "pass"},
		},
	}
	if rec := putJSON(t, s, "/api/intercept/rules/websocket_to_server", body); rec.Code != http.StatusOK {
		t.Fatalf("PUT ws rules: status = %d (%s)", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/rules-websocket_to_server-off", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rules-websocket_to_server-off = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	if !strings.Contains(rec.Body.String(), "WebSocket-to-server rules OFF") {
		t.Errorf("refreshed fragment does not show the WS list off: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	got := get(t, s, "/api/intercept/rules/websocket_to_server")
	var state struct {
		Active bool `json:"active"`
		Count  int  `json:"count"`
		Rules  []struct {
			Match   string `json:"string_match"`
			Comment string `json:"comment"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode ws rules: %v", err)
	}
	if state.Active {
		t.Errorf("WS list still active after the off toggle")
	}
	if state.Count != 1 || state.Rules[0].Match != "noisy.test" || state.Rules[0].Comment != "keep me" {
		t.Errorf("toggle rewrote the stored WS rules: %+v", state)
	}
	// An inactive WS list holds nothing.
	if s.intercept.Hold(&intercept.Message{Direction: intercept.DirectionWebSocketToServer, Host: "a.test", Port: 80, Path: "/ws", Opcode: "text", Raw: []byte("hi")}) != nil {
		t.Errorf("inactive WS list held a message")
	}
	req2 := httptest.NewRequest(http.MethodPost, "/ui2/intercept/rules-websocket_to_server-on", nil)
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("rules-websocket_to_server-on = %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "WebSocket-to-server rules ON") {
		t.Errorf("refreshed fragment does not show the WS list back on")
	}
	if l := s.intercept.Rules(intercept.DirectionWebSocketToServer); !l.Active {
		t.Errorf("WS list not active after the on toggle")
	}

	// The to-client list rides its own direction.
	if err := s.intercept.SetRules(intercept.DirectionWebSocketToClient, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	rec3 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/ui2/intercept", nil))
	for _, want := range []string{"empty list holds every server-to-client message", "Turn WebSocket-to-client rules off"} {
		if !strings.Contains(rec3.Body.String(), want) {
			t.Errorf("page lacks WS disclosure %q", want)
		}
	}
}

// A held WebSocket text message shows its opcode, offers the editor without the HTTP-only
// Content-Length control, and an edit ships exactly the bytes the operator saw - no CR
// injection from header-newline restoration, since a payload has no headers.
func TestUI2InterceptHeldWebSocketTextEditByteExact(t *testing.T) {
	s := newTestServer()
	h := ui2HoldWebSocket(t, s, "text", "line one\nline two")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/intercept", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "websocket_to_server · text") {
		t.Errorf("held WS row does not show the opcode: %s", body[:ui2Min(600, len(body))])
	}
	if strings.Contains(body, "Fix Content-Length") {
		t.Errorf("WS held editor offers the HTTP-only Content-Length control")
	}
	if !strings.Contains(body, "there are no headers and no Content-Length to fix") {
		t.Errorf("WS held editor lacks the no-headers note")
	}

	form := url.Values{"raw": {"line one\nCHANGED\nline three\n\nline five"}}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("WS forward = %d: %s", rec2.Code, rec2.Body.String()[:ui2Min(200, rec2.Body.Len())])
	}
	action, raw, _, userEdited := h.Wait()
	if action != intercept.ActionForward {
		t.Errorf("held action = %v, want forward", action)
	}
	if string(raw) != "line one\nCHANGED\nline three\n\nline five" {
		t.Errorf("edited WS payload was not byte-exact to what the operator saw: %q", raw)
	}
	if !userEdited {
		t.Errorf("an edited WS forward was not marked user-edited")
	}
}

// An unchanged WS round-trip ships the original bytes - including its CR breaks - and is not
// marked user-edited.
func TestUI2InterceptHeldWebSocketUnchangedRoundTrip(t *testing.T) {
	s := newTestServer()
	original := "first\r\nsecond"
	h := ui2HoldWebSocket(t, s, "text", original)
	form := url.Values{"raw": {"first\nsecond"}}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("WS unchanged round-trip = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	action, raw, _, userEdited := h.Wait()
	if action != intercept.ActionForward {
		t.Errorf("held action = %v, want forward", action)
	}
	if string(raw) != original {
		t.Errorf("an unchanged WS round-trip rewrote the payload: %q", raw)
	}
	if userEdited {
		t.Errorf("an unchanged WS round-trip was marked user-edited")
	}
}

// A printable binary message gets the editor with its limitation named, and the edit ships
// the shown bytes; the wire opcode is the relay's business and stays binary.
func TestUI2InterceptHeldWebSocketBinaryPrintable(t *testing.T) {
	s := newTestServer()
	h := ui2HoldWebSocket(t, s, "binary", "printable binary payload")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/intercept", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "websocket_to_server · binary") {
		t.Errorf("held binary row does not show the opcode")
	}
	if !strings.Contains(body, "goes out as a binary message") {
		t.Errorf("binary editor lacks the preserved-opcode note")
	}
	form := url.Values{"raw": {"changed binary payload"}}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("binary WS forward = %d: %s", rec2.Code, rec2.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	_, raw, _, userEdited := h.Wait()
	if string(raw) != "changed binary payload" {
		t.Errorf("edited binary payload not byte-exact: %q", raw)
	}
	if !userEdited {
		t.Errorf("an edited binary WS forward was not marked user-edited")
	}
}

// A binary message the textarea cannot carry keeps the editor off and names the console path.
func TestUI2InterceptHeldWebSocketBinaryUnsafe(t *testing.T) {
	s := newTestServer()
	ui2HoldWebSocket(t, s, "binary", "prefix\x00suffix")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/intercept", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "websocket_to_server · binary") {
		t.Errorf("unsafe binary row does not show the opcode")
	}
	if !strings.Contains(body, "not safe to edit here") {
		t.Errorf("unsafe binary message was offered the text editor")
	}
	if strings.Contains(body, "<textarea") {
		t.Errorf("unsafe binary message rendered a textarea")
	}
}

// ---- Phone table readability (tap-to-expand for truncated cells) -------------------------

// The pages whose tables carry long values (WebSocket URLs, listener binds, held-message
// hosts) tell phone users how to reach a cut-off value, and the shared script expands a
// truncated cell of any row without its own tap action on the first tap.
func TestUI2PhoneTablesAdvertiseTapToExpand(t *testing.T) {
	s := newTestServer()
	for page, path := range map[string]string{
		"ws":        "/ui2/ws",
		"intercept": "/ui2/intercept",
		"proxy":     "/ui2/proxy",
	} {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "cut-off table cell expands in place when tapped") {
			t.Errorf("%s page lacks the phone tap-to-expand hint", page)
		}
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/app.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui2/app.js = %d", rec.Code)
	}
	js := rec.Body.String()
	if !strings.Contains(js, "!tr.hasAttribute('hx-get')") {
		t.Errorf("tap-to-expand no longer covers rows without their own tap action")
	}
	if !strings.Contains(js, "tr.classList.contains('selected')") {
		t.Errorf("tap-to-expand dropped the two-tap rule for navigating rows")
	}
}

func TestUI2InterceptDropHeld(t *testing.T) {
	s := newTestServer()
	h := ui2HoldRequest(t, s, "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n")
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/drop-"+strconv.FormatUint(h.ID, 10), nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("drop-<id> = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	if action, _, _, _ := h.Wait(); action != intercept.ActionDrop {
		t.Errorf("held action = %v, want drop", action)
	}
	if n := len(s.intercept.Held()); n != 0 {
		t.Errorf("%d messages still held after the drop", n)
	}
}

func TestUI2InterceptRendersNonUTF8HeldWithoutEditor(t *testing.T) {
	s := newTestServer()
	raw := "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\n\xff\xfe"
	h := ui2HoldRequest(t, s, raw)
	req := httptest.NewRequest(http.MethodGet, "/ui2/intercept", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui2/intercept = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<textarea") {
		t.Errorf("a non-UTF-8 held message was offered the textarea that would corrupt it")
	}
	if !strings.Contains(body, "base64 editor") {
		t.Errorf("non-UTF-8 hold does not point at the console's exact-byte path")
	}
	id := strconv.FormatUint(h.ID, 10)
	if !strings.Contains(body, "/ui2/intercept/forward-"+id) || !strings.Contains(body, "/ui2/intercept/drop-"+id) {
		t.Errorf("non-UTF-8 hold lost its untouched forward/drop actions")
	}
	if err := s.intercept.Drop(h.ID, "test cleanup"); err != nil {
		t.Fatalf("cleanup drop: %v", err)
	}
}

func TestUI2InterceptForwardNonUTF8RefusesRaw(t *testing.T) {
	s := newTestServer()
	h := ui2HoldRequest(t, s, "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\n\xff\xfe")
	form := url.Values{"raw": {"POST /x HTTP/1.1\nHost: a.test\n\n\ufffd\ufffd"}}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("raw edit of a non-UTF-8 hold = %d, want 400", rec.Code)
	}
	if n := len(s.intercept.Held()); n != 1 {
		t.Fatalf("a refused edit still resolved the hold")
	}
	if err := s.intercept.Drop(h.ID, "test cleanup"); err != nil {
		t.Fatalf("cleanup drop: %v", err)
	}
}

func TestUI2InterceptForwardNonUTF8UntouchedByteExact(t *testing.T) {
	s := newTestServer()
	original := "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\n\xff\xfe"
	h := ui2HoldRequest(t, s, original)
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("untouched forward of a non-UTF-8 hold = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	_, raw, _, userEdited := h.Wait()
	if string(raw) != original {
		t.Errorf("untouched forward did not ship the exact held bytes: %q", raw)
	}
	if userEdited {
		t.Errorf("untouched forward of a non-UTF-8 hold was marked user-edited")
	}
}

func TestUI2InterceptRendersNULHeldWithoutEditor(t *testing.T) {
	// Valid UTF-8 that carries a NUL: the HTML parser replaces the NUL with U+FFFD in a
	// textarea, so the "valid UTF-8" label alone was never enough to make a hold editable.
	s := newTestServer()
	raw := "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 3\r\n\r\nA\x00B"
	h := ui2HoldRequest(t, s, raw)
	req := httptest.NewRequest(http.MethodGet, "/ui2/intercept", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui2/intercept = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<textarea") {
		t.Errorf("a NUL-carrying held message was offered the textarea that would corrupt it")
	}
	if !strings.Contains(body, "NUL") || !strings.Contains(body, "base64 editor") {
		t.Errorf("guard note does not name NUL and the console's exact-byte path")
	}
	if strings.Contains(body, "not valid UTF-8:") {
		t.Errorf("guard note falsely claims invalid UTF-8 for a valid-UTF-8 message")
	}
	id := strconv.FormatUint(h.ID, 10)
	if !strings.Contains(body, "/ui2/intercept/forward-"+id) || !strings.Contains(body, "/ui2/intercept/drop-"+id) {
		t.Errorf("NUL-carrying hold lost its untouched forward/drop actions")
	}
	if err := s.intercept.Drop(h.ID, "test cleanup"); err != nil {
		t.Fatalf("cleanup drop: %v", err)
	}
}

func TestUI2InterceptForwardNULUnchangedByteExact(t *testing.T) {
	s := newTestServer()
	original := "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 3\r\n\r\nA\x00B"
	h := ui2HoldRequest(t, s, original)
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("untouched forward of a NUL hold = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	_, raw, _, userEdited := h.Wait()
	if string(raw) != original {
		t.Errorf("untouched forward did not ship the exact NUL-carrying bytes: %q", raw)
	}
	if userEdited {
		t.Errorf("untouched forward of a NUL hold was marked user-edited")
	}
}

func TestUI2InterceptForwardNULRefusesRaw(t *testing.T) {
	s := newTestServer()
	h := ui2HoldRequest(t, s, "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 3\r\n\r\nA\x00B")
	// What the browser would have made of the field: the NUL came back as U+FFFD.
	form := url.Values{"raw": {"POST /x HTTP/1.1\nHost: a.test\n\nA\ufffdB"}}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-"+strconv.FormatUint(h.ID, 10), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("raw edit of a NUL-carrying hold = %d, want 400", rec.Code)
	}
	if n := len(s.intercept.Held()); n != 1 {
		t.Fatalf("a refused edit still resolved the hold")
	}
	if err := s.intercept.Drop(h.ID, "test cleanup"); err != nil {
		t.Fatalf("cleanup drop: %v", err)
	}
}

func TestUI2InterceptForwardMissingHeld(t *testing.T) {
	s := newTestServer()
	form := url.Values{"raw": {"GET / HTTP/1.1\r\n\r\n"}}
	req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/forward-999", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("forward-999 = %d, want 404", rec.Code)
	}
}

func TestUI2InterceptPerItemActionMalformedID(t *testing.T) {
	s := newTestServer()
	for _, action := range []string{"forward-abc", "drop-"} {
		req := httptest.NewRequest(http.MethodPost, "/ui2/intercept/"+action, nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST /ui2/intercept/%s = %d, want 400", action, rec.Code)
		}
	}
}

func TestUI2InterceptRendersHeldEditor(t *testing.T) {
	s := newTestServer()
	raw := "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n"
	h := ui2HoldRequest(t, s, raw)
	req := httptest.NewRequest(http.MethodGet, "/ui2/intercept", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui2/intercept = %d", rec.Code)
	}
	id := strconv.FormatUint(h.ID, 10)
	body := rec.Body.String()
	for _, want := range []string{
		"<textarea",
		raw,
		"/ui2/intercept/forward-" + id,
		"/ui2/intercept/drop-" + id,
		"fix_content_length",
		// The newline and byte-exactness disclosures the editor owes its operator.
		"CRLF",
		"base64 editor",
		"not marked user-edited",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("intercept page with a held item is missing %q", want)
		}
	}
	// Resolve the hold so the engine keeps nothing dangling.
	if err := s.intercept.Drop(h.ID, "test cleanup"); err != nil {
		t.Fatalf("cleanup drop: %v", err)
	}
}
