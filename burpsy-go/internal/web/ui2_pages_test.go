package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
