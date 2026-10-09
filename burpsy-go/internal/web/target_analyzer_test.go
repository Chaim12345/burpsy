package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func analyzerExchange(t *testing.T, s *Server, host string, port uint16, tls bool, raw string) {
	t.Helper()
	line, _, _ := strings.Cut(raw, "\r\n")
	fields := strings.Fields(line)
	req, err := s.store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), core.DirectionResponse)
	s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(req), Response: &resp, Host: host, Port: port, TLS: tls,
		Method: fields[0], Path: fields[1]})
}

// Burp's Target analyzer (burpsy-react-ui-dnvi) through its route, over captured content.
func TestTheTargetAnalyzerCountsDynamicAndStaticURLsAndParameters(t *testing.T) {
	s := newTestServer()
	analyzerExchange(t, s, "shop.test", 443, true, "GET /search?q=1&page=2 HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	analyzerExchange(t, s, "shop.test", 443, true, "GET /search?q=7&sort=asc HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	analyzerExchange(t, s, "shop.test", 443, true, "POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&q=x")
	analyzerExchange(t, s, "shop.test", 443, true, "GET /static/app.css HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	analyzerExchange(t, s, "other.test", 443, true, "GET /x?y=1 HTTP/1.1\r\nHost: other.test\r\n\r\n")

	rec := get(t, s, "/api/target/analyze?host=shop.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body.String())
	}
	var report analyzerReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	want := analyzerSummary{DynamicURLs: 2, StaticURLs: 1, Parameters: 5, UniqueParameterNames: 4}
	if report.Summary != want {
		t.Errorf("summary = %+v, want %+v (/search: q, page, sort; /login: user, q)", report.Summary, want)
	}
	if len(report.Parameters) == 0 || report.Parameters[0].Name != "q" || report.Parameters[0].URLCount != 2 {
		t.Errorf("parameters = %+v, want q first, in 2 URLs", report.Parameters)
	}
	for _, u := range report.Dynamic {
		if strings.Contains(u.URL, "other.test") || strings.Contains(u.URL, "?") {
			t.Errorf("dynamic URL %q: another host, or a query in the URL key", u.URL)
		}
	}
	if len(report.Dynamic) == 2 && report.Dynamic[0].Requests != 1 && report.Dynamic[1].Requests != 2 {
		t.Errorf("request counts %+v", report.Dynamic)
	}

	// A branch narrows to its path prefix, and an empty answer is arrays, not null.
	branch := get(t, s, "/api/target/analyze?host=shop.test&path=/static").Body.String()
	if !strings.Contains(branch, `"dynamic":[]`) || !strings.Contains(branch, `"static_urls":1`) {
		t.Errorf("branch /static = %s", branch)
	}
	none := get(t, s, "/api/target/analyze?host=nothing.test").Body.String()
	if !strings.Contains(none, `"dynamic":[],"static":[],"parameters":[]`) {
		t.Errorf("an empty analysis must marshal arrays: %s", none)
	}
	if rec := get(t, s, "/api/target/analyze"); rec.Code != http.StatusBadRequest {
		t.Errorf("no host = %d", rec.Code)
	}

	html := get(t, s, "/api/target/analyze?host=shop.test&format=html")
	if !strings.Contains(html.Header().Get("Content-Disposition"), "attachment") ||
		!strings.Contains(html.Body.String(), "<th>Dynamic URLs</th><td>2</td>") {
		t.Errorf("html report = %q %q", html.Header().Get("Content-Disposition"), html.Body.String())
	}
}

// A captured path that carries markup is text in the saved report, never markup.
func TestTheSavedAnalyzerReportEscapesCapturedPaths(t *testing.T) {
	s := newTestServer()
	analyzerExchange(t, s, "x.test", 80, false, "GET /<script>alert(1)</script>?a=1 HTTP/1.1\r\nHost: x.test\r\n\r\n")
	body := get(t, s, "/api/target/analyze?host=x.test&format=html").Body.String()
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("a captured path was emitted as markup in the saved report")
	}
}
