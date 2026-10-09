package web

// Burp's "Run isolated scan" (burpsy-react-ui-13uw): an isolated scan's traffic and the issues found
// only on it stay out of the site map and All issues; a task's own view can still ask for them.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func addSourcedExchange(t *testing.T, s *Server, host, path string, src core.Source) core.ExchangeID {
	t.Helper()
	reqID, _ := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), core.DirectionResponse)
	ex := &core.Exchange{Host: host, Port: 80, Method: "GET", Path: path, Request: core.MsgPtr(reqID), Response: core.MsgPtr(respID), Source: src}
	s.store.AddExchange(ex)
	return ex.ID
}

func TestIsolatedFindingsStayOffAllIssuesButATaskCanAsk(t *testing.T) {
	s := newTestServer()
	iso := addSourcedExchange(t, s, "iso.test", "/a", core.SourceIsolatedScan)
	norm := addSourcedExchange(t, s, "norm.test", "/b", core.SourceCrawl)
	s.findings.Add(core.NewFinding{Name: "only isolated", Severity: core.SeverityLow, Occurrences: []core.Occurrence{{ExchangeID: iso}}})
	s.findings.Add(core.NewFinding{Name: "ordinary", Severity: core.SeverityLow, Occurrences: []core.Occurrence{{ExchangeID: norm}}})

	all := get(t, s, "/api/issues").Body.String()
	if strings.Contains(all, "only isolated") || !strings.Contains(all, "ordinary") {
		t.Errorf("All issues must omit the isolated finding and keep the other: %s", all)
	}
	with := get(t, s, "/api/issues?include_isolated=1").Body.String()
	if !strings.Contains(with, "only isolated") || !strings.Contains(with, `"isolated":true`) {
		t.Errorf("include_isolated must return it flagged: %s", with)
	}
	// The route declares include_isolated a boolean for the MCP surface, so "true" — what an agent
	// sends for a boolean — must mean what "1" means.
	if agent := get(t, s, "/api/issues?include_isolated=true").Body.String(); !strings.Contains(agent, "only isolated") {
		t.Errorf("include_isolated=true must return the isolated finding: %s", agent)
	}
}

func TestAnIsolatedCrawlStaysOffTheSiteMap(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/next">n</a>`))
	}))
	defer origin.Close()
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{origin.URL + "/"}, "isolated": true, "max_requests": 5})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("crawl = %d %s", rec.Code, rec.Body.String())
	}
	var start crawlStartResp
	json.Unmarshal(rec.Body.Bytes(), &start)
	run := waitForCrawl(t, s, start.TaskID)
	if run.Report == nil || run.Report.Fetched == 0 {
		t.Fatalf("the isolated crawl fetched nothing: %+v", run.Report)
	}
	for _, ex := range s.store.Exchanges() {
		if ex.Source != core.SourceIsolatedScan {
			t.Errorf("exchange %d has source %q, want isolated-scan", ex.ID, ex.Source)
		}
	}
	if hosts := s.sitemap.Hosts(); len(hosts) != 0 {
		t.Errorf("an isolated crawl reached the site map: %d host(s)", len(hosts))
	}
}
