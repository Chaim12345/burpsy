package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
)

// ---- Crawl and audit (Burp's default scan kind) ------------------------------------------------
//
// Burp's New-scan dialog offers "Crawl and audit" as its primary workflow and burpsy could only
// launch the crawl half, so the audit of what a crawl found was reachable only as the always-on live
// sweep over proxied traffic. These pin the seam: the crawl's own exchanges are handed to the audit
// engine, and the audit reports itself as its own measurable task rather than as a number folded into
// the crawl's request count.

// crawlsForAuditTarget reads the audit task's row out of the registry. A crawl-and-audit is two rows
// by design — see auditCrawledExchanges — so "the audit happened" is a statement about the
// audit-session row, not about the crawl's.
func auditTaskFor(t *testing.T, s *Server) (dash.Task, bool) {
	t.Helper()
	for _, task := range s.tasks.Snapshot() {
		if task.Kind == dash.KindAuditSession {
			return task, true
		}
	}
	return dash.Task{}, false
}

// waitForAuditTask waits for the audit half to appear and finish, returning its row. The crawl's own
// run is marked finished *before* the audit starts, so a test that waited only on the crawl would be
// racing the phase under test.
func waitForAuditTask(t *testing.T, s *Server) dash.Task {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if task, ok := auditTaskFor(t, s); ok && !task.Running() {
			return task
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the audit half of the crawl-and-audit never finished; a launched scan that silently skips its audit is the defect this feature exists to remove")
	return dash.Task{}
}

// startCrawlAndAudit launches a crawl-and-audit against target and returns the task id.
func startCrawlAndAudit(t *testing.T, s *Server, seed string, extra map[string]any) uint64 {
	t.Helper()
	body := map[string]any{
		"seeds":        []string{seed},
		"kind":         "crawl-audit",
		"max_requests": 5,
		"max_depth":    2,
	}
	for k, v := range extra {
		body[k] = v
	}
	rec := postJSON(t, s, "/api/crawl", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: status = %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var start struct {
		TaskID uint64 `json:"task_id"`
		Kind   string `json:"kind"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if start.Kind != "crawl-audit" {
		t.Errorf("202 echoed kind = %q, want %q — the reply must say which kind the server took, or a "+
			"caller cannot tell an accepted audit from one silently downgraded to a crawl", start.Kind, "crawl-audit")
	}
	return start.TaskID
}

// linkTarget serves a two-page site, which is enough for a crawl to have more than one exchange to
// audit.
func linkTarget(t *testing.T) *httptest.Server {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><body><a href="/second">second</a></body></html>`))
			return
		}
		w.Write([]byte(`<html><body>leaf</body></html>`))
	}))
	t.Cleanup(target.Close)
	return target
}

// The core claim: a crawl-and-audit audits the exchanges the crawl itself produced, and reports that
// audit as its own task whose total is the number of exchanges it was given.
func TestCrawlAndAuditAuditsTheExchangesTheCrawlFetched(t *testing.T) {
	target := linkTarget(t)
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	crawlTaskID := startCrawlAndAudit(t, s, target.URL+"/", nil)
	run := waitForCrawl(t, s, crawlTaskID)
	if run.Report == nil {
		t.Fatal("the crawl produced no report")
	}
	fetched := run.Report.Fetched

	audit := waitForAuditTask(t, s)
	if int(audit.Total) != fetched {
		t.Errorf("audit total = %d, want %d — the audit's own total must be the exchanges the crawl "+
			"fetched, or its progress means nothing an operator can check", audit.Total, fetched)
	}
	if audit.Done != audit.Total {
		t.Errorf("audit done/total = %d/%d; a finished audit that did not advance through every "+
			"exchange it was given is a run that stopped looking", audit.Done, audit.Total)
	}
	if audit.State != dash.TaskDone {
		t.Errorf("audit state = %s, want done", audit.State)
	}
	if audit.Target == "" {
		t.Error("audit task has no target; a row naming no run is a row an operator cannot act on")
	}
}

// The audit is over this crawl's exchanges and nobody else's. An exchange the operator's own client
// proxied before the scan started is in the store and auditable, and the scan must not claim it.
func TestCrawlAndAuditAuditsOnlyTheCrawlsOwnExchanges(t *testing.T) {
	target := linkTarget(t)
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	// One complete proxied exchange, with a response, so it is a genuinely auditable row rather than
	// one the audit would skip for having nothing to look at.
	recordCompleteExchange(t, s, "h.test", "/proxied-before-the-scan")

	crawlTaskID := startCrawlAndAudit(t, s, target.URL+"/", nil)
	run := waitForCrawl(t, s, crawlTaskID)
	if run.Report == nil {
		t.Fatal("the crawl produced no report")
	}
	audit := waitForAuditTask(t, s)
	if int(audit.Total) != run.Report.Fetched {
		t.Errorf("audit total = %d with %d crawl fetches and one pre-existing proxied exchange; the "+
			"audit must cover exactly what the crawl fetched, never everything recorded since it started",
			audit.Total, run.Report.Fetched)
	}
}

// The crawl's own exchanges are attributed to the crawl's task, which is what makes "show me the
// traffic this scan produced" answerable — and what a later per-scan view will read.
func TestACrawlsExchangesCarryItsTaskID(t *testing.T) {
	target := linkTarget(t)
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	crawlTaskID := startCrawlAndAudit(t, s, target.URL+"/", nil)
	waitForCrawl(t, s, crawlTaskID)
	waitForAuditTask(t, s)

	var attributed, crawlish int
	for _, ex := range s.store.Exchanges() {
		if ex.Source != core.SourceCrawl {
			continue
		}
		crawlish++
		if ex.TaskID == crawlTaskID {
			attributed++
		}
	}
	if crawlish == 0 {
		t.Fatal("no exchanges were attributed to the crawler at all; the store saw nothing")
	}
	if attributed != crawlish {
		t.Errorf("%d of %d crawled exchanges carry task %d; an exchange whose run is unrecorded "+
			"cannot be traced back to the scan that made it", attributed, crawlish, crawlTaskID)
	}
}

// A plain crawl stays a plain crawl: no audit phase, no audit task, and the reply says so.
func TestAPlainCrawlRegistersNoAuditTask(t *testing.T) {
	target := linkTarget(t)
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	// No kind at all — the shape every caller predating the field sends.
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds": []string{target.URL + "/"}, "max_requests": 5, "max_depth": 2,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var start struct {
		TaskID uint64 `json:"task_id"`
		Kind   string `json:"kind"`
	}
	json.Unmarshal(rec.Body.Bytes(), &start)
	if start.Kind != "crawl" {
		t.Errorf("omitted kind echoed as %q, want %q", start.Kind, "crawl")
	}
	run := waitForCrawl(t, s, start.TaskID)
	if run.State != "done" {
		t.Fatalf("crawl state = %q (%s)", run.State, run.Error)
	}
	if task, ok := auditTaskFor(t, s); ok {
		t.Errorf("a plain crawl registered an audit task %q; the audit half must run only when it was asked for", task.Kind)
	}
}

// An unrecognised kind is refused, and the refusal names the kinds that exist. This is the typo an
// operator actually types — Burp's own card is labelled "Crawl and audit" — and silently running a
// plain crawl instead would leave them waiting for findings nothing was going to produce.
func TestAnUnknownScanKindIsRefusedAndNamesTheKindsThatExist(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds": []string{"https://demo.local/"},
		"kind":  "crawl-and-audit",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"crawl-and-audit", `"crawl"`, `"crawl-audit"`} {
		if !strings.Contains(body, want) {
			t.Errorf("refusal %q does not name %s; a refusal that does not say what is accepted leaves "+
				"the operator guessing", body, want)
		}
	}
	listing := get(t, s, "/api/crawl")
	var runs struct {
		Crawls []struct {
			TaskID uint64 `json:"task_id"`
		} `json:"crawls"`
	}
	json.Unmarshal(listing.Body.Bytes(), &runs)
	if len(runs.Crawls) != 0 {
		t.Errorf("a refused kind registered %d run(s); it must not appear as a task at all", len(runs.Crawls))
	}
}

// The retained run carries the kind, so an operator can ask what kind a scan from this morning was —
// and so a downgrade would be visible rather than inferred from absent findings.
func TestTheRetainedRunReportsItsScanKind(t *testing.T) {
	target := linkTarget(t)
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	taskID := startCrawlAndAudit(t, s, target.URL+"/", nil)
	waitForCrawl(t, s, taskID)
	waitForAuditTask(t, s)

	rec := get(t, s, "/api/crawl?task="+strconv.FormatUint(taskID, 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/crawl?task=%d: status = %d (%s)", taskID, rec.Code, rec.Body.String())
	}
	var run struct {
		Kind string `json:"kind"`
	}
	json.Unmarshal(rec.Body.Bytes(), &run)
	if run.Kind != "crawl-audit" {
		t.Errorf("retained run kind = %q, want %q", run.Kind, "crawl-audit")
	}
}

// recordCompleteExchange stores a request and a response and records an exchange holding both, so a
// row exists that an audit would genuinely consider.
func recordCompleteExchange(t *testing.T, s *Server, host, path string) {
	t.Helper()
	reqID, err := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	status := uint16(200)
	ex := &core.Exchange{
		Request:  reqID,
		Response: &respID,
		Host:     host,
		Port:     80,
		Method:   "GET",
		Path:     path,
		Status:   &status,
		Mime:     "text/html",
		Source:   core.SourceProxy,
	}
	s.store.AddExchange(ex)
}
