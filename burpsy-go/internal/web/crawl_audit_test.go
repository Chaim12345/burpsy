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
// by design — see crawlAuditFeed — so "the audit happened" is a statement about the audit-session
// row, not about the crawl's. There is exactly one of them however many batches ran.
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

// ---- The audit runs beside the crawl, not after it (burpsy-react-ui-7suo) -----------------------
//
// Burp's crawl→audit bridge is per-URL and event-driven: a newly-reached URL is published to the
// audit bus as it is reached, so audit work overlaps the crawl. burpsy handed the finished
// Report.Fetches to the audit engine after c.Run had returned, which made "crawl and audit" a crawl
// *then* an audit — on a twenty-minute crawl no finding could appear before minute twenty, and a
// crawl stopped at minute nineteen produced none at all despite having fetched hundreds of auditable
// exchanges.

// slowChainTarget serves a chain of pages, each linking to the next, with a delay on the pages the
// crawl walks. The delay is on the chain's own paths only, so the audit's probe traffic — which goes
// to the same server — is not slowed by the thing that exists to slow the crawl.
func slowChainTarget(t *testing.T, pages int, delay time.Duration) *httptest.Server {
	t.Helper()
	chain := map[string]string{}
	for i := 0; i < pages; i++ {
		path := "/page" + strconv.Itoa(i)
		if i == 0 {
			path = "/"
		}
		next := "/page" + strconv.Itoa(i+1)
		if i == pages-1 {
			chain[path] = `<html><body><p>end of the chain</p></body></html>`
			continue
		}
		chain[path] = `<html><body><a href="` + next + `">next</a></body></html>`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, onChain := chain[r.URL.Path]
		// Only a bare request for a chain page is a crawl fetch. A probe rewrites the query string or
		// the path, so it answers immediately and the audit is never throttled by the crawl's clock.
		if onChain && r.URL.RawQuery == "" {
			time.Sleep(delay)
		}
		w.Header().Set("Content-Type", "text/html")
		if !onChain {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`<html><body>not found</body></html>`))
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// crawlTaskState reads one crawl's row out of the registry.
func crawlTaskState(t *testing.T, s *Server, taskID uint64) (dash.Task, bool) {
	t.Helper()
	for _, task := range s.tasks.Snapshot() {
		if task.ID == taskID {
			return task, true
		}
	}
	return dash.Task{}, false
}

// The claim the whole change exists for: exchanges reach the audit half while the crawl is still
// fetching. Observed as the audit's row carrying work *before* the crawl's row leaves the running
// state — under the old batch shape the audit row did not exist at all until the crawl had finished.
func TestTheAuditOfACrawlStartsWhileTheCrawlIsStillFetching(t *testing.T) {
	target := slowChainTarget(t, 6, 300*time.Millisecond)
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	crawlTaskID := startCrawlAndAudit(t, s, target.URL+"/", map[string]any{
		"max_requests": 8, "max_depth": 8,
	})

	// Poll until the crawl's row leaves running, recording what the audit row looked like at each
	// look. The assertion is over what was true *during* the crawl, so nothing here waits for the end
	// first — that would be the batch shape and would pass either way.
	var auditSeenDuringCrawl, auditQueuedDuringCrawl uint64
	var sawAuditDuringCrawl bool
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		crawl, ok := crawlTaskState(t, s, crawlTaskID)
		if !ok {
			t.Fatalf("crawl task %d is not in the registry", crawlTaskID)
		}
		if audit, found := auditTaskFor(t, s); found && crawl.State == dash.TaskRunning {
			sawAuditDuringCrawl = true
			if audit.Total > auditQueuedDuringCrawl {
				auditQueuedDuringCrawl = audit.Total
			}
			if audit.Done > auditSeenDuringCrawl {
				auditSeenDuringCrawl = audit.Done
			}
		}
		if crawl.State != dash.TaskRunning {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !sawAuditDuringCrawl {
		t.Fatal("no audit task existed while the crawl was still running; the audit half is still a " +
			"batch that starts once the crawl is over, which is the gap this change closes")
	}
	if auditQueuedDuringCrawl == 0 {
		t.Error("the audit row existed during the crawl but was never handed an exchange; a row " +
			"registered early and fed late is the old batch with a longer-lived task")
	}
	if auditSeenDuringCrawl == 0 {
		t.Error("no exchange had been audited by the time the crawl finished; the bridge delivered " +
			"ids but no audit work overlapped the crawl, which is the capability being claimed")
	}

	// And the end state is still the honest one: everything the crawl fetched was audited.
	run := waitForCrawl(t, s, crawlTaskID)
	if run.Report == nil {
		t.Fatal("the crawl produced no report")
	}
	audit := waitForAuditTask(t, s)
	if int(audit.Total) != run.Report.Fetched || audit.Done != audit.Total {
		t.Errorf("audit done/total = %d/%d for %d fetched; running the audit early must not cost it "+
			"coverage — the incremental row still has to account for every exchange the crawl made",
			audit.Done, audit.Total, run.Report.Fetched)
	}
}

// A crawl that fetches nothing still says so. "The crawl found no exchanges to audit" and "the audit
// half did not run" are different facts, only one of them is a problem, and the row is the only place
// they are distinguishable.
func TestACrawlThatFetchesNothingStillReportsItsAuditRow(t *testing.T) {
	s := newTestServer()
	// In scope by name, and nothing listening: every fetch fails at the transport, so the crawl
	// completes with no exchange captured.
	s.scope.AddInclude("localhost")
	crawlTaskID := startCrawlAndAudit(t, s, "http://localhost:1/", nil)
	waitForCrawl(t, s, crawlTaskID)

	audit := waitForAuditTask(t, s)
	if audit.Total != 0 || audit.Done != 0 {
		t.Errorf("audit done/total = %d/%d for a crawl that captured nothing", audit.Done, audit.Total)
	}
	if !strings.Contains(audit.Note, "no exchanges to audit") {
		t.Errorf("the empty audit's note is %q; a row that does not say why it is empty cannot be "+
			"told apart from an audit that silently skipped its work", audit.Note)
	}
}
