package web

// The rendered-DOM audit over a crawl's locations (burpsy-react-ui-xuim), end to end.
//
// The unit half (which rendered pages count as script-created content) is pinned in
// internal/scanner/crawl_dom_audit_test.go; these pin the CRAWL half: that a crawl-and-audit
// with a browser renders its distinct locations, files the SPA fixture as a visibility finding
// and stays silent on the static twin, and that a crawl WITHOUT a browser reports the omission
// on the Report's own block rather than as an absent block that reads as "found nothing".

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// crawlRenderedResp mirrors the fields of the crawl run these tests assert on.
type crawlRenderedResp struct {
	TaskID uint64 `json:"task_id"`
	State  string `json:"state"`
	Error  string `json:"error,omitempty"`
	Report *struct {
		// Rendered is the report's rendered-audit block, decoded only when the pass ran.
		RenderedAudit *struct {
			Candidates int    `json:"candidates"`
			NoScript   int    `json:"no_script"`
			Capped     int    `json:"capped"`
			Rendered   int    `json:"rendered"`
			Failed     int    `json:"failed"`
			ScriptOnly int    `json:"script_only"`
			Declined   string `json:"declined,omitempty"`
		} `json:"rendered_audit"`
	} `json:"report,omitempty"`
}

// spaCrawlTarget serves the two fixture pages from the scanner's own vulnapp, addressed like a
// real target: the crawl fetches them over HTTP, and the pass renders them in a browser.
func spaCrawlTarget(t *testing.T) *httptest.Server {
	t.Helper()
	// vulnapp's DOM family plus one script-free page served from the same origin, so a single
	// crawl's location set contains both shapes: the NoScript gate has something real to skip
	// and the e2e test can assert it did (a pass that rendered script-free pages would be pure
	// cost with no finding to show for it).
	mux := http.NewServeMux()
	mux.HandleFunc("/plain", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html><body><p>a script-free page the wire and the browser both see whole</p></body></html>"))
	})
	mux.Handle("/", vulnapp.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// A crawl with a browser finds the SPA page's script-created content and stays silent on the
// static twin: the bead's criterion 4, both halves.
func TestACrawlWithABrowserReportsTheScriptCreatedContentItRendered(t *testing.T) {
	if os.Getenv("BURPSY_ALLOW_NO_CHROME") == "1" {
		t.Skip("BURPSY_ALLOW_NO_CHROME=1: this test needs the browser it exists to exercise")
	}
	target := spaCrawlTarget(t)
	u, _ := url.Parse(target.URL)

	s := newTestServer()
	s.scope.AddInclude(u.Hostname())
	// The same lazy provider the shipped binary attaches: naming no engine searches PATH, so
	// the provider is constructed without starting anything and the first render is the launch.
	audit := scanner.NewActiveScanner(s.store, zap.NewNop()).
		WithScope(s.scope).
		WithBrowserProvider(scanner.NewLazyBrowserProvider(domexec.Options{}))
	s = s.WithScanner(audit)

	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":        []string{target.URL + "/dm/spa", target.URL + "/dm/safe/spa", target.URL + "/plain"},
		"max_requests": 10,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var start crawlStartResp
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	run := waitForRenderedCrawl(t, s, start.TaskID)
	if run.State != "done" {
		t.Fatalf("crawl state = %q (%s), want done", run.State, run.Error)
	}
	for _, e := range s.events.Recent(50) {
		t.Logf("event: %s %s", e.Kind, e.Detail)
	}
	if run.Report != nil {
		for i, f := range repFetches(t, s, start.TaskID) {
			t.Logf("fetch %d: %s fp=%q", i, f.URL, f.Fingerprint[:min(12, len(f.Fingerprint))])
		}
	}
	for _, f := range s.findings.All() {
		t.Logf("finding: %s", f.Name)
	}
	if run.Report == nil || run.Report.RenderedAudit == nil {
		t.Fatal("finished crawl has no rendered-audit block: a crawl WITH a browser that rendered " +
			"nothing must say so with a block of zeroes, because an absent block is the no-browser shape")
	}
	block := run.Report.RenderedAudit
	if block.Declined != "" {
		t.Fatalf("rendered audit declined: %s", block.Declined)
	}
	if block.Rendered < 2 {
		t.Errorf("rendered = %d, want at least the two seed locations (candidates %d)", block.Rendered, block.Candidates)
	}
	// The /plain seed is script-free by construction, and the crawl's own rendered-discovery
	// pass (nx7b) drags in vulnapp's 404 pages, which are script-free too — so the exact count
	// depends on how many links the SPA page built. What is pinned is that the gate FIRED: /plain
	// lands in NoScript, not in Rendered.
	if block.NoScript < 1 {
		t.Errorf("no_script = %d, want at least 1: the /plain location carries no script, so a browser "+
			"could not reveal anything the wire pass did not see — rendering it would be pure cost, and "+
			"the count is what says the gate fired rather than the page silently rendering anyway", block.NoScript)
	}
	if block.ScriptOnly != 1 {
		t.Errorf("script_only = %d, want exactly 1: the SPA fixture creates content the wire never "+
			"carried and the static twin must stay silent — any other number is either a false positive "+
			"on the twin or a miss on the SPA page", block.ScriptOnly)
	}

	// And the finding itself exists, cites the crawl's own exchange, and is INFO: content
	// existing is a visibility fact, not a vulnerability.
	found := false
	for _, f := range s.findings.All() {
		if f.Name != "Content visible only after script runs" {
			continue
		}
		found = true
		if f.Severity != core.SeverityInformational {
			t.Errorf("finding severity = %v, want info: script-created content is a coverage fact, "+
				"and inflating it would train operators to ignore the row", f.Severity)
		}
		var citesSPA bool
		for _, occ := range f.Occurrences {
			if ex, err := s.store.GetExchange(occ.ExchangeID); err == nil && ex.Path == "/dm/spa" {
				citesSPA = true
			}
		}
		if !citesSPA {
			t.Errorf("finding does not cite the /dm/spa exchange: %v", f.Occurrences)
		}
	}
	if !found {
		t.Error("no 'Content visible only after script runs' finding: the rendered pass found the " +
			"content (script_only is non-zero above) but nothing landed in the finding store")
	}
}

// A crawl without a browser reports the omission on the Report's own block — Declined with the
// candidate count — never as an absent block that would read as "the pass found nothing"
// (criterion 3).
func TestACrawlWithoutABrowserReportsTheOmissionNotSilence(t *testing.T) {
	target := spaCrawlTarget(t)
	u, _ := url.Parse(target.URL)

	s := newTestServer()
	s.scope.AddInclude(u.Hostname())

	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":        []string{target.URL + "/dm/spa"},
		"max_requests": 5,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var start crawlStartResp
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	run := waitForRenderedCrawl(t, s, start.TaskID)
	if run.State != "done" {
		t.Fatalf("crawl state = %q (%s)", run.State, run.Error)
	}
	if run.Report == nil || run.Report.RenderedAudit == nil {
		t.Fatal("no rendered-audit block on a browser-less crawl: the omission must be stated, " +
			"because a nil block is indistinguishable from a pass that ran and found nothing")
	}
	block := run.Report.RenderedAudit
	if block.Declined == "" {
		t.Error("rendered-audit block has no Declined reason on a browser-less crawl: the operator " +
			"is told the locations were never rendered, not left to infer it from dom_engine = off")
	}
	if block.Candidates == 0 {
		t.Error("the declined block carries no candidate count: 'N locations existed and none were " +
			"looked at' is the honest shape of the omission, and N is the part that makes it actionable")
	}
	if block.Rendered != 0 || block.ScriptOnly != 0 {
		t.Errorf("a declined pass must not also claim renders: rendered=%d script_only=%d", block.Rendered, block.ScriptOnly)
	}
}

// waitForRenderedCrawl is waitForCrawl with a longer deadline: a crawl that renders its
// locations in a real browser takes as long as the renders take (seconds per page, not
// milliseconds), and the shorter helper's 15s would turn a slow machine into a false failure.
func waitForRenderedCrawl(t *testing.T, s *Server, taskID uint64) crawlRenderedResp {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		rec := get(t, s, "/api/crawl?task="+strconv.FormatUint(taskID, 10))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/crawl?task=%d: status = %d (%s)", taskID, rec.Code, rec.Body.String())
		}
		var run crawlRenderedResp
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode crawl run: %v", err)
		}
		if run.State != "running" {
			return run
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("crawl %d did not finish within the deadline", taskID)
	return crawlRenderedResp{}
}

// repFetches decodes the run's full fetch list for debugging; the test's own decode type
// above only carries the rendered-audit block.
func repFetches(t *testing.T, s *Server, taskID uint64) []struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
} {
	t.Helper()
	rec := get(t, s, "/api/crawl?task="+strconv.FormatUint(taskID, 10))
	var raw struct {
		Report *struct {
			Fetches []struct {
				URL         string `json:"url"`
				Fingerprint string `json:"fingerprint"`
			} `json:"fetches"`
		} `json:"report"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil || raw.Report == nil {
		return nil
	}
	return raw.Report.Fetches
}
