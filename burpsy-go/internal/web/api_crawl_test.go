package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// ---- The crawl endpoint ------------------------------------------------------------------------
//
// internal/crawler was a complete, tested engine that nothing outside its own tests imported: no CLI
// flag and no route could start one, so at runtime it did not exist. These pin the seam that makes it
// reachable, and — the part that actually matters — that reaching it did not also route around the
// scope gate every other burpsy tool goes through.

// crawlStartResp is the 202 body.
type crawlStartResp struct {
	TaskID uint64   `json:"task_id"`
	Seeds  []string `json:"seeds"`
	State  string   `json:"state"`
}

// crawlRunResp mirrors crawlRun for decoding, with only the fields these tests assert on.
type crawlRunResp struct {
	TaskID uint64 `json:"task_id"`
	State  string `json:"state"`
	Error  string `json:"error,omitempty"`
	Report *struct {
		Fetched int `json:"fetched"`
		Refused int `json:"refused"`
		Failed  int `json:"failed"`
		Skips   struct {
			Counts []struct {
				Name  string `json:"name"`
				Count int    `json:"count"`
			} `json:"counts"`
		} `json:"skips"`
	} `json:"report,omitempty"`
}

// skipCount reads one named skip category out of a report.
func (r crawlRunResp) skipCount(name string) int {
	if r.Report == nil {
		return 0
	}
	for _, c := range r.Report.Skips.Counts {
		if c.Name == name {
			return c.Count
		}
	}
	return 0
}

// waitForCrawl polls until the crawl leaves the running state. A crawl is asynchronous by design —
// it outlives the request that started it — so a test that read the report immediately would be
// asserting on a race rather than on the outcome.
func waitForCrawl(t *testing.T, s *Server, taskID uint64) crawlRunResp {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rec := get(t, s, "/api/crawl?task="+strconv.FormatUint(taskID, 10))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/crawl?task=%d: status = %d (%s)", taskID, rec.Code, rec.Body.String())
		}
		var run crawlRunResp
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode crawl run: %v", err)
		}
		if run.State != "running" {
			return run
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("crawl %d did not finish within the deadline", taskID)
	return crawlRunResp{}
}

// A crawl starts, fetches the seed and the page it links to, and the traffic lands in the store
// through the shared capture path — which is what makes it visible in history and the site map.
func TestACrawlFetchesItsSeedAndTheLinksItFinds(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><body><a href="/second">second</a></body></html>`))
		default:
			w.Write([]byte(`<html><body>leaf</body></html>`))
		}
	}))
	defer target.Close()

	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":        []string{target.URL + "/"},
		"max_requests": 5,
		"max_depth":    2,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: status = %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var start crawlStartResp
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start response: %v", err)
	}

	run := waitForCrawl(t, s, start.TaskID)
	if run.State != "done" {
		t.Fatalf("crawl state = %q (%s), want done", run.State, run.Error)
	}
	if run.Report == nil {
		t.Fatal("finished crawl has no report; the coverage story is the whole deliverable")
	}
	if run.Report.Fetched < 2 {
		t.Errorf("fetched = %d, want at least 2 — the seed and the page it links to", run.Report.Fetched)
	}
	if n := len(s.store.Exchanges()); n < 2 {
		t.Errorf("store holds %d exchanges, want at least 2 — a crawl must capture through the shared path so its traffic reaches history and the site map", n)
	}
}

// The point of the seam: reaching the crawler from the API must not route around the scope gate.
// A seed outside the engagement scope is refused rather than fetched.
func TestACrawlSeedOutsideTheScopeIsRefusedNotFetched(t *testing.T) {
	var reached int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.Write([]byte("should never be served"))
	}))
	defer target.Close()

	s := newTestServer()
	// Scope names a host the target is not, so nothing about this crawl is authorised.
	s.scope.AddInclude("someone-else.test")

	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":        []string{target.URL + "/"},
		"max_requests": 5,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: status = %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var start crawlStartResp
	json.Unmarshal(rec.Body.Bytes(), &start)

	run := waitForCrawl(t, s, start.TaskID)
	if reached != 0 {
		t.Errorf("the target was reached %d time(s); an out-of-scope crawl must never put a request on the wire", reached)
	}
	if run.Report == nil {
		t.Fatal("no report")
	}
	if run.Report.Fetched != 0 {
		t.Errorf("fetched = %d, want 0", run.Report.Fetched)
	}
	// Counted as an out-of-scope *skip*, not as Refused. Refused is the send-path chokepoint — a URL
	// that got as far as being sent and was stopped there. A seed the scope rejects at admission never
	// enters the frontier, so it is a skip, and the skip record carries the URL and the reason
	// ("matches no include rule") rather than just incrementing a counter. Asserting on the count that
	// the engine actually keeps, rather than the one that seemed likely.
	if n := run.skipCount("out-of-scope"); n == 0 {
		t.Error("out-of-scope skips = 0; the refusal must be counted and attributable, not silently dropped")
	}
}

// A crawl with no seeds is a configuration mistake the operator can fix, so it is a 400 rather than a
// task that appears on the dashboard only to fail.
func TestACrawlWithNoSeedsIsRefusedUpFront(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{"   "}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	listing := get(t, s, "/api/crawl")
	var body struct {
		Crawls []crawlRunResp `json:"crawls"`
	}
	json.Unmarshal(listing.Body.Bytes(), &body)
	if len(body.Crawls) != 0 {
		t.Errorf("a refused crawl registered %d run(s); it must not appear as a task at all", len(body.Crawls))
	}
}
