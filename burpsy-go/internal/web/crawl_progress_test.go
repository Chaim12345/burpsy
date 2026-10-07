package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
)

func crawlTask(s *Server, id uint64) (dash.Task, bool) {
	for _, t := range s.tasks.Snapshot() {
		if t.ID == id {
			return t, true
		}
	}
	return dash.Task{}, false
}

func startTestCrawl(t *testing.T, s *Server, body map[string]any) uint64 {
	t.Helper()
	rec := postJSON(t, s, "/api/crawl", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl = %d: %s", rec.Code, rec.Body.String())
	}
	var start crawlStartResp
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	return start.TaskID
}

// burpsy-react-ui-hbjo criterion 1: the task row moves while the crawl is still running. The origin
// holds its last page open until the test releases it, so the crawl is provably mid-flight when the
// row is read — a row that only advanced after Run returned reads 0 here.
func TestACrawlsTaskRowAdvancesWhileTheCrawlIsStillRunning(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	releaseOrigin := func() { once.Do(func() { close(release) }) }
	defer releaseOrigin()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><body><a href="/a">a</a><a href="/b">b</a><a href="/slow">slow</a></body></html>`))
		case "/slow":
			<-release
			w.Write([]byte(`<html><body>slow</body></html>`))
		default:
			w.Write([]byte(`<html><body>leaf</body></html>`))
		}
	}))
	defer target.Close()

	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())
	id := startTestCrawl(t, s, map[string]any{"seeds": []string{target.URL + "/"}, "max_requests": 20, "max_depth": 2})

	deadline := time.Now().Add(10 * time.Second)
	var mid dash.Task
	for time.Now().Before(deadline) {
		task, ok := crawlTask(s, id)
		if ok && task.State == dash.TaskRunning && task.Done >= 2 {
			mid = task
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if mid.Done < 2 {
		task, _ := crawlTask(s, id)
		t.Fatalf("while the crawl was held mid-flight the task row read done=%d state=%v — it does not move "+
			"until the crawl ends, so a long crawl looks hung", task.Done, task.State)
	}

	releaseOrigin()
	run := waitForCrawl(t, s, id)
	if run.Report == nil {
		t.Fatal("finished crawl has no report")
	}
	final, _ := crawlTask(s, id)
	if final.Done != uint64(run.Report.Fetched) {
		t.Errorf("final done = %d, report fetched = %d: the live advances and the closing credit must add up "+
			"to the report, neither double-counted nor short", final.Done, run.Report.Fetched)
	}
}

// burpsy-react-ui-z8qf through the API: with seed_from_site_map, a request the site map already holds
// is not fetched again and the saving is reported; the crawl's own seed is still fetched. Without the
// flag nothing changes — the default crawl is untouched.
func TestSeedFromSiteMapSkipsKnownRequestsButNeverTheSeed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		seed      bool
		wantKnown bool // whether /known is fetched
	}{
		{"default crawl fetches everything", false, true},
		{"seeded crawl spares the known request", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rootHits, knownHits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				switch r.URL.Path {
				case "/":
					rootHits.Add(1)
					w.Write([]byte(`<html><body><a href="/known">known</a><a href="/new">new</a></body></html>`))
				case "/known":
					knownHits.Add(1)
					w.Write([]byte(`<html><body>known</body></html>`))
				default:
					w.Write([]byte(`<html><body>leaf</body></html>`))
				}
			}))
			defer target.Close()

			s := newTestServer()
			u, _ := url.Parse(target.URL)
			port, _ := strconv.Atoi(u.Port())
			s.scope.AddInclude(u.Hostname())
			// The site map already knows "/" (the operator browsed it) and "/known".
			for _, p := range []string{"/", "/known"} {
				s.sitemap.Add(&core.Exchange{Host: u.Hostname(), Port: uint16(port), Method: "GET", Path: p})
			}

			id := startTestCrawl(t, s, map[string]any{
				"seeds": []string{target.URL + "/"}, "max_requests": 10, "max_depth": 2,
				"seed_from_site_map": tc.seed,
			})
			run := waitForCrawl(t, s, id)
			if run.State != "done" {
				t.Fatalf("crawl state = %q (%s)", run.State, run.Error)
			}
			if rootHits.Load() == 0 {
				t.Fatal("the crawl's own seed was never fetched — seeding dropped the starting point")
			}
			if got := knownHits.Load() > 0; got != tc.wantKnown {
				t.Errorf("/known fetched = %v, want %v", got, tc.wantKnown)
			}

			rec := get(t, s, "/api/crawl?task="+strconv.FormatUint(id, 10))
			var raw struct {
				Report struct {
					SitemapSeeded int `json:"sitemap_seeded"`
				} `json:"report"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if tc.seed && raw.Report.SitemapSeeded != 1 {
				t.Errorf("sitemap_seeded = %d, want 1 (/known only — the seed is exempt)", raw.Report.SitemapSeeded)
			}
			if !tc.seed && raw.Report.SitemapSeeded != 0 {
				t.Errorf("an unseeded crawl reports sitemap_seeded = %d", raw.Report.SitemapSeeded)
			}
		})
	}
}

// burpsy-react-ui-o0c5 AC1 at the API: the four crawler.error_handling keys are accepted on a crawl
// request under Burp's names, 0 is a real value (Burp's "Never stop" ships all three thresholds at 0),
// and a value no crawl can honour is a 400 naming the key rather than a crawl that quietly ignores it.
func TestCrawlRequestTakesTheErrorHandlingKeysAndZeroIsAnAnswer(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer target.Close()
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	id := startTestCrawl(t, s, map[string]any{
		"seeds": []string{target.URL + "/"}, "max_requests": 5,
		"pause_task_requests_timed_out_count":                     0,
		"pause_task_requests_timed_out_percentage":                0,
		"consecutive_authentication_failures_before_pausing_task": 0,
		"number_of_follow_up_passes":                              0,
	})
	if run := waitForCrawl(t, s, id); run.State != "done" {
		t.Fatalf("a crawl with every error-handling key at 0 = %q (%s); 0 must be accepted", run.State, run.Error)
	}

	for key, bad := range map[string]int{
		"consecutive_authentication_failures_before_pausing_task": 11, // Burp's panel caps it at 10
		"pause_task_requests_timed_out_percentage":                101,
		"pause_task_requests_timed_out_count":                     -1,
	} {
		rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{target.URL + "/"}, key: bad})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), key) {
			t.Errorf("%s=%d = %d %q, want 400 naming the key", key, bad, rec.Code, rec.Body.String())
		}
	}
}
