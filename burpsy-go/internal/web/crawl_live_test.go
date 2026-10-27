package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// slowSite serves a chain of structurally distinct pages, each a little slow, so a test can watch the
// crawl while it is still running.
func slowSite(t *testing.T, pages int, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/p%d", &n); err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Each page nests one level deeper than the last, so the location fingerprint differs.
		body := fmt.Sprintf("<h1>page %d</h1>", n) + strings.Repeat("<div>", n) + "x" + strings.Repeat("</div>", n)
		if n < pages {
			body += fmt.Sprintf(`<a href="/p%d">next</a>`, n+1)
		}
		_, _ = w.Write([]byte("<html><body>" + body + "</body></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type liveResp struct {
	TaskID  uint64 `json:"task_id"`
	State   string `json:"state"`
	Phase   string `json:"phase"`
	Current *struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"current"`
	Fetched int `json:"fetched"`
	Recent  []struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
	} `json:"recent"`
	Browser bool `json:"browser"`
	Frame   *struct {
		URL   string `json:"url"`
		Image string `json:"image"`
	} `json:"frame"`
	FrameNote string `json:"frame_note"`
	LastPage  *struct {
		URL        string `json:"url"`
		ExchangeID uint64 `json:"exchange_id"`
	} `json:"last_page"`
}

func getLive(t *testing.T, s *Server, task uint64) (liveResp, string) {
	t.Helper()
	rec := get(t, s, fmt.Sprintf("/api/crawl/live?task=%d", task))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET live: %d %s", rec.Code, rec.Body.String())
	}
	var v liveResp
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v, rec.Body.String()
}

func startLiveCrawl(t *testing.T, s *Server, seed string) uint64 {
	t.Helper()
	u, _ := url.Parse(seed)
	s.scope.AddInclude(u.Hostname())
	rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{seed}, "max_requests": 40, "max_depth": 30})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: %d %s", rec.Code, rec.Body.String())
	}
	var start crawlStartResp
	_ = json.Unmarshal(rec.Body.Bytes(), &start)
	return start.TaskID
}

// Without a browser: the request in flight and the fetch stream are live, the frame is null with the
// reason said, and the last HTML page is named for the console's wire preview.
func TestTheLiveCrawlViewWithoutABrowserShowsTheStreamAndSaysWhyThereIsNoFrame(t *testing.T) {
	site := slowSite(t, 8, 120*time.Millisecond)
	s := newTestServer()
	task := startLiveCrawl(t, s, site.URL+"/p1")

	var mid liveResp
	var midRaw string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		mid, midRaw = getLive(t, s, task)
		if mid.State == "running" && mid.Fetched >= 3 && mid.Current != nil {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if mid.State != "running" {
		t.Fatalf("never caught the crawl running: %s", midRaw)
	}
	if mid.Phase != "fetching" || mid.Current == nil || !strings.HasPrefix(mid.Current.URL, site.URL) || mid.Current.Method != "GET" {
		t.Fatalf("mid-crawl phase/current: %s", midRaw)
	}
	if mid.Browser || mid.Frame != nil || !strings.Contains(mid.FrameNote, "no browser is configured") {
		t.Fatalf("no-browser frame: %s", midRaw)
	}
	if !strings.Contains(midRaw, `"frame":null`) {
		t.Fatalf("frame must be null on the wire, not absent: %s", midRaw)
	}
	if len(mid.Recent) < 2 || mid.Recent[0].URL == mid.Recent[len(mid.Recent)-1].URL {
		t.Fatalf("recent: %s", midRaw)
	}
	if mid.LastPage == nil || !strings.HasPrefix(mid.LastPage.URL, site.URL+"/p") || mid.LastPage.ExchangeID == 0 {
		t.Fatalf("last_page: %s", midRaw)
	}

	run := waitForCrawl(t, s, task)
	end, endRaw := getLive(t, s, task)
	if run.State != "done" || end.State != "done" || end.Phase != "finished" || end.Current != nil {
		t.Fatalf("finished: %s", endRaw)
	}
	if end.Fetched < 8 || len(end.Recent) != end.Fetched {
		t.Fatalf("fetch stream after the crawl: fetched %d, recent %d", end.Fetched, len(end.Recent))
	}
	// Newest first: the deepest page is at the top.
	if !strings.HasSuffix(end.Recent[0].URL, "/p8") {
		t.Fatalf("recent[0] = %s, want the last page fetched", end.Recent[0].URL)
	}
}

func TestTheLiveCrawlViewRefusesWhatItDoesNotHold(t *testing.T) {
	s := newTestServer()
	if rec := get(t, s, "/api/crawl/live?task=99"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown task: %d", rec.Code)
	}
	if rec := get(t, s, "/api/crawl/live?task=x"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad task: %d", rec.Code)
	}
	// An empty view is [] for the stream, never null.
	l := newCrawlLive(false)
	raw, _ := json.Marshal(l.view(1, "running"))
	if !strings.Contains(string(raw), `"recent":[]`) || !strings.Contains(string(raw), `"current":null`) {
		t.Fatalf("empty view: %s", raw)
	}
}

// The frame throttle is at the source: inside one second only the first render asks for a picture.
func TestLiveFramesAreThrottledAtTheSource(t *testing.T) {
	l := newCrawlLive(true)
	if !l.rendering("http://a/1") {
		t.Fatal("the first render must ask for a frame")
	}
	if l.rendering("http://a/2") {
		t.Fatal("a second render inside a second must not ask for a frame")
	}
	l.lastFrame = time.Now().Add(-2 * crawlLiveFrameEvery)
	if !l.rendering("http://a/3") {
		t.Fatal("after the interval a render asks again")
	}
	l.setFrame("http://a/3", []byte{0xff, 0xd8})
	l.finish()
	if v := l.view(1, "done"); v.Frame != nil || !strings.Contains(v.FrameNote, "finished") {
		t.Fatalf("a finished crawl keeps no frame: %+v", v)
	}
	if l.rendering("http://a/4") {
		t.Fatal("a finished crawl asks for no frame")
	}
}

// With a browser, the render pass's frame reaches the view while the crawl runs.
func TestTheLiveCrawlViewShowsAFrameFromTheRenderPass(t *testing.T) {
	if !chromeAvailable() {
		domexectest.Skip(t, "no Chrome on PATH")
	}
	site := slowSite(t, 12, 150*time.Millisecond)
	provider := scanner.NewLazyBrowserProvider(domexec.Options{})
	t.Cleanup(func() { _ = provider.Close() })
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithScanner(
		scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithBrowserProvider(provider))
	task := startLiveCrawl(t, s, site.URL+"/p1")

	deadline := time.Now().Add(60 * time.Second)
	var v liveResp
	var raw string
	for time.Now().Before(deadline) {
		v, raw = getLive(t, s, task)
		if v.Frame != nil || v.State != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if v.Frame == nil {
		t.Fatalf("no frame while the crawl ran: %.400s", raw)
	}
	if !v.Browser || !strings.HasPrefix(v.Frame.Image, "data:image/jpeg;base64,/9j/") || !strings.HasPrefix(v.Frame.URL, site.URL) {
		t.Fatalf("frame: browser=%v url=%q image=%.40s", v.Browser, v.Frame.URL, v.Frame.Image)
	}
	waitForCrawlLong(t, s, task)
	if end, endRaw := getLive(t, s, task); end.Frame != nil {
		t.Fatalf("the frame outlived the crawl: %.300s", endRaw)
	}
}

func waitForCrawlLong(t *testing.T, s *Server, task uint64) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if run, ok := s.crawls.get(task); ok && run.State != "running" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("crawl did not finish")
}
