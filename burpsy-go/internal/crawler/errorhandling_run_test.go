package crawler

// The error_handling family (burpsy-react-ui-o0c5) end to end: real sockets, real failures. The
// policy type and its Burp-config import were tested where they were written; these tests are about
// the crawl actually DOING what the policy says, which nothing exercised while noteFailure and
// checkPauseThresholds were never called.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
)

func intp(v int) *int { return &v }

// slowOrigin serves "/" linking to n slow pages, each of which outlasts the sender's timeout.
func slowOrigin(t *testing.T, n int) *httptest.Server {
	t.Helper()
	links := ""
	for i := 0; i < n; i++ {
		links += `<a href="/slow` + string(rune('a'+i)) + `">s</a>`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>` + links + `</body></html>`))
			return
		}
		if r.URL.Path == "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runLikeProduction runs a crawl under a cancel-only context, the way the API does
// (context.WithCancel(context.Background()) in startCrawl). The package's run() helper adds a 30s
// deadline, and the sender prefers a context deadline over its own per-request bound — so under
// run() a slow page waits 30s instead of timing out, which is not what a real crawl sees.
func runLikeProduction(t *testing.T, cfg Config) Report {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Report, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case rep := <-done:
		return rep
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("crawl did not finish within 30s")
		return Report{}
	}
}

func fastTimeoutConfig(h *harness, seed string) Config {
	cfg := h.config(seed)
	cfg.Sender = sender.NewSender(&sender.SenderConfig{Timeout: 150 * time.Millisecond, TLSVerify: false})
	return cfg
}

// AC3: crossing the consecutive-timeout threshold ends the crawl with a NAMED stop, so the report
// says it was paused by policy — and the pages after the streak are not fetched.
func TestTheConsecutiveTimeoutThresholdStopsTheCrawlByName(t *testing.T) {
	srv := slowOrigin(t, 6)
	h := newHarness()
	cfg := fastTimeoutConfig(h, srv.URL+"/")
	cfg.ErrorHandling = ErrorHandling{PauseOnTimeoutCount: intp(2), FollowUpPasses: intp(0)}

	rep := runLikeProduction(t, cfg)
	if !rep.Limits.Hit(StopPausedTimeouts) {
		t.Fatalf("stops = %v, want StopPausedTimeouts — the report must say the crawl was paused by policy, "+
			"not that it finished", rep.Limits.Stops)
	}
	if rep.Failed != 2 {
		t.Errorf("failed = %d, want 2: the crawl must stop AT the threshold, not grind through the other "+
			"slow pages first", rep.Failed)
	}
}

// AC4: Burp's shipped "Never stop crawl due to application errors" sets all three thresholds to 0.
// That must be a crawl that never pauses — 0 read as "unset" would pause at the default 15 instead,
// and 0 read as "pause immediately" would be worse.
func TestAllThresholdsAtZeroIsACrawlThatNeverPauses(t *testing.T) {
	srv := slowOrigin(t, 6)
	h := newHarness()
	cfg := fastTimeoutConfig(h, srv.URL+"/")
	cfg.ErrorHandling = ErrorHandling{
		PauseOnTimeoutCount: intp(0), PauseOnTimeoutPercent: intp(0), PauseOnAuthFailures: intp(0),
		FollowUpPasses: intp(0),
	}

	rep := runLikeProduction(t, cfg)
	for _, stop := range []CrawlStop{StopPausedTimeouts, StopPausedTimeoutPercentage, StopPausedAuthFailures} {
		if rep.Limits.Hit(stop) {
			t.Errorf("a crawl with every threshold at 0 recorded %v; 0 means never", stop)
		}
	}
	if rep.Failed != 6 {
		t.Errorf("failed = %d, want 6: every slow page attempted, none skipped by a pause", rep.Failed)
	}
}

// The percentage axis fires on a crawl that is broadly slow. It divided by lim.Requests, which reads
// zero for the whole crawl, so before this it could never fire.
func TestTheTimeoutPercentageThresholdCanFire(t *testing.T) {
	srv := slowOrigin(t, 6)
	h := newHarness()
	cfg := fastTimeoutConfig(h, srv.URL+"/")
	cfg.ErrorHandling = ErrorHandling{
		PauseOnTimeoutCount: intp(0), PauseOnTimeoutPercent: intp(50), FollowUpPasses: intp(0),
	}
	rep := runLikeProduction(t, cfg)
	if !rep.Limits.Hit(StopPausedTimeoutPercentage) {
		t.Fatalf("stops = %v, want StopPausedTimeoutPercentage once half the sends had timed out", rep.Limits.Stops)
	}
}

// AC5: a follow-up pass recovers a request that failed once. The origin drops the connection the
// first time /flaky is asked for and serves it the second time; the report counts it fetched, not
// failed, and says the retry recovered it.
func TestAFollowUpPassRecoversARequestThatFailedOnce(t *testing.T) {
	var mu sync.Mutex
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="/flaky">f</a></body></html>`))
		case "/flaky":
			mu.Lock()
			asked++
			first := asked == 1
			mu.Unlock()
			if first {
				// A transport failure, not an HTTP error: the connection is dropped mid-request.
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>recovered</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.ErrorHandling = ErrorHandling{FollowUpPasses: intp(1)}
	rep := run(t, cfg)

	if asked != 2 {
		t.Fatalf("/flaky was asked for %d times, want 2: the failure and the follow-up", asked)
	}
	if rep.FollowUpRecovered != 1 {
		t.Errorf("follow_up_recovered = %d, want 1", rep.FollowUpRecovered)
	}
	if rep.Failed != 0 {
		t.Errorf("failed = %d, want 0: a recovered request ended fetched, and the partition counts each "+
			"request once by how it ended", rep.Failed)
	}
	if fetchedPaths(rep)["/flaky"] == 0 {
		t.Error("the recovered page is not in the report's fetches; the retry must go through perform so it is captured")
	}
}

// With follow-up passes at 0 the failure is recorded and not retried — 0 is a real answer.
func TestZeroFollowUpPassesDoesNotRetry(t *testing.T) {
	var mu sync.Mutex
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="/flaky">f</a></body></html>`))
			return
		}
		if r.URL.Path == "/flaky" {
			mu.Lock()
			asked++
			mu.Unlock()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.ErrorHandling = ErrorHandling{FollowUpPasses: intp(0)}
	rep := run(t, cfg)
	if asked != 1 {
		t.Errorf("/flaky asked for %d times with follow-up passes at 0, want 1", asked)
	}
	if rep.Failed != 1 {
		t.Errorf("failed = %d, want 1", rep.Failed)
	}
}

// The follow-up pass spends the SAME request budget as the main pass. It used to measure against
// lim.Requests, which reads zero during the crawl, so a crawl at its budget could send a second
// budget's worth of retries.
func TestAFollowUpPassNeverExceedsTheRequestBudget(t *testing.T) {
	var mu sync.Mutex
	failingHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="/a">a</a><a href="/b">b</a><a href="/ok1">1</a><a href="/ok2">2</a></body></html>`))
		case "/robots.txt":
			http.NotFound(w, r)
		case "/ok1", "/ok2":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
		default:
			// /a and /b drop their connection, every time.
			mu.Lock()
			failingHits++
			mu.Unlock()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.Limits = DefaultLimits()
	cfg.Limits.MaxRequests = 4
	cfg.ErrorHandling = ErrorHandling{FollowUpPasses: intp(5)}
	rep := run(t, cfg)

	// "/", robots.txt, /ok1 and /ok2 spend the budget of 4; /a and /b fail once each along the way.
	// The follow-up pass then has failures to retry and no budget to retry them with, so it must send
	// nothing — counted at the SERVER, because the report's own counters are exactly what a broken
	// budget would also miscount.
	mu.Lock()
	defer mu.Unlock()
	if failingHits != 2 {
		t.Errorf("the failing links were sent %d times, want 2 (once each in the main pass): the "+
			"follow-up passes ignored the spent budget and re-sent them", failingHits)
	}
	if !rep.Limits.Hit(StopFollowUpBudget) {
		t.Errorf("stops = %v, want StopFollowUpBudget: the report must say retries were withheld for budget",
			rep.Limits.Stops)
	}
}
