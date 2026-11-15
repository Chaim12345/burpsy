package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// seedUI2LoadExchanges stores n proxy exchanges with request+response as fast as the store
// allows, returning when all are recorded. It is the load generator: each AddExchange fires
// the store observer, which calls live.notify(changeHistory) — the same producer path a
// saturated crawl takes.
func seedUI2LoadExchanges(t *testing.T, s *Server, n int) {
	t.Helper()
	req := []byte("GET /load HTTP/1.1\r\nHost: load.test\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	for i := range n {
		reqID, err := s.store.Put(req, core.DirectionRequest)
		if err != nil {
			t.Fatal(err)
		}
		respID, err := s.store.Put(resp, core.DirectionResponse)
		if err != nil {
			t.Fatal(err)
		}
		status := uint16(200)
		s.store.AddExchange(&core.Exchange{
			Host: "load.test", Port: 80, Method: "GET", Path: fmt.Sprintf("/load/%d", i),
			Status: &status, Request: core.MsgPtr(reqID), Response: &respID, Source: core.SourceProxy,
		})
	}
}

// ui2Get issues one GET against the mux and returns elapsed time. No gate: this measures the
// handler path, which is what the load question is about.
func ui2Get(s *Server, path string) time.Duration {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	start := time.Now()
	s.mux.ServeHTTP(rec, req)
	return time.Since(start)
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)-1))
	return sorted[idx]
}

// TestUI2HistoryUnderEventFlood seeds 20k exchanges (each firing a changeHistory notify),
// then measures /ui2/history latency percentiles while a goroutine keeps notifying at
// ~2000 events/sec. The page handler must stay fast because it scans index rows only and
// renders one page.
func TestUI2HistoryUnderEventFlood(t *testing.T) {
	s := newTestServer()
	seedUI2LoadExchanges(t, s, 20000)

	// Background flood: ~2000 notify/sec for the duration of the measurements.
	stop := make(chan struct{})
	var floodWG sync.WaitGroup
	floodWG.Add(1)
	go func() {
		defer floodWG.Done()
		tick := time.NewTicker(500 * time.Microsecond) // 2000/sec
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				s.live.notify(changeHistory)
			}
		}
	}()

	paths := []string{
		"/ui2/history",
		"/ui2/history?limit=100",
		"/ui2/history?search=load",
		"/ui2/history?q=host:load.test",
		"/ui2/history?limit=100&offset=19900",
		"/ui2/issues",
	}
	var samples []time.Duration
	for i := range 200 {
		for _, p := range paths {
			samples = append(samples, ui2Get(s, p))
			_ = i
		}
	}
	close(stop)
	floodWG.Wait()

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("ui2 under 2k events/sec flood, %d requests over %d paths:", len(samples), len(paths))
	t.Logf("  p50=%v p90=%v p99=%v max=%v", percentile(samples, 0.50), percentile(samples, 0.90), percentile(samples, 0.99), samples[len(samples)-1])

	// The load contract: even at p99 a page renders in well under a second — the handler
	// never reads bodies and never holds more than one page.
	if p99 := percentile(samples, 0.99); p99 > time.Second {
		t.Errorf("p99 latency %v exceeds 1s under 2k events/sec", p99)
	}
}

// TestUI2SSEFrameRateUnderFlood measures how many coalesced frames a subscriber receives
// when notified at 2000/sec: the hub's 150ms window should cap it at ~6-7 frames/sec, which
// is the property that keeps the browser's re-fetch loop from being flooded.
func TestUI2SSEFrameRateUnderFlood(t *testing.T) {
	s := newTestServer()
	sub, unsubscribe := s.live.subscribe()
	defer unsubscribe()

	stop := make(chan struct{})
	var fired atomic.Uint64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(500 * time.Microsecond) // 2000/sec
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				s.live.notify(changeHistory)
				fired.Add(1)
			}
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	frames := 0
	var totalChanges uint64
	for time.Now().Before(deadline) {
		select {
		case <-sub.signal:
			for _, f := range s.live.take(sub) {
				frames++
				totalChanges += f.Changes
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	close(stop)
	wg.Wait()
	// Drain whatever the last flush carried after the flood stopped — the hub announces
	// every notify exactly once, so the tail must be read too.
	for range 20 {
		select {
		case <-sub.signal:
			for _, f := range s.live.take(sub) {
				frames++
				totalChanges += f.Changes
			}
		default:
			goto drained
		}
	}
drained:
	// The hub announces every notify exactly once (Swap-claim in flush), so after draining
	// the frames must account for all of them; small slack for a flush still inside its
	// 150ms trailing window when the drain ran.
	total := fired.Load()
	slack := uint64(400)
	t.Logf("2000 notifies/sec -> %d notifies fired, %d frames in ~3s (%.1f fps), carrying %d changes",
		total, frames, float64(frames)/3.0, totalChanges)
	if r := float64(frames) / 3.0; r > 10 {
		t.Errorf("frame rate %.1f fps is above the ~6.7/s coalescing ceiling — the browser would be flooded", r)
	}
	if totalChanges < total-slack {
		t.Errorf("frames carried %d of %d notifies; the hub must announce every change exactly once", totalChanges, total)
	}
}

// TestUI2DetailUnderFlood measures the detail pane (which DOES read message bytes) under the
// same flood, to show the one place body reads happen stays bounded.
func TestUI2DetailUnderFlood(t *testing.T) {
	s := newTestServer()
	seedUI2LoadExchanges(t, s, 5000)
	ex := s.store.Exchanges()[0]

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(500 * time.Microsecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				s.live.notify(changeHistory)
			}
		}
	}()

	var samples []time.Duration
	for range 100 {
		samples = append(samples, ui2Get(s, fmt.Sprintf("/ui2/history/%d", ex.ID)))
	}
	close(stop)
	wg.Wait()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("detail pane under flood: p50=%v p99=%v max=%v", percentile(samples, 0.5), percentile(samples, 0.99), samples[len(samples)-1])
	if p99 := percentile(samples, 0.99); p99 > 500*time.Millisecond {
		t.Errorf("detail p99 %v too slow under flood", p99)
	}
}

// TestUI2FilterTypingLatency simulates the filter box: a burst of keystrokes means a burst of
// /ui2/history?search=... requests with growing prefixes. Each must answer fast.
func TestUI2FilterTypingLatency(t *testing.T) {
	s := newTestServer()
	seedUI2LoadExchanges(t, s, 20000)
	term := "load/1"
	var samples []time.Duration
	for i := 1; i <= len(term); i++ {
		prefix := term[:i]
		for range 10 {
			samples = append(samples, ui2Get(s, "/ui2/history?search="+prefix))
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("filter typing (%d requests over growing prefixes): p50=%v p99=%v max=%v",
		len(samples), percentile(samples, 0.5), percentile(samples, 0.99), samples[len(samples)-1])
	if p99 := percentile(samples, 0.99); p99 > 500*time.Millisecond {
		t.Errorf("filter p99 %v too slow while typing", p99)
	}
}

// TestUI2OldUICatchAllStillServesUnderLoad proves the SPA route is unaffected by the flood.
func TestUI2OldUICatchAllStillServesUnderLoad(t *testing.T) {
	s := newTestServer()
	seedUI2LoadExchanges(t, s, 5000)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(500 * time.Microsecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				s.live.notify(changeHistory)
			}
		}
	}()
	var samples []time.Duration
	for range 50 {
		samples = append(samples, ui2Get(s, "/"))
	}
	close(stop)
	wg.Wait()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("old UI catch-all under flood: p50=%v p99=%v", percentile(samples, 0.5), percentile(samples, 0.99))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<") {
		t.Errorf("GET / = %d — SPA catch-all broken", rec.Code)
	}
}
