package web

// Per-task Pause/Resume (burpsy-react-ui-g0ba) on a live crawl: the row's own Pause stops the crawl
// sending at its next gate, Resume lets it finish, and a non-pausable or unknown id is refused.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/dash"
)

func TestPausingOneCrawlTaskStopsItsRequestsUntilResume(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		for i := 0; i < 40; i++ {
			fmt.Fprintf(&b, `<a href="/p%d">p%d</a>`, i, i)
		}
		w.Write([]byte("<html><body>" + b.String() + "</body></html>"))
	}))
	defer origin.Close()

	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{origin.URL + "/"}})
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("crawl = %d %s", rec.Code, rec.Body.String())
	}
	var started map[string]any
	json.Unmarshal(rec.Body.Bytes(), &started)
	var id uint64
	for _, task := range s.tasks.Snapshot() {
		if task.Kind == dash.KindCrawl {
			id = task.ID
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for hits.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec := postJSON(t, s, fmt.Sprintf("/api/tasks/%d/pause", id), nil); rec.Code != http.StatusOK {
		t.Fatalf("pause = %d %s", rec.Code, rec.Body.String())
	}
	time.Sleep(150 * time.Millisecond) // let in-flight units land
	before := hits.Load()
	time.Sleep(400 * time.Millisecond)
	if after := hits.Load(); after != before {
		t.Errorf("a paused crawl kept sending: %d -> %d", before, after)
	}
	snap := s.taskByID(id)
	if snap == nil || !snap.Paused || !snap.Pausable {
		t.Errorf("the row must say pausable and paused: %+v", snap)
	}
	if rec := postJSON(t, s, fmt.Sprintf("/api/tasks/%d/resume", id), nil); rec.Code != http.StatusOK {
		t.Fatalf("resume = %d", rec.Code)
	}
	deadline = time.Now().Add(5 * time.Second)
	for hits.Load() <= before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() <= before {
		t.Error("resume did not let the crawl continue")
	}
	if rec := postJSON(t, s, "/api/tasks/987654/pause", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec.Code)
	}
	// Stop the crawl so the test leaves nothing running.
	s.tasks.Cancel(id)
}

func TestPausingATaskThatNeverReachesAGateIsRefused(t *testing.T) {
	s := newTestServer()
	h := s.tasks.Start(dash.KindDiscovery, "x", 0)
	defer h.Finish(dash.Breakdown{})
	rec := postJSON(t, s, fmt.Sprintf("/api/tasks/%d/pause", h.ID()), nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "cannot be paused") {
		t.Errorf("non-pausable = %d %q, want 409 naming why", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/tasks/%d/pause", h.ID()), nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET pause = %d, want 405 (a prefetch must not pause a task)", w.Code)
	}
}
