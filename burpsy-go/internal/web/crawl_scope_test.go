package web

// A crawl's own scope (burpsy-react-ui-501u), end to end: the origin records every path it is asked
// for, and a crawl told to stay in its seed's directory never asks for anything outside it.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/dash"
)

func scopedOrigin(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><a href="/app/a">a</a><a href="/app/b/secret">b</a><a href="/other/x">x</a><a href="/">root</a></html>`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func runScopedCrawl(t *testing.T, scope map[string]any, seed string) []string {
	t.Helper()
	origin, paths := scopedOrigin(t)
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	body := map[string]any{"seeds": []string{origin.URL + seed}}
	if scope != nil {
		body["scope"] = scope
	}
	rec := postJSON(t, s, "/api/crawl", body)
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("crawl = %d %s", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		running := false
		for _, task := range s.tasks.Snapshot() {
			if task.Kind == dash.KindCrawl && task.Running() {
				running = true
			}
		}
		if !running {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return paths()
}

func TestASeedDirectoryCrawlNeverLeavesTheDirectory(t *testing.T) {
	got := runScopedCrawl(t, map[string]any{"mode": "seed_directories"}, "/app/index.html")
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "/app/a") {
		t.Errorf("the crawl did not walk its own directory: %v", got)
	}
	for _, p := range got {
		if !strings.HasPrefix(p, "/app/") {
			t.Errorf("the origin was asked for %s, outside the seed's directory: %v", p, got)
		}
	}
}

func TestPrefixScopeExcludesAndTheEngagementDefaultIsUnchanged(t *testing.T) {
	origin, paths := scopedOrigin(t)
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds": []string{origin.URL + "/app/index.html"},
		"scope": map[string]any{"mode": "prefixes", "include": []string{origin.URL + "/app/"}, "exclude": []string{origin.URL + "/app/b"}},
	})
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("crawl = %d %s", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && func() bool {
		for _, task := range s.tasks.Snapshot() {
			if task.Kind == dash.KindCrawl && task.Running() {
				return true
			}
		}
		return false
	}() {
		time.Sleep(20 * time.Millisecond)
	}
	got := strings.Join(paths(), " ")
	if !strings.Contains(got, "/app/a") || strings.Contains(got, "/app/b") || strings.Contains(got, "/other") {
		t.Errorf("include /app/ minus /app/b: the origin saw %q", got)
	}

	all := runScopedCrawl(t, nil, "/app/index.html")
	if !strings.Contains(strings.Join(all, " "), "/other/x") {
		t.Errorf("without a crawl scope the engagement scope alone applies, as before: %v", all)
	}
	if rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{"http://127.0.0.1:1/"}, "scope": map[string]any{"mode": "prefixes", "include": []string{"ftp://x"}}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a non-http prefix = %d, want 400", rec.Code)
	}
}
