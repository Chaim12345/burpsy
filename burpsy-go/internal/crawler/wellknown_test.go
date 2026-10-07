package crawler

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// burpsy-react-ui-bc2x: with RequestWellKnown, the standard .well-known documents are requested once
// per seed authority, through the same gates as any link, and counted in their own phase; without it
// (the default) none is requested.
func TestWellKnownDocumentsAreRequestedOncePerAuthority(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	on := h.config(srv.URL+"/", srv.URL+"/other") // two seeds, one authority
	on.RequestWellKnown = true
	rep := run(t, on)
	mu.Lock()
	n := asked["/.well-known/security.txt"]
	oidc := asked["/.well-known/openid-configuration"]
	mu.Unlock()
	if n != 1 || oidc != 1 {
		t.Errorf("security.txt asked %d times, openid-configuration %d, want 1 each (once per authority)", n, oidc)
	}
	if rep.Phases[PhaseWellKnown] != len(wellKnownPaths) {
		t.Errorf("phase 14-well-known = %d, want %d", rep.Phases[PhaseWellKnown], len(wellKnownPaths))
	}

	mu.Lock()
	asked = map[string]int{}
	mu.Unlock()
	run(t, h.config(srv.URL+"/")) // the default
	mu.Lock()
	defer mu.Unlock()
	if asked["/.well-known/security.txt"] != 0 {
		t.Error("a default crawl requested .well-known documents; the switch is opt-in")
	}
}

// An authority the scope excludes is not asked for them either — they are links like any other.
func TestWellKnownDocumentsRespectScope(t *testing.T) {
	var mu sync.Mutex
	hit := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit++
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	h := newHarness()
	h.scope.AddInclude("someone-else.test")
	cfg := h.config(srv.URL + "/")
	cfg.RequestWellKnown = true
	run(t, cfg)
	mu.Lock()
	defer mu.Unlock()
	if hit != 0 {
		t.Errorf("an out-of-scope authority received %d requests", hit)
	}
}
