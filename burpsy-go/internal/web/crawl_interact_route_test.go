package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
)

// burpsy-react-ui-spa1: POST /api/crawl's interact switch reaches the crawl the operator started, and
// the crawl reaches a route that exists only after a click. Every assertion is on what the TARGET saw
// — the paths it was asked for — never on a Config literal, because a field set on a literal the
// crawl never reads is the exact defect shape this test exists to catch.
//
// Chrome is required and its absence is a skip here (this is one of several web tests that need it),
// unlike internal/scanner's counted version: the wiring this proves is also covered without a browser
// by internal/crawler's stubbed-hook tests, so a machine with no Chrome loses the end-to-end
// demonstration, not the capability's only proof.

// interactSite serves a SPA-shaped page whose /scripted link exists only in the DOM a click produces,
// and records every path it is asked for.
type interactSite struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
}

func newInteractSite(t *testing.T) *interactSite {
	t.Helper()
	site := &interactSite{}
	site.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		site.mu.Lock()
		site.seen = append(site.seen, r.URL.Path)
		site.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/app" {
			// The click also fetches /forbidden, which the gated tests put out of scope: the browser's
			// own request, not a link the crawl frontier would ever follow.
			_, _ = w.Write([]byte(`<html><body>
				<div id="app">Home</div>
				<button id="go" onclick="fetch('/forbidden').catch(function(){}); document.getElementById('app').innerHTML='<a href=&quot;/scripted&quot;>x</a>'">Go</button>
			</body></html>`))
			return
		}
		_, _ = w.Write([]byte(`<html><body>page</body></html>`))
	}))
	t.Cleanup(site.srv.Close)
	return site
}

func (s *interactSite) saw(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.seen {
		if p == path {
			return true
		}
	}
	return false
}

// startInteractCrawl starts a crawl through the route and returns its finished report.
func startInteractCrawl(t *testing.T, s *Server, seed string, interact bool) crawlRunResp {
	t.Helper()
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds": []string{seed}, "max_requests": 30, "max_depth": 3, "interact": interact,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: %d %s", rec.Code, rec.Body.String())
	}
	var start crawlStartResp
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	run := waitForCrawl(t, s, start.TaskID)
	if run.State != "done" {
		t.Fatalf("crawl state %q (%s)", run.State, run.Error)
	}
	return run
}

// With interact on, the crawl reaches the route a click revealed; with it off, it does not. The
// second half is what proves the first is the switch working rather than a page the static parse
// happened to carry.
func TestTheCrawlRouteClicksThroughToAScriptRoutedPage(t *testing.T) {
	if !chromeAvailable() {
		domexectest.Skip(t, "no Chrome on PATH")
	}
	provider := scanner.NewLazyBrowserProvider(domexec.Options{})
	t.Cleanup(func() { _ = provider.Close() })
	build := func() *Server {
		return NewServer(core.NewTrafficStore(), loopbackScope()).WithScanner(
			scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithBrowserProvider(provider))
	}

	onSite := newInteractSite(t)
	startInteractCrawl(t, build(), onSite.srv.URL+"/app", true)
	if !onSite.saw("/scripted") {
		t.Fatalf("interact:true did not crawl the script-routed page; the target saw %v", onSite.seen)
	}

	offSite := newInteractSite(t)
	startInteractCrawl(t, build(), offSite.srv.URL+"/app", false)
	offSite.mu.Lock()
	seen := append([]string(nil), offSite.seen...)
	offSite.mu.Unlock()
	for _, p := range seen {
		if strings.Contains(p, "scripted") {
			t.Fatalf("interact:false crawled a page only a click reveals; the target saw %v", seen)
		}
	}
}

// loopbackScope declares 127.0.0.1 in scope and its /forbidden path out of it.
func loopbackScope() *core.Scope {
	sc := core.NewScope()
	sc.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	sc.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "127.0.0.1", "/forbidden"))
	return sc
}

// The interaction pass's browser is scope-gated: the click on /app makes the page fetch /forbidden,
// which the scope excludes, and the target must never see that request. An ungated browser sends it
// (the crawl frontier never would — the request is the PAGE's, which is why only a network gate stops
// it). The click-revealed route is still crawled, so the pass ran.
func TestTheCrawlInteractionPassIsScopeGated(t *testing.T) {
	if !chromeAvailable() {
		domexectest.Skip(t, "no Chrome on PATH")
	}
	provider := scanner.NewLazyBrowserProvider(domexec.Options{})
	t.Cleanup(func() { _ = provider.Close() })
	s := NewServer(core.NewTrafficStore(), loopbackScope()).WithScanner(
		scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithBrowserProvider(provider))

	site := newInteractSite(t)
	startInteractCrawl(t, s, site.srv.URL+"/app", true)
	if !site.saw("/scripted") {
		t.Fatalf("the interaction pass did not run (no click-revealed page crawled); the target saw %v", site.seen)
	}
	if site.saw("/forbidden") {
		t.Fatal("the interaction pass's browser sent a request the crawl scope excludes")
	}
}

// With no declared scope an interacting crawl is refused before it starts, rather than run in a
// browser that would follow whatever the page says.
func TestAnInteractingCrawlNeedsADeclaredScope(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithScanner(
		scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop()))
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds": []string{"http://127.0.0.1:1/app"}, "max_requests": 5, "interact": true,
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "declared scope") {
		t.Fatalf("an interacting crawl with no scope answered %d %s, want 400 naming the missing scope", rec.Code, rec.Body.String())
	}
}
