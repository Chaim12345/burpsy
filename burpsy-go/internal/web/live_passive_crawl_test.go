package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/proxy"
	"go.uber.org/zap"
)

// The live passive crawl (burpsy-react-ui-t3zk): links in a page the browser fetched through the proxy
// become unrequested site-map items, out-of-scope links do not, and requesting one turns it into an
// ordinary observed node. It sends nothing itself.
func Test_links_in_proxied_pages_become_unrequested_site_map_items(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<html><body><a href="/account">account</a><a href="/search?q=1">s</a>
			<a href="http://elsewhere.test/out">out</a><img src="/logo.png"></body></html>`)
	}))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)

	s := newTestServer()
	s.scope.AddInclude(u.Hostname())
	px := proxy.NewServer(proxy.NewProxyConfig(s.store).WithScope(s.scope).WithLogger(zap.NewNop()).
		WithPageObserver(s.ObserveProxiedPage))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go px.ListenAndServe(ctx, "127.0.0.1:0")
	deadline := time.Now().Add(5 * time.Second)
	for px.ListenerAddr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: px.ListenerAddr()})}}
	get := func(path string) {
		resp, err := client.Get(origin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	get("/")
	time.Sleep(100 * time.Millisecond)

	tree := get200(t, s, "/api/sitemap")
	// A grey item is drawn at its node (burpsy-react-ui-vc98): the link to /search?q=1 is the /search
	// row, with q in its parameter list, the way the fold draws a requested /search?q=1.
	for _, want := range []string{`"path":"/account"`, `"path":"/search"`} {
		if !strings.Contains(tree, want) || !strings.Contains(tree, `"unrequested":true`) {
			t.Errorf("site map lacks the unrequested item %s: %s", want, tree)
		}
	}
	if strings.Contains(tree, "elsewhere.test") || strings.Contains(tree, "/logo.png") {
		t.Errorf("an out-of-scope link or an asset became an unrequested item: %s", tree)
	}
	mu.Lock()
	if hits["/account"] != 0 {
		t.Errorf("the live passive crawl sent a request: %v", hits)
	}
	mu.Unlock()

	// Requested now: the item is an ordinary observed node, no longer grey.
	get("/account")
	time.Sleep(100 * time.Millisecond)
	if tree := get200(t, s, "/api/sitemap"); strings.Count(tree, `"unrequested":true`) != 1 {
		t.Errorf("after /account was requested, want exactly one unrequested item left (/search): %s", tree)
	}

	// A link carrying a query is cleared by requesting that URL (burpsy-react-ui-u6f8): the proxied
	// exchange is stored as /search?q=1, and the grey item must not survive beside it.
	get("/search?q=1")
	time.Sleep(100 * time.Millisecond)
	if tree := get200(t, s, "/api/sitemap"); strings.Contains(tree, `"unrequested":true`) {
		t.Errorf("after /search?q=1 was requested, an unrequested item is left: %s", tree)
	}
}

func get200(t *testing.T, s *Server, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}
