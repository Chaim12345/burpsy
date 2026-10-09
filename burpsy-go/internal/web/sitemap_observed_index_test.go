package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sitemap"
)

// observedPathReference is the per-item check GET /api/sitemap used before observedIndex (over a
// snapshot instead of a fresh sm.Hosts() per call), kept as the oracle the index must agree with on
// every input. One change from the original, burpsy-react-ui-u6f8: the exact-node test compares the
// item's node with each stored key's node. The original looked the item's stripped path up among
// the raw keys, which keep their query, so /search?q=1 never matched a stored "/search?q=1".
func observedPathReference(hosts []*sitemap.HostNode, in *sitemap.InsertedNode) bool {
	for _, host := range hosts {
		if host.Host != in.Host || host.Port != in.Port || host.TLS != in.TLS {
			continue
		}
		clean, _ := splitPathQuery(in.Path)
		for _, pn := range host.Paths {
			cleanPath, _ := splitPathQuery(pn.Path)
			if cleanPath == clean {
				return true
			}
			if clean == "/" || strings.HasPrefix(cleanPath, strings.TrimSuffix(clean, "/")+"/") {
				return true
			}
		}
	}
	return false
}

func hostWith(host string, port uint16, tls bool, paths ...string) *sitemap.HostNode {
	hn := &sitemap.HostNode{Host: host, Port: port, TLS: tls, Paths: map[string]*sitemap.PathNode{}}
	for _, p := range paths {
		hn.Paths[p] = &sitemap.PathNode{Path: p}
	}
	return hn
}

// The index answers exactly what the per-item scan answered, across exact keys, keys carrying a
// query, folders of observed paths, near-miss prefixes, "/", odd stored keys, a host listed twice,
// a host with no paths, and the port/TLS axes of the host identity.
func TestObservedIndexMatchesPerItemScan(t *testing.T) {
	hosts := []*sitemap.HostNode{
		hostWith("app.test", 443, true, "/", "/api/users/42", "/search?q=1", "/static/app.js", "rel/no-slash", "/trail/"),
		hostWith("app.test", 80, false, "/login"),
		hostWith("dup.test", 443, true, "/a/b"),
		hostWith("dup.test", 443, true, "/c"),
		hostWith("empty.test", 443, true),
	}
	idx := newObservedIndex(hosts)
	queries := []string{
		"", "/", "//", "/api", "/api/", "/api/users", "/api/users/", "/api/users/42", "/api/users/42/",
		"/api/users/4", "/ap", "/apix", "/search", "/search?q=1", "/search?q=2", "/static", "/static/app.js?v=3",
		"rel", "/rel", "rel/", "/rel/no-slash", "/trail", "/trail/", "/login", "/a", "/a/", "/a/b", "/c", "/d",
		"/a/b/c", "/?x=1", "api/users",
	}
	ids := []struct {
		host string
		port uint16
		tls  bool
	}{
		{"app.test", 443, true}, {"app.test", 80, false}, {"app.test", 443, false}, {"app.test", 8443, true},
		{"dup.test", 443, true}, {"empty.test", 443, true}, {"none.test", 443, true},
	}
	checked, positives := 0, 0
	for _, id := range ids {
		for _, q := range queries {
			in := &sitemap.InsertedNode{Host: id.host, Port: id.port, TLS: id.tls, Path: q}
			want := observedPathReference(hosts, in)
			if got := idx.has(in); got != want {
				t.Errorf("%s:%d tls=%v path %q: index=%v, per-item scan=%v", id.host, id.port, id.tls, q, got, want)
			}
			checked++
			if want {
				positives++
			}
		}
	}
	// Positive control: a grid where every answer was false would agree with an index that always
	// said no.
	if positives == 0 || positives == checked {
		t.Fatalf("degenerate grid: %d of %d observed", positives, checked)
	}
	// And the u6f8 cases themselves, pinned rather than left to agreement with the oracle: a stored
	// "/search?q=1" covers its own URL, its query variants and the bare node.
	for _, q := range []string{"/search?q=1", "/search?q=2", "/search", "/search/"} {
		if !idx.has(&sitemap.InsertedNode{Host: "app.test", Port: 443, TLS: true, Path: q}) {
			t.Errorf("%s is not observed under a stored /search?q=1", q)
		}
	}
	if idx.has(&sitemap.InsertedNode{Host: "app.test", Port: 443, TLS: true, Path: "/searches?q=1"}) {
		t.Error("/searches?q=1 is observed under a stored /search?q=1: a different node")
	}
}

// burpsy-react-ui-u6f8 through the real read: an unrequested /search?q=1, learned before anything
// requested it, is cleared from GET /api/sitemap by a request for /search?q=1, and so is the query
// variant /search?q=2 (one node: the fold draws it as the requested /search with q in its parameter
// list). An unrelated unrequested item is the control that the merge still emits grey items.
func TestSitemapGetRequestingAQueryURLClearsItsUnrequestedItem(t *testing.T) {
	s := newTestServer()
	seen := time.Unix(1_700_000_000, 0)
	for _, p := range []string{"/search?q=1", "/search?q=2", "/other?x=1"} {
		if !s.sitemap.AddUnrequested("app.test", 80, false, p, "http://app.test/", seen) {
			t.Fatalf("AddUnrequested %s refused on an empty map", p)
		}
	}
	unrequested := func() []string {
		t.Helper()
		var v sitemapTreeResp
		if err := json.Unmarshal([]byte(get200(t, s, "/api/sitemap")), &v); err != nil {
			t.Fatal(err)
		}
		var out []string
		var walk func([]sitemapNodeView)
		walk = func(ns []sitemapNodeView) {
			for _, n := range ns {
				if n.Unrequested {
					out = append(out, n.Path)
				}
				walk(n.Children)
			}
		}
		walk(v.Tree)
		sort.Strings(out)
		return out
	}
	if got, want := strings.Join(unrequested(), ","), "/other?x=1,/search?q=1,/search?q=2"; got != want {
		t.Fatalf("before any request: unrequested = %s, want %s", got, want)
	}

	s.sitemap.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/search?q=1"})
	if got, want := strings.Join(unrequested(), ","), "/other?x=1"; got != want {
		t.Errorf("after /search?q=1 was requested: unrequested = %s, want %s", got, want)
	}
	// And at record time: a later link to another query of the requested node is not stored.
	if s.sitemap.AddUnrequested("app.test", 80, false, "/search?q=3", "http://app.test/", seen) {
		t.Error("a link to /search?q=3 was recorded as unrequested after /search was requested")
	}
	// The requested node is the one /search row, carrying q, not a grey sibling per query.
	body := get200(t, s, "/api/sitemap")
	if strings.Count(body, `"path":"/search`) != 1 || !strings.Contains(body, `"params":["q"]`) {
		t.Errorf("want exactly one /search node with params [q]: %s", body)
	}
}

// End to end: GET /api/sitemap merges exactly the unrequested and inserted items the observed tree
// does not already cover, through the index.
func TestSitemapGetUnrequestedMergeSkipsObserved(t *testing.T) {
	s := newTestServer()
	seen := time.Unix(1_700_000_000, 0)
	sm := s.sitemap
	for _, p := range []string{"/account", "/api/v1", "/api/v1/users", "/docs", "/fresh"} {
		if !sm.AddUnrequested("app.test", 80, false, p, "/", seen) {
			t.Fatalf("AddUnrequested %s refused", p)
		}
	}
	for _, p := range []string{"/admin", "/api"} {
		sm.Insert("app.test", 80, false, p, seen)
	}
	// Requested afterwards: /account exactly, /api/v1/users/7 (so /api, /api/v1 and /api/v1/users are
	// folders of an observed path).
	for _, p := range []string{"/account", "/api/v1/users/7"} {
		sm.Add(&core.Exchange{Host: "app.test", Port: 80, Method: "GET", Path: p})
	}

	rec := get(t, s, "/api/sitemap")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/sitemap = %d %s", rec.Code, rec.Body.String())
	}
	var v sitemapTreeResp
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	var unrequested, inserted []string
	var walk func([]sitemapNodeView)
	walk = func(ns []sitemapNodeView) {
		for _, n := range ns {
			if n.Unrequested {
				unrequested = append(unrequested, n.Path)
			} else if n.Inserted {
				inserted = append(inserted, n.Path)
			}
			walk(n.Children)
		}
	}
	walk(v.Tree)
	sort.Strings(unrequested)
	sort.Strings(inserted)
	if got, want := strings.Join(unrequested, ","), "/docs,/fresh"; got != want {
		t.Errorf("unrequested items = %s, want %s", got, want)
	}
	if got, want := strings.Join(inserted, ","), "/admin"; got != want {
		t.Errorf("inserted items = %s, want %s", got, want)
	}
}
