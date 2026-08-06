package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sitemap"
)

// ---- CRAWL-05: the site map is built from proxy traffic continuously ----------------------------
//
// As found, sitemap.Sync had exactly one caller in the whole tree: the GET /api/sitemap handler. So
// the map was rebuilt from the store whenever an operator opened the tab and was empty at every other
// moment. There was no separate crawl action, which is half the requirement — but nothing was
// continuous, and a rebuild-on-read costs O(all exchanges) per view.
//
// These tests are written so they can only pass through the subscription. The read handler no longer
// syncs, so if the store observer were removed or never registered, every one of them would fail with
// an empty tree — which is the point: this is the failure mode this project has shipped twice (Match &
// Replace and the session coordinator both landed ported but unwired), and a read path that quietly
// does the subscription's job is how it stays invisible.

type sitemapNodeResp struct {
	Segment   string            `json:"segment"`
	Path      string            `json:"path"`
	Exchanges int               `json:"exchanges"`
	Methods   []string          `json:"methods"`
	Children  []sitemapNodeResp `json:"children"`
}

type sitemapResp struct {
	Exchanges int               `json:"exchanges"`
	Nodes     int               `json:"nodes"`
	Tree      []sitemapNodeResp `json:"tree"`
}

func sitemapGet(t *testing.T, s *Server) sitemapResp {
	t.Helper()
	rec := get(t, s, "/api/sitemap")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/sitemap: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var v sitemapResp
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode sitemap response %q: %v", rec.Body.String(), err)
	}
	return v
}

// addTraffic records one exchange the way the proxy does — through the store — and returns it.
func addTraffic(t *testing.T, store *core.TrafficStore, host, method, path string) *core.Exchange {
	t.Helper()
	reqID, err := store.Put([]byte(method+" "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	status := uint16(200)
	ex := &core.Exchange{
		Request:  reqID,
		Response: &respID,
		Host:     host,
		Port:     80,
		Method:   method,
		Path:     path,
		Status:   &status,
	}
	store.AddExchange(ex)
	return ex
}

// nodePaths flattens the tree to the set of paths it holds, so an assertion can name a path without
// walking children by hand.
func nodePaths(nodes []sitemapNodeResp, into map[string]int) {
	for _, n := range nodes {
		into[n.Path] = n.Exchanges
		nodePaths(n.Children, into)
	}
}

// Traffic recorded through the store appears in the site map with nothing calling Sync and no crawl
// action of any kind. This is CRAWL-05.
func TestSitemapBuildsFromTrafficWithNoSyncAndNoCrawlAction(t *testing.T) {
	s := newTestServer()

	addTraffic(t, s.store, "shop.test", "GET", "/products/list")
	addTraffic(t, s.store, "shop.test", "POST", "/cart")

	v := sitemapGet(t, s)
	if len(v.Tree) != 1 || v.Tree[0].Segment != "shop.test" {
		t.Fatalf("tree = %+v, want one host node for shop.test", v.Tree)
	}
	paths := map[string]int{}
	nodePaths(v.Tree[0].Children, paths)
	for _, want := range []string{"/products/list", "/cart"} {
		if _, ok := paths[want]; !ok {
			t.Errorf("path %q missing from the site map; got %v", want, paths)
		}
	}
	if v.Exchanges != 2 {
		t.Errorf("exchanges = %d, want 2", v.Exchanges)
	}
}

// The map keeps up: an exchange recorded after a read shows up in the next one, with no sync in
// between. A map that only reflected the store at construction time would pass the test above and
// fail this one.
func TestSitemapKeepsUpWithTrafficArrivingAfterARead(t *testing.T) {
	s := newTestServer()
	addTraffic(t, s.store, "shop.test", "GET", "/first")

	if v := sitemapGet(t, s); len(v.Tree) != 1 {
		t.Fatalf("first read: tree = %+v, want one host", v.Tree)
	}

	addTraffic(t, s.store, "later.test", "GET", "/second")

	v := sitemapGet(t, s)
	hosts := map[string]bool{}
	for _, n := range v.Tree {
		hosts[n.Segment] = true
	}
	if !hosts["later.test"] {
		t.Errorf("host recorded after the first read is missing; hosts = %v", hosts)
	}
	if !hosts["shop.test"] {
		t.Errorf("host from before the first read was lost; hosts = %v", hosts)
	}
}

// Traffic already in the store when the map is built must be folded in, and folded in exactly once —
// which is what makes ObserveExchanges return the existing set rather than leaving the caller to
// snapshot separately. A persistence restore lands exchanges before the server is constructed, so
// this is the ordinary startup path, not a corner case.
func TestSitemapBackfillsPreExistingTrafficExactlyOnce(t *testing.T) {
	store := core.NewTrafficStore()
	addTraffic(t, store, "old.test", "GET", "/before")

	s := NewServer(store, core.NewScope())
	addTraffic(t, s.store, "old.test", "GET", "/after")

	v := sitemapGet(t, s)
	paths := map[string]int{}
	for _, host := range v.Tree {
		nodePaths(host.Children, paths)
	}
	if n, ok := paths["/before"]; !ok {
		t.Errorf("pre-existing traffic missing from the site map; paths = %v", paths)
	} else if n != 1 {
		t.Errorf("/before counted %d exchanges, want 1: the backfill and the subscription must partition, not overlap", n)
	}
	if n := paths["/after"]; n != 1 {
		t.Errorf("/after counted %d exchanges, want 1", n)
	}
}

// Sync remains the rebuild primitive, and remains idempotent: calling it after the map has followed
// the store must not double every count. It is no longer on the read path, but it is still the repair
// path, and a repair that doubles the data it was repairing is worse than the fault.
func TestSitemapSyncAfterFollowingIsIdempotent(t *testing.T) {
	store := core.NewTrafficStore()
	sm := sitemap.New()
	sm.Follow(store)
	addTraffic(t, store, "shop.test", "GET", "/only")

	sm.Sync(store)
	sm.Sync(store)

	hosts := sm.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(hosts))
	}
	paths := hosts[0].PathsSorted()
	if len(paths) != 1 || len(paths[0].ExchangeIDs) != 1 {
		t.Fatalf("path exchange ids = %+v, want exactly one", paths)
	}
}

// Add is the observer the store calls, and a repeated call for the same exchange must not double the
// method and status counts. The store never repeats one, but Follow's backfill can overlap its own
// subscription by a single arrival, and a double-count there would be invisible.
func TestSitemapAddIsIdempotentForOneExchange(t *testing.T) {
	store := core.NewTrafficStore()
	sm := sitemap.New()
	ex := addTraffic(t, store, "shop.test", "GET", "/twice")

	sm.Add(ex)
	sm.Add(ex)

	path := sm.Hosts()[0].PathsSorted()[0]
	if len(path.ExchangeIDs) != 1 {
		t.Errorf("exchange ids = %v, want one", path.ExchangeIDs)
	}
	if path.Methods["GET"] != 1 {
		t.Errorf("GET counted %d times, want 1", path.Methods["GET"])
	}
	if path.Statuses[200] != 1 {
		t.Errorf("status 200 counted %d times, want 1", path.Statuses[200])
	}
}

// ObserveExchanges must partition: the returned slice plus every later callback covers each exchange
// exactly once. Tested directly because the site map's correctness rests on it.
func TestObserveExchangesPartitionsExistingFromArriving(t *testing.T) {
	store := core.NewTrafficStore()
	addTraffic(t, store, "a.test", "GET", "/1")
	addTraffic(t, store, "a.test", "GET", "/2")

	seen := map[core.ExchangeID]int{}
	existing := store.ObserveExchanges(func(ex *core.Exchange) { seen[ex.ID]++ })
	if len(existing) != 2 {
		t.Fatalf("existing = %d, want the 2 already recorded", len(existing))
	}
	addTraffic(t, store, "a.test", "GET", "/3")

	for _, ex := range existing {
		seen[ex.ID]++
	}
	if len(seen) != 3 {
		t.Fatalf("covered %d exchanges, want all 3", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("exchange %d covered %d times, want exactly once", id, n)
		}
	}
}
