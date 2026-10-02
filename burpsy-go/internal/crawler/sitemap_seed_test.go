package crawler

// Tests for site-map seeding (burpsy-react-ui-z8qf).
//
// # The property that decides whether this is safe
//
// The `queued` table is consulted BEFORE a request is built (crawler.go:2507-2513), which means
// "already queued" short-circuits everything downstream — including the scope gate. So seeding a URL
// that the engagement does not cover would mark an out-of-scope host as already handled, and a host
// the operator never authorised would never be examined. That is a scope decision arriving through a
// performance optimisation, and it is the reason SeedFromSiteMap takes a scope predicate at all.
//
// # What is NOT tested, and why
//
// There is no test that seeding prevents a fetch of a page whose CONTENT changed. It does: the
// location table is not seeded, so a changed page has a different fingerprint and is still compared
// on its own merits. A test asserting that would be asserting the absence of a behaviour, and the
// property worth asserting is the scope one above.

import (
	"context"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sitemap"
)

// seededMap builds a site map holding the given host:port:path:method tuples.
func seededMap(t *testing.T, entries ...[4]string) *sitemap.SiteMap {
	t.Helper()
	sm := sitemap.New()
	for _, e := range entries {
		var port uint16
		switch e[1] {
		case "443":
			port = 443
		case "8080":
			port = 8080
		}
		tls := e[1] == "443"
		// Insert records the node; Add is what records the METHOD (sitemap.go:238 — the map counts
		// methods from an exchange, and Insert alone carries none).
		sm.Insert(e[0], port, tls, e[2], time.Now())
		sm.Add(&core.Exchange{Host: e[0], Port: port, TLS: tls, Method: e[3], Path: e[2]})
	}
	return sm
}

// newSeededCrawler builds a crawler whose scope covers exactly the named hosts.
//
// Uses the package's own newHarness, so the Capture seam is a real one and the test is not
// asserting against a stub that behaves differently from the wiring it is meant to exercise.
func newSeededCrawler(t *testing.T, scopeHosts ...string) (*Crawler, *core.Scope) {
	t.Helper()
	h := newHarness()
	for _, hst := range scopeHosts {
		h.scope.AddInclude(hst)
	}
	// The harness config supplies Sender and Capture, both of which New requires. Hand-building a
	// Config here is how a crawler that cannot reach a target gets constructed in a test.
	cfg := h.config("http://a.test/")
	cfg.Scope = h.scope
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, h.scope
}

// allowInScope is the predicate shape SeedFromSiteMap takes.
func allowInScope(scope *core.Scope) func(string, uint16, bool) bool {
	return func(host string, port uint16, tls bool) bool {
		return scope.MayContainHost(host, port, tls)
	}
}

// A URL the site map already holds is not queued a second time, and the saving is counted.
func TestSeedingMarksAKnownRequestAsAlreadyQueued(t *testing.T) {
	sm := seededMap(t, [4]string{"a.test", "80", "/known", "GET"})
	c, scope := newSeededCrawler(t, "a.test")

	seeded := c.SeedFromSiteMap(sm, []string{"a.test:80"}, allowInScope(scope))
	if seeded != 1 {
		t.Fatalf("seeded %d requests, want 1", seeded)
	}

	u := mustURL(t, "http://a.test/known")
	key := requestFingerprint("GET", u, nil)
	if !c.queued[key] {
		t.Error("the site map's URL is not in the queued table, so a second crawl would still fetch it " +
			"— which is the whole saving this bead is about")
	}

	// And enqueue now refuses it, with the honest reason rather than a fetch.
	item := frontierItem{url: u, method: "GET", depth: 1}
	if c.enqueue(item, "http://a.test/", &LimitReport{Limits: c.limits}) {
		t.Error("enqueue accepted a URL the site map had already recorded; the seed is not taking effect")
	}
	if c.skips.Snapshot().Count(SkipAlreadyQueued) == 0 {
		t.Error("the refusal was not recorded as SkipAlreadyQueued, so a report cannot say why")
	}
}

// THE SCOPE TEST. An out-of-scope host must not be seeded, whatever the site map holds — because
// "already queued" is checked before the scope gate, so seeding would launder an unauthorised host
// past it.
func TestSeedingAnOutOfScopeHostIsRefused(t *testing.T) {
	sm := seededMap(t,
		[4]string{"in-scope.test", "80", "/ok", "GET"},
		[4]string{"out-of-scope.test", "80", "/secret", "GET"},
	)
	c, scope := newSeededCrawler(t, "in-scope.test")

	seeded := c.SeedFromSiteMap(sm, []string{"in-scope.test:80", "out-of-scope.test:80"}, allowInScope(scope))
	if seeded != 1 {
		t.Errorf("seeded %d requests, want 1: only the in-scope host's. The site map holds every host the "+
			"console has ever seen, including ones this engagement does not cover, and seeding one would "+
			"mark it already-handled so the scope gate never sees it", seeded)
	}
	if c.queued[requestFingerprint("GET", mustURL(t, "http://out-of-scope.test/secret"), nil)] {
		t.Error("an out-of-scope URL is in the queued table; seeding it smuggles a scope decision " +
			"through a performance optimisation")
	}
	if !c.queued[requestFingerprint("GET", mustURL(t, "http://in-scope.test/ok"), nil)] {
		t.Error("the in-scope host was not seeded either, so the scope filter is refusing too much")
	}
}

// Seeding is scoped to the origins named, not to every host the map happens to hold.
func TestOnlyTheNamedOriginsAreSeeded(t *testing.T) {
	sm := seededMap(t,
		[4]string{"a.test", "80", "/here", "GET"},
		[4]string{"elsewhere.test", "80", "/there", "GET"},
	)
	c, scope := newSeededCrawler(t, "a.test", "elsewhere.test")

	seeded := c.SeedFromSiteMap(sm, []string{"a.test:80"}, allowInScope(scope))
	if seeded != 1 {
		t.Errorf("seeded %d, want 1: naming one origin must not seed the whole map", seeded)
	}
	if c.queued[requestFingerprint("GET", mustURL(t, "http://elsewhere.test/there"), nil)] {
		t.Error("a host the caller did not name was seeded; a crawl of one origin must not inherit " +
			"another origin's dedup state")
	}
}

// Each method the site map recorded is seeded, and one it never saw is not — seeding a method
// nobody sent would claim a request was made that was not.
func TestOnlyTheMethodsTheMapRecordedAreSeeded(t *testing.T) {
	sm := seededMap(t, [4]string{"a.test", "80", "/thing", "POST"})
	c, scope := newSeededCrawler(t, "a.test")
	c.SeedFromSiteMap(sm, []string{"a.test:80"}, allowInScope(scope))

	u := mustURL(t, "http://a.test/thing")
	if !c.queued[requestFingerprint("POST", u, nil)] {
		t.Error("the method the map recorded was not seeded")
	}
	if c.queued[requestFingerprint("GET", u, nil)] {
		t.Error("a method the map never observed was seeded; that claims a request was made which " +
			"was not, and would suppress a GET the crawl has never made")
	}
}

// The count is on the report, because a seeding feature whose saving nobody can see is one nobody
// can tell is working.
func TestTheSeededCountReachesTheReport(t *testing.T) {
	sm := seededMap(t, [4]string{"a.test", "80", "/one", "GET"}, [4]string{"a.test", "80", "/two", "GET"})
	c, scope := newSeededCrawler(t, "a.test")

	if got := c.SeedFromSiteMap(sm, []string{"a.test:80"}, allowInScope(scope)); got != 2 {
		t.Fatalf("SeedFromSiteMap returned %d, want 2", got)
	}
	if c.sitemapSeeded != 2 {
		t.Errorf("crawler.sitemapSeeded = %d, want 2", c.sitemapSeeded)
	}

	rep := c.Run(context.Background())
	if rep.SitemapSeeded != 2 {
		t.Errorf("report.sitemap_seeded = %d, want 2 — a saving the operator cannot read is a "+
			"saving they cannot tell is working", rep.SitemapSeeded)
	}
}

// The nil cases are the obvious misuses and none may panic.
func TestTheNilCasesAreRefusedRatherThanPanicking(t *testing.T) {
	var c *Crawler
	if got := c.SeedFromSiteMap(nil, nil, nil); got != 0 {
		t.Errorf("seeding a nil crawler returned %d, want 0", got)
	}
	c, scope := newSeededCrawler(t, "a.test")
	if got := c.SeedFromSiteMap(nil, []string{"a.test:80"}, nil); got != 0 {
		t.Errorf("seeding a nil site map returned %d, want 0", got)
	}
	if got := c.SeedFromSiteMap(sitemap.New(), nil, nil); got != 0 {
		t.Errorf("seeding with no origins returned %d, want 0", got)
	}
	// A nil scope predicate means "no filter", which is a caller asserting every origin is
	// pre-authorised. It must not silently become "refuse everything".
	sm := seededMap(t, [4]string{"a.test", "80", "/x", "GET"})
	if got := c.SeedFromSiteMap(sm, []string{"a.test:80"}, nil); got != 1 {
		t.Errorf("a nil scope predicate seeded %d, want 1: nil means no filter, not refuse-all", got)
	}
	_ = scope
}

// Seeding the same map twice does not double-count: the count is requests seeded, not entries
// written, and a second identical pass has nothing new to mark.
func TestSeedingTwiceIsIdempotent(t *testing.T) {
	sm := seededMap(t, [4]string{"a.test", "80", "/x", "GET"})
	c, scope := newSeededCrawler(t, "a.test")

	first := c.SeedFromSiteMap(sm, []string{"a.test:80"}, allowInScope(scope))
	second := c.SeedFromSiteMap(sm, []string{"a.test:80"}, allowInScope(scope))
	if first != 1 || second != 1 {
		t.Errorf("seeded %d then %d, want 1 and 1: the count is what was marked, and a repeat pass over "+
			"the same map has exactly the same work to do", first, second)
	}
	if c.sitemapSeeded != 1 {
		t.Errorf("crawler.sitemapSeeded = %d after two identical passes, want 1", c.sitemapSeeded)
	}
}
