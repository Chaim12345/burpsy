package crawler

// Tests for fragment-routing support (burpsy-react-ui-wbqx): a hash-routed SPA puts its location in
// the fragment, so `#/orders/7` and `#/orders/8` are two pages of one GET. Burp detects this by
// character and offers `application_uses_fragments_for_routing` to force it; these tests pin both
// halves — that a routing fragment becomes identity, and that it NEVER goes on the wire.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The load-bearing property: two routes of one document are two locations, not one. Without the
// fragment in the request fingerprint the second would be refused as already-queued and the crawl
// would report one location for an entire hash-routed application.
func TestTwoRoutingFragmentsAreTwoLocations(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="#/orders/7">seven</a><a href="#/orders/8">eight</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := newHarness().config(srv.URL + "/")
	rep := run(t, cfg)

	// The page itself plus one fetch per route: both routes share one GET, and the CLIENT is what
	// renders the route, so the server sees the document repeatedly. That is correct.
	if hits < 3 {
		t.Errorf("the crawl made %d requests; two routing fragments should each be a location, so "+
			"the page is fetched once per route. Fetches: %v", hits, fetchLog(rep))
	}
	for _, want := range []string{"#/orders/7", "#/orders/8"} {
		found := false
		for _, f := range rep.Fetches {
			if f.Fragment == want {
				found = true
			}
		}
		if !found {
			t.Errorf("route %q was not fetched; a hash-routed SPA collapsed to one location", want)
		}
	}
}

// An in-page anchor is NOT a route and is still stripped, or every page with a table of contents
// would be crawled once per section.
func TestAnInPageAnchorIsNotARoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="#top">top</a><a href="#section-2">two</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := newHarness().config(srv.URL + "/")
	rep := run(t, cfg)

	for _, f := range rep.Fetches {
		if f.Fragment != "" {
			t.Errorf("an in-page anchor %q became a crawl location; only fragments containing the "+
				"routing characters are routes", f.Fragment)
		}
	}
}

// The fragment is identity ONLY: it must never appear in the request line, or every fetch of a
// route would be a malformed request.
func TestTheFragmentIsNeverSentOnTheWire(t *testing.T) {
	// Only the document fetch is asserted on: robots.txt is a different request this crawl makes
	// and is not what the test is about.
	var sawRaw string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			sawRaw = r.RequestURI
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="#/orders/7">seven</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := newHarness().config(srv.URL + "/")
	run(t, cfg)

	if sawRaw != "/" && sawRaw != "" {
		t.Errorf("the server saw request URI %q; the fragment is crawl identity and must not reach "+
			"the wire", sawRaw)
	}
}

// The Burp key lands on the field the crawl reads, and is reported applied.
func TestTheFragmentsRoutingBurpKeyIsApplied(t *testing.T) {
	const config = `{"crawler":{"customization":{"application_uses_fragments_for_routing": true}}}`
	cfg, err := ParseBurpCrawlConfig([]byte(config))
	if err != nil {
		t.Fatalf("a configuration naming the fragments-routing key failed to parse: %v", err)
	}
	if !cfg.FragmentsRoute {
		t.Error("FragmentsRoute was not set from the file")
	}
	if !containsString(cfg.AppliedKeys, "customization/application_uses_fragments_for_routing") {
		t.Errorf("the key was not reported applied; applied=%v unrepresentable=%v",
			cfg.AppliedKeys, cfg.UnrepresentableKeys)
	}
}

// fragmentIsRouting is Burp's character rule: / \ ? = & .
func TestTheRoutingCharacterRuleMatchesBurp(t *testing.T) {
	for _, frag := range []string{"/orders/7", "!/x", "?page=2", "a=b", "x&y"} {
		if !fragmentIsRouting(frag) {
			t.Errorf("fragment %q contains a routing character and should be treated as a route", frag)
		}
	}
	for _, frag := range []string{"top", "section-2", "", "Overview"} {
		if fragmentIsRouting(frag) {
			t.Errorf("fragment %q has no routing character and must be stripped as an anchor", frag)
		}
	}
}
