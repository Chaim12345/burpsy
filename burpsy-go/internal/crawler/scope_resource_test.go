package crawler

// Tests for the out-of-scope-resource distinction (burpsy-react-ui-hgor).
//
// The claim under test is a DIAGNOSTIC one: two refusals that are identical in the wire's eyes must be
// told apart in the ledger, because they mean opposite things to an operator. One is scope working as
// configured; the other is burpsy being stricter than the tool an operator is migrating from, and it is
// the second that explains an unexpectedly small crawl on a modern site.
//
// So every test here asserts on WHICH reason fired, not on the fact that something was refused. A test
// that only counted refusals would pass against the undivided behaviour this bead replaces.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// resourceScopeTarget serves a page that loads its assets from a SECOND host, which the crawl's scope
// does not cover, and offers the same second host as a navigational link too.
//
// Both halves are needed: without a navigational out-of-scope link there is nothing to tell the
// resource refusal apart from, and the test would pass even if every out-of-scope refusal were
// recorded as a resource.
func resourceScopeTarget(t *testing.T) *httptest.Server {
	t.Helper()
	// A second listener the crawl will not be scoped for.
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(`body{}`))
	}))
	t.Cleanup(cdn.Close)

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			// A subresource from the out-of-scope host (an <img> src), and a navigational link to
			// the same host. Both must be refused; only the first is a RESOURCE refusal.
			// An <iframe> is a SUBRESOURCE the crawler does queue (discover.go:22 queues iframe[src]),
			// so an out-of-scope one produces a real refusal this bead can name. An <img> would NOT:
			// subresources like img/script/link are never discovered at all, which is the larger half
			// of this bead's finding and is recorded on it rather than asserted here.
			_, _ = w.Write([]byte(`<html><body>
				<iframe src="` + cdn.URL + `/embed"></iframe>
				<a href="` + cdn.URL + `/docs">the same host, as a link</a>
				<a href="/inside">in scope</a>
			</body></html>`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>page</body></html>"))
		}
	}))
	t.Cleanup(app.Close)
	return app
}

// A subresource on an out-of-scope host is SkipOutOfScopeResource; a navigational link to the same
// host is SkipOutOfScope. One page carrying both, so the distinction is observable in a single run.
func TestAnOutOfScopeResourceAndAnOutOfScopeLinkAreToldApart(t *testing.T) {
	app := resourceScopeTarget(t)

	// The scope covers the app host ONLY, which is the situation every crawl of a modern site is in:
	// the page is in scope and everything it loads is not.
	rep := run(t, scopedConfig(t, app.URL))

	if !skippedWith(rep, SkipOutOfScopeResource) {
		t.Errorf("a subresource naming an out-of-scope host was not recorded as SkipOutOfScopeResource; "+
			"the operator cannot tell this refusal from scope working. Counts: %s", reasonCounts(rep))
	}
	if !skippedWith(rep, SkipOutOfScope) {
		t.Errorf("a navigational link to an out-of-scope host was not recorded as SkipOutOfScope; "+
			"counts: %s", reasonCounts(rep))
	}
	// And the in-scope link was still followed — the resource branch must not swallow navigational
	// admissions, which is what would happen if the tag check were applied at the wrong gate.
	if !fetchedAny(rep, "/inside") {
		t.Errorf("the in-scope link was not followed; fetches: %v", fetchLog(rep))
	}
}

// The refusal record names the referrer and the refused host, so an operator reading the ledger can
// see WHICH page wanted the asset — the only way to answer "why is this page missing from my crawl".
func TestAnOutOfScopeResourceRefusalNamesThePageThatWantedIt(t *testing.T) {
	app := resourceScopeTarget(t)

	rep := run(t, scopedConfig(t, app.URL))

	recs := rep.Skips.Records
	found := false
	for _, r := range recs {
		if r.Reason != SkipOutOfScopeResource {
			continue
		}
		found = true
		// The URL is the refused resource and FoundAt is the page that referenced it.
		if !strings.Contains(r.FoundAt, "/") || strings.TrimSpace(r.FoundAt) == "" {
			t.Errorf("the record has no referrer: %+v", r)
		}
		if r.URL == "" {
			t.Errorf("the record names no refused URL: %+v", r)
		}
	}
	if !found {
		t.Fatalf("no SkipOutOfScopeResource record in the sampled ledger (%d records)", len(recs))
	}
}

// The whole point of the bead: a COMPLETE crawl that refused resources must SAY SO. A crawl that ran to
// completion within a narrower world than the operator expects is exactly the case the existing
// caveat is silent about — it only speaks when a bound was hit.
func TestACompleteCrawlThatRefusedResourcesSaysSoInItsCaveat(t *testing.T) {
	app := resourceScopeTarget(t)

	rep := run(t, scopedConfig(t, app.URL))

	if rep.Limits.Truncated() {
		t.Fatalf("this crawl was truncated, so the test is not exercising the complete-crawl path; "+
			"stops: %+v", rep.Limits.Stops)
	}
	if rep.Limits.OutOfScopeResources == 0 {
		t.Fatalf("nothing was counted as an out-of-scope resource, so there is nothing for the " +
			"caveat to state")
	}
	caveat := rep.Caveat()
	if caveat == "" {
		t.Fatal("a complete crawl that refused out-of-scope resources reported no caveat; the " +
			"operator cannot see the one thing that explains the crawl's size")
	}
	// The caveat must be specific enough to act on: it names the count and the Burp default that
	// explains why burpsy is stricter.
	if !strings.Contains(caveat, "outside the engagement scope") {
		t.Errorf("the caveat does not say what was refused: %q", caveat)
	}
	if !strings.Contains(caveat, "subresource") {
		t.Errorf("the caveat does not say these were SUBRESOURCES rather than navigational links: %q", caveat)
	}
	if !strings.Contains(caveat, "allow_out_of_scope_resources") {
		t.Errorf("the caveat does not name the Burp setting that explains the difference: %q", caveat)
	}
}

// A crawl that refused NO out-of-scope resources says nothing — the caveat must not gain a permanent
// sentence about a condition that did not happen, or every report grows a disclaimer nobody reads.
func TestACrawlThatRefusedNoResourcesHasNoResourceCaveat(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/next">next</a></body></html>`))
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>done</body></html>"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rep := run(t, newHarness().config(srv.URL+"/"))

	if rep.Limits.OutOfScopeResources != 0 {
		t.Errorf("OutOfScopeResources = %d for a crawl that crossed no scope boundary",
			rep.Limits.OutOfScopeResources)
	}
	if strings.Contains(rep.Caveat(), "allow_out_of_scope_resources") {
		t.Errorf("the caveat carries the Burp-default note on a crawl that never crossed a scope "+
			"boundary: %q", rep.Caveat())
	}
}

// Every new reason is fully registered — the four tables an enum member must appear in, where a missing
// entry panics at runtime rather than failing to compile.
func TestSkipOutOfScopeResourceIsFullyRegistered(t *testing.T) {
	found := false
	for _, s := range SkipAll {
		if s == SkipOutOfScopeResource {
			found = true
		}
	}
	if !found {
		t.Fatal("SkipOutOfScopeResource is not in SkipAll, so its count could never be reported")
	}
	if got := SkipOutOfScopeResource.String(); got != "out-of-scope-resource" {
		t.Errorf("String() = %q, want %q", got, "out-of-scope-resource")
	}
	// A resource refusal is still a SCOPE refusal — that is what it is — so it rolls up with the
	// navigational one rather than inventing a category for a diagnostic distinction.
	if got := SkipOutOfScopeResource.Category(); got != CategoryScope {
		t.Errorf("Category() = %v, want CategoryScope", got)
	}
	if strings.TrimSpace(SkipOutOfScopeResource.Explanation()) == "" {
		t.Error("Explanation() is empty")
	}
}

// The tag classification itself, as a table — a helper predicate tested only through a crawl is a
// predicate whose edges nothing reaches.
func TestTheResourceTagSetIsTheSubresourceElementsAndNothingElse(t *testing.T) {
	for _, tag := range []string{"iframe", "frame", "embed", "object"} {
		if !isResourceTag(tag) {
			t.Errorf("%q was not classified as a subresource", tag)
		}
	}
	for _, tag := range []string{
		"a", "area", // navigational, even with a download attribute
		"",               // a seed: named by the operator, not carried by a page
		"form", "button", // navigational actions
		"math",               // an anchor
		"json:next",          // a location read out of a JSON document
		"api:openapi",        // an endpoint read out of an API definition
		"graphql:Query.user", // an operation read out of an introspection answer
		"speculative",        // a URL mined from a comment or script body
		"redirect", "robots", "sitemap", "robots-sitemap",
	} {
		if isResourceTag(tag) {
			t.Errorf("%q was classified as a subresource; reporting a navigational link as a "+
				"resource refusal inflates the count that explains an empty crawl", tag)
		}
	}
}

// scopedConfig is newHarness().config with an include rule for the seed's own host.
//
// Needed because an empty scope DENIES (crawler_test.go:123 says so outright), so a crawl seeded
// anywhere is refused at its own seed without this. Only the seed host is in scope — which is the
// point: the CDN host below it deliberately stays out.
func scopedConfig(t *testing.T, seedURL string) Config {
	t.Helper()
	h := newHarness()
	u, err := url.Parse(seedURL)
	if err != nil {
		t.Fatalf("parse seed URL %q: %v", seedURL, err)
	}
	h.scope.Add(core.NewScopeRuleWithPort(core.ScopeInclude, u.Hostname(), portOf(u)))
	return h.config(seedURL + "/")
}

// reasonCounts renders the ledger's per-reason counts compactly for a failure message.
func reasonCounts(rep Report) string {
	var parts []string
	for _, c := range rep.Skips.Counts {
		if c.Count > 0 {
			parts = append(parts, c.Name+"="+itoa64(int64(c.Count)))
		}
	}
	return strings.Join(parts, " ")
}
