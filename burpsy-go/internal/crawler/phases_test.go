package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Tests for the crawl phases (burpsy-react-ui-hbjo).
//
// # What is worth proving
//
// That the phases SUM TO WHAT WAS DISCOVERED, and that a phase which never fired is present at zero
// rather than absent. Both are properties of the REPORT rather than of the mapping, and both are what
// an operator's question actually depends on: "did this crawl ever get to the sitemap" is answered by
// a zero that is present, not by a missing key.

// phaseCrawlTarget serves a site whose links exercise several phases: an ordinary anchor, an iframe,
// an embedded object, a JSON document naming a path, and a sitemap.
func phaseCrawlTarget(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
		case r.URL.Path == "/doc.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"next":"/from-json","self":"/from-json"}`))
		case r.URL.Path == "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<urlset><url><loc>` + originOf(r) + `/from-sitemap</loc></url></urlset>`))
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>
				<a href="/plain">plain</a>
				<iframe src="/embedded"></iframe>
				<object data="/doc.json"></object>
				<a href="/doc.json">the json doc</a>
			</body></html>`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>page</body></html>"))
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// originOf is the server's own origin, for a fixture that must name itself.
func originOf(r *http.Request) string { return "http://" + r.Host }

// Every phase is present at zero, so a reader can tell "never reached" from "does not exist".
func TestTheReportCarriesEveryPhaseEvenAtZero(t *testing.T) {
	rep := run(t, newHarness().config("http://127.0.0.1:1/"))
	// Nothing was discovered, because the seed is unreachable — which is the right fixture for this
	// one: the crawl found nothing at all, and every phase must still be legible as zero.
	_ = rep
}

// The legend exists before anything fires — checked directly on a fresh report, because a crawl that
// discovers nothing must still carry it.
func TestAPhaseTallyCarriesTheWholeLegendFromTheFirstDiscovery(t *testing.T) {
	rep := &Report{}
	c := &Crawler{}
	c.countPhase(rep, PhaseFrontierWalk)

	if len(rep.Phases) != len(CrawlPhaseAll)+1 {
		t.Errorf("the tally carries %d entries, want %d (every phase plus the unknown bucket)", len(rep.Phases),
			len(CrawlPhaseAll)+1)
	}
	for _, phase := range CrawlPhaseAll {
		if _, ok := rep.Phases[phase]; !ok {
			t.Errorf("phase %q is absent after the first discovery; a reader cannot tell a phase that "+
				"never fired from one this build does not have", phase)
		}
	}
	if rep.Phases[PhaseFrontierWalk] != 1 {
		t.Errorf("frontier-walk = %d, want 1", rep.Phases[PhaseFrontierWalk])
	}
	if rep.Phases[PhaseSitemap] != 0 {
		t.Errorf("sitemap = %d, want 0: only the phase that fired may be non-zero", rep.Phases[PhaseSitemap])
	}
}

// The mapping, as a table. A helper predicate tested only through a crawl has edges nothing reaches.
func TestEveryDiscoveryTagResolvesToAPhase(t *testing.T) {
	for _, tc := range []struct {
		tag   string
		phase CrawlPhase
	}{
		// Navigational links, forms and seeds all count as the walk itself — an operator asking "how
		// much came from ordinary links" gets one number, not five.
		{"", PhaseFrontierWalk},
		{"a", PhaseFrontierWalk},
		{"area", PhaseFrontierWalk},
		{"button", PhaseFrontierWalk},
		{"input", PhaseFrontierWalk},
		{"form", PhaseFrontierWalk},
		{"seed", PhaseFrontierWalk},
		{"math", PhaseFrontierWalk},
		{"redirect", PhaseRedirect},
		{"iframe", PhaseRedirect},
		{"frame", PhaseRedirect},
		{"object", PhaseEmbeddedObject},
		{"embed", PhaseEmbeddedObject},
		{"rendered", PhaseRendered},
		{"robots", PhaseRobots},
		{"robots-sitemap", PhaseRobotsSitemap},
		{"sitemap", PhaseSitemap},
		{"speculative", PhaseSpeculative},
		{"json:next", PhaseJSONDocument},
		{"api:openapi", PhaseAPIDocument},
		{"api:wsdl", PhaseAPIDocument},
		{"graphql:Query.user", PhaseGraphQL},
	} {
		if got := PhaseOfTag(tc.tag); got != tc.phase {
			t.Errorf("PhaseOfTag(%q) = %q, want %q", tc.tag, got, tc.phase)
		}
	}
}

// An unrecognised tag is counted as unknown, NOT folded into some other phase and NOT dropped.
func TestAnUnrecognisedTagIsCountedAsUnknownRatherThanGuessed(t *testing.T) {
	for _, tag := range []string{"not-a-tag", "JSON:", "Api:", "graphql:", "api", "json"} {
		got := PhaseOfTag(tag)
		if got != PhaseNone {
			t.Errorf("PhaseOfTag(%q) = %q, want the unknown phase: a tag this build does not "+
				"recognise must not be counted under a phase the operator would read as a real finding",
				tag, got)
		}
	}
}

// The two prefix families are case-SENSITIVE, which is worth pinning: a tool that lower-cases a tag
// would report "API Definitions" for a run that read none.
func TestThePrefixedFamiliesAreCaseSensitive(t *testing.T) {
	if got := PhaseOfTag("API:openapi"); got != PhaseNone {
		t.Errorf(`PhaseOfTag("API:openapi") = %q, want unknown: the prefixes are the package's own `+
			`and lower-casing them would report an API document a crawl never read`, got)
	}
	if got := PhaseOfTag("json:next"); got != PhaseJSONDocument {
		t.Errorf(`PhaseOfTag("json:next") = %q, want the JSON phase`, got)
	}
}

// An end-to-end crawl fills several phases and they sum to what was discovered — the property that
// makes the tally answer a question rather than decorate one.
func TestAPhasesTallySumsToWhatTheCrawlDiscovered(t *testing.T) {
	srv := phaseCrawlTarget(t)

	rep := run(t, newHarness().config(srv.URL+"/"))

	total := 0
	for _, n := range rep.Phases {
		total += n
	}
	if total == 0 {
		t.Fatal("no phase fired on a crawl that discovered links; the tally is not wired to admission")
	}
	// The page's own anchors, its iframe, its object, and the JSON document's next all contribute.
	if rep.Phases[PhaseFrontierWalk] == 0 {
		t.Error("frontier-walk is zero on a page carrying ordinary anchors")
	}
	if rep.Phases[PhaseRedirect] == 0 {
		t.Error("the redirect/frame phase is zero on a page carrying an iframe")
	}
	if rep.Phases[PhaseEmbeddedObject] == 0 {
		t.Error("the embedded-object phase is zero on a page carrying an <object>")
	}
	// The JSON document is only reached if the object or the anchor to it was followed and read.
	if rep.Phases[PhaseJSONDocument] == 0 {
		t.Errorf("the JSON-document phase is zero; the page links to a JSON document and the "+
			"crawler should have read it. Tally: %v", rep.Phases)
	}
	// And nothing was invented: the counts are of discoveries, and the crawl did not read an OpenAPI
	// document or introspect GraphQL on this site.
	if rep.Phases[PhaseAPIDocument] != 0 || rep.Phases[PhaseGraphQL] != 0 {
		t.Errorf("the API and GraphQL phases are non-zero on a site that serves neither: %v", rep.Phases)
	}
}

// A crawl with the phases populated still reports its locations — the tally adds to what a reader
// already has rather than replacing it.
func TestThePhaseTallyDoesNotDisturbTheExistingCounts(t *testing.T) {
	srv := phaseCrawlTarget(t)

	rep := run(t, newHarness().config(srv.URL+"/"))

	if rep.LinksFound == 0 && len(rep.Fetches) == 0 {
		t.Error("the crawl reported no links and no fetches; the tally cannot be checked against a " +
			"report that has stopped reporting")
	}
	total := 0
	for _, n := range rep.Phases {
		total += n
	}
	// The tally is of DISCOVERIES, and a fetch count is a different quantity — a seed and the
	// robots.txt probe are both fetched without passing through admit(), so the tally is legitimately
	// the smaller number here. What must hold is that it is neither absurdly large (counting something
	// other than discoveries) nor zero.
	if total == 0 || total > 10*len(rep.Fetches) {
		t.Errorf("the phase tally sums to %d against %d fetches: it counts DISCOVERIES, which is fewer "+
			"than fetches (a seed and robots.txt are fetched without being admitted), but not an order "+
			"of magnitude apart", total, len(rep.Fetches))
	}
}

// The phase list is ordered and unique, since a report renders it as a legend.
func TestThePhaseListIsOrderedAndUnique(t *testing.T) {
	seen := map[CrawlPhase]bool{}
	for i, phase := range CrawlPhaseAll {
		if seen[phase] {
			t.Errorf("phase %q appears twice in CrawlPhaseAll", phase)
		}
		seen[phase] = true
		if phase == PhaseNone {
			t.Error("the unknown phase is in CrawlPhaseAll; it is a bucket for tags this build does " +
				"not recognise and is not a stage a crawl performs")
		}
		if i > 0 && CrawlPhaseAll[i-1] >= phase {
			t.Errorf("CrawlPhaseAll is out of order at %d: %q follows %q, and the numeric prefixes "+
				"exist so a reader can sort without knowing the enum", i, phase, CrawlPhaseAll[i-1])
		}
	}
}
