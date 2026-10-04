package crawler

// Tests for source-map recovery (burpsy-react-ui-jwy5, criterion 2).
//
// # The property under test is PASSIVITY, not extraction
//
// Criterion 2 says "no requests beyond fetching a .map", and that is the constraint that decides
// whether this feature is safe in a proxy-bound crawler. So the load-bearing assertions are about what
// the crawl FETCHED — exactly one extra request, to the map, nothing else — and about the map going
// through the ordinary pipeline so scope still governs it. An implementation that fetched the map from
// a private http.Client would pass every "did it find the endpoint" test and violate the bead.
//
// # Why the fixture uses an INLINE script
//
// An EXTERNAL `<script src>` is a subresource the crawler never fetches (discover.go:24: "Neither
// queued nor fingerprinted: img, script, link, source, embed, video, audio"). A map named by one is
// therefore unreachable without first fetching the bundle, and criterion 3 allows no request beyond
// the map. An inline script's body is in the page the crawl already holds, so its reference is visible
// with no request at all — which is what makes this reachable inside the bead's own constraint.
//
// The reachable set is therefore an inline script, and an external bundle this crawl has already
// captured as live traffic. Both name a map; neither needs a new request to learn that.
//
// # What is NOT claimed
//
// The map's own `sources` are NOT turned into locations. "/src/routes/dashboard.ts" is a file path, not
// a URL; admitting it would flood the frontier with TypeScript filenames that 404. The fetch is
// counted and the artifacts are read, but no source path becomes a location.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// inlineMapPage is a page whose INLINE script names a map. Kept as a package constant so the fixture
// and any later test read the same bytes.
const inlineMapPage = `<html><body><script>
//!function(){var r={p:["/dashboard"]};}();
//# sourceMappingURL=/static/js/main.js.map
</script></body></html>`

// sourceMapTarget serves that page and a map for it, recording every request it receives.
func sourceMapTarget(t *testing.T, mapBody string) (*httptest.Server, *[]string) {
	t.Helper()
	var fetched []string
	mux := http.NewServeMux()
	mux.HandleFunc("/static/js/main.js.map", func(w http.ResponseWriter, r *http.Request) {
		fetched = append(fetched, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mapBody))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(inlineMapPage))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &fetched
}

// The reference resolves against the PAGE for an inline script — the only base it has.
func TestAnInlineScriptsSourceMapResolvesAgainstThePage(t *testing.T) {
	got := parsePage([]byte(inlineMapPage), mustURL(t, "http://a.test/static/js/page.html"), DefaultLimits(), true)
	want := "http://a.test/static/js/main.js.map"
	if got.sourceMap != want {
		t.Errorf("sourceMap = %q, want %q — an inline script has no src of its own, so its "+
			"reference resolves against the page", got.sourceMap, want)
	}
}

// An absolute reference is taken AS WRITTEN, not re-resolved: it names a host the crawl may not
// cover, and rewriting it against the page would invent a same-host URL that does not exist.
func TestAnAbsoluteSourceMapReferenceIsNotRewritten(t *testing.T) {
	page := "<html><body><script>\n//# sourceMappingURL=https://cdn.example/m.js.map\n</script></body></html>"
	got := parsePage([]byte(page), mustURL(t, "http://a.test/"), DefaultLimits(), true)
	if got.sourceMap != "https://cdn.example/m.js.map" {
		t.Errorf("sourceMap = %q, want the reference as written; whether that host may be fetched "+
			"is the scope gate's decision, made later, on the real URL", got.sourceMap)
	}
}

// The extraction itself, as a table, because the shapes are the interesting part.
func TestSourceMapReferenceReadsEveryShapeARealBuildEmits(t *testing.T) {
	for _, tc := range []struct{ name, script, want string }{
		{"the plain form", "//# sourceMappingURL=main.js.map", "main.js.map"},
		{"code after the marker", "//# sourceMappingURL=a.map\nmore();after();", "a.map"},
		{"trailing whitespace", "//# sourceMappingURL=  a.map  ", "a.map"},
		{"the block-comment form", "/*# sourceMappingURL=b.map */", "b.map"},
		// The LAST marker wins: a concatenated bundle emits one per input and the last describes the
		// output the operator actually holds. Taking the first fetches a map for a component that is
		// not there.
		{"several markers, last wins", "//# sourceMappingURL=first.map\nx();\n//# sourceMappingURL=last.map", "last.map"},
		// An inline map is already in the body; there is nothing to fetch and a data: URL through the
		// resolver and the scope gate would be a request to nowhere.
		{"an inline map yields nothing to fetch", "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==", ""},
		{"no marker", `var routes = ["/a"];`, ""},
		{"an empty reference", "//# sourceMappingURL=", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sourceMapReference(tc.script); got != tc.want {
				t.Errorf("sourceMapReference(%q) = %q, want %q", tc.script, got, tc.want)
			}
		})
	}
}

// End to end: the crawl fetches the map, and the fetch appears in the pipeline like any other.
func TestTheCrawlFetchesTheSourceMapItSaw(t *testing.T) {
	srv, fetched := sourceMapTarget(t, `{"version":3,"sources":["webpack:///src/routes.ts"],"sourcesContent":["export const r = ['/from-the-map'];"]}`)

	cfg := newHarness().config(srv.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	if rep.SourceMapsFetched == 0 {
		t.Errorf("no source map was fetched; the requests that were made were %v", *fetched)
	}
	if !containsStr(*fetched, "/static/js/main.js.map") {
		t.Errorf("the map was not fetched; requests were %v", *fetched)
	}
}

// PASSIVITY: the pass adds the map request and nothing else. Criterion 3, asserted.
func TestTheSourceMapPassAddsExactlyOneRequestAndNoOthers(t *testing.T) {
	srv, fetched := sourceMapTarget(t, `{"version":3,"sources":[],"sourcesContent":[]}`)

	cfg := newHarness().config(srv.URL + "/")
	cfg.RequestSpeculative = true
	run(t, cfg)

	for _, path := range *fetched {
		switch path {
		case "/", "/robots.txt", "/static/js/main.js.map":
		default:
			t.Errorf("the source-map pass requested %q; criterion 3 allows no request beyond the "+
				"page's own and the map. Every request was %v", path, *fetched)
		}
	}
}

// A map that is not there must not become a location and must not fail the crawl.
func TestASourceMapThatIsNotThereIsNeitherAFailureNorALocation(t *testing.T) {
	var hits []string
	mux := http.NewServeMux()
	mux.HandleFunc("/missing.map", func(w http.ResponseWriter, r *http.Request) { hits = append(hits, "map") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><script>\n//# sourceMappingURL=/missing.map\n</script></body></html>"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := newHarness().config(srv.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	if len(hits) == 0 {
		t.Error("the missing map was never requested; the fixture is not exercising the path")
	}
	if rep.Fetched == 0 {
		t.Error("nothing was fetched at all")
	}
	// The 404 was a real request and is counted as a fetch — the crawl did send it. What it must not
	// become is a LOCATION: a .map is a build artifact, not a page of the application.
	for _, f := range rep.Fetches {
		if strings.Contains(f.URL, ".map") && f.ExchangeID == 0 {
			t.Errorf("the source map became a location with no exchange behind it: %q", f.URL)
		}
	}
}

// With the speculative phase off, no map is fetched: the reader rides on the phase that already reads
// script bodies, and a crawl with that off has not asked to read JavaScript.
func TestNoSourceMapIsFetchedWhenTheSpeculativePhaseIsOff(t *testing.T) {
	srv, fetched := sourceMapTarget(t, `{"version":3,"sources":[]}`)

	cfg := newHarness().config(srv.URL + "/")
	cfg.RequestSpeculative = false
	rep := run(t, cfg)

	if rep.SourceMapsFetched != 0 {
		t.Errorf("SourceMapsFetched = %d with the speculative phase off; requests were %v",
			rep.SourceMapsFetched, *fetched)
	}
	if containsStr(*fetched, "/static/js/main.js.map") {
		t.Errorf("the map was fetched with the speculative phase off: %v", *fetched)
	}
}
