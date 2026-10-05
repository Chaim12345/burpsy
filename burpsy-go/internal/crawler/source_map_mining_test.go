package crawler

// Tests for mining a fetched source map's sourcesContent (burpsy-react-ui-jwy5).
//
// The claim under test is an END-TO-END one: a route that exists ONLY inside a bundle's source map —
// nowhere in the minified body, nowhere in the HTML — is discovered and then actually requested. A
// test that asserts the extractor returns "/api/admin" would pass against a pass that parsed the map
// and threw the paths away; only a crawl that FETCHES the path proves the mine reached the frontier.
//
// # Why sourcesContent is the text that carries routes
//
// A production bundle's `sourcesContent` is the ORIGINAL source, written by a human before minification.
// For a SPA that is where the route table lives in readable form — `router.get("/admin", …)` — which
// is the whole reason one request to a .map is the highest-value find in a JavaScript application.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The page names a map; the map's sourcesContent names a route the minified body does not.
const minedRoutePage = `<html><body><script>
//# sourceMappingURL=/static/js/main.js.map
</script></body></html>`

// sourceMapTarget serves a page whose inline script names a map, and a map whose sourcesContent
// carries `sources`. It returns a record of every path the crawl actually requested.
func miningTarget(t *testing.T, sourcesContent []string) (*httptest.Server, *[]string) {
	t.Helper()
	var fetched []string
	record := func(w http.ResponseWriter, r *http.Request) {
		fetched = append(fetched, r.URL.Path)
		w.Write([]byte("ok"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/static/js/main.js.map", func(w http.ResponseWriter, r *http.Request) {
		fetched = append(fetched, r.URL.Path)
		parts := make([]string, 0, len(sourcesContent))
		for _, s := range sourcesContent {
			quoted, err := json.Marshal(s)
			if err != nil {
				quoted = []byte(`""`)
			}
			parts = append(parts, string(quoted))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":3,"sources":["webpack:///src/routes.ts"],"sourcesContent":[` +
			strings.Join(parts, ",") + `]}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(minedRoutePage))
			return
		}
		record(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &fetched
}

// THE END-TO-END CLAIM: a route that exists only inside sourcesContent is fetched.
func TestARouteThatExistsOnlyInsideTheSourceMapIsCrawled(t *testing.T) {
	// The route is in the map's embedded source. The MINIFIED BODY carries nothing — the page's
	// inline script is only the marker — so this path cannot be reached any other way.
	srv, fetched := miningTarget(t, []string{
		"import { Router } from 'vue-router';\nconst routes = [\n  { path: '/api/admin', name: 'admin' },\n];\n",
	})

	h := newHarness()
	h.scope.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	cfg := h.config(srv.URL + "/")
	cfg.RequestSpeculative = true
	run(t, cfg)

	if !containsStr(*fetched, "/api/admin") {
		t.Errorf("the route inside the source map was never crawled; the requests were %v. The map "+
			"was fetched (criterion 2) but its embedded source was not read.", *fetched)
	}
}

// A route the map names as a FILE must never become a request: "/src/routes/dashboard.ts" is a
// TypeScript path inside the build tree, and admitting it would flood the frontier with filenames
// that 404 — the exact failure mode that makes a map pass a liability instead of a find.
func TestAFilePathInTheMapsSourcesArrayIsNeverFetched(t *testing.T) {
	srv, fetched := miningTarget(t, []string{
		"// a source file that mentions a file-shaped path\nimport x from './src/routes/dashboard.ts';\n",
	})

	h := newHarness()
	h.scope.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	cfg := h.config(srv.URL + "/")
	cfg.RequestSpeculative = true
	run(t, cfg)

	for _, path := range *fetched {
		if strings.HasSuffix(path, ".ts") {
			t.Errorf("the crawler requested the TypeScript file %q; a map's `sources` entries are "+
				"build-tree paths, not URLs, and fetching them is the 404 flood this pass must avoid "+
				"(requests were %v)", path, *fetched)
		}
	}
}

// A production build that ships maps WITHOUT sourcesContent is the common case. The fetch is still
// counted — it happened — and nothing is invented to fill the gap.
func TestAMapWithNoEmbeddedSourceIsARealFetchAndAnHonestEmpty(t *testing.T) {
	var fetched []string
	mux := http.NewServeMux()
	mux.HandleFunc("/static/js/main.js.map", func(w http.ResponseWriter, r *http.Request) {
		fetched = append(fetched, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":3,"sources":["webpack:///src/a.ts","webpack:///src/b.ts"]}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(minedRoutePage))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	h.scope.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	cfg := h.config(srv.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	if rep.SourceMapsFetched != 1 {
		t.Errorf("SourceMapsFetched = %d, want 1: the map really was fetched, and reporting zero "+
			"would hide a request this crawl made", rep.SourceMapsFetched)
	}
	for _, path := range fetched {
		if path != "/" && path != "/static/js/main.js.map" && path != "/robots.txt" {
			t.Errorf("a map with no embedded source produced the request %q; its sources are file "+
				"paths and yield nothing (requests were %v)", path, fetched)
		}
	}
}

// A map that is not JSON at all — an HTML error page served at 200, the usual shape of a 404 that
// answers politely — must not fail the crawl. Two claims, about DIFFERENT readers:
//
//   - the MAP READER invents nothing from it (the extractor table below pins that directly);
//   - the request still happened and is still counted, because it was real traffic this crawl sent
//     and reporting zero would hide it.
//
// What this does NOT claim: that no link inside such a body is followed. A link in an HTML body is
// found by the ordinary HTML reader, which is correct behaviour for a mislabelled 200 and not a
// map-mining defect.
func TestAMapThatIsNotJSONDoesNotFailTheCrawl(t *testing.T) {
	var fetched []string
	mux := http.NewServeMux()
	mux.HandleFunc("/static/js/main.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Not Found</body></html>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fetched = append(fetched, r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(minedRoutePage))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	h.scope.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	cfg := h.config(srv.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	if rep.Fetched == 0 {
		t.Error("the crawl fetched nothing at all; the fixture is not exercising the path")
	}
	if rep.SourceMapsFetched != 1 {
		t.Errorf("SourceMapsFetched = %d, want 1: the request was made and captured even though its "+
			"body was not a map, and reporting zero would hide a request this crawl sent",
			rep.SourceMapsFetched)
	}
	for _, path := range fetched {
		if path != "/" && path != "/static/js/main.js.map" && path != "/robots.txt" {
			t.Errorf("a non-JSON map response produced the request %q; the map reader mines nothing "+
				"from a body that is not JSON (requests were %v)", path, fetched)
		}
	}
}

// The speculative cap bounds the mining exactly as it bounds every other speculative find: a map
// carrying far more paths than the cap admits is truncated AT the cap, and the overflow is counted.
// Without this, one map could flood the frontier past every bound the crawl advertises.
func TestTheSpeculativeCapBoundsWhatAMapCanContribute(t *testing.T) {
	var paths []string
	for i := 0; i < 200; i++ {
		paths = append(paths, `router.get("/route-`+itoaForTest(i)+`", h);`)
	}
	srv, _ := miningTarget(t, []string{strings.Join(paths, "\n")})

	h := newHarness()
	h.scope.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	cfg := h.config(srv.URL + "/")
	cfg.RequestSpeculative = true
	cfg.Limits.MaxSpeculativeLinks = 5
	rep := run(t, cfg)

	if rep.SpeculativeAdmitted > 5 {
		t.Errorf("SpeculativeAdmitted = %d with the cap at 5; a source map must be bounded by the "+
			"same cap as every other speculative find, or one artifact overrides the crawl's own bounds",
			rep.SpeculativeAdmitted)
	}
}

// itoaForTest is a tiny decimal formatter so this file carries no strconv import for one loop.
func itoaForTest(n int) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

// The extractor itself, as a table, because the shapes are the interesting part and the end-to-end
// test above cannot say WHY an empty map yielded nothing.
func TestSourceMapSourcesContentReadsTheShapesRealBuildsEmit(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"one source", `{"version":3,"sourcesContent":["/a"]}`, "/a\n"},
		{"two sources", `{"version":3,"sourcesContent":["/a","/b"]}`, "/a\n/b\n"},
		{"an absent array", `{"version":3,"sources":["a.ts"]}`, ""},
		{"an explicit empty array", `{"version":3,"sourcesContent":[]}`, ""},
		{"an empty entry is skipped, not read as content", `{"version":3,"sourcesContent":["","/b"]}`, "/b\n"},
		{"not JSON at all", `<html>404</html>`, ""},
		{"truncated JSON", `{"version":3,"sourcesContent":["/a"`, ""},
		{"a null entry is not a string", `{"version":3,"sourcesContent":[null,"/b"]}`, "/b\n"},
		// `sources` alone is the common case and the trap: it is a file list, and reading it as text
		// would hand "/src/routes.ts" to the path gates.
		{"sources alone yields nothing", `{"version":3,"sources":["/src/routes.ts","/src/app.ts"]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sourceMapSourcesContent([]byte(tc.body)); got != tc.want {
				t.Errorf("sourceMapSourcesContent(%s) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// The mined path is a SPECULATIVE link, counted as one — so it is bounded by the same cap and shows
// in the same tally as a comment-borne find. A pass that mined the map and admitted the path as an
// ordinary navigational link would escape the cap entirely, and this is what pins that it does not.
// It also kills the mine-and-discard mutant: with no admit call at all, admitted stays zero.
func TestAMinedRouteIsAdmittedAsASpeculativeLink(t *testing.T) {
	srv, _ := miningTarget(t, []string{`router.get("/api/admin", h);`})

	h := newHarness()
	h.scope.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	cfg := h.config(srv.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	if rep.SpeculativeAdmitted == 0 {
		t.Error("SpeculativeAdmitted = 0 with a route inside the map; the mining pass read the map and " +
			"admitted nothing, which is the same observable result as a map that was never read")
	}
	if rep.RequestSpeculative != true {
		t.Error("the report does not record that the speculative phase ran; a report that says a map " +
			"was fetched without saying what it contributed overstates the pass")
	}
}

// The page names a map AND links to a second page, so the crawl records the map's fetch and then a
// LATER row for that second page. Reading the last row therefore reads the SECOND PAGE's body, not
// the map's — which is exactly the substitution this test exists to catch, and the reason the miner
// looks its row up by URL instead of by position.
func TestTheMapBodyIsReadFromTheMapsOwnExchangeNotTheLastRow(t *testing.T) {
	var fetched []string
	record := func(w http.ResponseWriter, r *http.Request) {
		fetched = append(fetched, r.URL.Path)
		w.Write([]byte("ok"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/static/js/main.js.map", func(w http.ResponseWriter, r *http.Request) {
		fetched = append(fetched, r.URL.Path)
		quoted, _ := json.Marshal(`router.get("/api/admin", h);`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":3,"sources":[],"sourcesContent":[` + string(quoted) + `]}`))
	})
	mux.HandleFunc("/second", func(w http.ResponseWriter, r *http.Request) {
		fetched = append(fetched, r.URL.Path)
		w.Write([]byte("second page"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			// A link of its own, so a fetch recorded AFTER the map's is guaranteed to exist.
			_, _ = w.Write([]byte(`<html><body><a href="/second">second</a><script>` +
				`//# sourceMappingURL=/static/js/main.js.map</script></body></html>`))
			return
		}
		record(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	h.scope.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	cfg := h.config(srv.URL + "/")
	cfg.RequestSpeculative = true
	run(t, cfg)

	if !containsStr(fetched, "/static/js/main.js.map") {
		t.Fatalf("the map was never fetched; the fixture is not exercising the readback (%v)", fetched)
	}
	if !containsStr(fetched, "/second") {
		t.Fatalf("the page's own link was never followed, so no row sits after the map's and the "+
			"positional bug would be invisible here (%v)", fetched)
	}
	if !containsStr(fetched, "/api/admin") {
		t.Errorf("the route inside the map was not crawled (%v). The map's body must be read from the "+
			"exchange whose URL is the MAP's; reading the last fetch row instead reads whichever "+
			"response was recorded last, which here is /second's", fetched)
	}
}

// A map whose sourcesContent is empty must not reach the admission loop at all. Pinning it directly
// (rather than through "nothing was requested") is what makes the empty case a decision rather than
// an accident: the pass reads the map, finds no source text, and stops.
func TestAMapWithNoSourceTextIsNeverOfferedToTheAdmissionGates(t *testing.T) {
	var fetched []string
	mux := http.NewServeMux()
	mux.HandleFunc("/static/js/main.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":3,"sources":["a.ts"],"sourcesContent":[]}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fetched = append(fetched, r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(minedRoutePage))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	h.scope.Add(core.NewScopeRule(core.ScopeInclude, "127.0.0.1"))
	cfg := h.config(srv.URL + "/")
	cfg.RequestSpeculative = true
	rep := run(t, cfg)

	if rep.SpeculativeAdmitted != 0 {
		t.Errorf("SpeculativeAdmitted = %d with a map carrying no source text; an empty map must "+
			"contribute nothing rather than be mined as though it had content", rep.SpeculativeAdmitted)
	}
	for _, path := range fetched {
		if path != "/" && path != "/static/js/main.js.map" && path != "/robots.txt" {
			t.Errorf("an empty map produced the request %q (requests were %v)", path, fetched)
		}
	}
}
