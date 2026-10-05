package crawler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestNormaliseJSLocation(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"/api/users", "/api/users", true},
		{`"/api/users"`, "/api/users", true},
		{"/api/v2/orders/${orderId}", "/api/v2/orders/", true},
		{"/api/v2/orders/x${id}/items", "/api/v2/orders/", true},
		{"/admin/users?id=EXPR", "/admin/users", true},
		{"EXPR/admin/users?id=EXPR", "", false},
		{"./chunk-EXPR.js", "", false},
		{"./static/app.js", "./static/app.js", true},
		{"https://cdn.test/a.js", "https://cdn.test/a.js", true},
		{".js", "", false},
		{"users", "", false},
		{"/", "", false},
		{"//cdn.test/x", "", false},
	} {
		got, ok := normaliseJSLocation(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("normaliseJSLocation(%q) = %q %v, want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// The reason for the union, pinned: on the same script, the AST pass and the text miner each find
// something the other misses (measured before this was written), and the union keeps both.
func TestTheUnionKeepsWhatEachExtractorAloneMisses(t *testing.T) {
	src := []byte("const base = \"/api\";\n" +
		"fetch(base + \"/admin/users?id=\" + id);\n" +
		"axios.get(`/api/v2/orders/${orderId}`);\n" +
		"$.ajax({url: \"/legacy/report.php\", type: \"POST\"});\n")
	cands, failed := extractJavaScript(src)
	if failed {
		t.Fatal("the AST pass failed on ordinary script")
	}
	got := map[string]jsCandidate{}
	for _, c := range cands {
		got[c.raw] = c
	}
	// jsluice alone misses the template literal; the miner finds it.
	if _, ok := got["/api/v2/orders/"]; !ok {
		t.Errorf("the template-literal path is missing: %v", got)
	}
	// The miner alone cannot know a call's method; jsluice reads it from the $.ajax options.
	if c, ok := got["/legacy/report.php"]; !ok || !strings.Contains(c.note, "POST") {
		t.Errorf("/legacy/report.php = %+v, want the POST jsluice read", c)
	}
	if _, ok := got["/admin/users"]; !ok {
		t.Errorf("the concatenated fetch path is missing: %v", got)
	}
	for raw, c := range got {
		if !strings.HasPrefix(c.tag, "js:") {
			t.Errorf("%s tagged %q, want a js: tag so the phase and the audit enumerator can tell", raw, c.tag)
		}
	}
}

// A malformed script costs the AST pass, never the file: the miner still reads it.
func TestAMalformedScriptStillYieldsTheMinersPaths(t *testing.T) {
	cands, _ := extractJavaScript([]byte("function ( { \"/still/found\" ;;; }}}} ((("))
	for _, c := range cands {
		if c.raw == "/still/found" {
			return
		}
	}
	t.Errorf("the miner's path was lost with the parse: %+v", cands)
}

// THE ACCEPTANCE TEST: a page whose only reference to /api/admin/stats is inside an external bundle
// causes that path to be crawled — and the bundle's own source map is followed, so a route present
// only in the original sources is crawled too. Before this the bundle was fetched and then recorded
// as not-HTML with nothing inside it read.
func TestAPathOnlyAnExternalBundleNamesIsCrawled(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><div id="app"></div><script src="/static/app.js"></script></body></html>`))
		case "/static/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("!function(){fetch(\"/api/admin/stats\").then(r=>r.json())}();\n//# sourceMappingURL=app.js.map\n"))
		case "/static/app.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":3,"sources":["src/router.ts"],"sourcesContent":["const routes = [\"/hidden/from-source\"];"],"mappings":""}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	rep := run(t, h.config(srv.URL+"/"))

	mu.Lock()
	defer mu.Unlock()
	if asked["/api/admin/stats"] == 0 {
		t.Fatalf("/api/admin/stats, named only inside the external bundle, was never crawled; asked: %v", asked)
	}
	if asked["/static/app.js.map"] == 0 {
		t.Error("the external bundle's source map was not followed")
	}
	if asked["/hidden/from-source"] == 0 {
		t.Error("a route present only in the source map's original sources was not crawled")
	}
	if rep.JavaScriptRead == 0 || rep.JavaScriptLocationsFound == 0 {
		t.Errorf("report: javascript_read=%d javascript_locations_found=%d", rep.JavaScriptRead, rep.JavaScriptLocationsFound)
	}
	if rep.Phases[PhaseJavaScript] == 0 {
		t.Errorf("phases = %v: a location read from a script must be counted under the javascript phase", rep.Phases)
	}
}
