package crawler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Crawl telemetry by edge kind (burpsy-react-ui-ylr1): every location is attributed to the kind of
// edge that led to it, in Burp's vocabulary, and every kind is on the wire at zero.
func TestTheReportCountsDiscoveriesByEdgeKind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><head><meta http-equiv="refresh" content="9; url=/later"></head><body>
				<a href="/a1">a</a><a href="/a2">b</a>
				<iframe src="/frame"></iframe>
				<map><area href="/area"></map>
				<form action="/search" method="get"><input name="q"></form>
			</body></html>`))
		case "/old":
			http.Redirect(w, r, "/a1", http.StatusFound)
		default:
			w.Write([]byte(`<html><body><a href="/old">old</a></body></html>`))
		}
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.SubmitForms = true
	rep := run(t, cfg)

	k := rep.EdgeKinds
	for kind, atLeast := range map[string]int{
		"origin": 1, "anchor": 2, "iframe": 1, "area": 1, "form": 1, "delayed_redirect": 1, "redirect": 1,
	} {
		if k[kind] < atLeast {
			t.Errorf("edge_kinds[%s] = %d, want at least %d (all: %v)", kind, k[kind], atLeast, k)
		}
	}
	raw, _ := json.Marshal(rep)
	for _, kind := range EdgeKindsAll {
		if !strings.Contains(string(raw), `"`+kind+`":`) {
			t.Errorf("edge kind %q missing from the marshalled report", kind)
		}
	}
	if k["graphql"] != 0 || k["soap"] != 0 {
		t.Errorf("kinds the crawl never met must be 0: %v", k)
	}
}
