package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// burpsy-react-ui-hzzl: requests a rendered page issued at run time become locations — same-origin
// GETs only. The page's own POST and a third-party request are counted and never sent: replaying a
// page's write is acting, not discovering, and a third party is not the target.
func TestRequestsARenderedPageIssuesAreCrawledWhenSameOriginGET(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><div id="app"></div></body></html>`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.RenderWithOutcome = func(ctx context.Context, u string) (string, RenderOutcome, error) {
		out := RenderOutcome{Settled: true}
		if u == srv.URL+"/" {
			out.Requests = []RenderedRequest{
				{URL: srv.URL + "/api/items?page=1", Method: "GET"},
				{URL: srv.URL + "/api/track", Method: "POST"},
				{URL: "https://analytics.example.test/collect", Method: "GET"},
			}
		}
		return `<html><body><div id="app"></div></body></html>`, out, nil
	}
	rep := run(t, cfg)

	mu.Lock()
	defer mu.Unlock()
	if asked["GET /api/items"] == 0 {
		t.Errorf("the same-origin GET the page issued was not crawled; asked: %v", asked)
	}
	for k := range asked {
		if k == "POST /api/track" || k == "GET /api/track" {
			t.Errorf("the page's own POST was replayed by the crawler (%s)", k)
		}
	}
	if rep.RenderedRequestsAdmitted != 1 || rep.RenderedRequestsNotGET != 1 || rep.RenderedRequestsOtherOrigin != 1 {
		t.Errorf("admitted/not-GET/other-origin = %d/%d/%d, want 1/1/1",
			rep.RenderedRequestsAdmitted, rep.RenderedRequestsNotGET, rep.RenderedRequestsOtherOrigin)
	}
	if rep.Phases[PhaseRendered] == 0 {
		t.Errorf("phases = %v: a run-time request is the rendered pass's discovery", rep.Phases)
	}
}
