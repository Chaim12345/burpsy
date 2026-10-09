package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// burpsy-react-ui-ddln follow-up: a named configuration's form_submission_optimization_threshold
// reaches the crawl an operator starts through POST /api/crawl. The parser filled it and the crawler
// enforced it, but crawlConfig never set it, so the bound was off on every operator-launched crawl
// while the start reply — which names only the keys that did NOT apply — implied it was in force.

// pagingFormSite serves linked pages each carrying one form whose field value is the page number, so
// every submission reaches a DISTINCT destination: the per-form cap and request dedupe never fire and
// only the threshold bounds it. Mirrors the crawler package's own pagingFormTarget.
func pagingFormSite(t *testing.T, pages int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var submissions atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/search" {
			submissions.Add(1)
			_, _ = w.Write([]byte("<html><body>results</body></html>"))
			return
		}
		current := 1
		if n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/page/")); err == nil {
			current = n
		}
		if current > pages {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("<html><body><p>page " + strconv.Itoa(current) + "</p>" +
			`<form action="/search" method="post"><input name="page" value="` + strconv.Itoa(current) + `"><button>Go</button></form>` +
			`<a href="/page/` + strconv.Itoa(current+1) + `">next</a></body></html>`))
	}))
	t.Cleanup(srv.Close)
	return srv, &submissions
}

func startFormCrawl(t *testing.T, s *Server, seed, config string) (crawlRunResp, []string) {
	t.Helper()
	body := map[string]any{
		"seeds":        []string{seed},
		"submit_forms": true,
		"max_requests": 200,
		"max_depth":    20,
	}
	if config != "" {
		body["config"] = config
	}
	rec := postJSON(t, s, "/api/crawl", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: %d %s", rec.Code, rec.Body.String())
	}
	var start struct {
		TaskID    uint64   `json:"task_id"`
		Unapplied []string `json:"config_unapplied_keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	run := waitForCrawl(t, s, start.TaskID)
	if run.State != "done" || run.Report == nil {
		t.Fatalf("crawl state %q (%s), report %v", run.State, run.Error, run.Report != nil)
	}
	return run, start.Unapplied
}

func TestANamedConfigsFormThresholdIsEnforcedOnACrawlStartedThroughTheRoute(t *testing.T) {
	const threshold = 2
	const pages = 8
	const key = "crawl_optimization/form_submission_optimization_threshold"

	s, _ := newTestServerWithDB(t)
	if _, err := s.persist.SaveScanConfigLibrary("form bound",
		`{"crawler":{"crawl_optimization":{"form_submission_optimization_threshold":`+strconv.Itoa(threshold)+`}}}`); err != nil {
		t.Fatalf("save configuration: %v", err)
	}

	// Control first: no configuration, so the bound is off and the form is submitted once per page.
	// Without this the threshold assertion below could pass on a site that only ever offered two
	// destinations.
	srv, submissions := pagingFormSite(t, pages)
	u, _ := url.Parse(srv.URL)
	s.scope.AddInclude(u.Hostname())
	run, _ := startFormCrawl(t, s, srv.URL+"/", "")
	if got := submissions.Load(); got <= threshold {
		t.Fatalf("control crawl with no configuration submitted the form %d times; the site must offer more "+
			"than %d destinations for the threshold test to mean anything", got, threshold)
	}
	if n := run.skipCount("form-destination-exhausted"); n != 0 {
		t.Fatalf("a crawl naming no configuration recorded %d form-destination-exhausted skips; the bound must be off", n)
	}

	srv2, submissions2 := pagingFormSite(t, pages)
	u2, _ := url.Parse(srv2.URL)
	s.scope.AddInclude(u2.Hostname())
	run, unapplied := startFormCrawl(t, s, srv2.URL+"/", "form bound")
	for _, k := range unapplied {
		if strings.Contains(k, "form_submission_optimization_threshold") {
			t.Fatalf("the start reply lists %q as unapplied; the engine can honour it", k)
		}
	}
	// The reply implies the key applied (it is absent from config_unapplied_keys); this is the proof
	// that it did.
	if got := submissions2.Load(); got != threshold {
		t.Errorf("crawl under %q submitted the form %d times, want the configured threshold %d; the "+
			"reply did not list %s as unapplied, so it claimed a bound that never reached the crawler",
			"form bound", got, threshold, key)
	}
	if n := run.skipCount("form-destination-exhausted"); n == 0 {
		t.Errorf("crawl under the named configuration recorded no form-destination-exhausted skip; the operator " +
			"cannot tell the form space was cut short")
	}
}
