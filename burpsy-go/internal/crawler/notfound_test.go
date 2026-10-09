package crawler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Not-found detection (burpsy-react-ui-s92h): a site that answers a missing page with a 200 "not found"
// template. Without detection every invented link became a location and its links grew the frontier.

const softNotFoundPage = `<html><body><h1>Sorry</h1><p>We could not find that page.</p><a href="/deeper">try here</a></body></html>`

func softNotFoundSite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><body><a href="/real">real</a><a href="/missing-one">m1</a><a href="/missing-two">m2</a></body></html>`))
		case "/real":
			w.Write([]byte(`<html><body><h2>A real page</h2><p>with real content</p></body></html>`))
		default:
			w.Write([]byte(softNotFoundPage)) // 200, whatever was asked for
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestASoft404IsNotALocationAndItsLinksAreNotWalked(t *testing.T) {
	srv := softNotFoundSite(t)
	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.NoNotFoundProbe = false
	rep := run(t, cfg)

	paths := fetchedPaths(rep)
	if paths["/real"] == 0 {
		t.Errorf("the real page was not fetched: %v", paths)
	}
	if paths["/deeper"] != 0 {
		t.Errorf("a link on the soft-404 page was walked: %v", paths)
	}
	if rep.SoftNotFound != 2 {
		t.Errorf("SoftNotFound = %d, want 2 (/missing-one and /missing-two)", rep.SoftNotFound)
	}
	probes := 0
	for _, f := range rep.Fetches {
		if f.NotFoundProbe {
			probes++
			if !strings.Contains(f.URL, "burpsy-nf-") {
				t.Errorf("a probe fetched %s, not a random sibling", f.URL)
			}
		}
		if f.SoftNotFound && !strings.HasPrefix(strings.TrimPrefix(f.URL, srv.URL), "/missing") {
			t.Errorf("%s was judged a soft 404", f.URL)
		}
	}
	if probes != 1 || rep.NotFoundProbes != 1 {
		t.Errorf("probes = %d (report %d), want exactly one for the one directory", probes, rep.NotFoundProbes)
	}
	if _, exchanges := h.store.Count(); exchanges != rep.Fetched || rep.Fetched != len(rep.Fetches) {
		t.Errorf("fetched %d, report rows %d, exchanges %d: a probe must be a fetch like any other", rep.Fetched, len(rep.Fetches), exchanges)
	}
}

// Honest 404s mean nothing in the directory is a soft 404, and a catch-all site's seed (a SPA shell
// answers every path with itself) is never judged: the operator chose it.
func TestHonest404sAndSeedsAreNeverJudged(t *testing.T) {
	honest := newTarget(t, map[string]string{"/": `<html><body><a href="/x">x</a></body></html>`, "/x": `<html><body>x</body></html>`})
	h := newHarness()
	cfg := h.config(honest.URL + "/")
	cfg.NoNotFoundProbe = false
	if rep := run(t, cfg); rep.SoftNotFound != 0 || fetchedPaths(rep)["/x"] == 0 {
		t.Errorf("a site with real 404s: SoftNotFound=%d, fetched %v", rep.SoftNotFound, fetchedPaths(rep))
	}

	shell := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/route">route</a></body></html>`))
	}))
	t.Cleanup(shell.Close)
	h = newHarness()
	cfg = h.config(shell.URL + "/")
	cfg.NoNotFoundProbe = false
	rep := run(t, cfg)
	for _, f := range rep.Fetches {
		if f.SoftNotFound && f.Depth == 0 {
			t.Errorf("the seed %s was judged a soft 404", f.URL)
		}
	}
	if fetchedPaths(rep)["/route"] == 0 {
		t.Errorf("the shell's link was not walked: %v", fetchedPaths(rep))
	}
}

// An isolated scan's not-found probe carries the isolated source like its other fetches (13uw): the
// probe is traffic the scan created, and a crawl-sourced probe would put a random sibling into the
// site map an isolated scan promises to leave alone.
func TestANotFoundProbeCarriesTheCrawlsCaptureSource(t *testing.T) {
	srv := softNotFoundSite(t)
	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.NoNotFoundProbe = false
	cfg.Capture.Source = core.SourceIsolatedScan
	rep := run(t, cfg)

	probes := 0
	for _, f := range rep.Fetches {
		ex, err := h.store.GetExchange(f.ExchangeID)
		if err != nil || ex == nil {
			t.Fatalf("fetch %s has no stored exchange: %v", f.URL, err)
		}
		if f.NotFoundProbe {
			probes++
		}
		if ex.Source != core.SourceIsolatedScan {
			t.Errorf("%s (probe=%v) stored with source %q, want %q", f.URL, f.NotFoundProbe, ex.Source, core.SourceIsolatedScan)
		}
	}
	if probes == 0 {
		t.Fatal("no not-found probe ran, so the test proves nothing")
	}
}
