package crawler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Burp's crawl strategy (burpsy-react-ui-8bp2): each of the five shipped "Crawl strategy - *" files,
// which carry only this key, now sets burpsy's location tolerance band and per-form cap from Burp's
// own Zmqs table, and an explicit max_submissions_per_form still wins.
func TestEachCrawlStrategySetsBurpsZmqsValues(t *testing.T) {
	for _, c := range []struct {
		name       string
		band, form int
	}{
		{"fastest", 3, 5}, {"faster", 3, 20}, {"normal", 2, 30}, {"more complete", 0, 40}, {"Most Complete", 0, 50},
	} {
		cfg, err := ParseBurpCrawlConfig([]byte(`{"crawler":{"crawl_optimization":{"crawl_strategy":"` + c.name + `"}}}`))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if cfg.Limits.LocationToleranceBand == nil || *cfg.Limits.LocationToleranceBand != c.band || cfg.Limits.MaxSubmissionsPerForm != c.form {
			t.Errorf("%s: band %v form %d, want %d and %d", c.name, cfg.Limits.LocationToleranceBand, cfg.Limits.MaxSubmissionsPerForm, c.band, c.form)
		}
		if len(cfg.UnrepresentableKeys) != 0 || len(cfg.AppliedKeys) != 1 {
			t.Errorf("%s: applied %v, unrepresentable %v", c.name, cfg.AppliedKeys, cfg.UnrepresentableKeys)
		}
	}

	cfg, err := ParseBurpCrawlConfig([]byte(`{"crawler":{"crawl_optimization":{"crawl_strategy":"fastest","max_submissions_per_form":7}}}`))
	if err != nil || cfg.Limits.MaxSubmissionsPerForm != 7 {
		t.Errorf("an explicit max_submissions_per_form must win over the strategy: %d (%v)", cfg.Limits.MaxSubmissionsPerForm, err)
	}
	if _, err := ParseBurpCrawlConfig([]byte(`{"crawler":{"crawl_optimization":{"crawl_strategy":"turbo"}}}`)); err == nil ||
		!strings.Contains(err.Error(), "more complete") {
		t.Errorf("an unknown strategy must be refused naming Burp's five: %v", err)
	}
}

// The band reaches the crawl: two pages that differ only in one link's query value are one location
// under "normal" (band 2) and two under "most complete" (band 0).
func TestTheStrategyBandDecidesWhetherAMovedLinkIsANewLocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><body><a href="/p?id=1">one</a><a href="/q?id=2">two</a></body></html>`))
			return
		}
		// /p and /q: the same page, whose one link carries the id it was asked for.
		w.Write([]byte(`<html><body><p>item</p><a href="/x?v=` + r.URL.Query().Get("id") + `">x</a><a href="/y">y</a></body></html>`))
	}))
	t.Cleanup(srv.Close)
	folds := func(band *int) int {
		h := newHarness()
		cfg := h.config(srv.URL + "/")
		cfg.Limits = DefaultLimits()
		cfg.Limits.LocationToleranceBand = band
		return run(t, cfg).LocationFolds
	}
	if n := folds(nil); n < 1 {
		t.Fatalf("control: the normal band folded %d page(s); the fixture's two pages differ in one link value", n)
	}
	zero := 0
	if n := folds(&zero); n != 0 {
		t.Errorf("band 0 (most complete) still folded %d page(s)", n)
	}
}
