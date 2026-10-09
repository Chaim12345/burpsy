package web

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/crawler"
)

// A named configuration's form cap and crawl-strategy band reach the crawl (burpsy-react-ui-8bp2). The
// form cap was parsed and then dropped by this overlay since u0k3.
func Test_the_crawl_overlay_carries_the_form_cap_and_the_strategy_band(t *testing.T) {
	cfg, err := crawler.ParseBurpCrawlConfig([]byte(`{"crawler":{"crawl_optimization":{"crawl_strategy":"most complete"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	limits := crawler.DefaultLimits()
	overlayCrawlLimits(&limits, cfg.Limits)
	if limits.MaxSubmissionsPerForm != 50 || limits.LocationToleranceBand == nil || *limits.LocationToleranceBand != 0 {
		t.Errorf("overlaid limits: form cap %d, band %v; want 50 and 0", limits.MaxSubmissionsPerForm, limits.LocationToleranceBand)
	}
}
