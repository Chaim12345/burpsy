package crawler

// Burp's crawl strategy (burpsy-react-ui-8bp2): crawler/crawl_optimization/crawl_strategy, one of
// fastest, faster, normal, more complete, most complete. Burp ships a configuration for each one, and
// each carries only this key. Before this, importing any of the five was a silent no-op.
//
// The levels are Burp's enum burp.Zmqs (deobf_merged/burp/Zmqs.java, static initialiser). Each row
// sets about twenty crawler parameters. burpsy maps the ones it has an analog for:
//
//   - totalUnmatchedActionDescriptorTolerance and unmatchedAnchorTolerance: how many of a page's link
//     targets may differ before it counts as a different location. This is burpsy's location tolerance
//     band (location_band.go), whose 2 has always been NORMAL's value.
//   - maximumNumberOfFormInputStrategiesGeneratedPerActionDescriptor: how many input combinations one
//     form is submitted with. This is burpsy's per-form submission cap, applied when the file does not
//     also name max_submissions_per_form, which wins.
//
// The rest have no analog and are reported, not invented: maxLocationsPerUrl (burpsy keeps one
// location per URL), the browser idle and navigation timeouts (burpsy's rendered pass has its own
// bounds), and the masking thresholds and form-input chain lengths of Burp's state model.

import (
	"fmt"
	"sort"
	"strings"
)

// CrawlStrategy is one of Burp's five crawl strategy names, spelled as Burp's configuration files
// spell them.
type CrawlStrategy string

const (
	StrategyFastest      CrawlStrategy = "fastest"
	StrategyFaster       CrawlStrategy = "faster"
	StrategyNormal       CrawlStrategy = "normal"
	StrategyMoreComplete CrawlStrategy = "more complete"
	StrategyMostComplete CrawlStrategy = "most complete"
)

// strategyParams are the Zmqs values burpsy applies.
type strategyParams struct {
	// toleranceBand is unmatchedAnchorTolerance, which equals totalUnmatchedActionDescriptorTolerance
	// on every row.
	toleranceBand int
	// formInputs is maximumNumberOfFormInputStrategiesGeneratedPerActionDescriptor.
	formInputs int
}

var crawlStrategies = map[CrawlStrategy]strategyParams{
	StrategyFastest:      {toleranceBand: 3, formInputs: 5},
	StrategyFaster:       {toleranceBand: 3, formInputs: 20},
	StrategyNormal:       {toleranceBand: 2, formInputs: 30},
	StrategyMoreComplete: {toleranceBand: 0, formInputs: 40},
	StrategyMostComplete: {toleranceBand: 0, formInputs: 50},
}

// ParseCrawlStrategy reads a strategy name, case-insensitively, refusing anything else by name.
func ParseCrawlStrategy(name string) (CrawlStrategy, error) {
	s := CrawlStrategy(strings.ToLower(strings.TrimSpace(name)))
	if _, ok := crawlStrategies[s]; ok {
		return s, nil
	}
	known := make([]string, 0, len(crawlStrategies))
	for k := range crawlStrategies {
		known = append(known, string(k))
	}
	sort.Strings(known)
	return "", fmt.Errorf("unknown crawl strategy %q: Burp's are %s", name, strings.Join(known, ", "))
}
