package crawler

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Burp crawl-configuration loading: the `crawler` object inside a shipped or exported Burp
// configuration, read into CrawlConfig.
//
// # Why this exists
//
// internal/scanner/burpconfig.go reads the `scanner` object of the same file and reports every key
// it cannot apply. The `crawler` object — present in 9 of Burp's 29 shipped configurations, with ten
// keys across them — was parsed into nothing at all: burpConfigFile carried one field, so a third of
// a shipped configuration silently did not arrive, with no report line saying the section had
// existed and been ignored (burpsy-react-ui-3ok6).
//
// Importing a Burp configuration is a first-class migration path, and a loader that reports what it
// cannot honour is only honest if it looks at every section the file actually carries. This is the
// crawler's half of that: the same three-part shape (applied / unrepresentable / unknown) the
// scanner's loader already has, so an operator reading one report can read the other.
//
// # The keys
//
// Burp's shipped crawl configurations carry exactly three (map_root.tsv:12473-12478, burp.Zmst):
//
//	crawler.crawl_limits.maximum_crawl_time
//	crawler.crawl_limits.maximum_unique_locations
//	crawler.crawl_limits.maximum_request_count
//
// All three land on Limits fields this engine already has, so this is a projection and nothing more.
// A fourth key appearing in a future configuration is REPORTED by name rather than ignored, which is
// the whole point: an operator who exported a configuration and found a third of it missing has no
// way to know which third.
type burpCrawlConfigFile struct {
	// Crawler is the section Burp nests its crawl keys under. Held as a raw object rather than
	// decoded into fields so an UNKNOWN section can be reported by name instead of vanishing.
	Crawler map[string]json.RawMessage `json:"crawler"`
}

// burpCrawlConfigSections are the sub-objects Burp nests crawl keys under, mapped to the key prefix
// each becomes. Exactly as the scanner's table, every section Burp's own files use is listed rather
// than only the ones with fields behind them: an unlisted section is reported as one opaque name,
// which hides WHICH keys an operator's file set and did nothing with.
var burpCrawlConfigSections = map[string]string{
	"crawl_limits": "crawler/crawl_limits/",
	// Sections Burp's own configurations carry alongside the limits. Listed with no keys behind them
	// so their presence is reported rather than ignored — the same treatment the scanner's table gives
	// an unlisted section, and the reason a "nothing to apply" line is ever emitted.
	"optimization":       "crawler/optimization/",
	"crawl_scope":        "crawler/crawl_scope/",
	"exclusions":         "crawler/exclusions/",
	"inclusions":         "crawler/inclusions/",
	"crawl_optimisation": "crawler/crawl_optimisation/",
}

// burpCrawlConfigKey is one row of the crawler's key table: the Burp key as shipped, the Limits
// field it lands on, and whether the value is a count or a duration.
type burpCrawlConfigKey struct {
	// burpKey is the full dotted key as Burp spells it, section included.
	burpKey string
	// field is the Limits field this key lands on.
	field string
	// isDuration distinguishes a count from a wall-clock length. Burp's maximum_crawl_time is in
	// SECONDS in its own configurations, which is a fact this table has to carry rather than guess.
	isDuration bool
}

// burpCrawlConfigKeys is the whole of Burp's shipped crawl-key vocabulary, as read today.
//
// Burp's crawler has more settings than these three — and burpsy has more limits than Burp names —
// so the gap runs BOTH ways and both are reported rather than papered over. The keys here are the
// ones this engine can honour; the report names every other key the file carried.
var burpCrawlConfigKeys = []burpCrawlConfigKey{
	{burpKey: "crawler/crawl_limits/maximum_crawl_time", field: "MaxDuration", isDuration: true},
	{burpKey: "crawler/crawl_limits/maximum_unique_locations", field: "MaxLocations"},
	{burpKey: "crawler/crawl_limits/maximum_request_count", field: "MaxRequests"},
}

// CrawlConfig is what a Burp crawl configuration contributes: the limits to overlay, the keys that
// named a value this engine has nowhere to put, and the keys this engine has that Burp's file never
// mentioned.
//
// The three are separate because they answer different questions. "Applied" is what took effect. "Not
// representable" is a value the operator set that burpsy has no field for. "Not set" is a limit burpsy
// applies that Burp's vocabulary does not express — the one that is easiest to miss and the reason a
// migrated configuration does not behave like the donor's.
type CrawlConfig struct {
	// Limits are the overlaid values. A field left at its zero value was not named by the file.
	Limits Limits
	// UnrepresentableKeys are `crawler/*` keys the file carried that this engine cannot apply,
	// without the section prefix, so the name is what an operator recognises from their file.
	UnrepresentableKeys []string
	// UnknownSections are `crawler` sub-objects with no keys behind them at all. Reported separately
	// from UnrepresentableKeys because "this whole section is gone" and "this one key is gone" are
	// different amounts of loss, and an operator deciding whether to hand-write the difference needs
	// to know which it is.
	UnknownSections []string
	// AppliedKeys are the `crawler/*` keys that landed, in file order. Present so a report can say
	// "3 of 3 applied" rather than leaving the operator to infer it from a count.
	AppliedKeys []string
}

// ParseBurpCrawlConfig reads the `crawler` object of a Burp configuration into limits and a report.
//
// A section Burp's file carries but this table does not know is REPORTED, never dropped, and the
// same for a key inside a known section. A configuration whose crawler half is a typo must not load
// as if it carried no crawl settings at all — the operator would see a crawl run with burpsy's
// defaults and conclude the configuration had said so.
func ParseBurpCrawlConfig(data []byte) (CrawlConfig, error) {
	var file burpCrawlConfigFile
	if err := json.Unmarshal(data, &file); err != nil {
		return CrawlConfig{}, fmt.Errorf("burp crawl configuration: %w", err)
	}
	var out CrawlConfig

	byBurpKey := make(map[string]burpCrawlConfigKey, len(burpCrawlConfigKeys))
	for _, k := range burpCrawlConfigKeys {
		byBurpKey[k.burpKey] = k
	}

	for section, raw := range file.Crawler {
		prefix, known := burpCrawlConfigSections[section]
		if !known {
			out.UnknownSections = append(out.UnknownSections, section)
			continue
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(raw, &keys); err != nil {
			return CrawlConfig{}, fmt.Errorf("burp crawl configuration: crawler.%s: %w", section, err)
		}
		for key, v := range keys {
			full := prefix + key
			row, ok := byBurpKey[full]
			if !ok {
				out.UnrepresentableKeys = append(out.UnrepresentableKeys,
					strings.TrimPrefix(full, "crawler/"))
				continue
			}
			if err := out.applyCrawlKey(row, v); err != nil {
				return CrawlConfig{}, err
			}
			out.AppliedKeys = append(out.AppliedKeys, strings.TrimPrefix(full, "crawler/"))
		}
	}
	// Sorted because Go's map iteration is random and a report that reorders itself between two
	// reads of the same file cannot be diffed or eyeballed.
	sortStrings(out.UnknownSections)
	sortStrings(out.UnrepresentableKeys)
	sortStrings(out.AppliedKeys)
	return out, nil
}

// applyCrawlKey decodes one value onto the Limits field its row names.
func (c *CrawlConfig) applyCrawlKey(row burpCrawlConfigKey, raw json.RawMessage) error {
	if row.isDuration {
		// Burp's shipped files spell maximum_crawl_time in SECONDS. A value read as nanoseconds
		// would be a crawl whose time budget is effectively zero, which looks like "the crawl did
		// nothing" rather than "the duration was misread" — so the unit is the table's fact, not a
		// guess at the call site.
		n, err := burpCrawlConfigNumber(raw)
		if err != nil {
			return fmt.Errorf("burp crawl configuration: %s: %w", row.burpKey, err)
		}
		if n < 0 {
			return fmt.Errorf("burp crawl configuration: %s: a negative limit would be no limit at all", row.burpKey)
		}
		c.Limits.MaxDuration = time.Duration(n) * time.Second
		return nil
	}
	n, err := burpCrawlConfigNumber(raw)
	if err != nil {
		return fmt.Errorf("burp crawl configuration: %s: %w", row.burpKey, err)
	}
	if n < 0 {
		return fmt.Errorf("burp crawl configuration: %s: a negative limit would be no limit at all", row.burpKey)
	}
	switch row.field {
	case "MaxRequests":
		c.Limits.MaxRequests = int(n)
	case "MaxLocations":
		c.Limits.MaxLocations = int(n)
	case "MaxDepth":
		c.Limits.MaxDepth = int(n)
	}
	return nil
}

// burpCrawlConfigNumber reads one numeric value, refusing a boolean rather than coercing it.
//
// Burp's limits section is counts and minutes while its other sections are booleans, so a value
// arriving as a JSON true in a limits file is a mistyped configuration. Coercing it to 1 would give
// the operator a one-request crawl and a "configuration applied" line.
func burpCrawlConfigNumber(raw json.RawMessage) (int64, error) {
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("%s is not a number", strings.TrimSpace(string(raw)))
	}
	return n, nil
}

// sortStrings is the tiny sort this file needs, so the import list has no new dependency for it.
func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}
