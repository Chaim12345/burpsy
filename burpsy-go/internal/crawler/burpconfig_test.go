package crawler

import (
	"testing"
	"time"
)

// burpsy-react-ui-3ok6: a loaded Burp configuration's `crawler` object was parsed into nothing.
// internal/scanner/burpconfig.go read the `scanner` half of the same file and reported every key it
// could not apply; the `crawler` half — present in 9 of Burp's 29 shipped configurations, ten keys
// across them — was never looked at, so a third of a shipped configuration silently did not arrive.

// A shipped configuration's three crawl keys land on the three limits they name. This is the whole
// change: the section that used to vanish now applies.
func TestAShippedCrawlConfigAppliesItsThreeLimits(t *testing.T) {
	// Spelled as Burp spells it, from map_root.tsv:12473-12478 (burp.Zmst).
	doc := []byte(`{
	  "scanner": {"issues_reported": {"display_uninteresting_issues": true}},
	  "crawler": {"crawl_limits": {
	    "maximum_crawl_time": 90,
	    "maximum_unique_locations": 250,
	    "maximum_request_count": 1200
	  }}
	}`)

	cfg, err := ParseBurpCrawlConfig(doc)
	if err != nil {
		t.Fatalf("ParseBurpCrawlConfig: %v", err)
	}
	if cfg.Limits.MaxDuration != 90*time.Second {
		t.Errorf("MaxDuration = %v, want 90s", cfg.Limits.MaxDuration)
	}
	if cfg.Limits.MaxLocations != 250 {
		t.Errorf("MaxLocations = %d, want 250", cfg.Limits.MaxLocations)
	}
	if cfg.Limits.MaxRequests != 1200 {
		t.Errorf("MaxRequests = %d, want 1200", cfg.Limits.MaxRequests)
	}
	if len(cfg.UnrepresentableKeys) != 0 {
		t.Errorf("UnrepresentableKeys = %v, want none: all three keys this engine honours applied", cfg.UnrepresentableKeys)
	}
	if len(cfg.AppliedKeys) != 3 {
		t.Errorf("AppliedKeys = %v, want all three named so a report can say 3 of 46", cfg.AppliedKeys)
	}
	if cfg.ShippedKeyCount != 46 {
		t.Errorf("ShippedKeyCount = %d, want 46: the fixed denominator across every key Burp ships, "+
			"not a count derived from this one file", cfg.ShippedKeyCount)
	}
}

// The duration is SECONDS in Burp's files. Read as nanoseconds it is a crawl whose time budget is
// effectively zero, which looks like "the crawl did nothing" rather than "the unit was misread".
func TestACrawlTimeIsReadInSeconds(t *testing.T) {
	cfg, err := ParseBurpCrawlConfig([]byte(`{"crawler":{"crawl_limits":{"maximum_crawl_time":5}}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Limits.MaxDuration != 5*time.Second {
		t.Errorf("MaxDuration = %v, want 5s; Burp spells maximum_crawl_time in seconds and reading "+
			"it as another unit gives a crawl that stops before its first fetch", cfg.Limits.MaxDuration)
	}
}

// An unknown key is REPORTED BY NAME, never dropped. This is the property the whole loader exists
// for: an operator who exported a configuration and found a third of it missing has no way to know
// which third unless the loader says.
func TestAnUnknownCrawlKeyIsNamedRatherThanDropped(t *testing.T) {
	doc := []byte(`{"crawler":{"crawl_limits":{
	  "maximum_request_count": 100,
	  "maximum_depth": 3,
	  "maximum_crawl_depth": 9
	}}}`)
	cfg, err := ParseBurpCrawlConfig(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.UnrepresentableKeys) != 2 {
		t.Fatalf("UnrepresentableKeys = %v, want the two keys this engine has no field for",
			cfg.UnrepresentableKeys)
	}
	// Named without the section prefix, so the name is what an operator recognises from their file.
	for _, want := range []string{"crawl_limits/maximum_depth", "crawl_limits/maximum_crawl_depth"} {
		var found bool
		for _, got := range cfg.UnrepresentableKeys {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not named in %v; a key the operator set must be reportable by the name "+
				"they set it under", want, cfg.UnrepresentableKeys)
		}
	}
	if cfg.Limits.MaxRequests != 100 {
		t.Errorf("MaxRequests = %d, want the key that IS honoured", cfg.Limits.MaxRequests)
	}
}

// And an unknown SECTION is reported separately, because "this whole section is gone" and "this one
// key is gone" are different amounts of loss and an operator deciding whether to hand-write the
// difference needs to know which it is.
func TestAnUnknownCrawlSectionIsReportedAsASection(t *testing.T) {
	doc := []byte(`{"crawler":{
	  "crawl_limits": {"maximum_request_count": 50},
	  "behaviour": {"follow_redirects": true},
	  "something_new": {"a": 1}
	}}`)
	cfg, err := ParseBurpCrawlConfig(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.UnknownSections) != 2 {
		t.Errorf("UnknownSections = %v, want the two sub-objects with no keys behind them", cfg.UnknownSections)
	}
	if len(cfg.UnrepresentableKeys) != 0 {
		t.Errorf("UnrepresentableKeys = %v, want none: a whole unknown section is not an unknown key",
			cfg.UnrepresentableKeys)
	}
	if cfg.Limits.MaxRequests != 50 {
		t.Errorf("MaxRequests = %d; a section this engine does not know must not stop the one it does "+
			"from applying", cfg.Limits.MaxRequests)
	}
}

// A section listed with no keys behind it is still reported, not treated as absent: Burp's shipped
// files carry customization keys burpsy has no field for, and silence about them is the difference
// between "your configuration said nothing" and "your configuration said something we could not
// use". (login_functions was this test's example until uzil gave its keys a field — which is the
// test working as intended.)
func TestAKnownSectionWithNoKeysBehindItIsStillReported(t *testing.T) {
	doc := []byte(`{"crawler":{"customization": {"allow_all_clickables": true}}}`)
	cfg, err := ParseBurpCrawlConfig(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.UnrepresentableKeys) != 1 || cfg.UnrepresentableKeys[0] != "customization/allow_all_clickables" {
		t.Errorf("UnrepresentableKeys = %v, want the one key inside a section burpsy lists but has no "+
			"field for; the section being known does not make the key applicable", cfg.UnrepresentableKeys)
	}
}

// A boolean where a count belongs is REFUSED, not coerced. Burp's limits section carries numbers and
// its other sections carry booleans, so `true` in a limits file is a mistyped configuration — and
// coercing it to 1 would give the operator a one-request crawl and a "configuration applied" line.
func TestABooleanLimitIsRefusedRatherThanCoerced(t *testing.T) {
	_, err := ParseBurpCrawlConfig([]byte(`{"crawler":{"crawl_limits":{"maximum_request_count": true}}}`))
	if err == nil {
		t.Fatal("a boolean in the limits section was accepted; coercing it to 1 gives a one-request " +
			"crawl reported as a configuration that applied")
	}
}

// A negative limit would be no limit at all — the very thing the default limits exist to prevent —
// so it is refused rather than stored.
func TestANegativeLimitIsRefused(t *testing.T) {
	_, err := ParseBurpCrawlConfig([]byte(`{"crawler":{"crawl_limits":{"maximum_request_count": -1}}}`))
	if err == nil {
		t.Fatal("a negative limit was accepted; a negative bound is no bound, and the crawl against an " +
			"application that generates URLs never finishes")
	}
}

// A file with no crawler object is a scan configuration, not a crawl one, and loads as nothing
// rather than as an error.
func TestAFileWithNoCrawlerObjectIsNotAnError(t *testing.T) {
	cfg, err := ParseBurpCrawlConfig([]byte(`{"scanner":{"issues_reported":{"display_uninteresting_issues":true}}}`))
	if err != nil {
		t.Fatalf("a scanner-only configuration was refused: %v", err)
	}
	if len(cfg.AppliedKeys) != 0 || len(cfg.UnrepresentableKeys) != 0 || len(cfg.UnknownSections) != 0 {
		t.Errorf("a scanner-only file produced a crawl report: %+v", cfg)
	}
}

// The report is stable across reads, because Go's map iteration is random and a list that reorders
// itself between two reads of the same file cannot be diffed or eyeballed.
func TestTheCrawlConfigReportIsOrderedDeterministically(t *testing.T) {
	doc := []byte(`{"crawler":{"crawl_limits":{
	  "zzz_last": 1, "aaa_first": 2, "maximum_request_count": 3
	}}}`)
	first, err := ParseBurpCrawlConfig(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := 0; i < 12; i++ {
		again, err := ParseBurpCrawlConfig(doc)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		for j := range first.UnrepresentableKeys {
			if again.UnrepresentableKeys[j] != first.UnrepresentableKeys[j] {
				t.Fatalf("UnrepresentableKeys reordered between reads: %v then %v",
					first.UnrepresentableKeys, again.UnrepresentableKeys)
			}
		}
	}
	if first.UnrepresentableKeys[0] != "crawl_limits/aaa_first" {
		t.Errorf("UnrepresentableKeys = %v, want them sorted so the name is the first thing a reader sees",
			first.UnrepresentableKeys)
	}
}
