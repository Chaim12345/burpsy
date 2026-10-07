package crawler

import (
	"encoding/json"
	"testing"
)

// burpShippedCrawlKeys is every distinct `crawler/*` key Burp ships, transcribed on 2026-09-27 from
// /root/burp-re/in/extract/resources: Preferences/CrawlDefaults.json, Preferences/
// LivePassiveCrawlDefaults.json, and every crawler.* leaf across the 29 BuiltInConfigs/*.json files.
//
// It is the denominator burpsy-react-ui-8xhy exists to fix: the section table this file's sibling
// carried before named five sections Burp does not ship (optimization, crawl_scope, exclusions,
// inclusions, crawl_optimisation), so 43 of these 46 real keys reported as UNREPRESENTABLE for the
// wrong reason — the section itself was unrecognised, not the key. Kept in the tree so "every key
// Burp ships has been classified" is a checked claim, the same role burpShippedScannerKeys plays for
// the scanner's table.
var burpShippedCrawlKeys = []string{
	"crawl_limits/maximum_crawl_time",
	"crawl_limits/maximum_request_count",
	"crawl_limits/maximum_unique_locations",
	"crawl_optimization/await_navigation_timeout",
	"crawl_optimization/crawl_strategy",
	"crawl_optimization/crawl_strategy_customized",
	"crawl_optimization/crawl_using_provided_logins_only",
	"crawl_optimization/dom_idle_threshold",
	"crawl_optimization/logging_directory",
	"crawl_optimization/logging_enabled",
	"crawl_optimization/maximum_link_depth",
	"crawl_optimization/network_idle_threshold",
	"crawl_project_option_overrides/connect_timeout",
	"crawl_project_option_overrides/normal_timeout",
	"customization/allow_all_clickables",
	"customization/allow_all_pointer_cursor_elements",
	"customization/allow_out_of_scope_resources",
	"customization/application_uses_fragments_for_routing",
	"customization/browser_based_navigation_mode",
	"customization/customize_user_agent",
	"customization/guess_hidden_graphql_endpoints",
	"customization/maximum_items_from_sitemap",
	"customization/maximum_speculative_links",
	"customization/parse_api_definitions",
	"customization/parse_soap_wsdls",
	"customization/perform_graphql_introspection",
	"customization/request_robots_txt",
	"customization/request_sitemap",
	"customization/request_speculative",
	"customization/submit_forms",
	"customization/timeout_for_in_progress_resource_requests",
	"customization/user_agent",
	"error_handling/consecutive_authentication_failures_before_pausing_task",
	"error_handling/number_of_follow_up_passes",
	"error_handling/pause_task_requests_timed_out_count",
	"error_handling/pause_task_requests_timed_out_percentage",
	"live_passive_crawl/add_all_urls",
	"live_passive_crawl/add_form_submissions",
	"live_passive_crawl/add_item_itself",
	"live_passive_crawl/add_links",
	"live_passive_crawl/add_same_domain",
	"live_passive_crawl/add_urls_in_scope",
	"live_passive_crawl/custom_scope",
	"live_passive_crawl/scope_type",
	"login_functions/attempt_to_self_register_a_user",
	"login_functions/trigger_login_failures",
}

// buildBurpCrawlDocument assembles one synthetic `crawler` object naming every key in
// burpShippedCrawlKeys, exactly as Burp's own files spell them across the section boundaries above —
// the union of CrawlDefaults.json's six sections and LivePassiveCrawlDefaults.json's one. A single
// document is used (rather than parsing each real file separately and summing) because
// ParseBurpCrawlConfig's contract is per-call: this proves the whole shipped vocabulary against one
// parse, the same way an operator who merged both files into one saved configuration would see it.
func buildBurpCrawlDocument(t *testing.T) []byte {
	t.Helper()
	crawler := map[string]map[string]any{}
	for _, key := range burpShippedCrawlKeys {
		section, leaf, ok := splitCrawlKey(key)
		if !ok {
			t.Fatalf("key %q has no section/leaf split", key)
		}
		if crawler[section] == nil {
			crawler[section] = map[string]any{}
		}
		// The value's SHAPE matters for every family this engine can now apply, because applying a
		// key means decoding it: the three limits keys and the four error_handling keys are all
		// numbers, and burpCrawlConfigNumber refuses the boolean the unrepresentable keys are seeded
		// with. Seeding every non-limit key as `true` was right when only the limits were applied,
		// because the shape of an unrepresentable key's value was never looked at.
		//
		// `0` rather than `1` for the error_handling thresholds, because that is the value Burp
		// actually ships in "Never stop crawl due to application errors" and it is the one that
		// must survive the round trip rather than being normalised away (burpsy-react-ui-o0c5).
		switch {
		case section == "crawl_limits":
			crawler[section][leaf] = 1
		case section == "error_handling":
			crawler[section][leaf] = 0
		case leaf == "maximum_speculative_links":
			// The one numeric key outside crawl_limits/error_handling (burpsy-react-ui-t5m0):
			// seeded as a count, not the boolean the other customization keys take.
			crawler[section][leaf] = 1
		default:
			crawler[section][leaf] = true
		}
	}
	doc, err := json.Marshal(map[string]any{"crawler": crawler})
	if err != nil {
		t.Fatalf("marshal synthetic crawl document: %v", err)
	}
	return doc
}

func splitCrawlKey(key string) (section, leaf string, ok bool) {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}

// The whole shipped vocabulary, driven through the real section table: every section Burp ships
// resolves (zero UnknownSections), the three crawl_limits keys apply, and the other 43 are named as
// unrepresentable rather than dropped. This is the bead's own acceptance test: 0 dropped keys, 3
// applied, out of the 46 Burp actually ships.
func TestEveryShippedCrawlKeyIsClassifiedNoneIsDropped(t *testing.T) {
	doc := buildBurpCrawlDocument(t)
	cfg, err := ParseBurpCrawlConfig(doc)
	if err != nil {
		t.Fatalf("ParseBurpCrawlConfig: %v", err)
	}

	if len(cfg.UnknownSections) != 0 {
		t.Errorf("UnknownSections = %v, want none: every section in this document is one Burp "+
			"actually ships and burpCrawlConfigSections must recognise all seven", cfg.UnknownSections)
	}

	total := len(cfg.AppliedKeys) + len(cfg.UnrepresentableKeys)
	if total != len(burpShippedCrawlKeys) {
		t.Errorf("applied(%d) + unrepresentable(%d) = %d, want %d: a key present in the document but "+
			"absent from both lists was silently dropped",
			len(cfg.AppliedKeys), len(cfg.UnrepresentableKeys), total, len(burpShippedCrawlKeys))
	}

	// Three crawl_limits keys plus the four error_handling keys (burpsy-react-ui-o0c5), which
	// stopped being a silent no-op on import: two of Burp's shipped configurations name three of
	// them by value. The two speculative keys (burpsy-react-ui-t5m0) make nine, and the four
	// API-discovery customization keys (burpsy-react-ui-bwwg) make thirteen.
	//
	// The number is a census, not a target: it moves when this engine gains a field for a key Burp
	// ships, and that is the point of the test — a key that becomes applicable and is still reported
	// unrepresentable tells an operator migrating a configuration that their setting was dropped.
	const wantApplied = 13
	if len(cfg.AppliedKeys) != wantApplied {
		t.Errorf("AppliedKeys = %v (%d), want exactly %d: crawl_limits' three keys plus "+
			"error_handling's four, the two speculative keys, and the four API-discovery keys are the "+
			"ones this engine has a field for",
			cfg.AppliedKeys, len(cfg.AppliedKeys), wantApplied)
	}

	wantUnrepresentable := len(burpShippedCrawlKeys) - wantApplied
	if len(cfg.UnrepresentableKeys) != wantUnrepresentable {
		t.Errorf("UnrepresentableKeys count = %d, want %d (46 shipped minus the %d applied)",
			len(cfg.UnrepresentableKeys), wantUnrepresentable, wantApplied)
	}

	if cfg.ShippedKeyCount != len(burpShippedCrawlKeys) {
		t.Errorf("ShippedKeyCount = %d, want %d: the fixed denominator must match the transcribed "+
			"vocabulary this test drives", cfg.ShippedKeyCount, len(burpShippedCrawlKeys))
	}
}

// Every section this table names must appear in burpShippedCrawlKeys at least once, and vice versa —
// otherwise the two tables (the parser's section map and this test's transcription) have quietly
// drifted apart and one of them is testing a fiction.
func TestBurpCrawlConfigSectionsMatchesTheShippedKeyTranscription(t *testing.T) {
	fromKeys := map[string]bool{}
	for _, key := range burpShippedCrawlKeys {
		section, _, ok := splitCrawlKey(key)
		if !ok {
			t.Fatalf("key %q has no section/leaf split", key)
		}
		fromKeys[section] = true
	}
	for section := range burpCrawlConfigSections {
		if !fromKeys[section] {
			t.Errorf("burpCrawlConfigSections lists %q but no transcribed key uses it; "+
				"is the section actually shipped?", section)
		}
	}
	for section := range fromKeys {
		if _, ok := burpCrawlConfigSections[section]; !ok {
			t.Errorf("a transcribed key uses section %q but burpCrawlConfigSections does not list it",
				section)
		}
	}
}
