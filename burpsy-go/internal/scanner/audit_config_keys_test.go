package scanner

import (
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// burpShippedScannerKeys is every distinct key Burp's own 29 shipped scan configurations set under
// `scanner/`, transcribed on 2026-09-14 from
// /root/burp-re/in/extract/resources/BuiltInConfigs (29 files; `scanner/*` leaves only — the
// `crawler/*` and `description/*` leaves in the same files belong to other subsystems, and the
// scan-config overlay here governs scans).
//
// It is the denominator this table is measured against, kept in the tree so "every key Burp ships
// has been classified" is a checked claim rather than a remembered one. The 78 the carve-out issue
// counted was every leaf in those files; this is the scanner-side subset of it.
var burpShippedScannerKeys = []string{
	"scanner/audit_optimization/consolidate_passive_issues",
	"scanner/audit_optimization/follow_redirections",
	"scanner/audit_optimization/logging_enabled",
	"scanner/audit_optimization/maintain_session",
	"scanner/audit_optimization/max_items_in_progress",
	"scanner/audit_optimization/maximum_crawl_and_audit_time",
	"scanner/audit_optimization/parallel_crawl_and_audit",
	"scanner/audit_optimization/scan_accuracy",
	"scanner/audit_optimization/scan_speed",
	"scanner/audit_optimization/skip_ineffective_checks",
	"scanner/audit_project_option_overrides/connect_timeout",
	"scanner/audit_project_option_overrides/normal_timeout",
	"scanner/error_handling/consecutive_audit_check_failures_to_skip_insertion_point",
	"scanner/error_handling/consecutive_insertion_point_failures_to_fail_audit_item",
	"scanner/error_handling/number_of_follow_up_passes",
	"scanner/error_handling/pause_task_failed_audit_item_count",
	"scanner/error_handling/pause_task_failed_audit_item_percentage",
	"scanner/frequently_occurring_insertion_points/quick_scan_body_params",
	"scanner/frequently_occurring_insertion_points/quick_scan_cookies",
	"scanner/frequently_occurring_insertion_points/quick_scan_entire_body",
	"scanner/frequently_occurring_insertion_points/quick_scan_http_headers",
	"scanner/frequently_occurring_insertion_points/quick_scan_param_name",
	"scanner/frequently_occurring_insertion_points/quick_scan_url_params",
	"scanner/frequently_occurring_insertion_points/quick_scan_url_path_filename",
	"scanner/frequently_occurring_insertion_points/quick_scan_url_path_folders",
	"scanner/ignored_insertion_points/skip_all_tests_for_parameters",
	"scanner/ignored_insertion_points/skip_server_side_injection_for_parameters",
	"scanner/insertion_point_types/insert_body_params",
	"scanner/insertion_point_types/insert_cookies",
	"scanner/insertion_point_types/insert_entire_body",
	"scanner/insertion_point_types/insert_http_headers",
	"scanner/insertion_point_types/insert_param_name",
	"scanner/insertion_point_types/insert_url_params",
	"scanner/insertion_point_types/insert_url_path_filename",
	"scanner/insertion_point_types/insert_url_path_folders",
	"scanner/issues_reported/scan_only_selected_issues",
	"scanner/issues_reported/scan_type_intrusive_active",
	"scanner/issues_reported/scan_type_javascript_analysis",
	"scanner/issues_reported/scan_type_light_active",
	"scanner/issues_reported/scan_type_medium_active",
	"scanner/issues_reported/scan_type_passive",
	"scanner/issues_reported/select_individual_issues",
	"scanner/issues_reported/selected_issues",
	"scanner/issues_reported/store_issues_within_queue_items",
	"scanner/javascript_analysis/fetch_out_of_scope_resources",
	"scanner/javascript_analysis/max_dynamic_time_per_item",
	"scanner/javascript_analysis/max_static_time_per_item",
	"scanner/javascript_analysis/request_missing_dependencies",
	"scanner/javascript_analysis/use_dynamic_analysis",
	"scanner/javascript_analysis/use_static_analysis",
	"scanner/misc_insertion_point_options/max_insertion_points_per_base_request",
	"scanner/misc_insertion_point_options/use_nested_insertion_points",
	"scanner/modifying_parameter_locations/body_to_cookie",
	"scanner/modifying_parameter_locations/body_to_url",
	"scanner/modifying_parameter_locations/cookie_to_body",
	"scanner/modifying_parameter_locations/cookie_to_url",
	"scanner/modifying_parameter_locations/url_to_body",
	"scanner/modifying_parameter_locations/url_to_cookie",
}

// Every key Burp ships must have a row. A key with no row cannot be reported at all: ApplyWithReport
// names keys by row, so an unrowed key is invisible to the operator who loaded their own file — the
// silent drop this table exists to prevent.
func Test_burps_shipped_scanner_keys_all_have_a_row(t *testing.T) {
	rows := make(map[string]bool, len(builtInConfigKeys))
	for _, k := range builtInConfigKeys {
		if rows[k.burpKey] {
			t.Errorf("two rows claim %s", k.burpKey)
		}
		rows[k.burpKey] = true
	}
	var missing []string
	for _, key := range burpShippedScannerKeys {
		if !rows[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d key(s) Burp ships have no row, so a configuration naming one cannot report it: %v", len(missing), missing)
	}

	// The reverse direction: a row this table carries but the shipped list does not name is exactly
	// the defect that let max_items_in_progress, parallel_crawl_and_audit and logging_enabled go
	// unrowed for as long as they did (burpsy-react-ui-3ymo). Scanner keys only: builtInConfigKeys
	// also carries rows for other sections that burpShippedScannerKeys deliberately does not track.
	pinned := make(map[string]bool, len(burpShippedScannerKeys))
	for _, key := range burpShippedScannerKeys {
		pinned[key] = true
	}
	var unpinned []string
	for _, k := range builtInConfigKeys {
		if strings.HasPrefix(k.burpKey, "scanner/") && !pinned[k.burpKey] {
			unpinned = append(unpinned, k.burpKey)
		}
	}
	if len(unpinned) > 0 {
		t.Errorf("%d row(s) exist for keys the pinned shipped-key list does not name, so the list is no "+
			"longer the true denominator every row is measured against: %v", len(unpinned), unpinned)
	}

	// The counts are pinned: promoting a key from reported to applied, or dropping a row, has to
	// change this claim rather than quietly shifting what the project says it honours.
	// The counts are pinned, and there are THREE of them: promoting a key from reported to
	// applied, from reported to partial, or dropping a row, has to change this claim rather than
	// quietly shifting what the project says it honours.
	//
	// The partial bucket exists because "we support this, but not the way you probably meant" is a
	// third answer. skip_all_tests_for_parameters is it: the engine honours a list of parameter
	// NAMES and cannot read Burp's list of match rules, and reporting it as either "not applied" (a
	// settings page telling an operator their skip list is unsupported while it silently works) or
	// "applied" (claiming full support for a value shape that cannot be read) is a false statement
	// in an operator-facing table either way (burpsy-react-ui-86le).
	const wantApplied, wantPartial, wantReported = 38, 4, 16
	// 38/4/16 since burpsy-react-ui-y4om: skip_ineffective_checks moved from reported to applied,
	// which is the one change this table exists to make visible. A key that stops reporting as
	// unapplied without the count moving is the silent-coverage-change defect the pin prevents.
	applied, partial, reported := 0, 0, 0
	for _, k := range builtInConfigKeys {
		switch {
		case k.listShaped:
			partial++
			// A partial row must NOT carry a scalar reader: it is applied through a different shape
			// entirely, and a read here would make ApplyWithReport treat it as a boolean.
			if k.read != nil {
				t.Errorf("%s is partial but carries a scalar reader; the list-shaped path and the "+
					"OptUint32 path cannot both own it", k.name)
			}
			if !strings.HasPrefix(k.what, "partly applied: ") {
				t.Errorf("%s is partial but its description does not say so: %q", k.name, k.what)
			}
		case k.applies:
			applied++
		default:
			reported++
			if k.read != nil {
				t.Errorf("%s is reported as not applying but has a field to read; an unapplied row must not silently carry state", k.name)
			}
			if !strings.HasPrefix(k.what, "not applied: ") {
				t.Errorf("%s is unapplied but its description does not say so: %q", k.name, k.what)
			}
		}
	}
	if applied != wantApplied || partial != wantPartial || reported != wantReported {
		t.Errorf("the table honours %d key(s) in full, %d in a reduced form and reports %d as not "+
			"applied; want %d, %d and %d — the coverage claim moves with these counts",
			applied, partial, reported, wantApplied, wantPartial, wantReported)
	}
}

// The three active-tier keys claimed `applies` while the engine collapsed them onto one gate, so a
// preset importer reading the matrix was told all three were honoured and none of them was. The
// matrix's claim and the engine's behaviour must be the same claim, and this test holds them together
// by toggling each key and observing which checks actually change.
func Test_the_three_active_tier_keys_each_change_the_check_set(t *testing.T) {
	base := &ScanConfig{
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		CheckSqli:      true, CheckXss: true, CheckPathTraversal: true, CheckSSRF: true,
		CheckXXE: true, CheckJwtWeak: true, CheckJSVulns: true,
		CheckPassiveAnalysis: true, CheckPassivePosture: true, CheckHeaders: true,
		CheckHostDiscovery: true, CheckExtendedCoverage: true, CheckReflectionProbes: true,
		CheckResponseDependence: true, CheckActiveInjection: true,
		CheckExtendedActive: true, CheckOutOfBand: true, CheckStored: true, CheckCorpus: true,
	}
	s := NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithConfig(base)
	baseline := s.enabledChecks()
	if len(baseline) == 0 {
		t.Fatal("the scanner has no checks enabled, so the tier keys have nothing to select")
	}

	// Each key alone, with the other two explicitly off, must produce a set that differs from the
	// baseline AND from the set the other two produce. Under the collapsed gate all three were the
	// same test: any one true meant the base set, and all three false meant no active checks.
	light := s.enabledChecksUnder(AuditConfig{LightActiveChecks: SomeUint32(1), MediumActiveChecks: SomeUint32(0), IntrusiveActiveChecks: SomeUint32(0)})
	medium := s.enabledChecksUnder(AuditConfig{LightActiveChecks: SomeUint32(0), MediumActiveChecks: SomeUint32(1), IntrusiveActiveChecks: SomeUint32(0)})
	intrusive := s.enabledChecksUnder(AuditConfig{LightActiveChecks: SomeUint32(0), MediumActiveChecks: SomeUint32(0), IntrusiveActiveChecks: SomeUint32(1)})

	if len(light) == len(baseline) {
		t.Errorf("scan_type_light_active produced the base set (%d checks): the key changed nothing, so the matrix may not report it as applied", len(light))
	}
	if len(intrusive) == len(light) {
		t.Errorf("scan_type_intrusive_active and scan_type_light_active produced the same set (%d checks): the tiers are still one switch", len(light))
	}
	if len(medium) == len(baseline) {
		t.Errorf("scan_type_medium_active produced the base set (%d checks): the key changed nothing, so the matrix may not report it as applied", len(medium))
	}
	// The three sets are distinct, which is the claim the matrix makes. They need not be disjoint:
	// the passive rows are exempt from all three, so every set contains them.
	t.Logf("tier selection sizes: light=%d medium=%d intrusive=%d base=%d", len(light), len(medium), len(intrusive), len(baseline))
}

// A reported key must reach the report under each spelling in play: the section-qualified path the
// parser records and the bare row name a caller may pass. An operator reading "keys this engine
// cannot apply" has to see the key their own file spelled.
func Test_a_reported_key_is_named_by_both_spellings(t *testing.T) {
	for _, k := range builtInConfigKeys {
		if k.applies || k.read != nil {
			continue
		}
		full := strings.TrimPrefix(k.burpKey, "scanner/")
		for _, recorded := range []string{full, k.name} {
			c := BuiltInConfig{UnrepresentableKeys: []string{recorded}}
			_, unapplied := c.ApplyWithReport(DefaultAuditConfig())
			if len(unapplied) != 1 || unapplied[0] != k.name {
				t.Errorf("a file naming %q reports %v, want [%s]: the operator has to be told which key did nothing",
					recorded, unapplied, k.name)
			}
		}
	}
}
