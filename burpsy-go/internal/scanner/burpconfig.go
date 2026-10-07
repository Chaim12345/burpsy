// Burp scan-configuration loading: the `resources/BuiltInConfigs/*.json` shape, read into
// BuiltInConfig so a shipped configuration can be loaded without silently dropping keys.
//
// The six transcribed presets in BuiltInConfigs are static. This file is the other door: an
// operator points -scan-config at a Burp configuration file and gets exactly what the engine can
// honour, plus a report of what it cannot.
package scanner

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// burpConfigFile is the subset of Burp's configuration JSON this loader reads. Burp's files carry
// far more sections (crawl options, display, extensions); anything outside `scanner/*` is not this
// engine's business and is ignored without comment, while an unknown `scanner/*` key is reported —
// a scanner key the operator named should never vanish quietly.
type burpConfigFile struct {
	Scanner map[string]json.RawMessage `json:"scanner"`
}

// burpConfigSections are the `scanner` sub-objects Burp nests its keys under, mapped to the key
// prefix each becomes. Burp's shipped files nest each key one level under its section —
// `scanner.insertion_point_types.insert_url_params` — and walking these sections is what lets a
// nested key meet its row. Every section Burp's own 29 shipped configurations use is listed, not
// just the ones with fields behind them: an unlisted section is reported as one opaque section name,
// which hides *which* keys an operator's file set and did nothing with.
var burpConfigSections = map[string]string{
	"insertion_point_types":                 "scanner/insertion_point_types/",
	"issues_reported":                       "scanner/issues_reported/",
	"error_handling":                        "scanner/error_handling/",
	"audit_optimization":                    "scanner/audit_optimization/",
	"modifying_parameter_locations":         "scanner/modifying_parameter_locations/",
	"frequently_occurring_insertion_points": "scanner/frequently_occurring_insertion_points/",
	"ignored_insertion_points":              "scanner/ignored_insertion_points/",
	"misc_insertion_point_options":          "scanner/misc_insertion_point_options/",
	"javascript_analysis":                   "scanner/javascript_analysis/",
	"audit_project_option_overrides":        "scanner/audit_project_option_overrides/",
}

// ParseBurpConfig reads one of Burp's shipped (or exported) scan configurations.
//
// It returns the keys this engine can overlay, recording the keys the `scanner` section named that
// this engine cannot apply in UnrepresentableKeys so ApplyWithReport repeats them. The two numeric
// sections (`scanner/error_handling/*`, `scanner/audit_optimization/*`) carry counts and minutes;
// the insertion-point and issues_reported sections carry booleans. An unknown or field-less
// `scanner/*` key is reported, never dropped: a configuration whose scanner section was mistyped
// must not load as if it were empty.
func ParseBurpConfig(data []byte) (BuiltInConfig, error) {
	var file burpConfigFile
	if err := json.Unmarshal(data, &file); err != nil {
		return BuiltInConfig{}, fmt.Errorf("burp scan configuration: %w", err)
	}

	byBurpKey := make(map[string]int, len(builtInConfigKeys))
	for i, k := range builtInConfigKeys {
		byBurpKey[k.burpKey] = i
	}

	var out BuiltInConfig

	// set applies one decoded value to the field its row reads.
	set := func(row int, raw json.RawMessage) error {
		k := builtInConfigKeys[row]
		// The two audit_optimization selectors carry Burp's uiName SPELLINGS, not numbers:
		// `"scan_speed": "thorough"`, `"scan_accuracy": "minimise_false_positives"` (checked against
		// the shipped Minimize false positives.json / Audit coverage - maximum.json). They sit in a
		// section whose other keys are counts and minutes, so they are matched by name here for the
		// same reason skip_ineffective_checks is: a section-wide rule would read a string as a number
		// and reject a file Burp itself writes.
		if rank, ok, err := burpConfigNamedRank(k.burpKey, raw); ok {
			if err != nil {
				return err
			}
			setBurpConfigField(&out, k.name, SomeUint32(rank))
			return nil
		}
		// Burp writes -1 for an audit project-option override that is not set (Zbuj.java:27-28) and
		// reads `> -1` as set (:19-22), so a file Burp itself exported with no override carries -1.
		// Refusing it would reject Burp's own output; reading it as a number it is not would install an
		// override nobody asked for. It is recorded as asked-for-nothing and reported applied.
		if strings.HasPrefix(k.burpKey, "scanner/audit_project_option_overrides/") && isMinusOne(raw) {
			out.InheritedOverrides = append(out.InheritedOverrides, k.name)
			return nil
		}
		if isNumericBurpKey(k.burpKey) {
			n, err := burpConfigUint(raw)
			if err != nil {
				return fmt.Errorf("burp scan configuration: %s: %w", k.burpKey, err)
			}
			if k.max != 0 && n > k.max {
				return fmt.Errorf("burp scan configuration: %s: %d is above the largest value this key can carry (%d)",
					k.burpKey, n, k.max)
			}
			if k.min != 0 && n < k.min {
				return fmt.Errorf("burp scan configuration: %s: %d is below the smallest value this key can carry (%d); "+
					"a ceiling of zero would enumerate no insertion points, so the run would audit nothing and report a completed audit",
					k.burpKey, n, k.min)
			}
			setBurpConfigField(&out, k.name, SomeUint32(n))
			return nil
		}
		b, err := burpConfigBool(raw)
		if err != nil {
			return fmt.Errorf("burp scan configuration: %s: %w", k.burpKey, err)
		}
		setBurpConfigField(&out, k.name, SomeUint32(b2u(b)))
		return nil
	}

	apply := func(fullKey string, raw json.RawMessage) error {
		out.ParsedKeys = append(out.ParsedKeys, strings.TrimPrefix(fullKey, "scanner/"))
		row, ok := byBurpKey[fullKey]
		if ok && builtInConfigKeys[row].listShaped {
			return setListShaped(&out, builtInConfigKeys[row].name, fullKey, raw)
		}
		if !ok || builtInConfigKeys[row].read == nil {
			out.UnrepresentableKeys = append(out.UnrepresentableKeys, strings.TrimPrefix(fullKey, "scanner/"))
			return nil
		}
		return set(row, raw)
	}

	for section, raw := range file.Scanner {
		prefix, known := burpConfigSections[section]
		if !known {
			out.UnrepresentableKeys = append(out.UnrepresentableKeys, section)
			continue
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(raw, &keys); err != nil {
			return BuiltInConfig{}, fmt.Errorf("burp scan configuration: scanner.%s: %w", section, err)
		}
		for key, v := range keys {
			if err := apply(prefix+key, v); err != nil {
				return BuiltInConfig{}, err
			}
		}
	}
	return out, nil
}

// setListShaped decodes a key whose Burp value is a list rather than a scalar, into the typed field
// its handler reads. These keys never go to UnrepresentableKeys: their rows are accounted by
// applyIssueSelection and accountIgnoredParameterRules, which say applied or unapplied for each.
func setListShaped(out *BuiltInConfig, name, fullKey string, raw json.RawMessage) error {
	switch {
	case name == "selected_issues":
		issues, err := parseSelectedIssues(raw)
		if err != nil {
			return fmt.Errorf("burp scan configuration: %s: %w", fullKey, err)
		}
		out.SelectedIssues = issues
		out.SelectedIssuesSet = true
		return nil
	case strings.HasPrefix(fullKey, "scanner/ignored_insertion_points/"):
		var rules []json.RawMessage
		if err := json.Unmarshal(raw, &rules); err != nil {
			return fmt.Errorf("burp scan configuration: %s: expected a list of rules: %w", fullKey, err)
		}
		if out.IgnoredParameterRules == nil {
			out.IgnoredParameterRules = map[string]int{}
		}
		out.IgnoredParameterRules[name] = len(rules)
		return nil
	}
	// A list-shaped row this parser has no decoder for is recorded, so the report still names it.
	out.UnrepresentableKeys = append(out.UnrepresentableKeys, strings.TrimPrefix(fullKey, "scanner/"))
	return nil
}

// ApplyBurpConfigFile is the import path for one of Burp's own scan-configuration files: parse it,
// overlay it on base, and return every key the file set that this engine could not apply.
//
// It exists so the CLI's -scan-config and anything else that imports a file share ONE path, and so a
// test can drive exactly that path rather than a re-assembly of it.
func ApplyBurpConfigFile(base AuditConfig, data []byte) (AuditConfig, []string, error) {
	parsed, err := ParseBurpConfig(data)
	if err != nil {
		return base, nil, err
	}
	applied, unapplied := parsed.ApplyWithReport(base)
	return applied, unapplied, nil
}

// isNumericBurpKey reports whether the key carries a count or a duration rather than a boolean.
// The error-handling keys are failure counts and the audit-optimization key is minutes; every
// insertion_point_types and issues_reported key is a boolean in Burp's shipped files.
func isNumericBurpKey(burpKey string) bool {
	// Matched exactly, not by section prefix: misc_insertion_point_options carries one count and one
	// boolean side by side, so a prefix rule would read `"use_nested_insertion_points": true` as a
	// number and fail the whole file.
	if burpKey == "scanner/misc_insertion_point_options/max_insertion_points_per_base_request" {
		return true
	}
	// audit_optimization is the same shape and needs the same treatment: it carries minutes and
	// counts BESIDE one boolean, so the prefix rule would read Burp's own
	// `"skip_ineffective_checks": true` as a number and reject the whole file. Named rather than
	// section-matched, exactly as above.
	if burpKey == "scanner/audit_optimization/skip_ineffective_checks" {
		return false
	}
	// follow_redirections is the same section's other boolean (Zhd_.java:41 reads it with the boolean
	// getter). Before it had a reader the key never reached this function; with one, the section rule
	// would read `"follow_redirections": true` as a number and reject four of Burp's shipped files.
	if burpKey == "scanner/audit_optimization/follow_redirections" {
		return false
	}
	return strings.HasPrefix(burpKey, "scanner/error_handling/") ||
		strings.HasPrefix(burpKey, "scanner/audit_optimization/") ||
		// Whole seconds (Zbuj.java:19-22). Without this they would fall to the boolean decoder, which
		// accepts a number as "non-zero" — a 10-second override would load as 1.
		strings.HasPrefix(burpKey, "scanner/audit_project_option_overrides/")
}

// isMinusOne reports whether a raw JSON value is the integer -1.
func isMinusOne(raw json.RawMessage) bool {
	var n float64
	return json.Unmarshal(raw, &n) == nil && n == -1
}

// setBurpConfigField is the parse-side field map, keyed by row name. It exists so the parser does
// not need reflection: one entry per field-backed row, and the field/row invariant test asserts the
// two stay in step.
func setBurpConfigField(c *BuiltInConfig, name string, val OptUint32) {
	switch name {
	case "consecutive_check_failures_to_abandon_unit":
		c.ConsecutiveCheckFailuresToAbandonUnit = val
	case "consecutive_unit_failures_to_fail_item":
		c.ConsecutiveUnitFailuresToFailItem = val
	case "pause_session_after_failed_items":
		c.PauseSessionAfterFailedItems = val
	case "pause_session_at_failed_item_percentage":
		c.PauseSessionAtFailedItemPercentage = val
	case "maximum_audit_time_minutes":
		c.MaximumAuditTimeMinutes = val
	case "max_items_in_progress":
		c.MaxItemsInProgress = val
	case "scan_speed":
		c.ScanSpeed = val
	case "scan_accuracy":
		c.ScanAccuracy = val
	case "max_insertion_points_per_base_request":
		c.MaxInsertionPointsPerRequest = val
	case "use_nested_insertion_points":
		c.UseNestedInsertionPoints = val
	case "skip_ineffective_checks":
		c.SkipIneffectiveChecks = val
	case "insert_url_params":
		c.InsertURLParams = val
	case "insert_body_params":
		c.InsertBodyParams = val
	case "insert_cookies":
		c.InsertCookies = val
	case "insert_http_headers":
		c.InsertHTTPHeaders = val
	case "insert_param_name":
		c.InsertParamName = val
	case "insert_url_path_filename":
		c.InsertURLPathFilename = val
	case "insert_url_path_folders":
		c.InsertURLPathFolders = val
	case "insert_entire_body":
		c.InsertEntireBody = val
	case "scan_type_passive":
		c.PassiveChecks = val
	case "scan_type_light_active":
		c.LightActiveChecks = val
	case "scan_type_medium_active":
		c.MediumActiveChecks = val
	case "scan_type_intrusive_active":
		c.IntrusiveActiveChecks = val
	case "scan_type_javascript_analysis":
		c.JavaScriptAnalysis = val
	case "store_issues_within_queue_items":
		c.StoreQueueItems = val
	case "select_individual_issues":
		c.SelectIndividualIssues = val
	case "scan_only_selected_issues":
		c.ScanOnlySelectedIssues = val
	case "relocate_body_to_url":
		c.RelocateBodyToURL = val
	case "relocate_body_to_cookie":
		c.RelocateBodyToCookie = val
	case "relocate_url_to_body":
		c.RelocateURLToBody = val
	case "relocate_url_to_cookie":
		c.RelocateURLToCookie = val
	case "relocate_cookie_to_body":
		c.RelocateCookieToBody = val
	case "relocate_cookie_to_url":
		c.RelocateCookieToURL = val
	// The nine below had rows with readers and no entry here, so a loaded file's value was parsed,
	// validated and then dropped: the row read unset, and the report named the key in neither list
	// (found by TestEveryShippedConfigurationAccountsForEveryScannerKeyItNames, saq3.1). "Audit
	// coverage - maximum" sets all eight quick_scan keys; two shipped files set the follow-up count.
	case "number_of_follow_up_passes":
		c.FollowUpPasses = val
	case "quick_scan_url_params":
		c.QuickScanURLParams = val
	case "quick_scan_body_params":
		c.QuickScanBodyParams = val
	case "quick_scan_cookies":
		c.QuickScanCookies = val
	case "quick_scan_http_headers":
		c.QuickScanHTTPHeaders = val
	case "quick_scan_param_name":
		c.QuickScanParamName = val
	case "quick_scan_url_path_filename":
		c.QuickScanURLPathFilename = val
	case "quick_scan_url_path_folders":
		c.QuickScanURLPathFolders = val
	case "quick_scan_entire_body":
		c.QuickScanEntireBody = val
	// The three per-run project overrides (burpsy-react-ui-o2p3).
	case "follow_redirections":
		c.FollowRedirections = val
	case "audit_connect_timeout":
		c.AuditConnectTimeout = val
	case "audit_normal_timeout":
		c.AuditNormalTimeout = val
	}
}

// burpConfigBool decodes a boolean key. Burp writes JSON booleans; a 0/1 integer is accepted too,
// because exported files are not always round-tripped faithfully.
func burpConfigBool(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	n, err := burpConfigUint(raw)
	if err != nil {
		return false, err
	}
	return n != 0, nil
}

// burpConfigUint decodes a numeric key, refusing fractions — a fractional failure count is a
// corrupted file, and silently flooring it would load a configuration that was never written.
func burpConfigUint(raw json.RawMessage) (uint32, error) {
	var n float64
	if err := json.Unmarshal(raw, &n); err != nil || n < 0 || n != float64(int64(n)) || n > float64(^uint32(0)) {
		return 0, fmt.Errorf("expected a non-negative integer, got %s", strconv.Quote(string(raw)))
	}
	return uint32(n), nil
}

func b2u(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// burpConfigNamedRank decodes the two audit_optimization keys whose values are names rather than
// numbers, returning the rank, whether this key is one of them, and any decode error.
//
// Three returns rather than two because "not this key" and "this key, bad value" must not collapse:
// the first falls through to the numeric/boolean handling, the second has to fail the file. A
// configuration naming a speed this engine does not know is refused rather than read as the
// default — a typo that silently narrowed a scan would be the quiet-wrong-answer this package
// exists to avoid.
func burpConfigNamedRank(burpKey string, raw json.RawMessage) (uint32, bool, error) {
	switch burpKey {
	case "scanner/audit_optimization/scan_speed":
		name, err := burpConfigString(raw)
		if err != nil {
			return 0, true, fmt.Errorf("burp scan configuration: %s: %w", burpKey, err)
		}
		speed, ok := ParseCheckSpeed(name)
		if !ok {
			return 0, true, fmt.Errorf("burp scan configuration: %s: %q is not one of fast, normal or thorough", burpKey, name)
		}
		return uint32(speed), true, nil
	case "scanner/audit_optimization/scan_accuracy":
		name, err := burpConfigString(raw)
		if err != nil {
			return 0, true, fmt.Errorf("burp scan configuration: %s: %w", burpKey, err)
		}
		accuracy, ok := ParseCheckAccuracy(name)
		if !ok {
			return 0, true, fmt.Errorf("burp scan configuration: %s: %q is not one of minimise_false_negatives, "+
				"normal or minimise_false_positives", burpKey, name)
		}
		return uint32(accuracy), true, nil
	}
	return 0, false, nil
}

// burpConfigString decodes a JSON string value, naming what arrived when it is not one.
func burpConfigString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("expected a name, got %s", strings.TrimSpace(string(raw)))
	}
	return s, nil
}
