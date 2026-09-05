package scanner

import (
	"strings"
	"testing"
)

// A Burp file's scanner section must load into exactly the fields the engine can overlay, and an
// unknown scanner key must be reported rather than dropped.
func Test_parse_burp_config_maps_keys_and_reports_the_rest(t *testing.T) {
	data := []byte(`{
		"project_options": {"display": {"font": "Monospace"}},
		"scanner": {
			"insertion_point_types": {"insert_url_params": false, "insert_entire_body": true},
			"issues_reported": {"scan_type_passive": false, "scan_only_selected_issues": true},
			"error_handling": {"consecutive_audit_check_failures_to_skip_insertion_point": 5},
			"audit_optimization": {"maximum_crawl_and_audit_time": 15},
			"totally_unknown_key": true
		}
	}`)
	cfg, err := ParseBurpConfig(data)
	if err != nil {
		t.Fatalf("ParseBurpConfig: %v", err)
	}
	if !cfg.InsertURLParams.Set || cfg.InsertURLParams.Value != 0 {
		t.Errorf("insert_url_params = %+v, want set false", cfg.InsertURLParams)
	}
	if !cfg.InsertEntireBody.Set || cfg.InsertEntireBody.Value != 1 {
		t.Errorf("insert_entire_body = %+v, want set true", cfg.InsertEntireBody)
	}
	if !cfg.PassiveChecks.Set || cfg.PassiveChecks.Value != 0 {
		t.Errorf("scan_type_passive = %+v, want set false", cfg.PassiveChecks)
	}
	if !cfg.ConsecutiveCheckFailuresToAbandonUnit.Set || cfg.ConsecutiveCheckFailuresToAbandonUnit.Value != 5 {
		t.Errorf("consecutive_check_failures = %+v, want set 5", cfg.ConsecutiveCheckFailuresToAbandonUnit)
	}
	if !cfg.MaximumAuditTimeMinutes.Set || cfg.MaximumAuditTimeMinutes.Value != 15 {
		t.Errorf("maximum_audit_time_minutes = %+v, want set 15", cfg.MaximumAuditTimeMinutes)
	}
	reported := strings.Join(cfg.UnrepresentableKeys, ",")
	if !strings.Contains(reported, "scan_only_selected_issues") || !strings.Contains(reported, "totally_unknown_key") {
		t.Errorf("UnrepresentableKeys = %v, want the per-issue key and the unknown key", cfg.UnrepresentableKeys)
	}
}

// The parsed preset must overlay like a transcribed one: insertion keys build the point set, and
// the report comes out of ApplyWithReport.
func Test_parse_burp_config_applies_like_a_preset(t *testing.T) {
	data := []byte(`{"scanner": {"insertion_point_types": {"insert_cookies": false}, "issues_reported": {"scan_type_javascript_analysis": false}}}`)
	cfg, err := ParseBurpConfig(data)
	if err != nil {
		t.Fatalf("ParseBurpConfig: %v", err)
	}
	applied := cfg.Apply(DefaultAuditConfig())
	if containsKind(applied.InsertionKinds, "cookie") {
		t.Error("cookies disabled but still in the run's point classes")
	}
	if !containsKind(applied.InsertionKinds, "param_name_url") {
		t.Error("naming the insertion section must start from the full Burp-shaped set, not the engine default")
	}
	_, unapplied := cfg.ApplyWithReport(DefaultAuditConfig())
	if len(unapplied) != 0 {
		t.Errorf("every key parsed set a field; unapplied = %v", unapplied)
	}
}

// A preset that turns passive checking off must report both the gate it applies and the keys it
// could not apply, so nothing vanishes silently.
func Test_apply_with_report_names_unapplied_keys(t *testing.T) {
	perIssueOnly := BuiltInConfig{UnrepresentableKeys: []string{"scan_only_selected_issues"}}
	_, unapplied := perIssueOnly.ApplyWithReport(DefaultAuditConfig())
	if len(unapplied) != 1 || unapplied[0] != "scan_only_selected_issues" {
		t.Errorf("unapplied = %v, want the recorded per-issue key", unapplied)
	}

	// Without the parser's record, a field-less key is simply not present.
	_, again := BuiltInConfig{}.ApplyWithReport(DefaultAuditConfig())
	if len(again) != 0 {
		t.Errorf("an empty preset reports nothing; got %v", again)
	}
}

// Malformed values must be refused, not floor()ed into a plausible-looking lie.
func Test_parse_burp_config_refuses_malformed_values(t *testing.T) {
	for name, data := range map[string][]byte{
		"fractional count":   []byte(`{"scanner": {"error_handling": {"consecutive_audit_check_failures_to_skip_insertion_point": 1.5}}}`),
		"string boolean":     []byte(`{"scanner": {"insertion_point_types": {"insert_url_params": "yes"}}}`),
		"negative minutes":   []byte(`{"scanner": {"audit_optimization": {"maximum_crawl_and_audit_time": -5}}}`),
		"array where object": []byte(`{"scanner": [1, 2]}`),
	} {
		if _, err := ParseBurpConfig(data); err == nil {
			t.Errorf("%s: ParseBurpConfig accepted malformed input", name)
		}
	}
}
