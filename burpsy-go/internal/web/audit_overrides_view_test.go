package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

// burpsy-react-ui-o2p3: the configuration a run reports carries its project-option overrides, and an
// unset one reads null ("the engagement's setting applies"), never false or 0.
func TestTheAuditConfigViewReportsTheRunsProjectOptionOverrides(t *testing.T) {
	unset, err := json.Marshal(newAuditConfigView(scanner.DefaultAuditConfig()))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"follow_redirections":null`, `"connect_timeout_s":null`, `"normal_timeout_s":null`} {
		if !strings.Contains(string(unset), want) {
			t.Errorf("unset overrides: %s missing from %s", want, unset)
		}
	}
	cfg, _, err := scanner.ApplyBurpConfigFile(scanner.DefaultAuditConfig(), []byte(
		`{"scanner":{"audit_optimization":{"follow_redirections":true},"audit_project_option_overrides":{"connect_timeout":10,"normal_timeout":0}}}`))
	if err != nil {
		t.Fatal(err)
	}
	set, _ := json.Marshal(newAuditConfigView(cfg))
	for _, want := range []string{`"follow_redirections":true`, `"connect_timeout_s":10`, `"normal_timeout_s":0`} {
		if !strings.Contains(string(set), want) {
			t.Errorf("set overrides: %s missing from %s", want, set)
		}
	}
}

// burpsy-react-ui-9mti: the javascript_analysis keys a run carries are reported, null when unset.
func TestTheAuditConfigViewReportsTheRunsJavaScriptAnalysisKeys(t *testing.T) {
	unset, _ := json.Marshal(newAuditConfigView(scanner.DefaultAuditConfig()))
	for _, want := range []string{`"javascript_static_analysis":null`, `"javascript_dynamic_analysis":null`,
		`"max_static_time_per_item_s":null`, `"max_dynamic_time_per_item_s":null`} {
		if !strings.Contains(string(unset), want) {
			t.Errorf("unset: %s missing from %s", want, unset)
		}
	}
	cfg, _, err := scanner.ApplyBurpConfigFile(scanner.DefaultAuditConfig(), []byte(
		`{"scanner":{"javascript_analysis":{"use_static_analysis":true,"use_dynamic_analysis":false,"max_static_time_per_item":10,"max_dynamic_time_per_item":600}}}`))
	if err != nil {
		t.Fatal(err)
	}
	set, _ := json.Marshal(newAuditConfigView(cfg))
	for _, want := range []string{`"javascript_static_analysis":true`, `"javascript_dynamic_analysis":false`,
		`"max_static_time_per_item_s":10`, `"max_dynamic_time_per_item_s":600`} {
		if !strings.Contains(string(set), want) {
			t.Errorf("set: %s missing from %s", want, set)
		}
	}
}
