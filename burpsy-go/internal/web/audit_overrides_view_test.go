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
