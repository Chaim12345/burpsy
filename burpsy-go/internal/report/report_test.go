package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleRows() []Row {
	return []Row{
		{
			ID:          1,
			Name:        "SQL injection",
			Severity:    "High",
			Confidence:  "Firm",
			Description: "A classic ' OR 1=1-- payload matched.",
			Remediation: "Use parameterised queries.",
			Hosts:       []string{"127.0.0.1"},
			Occurrences: 2,
		},
		{
			ID:          2,
			Name:        "Missing CSP header",
			Severity:    "Low",
			Confidence:  "Tentative",
			Description: "Response carries no Content-Security-Policy.",
			Remediation: "Set a CSP header.",
			Hosts:       []string{"127.0.0.1", "10.0.0.1"},
			Occurrences: 1,
		},
	}
}

func TestJSON_ReportIncludesEveryFindingAndTotal(t *testing.T) {
	doc, err := JSON(sampleRows())
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	var parsed struct {
		Findings []Row `json:"findings"`
		Total    int   `json:"total"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("JSON() output is not parseable: %v", err)
	}
	if parsed.Total != 2 {
		t.Fatalf("total = %d, want 2", parsed.Total)
	}
	if len(parsed.Findings) != 2 || parsed.Findings[0].Name != "SQL injection" {
		t.Fatalf("findings = %+v, want both sample rows", parsed.Findings)
	}
}

func TestSARIF_LevelsMapToVocabAndRulesMatchResults(t *testing.T) {
	doc, err := SARIF(sampleRows())
	if err != nil {
		t.Fatalf("SARIF() error: %v", err)
	}
	var parsed struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("SARIF() output is not parseable: %v", err)
	}
	if parsed.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", parsed.Version)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(parsed.Runs))
	}
	run := parsed.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 2 {
		t.Fatalf("rules/results = %d/%d, want 2/2", len(run.Tool.Driver.Rules), len(run.Results))
	}
	if run.Results[0].RuleID != run.Tool.Driver.Rules[0].ID {
		t.Fatalf("result ruleId %q does not match rule id %q", run.Results[0].RuleID, run.Tool.Driver.Rules[0].ID)
	}
	if run.Results[0].Level != "error" || run.Results[1].Level != "note" {
		t.Fatalf("levels = %q/%q, want error/note", run.Results[0].Level, run.Results[1].Level)
	}
}

func TestHTML_ContainsFindingNamesAndCount(t *testing.T) {
	doc := string(HTML(sampleRows()))
	for _, want := range []string{"2 finding(s)", "SQL injection", "Missing CSP header", "Use parameterised queries."} {
		if !strings.Contains(doc, want) {
			t.Fatalf("HTML() missing %q", want)
		}
	}
}
