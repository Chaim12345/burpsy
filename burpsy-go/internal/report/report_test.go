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
	// "2 findings", not "2 finding(s)": the count is pluralised properly now. The rest is unchanged —
	// every finding's own name and remediation still has to appear.
	for _, want := range []string{"2 findings", "SQL injection", "Missing CSP header", "Use parameterised queries."} {
		if !strings.Contains(doc, want) {
			t.Fatalf("HTML() missing %q", want)
		}
	}
}

// The report used to be a bare <ul> with no stylesheet, no summary and no severity grouping — a wall
// of text that happened to be valid HTML. These pin the parts that make it readable, so it cannot
// quietly regress to that.
func TestHTMLIsAStyledDocumentWithASeveritySummary(t *testing.T) {
	doc := string(HTML(sampleRows()))
	for _, want := range []string{
		"<!DOCTYPE html>",
		`<html lang="en"`,      // WCAG 3.1.1: the document states its language
		"<style>",              // self-contained: one file an operator can mail
		"prefers-color-scheme", // renders in the reader's theme, not the tool's
		`class="summary"`,      // severity tiles before any detail
		`class="tile"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("HTML() is missing %q — the report must be a styled, self-contained document", want)
		}
	}
}

// Worst first. A report that lists findings in store order buries a critical under three infos.
func TestHTMLOrdersFindingsWorstFirst(t *testing.T) {
	rows := []Row{
		{ID: 1, Name: "An info thing", Severity: "INFO"},
		{ID: 2, Name: "A high thing", Severity: "HIGH"},
		{ID: 3, Name: "A medium thing", Severity: "MEDIUM"},
	}
	doc := string(HTML(rows))
	high, med, info := strings.Index(doc, "A high thing"), strings.Index(doc, "A medium thing"), strings.Index(doc, "An info thing")
	if !(high < med && med < info) {
		t.Errorf("findings are not ordered worst-first: high@%d medium@%d info@%d", high, med, info)
	}
}

// The catalogue is the most useful thing the report holds, and it was being dropped at this boundary.
func TestHTMLRendersTheAdvisoryIncludingReferencesAndClassifications(t *testing.T) {
	rows := []Row{{
		ID: 1, Name: "SQL injection", Severity: "HIGH",
		Advisory: &Advisory{
			Name:            "SQL injection",
			TypeIndex:       "00100200",
			TypicalSeverity: "HIGH",
			DescriptionHTML: "<p>Injected SQL is executed by the database.</p>",
			RemediationHTML: "<p>Use parameterised queries.</p>",
			References:      []Link{{Title: "Reading", URL: "https://portswigger.net/x"}},
			Classifications: []Link{{Title: "CWE-89", URL: "https://cwe.mitre.org/data/definitions/89.html"}},
		},
	}}
	doc := string(HTML(rows))
	for _, want := range []string{
		"00100200",
		"<p>Injected SQL is executed by the database.</p>", // structure survives, not escaped away
		"CWE-89",
		`href="https://cwe.mitre.org/data/definitions/89.html"`,
		`href="https://portswigger.net/x"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("HTML() advisory is missing %q", want)
		}
	}
}

// A missing catalogue entry is stated, not left as a silent hole the reader cannot distinguish from
// "nothing looked".
func TestHTMLPrintsTheReasonACatalogueEntryIsAbsent(t *testing.T) {
	doc := string(HTML([]Row{{ID: 1, Name: "Odd check", Severity: "LOW", AdvisoryNote: "the catalogue has no entry for this class"}}))
	if !strings.Contains(doc, "the catalogue has no entry for this class") {
		t.Error("an absent advisory must explain itself rather than render as nothing")
	}
}

// Evidence is what makes a finding reproducible rather than an assertion.
func TestHTMLRendersEvidenceRows(t *testing.T) {
	doc := string(HTML([]Row{{
		ID: 1, Name: "Thing", Severity: "HIGH",
		Evidence: []Evidence{{Method: "POST", Host: "shop.test", Path: "/login", Status: 200}},
	}}))
	for _, want := range []string{"POST", "shop.test", "/login", "200"} {
		if !strings.Contains(doc, want) {
			t.Errorf("evidence table is missing %q", want)
		}
	}
}

// The finding's own text is attacker-influenced — it can carry markup lifted out of a scanned
// response — and must never become live markup in a file someone opens later.
func TestAFindingsOwnTextIsEscapedEvenThoughTheAdvisoryIsNot(t *testing.T) {
	doc := string(HTML([]Row{{
		ID: 1, Severity: "HIGH",
		Name:        `<script>alert("name")</script>`,
		Description: `<img src=x onerror=alert(1)>`,
	}}))
	if strings.Contains(doc, "<script>alert(") || strings.Contains(doc, "<img src=x onerror") {
		t.Errorf("a finding's own text was not escaped:\n%s", doc)
	}
}

// A link the catalogue names with a non-http scheme is printed as text, never handed to the browser.
func TestANonHTTPReferenceIsPrintedAsTextRatherThanLinked(t *testing.T) {
	doc := string(HTML([]Row{{
		ID: 1, Name: "Thing", Severity: "LOW",
		Advisory: &Advisory{Name: "Thing", References: []Link{{Title: "Bad", URL: "javascript:alert(1)"}}},
	}}))
	if strings.Contains(doc, "javascript:") {
		t.Errorf("a javascript: URL was rendered:\n%s", doc)
	}
	if !strings.Contains(doc, "Bad") {
		t.Error("the reference title should still be shown as text")
	}
}

// An empty report says what empty means. "No findings" and "nothing was looked for" are different
// claims and a report that conflates them is misleading.
func TestAnEmptyReportSaysWhatEmptyMeans(t *testing.T) {
	doc := string(HTML(nil))
	if !strings.Contains(doc, "not that the target is clean") {
		t.Error("an empty report must not read as an all-clear")
	}
}
