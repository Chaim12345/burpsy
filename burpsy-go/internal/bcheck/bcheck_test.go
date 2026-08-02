package bcheck

import (
	"strings"
	"testing"
)

// f1 is the canonical minimal passive check from the research notes.
const f1 = `
metadata:
  language: v1-beta
  name: "NuGet API Key"
  description: "Looks for NuGet API keys in page source."
  author: "@puzzlepeaches"
  tags: "nuget", "token", "exposure"

given response then
  if {latest.response} matches "oy2[a-z0-9]{43}" then
      report issue:
          severity: info
          confidence: tentative
          detail: "NuGet API key found in page."
          remediation: "Review and remove unnecessary exposure."
  end if
`

func TestParseMinimalPassive(t *testing.T) {
	c, err := Parse(f1)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if c.Name != "NuGet API Key" {
		t.Errorf("name = %q, want %q", c.Name, "NuGet API Key")
	}
	if c.Given != "response" {
		t.Errorf("given = %q, want %q", c.Given, "response")
	}
	if len(c.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(c.Statements))
	}
	if _, ok := c.Statements[0].(*IfStatement); !ok {
		t.Fatalf("statement 0 is %T, want *IfStatement", c.Statements[0])
	}
	if len(c.Metadata.Reference) != 3 {
		t.Errorf("tags = %v, want 3 tags", c.Metadata.Reference)
	}
}

func TestRunPassiveMatchesRegex(t *testing.T) {
	c, err := Parse(f1)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Positive: the response contains a NuGet key.
	ctx := NewContext()
	ctx.Response = []byte("https://example.com/nuget/oy2abc1234567890123456789012345678901234567xyz")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Severity != SeverityInfo {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityInfo)
	}
	if findings[0].Confidence != ConfidenceTentative {
		t.Errorf("confidence = %q, want %q", findings[0].Confidence, ConfidenceTentative)
	}

	// Negative: no key in the response.
	ctx2 := NewContext()
	ctx2.Response = []byte("no secrets here")
	findings2, err := RunPassive(c, ctx2)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings2) != 0 {
		t.Errorf("findings = %d, want 0", len(findings2))
	}
}

func TestParseInOperator(t *testing.T) {
	src := `
given response then
  if "secret" in {latest.response} then
      report issue:
          severity: low
          confidence: certain
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	ctx := NewContext()
	ctx.Response = []byte("the secret is here")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (needle on LEFT containment)", len(findings))
	}

	ctx2 := NewContext()
	ctx2.Response = []byte("nothing interesting")
	findings2, _ := RunPassive(c, ctx2)
	if len(findings2) != 0 {
		t.Errorf("findings = %d, want 0", len(findings2))
	}
}

func TestParseDefineAndForEach(t *testing.T) {
	src := `
metadata:
  name: "iterated check"

define:
  needle = "admin"

run for each:
  path = "/login", "/admin"

given response then
  if {needle} in {latest.response} then
      report issue:
          severity: medium
          confidence: firm
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(c.Defines) != 1 || c.Defines[0].Name != "needle" {
		t.Errorf("defines = %+v, want needle define", c.Defines)
	}
	if len(c.ForEach) != 1 || c.ForEach[0].Iterator != "path" || len(c.ForEach[0].Values) != 2 {
		t.Errorf("for_each = %+v, want path with 2 values", c.ForEach)
	}

	// The define should be bound before the body runs.
	ctx := NewContext()
	ctx.Response = []byte("admin panel")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 2 { // two iterations
		t.Errorf("findings = %d, want 2 (one per iteration)", len(findings))
	}
}

func TestParseElseIfChain(t *testing.T) {
	src := `
given response then
  if {latest.response} matches "critical" then
      report issue:
          severity: high
          confidence: certain
  else if {latest.response} matches "warning" then
      report issue:
          severity: medium
          confidence: certain
  else then
      report issue:
          severity: info
          confidence: certain
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	run := func(body string) int {
		ctx := NewContext()
		ctx.Response = []byte(body)
		f, err := RunPassive(c, ctx)
		if err != nil {
			t.Fatalf("run failed: %v", err)
		}
		return len(f)
	}
	if got := run("critical issue"); got != 1 {
		t.Errorf("critical branch findings = %d, want 1", got)
	}
	if got := run("warning only"); got != 1 {
		t.Errorf("warning branch findings = %d, want 1", got)
	}
	if got := run("nothing"); got != 1 {
		t.Errorf("else branch findings = %d, want 1", got)
	}
}

func TestParseAndOrNot(t *testing.T) {
	src := `
given response then
  if {latest.response} contains "a" and {latest.response} contains "b" then
      report issue:
          severity: low
          confidence: certain
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	ctx := NewContext()
	ctx.Response = []byte("has a and b")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("and-branch findings = %d, want 1", len(findings))
	}
	ctx2 := NewContext()
	ctx2.Response = []byte("only a")
	findings2, _ := RunPassive(c, ctx2)
	if len(findings2) != 0 {
		t.Errorf("and-branch negative findings = %d, want 0", len(findings2))
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"missing given", `if x then end if`, "given"},
		{"missing end if", "given response then\n  if {a} is \"b\" then\n    report issue:\n      severity: low\n      confidence: certain\n", "end if"},
		{"bad severity", `
given response then
  report issue:
    severity: catastrophic
    confidence: certain
`, "severity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.src)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestRunPassiveIgnoresNonResponseChecks(t *testing.T) {
	src := `given host then
  report issue:
    severity: low
    confidence: certain
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	findings, err := RunPassive(c, NewContext())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0 for host-given check", len(findings))
	}
}
