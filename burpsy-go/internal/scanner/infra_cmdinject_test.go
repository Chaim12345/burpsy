package scanner

import "testing"

const pingTemplate = `ping -c 1 HOST`

func TestSemicolonPayloadIsAStatementBreakout(t *testing.T) {
	if got := PayloadBreaksOut(pingTemplate, "HOST", "1.1.1.1; id"); got != BreakoutStatementSeparator {
		t.Fatalf("got %v, want BreakoutStatementSeparator", got)
	}
}

func TestAndOrPayloadsAreStatementBreakouts(t *testing.T) {
	for _, p := range []string{"1.1.1.1 && id", "1.1.1.1 || id"} {
		if got := PayloadBreaksOut(pingTemplate, "HOST", p); got != BreakoutStatementSeparator {
			t.Errorf("payload %q: got %v, want BreakoutStatementSeparator", p, got)
		}
	}
}

func TestCommandSubstitutionIsDetected(t *testing.T) {
	for _, p := range []string{"$(id)", "`id`"} {
		if got := PayloadBreaksOut(pingTemplate, "HOST", p); got != BreakoutCommandSubstitution {
			t.Errorf("payload %q: got %v, want BreakoutCommandSubstitution", p, got)
		}
	}
}

func TestPipePayloadIsAPipelineBreakout(t *testing.T) {
	if got := PayloadBreaksOut(pingTemplate, "HOST", "1.1.1.1 | id"); got != BreakoutPipeline {
		t.Fatalf("got %v, want BreakoutPipeline", got)
	}
}

// The property the primitive exists for: a payload that stays inside its quoting is inert
// no matter how injection-shaped it looks in the response body.
func TestPayloadInsideQuotesIsNotABreakout(t *testing.T) {
	if got := PayloadBreaksOut(`ping -c 1 "HOST"`, "HOST", "1.1.1.1; id"); got != BreakoutNone {
		t.Fatalf("a payload contained by double quotes was reported as %v, want BreakoutNone", got)
	}
}

func TestSingleQuotesContainSubstitutionToo(t *testing.T) {
	if got := PayloadBreaksOut(`ping -c 1 'HOST'`, "HOST", "$(id)"); got != BreakoutNone {
		t.Fatalf("single-quoted substitution reported as %v, want BreakoutNone", got)
	}
}

func TestBenignPayloadIsNotABreakout(t *testing.T) {
	if got := PayloadBreaksOut(pingTemplate, "HOST", "1.1.1.1"); got != BreakoutNone {
		t.Fatalf("got %v, want BreakoutNone", got)
	}
}

// Unparseable must be its own answer: it is not a breakout, and it is not proof of safety.
func TestUnparseableLineIsNeitherBreakoutNorSafe(t *testing.T) {
	got := PayloadBreaksOut(pingTemplate, "HOST", `"unterminated`)
	if got != BreakoutUnparseable {
		t.Fatalf("got %v, want BreakoutUnparseable", got)
	}
	if got.IsBreakout() {
		t.Error("BreakoutUnparseable must not count as a breakout")
	}
}

func TestNewlinePayloadIsAStatementBreakout(t *testing.T) {
	if got := PayloadBreaksOut(pingTemplate, "HOST", "1.1.1.1\nid"); got != BreakoutStatementSeparator {
		t.Fatalf("got %v, want BreakoutStatementSeparator", got)
	}
}

func TestOnlyBreakoutKindsReportIsBreakout(t *testing.T) {
	if BreakoutNone.IsBreakout() {
		t.Error("BreakoutNone reported as a breakout")
	}
	for _, k := range []BreakoutKind{BreakoutStatementSeparator, BreakoutCommandSubstitution, BreakoutPipeline} {
		if !k.IsBreakout() {
			t.Errorf("%v did not report as a breakout", k)
		}
	}
}
