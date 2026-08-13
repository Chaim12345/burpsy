package scanner

import (
	"strings"
	"testing"
)

func TestJavaSQLiEvidenceRecognizesErrorAndEscapedQuotePair(t *testing.T) {
	observations := map[sqlInjectionProbeKind]string{
		sqliProbeQuote:        "database syntax error",
		sqliProbeEscapedQuote: "normal response",
		sqliProbeError:        "normal response",
	}
	evidence := analyzeSQLiEvidence("baseline", observations, func(body string) bool {
		return strings.Contains(body, "error")
	})
	if evidence&SQLiEvidenceDatabaseError == 0 {
		t.Fatal("database error evidence was not recognized")
	}
	if evidence&SQLiEvidenceQuotePair == 0 {
		t.Fatal("quote-pair evidence was not recognized")
	}
}

func TestJavaSQLiEvidenceRecognizesBooleanAndOrderDifferences(t *testing.T) {
	observations := map[sqlInjectionProbeKind]string{
		sqliProbeBooleanTrue:  "rows=1",
		sqliProbeBooleanFalse: "rows=0",
		sqliProbeOrderTrue:    "first row",
		sqliProbeOrderFalse:   "database syntax error",
	}
	evidence := analyzeSQLiEvidence("baseline", observations, func(body string) bool {
		return strings.Contains(body, "error")
	})
	if evidence&SQLiEvidenceBooleanDifference == 0 {
		t.Fatal("boolean true/false difference was not recognized")
	}
	if evidence&SQLiEvidenceOrderDifference == 0 {
		t.Fatal("ORDER BY difference was not recognized")
	}
}

func TestJavaSQLiEvidenceDoesNotTreatIdenticalResponsesAsDifferences(t *testing.T) {
	observations := map[sqlInjectionProbeKind]string{
		sqliProbeBooleanTrue:  "same response",
		sqliProbeBooleanFalse: "same response",
		sqliProbeOrderTrue:    "same response",
		sqliProbeOrderFalse:   "same response",
	}
	if evidence := analyzeSQLiEvidence("baseline", observations, func(string) bool { return false }); evidence != 0 {
		t.Fatalf("identical responses produced evidence %#x", evidence)
	}
}

func TestJavaSQLiProbeFamiliesCoverTheNonOOBEvidencePaths(t *testing.T) {
	seen := make(map[sqlInjectionProbeKind]bool)
	for _, probe := range sqlInjectionProbes {
		seen[probe.kind] = true
	}
	for _, kind := range []sqlInjectionProbeKind{
		sqliProbeQuote,
		sqliProbeEscapedQuote,
		sqliProbeBooleanTrue,
		sqliProbeBooleanFalse,
		sqliProbeOrderTrue,
		sqliProbeOrderFalse,
		sqliProbeError,
	} {
		if !seen[kind] {
			t.Errorf("missing SQLi probe kind %d", kind)
		}
	}
}
