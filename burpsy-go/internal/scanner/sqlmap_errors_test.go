package scanner

import (
	"strings"
	"testing"
)

// The embedded bank parses whole: every pattern compiles under RE2, and the count is pinned so a
// truncated or mis-parsed file fails here instead of silently shrinking coverage.
func TestSqlmapErrorPatternsLoad(t *testing.T) {
	patterns, err := sqlmapErrorPatterns()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	engines := map[string]bool{}
	for _, p := range patterns {
		engines[p.DBMS] = true
	}
	if len(patterns) < 187 || len(engines) < 31 {
		t.Fatalf("loaded %d patterns across %d engines, want at least 187 across 31", len(patterns), len(engines))
	}
}

// Messages only sqlmap's bank knows — no SQLErrorSignatures substring matches them — are now
// evidence, and the detail names the engine sqlmap attributes them to.
func TestSqlmapPatternsCatchWhatTheSubstringBankMisses(t *testing.T) {
	for msg, engine := range map[string]string{
		"Unknown column 'x1' in 'field list'":                              "MySQL",
		"SQL compilation error: 001003 (42000): syntax error line 1":       "Snowflake",
		"ERROR 4856: Syntax error, Sqlstate: 42601, Routine: base_yyerror": "Vertica",
		"com.sap.db.jdbc.exceptions: SAP DBTech JDBC: [257]":               "SAP HANA",
	} {
		if sub := ClassifyErrorEvidence("<p>ok</p>", "<p>"+msg+"</p>", SQLErrorSignatures); sub.Evidence == InjectionEvidenceErrorSignature {
			t.Errorf("%q: the substring bank already matches it (%v), so it does not show the regexes doing anything", msg, sub.Matched)
			continue
		}
		got := ClassifySQLError("<p>ok</p>", "<p>"+msg+"</p>")
		if got.Evidence != InjectionEvidenceErrorSignature {
			t.Errorf("%q: evidence = %v, want ErrorSignature from sqlmap's bank", msg, got.Evidence)
			continue
		}
		if !strings.Contains(strings.Join(got.Matched, " "), engine) {
			t.Errorf("%q: matched %v, want a %s pattern", msg, got.Matched, engine)
		}
	}
}

// The baseline rule holds for regexes too: a page that already carries the error proves nothing,
// and an ordinary page matches nothing.
func TestSqlmapPatternsHonourTheBaselineRule(t *testing.T) {
	const err = "<p>Unknown column 'x1' in 'field list'</p>"
	if got := ClassifySQLError(err, err); got.Evidence != InjectionEvidenceInconclusive {
		t.Errorf("error already in the baseline: evidence = %v, want Inconclusive", got.Evidence)
	}
	if got := ClassifySQLError("<p>ok</p>", "<p>Welcome back, your basket has 3 items.</p>"); got.Evidence != InjectionEvidenceNone {
		t.Errorf("ordinary page: evidence = %v (%v), want None", got.Evidence, got.Matched)
	}
}
