package scanner

import (
	"regexp"
	"strings"
)

// SQLi probe data is package-level immutable state: constructing it per exchange
// adds allocations without changing the evaluator's evidence.
const sqlInjectionIssue = "SQL injection"

type sqlInjectionProbeKind uint8

const (
	sqliProbeError sqlInjectionProbeKind = iota
	sqliProbeQuote
	sqliProbeEscapedQuote
	sqliProbeBooleanTrue
	sqliProbeBooleanFalse
	sqliProbeOrderTrue
	sqliProbeOrderFalse
)

type sqlInjectionProbe struct {
	kind    sqlInjectionProbeKind
	payload string
}

var sqlInjectionProbes = [...]sqlInjectionProbe{
	{kind: sqliProbeQuote, payload: "'"},
	{kind: sqliProbeEscapedQuote, payload: "''"},
	{kind: sqliProbeBooleanTrue, payload: "' OR '1'='1"},
	{kind: sqliProbeBooleanFalse, payload: "' AND '1'='2"},
	{kind: sqliProbeOrderTrue, payload: "' ORDER BY 1--"},
	{kind: sqliProbeOrderFalse, payload: "' ORDER BY 999--"},
	{kind: sqliProbeError, payload: "' UNION SELECT NULL--"},
}

var sqlInjectionErrorPatterns = [...]string{
	"(?i)syntax.*error",
	"(?i)unclosed.*quote",
	"(?i)SQL.*warning",
	"(?i)mysql.*fetch",
	"(?i)ORA-[0-9]+",
	"(?i)Microsoft.*ODBC",
	"(?i)PostgreSQL.*ERROR",
	"(?i)SQLite.*error",
}

var sqlInjectionErrorRE = regexp.MustCompile(`(?i)(syntax.*error|unclosed.*quote|sql.*warning|mysql.*fetch|ORA-[0-9]+|Microsoft.*ODBC|PostgreSQL.*ERROR|SQLite.*error)`)

// SQLiCoverage describes which Java evidence classes this Go port can execute.
// Unsupported capabilities are named so reports cannot turn missing OOB or
// second-order work into a clean result.
type SQLiCoverage struct {
	DatabaseErrors     bool
	QuotePairs         bool
	BooleanDifferences bool
	OrderDifferences   bool
	OOBInteractions    bool
	SecondOrder        bool
	UnsupportedReasons []string
}

func SQLiCoverageReport() SQLiCoverage {
	return SQLiCoverage{
		DatabaseErrors:     true,
		QuotePairs:         true,
		BooleanDifferences: true,
		OrderDifferences:   true,
		UnsupportedReasons: []string{
			"Collaborator/OAST-backed Oracle, MSSQL, and MySQL probes require an external interaction channel",
			"SQL injection (second order) requires a stored-exchange follow-up producer",
		},
	}
}

// SQLiEvidence mirrors the observable result classes in Java's Zh6 evaluator.
// OOB bits are intentionally absent: without a Collaborator/OAST channel, Go
// must report that capability as unsupported rather than infer a clean result.
type SQLiEvidence uint16

const (
	SQLiEvidenceDatabaseError SQLiEvidence = 1 << iota
	SQLiEvidenceQuotePair
	SQLiEvidenceBooleanDifference
	SQLiEvidenceOrderDifference
)

// analyzeSQLiEvidence classifies response evidence without network or storage
// access, making the Java-derived decision table independently testable.
func analyzeSQLiEvidence(_ string, observations map[sqlInjectionProbeKind]string, errorMatch func(string) bool) SQLiEvidence {
	var evidence SQLiEvidence
	quote, quoteOK := observations[sqliProbeQuote]
	escaped, escapedOK := observations[sqliProbeEscapedQuote]
	if quoteOK && errorMatch(quote) {
		evidence |= SQLiEvidenceDatabaseError
		if escapedOK && !errorMatch(escaped) {
			evidence |= SQLiEvidenceQuotePair
		}
	}
	if trueBody, ok := observations[sqliProbeBooleanTrue]; ok {
		if falseBody, ok := observations[sqliProbeBooleanFalse]; ok && responsesDiffer(trueBody, falseBody) {
			evidence |= SQLiEvidenceBooleanDifference
		}
	}
	if trueBody, ok := observations[sqliProbeOrderTrue]; ok {
		if falseBody, ok := observations[sqliProbeOrderFalse]; ok && responsesDiffer(trueBody, falseBody) {
			evidence |= SQLiEvidenceOrderDifference
		}
	}
	for kind, body := range observations {
		switch kind {
		case sqliProbeQuote, sqliProbeEscapedQuote, sqliProbeBooleanTrue, sqliProbeBooleanFalse, sqliProbeOrderTrue, sqliProbeOrderFalse:
			continue
		}
		if errorMatch(body) {
			evidence |= SQLiEvidenceDatabaseError
		}
	}
	return evidence
}

func responsesDiffer(left, right string) bool {
	if left == right {
		return false
	}
	// Java warns that difference checks are heuristic. Requiring a meaningful
	// byte difference avoids flagging transport formatting noise.
	return strings.TrimSpace(left) != strings.TrimSpace(right)
}

func sqlInjectionEvidenceText(evidence SQLiEvidence) string {
	parts := make([]string, 0, 3)
	if evidence&SQLiEvidenceDatabaseError != 0 {
		parts = append(parts, "database error response")
	}
	if evidence&SQLiEvidenceQuotePair != 0 {
		parts = append(parts, "single-quote error cleared by escaped quote")
	}
	if evidence&SQLiEvidenceBooleanDifference != 0 {
		parts = append(parts, "boolean true/false response difference")
	}
	if evidence&SQLiEvidenceOrderDifference != 0 {
		parts = append(parts, "ORDER BY response difference")
	}
	return strings.Join(parts, "; ")
}
