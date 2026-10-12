package scanner

// The statement-echo technique for SQL injection (burpsy-react-ui-j1mk.36).
//
// The quote probes (sqlErrorProbePayloads) prove injection by unbalancing a literal: a syntax
// error that only a quote produces. An application that strips quotes before concatenating, or
// that wraps a numeric column in a quoted literal, never yields that error, and the boolean and
// timing probes cannot get past the stripped quote either. What such an application often still
// does is relay the database's own exception, and many drivers and frameworks put the failing
// statement's TEXT in that exception (H2's "SQL statement: ...", Spring's "SQL [...]", PostgreSQL's
// "STATEMENT: ...", MySQL's "... near '...' at line 1").
//
// That text is the proof. A bound parameter never appears in the statement text - a parameterised
// query fails with "where id=?" or "where id=$1" - so a fresh marker that comes back INSIDE the
// statement, after the SQL verb that opens it, can only be there because the value was
// concatenated into the SQL the database parsed. The error signature alone is not enough and is
// deliberately not used alone: a type-conversion error ("Data conversion error", "invalid input
// syntax for type integer") is exactly what a correctly parameterised query raises when it is
// handed a non-numeric value for a numeric column.
//
// Evidence rule, all of which must hold:
//   - the response to a fresh marker appended to the original value carries a database error
//     signature the baseline (the original value, the fixed control) does not;
//   - the marker appears inside echoed statement text: after a SQL verb (select/insert/update/
//     delete/merge) and a clause keyword (from/into/set/where), on the same statement line;
//   - a second, independent marker reproduces both.
//
// Confidence is tentative. The probe proves concatenation, not that the query's shape can be
// changed: a filter may still stand between the value and a working payload, and the finding
// says so rather than claiming a demonstrated exploit.

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// sqlEngineErrorSignatures are database error wordings beyond burp.Ze2s's recovered bank: the
// type-conversion and syntax messages of H2, PostgreSQL, SQL Server, MySQL and SQLite, and the
// JDBC/Spring/PDO wrappers that relay them. burpsy's own; each is the engine's documented text.
// They are used ONLY by the statement-echo rule, never as a standalone signature: a conversion
// error is what a parameterised query raises too.
var sqlEngineErrorSignatures = []string{
	"Data conversion error converting",
	"Syntax error in SQL statement",
	"JdbcSQLDataException",
	"JdbcSQLSyntaxErrorException",
	"SQLSyntaxErrorException",
	"SQLDataException",
	"bad SQL grammar",
	"invalid input syntax for type",
	"invalid input syntax for integer",
	"Conversion failed when converting",
	"Truncated incorrect",
	"SQLSTATE[",
	"SQLITE_ERROR",
	"sqlite3.OperationalError",
	"datatype mismatch",
}

// sqlStatementVerb opens an echoed statement; sqlStatementClause must follow it before the marker.
// Both are matched on one line with no statement terminator between them and the marker, so a
// marker quoted elsewhere in the error ("converting \"1x\"; SQL statement: select ... id=?") does
// not count: there the marker precedes the statement, and the statement holds a placeholder.
var (
	sqlStatementVerb   = regexp.MustCompile(`(?i)\b(?:select|insert|update|delete|merge)\b`)
	sqlStatementClause = regexp.MustCompile(`(?i)\b(?:from|into|set|where)\b`)
)

// sqlStatementEchoes reports whether body holds echoed SQL statement text with marker inside it.
func sqlStatementEchoes(body, marker string) bool {
	m := strings.ToLower(marker)
	for _, form := range matchableForms(body) {
		for _, line := range strings.Split(form, "\n") {
			at := strings.Index(line, m)
			for at >= 0 {
				head := line[:at]
				// The statement the marker sits in starts after the last terminator before it.
				if i := strings.LastIndexByte(head, ';'); i >= 0 {
					head = head[i+1:]
				}
				if loc := sqlStatementVerb.FindStringIndex(head); loc != nil &&
					sqlStatementClause.MatchString(head[loc[1]:]) {
					return true
				}
				next := strings.Index(line[at+len(m):], m)
				if next < 0 {
					break
				}
				at += len(m) + next
			}
		}
	}
	return false
}

// sqlDatabaseErrorIntroduced returns the first database error signature in injected that the
// baseline does not carry.
func sqlDatabaseErrorIntroduced(baseline, injected string) (string, bool) {
	signatures := make([]string, 0, len(SQLErrorSignatures)+len(sqlEngineErrorSignatures))
	signatures = append(signatures, SQLErrorSignatures...)
	signatures = append(signatures, sqlEngineErrorSignatures...)
	ev := ClassifyErrorEvidence(baseline, injected, signatures)
	if ev.Evidence != InjectionEvidenceErrorSignature {
		return "", false
	}
	return ev.Matched[0], true
}

// sqlStatementEchoProbe sends a fresh marker appended to the point's value and, on a hit, a second
// independent one. It is an error-message technique and passes the same method gate.
func sqlStatementEchoProbe(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint) InjectionProbe {
	first := newProbeCanary("zq")
	out := InjectionProbe{Payload: first}
	if h.withhold(MethodErrorMessages, 1) {
		return withheldProbe(p, first, MethodErrorMessages)
	}
	try := func(marker string) (string, bool, error) {
		resp, err := h.SendAppending(ctx, p, marker)
		if err != nil {
			return "", false, err
		}
		sig, introduced := sqlDatabaseErrorIntroduced(h.baseline.Body, resp.Body)
		if !introduced || strings.Contains(strings.ToLower(h.baseline.Body), strings.ToLower(marker)) {
			return "", false, nil
		}
		return sig, sqlStatementEchoes(resp.Body, marker), nil
	}
	sig, echoed, err := try(first)
	if err != nil {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s %q: probe not sent: %v", p.Kind, p.Name, err)
		return out
	}
	if !echoed {
		out.Evidence = InjectionEvidenceNone
		out.Detail = fmt.Sprintf("%s %q: no database error echoing the value inside statement text", p.Kind, p.Name)
		return out
	}
	second := newProbeCanary("zq")
	sig2, echoed2, err := try(second)
	if err != nil || !echoed2 {
		// Something produced the echo once; that is undecided, not clean.
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s %q: the statement echo appeared once (%q) and did not reproduce with a second marker",
			p.Kind, p.Name, sig)
		return out
	}
	out.Payload = first + " / " + second
	out.Evidence = InjectionEvidenceErrorSignature
	out.Tentative = true
	out.Detail = fmt.Sprintf("%s %q: two independent markers each produced a database error (%q, %q) absent from the "+
		"baseline, and each came back inside the failing SQL statement's own text, so the value is concatenated "+
		"into the query rather than bound; changing the query's structure was not demonstrated",
		p.Kind, p.Name, sig, sig2)
	return out
}
