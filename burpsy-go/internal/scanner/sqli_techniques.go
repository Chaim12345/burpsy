package scanner

// The blind-SQLi technique families Burp switches as detection methods for the SQL-injection
// issue type (burpsy-react-ui-saq3.2.1): boolean conditions and time delays.
//
// # What is recovered and what is documented
//
// The probe builders Burp itself uses are burp.Zm4e (boolean) and burp.Zxpy / burp.Zuyg
// (PostgreSQL and SQL Server timing). Their STRUCTURE decompiles cleanly and is transcribed
// below: which context breaks each dialect uses and how the quoted forms are wrapped. The
// boolean condition cores (`1=1` / `1=2`) live inside ZKM string decoders this tree does not
// run, so those literals are the documented standard forms rather than recovered bytes — the
// same convention templateArithmeticPayloads applies to SSTI delimiters. The timing payload
// TEXTS (`pg_sleep(%%)--`, `waitfor delay'0:0:%%'--`) ARE recovered plaintext from Zxpy/Zuyg;
// the context breaks ahead of them are recovered too (Ze2s's ZQ for PostgreSQL, ZM/Zv/Zd for
// SQL Server, ZX/ZO/ZD/ZG for the boolean pairs).
//
// # Which dialects, honestly
//
// Only PostgreSQL and SQL Server timing banks are recoverable in the decompile; Burp's MySQL
// and Oracle timing payloads are not, so burpsy sends none. The selection layer already says
// so: MySQL specific and Oracle specific stay in the declined list with their reason, and a
// run that enables them is told burpsy will not run them rather than quietly pretending.
//
// # How each family is gated
//
// The techniques live INSIDE the one SQL-injection check (blindSQLProbes), and every probe passes
// the harness's method gate (2hze): the error bank under "Error messages", ProbeBoolean under
// "Boolean conditions", and the timing probes under "Time delays" AND their dialect method — a
// PostgreSQL probe is withheld when either PostgreSQL specific or Time delays is disabled, because
// Burp's UI offers both switches over the same request. Nothing here is gated at the descriptor:
// the check declares all five implemented methods (burpsyDetectionMethods), and Burp's own rule
// (Zwy6.java:36-75) keeps it dispatched while ANY declared method is still enabled — withholding
// it whole would also have withheld the error probes an operator left on. The gate's declines are
// counted in the item's methods_declined, which is the same record a descriptor-level withholding
// would have produced, at the granularity of the exact technique instead.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// sqlBooleanContexts are the prefix/suffix pairs that place a boolean condition in the
// statement around the insertion point, transcribed from burp.Ze2s's ZX/ZO/ZD/ZG pair banks.
//
// A pair's first element is the break that closes whatever the application put around the
// value; the second terminates the rest of the original statement. The same pair carries both
// the always-true and the always-false form, because the classifier needs the two halves to
// differ only in the condition.
var sqlBooleanContexts = [][2]string{
	{"", ""},          // the value sits bare in the statement
	{" and ", "-- "},  // append a condition, comment out the rest
	{")and ", "-- "},  // close one paren the application opened, then append
	{"))and ", "-- "}, // close two
	{"||", "||"},      // string concatenation (PostgreSQL/Oracle quoting)
	{",", ""},         // a further argument: the condition becomes a new expression
}

// sqlBooleanPayloads renders the always-true / always-false pair for each context.
//
// The condition cores are the documented standard forms; see the file header for why they are
// labelled rather than claimed as recovered. Rendering mirrors Zm4e's composition: prefix
// before the core, suffix after, and a `'` appended when the suffix comments the rest of the
// statement out — a `--` inside a still-open quote would turn the probe into a syntax error
// instead of a condition, and the classifier needs the pair to differ only in the condition.
func sqlBooleanPayloads() [][2]string {
	out := make([][2]string, 0, len(sqlBooleanContexts))
	for _, ctx := range sqlBooleanContexts {
		trueCore := ctx[0] + "1=1" + ctx[1]
		falseCore := ctx[0] + "1=2" + ctx[1]
		if strings.Contains(ctx[1], "--") {
			trueCore += "'"
			falseCore += "'"
		}
		out = append(out, [2]string{trueCore, falseCore})
	}
	return out
}

// sqlTimingPayload is one dialect's delay probe: the payload text with the delay already
// substituted, and every Burp detection method that gates it.
type sqlTimingPayload struct {
	payload string
	methods []string
}

// sqlTimingPayloads renders the time-based probes for the recoverable dialects.
//
// PostgreSQL (Zxpy): breaks `||`, ` AND `, `,”||` ahead of pg_sleep, the delay in seconds, a
// `--` terminator; the quoted form opens with a `'` the application's own close finishes.
// SQL Server (Zuyg): breaks `" "`, `")"`, `",0)"`, `",0,0)"`, `",0,0,0)"` ahead of
// waitfor delay. The delay is `0:0:S` — Burp's own spelling — because WAITFOR DELAY takes an
// h:m:s literal, not an expression, and a probe that cannot parse cannot sleep.
//
// The break between the application's value and the sleep call is what makes the payload
// injectable rather than a syntax error: `1 pg_sleep(5)` is nothing, `1 AND pg_sleep(5)` is a
// boolean AND, `'1',”||pg_sleep(5)` concatenates a sleeping expression into a string list.
// Burp sends one form per break it recovered for the dialect; the same set is sent here.
func sqlTimingPayloads(delay time.Duration) []sqlTimingPayload {
	seconds := int(delay.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	pg := fmt.Sprintf("pg_sleep(%d)--", seconds)
	mssql := fmt.Sprintf("waitfor delay'0:0:%d'--", seconds)
	pgMethods := []string{MethodTimeDelays, MethodPostgreSQLSpecific}
	mssqlMethods := []string{MethodTimeDelays, MethodSQLServerSpecific}

	var out []sqlTimingPayload
	// PostgreSQL (Zxpy): every recovered break ahead of the sleep call, each with its quoted
	// form — Zxpy builds `break+pg_sleep(%%)--` and `'break+pg_sleep(%%)--` per prefix.
	for _, brk := range []string{"||", " AND ", ",''||"} {
		body := brk + pg
		out = append(out,
			sqlTimingPayload{payload: body, methods: pgMethods},
			sqlTimingPayload{payload: "'" + body, methods: pgMethods},
		)
	}
	// SQL Server (Zuyg): every recovered break ahead of waitfor, same two forms per prefix.
	for _, brk := range []string{" ", ")", ",0)", ",0,0)", ",0,0,0)"} {
		body := brk + mssql
		out = append(out,
			sqlTimingPayload{payload: body, methods: mssqlMethods},
			sqlTimingPayload{payload: "'" + body, methods: mssqlMethods},
		)
	}
	return out
}

// blindInjectionPointProbes is the per-point body of the SQL-injection check's blind half: the
// boolean pairs first (cheapest, one request each), then the timing probes — the two dialects'
// recovered forms. The order matters for cost, not for truth: both banks are sent PROGRESSIVELY,
// stopping at the first pair or delay whose evidence confirms — the same rule runInjection applies
// between points ("further payloads cost requests and add nothing to a proven finding"), applied
// inside the point, because the runInjection driver builds a point's whole list before it ever
// looks at the evidence. Without the early stop a timing-vulnerable endpoint is billed one
// 5-second sleep per payload form (16 here), and a boolean-vulnerable one three further pairs
// that ask the same question in a different break style.
//
// The three banks all go through per-technique gates at the probe (error probes inside
// ProbeErrorSignatures, boolean inside ProbeBoolean, timing inside ProbeTimingUnder), so a
// method-disabled family is WITHHELD and counted here, in exactly one shared insertion-point
// walk — one enumeration, one coverage line, one effectiveness prior per point (any of which
// would have been tripled by three separate checks of the same type).
func blindInjectionPointProbes(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
	var probes []InjectionProbe
	for _, pair := range sqlBooleanPayloads() {
		pr := h.ProbeBoolean(ctx, p, pair[0], pair[1])
		probes = append(probes, pr)
		if pr.Evidence == InjectionEvidenceBooleanDifferential {
			break // a proven differential; the further break styles ask the same question
		}
	}
	for _, tp := range sqlTimingPayloads(InjectionTimingDelay) {
		pr := h.ProbeTimingUnder(ctx, p, tp.payload, InjectionTimingDelay, tp.methods)
		probes = append(probes, pr)
		if pr.Evidence == InjectionEvidenceTiming {
			break // the delay is proven; the further break styles ask the same question
		}
	}
	return probes
}
