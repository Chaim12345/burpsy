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
// and Oracle timing payloads are not. Those two, and SQLite, IBM DB2, H2 and HSQLDB, are sent
// from burpsy's OWN documented forms in sqli_timing_dialects.go (burpsy-react-ui-v0ei.1), which is
// also where the evidence rule every timing family is confirmed under lives. They are labelled as
// burpsy's, not as recovered bytes; MySQL specific and Oracle specific gate their families.
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
	mathrand "math/rand/v2"
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

// sqlBooleanShape is one place to put a condition: render(l, r) spells the condition `l = r` in
// that place, so render(a, a) is the always-true half and render(a, b) the always-false one. A
// shape renders any operands, which is what lets the confirmation ask the same question a second
// time with operands the first pair never used (sqlBooleanProbe).
type sqlBooleanShape struct {
	render func(l, r string) string
	// widening marks an `or` shape (sqlOrBooleanShapes): its differential runs the other way.
	widening bool
}

// pair renders the shape's documented first pair, 1=1 / 1=2.
func (s sqlBooleanShape) pair() [2]string { return [2]string{s.render("1", "1"), s.render("1", "2")} }

// contextShape places the condition between a recovered prefix and suffix. When the suffix
// comments the rest of the statement out, a `'` is appended — a `--` inside a still-open quote
// would turn the probe into a syntax error instead of a condition.
func contextShape(prefix, suffix string) sqlBooleanShape {
	return sqlBooleanShape{render: func(l, r string) string {
		out := prefix + l + "=" + r + suffix
		if strings.Contains(suffix, "--") {
			out += "'"
		}
		return out
	}}
}

// formatShape spells the condition with a format whose %[1]s and %[2]s are the operands.
func formatShape(format string, widening bool) sqlBooleanShape {
	return sqlBooleanShape{widening: widening, render: func(l, r string) string { return fmt.Sprintf(format, l, r) }}
}

// sqlQuotedBooleanFormats are the quote-opening shapes for a value that sits inside a string
// literal (burpsy's own, the standard forms): the payload closes the application's quote, adds the
// condition, and leaves the application's own closing quote to finish the last literal. Appended
// to the original value — `seed' and '1'='1` — so the literal before the condition is still the
// value the application expected.
var sqlQuotedBooleanFormats = []string{
	"' and '%[1]s'='%[2]s",
	"' and %[1]s=%[2]s-- ",
	`" and "%[1]s"="%[2]s`,
	"') and ('%[1]s'='%[2]s",
	// A value inside a LIKE pattern, `LIKE '%seed%'` (reused from the branch's faf10117): the
	// application's own wildcard and quote follow the payload, so the condition's last literal has
	// to absorb a `%` too — `'1%'='1%'` is true, where the plain shape above renders `'1'='1%'`,
	// false in both halves, and reads as a clean answer.
	"%%' and '%[1]s%%'='%[2]s",
	`%%" and "%[1]s%%"="%[2]s`,
	// Deeper nesting than the single `')` above: close the literal and every paren the application
	// opened, then comment out the rest (the standard spellings of sqlmap's `')` / `'))` boundaries).
	"') and %[1]s=%[2]s-- ",
	"')) and %[1]s=%[2]s-- ",
	"')) and (('%[1]s'='%[2]s",
}

// sqlOrBooleanFormats widen the WHERE clause instead of narrowing it, for the statement whose
// baseline matched nothing — a failed login, a lookup of an unknown id. There an `and` pair can
// only leave "nothing" unchanged in both halves, while `or 1=1` turns it into "everything" and
// `or 1=2` leaves it as it was. The differential is inverted: the false half keeps the baseline and
// the true half changes it. So is the risk: on an UPDATE or DELETE, `or 1=1` widens the write to
// every row. These shapes are therefore sent only under check_sqli_or_boolean (off by default).
var sqlOrBooleanFormats = []string{
	"' or %[1]s=%[2]s-- ",
	`" or %[1]s=%[2]s-- `,
	"') or %[1]s=%[2]s-- ",
	" or %[1]s=%[2]s-- ",
}

// sqlBooleanShapes is every narrowing shape, in the order they are tried: the recovered contexts
// first, then the quoted ones.
func sqlBooleanShapes() []sqlBooleanShape {
	out := make([]sqlBooleanShape, 0, len(sqlBooleanContexts)+len(sqlQuotedBooleanFormats))
	for _, ctx := range sqlBooleanContexts {
		out = append(out, contextShape(ctx[0], ctx[1]))
	}
	for _, f := range sqlQuotedBooleanFormats {
		out = append(out, formatShape(f, false))
	}
	return out
}

// sqlOrBooleanShapes is every widening shape.
func sqlOrBooleanShapes() []sqlBooleanShape {
	out := make([]sqlBooleanShape, 0, len(sqlOrBooleanFormats))
	for _, f := range sqlOrBooleanFormats {
		out = append(out, formatShape(f, true))
	}
	return out
}

// sqlBooleanPayloads renders the always-true / always-false pair for each narrowing shape.
//
// The condition cores are the documented standard forms; see the file header for why they are
// labelled rather than claimed as recovered.
func sqlBooleanPayloads() [][2]string {
	shapes := sqlBooleanShapes()
	out := make([][2]string, 0, len(shapes))
	for _, s := range shapes {
		out = append(out, s.pair())
	}
	return out
}

// orBooleanEnabled reports whether the run admits the widening `or` shapes.
func orBooleanEnabled(h *ProbeHarness) bool {
	return h != nil && h.scanner != nil && h.scanner.config != nil && h.scanner.config.CheckSqliOrBoolean
}

// sqlTimingPayload is one dialect's delay probe in one place: the first probe's text, how to spell
// it for another delay value, every Burp detection method that gates it, and what a confirmed delay
// may be attributed to.
type sqlTimingPayload struct {
	payload string
	// render spells the probe for a delay value: seconds for a sleep family, work units for a heavy
	// one. render(0) is a sleep family's zero-delay control; a heavy family never renders 0 (see
	// sqlTimingProbe: its control is a handful of units, and every heavy value carries a unique offset).
	render  func(n int64) string
	methods []string
	// dbms names the engine whose own syntax the delay primitive is; primitive names it.
	dbms, primitive string
	// context is the quoting context (or, for a recovered form, the recovered break) it is placed in.
	context string
	// heavy marks a work-unit family, admitted only under ScanConfig.CheckSqliHeavyQuery.
	heavy     bool
	probeSize int64
	// foreign spells the same place with another engine's sleep, the attribution control.
	foreign func(seconds int64) string
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
	seconds := delaySeconds(delay)
	pgMethods := []string{MethodTimeDelays, MethodPostgreSQLSpecific}
	mssqlMethods := []string{MethodTimeDelays, MethodSQLServerSpecific}
	form := func(prefix, call, dbms, primitive string, methods []string) sqlTimingPayload {
		render := func(n int64) string { return prefix + fmt.Sprintf(call, n) }
		// The attribution control keeps the recovered break and swaps the call for MySQL's SLEEP.
		foreign := func(n int64) string { return prefix + mysqlSleepExpr(n) + "--" }
		return sqlTimingPayload{payload: render(seconds), render: render, methods: methods,
			dbms: dbms, primitive: primitive, context: fmt.Sprintf("recovered break %q", prefix), foreign: foreign}
	}

	var out []sqlTimingPayload
	// PostgreSQL (Zxpy): every recovered break ahead of the sleep call, each with its quoted
	// form — Zxpy builds `break+pg_sleep(%%)--` and `'break+pg_sleep(%%)--` per prefix.
	for _, brk := range []string{"||", " AND ", ",''||"} {
		out = append(out,
			form(brk, "pg_sleep(%d)--", "PostgreSQL", "pg_sleep", pgMethods),
			form("'"+brk, "pg_sleep(%d)--", "PostgreSQL", "pg_sleep", pgMethods),
		)
	}
	// SQL Server (Zuyg): every recovered break ahead of waitfor, same two forms per prefix.
	for _, brk := range []string{" ", ")", ",0)", ",0,0)", ",0,0,0)"} {
		out = append(out,
			form(brk, "waitfor delay'0:0:%d'--", "Microsoft SQL Server", "WAITFOR DELAY", mssqlMethods),
			form("'"+brk, "waitfor delay'0:0:%d'--", "Microsoft SQL Server", "WAITFOR DELAY", mssqlMethods),
		)
	}
	return out
}

// blindInjectionPointProbes is the per-point body of the SQL-injection check's blind half: the
// boolean pairs first (cheapest, one request each), then the timing probes — the two dialects'
// recovered forms, then burpsy's own per-dialect families (sqli_timing_dialects.go; the heavy-query
// ones only under check_sqli_heavy_query). The order matters for cost, not for truth: both banks
// are sent PROGRESSIVELY, stopping at the first pair or delay whose evidence confirms — or, for
// timing, at the first delay shown to follow a foreign dialect's sleep spelling too, which no
// further family can attribute either. That is the same rule runInjection applies
// between points ("further payloads cost requests and add nothing to a proven finding"), applied
// inside the point, because the runInjection driver builds a point's whole list before it ever
// looks at the evidence. Without the early stop a timing-vulnerable endpoint is billed one
// 5-second sleep per payload form, and a boolean-vulnerable one three further pairs
// that ask the same question in a different break style.
//
// The three banks all go through per-technique gates at the probe (error probes inside
// ProbeErrorSignatures, boolean inside sqlBooleanProbe, timing inside sqlTimingProbe), so a
// method-disabled family is WITHHELD and counted here, in exactly one shared insertion-point
// walk — one enumeration, one coverage line, one effectiveness prior per point (any of which
// would have been tripled by three separate checks of the same type).
func blindInjectionPointProbes(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
	probes := booleanPointProbes(ctx, h, p)
	if ctx.Err() != nil {
		return probes
	}
	// A baseline already slow relative to the delay makes every timing probe undecidable; one
	// probe says so instead of sixteen requests each waiting to learn it.
	if h.baseline.Duration >= time.Duration(float64(InjectionTimingDelay)*TimingBaselineNoiseCeiling) {
		return append(probes, InjectionProbe{Payload: "time delays", Evidence: InjectionEvidenceInconclusive,
			Detail: fmt.Sprintf("%s %q: the baseline took %s, too close to the %s delay for a delay to be told apart; no timing probe sent",
				p.Kind, p.Name, h.baseline.Duration, InjectionTimingDelay)})
	}
	heavy := heavyQueryTimingEnabled(h)
	for _, tp := range append(sqlTimingPayloads(InjectionTimingDelay), sqlDialectDelayPayloads(InjectionTimingDelay)...) {
		if ctx.Err() != nil {
			return probes
		}
		if tp.heavy && !heavy {
			continue // heavy-query families are an opt-in (check_sqli_heavy_query)
		}
		pr, outcome := sqlTimingProbe(ctx, h, p, tp, InjectionTimingDelay)
		probes = append(probes, pr)
		if pr.Evidence == InjectionEvidenceTiming || outcome.notAttributable {
			// Proven, or shown to follow any dialect's sleep spelling: either way the further
			// families ask a question this point has already answered.
			break
		}
	}
	return probes
}

// booleanPointProbes runs the boolean technique at one point: the narrowing shapes, then (only
// under check_sqli_or_boolean) the widening ones, stopping at the first confirmed differential.
//
// One extra request per point is spent before any pair: a second fetch of the unmodified request,
// from which the page's dynamic regions are learned (sqli_boolean_compare.go). A page whose two
// baselines are not alike even with those regions removed cannot be judged, and is reported
// undecided in one probe instead of fifteen pairs each failing to learn it.
func booleanPointProbes(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
	shapes := sqlBooleanShapes()
	if orBooleanEnabled(h) {
		shapes = append(shapes, sqlOrBooleanShapes()...)
	}
	var probes []InjectionProbe
	var cmp *booleanComparator
	for _, shape := range shapes {
		if ctx.Err() != nil {
			return probes
		}
		pair := shape.pair()
		label := pair[0] + " / " + pair[1]
		if h.withhold(MethodBooleanConditions, 2) {
			probes = append(probes, withheldProbe(p, label, MethodBooleanConditions))
			continue
		}
		if cmp == nil {
			again, err := h.SendAppending(ctx, p, "")
			if err != nil {
				return append(probes, InjectionProbe{Payload: label, Evidence: InjectionEvidenceInconclusive,
					Detail: fmt.Sprintf("%s %q: boolean probe not completed: the baseline re-fetch failed: %v", p.Kind, p.Name, err)})
			}
			cmp = newBooleanComparator(h.baseline.Status, h.baseline.Body, again.Status, again.Body)
			if !cmp.stable() {
				return append(probes, InjectionProbe{Payload: "boolean conditions", Evidence: InjectionEvidenceInconclusive,
					Detail: fmt.Sprintf("%s %q: two fetches of the unmodified request are only %.2f alike even with "+
						"%d dynamic region(s) removed, so a condition's effect cannot be told from the page's own "+
						"variation; no boolean pair sent", p.Kind, p.Name, cmp.stability, len(cmp.regions))})
			}
		}
		pr := sqlBooleanProbe(ctx, h, p, shape, cmp)
		probes = append(probes, pr)
		if pr.Evidence == InjectionEvidenceBooleanDifferential {
			break // a proven differential; the further shapes ask the same question
		}
	}
	return probes
}

// sqlBooleanProbe sends one always-true / always-false pair appended to the point's value, and
// confirms a differential before reporting it (review of saq3.2.1; v0ei.4). One pair can differ by
// chance — a rate limit, a rotating banner, a session that expired between the two requests — and a
// page can react to the literal text `1=2` rather than to its truth, so a differential stands only
// when, against a baseline re-fetched unchanged:
//
//   - the same pair repeats with the same verdict, and
//   - a second pair in the same shape with fresh operands (`4821=4821` / `4821=7302`) gives it too,
//   - and the three changed halves agree with each other.
//
// That costs five requests, and only on a positive. "Same" and "changed" are judged by cmp: the
// reflected payload and the learned dynamic regions removed, then exact or ratio comparison
// (sqli_boolean_compare.go).
//
// Both halves changing the response is a clean answer for SQL injection, not an undecided one: the
// payload was rejected or reflected, not interpreted, and a reflecting parameter would otherwise
// never count as clean for the light-audit tier or the effectiveness prior.
//
// A widening (`or`) shape's differential runs the other way: the always-false half keeps the
// baseline and the always-true half changes it. Its true half answering 5xx is a broken query, not
// a wider match, and does not count.
func sqlBooleanProbe(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint, shape sqlBooleanShape,
	cmp *booleanComparator) InjectionProbe {
	pair := shape.pair()
	out := InjectionProbe{Payload: pair[0] + " / " + pair[1]}
	fetch := func(payload string) (booleanPage, error) {
		resp, err := h.SendAppending(ctx, p, payload)
		if err != nil {
			return booleanPage{}, err
		}
		return cmp.page(resp.Status, resp.Body, payload), nil
	}
	// keepChange orders a pair's halves as (the one that must stay the baseline, the one that must
	// not) for this shape's direction.
	keepChange := func(t, f booleanPage) (booleanPage, booleanPage) {
		if shape.widening {
			return f, t
		}
		return t, f
	}
	t1, err := fetch(pair[0])
	var f1 booleanPage
	if err == nil {
		f1, err = fetch(pair[1])
	}
	if err != nil {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s %q: boolean probe not completed: %v", p.Kind, p.Name, err)
		return out
	}
	keep1, change1 := keepChange(t1, f1)
	keeps, changes := cmp.sameAsBase(keep1), cmp.sameAsBase(change1)
	switch {
	case keeps && !changes && !(shape.widening && change1.status >= 500):
	case !keeps && !changes:
		out.Evidence = InjectionEvidenceNone
		out.Detail = fmt.Sprintf("%s %q: both halves changed the response, so the condition was not interpreted", p.Kind, p.Name)
		return out
	default:
		out.Evidence = InjectionEvidenceNone
		out.Detail = fmt.Sprintf("%s %q: %s", p.Kind, p.Name, InjectionEvidenceNone)
		return out
	}

	// The confirmation: the baseline again, the same pair again, and a fresh-operand pair.
	l, r := booleanOperands()
	second := [2]string{shape.render(l, l), shape.render(l, r)}
	base2, err := fetch("")
	var t2, f2, t3, f3 booleanPage
	if err == nil {
		if t2, err = fetch(pair[0]); err == nil {
			if f2, err = fetch(pair[1]); err == nil {
				if t3, err = fetch(second[0]); err == nil {
					f3, err = fetch(second[1])
				}
			}
		}
	}
	if err != nil {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s %q: a differential appeared and its confirmation could not be completed: %v", p.Kind, p.Name, err)
		return out
	}
	keep2, change2 := keepChange(t2, f2)
	keep3, change3 := keepChange(t3, f3)
	if !confirmBooleanPages(cmp, base2, []booleanPage{keep1, keep2, keep3}, []booleanPage{change1, change2, change3}, shape.widening) {
		out.Evidence = InjectionEvidenceNone
		out.Detail = fmt.Sprintf("%s %q: a differential appeared once and did not repeat, with the same and with fresh operands, against a stable baseline", p.Kind, p.Name)
		return out
	}
	out.Payload += " ; " + second[0] + " / " + second[1]
	out.Evidence = InjectionEvidenceBooleanDifferential
	verb := "always-true kept the response and always-false changed it"
	if shape.widening {
		verb = "an always-false `or` kept the response and an always-true `or` widened it"
	}
	out.Detail = fmt.Sprintf("%s %q: %s, twice, and again with fresh operands, against a stable baseline "+
		"(similarity to the baseline %.2f kept vs %.2f changed; reflected payload and %d dynamic region(s) removed before comparing)",
		p.Kind, p.Name, verb, similarity(cmp.base, keep1), similarity(cmp.base, change1), len(cmp.regions))
	return out
}

// confirmBooleanPages is the repeat rule: the re-fetched baseline is the baseline, every half that
// must keep the page keeps it, every half that must change it changes it, and the changed halves
// agree with each other — one differential, seen three times, not three different accidents. A
// widening shape's changed halves must not be server errors.
func confirmBooleanPages(cmp *booleanComparator, base2 booleanPage, keeps, changes []booleanPage, widening bool) bool {
	if !cmp.sameAsBase(base2) {
		return false
	}
	for _, k := range keeps {
		if !cmp.sameAsBase(k) {
			return false
		}
	}
	for _, c := range changes {
		if cmp.sameAsBase(c) || (widening && c.status >= 500) {
			return false
		}
		if !cmp.alike(changes[0], c) {
			return false
		}
	}
	return true
}

// booleanOperands returns two distinct four-digit operands for a fresh pair. They are drawn from the
// digits 3-9 only, so neither half of the fresh pair contains any text of the documented 1=1 / 1=2
// pair (`4831=2...` would spell `1=2` again): a page keyed on the documented spelling cannot react
// to the fresh pair by coincidence.
func booleanOperands() (string, string) {
	draw := func() string {
		b := make([]byte, 4)
		for i := range b {
			b[i] = byte('3' + mathrand.IntN(7))
		}
		return string(b)
	}
	l, r := draw(), draw()
	for r == l {
		r = draw()
	}
	return l, r
}
