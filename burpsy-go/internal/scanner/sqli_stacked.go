package scanner

// Stacked queries (burpsy-react-ui-v0ei.5): sqlmap's technique S, reported only as a property of a
// SQL injection another technique has already proven.
//
// The probe terminates the application's statement and starts a second one that only waits:
// `;SELECT SLEEP(n)-- ` (MySQL/MariaDB), `;SELECT pg_sleep(n)-- ` (PostgreSQL), `;WAITFOR DELAY
// '0:0:n'-- ` (SQL Server). No other statement is ever stacked: the second statement reads nothing
// and writes nothing. The texts are burpsy's own documented forms, not recovered Burp bytes — Burp
// has no stacked-query method.
//
// The evidence rule is the one every timing family is held to (sqlTimingProbe in
// sqli_timing_dialects.go): a slow first probe, two zero-delay controls, two delay values whose
// excesses scale, a repeat, and a foreign-dialect control in the same place that must NOT delay.
// Each family is gated by Time delays and its dialect's method, exactly like the in-statement timing
// families, and the whole technique by ScanConfig.CheckSqliStacked (off by default): it is
// supplementary — it never makes a finding, only annotates one — and a confirming walk costs several
// multi-second sleeps.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// sqlStackedContexts close the application's value before the `;`.
var sqlStackedContexts = []sqlUnionContext{
	{"numeric", ""},
	{"single-quoted string", "'"},
	{"parenthesised numeric", ")"},
	{"parenthesised string", "')"},
}

func stackedMySQLSleep(n int64) string { return fmt.Sprintf(";SELECT SLEEP(%d)-- ", n) }
func stackedPgSleep(n int64) string    { return fmt.Sprintf(";SELECT pg_sleep(%d)-- ", n) }
func stackedWaitfor(n int64) string    { return fmt.Sprintf(";WAITFOR DELAY '0:0:%d'-- ", n) }

// sqlStackedPayloads renders every stacked family in every context, as timing payloads.
func sqlStackedPayloads(delay time.Duration) []sqlTimingPayload {
	seconds := delaySeconds(delay)
	families := []struct {
		dbms, primitive string
		stmt, foreign   func(int64) string
		methods         []string
	}{
		{"MySQL/MariaDB", "stacked SELECT SLEEP", stackedMySQLSleep, stackedPgSleep, []string{MethodTimeDelays, MethodMySQLSpecific}},
		{"PostgreSQL", "stacked SELECT pg_sleep", stackedPgSleep, stackedMySQLSleep, []string{MethodTimeDelays, MethodPostgreSQLSpecific}},
		{"Microsoft SQL Server", "stacked WAITFOR DELAY", stackedWaitfor, stackedMySQLSleep, []string{MethodTimeDelays, MethodSQLServerSpecific}},
	}
	var out []sqlTimingPayload
	for _, f := range families {
		for _, c := range sqlStackedContexts {
			f, c := f, c
			render := func(n int64) string { return c.prefix + f.stmt(n) }
			out = append(out, sqlTimingPayload{
				payload: render(seconds), render: render, methods: f.methods,
				dbms: f.dbms, primitive: f.primitive, context: c.name,
				foreign: func(n int64) string { return c.prefix + f.foreign(n) },
			})
		}
	}
	return out
}

// stackedQueriesEnabled reports whether the run admits the stacked-query probe.
func stackedQueriesEnabled(h *ProbeHarness) bool {
	return h != nil && h.scanner != nil && h.scanner.config != nil && h.scanner.config.CheckSqliStacked
}

// sqlStackedNote probes a point already proven injectable and returns one sentence for the finding:
// "stacked queries supported (...)" when a stacked sleep confirmed, otherwise what was and was not
// shown. It never produces evidence of its own.
func sqlStackedNote(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint) string {
	if h.baseline.Duration >= time.Duration(float64(InjectionTimingDelay)*TimingBaselineNoiseCeiling) {
		return fmt.Sprintf("Stacked queries: not probed — the baseline took %s, too close to the %s delay.", h.baseline.Duration, InjectionTimingDelay)
	}
	var sent, withheld, undecided int
	for _, tp := range sqlStackedPayloads(InjectionTimingDelay) {
		if ctx.Err() != nil {
			break
		}
		pr, outcome := sqlTimingProbe(ctx, h, p, tp, InjectionTimingDelay)
		switch {
		case pr.Withheld:
			withheld++
			continue
		case pr.Evidence == InjectionEvidenceTiming:
			return "Stacked queries supported: a second statement that only sleeps, terminated onto the application's own with `;`, " +
				"delayed the response under the timing evidence rule — " + strings.TrimSpace(pr.Detail) + "."
		case pr.Evidence == InjectionEvidenceInconclusive:
			undecided++
		}
		sent++
		if outcome.notAttributable {
			break
		}
	}
	return fmt.Sprintf("Stacked queries: not shown (%d stacked-sleep probe(s) sent, %d undecided, %d withheld by a disabled detection method).",
		sent, undecided, withheld)
}
