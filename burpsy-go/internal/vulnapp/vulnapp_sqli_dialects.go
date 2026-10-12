package vulnapp

// Time-based blind SQL injection, one endpoint per database dialect (burpsy-react-ui-v0ei.1).
//
// Each vulnerable endpoint concatenates its parameter into a statement for ONE simulated engine and
// answers with the same body whatever happened — rows, no rows, or a syntax error — so the response
// time is the only channel, and neither the error bank nor the boolean differential can see it. What
// the endpoint executes is decided by a small dialect-aware evaluator, not by matching any payload:
//
//   - the value is spliced into the statement and the clause is parsed: quotes and parentheses must
//     balance, conditions are joined by AND/OR, each is a comparison or `<n> <= (<expression>)`;
//   - every function the expression calls must exist in the engine (an unknown one is an error, the
//     way `pg_sleep` is an error on MySQL), and every schema-qualified object must be in its catalog;
//   - the delay comes from the engine's own primitive only — SLEEP or BENCHMARK on MySQL,
//     DBMS_PIPE.RECEIVE_MESSAGE or a ROWNUM-bounded join on Oracle, a recursive CTE on SQLite,
//     FETCH FIRST on DB2, SYSTEM_RANGE on H2, LIMIT on HSQLDB — at a per-engine work rate, capped.
//
// H2 answers an exact repeat of a statement from its result cache, which the simulation keeps too.
// HSQLDB's `LIMIT 0` is "no limit", which the simulation keeps: it costs the cap, the way the real
// engine runs an unbounded join (and the way a scanner that sent a zero-work control there would see
// its control come back slow).
//
// The safe twins: one answers at a constant slow pace whatever it is given; the other is a job
// runner whose step DSL honours a sleep directive in ANY spelling — it delays on sleep-shaped text
// but runs no SQL at all, so a scanner must not attribute that delay to a database.
//
// Nothing here opens a database; every delay is a bounded time.Sleep.

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dialectDelayCap bounds every simulated statement.
const dialectDelayCap = 6 * time.Second

func sqliDialectEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/ij/dialect/mysql/orders?id=7", Row: "SQL injection",
			Note: "MySQL: concatenates id into `WHERE id=<v>`; answers identically whatever happened, so only time tells"},
		{Path: "/ij/dialect/mysql-filtered/orders?id=7", Row: "SQL injection",
			Note: "MySQL behind a filter that rejects the word sleep: only a work-unit delay (BENCHMARK) reaches the engine"},
		{Path: "/ij/dialect/oracle/staff?name=seed", Row: "SQL injection",
			Note: "Oracle: concatenates name into `WHERE name='<v>'`"},
		{Path: "/ij/dialect/sqlite/notes?id=7", Row: "SQL injection",
			Note: "SQLite: concatenates id into `WHERE (id=<v>)`; SQLite has no sleep function"},
		{Path: "/ij/dialect/db2/ledger?sort=amount", Row: "SQL injection",
			Note: "IBM DB2: concatenates sort into `ORDER BY <v>`"},
		{Path: "/ij/dialect/h2/cars?id=1", Row: "SQL injection",
			Note: "H2: concatenates id into `WHERE id=<v>`; H2 has no sleep function"},
		{Path: "/ij/dialect/hsqldb/parts?code=seed", Row: "SQL injection",
			Note: "HSQLDB: concatenates code into `WHERE (code='<v>')`; HSQLDB has no sleep function"},

		{Path: "/ij/safe/dialect/slow?id=7", Row: "SQL injection", Safe: true,
			Note: "binds id and answers at a constant slow pace whatever it is given"},
		{Path: "/ij/safe/dialect/jobs?step=seed", Row: "SQL injection", Safe: true,
			Note: "a job runner whose step DSL honours a sleep directive in any spelling; no SQL is ever run"},
	}
}

func registerSQLiDialects(mux *http.ServeMux) {
	mux.HandleFunc("/ij/dialect/mysql/orders", dialectEndpoint(dialectMySQL, "id", "id=%s", "", map[string]string{"id": "7"}))
	mux.HandleFunc("/ij/dialect/mysql-filtered/orders", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.Query().Get("id")), "sleep") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "Order lookup queued.")
			return
		}
		dialectEndpoint(dialectMySQL, "id", "id=%s", "", map[string]string{"id": "7"})(w, r)
	})
	mux.HandleFunc("/ij/dialect/oracle/staff", dialectEndpoint(dialectOracle, "name", "name='%s'", "", map[string]string{"name": "seed"}))
	mux.HandleFunc("/ij/dialect/sqlite/notes", dialectEndpoint(dialectSQLite, "id", "(id=%s)", "", map[string]string{"id": "7"}))
	mux.HandleFunc("/ij/dialect/db2/ledger", dialectEndpoint(dialectDB2, "sort", "", "%s", map[string]string{"amount": "", "id": ""}))
	// H2 reuses the result of an identical statement while no table changed, so an exact repeat of a
	// heavy query costs nothing: the cache is part of the engine being simulated.
	h2 := dialectEndpoint(dialectH2, "id", "id=%s", "", map[string]string{"id": "1"})
	var h2Seen sync.Map
	mux.HandleFunc("/ij/dialect/h2/cars", func(w http.ResponseWriter, r *http.Request) {
		if _, cached := h2Seen.LoadOrStore(r.URL.Query().Get("id"), true); cached {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "Lookup complete.")
			return
		}
		h2(w, r)
	})
	mux.HandleFunc("/ij/dialect/hsqldb/parts", dialectEndpoint(dialectHSQLDB, "code", "(code='%s')", "", map[string]string{"code": "seed"}))

	mux.HandleFunc("/ij/safe/dialect/slow", func(w http.ResponseWriter, r *http.Request) {
		// A constant pace whatever the input: the latency of a slow backend, not of the value.
		time.Sleep(250 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Record lookup complete.")
	})
	mux.HandleFunc("/ij/safe/dialect/jobs", func(w http.ResponseWriter, r *http.Request) {
		// The step DSL: a sleep directive in any spelling pauses the job; everything else is a label.
		if m := jobSleepDirective.FindStringSubmatch(r.URL.Query().Get("step")); m != nil {
			n, _ := strconv.Atoi(m[1] + m[2])
			time.Sleep(min(time.Duration(n)*time.Second, dialectDelayCap))
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Job step accepted.")
	})
}

// jobSleepDirective is the job runner's pause step, in every spelling its users have written.
var jobSleepDirective = regexp.MustCompile(`(?i)(?:pg_)?sleep\s*\(\s*(\d+)\s*\)|waitfor\s+delay\s*'0:0:(\d+)'`)

// sqlEngine is one simulated database: the functions it has, the schema-qualified objects in its
// catalog, and how its own delay primitives cost time.
type sqlEngine struct {
	name      string
	functions map[string]bool
	objects   map[string]bool
	// delay reads the engine's own delay primitives in an expression that has passed the function and
	// object checks; unbounded reports a statement the engine would run without a work bound.
	delay func(expr string) (d time.Duration, unbounded bool)
}

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// perRate converts a work bound into time at an engine's simulated rate (units per second).
func perRate(n int64, rate float64) time.Duration {
	return time.Duration(float64(n) / rate * float64(time.Second))
}

func firstInt(re *regexp.Regexp, s string) (int64, bool) {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[len(m)-1], 10, 64)
	return n, err == nil
}

var (
	reSleepCall     = regexp.MustCompile(`(?i)\bsleep\s*\(\s*(\d+)\s*\)`)
	reBenchmarkCall = regexp.MustCompile(`(?i)\bbenchmark\s*\(\s*(\d+)\s*,`)
	rePipeReceive   = regexp.MustCompile(`(?i)\bdbms_pipe\.receive_message\s*\([^,()]*(?:\([^()]*\))?[^,()]*,\s*(\d+)\s*\)`)
	reRownumBound   = regexp.MustCompile(`(?i)\brownum\s*<=?\s*(\d+)`)
	reRecursiveCap  = regexp.MustCompile(`(?i)\bwhere\s+\w+\s*<=?\s*(\d+)`)
	reFetchFirst    = regexp.MustCompile(`(?i)\bfetch\s+first\s+(\d+)\s+rows?\s+only`)
	reSystemRange   = regexp.MustCompile(`(?i)\bsystem_range\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)`)
	reLimit         = regexp.MustCompile(`(?i)\blimit\s+(\d+)`)
)

var dialectMySQL = &sqlEngine{
	name:      "MySQL",
	functions: set("sleep", "benchmark", "md5", "count", "concat", "version"),
	objects:   set("information_schema.tables", "information_schema.columns"),
	delay: func(e string) (time.Duration, bool) {
		var d time.Duration
		if n, ok := firstInt(reSleepCall, e); ok {
			d += time.Duration(n) * time.Second
		}
		if n, ok := firstInt(reBenchmarkCall, e); ok {
			d += perRate(n, 4e6)
		}
		return d, false
	},
}

var dialectOracle = &sqlEngine{
	name:      "Oracle",
	functions: set("dbms_pipe.receive_message", "chr", "count"),
	objects:   set("sys.dual"),
	delay: func(e string) (time.Duration, bool) {
		var d time.Duration
		if n, ok := firstInt(rePipeReceive, e); ok {
			d += time.Duration(n) * time.Second
		}
		if strings.Contains(strings.ToLower(e), "all_objects") {
			if n, ok := firstInt(reRownumBound, e); ok {
				d += perRate(n, 1e7)
			} else {
				return 0, true
			}
		}
		return d, false
	},
}

var dialectSQLite = &sqlEngine{
	name:      "SQLite",
	functions: set("randomblob", "hex", "length", "count", "sqlite_version"),
	objects:   set(),
	delay: func(e string) (time.Duration, bool) {
		if regexp.MustCompile(`(?i)\bwith\s+recursive\b`).MatchString(e) {
			if n, ok := firstInt(reRecursiveCap, e); ok {
				return perRate(n, 4e6), false
			}
			return 0, true
		}
		return 0, false
	},
}

var dialectDB2 = &sqlEngine{
	name:      "DB2",
	functions: set("count"),
	objects:   set("sysibm.syscolumns", "sysibm.systables", "sysibm.sysdummy1"),
	delay: func(e string) (time.Duration, bool) {
		if strings.Contains(strings.ToLower(e), "sysibm.") && strings.Count(strings.ToLower(e), "sysibm.") > 1 {
			if n, ok := firstInt(reFetchFirst, e); ok {
				return perRate(n, 1e7), false
			}
			return 0, true
		}
		return 0, false
	},
}

var dialectH2 = &sqlEngine{
	name:      "H2",
	functions: set("system_range", "count", "h2version"),
	objects:   set("information_schema.tables", "information_schema.columns"),
	delay: func(e string) (time.Duration, bool) {
		m := reSystemRange.FindStringSubmatch(e)
		if m == nil {
			return 0, false
		}
		lo, _ := strconv.ParseInt(m[1], 10, 64)
		hi, _ := strconv.ParseInt(m[2], 10, 64)
		return perRate(max(hi-lo+1, 0), 1e7), false
	},
}

var dialectHSQLDB = &sqlEngine{
	name:      "HSQLDB",
	functions: set("count"),
	objects:   set("information_schema.system_columns", "information_schema.system_tables", "information_schema.tables"),
	delay: func(e string) (time.Duration, bool) {
		if strings.Count(strings.ToLower(e), "information_schema.system_columns") < 2 {
			return 0, false
		}
		n, ok := firstInt(reLimit, e)
		if !ok || n == 0 {
			return 0, true // no LIMIT, or LIMIT 0 — which HSQLDB reads as no limit
		}
		return perRate(n, 2e6), false
	},
}

// errSQL is a statement the simulated engine rejects.
type errSQL string

func (e errSQL) Error() string { return string(e) }

// dialectEndpoint builds a handler concatenating param into either a WHERE clause (whereFmt) or an
// ORDER BY list (orderFmt), against a single row whose columns are row. The body never varies.
func dialectEndpoint(engine *sqlEngine, param, whereFmt, orderFmt string, row map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		var d time.Duration
		var err error
		if whereFmt != "" {
			d, err = engine.where(fmt.Sprintf(whereFmt, v), row)
		} else {
			d, err = engine.orderBy(fmt.Sprintf(orderFmt, v), row)
		}
		if err == nil && d > 0 {
			time.Sleep(min(d, dialectDelayCap))
		}
		// The same answer for rows, no rows and a rejected statement: a blind endpoint.
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Lookup complete.")
	}
}

// stripComment removes a `--` comment that sits outside a string literal.
func stripComment(s string) string {
	in := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\'':
			in = !in
		case !in && strings.HasPrefix(s[i:], "--"):
			return s[:i]
		}
	}
	return s
}

// balanced reports whether quotes pair up and parentheses nest, outside literals.
func balanced(s string) bool {
	depth, in := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'':
			in = !in
		case in:
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return !in && depth == 0
}

// splitTop splits s on a separator that sits at nesting depth zero outside literals. A word
// separator (AND/OR) matches case-insensitively between word boundaries.
func splitTop(s, sep string) []string {
	var parts []string
	depth, in, start := 0, false, 0
	word := sep != ","
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			in = !in
			continue
		case in:
			continue
		case c == '(':
			depth++
			continue
		case c == ')':
			depth--
			continue
		}
		if depth != 0 {
			continue
		}
		if !word && c == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
			continue
		}
		if word && i+len(sep) <= len(s) && strings.EqualFold(s[i:i+len(sep)], sep) &&
			(i == 0 || !isWordByte(s[i-1])) && (i+len(sep) == len(s) || !isWordByte(s[i+len(sep)])) {
			parts = append(parts, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	return append(parts, s[start:])
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// unwrap removes parentheses that enclose the whole of s.
func unwrap(s string) string {
	for {
		s = strings.TrimSpace(s)
		if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' || !balanced(s[1:len(s)-1]) {
			return s
		}
		// `(a) AND (b)` starts and ends with a parenthesis without one pair enclosing it all.
		depth, encloses := 0, true
		for i := 0; i < len(s)-1; i++ {
			if s[i] == '(' {
				depth++
			} else if s[i] == ')' {
				depth--
			}
			if depth == 0 {
				encloses = false
				break
			}
		}
		if !encloses {
			return s
		}
		s = s[1 : len(s)-1]
	}
}

var (
	reComparison = regexp.MustCompile(`^(\w+|'[^']*'|\d+)\s*(=|<=|>=|<|>)\s*(\w+|'[^']*'|\d+)$`)
	reDelayAtom  = regexp.MustCompile(`(?s)^\d+\s*<=\s*(\(.*\))$`)
	reCallName   = regexp.MustCompile(`([A-Za-z_][\w.]*)\s*\(`)
	reQualified  = regexp.MustCompile(`\b([A-Za-z_]\w*\.[A-Za-z_]\w*)\b\s*([(]?)`)
	reCTEName    = regexp.MustCompile(`(?i)\bwith\s+recursive\s+(\w+)\s*\(`)
)

// sqlKeywords may precede a parenthesis without being a function call.
var sqlKeywords = set("and", "or", "not", "in", "as", "exists", "select", "from", "where", "values",
	"recursive", "with", "on", "all", "any", "union")

func (e *sqlEngine) where(clause string, row map[string]string) (time.Duration, error) {
	clause = stripComment(clause)
	if !balanced(clause) {
		return 0, errSQL("syntax error: unbalanced quote or parenthesis")
	}
	return e.condition(clause, row)
}

func (e *sqlEngine) condition(s string, row map[string]string) (time.Duration, error) {
	var total time.Duration
	for _, disj := range splitTop(s, "or") {
		for _, conj := range splitTop(disj, "and") {
			conj = unwrap(conj)
			if len(splitTop(conj, "and")) > 1 || len(splitTop(conj, "or")) > 1 {
				d, err := e.condition(conj, row)
				if err != nil {
					return 0, err
				}
				total += d
				continue
			}
			if m := reDelayAtom.FindStringSubmatch(conj); m != nil {
				d, err := e.expression(m[1])
				if err != nil {
					return 0, err
				}
				total += d
				continue
			}
			m := reComparison.FindStringSubmatch(conj)
			if m == nil {
				return 0, errSQL("syntax error near " + strconv.Quote(conj))
			}
			for _, operand := range []string{m[1], m[3]} {
				if _, err := strconv.Atoi(operand); err == nil || strings.HasPrefix(operand, "'") {
					continue
				}
				if _, ok := row[strings.ToLower(operand)]; !ok {
					return 0, errSQL("unknown column " + operand)
				}
			}
		}
	}
	return total, nil
}

func (e *sqlEngine) orderBy(list string, row map[string]string) (time.Duration, error) {
	list = stripComment(list)
	if !balanced(list) {
		return 0, errSQL("syntax error: unbalanced quote or parenthesis")
	}
	var total time.Duration
	for _, item := range splitTop(list, ",") {
		item = strings.TrimSpace(item)
		lower := strings.ToLower(item)
		lower = strings.TrimSuffix(strings.TrimSuffix(lower, " asc"), " desc")
		if _, ok := row[strings.TrimSpace(lower)]; ok {
			continue
		}
		if strings.HasPrefix(item, "(") && strings.HasSuffix(item, ")") {
			d, err := e.expression(item)
			if err != nil {
				return 0, err
			}
			total += d
			continue
		}
		return 0, errSQL("unknown sort key " + strconv.Quote(item))
	}
	return total, nil
}

// expression checks that an expression only names things this engine has, then costs its delay.
func (e *sqlEngine) expression(expr string) (time.Duration, error) {
	ctes := map[string]bool{}
	for _, m := range reCTEName.FindAllStringSubmatch(expr, -1) {
		ctes[strings.ToLower(m[1])] = true
	}
	for _, m := range reCallName.FindAllStringSubmatch(expr, -1) {
		name := strings.ToLower(m[1])
		if sqlKeywords[name] || ctes[name] {
			continue
		}
		if !e.functions[name] {
			return 0, errSQL(e.name + ": function " + name + " does not exist")
		}
	}
	for _, m := range reQualified.FindAllStringSubmatch(expr, -1) {
		if m[2] == "(" {
			continue // a qualified function call, checked above
		}
		if !e.objects[strings.ToLower(m[1])] {
			return 0, errSQL(e.name + ": object " + m[1] + " does not exist")
		}
	}
	d, unbounded := e.delay(expr)
	if unbounded {
		return dialectDelayCap, nil
	}
	return d, nil
}
