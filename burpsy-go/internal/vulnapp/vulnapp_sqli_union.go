package vulnapp

// UNION-based and stacked-query SQL injection (burpsy-react-ui-v0ei.5), and the out-of-band SQL
// fixtures (v0ei.3).
//
// Every vulnerable endpoint here concatenates its parameter into a statement that a small SQL
// evaluator runs over an in-memory table. Nothing matches payload text: the evaluator parses the
// spliced statement, evaluates the WHERE clause per row, checks an ORDER BY index against the column
// count, and evaluates every expression of a UNION SELECT — string literals, NULL, integers, `*`,
// CONCAT(), `||` and `+` concatenation, CAST, SUBSTRING/SUBSTR and the engine's own functions — under
// that engine's rules: a function the engine does not have is an error, a UNION with the wrong
// column count is an error, a string in a strictly typed INT column is an error. A marker therefore
// reaches the page only when the expression that spells it was evaluated.
//
// The safe twins: /ij/safe/union/cars binds the id (and echoes what it was given), and the
// /ij/sqli/union-echo endpoint IS injectable (its errors say so) but renders no rows: what it shows
// is the search term with every `'||'` deleted, which turns `'bsyu'||'x'` into the marker a scanner
// would look for. A UNION claim there is a false positive; only the SQL-injection finding the error
// proves is true.
//
// Nothing here opens a database; every delay is a bounded time.Sleep, and every out-of-band "lookup"
// is a line in OutboundContacts.

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func sqliUnionEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/ij/union/cars?id=1", Row: "SQL injection",
			Note: "H2-like: concatenates id into `SELECT id,name,image FROM cars WHERE id=<v>` and renders the FIRST row only; errors are a generic 500"},
		{Path: "/ij/union/cars-noorder?id=1", Row: "SQL injection",
			Note: "the H2-like cars lookup behind a filter that deletes `ORDER BY`: the column count is learnable only from UNION SELECT NULL"},
		{Path: "/ij/union/staff?name=alice", Row: "SQL injection",
			Note: "SQLite-like: concatenates name into `WHERE name='<v>'` and lists every row; `||` concatenation only"},
		{Path: "/ij/sqli/union-echo?q=seed", Row: "SQL injection",
			Note: "MySQL errors prove the injection; rows are never rendered, and the echoed term has every `'||'` deleted (a UNION marker look-alike)"},
		{Path: "/ij/stacked/mysql/items?id=7", Row: "SQL injection",
			Note: "MySQL with multi-statements on: `;SELECT SLEEP(n)` after the statement sleeps"},
		{Path: "/ij/stacked/single/items?id=7", Row: "SQL injection",
			Note: "MySQL with multi-statements off: injectable, but a stacked statement is a syntax error"},
		{Path: "/ij/safe/union/cars?id=1", Row: "SQL injection", Safe: true,
			Note: "binds id as an integer and echoes a non-integer back as text"},
	}
}

func registerSQLiUnion(mux *http.ServeMux) {
	mux.HandleFunc("/ij/union/cars", unionCars)
	mux.HandleFunc("/ij/union/cars-noorder", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		q.Set("id", reOrderBy.ReplaceAllString(q.Get("id"), ""))
		r.URL.RawQuery = q.Encode()
		unionCars(w, r)
	})
	mux.HandleFunc("/ij/union/staff", unionStaff)
	mux.HandleFunc("/ij/sqli/union-echo", unionEcho)
	mux.HandleFunc("/ij/stacked/mysql/items", stackedItems(true))
	mux.HandleFunc("/ij/stacked/single/items", stackedItems(false))
	mux.HandleFunc("/ij/safe/union/cars", safeUnionCars)
}

// unionEngine is one simulated engine's expression rules.
type unionEngine struct {
	name          string
	concatFn      bool // CONCAT()
	pipes         bool // `||` joins strings
	plusConcat    bool // `+` joins strings
	dual          bool // FROM DUAL is accepted
	strict        bool // a non-numeric string in an INT column is an error
	functions     map[string]string
	systemVars    map[string]string
	syntaxMessage string
}

var (
	unionH2 = &unionEngine{name: "H2", concatFn: true, pipes: true, dual: true, strict: true,
		functions: map[string]string{"h2version": "2.1.214"}, syntaxMessage: "Syntax error in SQL statement"}
	unionSQLite = &unionEngine{name: "SQLite", pipes: true,
		functions: map[string]string{"sqlite_version": "3.45.1"}, syntaxMessage: "SQLITE_ERROR: syntax error"}
	unionMySQL = &unionEngine{name: "MySQL", concatFn: true, dual: true,
		functions:     map[string]string{"uuid_short": "100", "version": "8.0.36"},
		syntaxMessage: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"}
)

// unionTable is the in-memory table a statement reads.
type unionTable struct {
	cols  []string
	types []string // "int" or "text"
	rows  [][]any
}

var carsTable = &unionTable{
	cols:  []string{"id", "name", "image"},
	types: []string{"int", "text", "text"},
	rows: [][]any{
		{int64(1), "Audi", "/img/audi.jpg"},
		{int64(2), "Volvo", "/img/volvo.jpg"},
	},
}

var staffTable = &unionTable{
	cols:  []string{"name", "role"},
	types: []string{"text", "text"},
	rows:  [][]any{{"alice", "engineer"}, {"bob", "manager"}},
}

var itemsTable = &unionTable{
	cols:  []string{"id", "label"},
	types: []string{"int", "text"},
	rows:  [][]any{{int64(7), "widget"}},
}

// run executes `SELECT <cols> FROM t WHERE <tail>` with tail as spliced, returning the rows.
func (e *unionEngine) run(t *unionTable, tail string) ([][]any, error) {
	tail = stripComment(tail)
	if !balanced(tail) {
		return nil, errSQL("unbalanced quote or parenthesis")
	}
	parts := splitTop(tail, "union")
	last := len(parts) - 1
	order := splitTop(parts[last], "order")
	if len(order) > 2 {
		return nil, errSQL("syntax error near ORDER")
	}
	parts[last] = order[0]
	var out [][]any
	cond := strings.TrimSpace(parts[0])
	for _, row := range t.rows {
		ok, err := e.truth(t, row, cond)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, row)
		}
	}
	for _, u := range parts[1:] {
		row, err := e.unionRow(t, u)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if len(order) == 2 {
		rest := strings.TrimSpace(order[1])
		if !strings.HasPrefix(strings.ToLower(rest), "by ") {
			return nil, errSQL("syntax error near ORDER")
		}
		n, err := strconv.Atoi(strings.TrimSpace(rest[3:]))
		if err != nil || n < 1 || n > len(t.cols) {
			return nil, errSQL("ORDER BY position " + strings.TrimSpace(rest[3:]) + " is not in select list")
		}
	}
	return out, nil
}

// truth evaluates a WHERE clause over one row: comparisons joined by AND / OR.
func (e *unionEngine) truth(t *unionTable, row []any, s string) (bool, error) {
	matched := false
	for _, disj := range splitTop(s, "or") {
		all := true
		for _, conj := range splitTop(disj, "and") {
			conj = unwrap(conj)
			if len(splitTop(conj, "and")) > 1 || len(splitTop(conj, "or")) > 1 {
				ok, err := e.truth(t, row, conj)
				if err != nil {
					return false, err
				}
				all = all && ok
				continue
			}
			m := reUnionComparison.FindStringSubmatch(strings.TrimSpace(conj))
			if m == nil {
				return false, errSQL("syntax error near " + strconv.Quote(conj))
			}
			l, err := t.operand(row, m[1])
			if err != nil {
				return false, err
			}
			r, err := t.operand(row, m[2])
			if err != nil {
				return false, err
			}
			all = all && fmt.Sprint(l) == fmt.Sprint(r)
		}
		matched = matched || all
	}
	return matched, nil
}

func (t *unionTable) operand(row []any, s string) (any, error) {
	if strings.HasPrefix(s, "'") {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	for i, c := range t.cols {
		if strings.EqualFold(c, s) {
			return row[i], nil
		}
	}
	return nil, errSQL("unknown column " + s)
}

var reOrderBy = regexp.MustCompile(`(?i)order\s+by`)

var reUnionComparison = regexp.MustCompile(`^(\w+|'(?:[^']|'')*'|-?\d+)\s*=\s*(\w+|'(?:[^']|'')*'|-?\d+)$`)

var reFromDual = regexp.MustCompile(`(?i)\s+from\s+dual\s*$`)

// unionRow evaluates one `[ALL] SELECT <list> [FROM DUAL]` branch.
func (e *unionEngine) unionRow(t *unionTable, s string) ([]any, error) {
	s = strings.TrimSpace(s)
	if low := strings.ToLower(s); strings.HasPrefix(low, "all ") {
		s = strings.TrimSpace(s[4:])
	}
	if !strings.HasPrefix(strings.ToLower(s), "select ") {
		return nil, errSQL("syntax error near UNION")
	}
	s = s[7:]
	if loc := reFromDual.FindStringIndex(s); loc != nil {
		if !e.dual {
			return nil, errSQL("no such table: DUAL")
		}
		s = s[:loc[0]]
	}
	exprs := splitTop(s, ",")
	if len(exprs) != len(t.cols) {
		return nil, errSQL("the used SELECT statements have a different number of columns")
	}
	row := make([]any, len(exprs))
	for i, x := range exprs {
		v, err := e.eval(x)
		if err != nil {
			return nil, err
		}
		if s, ok := v.(string); ok && e.strict && t.types[i] == "int" {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return nil, errSQL("Data conversion error converting " + strconv.Quote(s))
			}
			v = n
		}
		row[i] = v
	}
	return row, nil
}

// eval evaluates one expression.
func (e *unionEngine) eval(s string) (any, error) {
	p := &exprParser{e: e, toks: exprTokens(s)}
	v, err := p.concat()
	if err != nil {
		return nil, err
	}
	if p.i != len(p.toks) {
		return nil, errSQL("syntax error near " + strconv.Quote(strings.Join(p.toks[p.i:], " ")))
	}
	return v, nil
}

var reExprToken = regexp.MustCompile(`'(?:[^']|'')*'|\|\||@@\w+|\d+|[A-Za-z_][\w.]*|[(),*+]|\S`)

func exprTokens(s string) []string { return reExprToken.FindAllString(s, -1) }

type exprParser struct {
	e    *unionEngine
	toks []string
	i    int
}

func (p *exprParser) peek() string {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return ""
}

func (p *exprParser) next() string { t := p.peek(); p.i++; return t }

func (p *exprParser) expect(t string) error {
	if !strings.EqualFold(p.next(), t) {
		return errSQL("syntax error: expected " + t)
	}
	return nil
}

func sqlString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		return fmt.Sprint(x)
	}
}

func (p *exprParser) concat() (any, error) {
	v, err := p.add()
	if err != nil {
		return nil, err
	}
	for p.peek() == "||" {
		if !p.e.pipes {
			return nil, errSQL(p.e.name + ": operator || is not string concatenation here")
		}
		p.next()
		r, err := p.add()
		if err != nil {
			return nil, err
		}
		v = sqlString(v) + sqlString(r)
	}
	return v, nil
}

func (p *exprParser) add() (any, error) {
	v, err := p.mul()
	if err != nil {
		return nil, err
	}
	for p.peek() == "+" {
		p.next()
		r, err := p.mul()
		if err != nil {
			return nil, err
		}
		li, lok := v.(int64)
		ri, rok := r.(int64)
		switch {
		case lok && rok:
			v = li + ri
		case p.e.plusConcat:
			v = sqlString(v) + sqlString(r)
		default:
			return nil, errSQL(p.e.name + ": cannot add strings")
		}
	}
	return v, nil
}

func (p *exprParser) mul() (any, error) {
	v, err := p.primary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "*" {
		p.next()
		r, err := p.primary()
		if err != nil {
			return nil, err
		}
		li, lok := v.(int64)
		ri, rok := r.(int64)
		if !lok || !rok {
			return nil, errSQL("cannot multiply non-numbers")
		}
		v = li * ri
	}
	return v, nil
}

func (p *exprParser) args() ([]any, error) {
	if err := p.expect("("); err != nil {
		return nil, err
	}
	var out []any
	if p.peek() == ")" {
		p.next()
		return out, nil
	}
	for {
		v, err := p.concat()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		switch p.next() {
		case ",":
			continue
		case ")":
			return out, nil
		default:
			return nil, errSQL("syntax error in argument list")
		}
	}
}

func (p *exprParser) primary() (any, error) {
	t := p.next()
	switch {
	case t == "":
		return nil, errSQL("unexpected end of expression")
	case strings.HasPrefix(t, "'"):
		return strings.ReplaceAll(t[1:len(t)-1], "''", "'"), nil
	case strings.EqualFold(t, "null"):
		return nil, nil
	case t[0] >= '0' && t[0] <= '9':
		n, _ := strconv.ParseInt(t, 10, 64)
		return n, nil
	case t == "(":
		v, err := p.concat()
		if err != nil {
			return nil, err
		}
		return v, p.expect(")")
	case strings.HasPrefix(t, "@@"):
		if v, ok := p.e.systemVars[strings.ToLower(t[2:])]; ok {
			return v, nil
		}
		return nil, errSQL("unknown system variable " + t)
	case strings.EqualFold(t, "cast"):
		if err := p.expect("("); err != nil {
			return nil, err
		}
		v, err := p.concat()
		if err != nil {
			return nil, err
		}
		if err := p.expect("as"); err != nil {
			return nil, err
		}
		p.next() // the type name
		if p.peek() == "(" {
			p.next()
			p.next()
			if err := p.expect(")"); err != nil {
				return nil, err
			}
		}
		return sqlString(v), p.expect(")")
	}
	name := strings.ToLower(t)
	if p.peek() != "(" {
		return nil, errSQL("unknown column " + t)
	}
	args, err := p.args()
	if err != nil {
		return nil, err
	}
	switch {
	case name == "concat" && p.e.concatFn:
		var b strings.Builder
		for _, a := range args {
			b.WriteString(sqlString(a))
		}
		return b.String(), nil
	case name == "substring" || name == "substr":
		if len(args) != 3 {
			return nil, errSQL(name + " takes three arguments here")
		}
		s := sqlString(args[0])
		from, _ := args[1].(int64)
		n, _ := args[2].(int64)
		if from < 1 || int(from) > len(s)+1 {
			return "", nil
		}
		end := min(int(from-1+n), len(s))
		return s[from-1 : end], nil
	}
	if v, ok := p.e.functions[name]; ok {
		return v, nil
	}
	return nil, errSQL(p.e.name + ": function " + name + " does not exist")
}

// unionCars renders the first row as JSON, the way an application that maps one entity does.
func unionCars(w http.ResponseWriter, r *http.Request) {
	rows, err := unionH2.run(carsTable, "id="+r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "System Error Occurred. please check logs.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if len(rows) == 0 {
		fmt.Fprint(w, "{}")
		return
	}
	b, _ := json.Marshal(map[string]any{"id": rows[0][0], "name": rows[0][1], "imagePath": rows[0][2]})
	w.Write(b)
}

// unionStaff lists every row.
func unionStaff(w http.ResponseWriter, r *http.Request) {
	rows, err := unionSQLite.run(staffTable, "name='"+r.URL.Query().Get("name")+"'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err != nil {
		fmt.Fprint(w, "<html><body><p>Search failed.</p></body></html>")
		return
	}
	var b strings.Builder
	b.WriteString("<html><body><ul>")
	for _, row := range rows {
		fmt.Fprintf(&b, "<li>%s (%s)</li>", html.EscapeString(sqlString(row[0])), html.EscapeString(sqlString(row[1])))
	}
	b.WriteString("</ul></body></html>")
	fmt.Fprint(w, b.String())
}

// unionEcho is injectable (MySQL's syntax error shows), renders a row count but never a row, and
// echoes the term with every `'||'` deleted.
func unionEcho(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	shown := html.EscapeString(strings.ReplaceAll(q, "'||'", ""))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	rows, err := unionMySQL.run(staffTable, "name='"+q+"'")
	if err != nil {
		fmt.Fprintf(w, "<html><body><p>You searched: %s</p><p>%s</p></body></html>", shown, unionMySQL.syntaxMessage)
		return
	}
	fmt.Fprintf(w, "<html><body><p>You searched: %s</p><p>%d match(es).</p></body></html>", shown, len(rows))
}

var reStackedSleep = regexp.MustCompile(`(?i)^\s*select\s+sleep\s*\(\s*(\d+)\s*\)\s*$`)

// stackedItems runs a MySQL statement; with multi on, further `;`-separated statements run too, and
// the only one this engine knows is SELECT SLEEP(n).
func stackedItems(multi bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		stmts := splitStatements(stripComment("id=" + v))
		fail := func() {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><p>%s</p></body></html>", unionMySQL.syntaxMessage)
		}
		if len(stmts) > 1 && !multi {
			fail()
			return
		}
		rows, err := unionMySQL.run(itemsTable, stmts[0])
		if err != nil {
			fail()
			return
		}
		var delay time.Duration
		for _, s := range stmts[1:] {
			if strings.TrimSpace(s) == "" {
				continue
			}
			m := reStackedSleep.FindStringSubmatch(s)
			if m == nil {
				fail()
				return
			}
			n, _ := strconv.Atoi(m[1])
			delay += time.Duration(n) * time.Second
		}
		time.Sleep(min(delay, dialectDelayCap))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><p>%d item(s).</p></body></html>", len(rows))
	}
}

// splitStatements splits on `;` outside string literals.
func splitStatements(s string) []string {
	var out []string
	in, start := false, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\'':
			in = !in
		case !in && s[i] == ';':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// safeUnionCars binds the id: a non-integer matches nothing and is echoed back.
func safeUnionCars(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		fmt.Fprintf(w, "<html><body><p>No car with id %s.</p></body></html>", html.EscapeString(v))
		return
	}
	for _, row := range carsTable.rows {
		if row[0] == n {
			fmt.Fprintf(w, "<html><body><p>%s</p></body></html>", html.EscapeString(sqlString(row[1])))
			return
		}
	}
	fmt.Fprintf(w, "<html><body><p>No car with id %d.</p></body></html>", n)
}

// ---------------------------------------------------------------------------
// out-of-band SQL fixtures (v0ei.3): not manifest rows, for the same reason as /oob/fetch
// (vulnapp_oob.go) — the runtime suite has no interaction server.
// ---------------------------------------------------------------------------

var (
	reXpDirtree  = regexp.MustCompile(`(?i)^\s*exec\s+master\.\.xp_dirtree\s+'\\\\([A-Za-z0-9.-]+)\\[^']*'\s*$`)
	reUtlInaddr  = regexp.MustCompile(`(?i)\butl_inaddr\.get_host_address\s*\(\s*'([A-Za-z0-9.-]+)'\s*\)`)
	reHTTPURI    = regexp.MustCompile(`(?i)\bhttpuritype\s*\(\s*'http://([A-Za-z0-9.-]+)/[^']*'\s*\)\.getclob\(\)`)
	reHostShaped = regexp.MustCompile(`[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)
)

func registerOOBSQLFixtures(mux *http.ServeMux) {
	// SQL Server, multi-statement: the statement is `SELECT ... WHERE id=<v>`; a stacked
	// `EXEC master..xp_dirtree '\\host\share'` resolves host. The page never changes.
	mux.HandleFunc("/oob/sqli/mssql", func(w http.ResponseWriter, r *http.Request) {
		stmts := splitStatements(stripComment("id=" + r.URL.Query().Get("id")))
		if balanced(stmts[0]) {
			for _, s := range stmts[1:] {
				if m := reXpDirtree.FindStringSubmatch(s); m != nil {
					recordContact("dns", strings.ToLower(m[1]))
				}
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Lookup complete.")
	})
	// Oracle: `WHERE name='<v>'`; UTL_INADDR resolves, HTTPURITYPE resolves and fetches, but only
	// in a statement that parses (balanced, outside any literal the function name sits in).
	mux.HandleFunc("/oob/sqli/oracle", func(w http.ResponseWriter, r *http.Request) {
		stmt := stripComment("name='" + r.URL.Query().Get("name") + "'")
		if balanced(stmt) && !insideLiteral(stmt, "utl_inaddr") && !insideLiteral(stmt, "httpuritype") {
			for _, m := range reUtlInaddr.FindAllStringSubmatch(stmt, -1) {
				recordContact("dns", strings.ToLower(m[1]))
			}
			for _, m := range reHTTPURI.FindAllStringSubmatch(stmt, -1) {
				recordContact("dns", strings.ToLower(m[1]))
				recordContact("http", strings.ToLower(m[1]))
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Lookup complete.")
	})
	// Bound parameter: nothing the value says is ever executed or resolved.
	mux.HandleFunc("/safe/oob/sqli/bound", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Lookup complete.")
	})
	// Not SQL at all: a link previewer that resolves every host-shaped token it is given.
	mux.HandleFunc("/safe/oob/sqli/resolver", func(w http.ResponseWriter, r *http.Request) {
		for _, h := range reHostShaped.FindAllString(r.URL.Query().Get("q"), -1) {
			recordContact("dns", strings.ToLower(h))
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Preview queued.")
	})
}

// insideLiteral reports whether the first occurrence of word sits inside a string literal.
func insideLiteral(s, word string) bool {
	i := strings.Index(strings.ToLower(s), word)
	if i < 0 {
		return false
	}
	return strings.Count(s[:i], "'")%2 == 1
}
