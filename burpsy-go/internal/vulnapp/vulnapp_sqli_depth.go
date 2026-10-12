package vulnapp

// SQL-injection depth (burpsy-react-ui-v0ei.2, v0ei.4): database errors only sqlmap's per-DBMS
// error bank recognises, and boolean injection on pages that change on every request.
//
// # Engine error pages (v0ei.2)
//
// Each /ij/dberr/<engine>/accounts endpoint concatenates owner into
// `SELECT id, balance FROM accounts WHERE owner = '<owner>'` for one simulated engine and parses
// the statement the way a SQL lexer does: a single-quoted literal in which `''` is an escaped
// quote, then an optional `and <a> = <b>` condition, then an optional `--` comment. A statement
// that parses answers the same page whatever it selected, so the error channel is the only one; a
// statement that does not parse is answered with that engine's own error text, HTML-escaped into
// an error page the way a debug build relays it. The wording is each engine's, not a payload's: an
// unbalanced quote (`seed'`) is an unterminated literal, a doubled one (`seed''`) is a literal that
// contains a quote and parses. None of these messages contains a substring of Burp's recovered
// bank; only sqlmap's regexes name them.
//
// The safe twin binds owner and, when the value carries a quote, explains that quotes and SQL words
// mean nothing to it — a page the probe introduced that is full of SQL vocabulary and is not a
// database error.
//
// # Dynamic pages (v0ei.4)
//
// /ij/dyn/catalog renders a fresh CSRF token, a nanosecond render timestamp and a request id on
// every request, and reflects the category it was asked for. Its category is concatenated into
// `category = '<value>'` and an appended `and <a> = <b>` decides whether rows come back. Its safe
// twin renders the same dynamic page and binds the category, so any appended text is just a
// category with no products.
//
// /ij/dyn/members looks a handle up with `handle = '<value>'`; the seeded handle matches nobody, so
// only a widening `or <a> = <b>` changes the answer. Its safe twin binds the handle.
//
// Nothing here opens a database or executes anything.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// dbErrorEngine spells one engine's errors for an unterminated literal and for an unexpected token.
// pos is the 1-based character position in the statement, statement the full SQL text.
type dbErrorEngine struct {
	name         string
	unterminated func(statement string, pos int) string
	unexpected   func(statement string, pos int, token string) string
}

var dbErrorEngines = []dbErrorEngine{
	{
		name: "sqlite",
		unterminated: func(_ string, _ int) string {
			return `sqlite3.OperationalError: unrecognized token: "'"`
		},
		unexpected: func(_ string, _ int, tok string) string {
			return fmt.Sprintf(`sqlite3.OperationalError: near "%s": syntax error`, tok)
		},
	},
	{
		name: "h2",
		unterminated: func(st string, pos int) string {
			return fmt.Sprintf("org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL statement \"%s[*]%s\"; SQL statement:\n%s [42000-224]",
				st[:pos-1], st[pos-1:], st)
		},
		unexpected: func(st string, pos int, _ string) string {
			return fmt.Sprintf("org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL statement \"%s[*]%s\"; SQL statement:\n%s [42000-224]",
				st[:pos-1], st[pos-1:], st)
		},
	},
	{
		name: "clickhouse",
		unterminated: func(_ string, pos int) string {
			return fmt.Sprintf("Code: 62. DB::Exception: Syntax error: failed at position %d ('''): '. Unmatched quotes. (SYNTAX_ERROR) (version 24.3.2.23 (official build))", pos)
		},
		unexpected: func(_ string, pos int, tok string) string {
			return fmt.Sprintf("Code: 62. DB::Exception: Syntax error: failed at position %d ('%s'): %s. Expected end of query. (SYNTAX_ERROR) (version 24.3.2.23 (official build))", pos, tok, tok)
		},
	},
	{
		name: "snowflake",
		unterminated: func(_ string, pos int) string {
			return fmt.Sprintf("001003 (42000): SQL compilation error:\nsyntax error line 1 at position %d unexpected '''.", pos-1)
		},
		unexpected: func(_ string, pos int, tok string) string {
			return fmt.Sprintf("001003 (42000): SQL compilation error:\nsyntax error line 1 at position %d unexpected '%s'.", pos-1, tok)
		},
	},
	{
		name: "hsqldb",
		unterminated: func(st string, _ int) string {
			return fmt.Sprintf("Unexpected end of command in statement [%s]", st)
		},
		unexpected: func(st string, _ int, tok string) string {
			return fmt.Sprintf("Unexpected token: %s in statement [%s]", strings.ToUpper(tok), st)
		},
	},
	{
		name: "firebird",
		unterminated: func(_ string, pos int) string {
			return fmt.Sprintf("Dynamic SQL Error SQL error code = -104 Unexpected end of command - line 1, column %d", pos)
		},
		unexpected: func(_ string, pos int, tok string) string {
			return fmt.Sprintf("Dynamic SQL Error SQL error code = -104 Token unknown - line 1, column %d %s", pos, tok)
		},
	},
}

// DBErrorEngines names the engines /ij/dberr simulates, for the scanner tests that drive each one.
func DBErrorEngines() []string {
	out := make([]string, 0, len(dbErrorEngines))
	for _, e := range dbErrorEngines {
		out = append(out, e.name)
	}
	return out
}

func sqliDepthEndpoints() []Endpoint {
	var out []Endpoint
	for _, e := range dbErrorEngines {
		out = append(out, Endpoint{Path: "/ij/dberr/" + e.name + "/accounts?owner=seed", Row: "SQL injection",
			Note: "concatenates owner into a quoted literal for a simulated " + e.name +
				" engine and relays that engine's own parse error; a parsed statement answers the same page whatever it selected"})
	}
	return append(out,
		Endpoint{Path: "/ij/safe/dberr/accounts?owner=seed", Row: "SQL injection", Safe: true,
			Note: "binds owner; a quoted value gets a help text full of SQL keywords, which is not a database error"},

		Endpoint{Path: "/ij/dyn/catalog?category=seed", Row: "SQL injection",
			Note: "a page with a fresh CSRF token, render timestamp and request id that reflects category; category is concatenated into a condition that decides whether rows come back"},
		Endpoint{Path: "/ij/safe/dyn/catalog?category=seed", Row: "SQL injection", Safe: true,
			Note: "the same dynamic, reflecting page with category bound: appended text is only a category with no products"},

		Endpoint{Path: "/ij/dyn/members?handle=nobody", Row: "SQL injection",
			Note: "concatenates handle into a lookup whose seeded value matches nobody; only a widening or-condition changes the answer (check_sqli_or_boolean)"},
		Endpoint{Path: "/ij/safe/dyn/members?handle=nobody", Row: "SQL injection", Safe: true,
			Note: "binds handle; no condition in the value is evaluated"},
	)
}

func registerSQLiDepth(mux *http.ServeMux) {
	for _, e := range dbErrorEngines {
		mux.HandleFunc("/ij/dberr/"+e.name+"/accounts", accountsOnEngine(e))
	}
	mux.HandleFunc("/ij/safe/dberr/accounts", safeAccounts)
	mux.HandleFunc("/ij/dyn/catalog", dynamicCatalog(false))
	mux.HandleFunc("/ij/safe/dyn/catalog", dynamicCatalog(true))
	mux.HandleFunc("/ij/dyn/members", memberLookup(false))
	mux.HandleFunc("/ij/safe/dyn/members", memberLookup(true))
}

// sqlCondition is `<a> = <b>` with operands numbers or quoted strings.
var sqlCondition = regexp.MustCompile(`^(\d+|'[^']*')\s*=\s*(\d+|'[^']*')$`)

// parsedLiteralClause is a statement `... = '<value>'` after lexing: the literal, the conjunction
// and condition after it (if any), and where it stopped parsing if it could not.
type parsedLiteralClause struct {
	literal   string
	conj      string // "", "and", "or"
	condTrue  bool
	errPos    int    // 1-based position in the statement of the failure; 0 when it parsed
	errToken  string // the unexpected token, empty for an unterminated literal
	statement string
}

// parseLiteralClause lexes `prefix + '<value>'` the way SQL does: `”` inside the literal is an
// escaped quote, a lone `'` ends it; after it, an optional `and|or <a> = <b>` and an optional `--`
// comment, nothing else.
func parseLiteralClause(prefix, value string) parsedLiteralClause {
	st := prefix + "'" + value + "'"
	out := parsedLiteralClause{statement: st}
	literal, rest, ok := pgStringLiteral(value + "'")
	if !ok {
		out.errPos = len(st)
		return out
	}
	out.literal = literal
	restAt := len(st) - len(rest) + 1
	if c := strings.Index(rest, "--"); c >= 0 {
		rest = rest[:c]
	}
	trimmed := strings.TrimSpace(rest)
	if trimmed == "" {
		return out
	}
	fail := func() parsedLiteralClause {
		out.errPos = restAt + strings.Index(rest, trimmed)
		out.errToken = strings.Fields(trimmed)[0]
		return out
	}
	conj, cond, found := strings.Cut(trimmed, " ")
	conj = strings.ToLower(conj)
	if !found || (conj != "and" && conj != "or") {
		return fail()
	}
	m := sqlCondition.FindStringSubmatch(strings.TrimSpace(cond))
	if m == nil {
		return fail()
	}
	out.conj, out.condTrue = conj, m[1] == m[2]
	return out
}

// accountsOnEngine is one engine's error-relaying lookup.
func accountsOnEngine(e dbErrorEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		c := parseLiteralClause("SELECT id, balance FROM accounts WHERE owner = ", r.URL.Query().Get("owner"))
		if c.errPos > 0 {
			msg := e.unterminated(c.statement, c.errPos)
			if c.errToken != "" {
				msg = e.unexpected(c.statement, c.errPos, c.errToken)
			}
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "<html><body><h1>Internal error</h1><pre>%s</pre></body></html>", html.EscapeString(msg))
			return
		}
		fmt.Fprint(w, "<html><body><h1>Accounts</h1><p>Lookup complete.</p></body></html>")
	}
}

// safeAccounts binds owner. A value with a quote in it gets help text, not an error.
func safeAccounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	owner := r.URL.Query().Get("owner")
	if strings.ContainsAny(owner, `'"`) {
		fmt.Fprintf(w, "<html><body><h1>Accounts</h1><p>No account for owner &ldquo;%s&rdquo;.</p>"+
			"<p>Owners are matched as plain text by a parameterised SELECT ... WHERE owner = ? query, so SQL syntax "+
			"never comes from your input: quotes, -- comments and words like UNION, ORDER BY or OR 1=1 have no special "+
			"meaning here.</p></body></html>", html.EscapeString(owner))
		return
	}
	fmt.Fprint(w, "<html><body><h1>Accounts</h1><p>Lookup complete.</p></body></html>")
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// dynamicCatalog serves the dynamic catalogue page; bound selects the safe twin.
func dynamicCatalog(bound bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		category := r.URL.Query().Get("category")
		rows := category == "seed"
		if !bound {
			c := parseLiteralClause("SELECT name FROM products WHERE category = ", category)
			if c.errPos > 0 {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "<html><body><p>Something went wrong.</p></body></html>")
				return
			}
			rows = c.literal == "seed"
			switch c.conj {
			case "and":
				rows = rows && c.condTrue
			case "or":
				rows = rows || c.condTrue
			}
		}
		token := randomHex(16)
		var b strings.Builder
		fmt.Fprintf(&b, "<html><head><meta name=\"csrf-token\" content=\"%s\"></head><body>\n", token)
		fmt.Fprintf(&b, "<p class=\"meta\">Rendered at %s</p>\n", time.Now().UTC().Format(time.RFC3339Nano))
		fmt.Fprintf(&b, "<form method=\"get\"><input type=\"hidden\" name=\"csrf\" value=\"%s\">"+
			"<input name=\"category\" value=\"%s\"><button>Search</button></form>\n", token, html.EscapeString(category))
		fmt.Fprintf(&b, "<h2>Products in %s</h2>\n", html.EscapeString(category))
		if rows {
			b.WriteString("<ul><li>Widget</li><li>Gadget</li><li>Gizmo</li></ul>\n")
		} else {
			b.WriteString("<p>No products in this category.</p>\n")
		}
		fmt.Fprintf(&b, "<footer>Request %s</footer></body></html>", randomHex(8))
		fmt.Fprint(w, b.String())
	}
}

// memberLookup serves the member lookup; bound selects the safe twin.
func memberLookup(bound bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		handle := r.URL.Query().Get("handle")
		members := []string{"alice", "bob", "carol"}
		var found []string
		if bound {
			for _, m := range members {
				if m == handle {
					found = append(found, m)
				}
			}
		} else {
			c := parseLiteralClause("SELECT handle FROM members WHERE handle = ", handle)
			if c.errPos > 0 {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "<html><body><p>Something went wrong.</p></body></html>")
				return
			}
			for _, m := range members {
				match := m == c.literal
				switch c.conj {
				case "and":
					match = match && c.condTrue
				case "or":
					match = match || c.condTrue
				}
				if match {
					found = append(found, m)
				}
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "<html><body><p class=\"meta\">Rendered at %s</p>\n", time.Now().UTC().Format(time.RFC3339Nano))
		if len(found) == 0 {
			fmt.Fprintf(&b, "<p>No member named %s.</p>\n", html.EscapeString(handle))
		} else {
			b.WriteString("<ul>")
			for _, m := range found {
				fmt.Fprintf(&b, "<li>%s</li>", m)
			}
			b.WriteString("</ul>\n")
		}
		b.WriteString("</body></html>")
		fmt.Fprint(w, b.String())
	}
}
