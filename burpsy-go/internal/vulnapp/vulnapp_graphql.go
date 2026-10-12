package vulnapp

// The GraphQL hardening family (burpsy-react-ui-0vzb.13): one GraphQL server with every hardening
// gap, and its hardened twin.
//
// /gql/api is vulnerable to:
//   - "GraphQL query batching enabled": it executes a JSON array of operations, and any number of
//     aliases in one operation;
//   - "GraphQL query depth not limited": Category.parent is a Category, and no depth is refused;
//   - "GraphQL debug information disclosed": every error carries a Node-style stack trace in
//     extensions.exception.stacktrace;
//   - "SQL injection": book(title:) concatenates its argument into a quoted SQL literal - an
//     appended condition that closes the literal decides whether the book comes back. Reachable
//     only through the argument inside the GraphQL document, which is what the GraphQL nested
//     insertion points (bcheck/insertion_graphql.go) exist to reach.
//
// /gql/safe/api answers the same schema, with introspection still ON (the depth probe needs a
// schema to build a nested query from, so a twin with introspection off would pass the depth row
// without the check ever being exercised): array bodies refused, more than 15 aliases refused,
// depth over 5 refused, errors masked to their message, and book(title:) compared as a bound value.
//
// Nothing is executed: the "database" is parseQuotedClause, the same pattern-matcher the other SQL
// fixtures use, and the stack trace is a fixed string.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	gqlSeedBody    = `{"query":"query{book(title:\"seed\"){title author}}"}`
	gqlContentType = "application/json"
)

func graphQLEndpoints() []Endpoint {
	var out []Endpoint
	for _, row := range []struct{ name, vuln, safe string }{
		{"GraphQL query batching enabled",
			"executes a JSON array of operations and any number of aliases in one request",
			"refuses array bodies and operations with more than 15 aliases"},
		{"GraphQL query depth not limited",
			"Category.parent is self-referential and no query depth is refused",
			"same self-referential schema, introspection on, queries deeper than 5 refused"},
		{"GraphQL debug information disclosed",
			"every GraphQL error carries a server stack trace in extensions.exception.stacktrace",
			"errors are masked to their message; no stack, no extensions"},
		{"SQL injection",
			"book(title:) concatenates the argument into a quoted SQL literal; an appended condition decides whether the book comes back",
			"book(title:) compares the argument as a bound value; no condition in it is ever evaluated"},
	} {
		out = append(out,
			Endpoint{Path: "/gql/api", Method: "POST", Body: gqlSeedBody, ContentType: gqlContentType, Row: row.name, Note: row.vuln},
			Endpoint{Path: "/gql/safe/api", Method: "POST", Body: gqlSeedBody, ContentType: gqlContentType, Row: row.name, Safe: true, Note: row.safe})
	}
	return out
}

func registerGraphQL(mux *http.ServeMux) {
	mux.HandleFunc("/gql/api", func(w http.ResponseWriter, r *http.Request) { serveGQL(w, r, false) })
	mux.HandleFunc("/gql/safe/api", func(w http.ResponseWriter, r *http.Request) { serveGQL(w, r, true) })
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

func serveGQL(w http.ResponseWriter, r *http.Request, safe bool) {
	w.Header().Set("Content-Type", "application/json")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	ct := r.Header.Get("Content-Type")
	if safe && (r.Method != http.MethodPost || !strings.HasPrefix(ct, "application/json")) {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		fmt.Fprint(w, `{"errors":[{"message":"only POST application/json is accepted"}]}`)
		return
	}
	var query string
	switch {
	case r.Method == http.MethodGet:
		query = r.URL.Query().Get("query")
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		v, _ := url.ParseQuery(string(body))
		query = v.Get("query")
	default:
		trimmed := strings.TrimSpace(string(body))
		if strings.HasPrefix(trimmed, "[") {
			if safe {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"errors":[{"message":"batched operations are not accepted"}]}`)
				return
			}
			var ops []struct {
				Query string `json:"query"`
			}
			if err := json.Unmarshal([]byte(trimmed), &ops); err != nil || len(ops) > 50 {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"errors":[{"message":"malformed batch"}]}`)
				return
			}
			results := make([]any, len(ops))
			for i, op := range ops {
				results[i] = executeGQL(op.Query, safe)
			}
			_ = json.NewEncoder(w).Encode(results)
			return
		}
		var op struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(body, &op)
		query = op.Query
	}
	if query == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(gqlErrorEnvelope("Must provide query string.", safe))
		return
	}
	_ = json.NewEncoder(w).Encode(executeGQL(query, safe))
}

// gqlStack is the fixed trace the vulnerable server leaks: the shape graphql-js errors take under a
// development-mode Apollo Server.
var gqlStack = []string{
	"GraphQLError: request failed",
	"    at syntaxError (/srv/catalog/node_modules/graphql/error/syntaxError.js:15:10)",
	"    at Parser.expectToken (/srv/catalog/node_modules/graphql/language/parser.js:1397:40)",
	"    at Parser.parseDocument (/srv/catalog/node_modules/graphql/language/parser.js:121:11)",
	"    at processGraphQLRequest (/srv/catalog/node_modules/@apollo/server/dist/cjs/requestPipeline.js:113:34)",
}

func gqlErrorEnvelope(msg string, safe bool) map[string]any {
	e := map[string]any{"message": msg}
	if !safe {
		e["extensions"] = map[string]any{
			"code":      "INTERNAL_SERVER_ERROR",
			"exception": map[string]any{"stacktrace": gqlStack},
		}
	}
	return map[string]any{"errors": []any{e}, "data": nil}
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

// The schema: Query{book(title:String):Book, category:Category}, Book{title,author:String,
// category:Category}, Category{name:String, parent:Category}, Mutation{} (only __typename).
var gqlFields = map[string]map[string]string{
	"Query":    {"book": "Book", "category": "Category"},
	"Mutation": {},
	"Book":     {"title": "String", "author": "String", "category": "Category"},
	"Category": {"name": "String", "parent": "Category"},
}

const (
	gqlSafeMaxDepth   = 5
	gqlSafeMaxAliases = 15
)

func executeGQL(query string, safe bool) map[string]any {
	if strings.Contains(query, "__schema") {
		return map[string]any{"data": json.RawMessage(gqlIntrospection())}
	}
	op, err := parseGQL(query)
	if err != nil {
		return gqlErrorEnvelope("Syntax Error: "+err.Error(), safe)
	}
	if msg := validateGQL(op.root, op.sels); msg != "" {
		return gqlErrorEnvelope(msg, safe)
	}
	if safe {
		if d := gqlDepth(op.sels); d > gqlSafeMaxDepth {
			return gqlErrorEnvelope(fmt.Sprintf("Query depth %d exceeds the maximum of %d", d, gqlSafeMaxDepth), true)
		}
		if n := gqlAliases(op.sels); n > gqlSafeMaxAliases {
			return gqlErrorEnvelope(fmt.Sprintf("Too many aliases (%d); the maximum is %d", n, gqlSafeMaxAliases), true)
		}
	}
	data, errMsg := resolveGQL(op.root, op.sels, gqlObject{typ: op.root}, safe)
	if errMsg != "" {
		return gqlErrorEnvelope(errMsg, safe)
	}
	return map[string]any{"data": data}
}

type gqlObject struct {
	typ   string
	level int // Category: how far up the chain
	book  bool
}

func validateGQL(typ string, sels []gqlSel) string {
	for _, s := range sels {
		if s.name == "__typename" {
			continue
		}
		ft, ok := gqlFields[typ][s.name]
		if !ok {
			return fmt.Sprintf("Cannot query field %q on type %q.", s.name, typ)
		}
		_, isObject := gqlFields[ft]
		switch {
		case isObject && len(s.sub) == 0:
			return fmt.Sprintf("Field %q of type %q must have a selection of subfields.", s.name, ft)
		case !isObject && len(s.sub) > 0:
			return fmt.Sprintf("Field %q must not have a selection since type %q has no subfields.", s.name, ft)
		}
		if isObject {
			if msg := validateGQL(ft, s.sub); msg != "" {
				return msg
			}
		}
	}
	return ""
}

func gqlDepth(sels []gqlSel) int {
	d := 0
	for _, s := range sels {
		if s.sub != nil {
			d = max(d, 1+gqlDepth(s.sub))
		} else {
			d = max(d, 1)
		}
	}
	return d
}

func gqlAliases(sels []gqlSel) int {
	n := 0
	for _, s := range sels {
		if s.alias != "" {
			n++
		}
		n += gqlAliases(s.sub)
	}
	return n
}

func resolveGQL(typ string, sels []gqlSel, obj gqlObject, safe bool) (map[string]any, string) {
	out := map[string]any{}
	for _, s := range sels {
		key := s.name
		if s.alias != "" {
			key = s.alias
		}
		if s.name == "__typename" {
			out[key] = typ
			continue
		}
		switch typ + "." + s.name {
		case "Query.book":
			found, errMsg := gqlFindBook(s.args["title"], safe)
			if errMsg != "" {
				return nil, errMsg
			}
			if !found {
				out[key] = nil
				continue
			}
			v, msg := resolveGQL("Book", s.sub, gqlObject{typ: "Book", book: true}, safe)
			if msg != "" {
				return nil, msg
			}
			out[key] = v
		case "Query.category", "Book.category":
			v, msg := resolveGQL("Category", s.sub, gqlObject{typ: "Category"}, safe)
			if msg != "" {
				return nil, msg
			}
			out[key] = v
		case "Category.parent":
			v, msg := resolveGQL("Category", s.sub, gqlObject{typ: "Category", level: obj.level + 1}, safe)
			if msg != "" {
				return nil, msg
			}
			out[key] = v
		case "Category.name":
			out[key] = "level-" + strconv.Itoa(obj.level)
		case "Book.title":
			out[key] = "seed"
		case "Book.author":
			out[key] = "A. Writer"
		}
	}
	return out, ""
}

// gqlFindBook is the book(title:) resolver. The vulnerable one builds
// `SELECT ... WHERE title = '<title>'`; the safe one binds the value.
func gqlFindBook(title string, safe bool) (bool, string) {
	if safe {
		return title == "seed", ""
	}
	clause := parseQuotedClause(title)
	switch {
	case clause.parseErr:
		return false, "query failed"
	case clause.rest == "":
		return clause.literal == "seed", ""
	}
	m := sqlAndCondition.FindStringSubmatch(clause.rest)
	if m == nil {
		return false, "query failed"
	}
	return clause.literal == "seed" && m[1] == m[2], ""
}

// gqlIntrospection is the schema above in introspection form.
func gqlIntrospection() []byte {
	named := func(kind, name string) map[string]any {
		return map[string]any{"kind": kind, "name": name, "ofType": nil}
	}
	field := func(name string, typ map[string]any, args ...map[string]any) map[string]any {
		if args == nil {
			args = []map[string]any{}
		}
		return map[string]any{"name": name, "args": args, "type": typ}
	}
	str := named("SCALAR", "String")
	doc := map[string]any{"__schema": map[string]any{
		"queryType":    map[string]string{"name": "Query"},
		"mutationType": map[string]string{"name": "Mutation"},
		"types": []map[string]any{
			{"kind": "OBJECT", "name": "Query", "fields": []any{
				field("book", named("OBJECT", "Book"), map[string]any{"name": "title", "type": str, "defaultValue": nil}),
				field("category", named("OBJECT", "Category")),
			}},
			{"kind": "OBJECT", "name": "Mutation", "fields": []any{}},
			{"kind": "OBJECT", "name": "Book", "fields": []any{
				field("title", str), field("author", str), field("category", named("OBJECT", "Category")),
			}},
			{"kind": "OBJECT", "name": "Category", "fields": []any{
				field("name", str), field("parent", named("OBJECT", "Category")),
			}},
			{"kind": "SCALAR", "name": "String", "fields": nil},
		},
	}}
	b, _ := json.Marshal(doc)
	return b
}

// ---------------------------------------------------------------------------
// A small GraphQL parser: operations, aliases, arguments, nested selections. No fragments,
// variables or directives - the probes this fixture answers use none, and a document using them
// gets a syntax error, as from a server that does not support them.
// ---------------------------------------------------------------------------

type gqlSel struct {
	alias, name string
	args        map[string]string
	sub         []gqlSel
}

type gqlOp struct {
	root string
	sels []gqlSel
}

type gqlParser struct {
	s     string
	i     int
	depth int
}

func parseGQL(s string) (gqlOp, error) {
	p := &gqlParser{s: s}
	root := "Query"
	if name := p.peekName(); name == "query" || name == "mutation" {
		p.name()
		if name == "mutation" {
			root = "Mutation"
		}
		if p.peekName() != "" {
			p.name()
		}
	}
	sels, err := p.selectionSet()
	if err != nil {
		return gqlOp{}, err
	}
	p.skip()
	if p.i != len(p.s) {
		return gqlOp{}, fmt.Errorf("Unexpected %q.", p.s[p.i:p.i+1])
	}
	return gqlOp{root: root, sels: sels}, nil
}

func (p *gqlParser) skip() {
	for p.i < len(p.s) {
		switch c := p.s[p.i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			p.i++
		case c == '#':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		default:
			return
		}
	}
}

func (p *gqlParser) peekName() string {
	p.skip()
	j := p.i
	for j < len(p.s) && (p.s[j] == '_' || (p.s[j] >= 'a' && p.s[j] <= 'z') || (p.s[j] >= 'A' && p.s[j] <= 'Z') || (j > p.i && p.s[j] >= '0' && p.s[j] <= '9')) {
		j++
	}
	return p.s[p.i:j]
}

func (p *gqlParser) name() string {
	n := p.peekName()
	p.i += len(n)
	return n
}

func (p *gqlParser) expect(c byte) error {
	p.skip()
	if p.i >= len(p.s) {
		return fmt.Errorf("Expected %q, found <EOF>.", string(c))
	}
	if p.s[p.i] != c {
		return fmt.Errorf("Expected %q, found %q.", string(c), p.s[p.i:p.i+1])
	}
	p.i++
	return nil
}

func (p *gqlParser) selectionSet() ([]gqlSel, error) {
	if err := p.expect('{'); err != nil {
		return nil, err
	}
	p.depth++
	if p.depth > 64 {
		return nil, fmt.Errorf("document nests too deeply to parse")
	}
	sels := []gqlSel{}
	for {
		p.skip()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("Expected Name, found <EOF>.")
		}
		if p.s[p.i] == '}' {
			p.i++
			p.depth--
			return sels, nil
		}
		n := p.name()
		if n == "" {
			return nil, fmt.Errorf("Expected Name, found %q.", p.s[p.i:p.i+1])
		}
		sel := gqlSel{name: n}
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ':' {
			p.i++
			sel.alias = n
			if sel.name = p.name(); sel.name == "" {
				return nil, fmt.Errorf("Expected Name after alias %q.", n)
			}
			p.skip()
		}
		if p.i < len(p.s) && p.s[p.i] == '(' {
			args, err := p.arguments()
			if err != nil {
				return nil, err
			}
			sel.args = args
			p.skip()
		}
		if p.i < len(p.s) && p.s[p.i] == '{' {
			sub, err := p.selectionSet()
			if err != nil {
				return nil, err
			}
			sel.sub = sub
		}
		sels = append(sels, sel)
	}
}

// arguments reads `(name: value, ...)`. Values are string literals (decoded), or a bare token
// (number, boolean, enum) kept as written.
func (p *gqlParser) arguments() (map[string]string, error) {
	p.i++ // '('
	args := map[string]string{}
	for {
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ')' {
			p.i++
			return args, nil
		}
		n := p.name()
		if n == "" {
			return nil, fmt.Errorf("Expected argument name.")
		}
		if err := p.expect(':'); err != nil {
			return nil, err
		}
		p.skip()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("Expected value, found <EOF>.")
		}
		if p.s[p.i] == '"' {
			j := p.i + 1
			for j < len(p.s) && p.s[j] != '"' {
				if p.s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(p.s) {
				return nil, fmt.Errorf("Unterminated string.")
			}
			var v string
			if err := json.Unmarshal([]byte(p.s[p.i:j+1]), &v); err != nil {
				return nil, fmt.Errorf("Invalid string literal.")
			}
			args[n] = v
			p.i = j + 1
			continue
		}
		v := p.name()
		if v == "" {
			j := p.i
			for j < len(p.s) && (p.s[j] == '-' || p.s[j] == '.' || (p.s[j] >= '0' && p.s[j] <= '9')) {
				j++
			}
			if j == p.i {
				return nil, fmt.Errorf("Unexpected %q.", p.s[p.i:p.i+1])
			}
			v = p.s[p.i:j]
			p.i = j
		}
		args[n] = v
	}
}
