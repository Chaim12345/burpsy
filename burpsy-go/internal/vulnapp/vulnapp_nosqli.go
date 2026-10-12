package vulnapp

// The NoSQL injection family (burpsy-react-ui-v0ei.6): endpoints backed by an in-memory, MongoDB-like
// matcher that honours query operators ($eq, $ne, $gt, $gte, $lt, $lte, $in, $nin, $regex, $exists)
// and a string $where clause evaluated by a small JavaScript expression evaluator, so the defects are
// the real mechanism rather than a canned answer to a known payload.
//
// Vulnerable:
//
//   - POST /nosql/login (JSON) passes the decoded body's username and password straight into the
//     filter, so {"$ne": ...} in place of the password logs in;
//   - GET /nosql/search parses brackets the way Express's qs and PHP do, so category[$ne]=x reaches
//     the filter as an operator object;
//   - GET /nosql/where builds `this.category == '<input>'` as a $where clause: a quote breaks the
//     JavaScript (a MongoServerError wrapping SyntaxError), and '||'a'=='a matches everything;
//   - GET /nosql/report runs the same $where but answers every query that runs with the same
//     constant page, so only the error tells the injection apart;
//   - GET /nosql/lookup passes sku[$op]=x into the filter and answers with a constant page too, so
//     only an unknown operator's MongoServerError shows that operators reach the database.
//
// Safe twins:
//
//   - POST /nosql/safe/login casts each field to a string first, the way String() does, so an
//     operator object becomes the literal "[object Object]";
//   - GET /nosql/safe/search casts the parsed category to a string the same way;
//   - POST /nosql/safe/strict/login answers ANY non-string field with a 500 carrying a Mongoose-style
//     CastError that echoes the value, without ever running the query: every object probe errors
//     alike, so neither a differential nor an error-only-for-the-unknown-operator exists;
//   - GET /nosql/safe/echo ignores the parameter for the result set (constant) and echoes the
//     parsed value back, operators and all: the echo/constant-response control;
//   - GET /nosql/safe/where quotes the input as a JavaScript string literal (escaping quotes and
//     backslashes) before building the $where clause;
//   - GET /nosql/safe/allowlist admits only $eq and $in and refuses every other operator with a 400;
//   - POST /nosql/safe/profile/update is a write with an injectable filter: the check must send it
//     nothing at all;
//   - GET /nosql/safe/report rejects any value holding a quote or a backslash with a validation
//     message that names MongoServerError, so the broken probe AND its repaired control both carry
//     the signature.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const rowNoSQLi = "NoSQL injection"

func nosqliEndpoints() []Endpoint {
	const loginBody = `{"username":"alice","password":"not-her-password"}`
	return []Endpoint{
		{Path: "/nosql/login", Method: http.MethodPost, Row: rowNoSQLi, ContentType: "application/json",
			Body: loginBody,
			Note: "decodes the JSON body and puts username and password into a Mongo-style filter as they are, " +
				"so {\"$ne\": x} for the password logs in"},
		{Path: "/nosql/search?category=books", Row: rowNoSQLi,
			Note: "parses category[$ne]=x into an operator object (qs/PHP bracket syntax) and filters on it"},
		{Path: "/nosql/where?category=books", Row: rowNoSQLi,
			Note: "builds the $where clause this.category == '<input>' by concatenation; a quote is a " +
				"MongoServerError SyntaxError and '||'a'=='a matches every product"},
		{Path: "/nosql/report?category=books", Row: rowNoSQLi,
			Note: "runs the same concatenated $where but answers every query that runs with one constant page, " +
				"so only the MongoServerError on a broken quote shows the injection"},

		{Path: "/nosql/lookup?sku=A-100", Row: rowNoSQLi,
			Note: "passes sku[$op]=x into the filter but answers every query that runs with one constant page; an " +
				"operator MongoDB does not define is a MongoServerError, a valid one is not"},

		{Path: "/nosql/safe/login", Method: http.MethodPost, Row: rowNoSQLi, Safe: true,
			ContentType: "application/json", Body: loginBody,
			Note: "casts username and password to strings before querying, so an operator object is the literal " +
				"\"[object Object]\""},
		{Path: "/nosql/safe/search?category=books", Row: rowNoSQLi, Safe: true,
			Note: "parses brackets but casts the category to a string before querying"},
		{Path: "/nosql/safe/strict/login", Method: http.MethodPost, Row: rowNoSQLi, Safe: true,
			ContentType: "application/json", Body: loginBody,
			Note: "answers any non-string field with a 500 CastError echoing the value, before any query runs: " +
				"every object input fails alike"},
		{Path: "/nosql/safe/echo?q=lamp", Row: rowNoSQLi, Safe: true,
			Note: "ignores q for its (constant) result set and echoes the parsed value, operators included"},
		{Path: "/nosql/safe/where?category=books", Row: rowNoSQLi, Safe: true,
			Note: "quotes the input as a JavaScript string literal before building the $where clause"},
		{Path: "/nosql/safe/allowlist?category=books", Row: rowNoSQLi, Safe: true,
			Note: "accepts only the $eq and $in operators and refuses every other one with a 400, so the " +
				"always-true operators are refused rather than evaluated"},
		{Path: "/nosql/safe/profile/update", Method: http.MethodPost, Row: rowNoSQLi, Safe: true,
			ContentType: "application/json", Body: `{"username":"alice","bio":"hello"}`,
			Note: "a write whose filter takes the username as it is: the check must never send it a probe, " +
				"because a match-everything operator would update every profile"},
		{Path: "/nosql/safe/report?category=books", Row: rowNoSQLi, Safe: true,
			Note: "rejects any quote or backslash with a validation message naming MongoServerError, so the " +
				"repaired control carries the signature too"},
	}
}

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------

type nosqlDoc map[string]any

var nosqlUsers = []nosqlDoc{
	{"username": "alice", "password": "a1ice-Pw-77", "role": "user"},
	{"username": "bob", "password": "b0b-Pw-12", "role": "user"},
	{"username": "carol", "password": "car0l-Pw-90", "role": "admin"},
}

var nosqlProducts = []nosqlDoc{
	{"name": "Field guide", "sku": "A-100", "category": "books", "price": 12.5},
	{"name": "Atlas", "sku": "A-101", "category": "books", "price": 30.0},
	{"name": "Desk lamp", "sku": "H-200", "category": "home", "price": 21.0},
	{"name": "Kettle", "sku": "H-201", "category": "home", "price": 18.0},
	{"name": "Prototype drone", "sku": "X-900", "category": "unreleased", "price": 999.0},
}

// ---------------------------------------------------------------------------
// the matcher
// ---------------------------------------------------------------------------

// errNoSQL is a query error as a MongoDB driver reports it.
type errNoSQL struct{ msg string }

func (e errNoSQL) Error() string { return "MongoServerError: " + e.msg }

// nosqlMatch evaluates a filter against one document: implicit equality for scalars, and the
// operator objects MongoDB honours when a value is an object whose keys start with '$'.
func nosqlMatch(doc nosqlDoc, filter map[string]any) (bool, error) {
	for field, cond := range filter {
		if field == "$where" {
			src, ok := cond.(string)
			if !ok {
				return false, errNoSQL{"$where got bad type"}
			}
			v, err := jsEval(src, doc)
			if err != nil {
				return false, errNoSQL{"Executor error during find command :: caused by :: " + err.Error()}
			}
			if !jsTruthy(v) {
				return false, nil
			}
			continue
		}
		have, present := doc[field]
		ops, isOps := cond.(map[string]any)
		if !isOps {
			if !present || !nosqlEqual(have, cond) {
				return false, nil
			}
			continue
		}
		for op, arg := range ops {
			ok, err := nosqlOp(op, have, present, arg)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
	}
	return true, nil
}

func nosqlOp(op string, have any, present bool, arg any) (bool, error) {
	switch op {
	case "$eq":
		return present && nosqlEqual(have, arg), nil
	case "$ne":
		return !present || !nosqlEqual(have, arg), nil
	case "$gt", "$gte", "$lt", "$lte":
		c, ok := nosqlCompare(have, arg)
		if !present || !ok {
			return false, nil
		}
		switch op {
		case "$gt":
			return c > 0, nil
		case "$gte":
			return c >= 0, nil
		case "$lt":
			return c < 0, nil
		}
		return c <= 0, nil
	case "$in", "$nin":
		list, ok := arg.([]any)
		if !ok {
			return false, errNoSQL{op + " needs an array"}
		}
		in := false
		for _, x := range list {
			in = in || (present && nosqlEqual(have, x))
		}
		if op == "$in" {
			return in, nil
		}
		return !in, nil
	case "$regex":
		pat, ok := arg.(string)
		if !ok {
			return false, errNoSQL{"$regex has to be a string"}
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return false, errNoSQL{"Regular expression is invalid: " + err.Error()}
		}
		s, ok := have.(string)
		return present && ok && re.MatchString(s), nil
	case "$exists":
		want := jsTruthy(arg)
		return present == want, nil
	}
	return false, errNoSQL{"unknown operator: " + op}
}

func nosqlEqual(a, b any) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case float64:
		switch y := b.(type) {
		case float64:
			return x == y
		case json.Number:
			f, err := y.Float64()
			return err == nil && f == x
		}
	}
	return false
}

func nosqlCompare(a, b any) (int, bool) {
	if x, ok := a.(string); ok {
		if y, ok := b.(string); ok {
			return strings.Compare(x, y), true
		}
	}
	if x, ok := a.(float64); ok {
		var y float64
		switch v := b.(type) {
		case float64:
			y = v
		case json.Number:
			f, err := v.Float64()
			if err != nil {
				return 0, false
			}
			y = f
		default:
			return 0, false
		}
		switch {
		case x < y:
			return -1, true
		case x > y:
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func nosqlFind(coll []nosqlDoc, filter map[string]any) ([]nosqlDoc, error) {
	var out []nosqlDoc
	for _, d := range coll {
		ok, err := nosqlMatch(d, filter)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, d)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// request decoding
// ---------------------------------------------------------------------------

// nosqlBracketParams parses a query or form the way Express's qs and PHP do: a[$ne]=x becomes
// {"a": {"$ne": "x"}} and a[$in][]=x becomes {"a": {"$in": ["x"]}}; a plain a=x stays a string.
func nosqlBracketParams(values url.Values) map[string]any {
	out := map[string]any{}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name, rest, nested := strings.Cut(k, "[")
		vals := values[k]
		if !nested {
			out[name] = vals[0]
			continue
		}
		op, tail, _ := strings.Cut(rest, "]")
		obj, _ := out[name].(map[string]any)
		if obj == nil {
			obj = map[string]any{}
			out[name] = obj
		}
		if tail == "[]" {
			list := make([]any, 0, len(vals))
			for _, v := range vals {
				list = append(list, v)
			}
			obj[op] = list
			continue
		}
		obj[op] = vals[0]
	}
	return out
}

// jsString is JavaScript's String(): an object becomes "[object Object]".
func jsString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "undefined"
	case map[string]any:
		return "[object Object]"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = jsString(e)
		}
		return strings.Join(parts, ",")
	case bool:
		return strconv.FormatBool(x)
	case json.Number:
		return x.String()
	}
	return fmt.Sprint(v)
}

func nosqlJSONBody(r *http.Request) (map[string]any, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

func nosqlWrite(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func nosqlNames(docs []nosqlDoc) []string {
	out := []string{}
	for _, d := range docs {
		out = append(out, jsString(d["name"]))
	}
	return out
}

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

func registerNoSQLi(mux *http.ServeMux) {
	login := func(w http.ResponseWriter, filter map[string]any) {
		users, err := nosqlFind(nosqlUsers, filter)
		if err != nil {
			nosqlWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if len(users) == 0 {
			nosqlWrite(w, http.StatusUnauthorized, map[string]string{"status": "error", "message": "Invalid username or password"})
			return
		}
		u := users[0]
		nosqlWrite(w, http.StatusOK, map[string]string{"status": "ok", "message": "Welcome back, " + jsString(u["username"]),
			"role": jsString(u["role"])})
	}
	mux.HandleFunc("/nosql/login", func(w http.ResponseWriter, r *http.Request) {
		body, err := nosqlJSONBody(r)
		if err != nil {
			nosqlWrite(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		login(w, map[string]any{"username": body["username"], "password": body["password"]})
	})
	mux.HandleFunc("/nosql/safe/login", func(w http.ResponseWriter, r *http.Request) {
		body, err := nosqlJSONBody(r)
		if err != nil {
			nosqlWrite(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		login(w, map[string]any{"username": jsString(body["username"]), "password": jsString(body["password"])})
	})
	mux.HandleFunc("/nosql/safe/strict/login", func(w http.ResponseWriter, r *http.Request) {
		body, err := nosqlJSONBody(r)
		if err != nil {
			nosqlWrite(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		for _, f := range []string{"username", "password"} {
			if _, ok := body[f].(string); !ok {
				raw, _ := json.Marshal(body[f])
				nosqlWrite(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf(
					"CastError: Cast to string failed for value %s (type Object) at path %q", raw, f)})
				return
			}
		}
		login(w, map[string]any{"username": body["username"], "password": body["password"]})
	})

	search := func(w http.ResponseWriter, category any) {
		found, err := nosqlFind(nosqlProducts, map[string]any{"category": category})
		if err != nil {
			nosqlWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		nosqlWrite(w, http.StatusOK, map[string]any{"count": len(found), "products": nosqlNames(found)})
	}
	mux.HandleFunc("/nosql/search", func(w http.ResponseWriter, r *http.Request) {
		search(w, nosqlBracketParams(r.URL.Query())["category"])
	})
	mux.HandleFunc("/nosql/safe/search", func(w http.ResponseWriter, r *http.Request) {
		search(w, jsString(nosqlBracketParams(r.URL.Query())["category"]))
	})
	mux.HandleFunc("/nosql/safe/echo", func(w http.ResponseWriter, r *http.Request) {
		nosqlWrite(w, http.StatusOK, map[string]any{"you_searched_for": nosqlBracketParams(r.URL.Query())["q"],
			"products": []string{"Desk lamp", "Kettle"}})
	})

	mux.HandleFunc("/nosql/lookup", func(w http.ResponseWriter, r *http.Request) {
		if _, err := nosqlFind(nosqlProducts, map[string]any{"sku": nosqlBracketParams(r.URL.Query())["sku"]}); err != nil {
			nosqlWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		nosqlWrite(w, http.StatusOK, map[string]string{"status": "lookup logged"})
	})
	mux.HandleFunc("/nosql/safe/allowlist", func(w http.ResponseWriter, r *http.Request) {
		category := nosqlBracketParams(r.URL.Query())["category"]
		if ops, ok := category.(map[string]any); ok {
			for op := range ops {
				if op != "$eq" && op != "$in" {
					nosqlWrite(w, http.StatusBadRequest, map[string]string{"error": "operator not allowed"})
					return
				}
			}
		}
		search(w, category)
	})
	mux.HandleFunc("/nosql/safe/profile/update", func(w http.ResponseWriter, r *http.Request) {
		body, err := nosqlJSONBody(r)
		if err != nil {
			nosqlWrite(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		// The filter is injectable; nothing is stored, the fixture only reports what it would update.
		users, err := nosqlFind(nosqlUsers, map[string]any{"username": body["username"]})
		if err != nil {
			nosqlWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		nosqlWrite(w, http.StatusOK, map[string]int{"updated": len(users)})
	})

	where := func(w http.ResponseWriter, clause string, constant bool) {
		found, err := nosqlFind(nosqlProducts, map[string]any{"$where": clause})
		if err != nil {
			nosqlWrite(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if constant {
			nosqlWrite(w, http.StatusOK, map[string]string{"status": "report queued"})
			return
		}
		nosqlWrite(w, http.StatusOK, map[string]any{"count": len(found), "products": nosqlNames(found)})
	}
	mux.HandleFunc("/nosql/where", func(w http.ResponseWriter, r *http.Request) {
		where(w, "this.category == '"+r.URL.Query().Get("category")+"'", false)
	})
	mux.HandleFunc("/nosql/report", func(w http.ResponseWriter, r *http.Request) {
		where(w, "this.category == '"+r.URL.Query().Get("category")+"'", true)
	})
	mux.HandleFunc("/nosql/safe/where", func(w http.ResponseWriter, r *http.Request) {
		where(w, "this.category == "+jsQuote(r.URL.Query().Get("category")), false)
	})
	mux.HandleFunc("/nosql/safe/report", func(w http.ResponseWriter, r *http.Request) {
		c := r.URL.Query().Get("category")
		if strings.ContainsAny(c, `'"\`) {
			nosqlWrite(w, http.StatusBadRequest, map[string]string{"error": "MongoServerError rejected: the category " +
				"may not contain quotes or backslashes"})
			return
		}
		where(w, "this.category == '"+c+"'", true)
	})
}

// jsQuote writes s as a double-quoted JavaScript string literal.
func jsQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ---------------------------------------------------------------------------
// a small JavaScript expression evaluator for $where
// ---------------------------------------------------------------------------

// jsEval evaluates the expression subset a $where clause in these fixtures can hold: string and
// number literals, true/false, this.<field>, parentheses, !, ==, ===, !=, !==, && and ||, with
// JavaScript's operator precedence and short-circuit values. Anything else is a SyntaxError worded
// the way MongoDB's JavaScript engine words it.
func jsEval(src string, doc nosqlDoc) (any, error) {
	toks, err := jsLex(src)
	if err != nil {
		return nil, err
	}
	p := &jsParser{toks: toks, doc: doc}
	v, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.i != len(p.toks) {
		return nil, errors.New("SyntaxError: missing ; before statement")
	}
	return v, nil
}

type jsTok struct {
	kind string // "str", "num", "ident", "op"
	text string
}

func jsLex(s string) ([]jsTok, error) {
	var out []jsTok
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'' || c == '"':
			var b strings.Builder
			j := i + 1
			closed := false
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					b.WriteByte(s[j+1])
					j += 2
					continue
				}
				if s[j] == c {
					closed = true
					break
				}
				b.WriteByte(s[j])
				j++
			}
			if !closed {
				return nil, errors.New("SyntaxError: unterminated string literal")
			}
			out = append(out, jsTok{"str", b.String()})
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.') {
				j++
			}
			out = append(out, jsTok{"num", s[i:j]})
			i = j
		case c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '$' || s[j] == '.' || s[j] >= 'a' && s[j] <= 'z' ||
				s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			out = append(out, jsTok{"ident", s[i:j]})
			i = j
		default:
			matched := false
			for _, op := range []string{"===", "!==", "==", "!=", "&&", "||", "(", ")", "!"} {
				if strings.HasPrefix(s[i:], op) {
					out = append(out, jsTok{"op", op})
					i += len(op)
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("SyntaxError: illegal character %q", c)
			}
		}
	}
	return out, nil
}

type jsParser struct {
	toks []jsTok
	i    int
	doc  nosqlDoc
}

func (p *jsParser) peek(op string) bool {
	return p.i < len(p.toks) && p.toks[p.i].kind == "op" && p.toks[p.i].text == op
}

func (p *jsParser) or() (any, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek("||") {
		p.i++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		if !jsTruthy(l) {
			l = r
		}
	}
	return l, nil
}

func (p *jsParser) and() (any, error) {
	l, err := p.eq()
	if err != nil {
		return nil, err
	}
	for p.peek("&&") {
		p.i++
		r, err := p.eq()
		if err != nil {
			return nil, err
		}
		if jsTruthy(l) {
			l = r
		}
	}
	return l, nil
}

func (p *jsParser) eq() (any, error) {
	l, err := p.unary()
	if err != nil {
		return nil, err
	}
	for _, op := range []string{"===", "!==", "==", "!="} {
		if p.peek(op) {
			p.i++
			r, err := p.unary()
			if err != nil {
				return nil, err
			}
			same := jsString(l) == jsString(r)
			if op == "===" || op == "!==" {
				same = same && fmt.Sprintf("%T", l) == fmt.Sprintf("%T", r)
			}
			if strings.HasPrefix(op, "!") {
				return !same, nil
			}
			return same, nil
		}
	}
	return l, nil
}

func (p *jsParser) unary() (any, error) {
	if p.peek("!") {
		p.i++
		v, err := p.unary()
		if err != nil {
			return nil, err
		}
		return !jsTruthy(v), nil
	}
	if p.i >= len(p.toks) {
		return nil, errors.New("SyntaxError: expected expression, got end of script")
	}
	t := p.toks[p.i]
	p.i++
	switch t.kind {
	case "str":
		return t.text, nil
	case "num":
		f, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, errors.New("SyntaxError: identifier starts immediately after numeric literal")
		}
		return f, nil
	case "ident":
		switch {
		case t.text == "true":
			return true, nil
		case t.text == "false":
			return false, nil
		case strings.HasPrefix(t.text, "this."):
			return p.doc[strings.TrimPrefix(t.text, "this.")], nil
		}
		return nil, fmt.Errorf("ReferenceError: %s is not defined", t.text)
	case "op":
		if t.text == "(" {
			v, err := p.or()
			if err != nil {
				return nil, err
			}
			if !p.peek(")") {
				return nil, errors.New("SyntaxError: missing ) in parenthetical")
			}
			p.i++
			return v, nil
		}
	}
	return nil, fmt.Errorf("SyntaxError: expected expression, got '%s'", t.text)
}

func jsTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	}
	return true
}
