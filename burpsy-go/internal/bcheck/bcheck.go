// Package bcheck provides the BCheck DSL parser and evaluator.
package bcheck

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Check represents a parsed BCheck file.
type Check struct {
	Name           string
	Version        string
	Given          string
	InsertionKinds []string
	Metadata       Metadata
	Defines        []DefineStatement
	ForEach        []RunForEachStatement
	Statements     []Statement
}

// Metadata holds check metadata.
type Metadata struct {
	Author      string
	Severity    string
	Confidence  string
	Description string
	Reference   []string
}

// Statement represents a BCheck statement.
type Statement interface {
	isStatement()
}

// IfStatement represents an if statement.
type IfStatement struct {
	Condition BoolExpr
	Then      []Statement
	Else      []Statement
}

func (IfStatement) isStatement() {}

// ReportIssueStatement represents a report issue statement.
//
// name, detail and remediation are Values rather than plain strings because the
// corpus interpolates `{…}` into report text (13 passive files build detail or
// remediation lines in a backtick string). Resolution happens at execute time,
// when the check's variables are bound.
type ReportIssueStatement struct {
	IssueName   Value
	Severity    string
	Confidence  string
	Description Value
	Remediation Value
	// Continue distinguishes `report issue and continue` from plain `report
	// issue`, which ends the check. The parser used to consume the phrase and
	// throw the answer away, so every report behaved as `and continue` — a
	// check that should have stopped at its first hit went on to fire again for
	// every later branch that matched. Only 11 of the 264 corpus files ask for
	// `and continue`; the other 253 were getting the wrong control flow.
	Continue bool
}

func (ReportIssueStatement) isStatement() {}

// DefineStatement represents a define statement.
type DefineStatement struct {
	Name  string
	Value Value
}

func (DefineStatement) isStatement() {}

// SendRequestStatement represents a send request statement.
type SendRequestStatement struct {
	Template string
	StoreAs  string
}

func (SendRequestStatement) isStatement() {}

// SendPayloadStatement represents a send payload statement (M3).
type SendPayloadStatement struct {
	StoreAs   string
	Appending bool
	Value     Value
}

func (SendPayloadStatement) isStatement() {}

// RunForEachStatement represents a run for each statement.
type RunForEachStatement struct {
	Iterator string
	Values   []Value
	Body     []Statement
}

func (RunForEachStatement) isStatement() {}

// BoolExpr represents a boolean expression.
// For a comparison, Left/Operator/Right are set. For logical composition
// (Operator "and", "or", "not") the operands live in LHS/RHS instead.
type BoolExpr struct {
	Left     Value
	Operator string
	Right    Value
	LHS      *BoolExpr
	RHS      *BoolExpr
}

// Value represents a BCheck value.
type Value struct {
	Type      string // "str", "tpl", "var", "bool", "int"
	StringVal string
	BoolVal   bool
	IntVal    int
}

// CmpOp represents a comparison operator.
type CmpOp string

const (
	CmpEq       CmpOp = "eq"
	CmpNe       CmpOp = "ne"
	CmpLt       CmpOp = "lt"
	CmpGt       CmpOp = "gt"
	CmpLe       CmpOp = "le"
	CmpGe       CmpOp = "ge"
	CmpContains CmpOp = "contains"
	CmpMatches  CmpOp = "matches"
)

// Severity represents issue severity.
type Severity string

const (
	SeverityHigh   Severity = "High"
	SeverityMedium Severity = "Medium"
	SeverityLow    Severity = "Low"
	SeverityInfo   Severity = "Informational"
)

// Confidence represents issue confidence.
type Confidence string

const (
	ConfidenceCertain   Confidence = "Certain"
	ConfidenceFirm      Confidence = "Firm"
	ConfidenceTentative Confidence = "Tentative"
)

// ParseError represents a parsing error.
type ParseError struct {
	Message string
	Line    int
	Column  int
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d:%d: %s", e.Line, e.Column, e.Message)
}

// Unsupported represents an unsupported feature.
type Unsupported struct {
	Feature string
}

func (u Unsupported) Error() string {
	return fmt.Sprintf("unsupported: %s", u.Feature)
}

// Finding represents a finding from check execution.
type Finding struct {
	CheckName   string
	IssueName   string
	Severity    Severity
	Confidence  Confidence
	Description string
	Remediation string
	RequestID   uint64
}

// IsPassive reports whether the check needs no outbound traffic — it binds to
// the response and never sends. Only these checks can run in a passive scan;
// everything else is counted and reported, never silently run as if passive.
func (c *Check) IsPassive() bool {
	return c.Given == "response" && !containsSend(c.Statements)
}

// NeedsCollaborator reports whether the check requires an interaction server.
// Such checks cannot produce a verdict without a Collaborator-style service,
// and are counted as such at load time rather than run against nothing.
func (c *Check) NeedsCollaborator() bool {
	return containsInteractions(c.Statements)
}

// containsSend walks the statement tree for any outbound send.
func containsSend(stmts []Statement) bool {
	for _, s := range stmts {
		switch t := s.(type) {
		case *SendRequestStatement, *SendPayloadStatement:
			return true
		case *IfStatement:
			if containsSend(t.Then) || containsSend(t.Else) {
				return true
			}
		case *RunForEachStatement:
			if containsSend(t.Body) {
				return true
			}
		}
	}
	return false
}

// containsInteractions walks conditions for a `<type> interactions` construct.
// The parser represents it as an equality with the right operand "interactions".
func containsInteractions(stmts []Statement) bool {
	for _, s := range stmts {
		switch t := s.(type) {
		case *IfStatement:
			if exprHasInteractions(t.Condition) || containsInteractions(t.Then) || containsInteractions(t.Else) {
				return true
			}
		case *RunForEachStatement:
			if containsInteractions(t.Body) {
				return true
			}
		}
	}
	return false
}

func exprHasInteractions(e BoolExpr) bool {
	if strings.EqualFold(e.Operator, "and") || strings.EqualFold(e.Operator, "or") ||
		strings.EqualFold(e.Operator, "not") {
		return (e.LHS != nil && exprHasInteractions(*e.LHS)) ||
			(e.RHS != nil && exprHasInteractions(*e.RHS))
	}
	// A bare `<type> interactions` parses as a comparison with operator "is" and
	// right operand "interactions" (e.g. `http interactions`).
	return strings.EqualFold(e.Operator, "is") &&
		strings.EqualFold(e.Right.StringVal, "interactions")
}

// Context holds the execution context.
type Context struct {
	Variables map[string]Value
	Request   []byte
	Response  []byte
	Host      string
	Port      uint16
	TLS       bool
	Path      string

	respFields *messageFields
	reqFields  *messageFields
	// rng is the `random_str` state, seeded from the message so probes are
	// reproducible per target. ensureRNG seeds it lazily on first use; the
	// zero value means "not yet seeded", and FNV-1a is a bijection so a raw
	// 0 seed is never produced (see ensureRNG).
	rng uint64
}

// NewContext creates a new execution context.
func NewContext() *Context {
	return &Context{
		Variables: make(map[string]Value),
	}
}

// messageFields is the parsed view of a raw HTTP message, extracted once and
// cached so resolving `{latest.response.body}` a hundred times in one check
// does not re-split the bytes each time.
type messageFields struct {
	first  string // request method / response status line
	second string // request target / response status code
	body   string
	// headers is the raw header block, status line excluded, trailing blank
	// line trimmed — what `{latest.response.headers}` resolves to.
	headers string
	// byName maps lowercased header names to their values.
	byName map[string]string
}

func parseMessage(raw []byte) *messageFields {
	f := &messageFields{byName: make(map[string]string)}
	s := string(raw)
	// Split the start line from the header block, then the header block from the
	// body, at the first blank line.
	headEnd := strings.Index(s, "\r\n\r\n")
	sep := "\r\n"
	if headEnd < 0 {
		headEnd = strings.Index(s, "\n\n")
		sep = "\n"
	}
	if headEnd < 0 {
		// No body and no blank line: everything is headers, possibly a bare line.
		headEnd = len(s)
	}
	head := s[:headEnd]
	// headEnd points at the start of the blank-line separator, which is the
	// whole "\r\n\r\n" (4 bytes) or "\n\n" (2 bytes). Skipping only one
	// "\r\n" left the second half of the blank line glued onto the body, so
	// `{base.response.body}` and `{base.request.body}` carried a leading
	// "\r\n" that no server would ever send.
	sepLen := 4
	if sep == "\n" {
		sepLen = 2
	}
	f.body = ""
	if headEnd+sepLen < len(s) {
		f.body = s[headEnd+sepLen:]
	}
	lines := strings.Split(head, "\n")
	if len(lines) > 0 {
		first := strings.TrimSuffix(strings.TrimSuffix(lines[0], "\r"), "\n")
		parts := strings.Fields(first)
		f.first = first
		if len(parts) >= 2 {
			f.second = parts[1]
		}
	}
	headerLines := lines[1:]
	for i := range headerLines {
		headerLines[i] = strings.TrimSuffix(headerLines[i], "\r")
	}
	// The raw header block as the corpus greps it: real bytes, no reconstruction.
	f.headers = strings.TrimRight(strings.Join(headerLines, "\n"), "\n")
	for _, l := range headerLines {
		if idx := strings.IndexByte(l, ':'); idx > 0 {
			name := strings.ToLower(strings.TrimSpace(l[:idx]))
			val := strings.TrimSpace(l[idx+1:])
			if _, seen := f.byName[name]; !seen {
				f.byName[name] = val
			}
		}
	}
	return f
}

// responseFields returns the parsed response, populating the cache on first use.
func (ctx *Context) responseFields() *messageFields {
	if ctx.respFields == nil {
		ctx.respFields = parseMessage(ctx.Response)
	}
	return ctx.respFields
}

// requestFields returns the parsed request, populating the cache on first use.
func (ctx *Context) requestFields() *messageFields {
	if ctx.reqFields == nil {
		ctx.reqFields = parseMessage(ctx.Request)
	}
	return ctx.reqFields
}

// resolveRef resolves a `{…}` reference, which may be a builtin call or an
// object path / variable. Builtins are detected by signature because the parser
// keeps the raw inner text of the reference. Unknown references resolve to the
// empty string, matching Burp's rendering of absent bindings in message text.
func (ctx *Context) resolveRef(name string) string {
	name = strings.TrimSpace(name)
	if v, ok := ctx.Variables[name]; ok {
		return ctx.resolveValue(v)
	}
	switch {
	case strings.HasPrefix(name, "to_lower(") && strings.HasSuffix(name, ")"):
		return strings.ToLower(ctx.resolveRef(innerCall(name, "to_lower(")))
	case strings.HasPrefix(name, "to_upper(") && strings.HasSuffix(name, ")"):
		return strings.ToUpper(ctx.resolveRef(innerCall(name, "to_upper(")))
	case strings.HasPrefix(name, "base64_decode(") && strings.HasSuffix(name, ")"):
		if dec, err := base64.StdEncoding.DecodeString(ctx.resolveRef(innerCall(name, "base64_decode("))); err == nil {
			return string(dec)
		}
		return ""
	case strings.HasPrefix(name, "regex_replace(") && strings.HasSuffix(name, ")"):
		args := splitCallArgs(name[len("regex_replace(") : len(name)-1])
		if len(args) != 3 {
			return ""
		}
		subject := ctx.resolveCallArg(args[0])
		pattern := ctx.resolveCallArg(args[1])
		repl := ctx.resolveCallArg(args[2])
		re, err := regexp.Compile(pattern)
		if err != nil {
			return ""
		}
		// `$1` is Java's spelling: it takes only the digits that follow it, so
		// `$1eyJ…` means group 1 followed by literal text. Go's regexp takes
		// the longest run of [0-9A-Za-z_] as a group *name* — untranslated,
		// `other/tokens/jwt-none-algorithm.bcheck:15` sends a JWT header that
		// is silently empty. Translate before substitution.
		return re.ReplaceAllString(subject, javaBackrefs(repl))
	case strings.HasPrefix(name, "random_str(") && strings.HasSuffix(name, ")"):
		n, err := strconv.Atoi(ctx.resolveCallArg(innerCall(name, "random_str(")))
		if err != nil {
			return ""
		}
		ctx.ensureRNG()
		return randomStr(&ctx.rng, n)
	}
	return ctx.resolvePath(name)
}

// innerCall returns the argument text of a call of the form `name(arg)`.
func innerCall(name, prefix string) string {
	return name[len(prefix) : len(name)-1]
}

// resolveCallArg resolves one argument of a builtin call. The corpus quotes
// string arguments (`"^.*?/"`), wraps references in braces (`{base.request.url}`)
// and passes bare integers to `random_str(8)`. Quoted text is a literal, a
// backtick is a template, braces unwrap to a nested reference, and anything else
// resolves as a path — with a numeric fallback so a bare length reaches
// `random_str` intact.
func (ctx *Context) resolveCallArg(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
		if s[0] == '`' && s[len(s)-1] == '`' {
			return ctx.interpolate(s[1 : len(s)-1])
		}
		if s[0] == '{' && s[len(s)-1] == '}' {
			return ctx.resolveCallArg(s[1 : len(s)-1])
		}
	}
	if _, err := strconv.Atoi(s); err == nil {
		return s
	}
	return ctx.resolveRef(s)
}

// splitCallArgs splits a call's argument list on top-level commas, honouring
// quotes and nested braces.
func splitCallArgs(s string) []string {
	var out []string
	depth := 0
	start := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '`':
			quote = c
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// ensureRNG seeds the random_str state from the response bytes on first use.
// The seed is FNV-1a over the first 512 bytes of the response: same target and
// body give the same probe values, so a reported finding can be re-checked,
// while different targets get different values. `| 1` keeps the xorshift state
// away from the all-zero lane, which xorshift can never leave.
func (ctx *Context) ensureRNG() {
	if ctx.rng != 0 {
		return
	}
	var seed uint64 = 0xcbf29ce484222325
	limit := len(ctx.Response)
	if limit > 512 {
		limit = 512
	}
	for _, b := range ctx.Response[:limit] {
		seed ^= uint64(b)
		seed *= 0x100000001b3
	}
	ctx.rng = seed | 1
}

// javaBackrefs rewrites Java's `$N` group references into Go's `${N}`.
//
// `regex_replace` is Java `Matcher.replaceAll`, where `$` takes only the digits
// that follow it, so `$1eyJhbGci…` means group 1 followed by literal text. Go's
// replacement syntax takes the longest run of `[0-9A-Za-z_]` as a group *name*:
// it looks for a group called `1eyJhbGci…`, finds none, and expands to nothing —
// destroying both the capture and the literal that followed it. That is exactly
// `other/tokens/jwt-none-algorithm.bcheck:15`; untranslated, the check sends a
// token with an empty header and reports on the server's answer to a probe it
// never actually made.
func javaBackrefs(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '$' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			out.WriteString("${")
			out.WriteString(s[i+1 : j])
			out.WriteByte('}')
			i = j
		} else {
			// Step by whole characters so a multi-byte replacement survives.
			// `${1}` already in Go's form passes through untouched, because `{`
			// is not a digit.
			r, size := utf8.DecodeRuneInString(s[i:])
			out.WriteRune(r)
			i += size
		}
	}
	return out.String()
}

// randomAlphabet is what randomStr draws from. Alphanumeric only, so a value is
// safe in a path or a query without escaping.
const randomAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// randomStr draws len characters from randomAlphabet using xorshift64*, seeded
// from the message. The scan is reproducible: re-running a check against the
// same response yields the same probe value. Length is capped at 4096 so a
// hostile `random_str(999999999)` cannot allocate without bound.
func randomStr(state *uint64, n int) string {
	if n > 4096 {
		n = 4096
	}
	if n < 0 {
		return ""
	}
	var out strings.Builder
	out.Grow(n)
	for i := 0; i < n; i++ {
		*state ^= *state >> 12
		*state ^= *state << 25
		*state ^= *state >> 27
		r := *state * 0x2545F4914F6CDD1D
		out.WriteByte(randomAlphabet[(r>>33)%uint64(len(randomAlphabet))])
	}
	return out.String()
}

// resolvePath resolves a dotted path: a binding (`base`/`latest`/`check`), the
// side (`response`/`request`), and the field chain. Passive checks only ever
// name the base exchange, so every binding resolves to the same pair.
func (ctx *Context) resolvePath(p string) string {
	parts := strings.Split(p, ".")
	switch parts[0] {
	case "host":
		if len(parts) == 1 {
			return ctx.Host
		}
	case "path":
		if len(parts) == 1 {
			return ctx.Path
		}
	}
	if len(parts) < 2 {
		return ""
	}
	// Bindings `base`, `latest`, `check` and any named send all refer to the
	// base exchange until a send exists — passive evaluation never sends, so
	// there is no latest distinct from base.
	binding := parts[0]
	side := parts[1]
	if binding != "base" && binding != "latest" && binding != "check" && side != "response" && side != "request" {
		return ""
	}
	rest := parts[2:]
	switch side {
	case "response":
		return ctx.responseField(rest)
	case "request":
		return ctx.requestField(rest)
	}
	return ""
}

// responseField resolves `<binding>.response.<rest…>` against the base response.
func (ctx *Context) responseField(rest []string) string {
	if len(rest) == 0 {
		return string(ctx.Response)
	}
	f := ctx.responseFields()
	switch rest[0] {
	case "body":
		return f.body
	case "status_code":
		return f.second
	case "headers":
		if len(rest) > 1 {
			return f.byName[strings.ToLower(rest[1])]
		}
		return f.headers
	case "url":
		return ctx.urlField(rest[1:])
	case "method":
		// Not meaningful for a response, but harmless to answer.
		return f.first
	}
	return ""
}

// requestField resolves `<binding>.request.<rest…>` against the base request.
func (ctx *Context) requestField(rest []string) string {
	if len(rest) == 0 {
		return string(ctx.Request)
	}
	f := ctx.requestFields()
	switch rest[0] {
	case "body":
		return f.body
	case "method":
		if method := firstField(f.first); method != "" {
			return method
		}
		return f.first
	case "headers":
		if len(rest) > 1 {
			return f.byName[strings.ToLower(rest[1])]
		}
		return f.headers
	case "query_string":
		if idx := strings.IndexByte(ctx.Path, '?'); idx >= 0 {
			return ctx.Path[idx+1:]
		}
		return ""
	case "path":
		return ctx.Path
	case "url":
		return ctx.urlField(rest[1:])
	}
	return ""
}

// urlField resolves `<binding>.(request|response).url.<rest…>`. With no rest it
// is the full URL the request was issued to; with a field it is that component.
func (ctx *Context) urlField(rest []string) string {
	scheme := "http"
	if ctx.TLS {
		scheme = "https"
	}
	host := ctx.Host
	if ctx.Port != 0 {
		if !(ctx.Port == 80 && !ctx.TLS) && !(ctx.Port == 443 && ctx.TLS) {
			host = fmt.Sprintf("%s:%d", host, ctx.Port)
		}
	}
	base := scheme + "://" + host
	if len(rest) == 0 {
		return base + ctx.Path
	}
	switch rest[0] {
	case "host":
		return ctx.Host
	case "port":
		return strconv.Itoa(int(ctx.Port))
	case "file":
		return ctx.Path
	case "path":
		return ctx.Path
	}
	return ""
}

// firstField returns the first whitespace-delimited token of a start line.
func firstField(line string) string {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// interpolate expands `{…}` and the documented escapes inside a backtick string.
// Literal `"…"` strings are never passed through here, which is what protects a
// regex's braces from being read as references.
func (ctx *Context) interpolate(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				switch s[i+1] {
				case '{':
					out.WriteByte('{')
					i++
				case '}':
					out.WriteByte('}')
					i++
				case 'r':
					out.WriteByte('\r')
					i++
				case 'n':
					out.WriteByte('\n')
					i++
				case 't':
					out.WriteByte('\t')
					i++
				case '\\':
					out.WriteByte('\\')
					i++
				default:
					out.WriteByte('\\')
				}
			} else {
				out.WriteByte('\\')
			}
		case '{':
			// Match the closing brace at depth zero so a nested call survives.
			//
			// The scan is written with if/else rather than a switch on purpose:
			// a `break` inside a switch binds to the switch, not to this loop,
			// so the earlier version never stopped at the closing brace. j then
			// always reached len(s), the "did we close?" test (`j < len(s)`)
			// was always false, and every reference in every backtick template
			// was emitted literally as `{name}`. Report detail and remediation
			// lines are the main consumers of templates, so the corpus checks
			// that build them were filing findings with un-substituted text.
			// `closed` now records termination explicitly instead of inferring
			// it from the cursor.
			j := i + 1
			depth := 1
			var name []byte
			closed := false
			for j < len(s) {
				c := s[j]
				if c == '{' {
					depth++
					name = append(name, '{')
				} else if c == '}' {
					depth--
					if depth == 0 {
						closed = true
						break
					}
					name = append(name, '}')
				} else {
					name = append(name, c)
				}
				j++
			}
			if closed {
				out.WriteString(ctx.resolveRef(string(name)))
				i = j
			} else {
				// An unterminated `{` is literal text, not a broken reference.
				out.WriteByte('{')
			}
		default:
			out.WriteByte(s[i])
		}
	}
	return out.String()
}

// resolveVar resolves a variable reference against the context.
func (ctx *Context) resolveVar(name string) string {
	return ctx.resolveRef(name)
}

// resolveValue resolves a Value to its string form.
func (ctx *Context) resolveValue(v Value) string {
	switch v.Type {
	case "var":
		return ctx.resolveRef(v.StringVal)
	case "tpl":
		return ctx.interpolate(v.StringVal)
	case "bool":
		if v.BoolVal {
			return "true"
		}
		return "false"
	case "int":
		return strconv.Itoa(v.IntVal)
	default:
		return v.StringVal
	}
}

// execOutcome is what executing a statement or a block produced.
//
// The evaluator used to signal "stop" by returning a non-nil *Finding, which
// conflated two independent things — that a finding exists, and that the check
// is over — so `report issue and continue` could not be expressed at all and a
// block could never report twice.
type execOutcome struct {
	findings []Finding
	// halt is set by a plain `report issue`. It unwinds every enclosing block,
	// including all remaining `run for each` iterations.
	halt bool
}

// fork returns a copy of the context whose variable bindings are independent.
//
// Burp deep-copies the context per iteration (decompiled `Zpa0.ZI` calls `ZF`
// to copy), so a binding made in one iteration is invisible to the next. The
// previous implementation mutated one shared map, which meant a `define` or an
// iterator bound inside iteration n was still visible in iteration n+1 — and a
// check whose later iteration only matched because of a leaked binding reported
// a finding that its own logic did not justify.
//
// The parsed-message caches are deliberately shared rather than copied: they
// are derived purely from Request/Response, which no statement can modify, so
// sharing them is both correct and what keeps a large cartesian product from
// re-splitting the same response bytes on every combination.
func (ctx *Context) fork() *Context {
	c := *ctx
	c.Variables = make(map[string]Value, len(ctx.Variables))
	for k, v := range ctx.Variables {
		c.Variables[k] = v
	}
	return &c
}

// RunPassive runs passive checks on a response.
func RunPassive(check *Check, ctx *Context) ([]Finding, error) {
	if check.Given != "response" {
		return nil, nil
	}

	statements := prependDefines(check.Defines, check.Statements)
	if len(check.ForEach) > 0 {
		return runForEachProduct(check, ctx, statements)
	}

	out, err := executeBlock(statements, ctx)
	if err != nil {
		return nil, err
	}
	return out.findings, nil
}

// runForEachProduct executes the check once per combination of its `run for
// each` iterables.
//
// With k iterables this is the cartesian product — ∏nᵢ executions — which is
// what Burp does (`Zpa0.ZI` builds the product explicitly). The previous
// implementation walked `check.ForEach[0]` and ignored the rest, so a check
// declaring two lists ran n₁ times instead of n₁×n₂ and silently never tested
// most of what it was asked to test. `run for each` appears in 30.7% of the
// 264-file corpus, so this was not a corner.
//
// Iterators are bound in declaration order into the same forked context, so a
// later iterable's values may reference an earlier iterator.
func runForEachProduct(check *Check, base *Context, statements []Statement) ([]Finding, error) {
	dims := make([]int, len(check.ForEach))
	total := 1
	for i, fe := range check.ForEach {
		dims[i] = len(fe.Values)
		total *= dims[i]
	}
	// An empty iterable makes the whole product empty. Running the body once
	// with the iterator unbound would be the tempting alternative and is wrong:
	// it would test a combination the check never declared.
	if total == 0 {
		return nil, nil
	}

	// Warm the message caches once on the shared parent so every fork inherits
	// them instead of re-parsing the response per combination.
	base.responseFields()
	base.requestFields()

	var findings []Finding
	idx := make([]int, len(dims))
	for n := 0; n < total; n++ {
		iter := base.fork()
		for i, fe := range check.ForEach {
			iter.Variables[fe.Iterator] = Value{Type: "str", StringVal: iter.resolveValue(fe.Values[idx[i]])}
		}
		out, err := executeBlock(statements, iter)
		if err != nil {
			return nil, err
		}
		findings = append(findings, out.findings...)
		if out.halt {
			return findings, nil
		}
		// Advance the odometer, least-significant iterable first.
		for i := len(idx) - 1; i >= 0; i-- {
			idx[i]++
			if idx[i] < dims[i] {
				break
			}
			idx[i] = 0
		}
	}
	return findings, nil
}

// executeBlock runs statements in order, stopping at the first halt.
func executeBlock(stmts []Statement, ctx *Context) (execOutcome, error) {
	var out execOutcome
	for _, stmt := range stmts {
		o, err := executeStatement(stmt, ctx)
		if err != nil {
			return out, err
		}
		out.findings = append(out.findings, o.findings...)
		if o.halt {
			out.halt = true
			return out, nil
		}
	}
	return out, nil
}

// prependDefines converts the defines slice to statements and prefixes the body.
func prependDefines(defines []DefineStatement, body []Statement) []Statement {
	out := make([]Statement, 0, len(defines)+len(body))
	for i := range defines {
		out = append(out, &defines[i])
	}
	return append(out, body...)
}

func executeStatement(stmt Statement, ctx *Context) (execOutcome, error) {
	switch s := stmt.(type) {
	case *IfStatement:
		return executeIf(s, ctx)
	case *ReportIssueStatement:
		// Plain `report issue` ends the check; `report issue and continue` does
		// not. The ambiguity BCHECK-M2-SEMANTICS.md records is what "ends the
		// check" means inside `run for each`, and 77 corpus files hinge on it.
		// Taken here as: the whole check, every remaining iteration included.
		//
		// The alternative — end only the current iteration and carry on with
		// the next — is worse for the reason the corpus shows: an iterator is
		// almost always a list of candidate paths or payloads probing for one
		// condition, so continuing after a hit re-reports the same issue once
		// per surviving value. That turns one finding into n and makes a report
		// count meaningless, which is exactly the failure this project refuses.
		// A check that genuinely wants a finding per value says `and continue`.
		return execOutcome{
			findings: []Finding{{
				IssueName:   ctx.resolveValue(s.IssueName),
				Severity:    Severity(s.Severity),
				Confidence:  Confidence(s.Confidence),
				Description: ctx.resolveValue(s.Description),
				Remediation: ctx.resolveValue(s.Remediation),
			}},
			halt: !s.Continue,
		}, nil
	case *DefineStatement:
		// Resolve at bind time so a template define is usable as a plain string
		// by every later reference.
		ctx.Variables[s.Name] = Value{Type: "str", StringVal: ctx.resolveValue(s.Value)}
	case *SendRequestStatement, *SendPayloadStatement:
		// Would send in active checks; the passive evaluator never sends.
	case *RunForEachStatement:
		return executeForEach(s, ctx)
	}
	return execOutcome{}, nil
}

// executeForEach runs a `run for each` that appears as a statement in a body,
// as opposed to the check-level block handled by runForEachProduct. Each value
// gets its own forked context for the same reason: a binding made while testing
// one value must not survive into the next.
func executeForEach(s *RunForEachStatement, ctx *Context) (execOutcome, error) {
	var out execOutcome
	for _, v := range s.Values {
		iter := ctx.fork()
		iter.Variables[s.Iterator] = Value{Type: "str", StringVal: iter.resolveValue(v)}
		o, err := executeBlock(s.Body, iter)
		if err != nil {
			return out, err
		}
		out.findings = append(out.findings, o.findings...)
		if o.halt {
			out.halt = true
			return out, nil
		}
	}
	return out, nil
}

func executeIf(stmt *IfStatement, ctx *Context) (execOutcome, error) {
	if evalBoolExpr(stmt.Condition, ctx) {
		return executeBlock(stmt.Then, ctx)
	}
	if stmt.Else != nil {
		return executeBlock(stmt.Else, ctx)
	}
	return execOutcome{}, nil
}

// evalBoolExpr evaluates a boolean expression against the context.
func evalBoolExpr(expr BoolExpr, ctx *Context) bool {
	switch expr.Operator {
	case "and":
		if expr.LHS == nil || expr.RHS == nil {
			return false
		}
		return evalBoolExpr(*expr.LHS, ctx) && evalBoolExpr(*expr.RHS, ctx)
	case "or":
		if expr.LHS == nil || expr.RHS == nil {
			return false
		}
		return evalBoolExpr(*expr.LHS, ctx) || evalBoolExpr(*expr.RHS, ctx)
	case "not":
		if expr.LHS == nil {
			return false
		}
		return !evalBoolExpr(*expr.LHS, ctx)
	}

	left := ctx.resolveValue(expr.Left)
	right := ctx.resolveValue(expr.Right)

	switch expr.Operator {
	case "eq", "is":
		return left == right
	case "ne":
		return left != right
	case "contains":
		return contains(left, right)
	case "in":
		// `x in y` — containment with the needle on the LEFT.
		return contains(right, left)
	case "matches":
		// The pattern is taken raw, never interpolated — this is what lets a
		// literal regex keep its braces (`"oy2[a-z0-9]{43}"`).
		re, err := regexp.Compile(expr.Right.StringVal)
		if err != nil {
			return false
		}
		return re.MatchString(left)
	}
	return false
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
