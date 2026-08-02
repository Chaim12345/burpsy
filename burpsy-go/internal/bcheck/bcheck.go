// Package bcheck provides the BCheck DSL parser and evaluator.
package bcheck

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
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
	f.body = ""
	if headEnd+len(sep) < len(s) {
		f.body = s[headEnd+len(sep):]
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
		subject := ctx.resolveRef(args[0])
		pattern := ctx.resolveRef(args[1])
		repl := ctx.resolveRef(args[2])
		re, err := regexp.Compile(pattern)
		if err != nil {
			return ""
		}
		// Go's replacement syntax is `$1`, which is also Java's spelling — the
		// corpus's backrefs work as written.
		return re.ReplaceAllString(subject, repl)
	}
	return ctx.resolvePath(name)
}

// innerCall returns the argument text of a call of the form `name(arg)`.
func innerCall(name, prefix string) string {
	return name[len(prefix) : len(name)-1]
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
			j := i + 1
			depth := 1
			var name []byte
			for j < len(s) {
				switch s[j] {
				case '{':
					depth++
					name = append(name, '{')
				case '}':
					depth--
					if depth == 0 {
						break
					}
					name = append(name, '}')
				default:
					name = append(name, s[j])
				}
				j++
			}
			if j < len(s) {
				out.WriteString(ctx.resolveRef(string(name)))
				i = j
			} else {
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

// RunPassive runs passive checks on a response.
func RunPassive(check *Check, ctx *Context) ([]Finding, error) {
	var findings []Finding

	if check.Given != "response" {
		return findings, nil
	}

	// Execute statements. If the check declares `run for each`, iterate the
	// first iterable (one value per run, matching the corpus usage).
	statements := prependDefines(check.Defines, check.Statements)
	if len(check.ForEach) > 0 {
		fe := check.ForEach[0]
		for _, v := range fe.Values {
			// Resolve the value at bind time so a template iterator interpolates.
			ctx.Variables[fe.Iterator] = Value{Type: "str", StringVal: ctx.resolveValue(v)}
			for _, stmt := range statements {
				result, err := executeStatement(stmt, ctx)
				if err != nil {
					return nil, err
				}
				if result != nil {
					findings = append(findings, *result)
				}
			}
		}
		return findings, nil
	}

	// Execute statements
	for _, stmt := range statements {
		result, err := executeStatement(stmt, ctx)
		if err != nil {
			return nil, err
		}
		if result != nil {
			findings = append(findings, *result)
		}
	}

	return findings, nil
}

// prependDefines converts the defines slice to statements and prefixes the body.
func prependDefines(defines []DefineStatement, body []Statement) []Statement {
	out := make([]Statement, 0, len(defines)+len(body))
	for i := range defines {
		out = append(out, &defines[i])
	}
	return append(out, body...)
}

func executeStatement(stmt Statement, ctx *Context) (*Finding, error) {
	switch s := stmt.(type) {
	case *IfStatement:
		return executeIf(s, ctx)
	case *ReportIssueStatement:
		return &Finding{
			IssueName:   ctx.resolveValue(s.IssueName),
			Severity:    Severity(s.Severity),
			Confidence:  Confidence(s.Confidence),
			Description: ctx.resolveValue(s.Description),
			Remediation: ctx.resolveValue(s.Remediation),
		}, nil
	case *DefineStatement:
		// Resolve at bind time so a template define is usable as a plain string
		// by every later reference.
		ctx.Variables[s.Name] = Value{Type: "str", StringVal: ctx.resolveValue(s.Value)}
	case *SendRequestStatement, *SendPayloadStatement:
		// Would send in active checks; the passive evaluator never sends.
	case *RunForEachStatement:
		// Iterate the collection, binding the iterator for each value.
		for _, v := range s.Values {
			ctx.Variables[s.Iterator] = Value{Type: "str", StringVal: ctx.resolveValue(v)}
			for _, body := range s.Body {
				result, err := executeStatement(body, ctx)
				if err != nil {
					return nil, err
				}
				if result != nil {
					return result, nil
				}
			}
		}
	}
	return nil, nil
}

func executeIf(stmt *IfStatement, ctx *Context) (*Finding, error) {
	if evalBoolExpr(stmt.Condition, ctx) {
		for _, s := range stmt.Then {
			result, err := executeStatement(s, ctx)
			if err != nil {
				return nil, err
			}
			if result != nil {
				return result, nil
			}
		}
	} else if stmt.Else != nil {
		for _, s := range stmt.Else {
			result, err := executeStatement(s, ctx)
			if err != nil {
				return nil, err
			}
			if result != nil {
				return result, nil
			}
		}
	}
	return nil, nil
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
