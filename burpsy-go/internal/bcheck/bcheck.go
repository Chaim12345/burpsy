// Package bcheck provides the BCheck DSL parser and evaluator.
package bcheck

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
)

// maxForEachDim bounds a single `run for each` list. A check loaded from an
// untrusted source could otherwise declare an arbitrarily large list.
const maxForEachDim = 10000

// maxForEachProduct bounds the cartesian product of all `run for each` lists in
// one check. Two 10k lists would be 100M iterations; this cap stops the product
// before it becomes a denial-of-service via the evaluator.
const maxForEachProduct = 100000

// compiledRegexCache memoises regex compilations keyed by pattern, so the
// `matches` operator and `regex_replace` builtin do not recompile the same
// literal on every iteration of a `run for each` product. Go's regexp is RE2
// (linear-time, no catastrophic backtracking), so this is a performance fix, not
// a ReDoS fix.
var compiledRegexCache sync.Map // map[string]*regexp.Regexp

// compileRegex returns a cached *regexp.Regexp for pattern, sharing one
// compilation across every call site that uses the same literal.
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := compiledRegexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	actual, _ := compiledRegexCache.LoadOrStore(pattern, re)
	return actual.(*regexp.Regexp), nil
}

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
	// Template is the raw-request form (`send request: `GET / …`). Mutually exclusive with
	// Modifiers: a check that names a raw request has no modifier clauses, and a check that
	// names clauses has no raw request.
	Template string
	// Modifiers are the structural form's clauses — `path:`, `method:`, `replacing headers:` —
	// in source order, applied to a fresh copy of the base request in that order. See
	// buildRequest in active.go.
	Modifiers []RequestModifier
	StoreAs   string
}

func (SendRequestStatement) isStatement() {}

// SendPayloadStatement represents a send payload statement (M3).
type SendPayloadStatement struct {
	StoreAs   string
	Appending bool
	Value     Value
}

func (SendPayloadStatement) isStatement() {}

// RunToolStatement represents a run tool statement: an outbound call to an
// external security tool (sqlmap, jwt_tool, …), allowlisted by the caller.
// The tool name and every arg resolve at execute time like any other value, so
// a check can pass `{base.request.url}` to a tool. The result binds under
// StoreAs and is read back as `{<name>.stdout}`, `{<name>.stderr}` and
// `{<name>.exit_code}`.
type RunToolStatement struct {
	// Tool is the tool name as written in the check — `sqlmap`, not a path. The
	// caller maps it to an executable through its allowlist; the check never
	// names a binary. Refused, not resolved, when the caller has no runner.
	Tool Value
	// StoreAs is the binding name the result is addressable as, from the
	// `called <name>` clause.
	StoreAs string
	// Args are the command-line arguments, resolved at execute time.
	Args []Value
}

func (RunToolStatement) isStatement() {}

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
	// Param is the name of the insertion point this finding fired at, when it
	// fired inside a `given insertion point` check. Empty outside one — a
	// per-host or per-request finding is about a resource, not a parameter, and
	// saying so is what keeps a report's Parameter column from lying.
	Param string
}

// IsPassive reports whether the check needs no outbound traffic — it binds to
// the response and never sends. Only these checks can run in a passive scan;
// everything else is counted and reported, never silently run as if passive.
//
// A `run tool` statement is outbound activity too — it executes an external
// process — so a check carrying one is never passive.
func (c *Check) IsPassive() bool {
	return c.Given == "response" && !containsSend(c.Statements) && !containsTool(c.Statements)
}

// NeedsCollaborator reports whether the check requires an interaction server.
// Such checks cannot produce a verdict without a Collaborator-style service,
// and are counted as such at load time rather than run against nothing.
func (c *Check) NeedsCollaborator() bool {
	return containsInteractions(c.Statements)
}

// NeedsTool reports whether the check invokes an external tool via `run tool`.
// Such a check needs a caller-configured tool runner; without one it is counted
// at load time (LoadReport.Tools) and refused, never run against nothing — the
// same honest bucket as NeedsCollaborator.
func (c *Check) NeedsTool() bool {
	return containsTool(c.Statements)
}

// M2Runnable reports whether the evaluator can run this check with a sender but
// no interaction server — the active set the audit engine dispatches.
func (c *Check) M2Runnable() bool {
	return !c.NeedsCollaborator() &&
		c.Given != "insertion point" &&
		!containsSendPayload(c.Statements)
}

func containsSendPayload(stmts []Statement) bool {
	for _, s := range stmts {
		switch t := s.(type) {
		case *SendPayloadStatement:
			return true
		case *IfStatement:
			if containsSendPayload(t.Then) || containsSendPayload(t.Else) {
				return true
			}
		case *RunForEachStatement:
			if containsSendPayload(t.Body) {
				return true
			}
		}
	}
	return false
}

// containsTool walks the statement tree for any `run tool` statement.
func containsTool(stmts []Statement) bool {
	for _, s := range stmts {
		switch t := s.(type) {
		case *RunToolStatement:
			return true
		case *IfStatement:
			if containsTool(t.Then) || containsTool(t.Else) {
				return true
			}
		case *RunForEachStatement:
			if containsTool(t.Body) {
				return true
			}
		}
	}
	return false
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
	// UserAgent is the reserved `{user_agent}` — Burp's "Returns Burp's user agent", here the
	// User-Agent the scanner's sender puts on requests that carry none (u411). Empty falls back to the
	// base request's own User-Agent, and a context with neither leaves the reference unresolved.
	UserAgent string
	// EnumerateOptions is the enumerator tuning a `given insertion point` check expands under: the
	// audit run's own (its insertion-point cap, nested switch, manual spans and the operator's
	// skip-all-tests parameter list) when the scanner supplies one. Nil enumerates with the engine
	// default, which is what a direct evaluator call has always done.
	EnumerateOptions *EnumerateOptions

	// sink performs the outbound half of `send request` and `send payload`. Nil means the check
	// is being evaluated passively, where a send is a no-op — RunPassive never sets it, RunActive
	// always does.
	sink Sink
	// target is the one authority every send goes to: the scanned exchange's own. The check
	// chooses the bytes; it never chooses the connection.
	target *Target
	// point is the insertion point `send payload` may write, for a `given insertion point` run.
	// Nil everywhere else, which is what makes `send payload` outside such a check an error
	// rather than a no-op.
	point *InsertionPoint
	// toolRunner executes the outbound half of `run tool`. Nil means the caller
	// supplied no tool allowlist — a `run tool` statement is then refused as
	// ActiveUnsupported rather than skipped, exactly as a check that needs a
	// Collaborator is refused rather than run against nothing.
	toolRunner ToolRunner
	// toolCtx is the caller's context for the tool seam, when one was attached.
	// runTool hands it to the runner so a hung tool is killed with the audit
	// that spawned it. Nil defers to the runner's own timeout.
	toolCtx context.Context
	// tools records every tool run in order; the `called` name addresses its own entry. Always
	// a fresh list per point and per `run for each` iteration, like sent — a later iteration
	// must not see an earlier one's `{probe.stdout}`.
	tools []boundTool
	// sent records every send in order; the last is `latest.*` and a `called` name addresses its
	// own entry. Always a fresh list per point and per `run for each` iteration — a later
	// iteration must not see an earlier one's `{check.response}`.
	sent []boundSend
	// baseReq is the parsed base request, cached on first use.
	baseReq *core.RequestEdit
	// unresolved records `{…}` paths the check referenced that this context could not supply. A
	// non-empty set is a check written against data this engine does not expose — a bug to fix,
	// not a finding.
	unresolved map[string]bool
	// declined records insertion places the enumerator refused to splice into while real points
	// still ran. The check ran; it just did not run everywhere. See RunActive.
	declined []string

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

// SetToolRunner attaches the allowlist runner `run tool` statements execute
// through. The active scanner calls this alongside setting the sink; without
// it a tool check is refused (NeedsTool + nil runner) rather than run against
// nothing.
func (ctx *Context) SetToolRunner(r ToolRunner) {
	ctx.toolRunner = r
}

// SetToolContext attaches the caller's context to the tool seam, so a tool
// run is cancelled with the audit that spawned it — a hung allowlisted tool
// must not outlive the scan that asked for it. Nil means the runner bounds the
// run with its own timeout alone.
func (ctx *Context) SetToolContext(c context.Context) {
	ctx.toolCtx = c
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
	// raw is the whole message as received — what `{x.response}` (no field) resolves to.
	raw string
}

func parseMessage(raw []byte) *messageFields {
	s := string(raw)
	f := &messageFields{byName: make(map[string]string), raw: s}
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
	// The three single-argument builtins resolve their argument through
	// resolveCallArg, not resolveRef. resolveRef resolves a *reference* — a
	// variable name or a path — so it answers "" for the two argument shapes the
	// corpus actually writes: a quoted literal (`base64_decode("DA==")`, which is
	// how all five of the corpus's base64_decode calls are written) and a
	// brace-wrapped reference (`to_lower({crlf.response.headers})`). Both used to
	// resolve to "", and "" is also what a genuinely empty value looks like, so
	// every one of those calls silently compared against nothing. Only a bare path
	// (`to_lower(check1.response.body)`) ever worked. regex_replace already routed
	// its arguments correctly; these three did not.
	case strings.HasPrefix(name, "to_lower(") && strings.HasSuffix(name, ")"):
		return strings.ToLower(ctx.resolveCallArg(innerCall(name, "to_lower(")))
	case strings.HasPrefix(name, "to_upper(") && strings.HasSuffix(name, ")"):
		return strings.ToUpper(ctx.resolveCallArg(innerCall(name, "to_upper(")))
	case strings.HasPrefix(name, "base64_decode(") && strings.HasSuffix(name, ")"):
		return base64DecodeTolerant(ctx.resolveCallArg(innerCall(name, "base64_decode(")))
	case strings.HasPrefix(name, "regex_replace(") && strings.HasSuffix(name, ")"):
		args := splitCallArgs(name[len("regex_replace(") : len(name)-1])
		if len(args) != 3 {
			return ""
		}
		subject := ctx.resolveCallArg(args[0])
		pattern := ctx.resolveCallArg(args[1])
		repl := ctx.resolveCallArg(args[2])
		re, err := compileRegex(pattern)
		if err != nil {
			return ""
		}
		// `$1` is Java's spelling: it takes only the digits that follow it, so
		// `$1eyJ…` means group 1 followed by literal text. Go's regexp takes
		// the longest run of [0-9A-Za-z_] as a group *name* — untranslated,
		// `other/tokens/jwt-none-algorithm.bcheck:15` sends a JWT header that
		// is silently empty. Translate before substitution.
		return re.ReplaceAllString(subject, javaBackrefs(repl))
	// The hash functions (u411) answer lowercase hex, as Burp's reference examples do. Those examples
	// hash "Hello" yet show the digests of "hello" (aaf4c61d…, 2cf24dba…, 5d41402a…); the input is
	// hashed as given here — a check that lowercases first can say so with to_lower. The reference
	// spells one example MD5(…), so the name is matched case-insensitively.
	case hasCallPrefix(name, "sha1("):
		sum := sha1.Sum([]byte(ctx.resolveCallArg(innerCall(name, name[:len("sha1(")]))))
		return hex.EncodeToString(sum[:])
	case hasCallPrefix(name, "sha256("):
		sum := sha256.Sum256([]byte(ctx.resolveCallArg(innerCall(name, name[:len("sha256(")]))))
		return hex.EncodeToString(sum[:])
	case hasCallPrefix(name, "md5("):
		sum := md5.Sum([]byte(ctx.resolveCallArg(innerCall(name, name[:len("md5(")]))))
		return hex.EncodeToString(sum[:])
	case strings.HasPrefix(name, "base64_encode(") && strings.HasSuffix(name, ")"):
		return base64.StdEncoding.EncodeToString([]byte(ctx.resolveCallArg(innerCall(name, "base64_encode("))))
	case strings.HasPrefix(name, "random_str(") && strings.HasSuffix(name, ")"):
		n, err := strconv.Atoi(ctx.resolveCallArg(innerCall(name, "random_str(")))
		if err != nil {
			return ""
		}
		ctx.ensureRNG()
		return randomStr(&ctx.rng, n)
	}
	s, ok := ctx.resolvePathOpt(name)
	if !ok {
		// An absent binding renders empty in message text, matching Burp — but it is still
		// recorded, so a check that keeps referencing a path this engine cannot supply is a
		// diagnosable gap rather than a silent comparison against nothing.
		ctx.recordUnresolved(name)
		return ""
	}
	return s
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

// base64DecodeTolerant decodes the standard base64 alphabet the way the corpus
// actually needs it, and the way `crates/bcheck/src/funcs.rs:184` does: padding
// is optional, `=` ends the value, and a character outside the alphabet is
// skipped rather than failing the whole decode.
//
// `encoding/base64`'s StdEncoding is the wrong tool here even though it is the
// obvious one. It requires padding and rejects whitespace, so the two shapes the
// corpus contains — `"SGVsbG8"` (unpadded) and `"SGVs bG8="` (wrapped, so the
// value carries a space) — both decoded to `""` on the Go side while decoding to
// `"Hello"` on the Rust side. An empty string is exactly what a check that found
// nothing also produces, so the failure was invisible: a check whose whole
// premise was a decoded value silently compared against nothing.
//
// A value the corpus cannot have meant is still not invented: bits that do not
// complete a byte are dropped, matching the Rust walk bit for bit.
//
// Divergence from Rust, and Go is the stronger side: Rust returns
// `String::from_utf8_lossy`, so a genuinely binary decode becomes U+FFFD — its
// own doc names this a known limitation, citing
// `PathSuffix_WAF_Proxy.bcheck:32-34`, which decodes `"DA=="`, `"oA=="` and
// `"hQ=="` to `\x0C`, `\xA0`, `\x85`. A Go string is a byte string, so those
// bytes survive here and the check means what it says. Nothing is lost by not
// replicating the lossy conversion.
func base64DecodeTolerant(s string) string {
	// val maps one alphabet character to its 6 bits, or reports that it is not
	// part of the alphabet at all.
	val := func(c byte) (byte, bool) {
		switch {
		case c >= 'A' && c <= 'Z':
			return c - 'A', true
		case c >= 'a' && c <= 'z':
			return c - 'a' + 26, true
		case c >= '0' && c <= '9':
			return c - '0' + 52, true
		case c == '+':
			return 62, true
		case c == '/':
			return 63, true
		default:
			return 0, false
		}
	}
	out := make([]byte, 0, len(s)*3/4+1)
	var acc uint32
	var bits uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			break
		}
		v, ok := val(c)
		if !ok {
			continue
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return string(out)
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

// resolvePathOpt resolves a dotted path: a binding (`base`/`latest`/a named send), the side
// (`response`/`request`), and the field chain. ok is false when the context cannot supply the
// path at all — an unknown binding, a side it has no data for — which is what makes a
// comparison against it false rather than a comparison against the empty string.
//
// Bare `response.*` / `request.*` mean the base exchange, as does `check.*` (the Go port's
// historical alias). A passive context has no sends, so `latest` resolves to base there too.
func (ctx *Context) resolvePathOpt(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if v, ok := ctx.Variables[p]; ok {
		return ctx.resolveValue(v), true
	}
	parts := strings.Split(p, ".")
	switch parts[0] {
	case "host":
		if len(parts) == 1 {
			return ctx.Host, true
		}
		return "", false
	case "path":
		if len(parts) == 1 {
			return ctx.Path, true
		}
		return "", false
	case "user_agent":
		if len(parts) != 1 {
			return "", false
		}
		if ctx.UserAgent != "" {
			return ctx.UserAgent, true
		}
		if ua := ctx.requestFields().byName["user-agent"]; ua != "" {
			return ua, true
		}
		return "", false
	}
	// A tool binding is `{<called>.stdout|stderr|exit_code}` — the run recorded
	// under that name. Only the three tool fields take this branch: a send and a
	// tool may share a `called` name in one check, and `{probe.response}` must
	// still reach the send-binding logic below rather than be shadowed by the
	// tool run. A name with no matching component falls through and resolves
	// false at the bottom, exactly as it would without the tool branch.
	if len(parts) >= 2 && (parts[1] == "stdout" || parts[1] == "stderr" || parts[1] == "exit_code") {
		if t := ctx.boundTool(parts[0]); t != nil {
			switch parts[1] {
			case "stdout":
				return t.stdout, true
			case "stderr":
				return t.stderr, true
			case "exit_code":
				return strconv.Itoa(t.exitCode), true
			}
		}
	}

	var bind, side string
	switch parts[0] {
	case "response", "request", "check":
		bind, side = "base", parts[0]
	default:
		if len(parts) < 2 {
			return "", false
		}
		bind, side = parts[0], parts[1]
	}
	if side != "response" && side != "request" {
		return "", false
	}
	rest := parts[2:]
	if bind == "base" {
		switch side {
		case "response":
			return ctx.baseResponseField(rest), true
		case "request":
			return ctx.baseRequestField(rest), true
		}
	}
	b := ctx.bound(bind)
	if b == nil {
		return "", false
	}
	// Every send goes to the scanned exchange's own authority (see target), so a sent request's
	// scheme and port are that authority's — the request bytes carry neither reliably: an
	// origin-form target has no scheme, and a Host header may omit the port (u411).
	if len(rest) == 2 && rest[0] == "url" {
		switch rest[1] {
		case "protocol":
			return ctx.baseURLField([]string{"protocol"}), true
		case "port":
			if v, ok := b.field(side, rest); ok && v != "" {
				return v, true
			}
			return ctx.baseURLField([]string{"port"}), true
		}
	}
	return b.field(side, rest)
}

// boundTool resolves a tool binding by its `called` name: the most recent run
// that was named it. A name that never ran resolves to nil — absent, which
// makes a comparison false, never an empty string.
func (ctx *Context) boundTool(name string) *boundTool {
	for i := len(ctx.tools) - 1; i >= 0; i-- {
		if ctx.tools[i].name == name {
			return &ctx.tools[i]
		}
	}
	return nil
}

// bound resolves a send binding by name: `base` is the exchange the scan started from, `latest`
// is the most recent send (or the base exchange before the first), and any other name is the
// most recent send that was `called` it. A name that was never sent resolves to nil — absent,
// which makes a comparison false, never an empty string.
func (ctx *Context) bound(name string) *Bound {
	switch name {
	case "base", "check":
		return &Bound{request: ctx.baseRequest(), response: ctx.responseFields()}
	case "latest":
		if n := len(ctx.sent); n > 0 {
			return &ctx.sent[n-1].bound
		}
		return &Bound{request: ctx.baseRequest(), response: ctx.responseFields()}
	default:
		for i := len(ctx.sent) - 1; i >= 0; i-- {
			if ctx.sent[i].name == name {
				return &ctx.sent[i].bound
			}
		}
		return nil
	}
}

// baseRequest returns the parsed base request, cached on first use. Nil when the stored bytes
// cannot be parsed as a request — an exchange with a response but no usable request has no
// request side to bind.
func (ctx *Context) baseRequest() *core.RequestEdit {
	if ctx.baseReq != nil {
		return ctx.baseReq
	}
	if len(ctx.Request) == 0 {
		return nil
	}
	e, err := core.ParseRequestEdit(ctx.Request)
	if err != nil {
		return nil
	}
	ctx.baseReq = e
	return e
}

// recordUnresolved notes a path this context could not supply, for Unresolved.
func (ctx *Context) recordUnresolved(p string) {
	if ctx.unresolved == nil {
		ctx.unresolved = make(map[string]bool)
	}
	ctx.unresolved[p] = true
}

// mergeUnresolved folds a child context's unresolved paths into this one — a diagnostic that
// only existed on a per-point or per-iteration temporary is no diagnostic at all.
func (ctx *Context) mergeUnresolved(child *Context) {
	for p := range child.unresolved {
		ctx.recordUnresolved(p)
	}
}

// Unresolved lists the `{…}` paths the check referenced that this context could not supply,
// sorted for stable output.
func (ctx *Context) Unresolved() []string {
	if len(ctx.unresolved) == 0 {
		return nil
	}
	out := make([]string, 0, len(ctx.unresolved))
	for p := range ctx.unresolved {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Declined lists the insertion places the enumerator refused to splice into while real points
// still ran — see RunActive and insertion.go's Declined. Nil when nothing was declined.
func (ctx *Context) Declined() []string {
	return ctx.declined
}

// baseResponseField resolves `<binding>.response.<rest…>` against the base response.
func (ctx *Context) baseResponseField(rest []string) string {
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
		return ctx.baseURLField(rest[1:])
	case "http_version":
		return firstField(f.first)
	case "method":
		// Not meaningful for a response, but harmless to answer.
		return f.first
	}
	return ""
}

// baseRequestField resolves `<binding>.request.<rest…>` against the base request.
func (ctx *Context) baseRequestField(rest []string) string {
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
		return ctx.baseURLField(rest[1:])
	case "http_version":
		// The request line's third token: "GET /x HTTP/1.1" → HTTP/1.1 (u411).
		if parts := strings.Fields(f.first); len(parts) >= 3 {
			return parts[2]
		}
		return ""
	}
	return ""
}

// baseURLField resolves `<binding>.(request|response).url.<rest…>`. With no rest it
// is the full URL the request was issued to; with a field it is that component.
func (ctx *Context) baseURLField(rest []string) string {
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
	// Burp's reference: path "/catalog/product", file "/catalog/product?productId=1", query
	// "productId=1", protocol "https" (u411). ctx.Path is the request target, query included.
	path, query, _ := strings.Cut(ctx.Path, "?")
	switch rest[0] {
	case "protocol":
		return scheme
	case "host":
		return ctx.Host
	case "port":
		return strconv.Itoa(int(ctx.Port))
	case "file":
		return ctx.Path
	case "path":
		return path
	case "query", "query_string":
		return query
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
				// Burp's "Special characters" (movb): \s space, \b backspace, \f form feed.
				case 's':
					out.WriteByte(' ')
					i++
				case 'b':
					out.WriteByte('\b')
					i++
				case 'f':
					out.WriteByte('\f')
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

// resolveValueOpt resolves a Value to its string form, reporting whether the context could
// supply it at all. A comparison operand that cannot be supplied makes the comparison false —
// see evalBoolExpr — while resolveValue (report text, sends) renders absence as "" exactly as
// Burp does.
func (ctx *Context) resolveValueOpt(v Value) (string, bool) {
	switch v.Type {
	case "var":
		s, ok := ctx.resolvePathOpt(v.StringVal)
		if !ok {
			ctx.recordUnresolved(v.StringVal)
			return "", false
		}
		return s, true
	case "tpl":
		return ctx.interpolate(v.StringVal), true
	case "bool":
		if v.BoolVal {
			return "true", true
		}
		return "false", true
	case "int":
		return strconv.Itoa(v.IntVal), true
	default:
		return v.StringVal, true
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
//
// For the active evaluator, a fork also starts with an empty send list — an
// iteration must not see the previous iteration's `{check.response}` — and an
// empty unresolved set, which the caller folds back with mergeUnresolved. The
// insertion point, sink and target survive the fork: a `run for each` inside a
// point still writes to that point.
func (ctx *Context) fork() *Context {
	c := *ctx
	c.Variables = make(map[string]Value, len(ctx.Variables))
	for k, v := range ctx.Variables {
		c.Variables[k] = v
	}
	c.sent = nil
	c.tools = nil
	c.unresolved = nil
	return &c
}

// RunPassive runs passive checks on a response.
func RunPassive(check *Check, ctx *Context) ([]Finding, error) {
	if check.Given != "response" {
		return nil, nil
	}
	return runCheckBody(check, ctx)
}

// runCheckBody executes a check's body against ctx: `define:` bindings, the `run for each`
// product, then the statements. Shared by the passive and active evaluators so a statement's
// meaning cannot diverge between them.
func runCheckBody(check *Check, ctx *Context) ([]Finding, error) {
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
		// Guard against integer overflow (a huge declared length would wrap total
		// to a small number and the loop would run far more than intended) and
		// against an unbounded cartesian product: a crafted .bcheck file with
		// several large `run for each` lists could otherwise force millions of
		// iterations, each forking a context and running the statement body.
		if dims[i] > maxForEachDim {
			return nil, fmt.Errorf("run for each list %d has %d values, more than the %d cap", i, dims[i], maxForEachDim)
		}
		if dims[i] > 0 && total > maxForEachProduct/dims[i] {
			return nil, fmt.Errorf("run for each product %d exceeds the %d cap", total*dims[i], maxForEachProduct)
		}
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
		// Fold the iteration's diagnostics and RNG state back into the shared context: a
		// cache-busting nonce must advance across iterations, and an unresolved path that only
		// existed inside a temporary is no diagnostic at all.
		base.rng = iter.rng
		base.mergeUnresolved(iter)
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
		f := Finding{
			IssueName:   ctx.resolveValue(s.IssueName),
			Severity:    Severity(s.Severity),
			Confidence:  Confidence(s.Confidence),
			Description: ctx.resolveValue(s.Description),
			Remediation: ctx.resolveValue(s.Remediation),
		}
		// A `given insertion point` check runs once per point with its own
		// context, so at report time ctx.point *is* the point this finding was
		// produced for. Naming it here is what makes the finding attributable to
		// one parameter — the entire reason the construct exists.
		if ctx.point != nil {
			f.Param = ctx.point.Name
		}
		return execOutcome{
			findings: []Finding{f},
			halt:     !s.Continue,
		}, nil
	case *DefineStatement:
		// Resolve at bind time so a template define is usable as a plain string
		// by every later reference.
		ctx.Variables[s.Name] = Value{Type: "str", StringVal: ctx.resolveValue(s.Value)}
	case *SendRequestStatement:
		// The passive evaluator never sends: a check that reaches a send with no sink on its
		// context is being run without outbound traffic, and the send is a no-op, exactly as
		// before. RunActive supplies the sink, at which point the send really goes out through
		// the caller's chokepoint and the result is bound as `latest` / `StoreAs`.
		if ctx.sink == nil {
			return execOutcome{}, nil
		}
		if err := ctx.sendRequest(s); err != nil {
			return execOutcome{}, err
		}
		return execOutcome{}, nil
	case *SendPayloadStatement:
		if ctx.sink == nil {
			return execOutcome{}, nil
		}
		if err := ctx.sendPayload(s); err != nil {
			return execOutcome{}, err
		}
		return execOutcome{}, nil
	case *RunToolStatement:
		// Tool execution is never a no-op: unlike a send in the passive
		// evaluator, a tool run with no runner is refused rather than skipped,
		// because a check whose tool never ran must not look clean. RunActive
		// already refuses whole tool checks up front; this is the defence for a
		// tool statement reached on a context that lost its runner.
		if err := ctx.runTool(s); err != nil {
			return execOutcome{}, err
		}
		return execOutcome{}, nil
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
		ctx.rng = iter.rng
		ctx.mergeUnresolved(iter)
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

	// An operand this context cannot supply makes a comparison false, never true: absence is not
	// evidence. Coercing an absent binding to "" would make `{typo.response.body} in
	// {latest.response}` fire on every response — a check reporting a vulnerability it never
	// observed. This is the Rust evaluator's value_opt distinction, ported.
	switch expr.Operator {
	case "eq", "is":
		l, lok := ctx.resolveValueOpt(expr.Left)
		r, rok := ctx.resolveValueOpt(expr.Right)
		if !lok || !rok {
			return false
		}
		return l == r
	case "ne":
		l, lok := ctx.resolveValueOpt(expr.Left)
		r, rok := ctx.resolveValueOpt(expr.Right)
		if !lok || !rok {
			return false
		}
		return l != r
	case "contains":
		l, lok := ctx.resolveValueOpt(expr.Left)
		r, rok := ctx.resolveValueOpt(expr.Right)
		if !lok || !rok {
			return false
		}
		return contains(l, r)
	case "in":
		// `x in y` — containment with the needle on the LEFT.
		l, lok := ctx.resolveValueOpt(expr.Left)
		r, rok := ctx.resolveValueOpt(expr.Right)
		if !lok || !rok {
			return false
		}
		return contains(r, l)
	case "matches":
		// The pattern is taken raw, never interpolated — this is what lets a
		// literal regex keep its braces (`"oy2[a-z0-9]{43}"`).
		l, lok := ctx.resolveValueOpt(expr.Left)
		if !lok {
			return false
		}
		re, err := compileRegex(expr.Right.StringVal)
		if err != nil {
			return false
		}
		return re.MatchString(l)
	}
	return false
}

func contains(s, substr string) bool {
	// strings.Contains uses a tuned search (Rabin-Karp for long needles); the
	// hand-rolled O(n*m) loop it replaced was the slow path for large bodies.
	return strings.Contains(s, substr)
}

// hasCallPrefix reports whether name is a call of fn, matching the function name without regard to
// case (Burp's reference writes MD5(…) and md5(…) alike).
func hasCallPrefix(name, fn string) bool {
	return len(name) > len(fn) && strings.EqualFold(name[:len(fn)], fn) && strings.HasSuffix(name, ")")
}
