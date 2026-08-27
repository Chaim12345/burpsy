// Package query implements burpsy's filter grammar over captured traffic: one small, closed,
// typed language shared by the History filter box, the CLI's `history --query`, and — DSL-02 — any
// other consumer that can describe its own row type through Queryable.
//
// # Why a closed typed grammar and not an embedded scripting language
//
// An embedded interpreter would buy expressiveness an operator filtering history does not need,
// and would give up the one property they do need: `status > "abc"` must be rejected before a
// single row is compared, not evaluated to false because comparing a number to a string happens to
// be falsy. A typed grammar makes that a parse-time error; a general-purpose script only offers a
// runtime one, in the one place — a history filter — where a runtime failure is easiest to mistake
// for "no matches". That is DSL-04, and it can only be a guarantee if the grammar is closed.
//
// # Why the check lives in Parse and not in Match
//
// Match returns a plain bool, not (bool, error), and that is the point. Every *Expr that exists
// came out of Parse, which has already checked the field, the operator and the value shape against
// each other — so there is no ill-typed comparison left for Match to discover, and no reason for it
// to have a failure channel that would collapse back into false. The Expr fields are unexported for
// the same reason Rust wraps its tree in a private `Query(Expr)`: Parse is the only constructor, so
// "this Expr is type-checked" is an invariant of the type rather than a convention.
//
// A malformed query is an error value; a query that legitimately selects nothing is a valid *Expr
// whose Match returns false. Those two are different types here, so a caller cannot conflate them
// by accident — only by deliberately discarding the error.
//
// # Grammar
//
//	query      := or-expr
//	or-expr    := and-expr ( "or" and-expr )*
//	and-expr   := unary-expr ( "and" unary-expr )*
//	unary-expr := "not" unary-expr | primary
//	primary    := "(" or-expr ")" | comparison
//	comparison := field op value
//	field      := "host" | "status" | "method" | "path" | "mime" | "body"
//
// `not` binds tighter than `and`, which binds tighter than `or` — `a or b and c` parses as
// `a or (b and c)`. Parentheses override both, and `not` needs none of its own: `not host = "x"`
// is valid because `not`'s operand is any unary-expr, and a bare comparison is one.
//
// # The field/operator matrix, all of it enforced by Parse
//
//   - host, method, path, mime: `=` (`==`), `!=`, `~` (contains), each with a string value. host and
//     mime compare case-insensitively (DNS names and MIME type/subtype both are); method and path do
//     not, because the HTTP method token is case-sensitive per RFC 7230 and the path component is
//     case-sensitive per RFC 3986 — folding case in either would accept a query describing a
//     different wire request than the one actually sent.
//   - status: `=` (`==`), `!=`, `<`, `<=`, `>`, `>=` with an integer value, or `in low..high` for a
//     range inclusive of both ends. A literal outside 0-65535 is rejected at parse time.
//   - body: `~` only, matched case-sensitively against the raw bytes. There is no equality on body:
//     matching a whole message body byte-for-byte is never what an operator means by "filter on
//     body content".
//
// An inverted range (`status in 299..200`) parses and matches nothing, exactly as in Rust — the
// bounds are compared, not reordered. That is a well-typed query that selects no rows, which is a
// different thing from an ill-typed one, and only the latter is DSL-04's business.
//
// Quoted strings support the escapes \", \\, \n, \t and \r — the same five the Rust lexer takes,
// and no others: an unrecognised escape is a parse error rather than a silently-dropped backslash.
//
// # Absent fields are absent, not zero
//
// Queryable models "no response yet" as Status() == 0 and "no Content-Type" as Mime() == "", since
// neither is a value HTTP can produce. Every comparison on an absent field is false — never true,
// and never an error. A query naming a field the row does not have yet is not a fault in the query,
// but neither is a pending request a 0-status response: before this was explicit, `status < 400`
// matched every request still waiting for its response, because 0 < 400.
//
// # Named divergences from crates/query
//
//   - One file, not five. Rust splits lexer/parser/ast/eval/error; this parser reads characters
//     directly rather than materialising a token slice, so the split would be four files of two
//     functions each. Behaviour is what parity is measured on, and the behaviour matches.
//   - `=` is accepted as a synonym for `==`. Rust's lexer rejects a lone `=` outright. Go's grammar
//     has documented `=` since it was written while the UI's own placeholder query uses `==`, and
//     `==` used to parse and then silently never match — the exact failure mode DSL-04 exists to
//     prevent. Both spellings are accepted rather than breaking either caller.
//   - An unquoted bare word is accepted as a string value (`host = example.com`), which Rust
//     rejects. Go's grammar has always allowed it and the CLI's --query examples are unquoted. A
//     bare word that is all digits is still refused, because a number where a string belongs is a
//     type error and not a hostname: quote it (`host = "8080"`) to mean the text.
//   - One error type with an offset and a message, rather than Rust's ten-variant enum. Callers
//     discriminate on position and text, not on variant; QueryError.Render carries over the caret
//     rendering that Rust's QueryError::render provides.
package query

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Queryable is what the evaluator inspects on each exchange. A consumer implements it over
// whatever its own row type is, which is what lets one parsed *Expr drive both the history filter
// and an unrelated match-and-replace candidate (DSL-02) without either knowing about the other.
type Queryable interface {
	Host() string
	Method() string
	Path() string // "" = absent
	Status() int  // 0 = absent (no response yet)
	Mime() string
	Body() []byte
	// ResponseLen reports the response's size in bytes, and whether there is a response at all.
	//
	// The bool is not optional politeness: 0 is a legitimate length — a 204 has an empty body — so a
	// bare int64 could not tell "an empty response" from "no response", and `length = 0` would match
	// every request still in flight. Same reasoning as Status()'s documented 0-means-absent, made
	// explicit here because for length the absent value collides with a real one.
	ResponseLen() (int64, bool)
	// DurationUs reports how long the exchange took, in microseconds, and whether anyone measured
	// it. Mirrors core.ExchangeDuration, whose Measured flag exists for exactly this reason: an
	// exchange nobody timed must not report as instantaneous.
	DurationUs() (int64, bool)
	// Header returns every value for a response header name, in wire order, and whether the header
	// was present.
	//
	// Every value, not the first: Set-Cookie legally repeats and is the header a predicate is most
	// often wanted over, so a first-match accessor would pass a response whose SECOND cookie is the
	// insecure one. See core.StoredMessage.HeaderValues.
	//
	// The bool separates absent from present-with-an-empty-value. Both are real — `Set-Cookie:` with
	// nothing after it is a server bug worth seeing — and an absent header must fail every
	// comparison, negations included, the way an absent status does.
	Header(name string) ([]string, bool)
}

// Expr is a parsed, type-checked query expression. Parse is the only way to obtain one, so every
// Expr that exists has already passed the field/operator/value rules above and Match cannot fail.
//
// The fields are unexported deliberately: an Expr assembled by hand could carry a comparison the
// grammar forbids, and Match would then have to decide what an ill-typed comparison means — the
// silent-false answer this package exists to eliminate.
type Expr struct {
	kind        exprKind
	left, right *Expr

	// Set only when kind == kindCmp.
	field field
	op    op
	str   string // value for host/method/mime/body
	num   uint16 // status value for =, !=, <, <=, >, >=
	lo    uint16 // status range lower bound, inclusive (op == opIn)
	hi    uint16 // status range upper bound, inclusive (op == opIn)
	// The wide numerics, for length and duration. Separate from num/lo/hi rather than widening
	// those: status is a 16-bit value and the parser rejects anything larger with a message that
	// says so, which is a real check worth keeping. A response length does not fit in 16 bits at
	// all — 65535 bytes is a small page — so sharing the field would have silently truncated.
	num64 int64
	lo64  int64
	hi64  int64
	// key is the header name for fieldHeader. Held separately from str, which carries the value being
	// compared: `header["set-cookie"] ~ "HttpOnly"` has both, and collapsing them into one string
	// would make the comparison unable to say which half it was matching.
	key string
}

type exprKind int

const (
	kindAnd exprKind = iota
	kindOr
	kindNot
	kindCmp
)

type field int

const (
	fieldHost field = iota
	fieldMethod
	fieldPath
	fieldMime
	fieldStatus
	fieldBody
	fieldLength
	fieldDuration
	fieldHeader
	fieldExtension
	fieldParams
	// fieldCount is the number of fields the grammar has. Fields() sizes its seen-set from this.
	//
	// NOTE: adding a field here is NOT caught by the compiler in fieldOrder — a short
	// [fieldCount]field literal is legal Go and pads with the zero value, which is fieldHost, so the
	// omission shows up as Fields() reporting "host" for a query that never named it. That happened
	// when length and duration were added. TestFieldOrderCoversEveryField is what catches it now.
	fieldCount = iota
)

func (f field) String() string {
	switch f {
	case fieldHost:
		return "host"
	case fieldMethod:
		return "method"
	case fieldPath:
		return "path"
	case fieldMime:
		return "mime"
	case fieldStatus:
		return "status"
	case fieldBody:
		return "body"
	case fieldLength:
		return "length"
	case fieldDuration:
		return "duration"
	case fieldHeader:
		return "header"
	case fieldExtension:
		return "extension"
	case fieldParams:
		return "params"
	}
	return "?"
}

type op int

const (
	opEq op = iota
	opNe
	opContains
	opLt
	opLe
	opGt
	opGe
	opIn
)

func (o op) String() string {
	switch o {
	case opEq:
		return "="
	case opNe:
		return "!="
	case opContains:
		return "~"
	case opLt:
		return "<"
	case opLe:
		return "<="
	case opGt:
		return ">"
	case opGe:
		return ">="
	case opIn:
		return "in"
	}
	return "?"
}

// QueryError is a parse fault carrying the byte offset it was found at, plus the source it was
// found in so Render can point at it. This type is the whole of DSL-04 on the Go side: there is no
// function in this package that turns one into an *Expr that matches nothing.
type QueryError struct {
	// At is the byte offset in Src where the fault was found.
	At int
	// Msg says what the fault means to an operator, not which token disagreed.
	Msg string
	// Src is the query text the fault was found in, kept so Render needs no arguments.
	Src string
}

func (e *QueryError) Error() string {
	return fmt.Sprintf("query parse error at byte %d: %s", e.At, e.Msg)
}

// Render reproduces the offending line under the message with a caret pointing at At. A byte
// offset alone in a JSON field is not "where" for an operator typing into a filter box — this is.
// The output is three lines: message, source line, caret line.
func (e *QueryError) Render() string {
	at := e.At
	if at > len(e.Src) {
		at = len(e.Src)
	}
	lineStart := strings.LastIndexByte(e.Src[:at], '\n') + 1 // -1+1 == 0 when there is no newline
	lineEnd := len(e.Src)
	if i := strings.IndexByte(e.Src[at:], '\n'); i >= 0 {
		lineEnd = at + i
	}
	// Column in runes, not bytes: a caret counted in bytes drifts right of the character it means
	// as soon as the query contains a multi-byte host name.
	col := len([]rune(e.Src[lineStart:at]))
	return fmt.Sprintf("%s\n%s\n%s^", e.Error(), e.Src[lineStart:lineEnd], strings.Repeat(" ", col))
}

// Render formats err for display to an operator: the caret rendering when err came from Parse, and
// the plain message otherwise. Callers that show a query fault in a UI want the caret; callers
// that only log it can use err.Error() directly.
func Render(err error) string {
	if err == nil {
		return ""
	}
	var qe *QueryError
	if errors.As(err, &qe) {
		return qe.Render()
	}
	return err.Error()
}

// Parse parses and type-checks a query string. A returned error is always a *QueryError.
func Parse(input string) (*Expr, error) {
	p := &parser{src: input}
	p.skipWs()
	if p.pos >= len(p.src) {
		return nil, p.errAt(0, "the query is empty — there is nothing to filter on; write at least one comparison, e.g. `status = 200`")
	}
	e, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	// Rust's parser demands EOF here. Without that check a trailing `)` or a mistyped second
	// clause is silently discarded, and the query that runs is not the query that was typed —
	// which reads, once again, as "that filter matched fewer rows than I expected".
	p.skipWs()
	if p.pos < len(p.src) {
		return nil, p.errAt(p.pos, "expected the end of the query but found %q — an unbalanced ')' or a clause missing its `and`/`or` lands here", p.restOfToken())
	}
	return e, nil
}

type parser struct {
	src string
	pos int
}

func (p *parser) errAt(at int, format string, args ...interface{}) error {
	return &QueryError{At: at, Msg: fmt.Sprintf(format, args...), Src: p.src}
}

func (p *parser) peek() byte {
	if p.pos >= len(p.src) {
		return 0
	}
	return p.src[p.pos]
}

func (p *parser) skipWs() {
	for p.pos < len(p.src) && isSpaceByte(p.src[p.pos]) {
		p.pos++
	}
}

// restOfToken is for error messages only: the run of non-space bytes at the cursor, so a message
// can quote what it choked on instead of naming a bare offset.
func (p *parser) restOfToken() string {
	start := p.pos
	end := p.pos
	for end < len(p.src) && !isSpaceByte(p.src[end]) {
		end++
	}
	if end == start && start < len(p.src) {
		end = start + 1
	}
	return p.src[start:end]
}

func (p *parser) consumeIdent() string {
	p.skipWs()
	start := p.pos
	for p.pos < len(p.src) && (p.src[p.pos] == '_' || isAlpha(p.src[p.pos]) || isDigit(p.src[p.pos])) {
		p.pos++
	}
	return p.src[start:p.pos]
}

// consumeKeyword consumes the whole identifier at the cursor if it equals kw, and consumes nothing
// otherwise. Whole-identifier, not prefix: `order = "x"` must not be read as `or` followed by
// `der`, and `nothing` must not be read as `not hing`.
func (p *parser) consumeKeyword(kw string) bool {
	saved := p.pos
	if strings.EqualFold(p.consumeIdent(), kw) {
		return true
	}
	p.pos = saved
	return false
}

// ---- boolean composition -----------------------------------------------------------------------

func (p *parser) parseOr() (*Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWs()
		if !p.consumeKeyword("or") {
			break
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &Expr{kind: kindOr, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (*Expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWs()
		if !p.consumeKeyword("and") {
			break
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &Expr{kind: kindAnd, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (*Expr, error) {
	p.skipWs()
	if p.consumeKeyword("not") {
		sub, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &Expr{kind: kindNot, left: sub}, nil
	}
	return p.parsePrimary()
}

// parsePrimary is the level parentheses live at: a group recurses all the way back to parseOr, so
// the precedence the outer levels impose is exactly what `(` and `)` suspend.
func (p *parser) parsePrimary() (*Expr, error) {
	p.skipWs()
	if p.peek() == '(' {
		openAt := p.pos
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipWs()
		if p.peek() != ')' {
			// Reported at the cursor, which for a group that runs off the end of the input is the
			// end of the input — the offset a caret should point at to say "it stopped here".
			return nil, p.errAt(p.pos, "the group opened at byte %d is never closed — expected ')'", openAt)
		}
		p.pos++
		return inner, nil
	}
	return p.parseCmp()
}

// ---- one `field op value` comparison -----------------------------------------------------------

// parseCmp is where the type check happens: the single point at which a field, an operator and a
// value literal come together. There is no path from input to a kindCmp Expr that skips it.
func (p *parser) parseCmp() (*Expr, error) {
	p.skipWs()
	fieldAt := p.pos
	name := p.consumeIdent()
	if name == "" {
		return nil, p.errAt(fieldAt, "expected a field name (%s) or '('", fieldNames())
	}
	f, ok := fieldByName(name)
	if !ok {
		return nil, p.errAt(fieldAt, "'%s' is not a field this grammar has — the fields are %s", name, fieldNames())
	}

	// header takes a subscript naming which header: header["set-cookie"] ~ "HttpOnly".
	//
	// Indexed rather than a flat text match over the whole head, which would have been one line and
	// no new syntax. A flat match cannot respect header boundaries: a value ending in "set-cookie"
	// followed by any header beginning "HttpOnly" would satisfy it, and folded continuation lines
	// make that likelier than it sounds. An operator asking about a header means that header.
	var headerName string
	if f == fieldHeader {
		name, err := p.parseHeaderSubscript()
		if err != nil {
			return nil, err
		}
		headerName = name
	}

	o, opAt, err := p.parseOp(f)
	if err != nil {
		return nil, err
	}
	// Quote the operator as it was written, not as the canonical spelling: an operator told `==`
	// does not apply should say `==`, or the message looks like it is answering a different query.
	opLit := p.src[opAt:p.pos]
	if !fieldAllows(f, o) {
		return nil, p.errAt(opAt, "'%s' does not apply to %s — %s supports %s", opLit, f, f, allowedOps(f))
	}

	if f == fieldStatus {
		return p.parseStatusValue(o)
	}
	if f == fieldLength || f == fieldDuration || f == fieldParams {
		return p.parseNumericValue(f, o)
	}
	val, err := p.parseStringValue(f)
	if err != nil {
		return nil, err
	}
	return &Expr{kind: kindCmp, field: f, op: o, str: val, key: headerName}, nil
}

// fieldNames lists every field the grammar has, derived from fieldOrder rather than written out.
//
// The two "the fields are host, status, method, path, mime and body" messages this replaces were
// already wrong: length and duration had been added and neither message mentioned them, so an
// operator who mistyped a field name was told a list that omitted two of the answers. Derived, it
// cannot drift again.
func fieldNames() string {
	names := make([]string, 0, len(fieldOrder))
	for _, f := range fieldOrder {
		names = append(names, f.String())
	}
	return strings.Join(names, ", ")
}

// parseHeaderSubscript reads the ["name"] that follows the header field.
//
// The name must be quoted. An unquoted bare word is accepted elsewhere in this grammar for values,
// but a header name can contain characters the identifier lexer would stop at, and accepting a bare
// word here would make `header[x-foo]` parse as `header[x]` followed by junk — an error reported
// somewhere unhelpful rather than at the subscript.
func (p *parser) parseHeaderSubscript() (string, error) {
	p.skipWs()
	at := p.pos
	if p.pos >= len(p.src) || p.peek() != '[' {
		return "", p.errAt(at, "header needs a subscript naming which header to test — the form is "+
			"`header[\"set-cookie\"] ~ \"HttpOnly\"`")
	}
	p.pos++
	p.skipWs()
	if p.pos >= len(p.src) || p.peek() != '"' {
		return "", p.errAt(p.pos, "a header name must be quoted: `header[\"set-cookie\"]`, not "+
			"`header[set-cookie]` — an unquoted name would stop at the first character the identifier "+
			"lexer does not accept and report the error somewhere else")
	}
	name, err := p.consumeQuoted()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(name) == "" {
		return "", p.errAt(at, "a header name cannot be empty — `header[\"\"]` matches no header, and "+
			"a comparison that cannot match is refused here rather than reported as no rows found")
	}
	p.skipWs()
	if p.pos >= len(p.src) || p.peek() != ']' {
		return "", p.errAt(p.pos, "expected ']' to close the header subscript")
	}
	p.pos++
	return name, nil
}

func fieldByName(name string) (field, bool) {
	switch strings.ToLower(name) {
	case "host":
		return fieldHost, true
	case "method":
		return fieldMethod, true
	case "path":
		return fieldPath, true
	case "mime":
		return fieldMime, true
	case "status":
		return fieldStatus, true
	case "body":
		return fieldBody, true
	case "length":
		return fieldLength, true
	case "duration":
		return fieldDuration, true
	case "header":
		return fieldHeader, true
	case "extension":
		return fieldExtension, true
	case "params":
		return fieldParams, true
	}
	return 0, false
}

// fieldAllows is the operator half of the matrix. Spelled out per field rather than derived from a
// "is this a string field" predicate, so adding a field or an operator forces a decision here
// instead of inheriting one.
func fieldAllows(f field, o op) bool {
	switch f {
	case fieldHost, fieldMethod, fieldPath, fieldMime:
		return o == opEq || o == opNe || o == opContains
	case fieldStatus:
		return o == opEq || o == opNe || o == opLt || o == opLe || o == opGt || o == opGe || o == opIn
	case fieldBody:
		return o == opContains
	case fieldLength, fieldDuration:
		// The same set status has. A range reads better than two clauses for the case an operator
		// actually wants — "responses between 1 and 2 megabytes" — and `in` already exists.
		return o == opEq || o == opNe || o == opLt || o == opLe || o == opGt || o == opGe || o == opIn
	case fieldHeader:
		// String operators only. A header value is text, and no ordering on it means anything.
		return o == opEq || o == opNe || o == opContains
	case fieldExtension:
		return o == opEq || o == opNe || o == opContains
	case fieldParams:
		// A count, so the numeric set — including `in`, for "between two and five parameters".
		return o == opEq || o == opNe || o == opLt || o == opLe || o == opGt || o == opGe || o == opIn
	}
	return false
}

// allowedOps names what would have worked, so the error is actionable rather than just a refusal.
func allowedOps(f field) string {
	switch f {
	case fieldStatus:
		return "=, !=, <, <=, >, >= and `in low..high`"
	case fieldBody:
		return "~ (contains) only, since matching a whole body exactly is rarely what \"filter on body content\" means"
	case fieldLength, fieldDuration:
		return "=, !=, <, <=, >, >= and `in low..high`"
	case fieldHeader:
		return "=, != and ~ (contains), each case-insensitive on the value"
	case fieldExtension:
		return "=, != and ~ (contains), case-insensitive"
	case fieldParams:
		return "=, !=, <, <=, >, >= and `in low..high`"
	}
	return "=, != (case-insensitive for host and mime) and ~ (contains)"
}

// parseOp reads one operator: a run of symbol characters, or the word `in`. The field is taken only
// to name it in the "expected an operator" message; legality is decided by the caller so that an
// operator this grammar has but the field forbids reports as "does not apply to", not "unknown".
func (p *parser) parseOp(f field) (op, int, error) {
	p.skipWs()
	at := p.pos
	if p.pos >= len(p.src) {
		return 0, at, p.errAt(at, "the query ended while an operator for %s was still expected (%s)", f, allowedOps(f))
	}
	if isAlpha(p.peek()) || p.peek() == '_' {
		word := p.consumeIdent()
		if strings.EqualFold(word, "in") {
			return opIn, at, nil
		}
		return 0, at, p.errAt(at, "expected an operator for %s but found the word '%s' — %s supports %s", f, word, f, allowedOps(f))
	}
	start := p.pos
	for p.pos < len(p.src) && strings.IndexByte("=<>!~", p.src[p.pos]) >= 0 {
		p.pos++
	}
	switch p.src[start:p.pos] {
	case "=", "==":
		return opEq, at, nil
	case "!=":
		return opNe, at, nil
	case "~":
		return opContains, at, nil
	case "<":
		return opLt, at, nil
	case "<=":
		return opLe, at, nil
	case ">":
		return opGt, at, nil
	case ">=":
		return opGe, at, nil
	case "":
		return 0, at, p.errAt(at, "expected an operator for %s but found %q — %s supports %s", f, p.restOfToken(), f, allowedOps(f))
	default:
		return 0, at, p.errAt(at, "'%s' is not an operator this grammar has — %s supports %s", p.src[start:p.pos], f, allowedOps(f))
	}
}

// parseStringValue reads the value of a comparison on host, method, mime or body.
func (p *parser) parseStringValue(f field) (string, error) {
	p.skipWs()
	at := p.pos
	if p.pos >= len(p.src) {
		return "", p.errAt(at, "the query ended while a value for %s was still expected", f)
	}
	if p.peek() == '"' {
		return p.consumeQuoted()
	}
	word := p.consumeBareWord()
	if word == "" {
		return "", p.errAt(at, "expected a value for %s but found %q — write it as a quoted string, e.g. %s ~ \"example\"", f, p.restOfToken(), f)
	}
	if isAllDigits(word) {
		// The mirror image of `status > "abc"`: a number where a string belongs. Refused rather
		// than compared as text, because a query that says `host = 8080` is a mistake, and
		// answering it with an empty row list would hide that.
		return "", p.errAt(at, "%s expects a string value but found the number %s — quote it (%s = \"%s\") if that is really the text you mean", f, word, f, word)
	}
	return word, nil
}

// parseStatusValue reads either one status literal or a `low..high` range, and is the other half of
// the matrix: the value shape is decided by the operator that was already accepted for the field.
func (p *parser) parseStatusValue(o op) (*Expr, error) {
	lo, err := p.parseStatusNumber()
	if err != nil {
		return nil, err
	}
	if o != opIn {
		return &Expr{kind: kindCmp, field: fieldStatus, op: o, num: lo}, nil
	}
	p.skipWs()
	if !strings.HasPrefix(p.src[p.pos:], "..") {
		return nil, p.errAt(p.pos, "expected '..' between the bounds of a status range — the form is `status in 200..299`, inclusive of both ends")
	}
	p.pos += 2
	hi, err := p.parseStatusNumber()
	if err != nil {
		return nil, err
	}
	return &Expr{kind: kindCmp, field: fieldStatus, op: opIn, lo: lo, hi: hi}, nil
}

// parseNumericValue reads a length or duration comparison, including the `in low..high` form.
func (p *parser) parseNumericValue(f field, o op) (*Expr, error) {
	lo, err := p.parseScaledNumber(f)
	if err != nil {
		return nil, err
	}
	if o != opIn {
		return &Expr{kind: kindCmp, field: f, op: o, num64: lo}, nil
	}
	p.skipWs()
	if !strings.HasPrefix(p.src[p.pos:], "..") {
		return nil, p.errAt(p.pos, "expected '..' between the bounds of a %s range — the form is `%s in %s`, inclusive of both ends",
			f, f, numericRangeExample(f))
	}
	p.pos += 2
	hi, err := p.parseScaledNumber(f)
	if err != nil {
		return nil, err
	}
	// Bounds the wrong way round match nothing, which on this grammar is a verdict indistinguishable
	// from "no rows are that size". Rejected at parse time, as the type mismatches above are.
	if lo > hi {
		return nil, p.errAt(p.pos, "the range for %s is empty: its lower bound (%d) is above its upper bound (%d), so nothing could match it", f, lo, hi)
	}
	return &Expr{kind: kindCmp, field: f, op: opIn, lo64: lo, hi64: hi}, nil
}

func numericRangeExample(f field) string {
	if f == fieldDuration {
		return "100ms..2s"
	}
	return "1kb..1mb"
}

// numericUnits is the suffix vocabulary per field, with each suffix's multiplier in the field's own
// base unit — bytes for length, microseconds for duration.
//
// # Why suffixes exist at all
//
// The question an operator actually has is "which responses are over a megabyte", and the
// unsuffixed form of that is `length > 1048576`. Requiring it would be hostile, and worse, easy to
// get wrong by an order of magnitude in a way the result set would not reveal.
//
// # Why a bare number still has one documented meaning
//
// Bytes for length, milliseconds for duration — milliseconds because that is what the History
// column shows, so `duration > 500` means what an operator reading the screen expects. The base
// unit internally is microseconds, because that is what core.ExchangeDuration stores; the
// difference is confined to this table.
var numericUnits = map[field][]struct {
	suffix string
	scale  int64
}{
	fieldLength: {
		{"kb", 1024},
		{"mb", 1024 * 1024},
		{"gb", 1024 * 1024 * 1024},
		{"b", 1},
		{"", 1}, // bare: bytes
	},
	fieldDuration: {
		{"us", 1},
		{"ms", 1000},
		{"s", 1000 * 1000},
		{"", 1000}, // bare: milliseconds, matching the History column
	},
	// params is a plain count, so the only accepted form is a bare number. It still needs an entry:
	// parseScaledNumber looks its field up here, and a missing entry made every `params = 3` fail
	// with "\"\" is not a unit params accepts — length accepts b, kb, mb and gb", which is both a
	// refusal of valid input and an offer of megabytes for a count.
	fieldParams: {
		{"", 1},
	},
}

// parseScaledNumber reads a number with an optional unit suffix and returns it in the field's base
// unit.
func (p *parser) parseScaledNumber(f field) (int64, error) {
	p.skipWs()
	at := p.pos
	if p.pos >= len(p.src) {
		return 0, p.errAt(at, "the query ended while a number for %s was still expected", f)
	}
	if p.peek() == '"' {
		// Same rule as status: a comparison whose types do not fit is refused here rather than
		// reaching Match and returning false, which reads as "nothing matched".
		return 0, p.errAt(at, "%s expects a number but found a quoted string — a comparison whose types do not fit is rejected here rather than silently matching nothing", f)
	}
	start := p.pos
	for p.pos < len(p.src) && isDigit(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return 0, p.errAt(at, "%s expects a number but found %q — a comparison whose types do not fit is rejected here rather than silently matching nothing", f, p.restOfToken())
	}
	digits := p.src[start:p.pos]

	// The suffix, if any. Read as letters so `1kbx` is an error rather than `1kb` with trailing
	// junk the parser would then fail on somewhere less helpful.
	unitStart := p.pos
	for p.pos < len(p.src) && isAlpha(p.src[p.pos]) {
		p.pos++
	}
	unit := strings.ToLower(p.src[unitStart:p.pos])

	var scale int64
	found := false
	for _, candidate := range numericUnits[f] {
		if candidate.suffix == unit {
			scale = candidate.scale
			found = true
			break
		}
	}
	if !found {
		return 0, p.errAt(unitStart, "%q is not a unit %s accepts — %s", unit, f, unitsFor(f))
	}

	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, p.errAt(at, "%s is too large a number for %s", digits, f)
	}
	// Overflow is checked rather than allowed to wrap: a wrapped bound becomes a negative number
	// that matches nothing, or everything, with no error to say why.
	if scale != 0 && n > math.MaxInt64/scale {
		return 0, p.errAt(at, "%s%s overflows the range %s can express", digits, unit, f)
	}
	return n * scale, nil
}

// unitsFor names the accepted suffixes, and what a bare number means, so the error is actionable.
func unitsFor(f field) string {
	switch f {
	case fieldDuration:
		return "duration accepts us, ms and s, and a bare number means milliseconds"
	case fieldParams:
		return "params is a count and takes a plain number with no unit"
	default:
		// Spelled as a switch with an explicit default rather than an if: the previous form returned
		// length's units for every field that was not duration, so params was told it accepts
		// megabytes. A new numeric field now gets length's text only by falling through here
		// deliberately.
		return "length accepts b, kb, mb and gb, and a bare number means bytes"
	}
}

func (p *parser) parseStatusNumber() (uint16, error) {
	p.skipWs()
	at := p.pos
	if p.pos >= len(p.src) {
		return 0, p.errAt(at, "the query ended while a number for status was still expected")
	}
	if p.peek() == '"' {
		// DSL-04's canonical case, `status > "abc"`. Rejected here, at parse time, so it can never
		// reach Match and come back as false — a verdict indistinguishable from "no rows matched".
		return 0, p.errAt(at, "status expects a number but found a quoted string — a comparison whose types do not fit is rejected here rather than silently matching nothing")
	}
	start := p.pos
	for p.pos < len(p.src) && isDigit(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return 0, p.errAt(at, "status expects a number but found %q — a comparison whose types do not fit is rejected here rather than silently matching nothing", p.restOfToken())
	}
	text := p.src[start:p.pos]
	n, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return 0, p.errAt(at, "%s is not a valid status code — status is a 16-bit value (0-65535)", text)
	}
	return uint16(n), nil
}

// consumeQuoted reads a double-quoted string, decoding the five escapes the grammar has. An
// unknown escape is an error, not a dropped backslash: `host ~ "a\qb"` is a typo, and quietly
// searching for `aqb` would answer a question nobody asked.
func (p *parser) consumeQuoted() (string, error) {
	openAt := p.pos // the caller has checked p.peek() == '"'
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) {
		switch c := p.src[p.pos]; c {
		case '"':
			p.pos++
			return b.String(), nil
		case '\\':
			if p.pos+1 >= len(p.src) {
				return "", p.errAt(openAt, "the quoted string opened at byte %d is never closed — its last character is a trailing backslash", openAt)
			}
			esc := p.src[p.pos+1]
			switch esc {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				return "", p.errAt(p.pos+1, "'\\%c' is not a recognised escape — the escapes are \\\", \\\\, \\n, \\t and \\r", esc)
			}
			p.pos += 2
		default:
			// Byte-at-a-time is safe for multi-byte UTF-8: every continuation byte is copied
			// through unchanged, and none of them can be '"' or '\\'.
			b.WriteByte(c)
			p.pos++
		}
	}
	return "", p.errAt(openAt, "the quoted string opened at byte %d is never closed — add a closing '\"' before the end of the query", openAt)
}

// consumeBareWord reads an unquoted value: everything up to whitespace, a quote, a parenthesis or
// an operator character. Non-ASCII bytes pass through, so an internationalised host name written
// without quotes still works.
func (p *parser) consumeBareWord() string {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if isSpaceByte(c) || c == '"' || c == '(' || c == ')' || strings.IndexByte("=<>!~", c) >= 0 {
			break
		}
		p.pos++
	}
	return p.src[start:p.pos]
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

// ---- evaluation --------------------------------------------------------------------------------

// Match evaluates the parsed expression against a Queryable.
//
// Returns a plain bool, not (bool, error): every Expr was type-checked when it was parsed, so
// evaluating one cannot fail. A query that legitimately matches nothing looks like Parse returning
// an *Expr whose Match is false — which is a different value, of a different type, from Parse
// returning an error.
//
// A nil *Expr matches everything, so a caller holding "no filter" need not special-case it.
func (e *Expr) Match(q Queryable) bool {
	if e == nil {
		return true
	}
	switch e.kind {
	case kindAnd:
		return e.left.Match(q) && e.right.Match(q)
	case kindOr:
		return e.left.Match(q) || e.right.Match(q)
	case kindNot:
		return !e.left.Match(q)
	case kindCmp:
		return e.matchCmp(q)
	}
	// Unreachable: kind is set only by this package's parser, and every kind it sets is above.
	return false
}

func (e *Expr) matchCmp(q Queryable) bool {
	switch e.field {
	case fieldHost:
		// Case-insensitive: DNS names are, and an operator who typed `Example.COM` means the same
		// host as `example.com`. Burp's own history search defaults to case-insensitive and offers
		// a separate opt-in checkbox, which is the same call made here.
		return strOp(e.op, q.Host(), e.str, true)
	case fieldMethod:
		// Case-sensitive per RFC 7230: a server that defines only GET does not also answer `get`.
		return strOp(e.op, q.Method(), e.str, false)
	case fieldPath:
		path := q.Path()
		if path == "" {
			return false // absent path: no comparison on it can hold, `!=` included
		}
		// Case-sensitive per RFC 3986: /Admin and /admin are different resources.
		return strOp(e.op, path, e.str, false)
	case fieldMime:
		mime := q.Mime()
		if mime == "" {
			return false // absent Content-Type: no comparison on it can hold
		}
		// Type and subtype are case-insensitive per RFC 2045.
		return strOp(e.op, mime, e.str, true)
	case fieldStatus:
		status := q.Status()
		if status == 0 {
			return false // no response yet: not a 0-status response
		}
		return statusOp(e, status)
	case fieldBody:
		// Case-sensitive and byte-exact: a body needle is content, not an identifier.
		return bytes.Contains(q.Body(), []byte(e.str))
	case fieldLength:
		length, present := q.ResponseLen()
		if !present {
			// No response: not a zero-length one. `length != 0` must not sweep up every request
			// still in flight, which is precisely what a bare int64 here would have done.
			return false
		}
		return numOp(e, length)
	case fieldExtension:
		path := q.Path()
		if path == "" {
			return false // no path: nothing to take an extension from
		}
		ext, has := pathExtension(path)
		if !has {
			// No extension is not an empty extension. `extension != "js"` must not sweep up every
			// extensionless path, the same rule an absent header follows.
			return false
		}
		// Case-insensitive: a URL naming LOGO.PNG and one naming logo.png name the same file type,
		// and Burp's own filter folds it.
		return strOp(e.op, ext, e.str, true)
	case fieldParams:
		path := q.Path()
		if path == "" {
			return false
		}
		// Derived rather than carried, because it is derivable exactly: the count is a property of
		// the path this row already has, so no adapter has to answer a new question and none can
		// answer it differently. The UI's Query column computes the same thing client-side from the
		// same string (see pathParts in history.tsx), which is why this counts QUERY parameters only
		// and not body parameters — a field named `params` that silently included body parameters
		// would disagree with the column beside it.
		return numOp(e, int64(queryParamCount(path)))
	case fieldHeader:
		values, present := q.Header(e.key)
		if !present {
			// An absent header fails every comparison, `!=` included — the same rule as an absent
			// status. Without it, `header["x-api-key"] != "leaked"` would be true for every response
			// that has no such header, which is the opposite of what an operator asking about
			// x-api-key wants to see.
			return false
		}
		// Any-of over the values. Set-Cookie repeats, and "does any cookie contain HttpOnly" is the
		// question; requiring all of them would answer a different one. For `!=` this means "some
		// value differs", which is the reading consistent with the other operators — an operator who
		// wants "no value equals" writes `not header["x"] = "y"`, and the precedence rules make that
		// expressible.
		for _, value := range values {
			// Case-insensitive on the value: header values are compared this way throughout this
			// package's string fields except method and path, where a spec says otherwise. No spec
			// makes a general header value case-sensitive.
			if strOp(e.op, value, e.str, true) {
				return true
			}
		}
		return false
	case fieldDuration:
		us, measured := q.DurationUs()
		if !measured {
			// Nobody timed this exchange. An unmeasured duration is not a fast one, and
			// `duration < 100ms` reporting it would be the tool inventing a measurement.
			return false
		}
		return numOp(e, us)
	}
	// Unreachable: field is set only by parseCmp, from fieldByName.
	return false
}

func strOp(o op, actual, expected string, caseInsensitive bool) bool {
	switch o {
	case opEq:
		if caseInsensitive {
			return strings.EqualFold(actual, expected)
		}
		return actual == expected
	case opNe:
		if caseInsensitive {
			return !strings.EqualFold(actual, expected)
		}
		return actual != expected
	case opContains:
		if caseInsensitive {
			return strings.Contains(strings.ToLower(actual), strings.ToLower(expected))
		}
		return strings.Contains(actual, expected)
	}
	// Unreachable: fieldAllows admits no other operator for a string field.
	return false
}

// pathExtension returns the lowercased extension of a path's last segment, and whether it has one.
//
// The query string is cut first: `/report.pdf?v=2` has extension "pdf", and a naive last-dot search
// would find the one in `?v=2.1` on a path with no extension at all. A leading dot on the segment
// itself (`/.env`) is not an extension either — the whole name is ".env" — because treating it as
// one would make `extension = "env"` match a dotfile whose type is not env.
func pathExtension(path string) (string, bool) {
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		path = path[:cut]
	}
	segment := path
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		segment = path[slash+1:]
	}
	dot := strings.LastIndexByte(segment, '.')
	if dot <= 0 || dot == len(segment)-1 {
		// dot <= 0 covers both "no dot" and a leading dot; dot at the end is a trailing dot with no
		// extension after it.
		return "", false
	}
	return strings.ToLower(segment[dot+1:]), true
}

// queryParamCount counts the query parameters in a path.
//
// Empty pairs are not counted: `?a=1&&b=2` has two parameters, not three, and `?` alone has none. A
// count that included them would report a number an operator cannot see anywhere on screen.
func queryParamCount(path string) int {
	cut := strings.IndexByte(path, '?')
	if cut < 0 {
		return 0
	}
	query := path[cut+1:]
	if fragment := strings.IndexByte(query, '#'); fragment >= 0 {
		query = query[:fragment]
	}
	count := 0
	for _, pair := range strings.Split(query, "&") {
		if pair != "" {
			count++
		}
	}
	return count
}

// numOp is statusOp for the wide numeric fields. Kept separate rather than made generic: status
// carries its bounds in uint16 and these in int64, and a shared helper would have to widen or
// narrow one of them at the comparison, which is where an off-by-a-factor hides.
func numOp(e *Expr, actual int64) bool {
	switch e.op {
	case opEq:
		return actual == e.num64
	case opNe:
		return actual != e.num64
	case opLt:
		return actual < e.num64
	case opLe:
		return actual <= e.num64
	case opGt:
		return actual > e.num64
	case opGe:
		return actual >= e.num64
	case opIn:
		// Inclusive of both ends, as status ranges are.
		return actual >= e.lo64 && actual <= e.hi64
	}
	// Unreachable: fieldAllows admits no other operator for these fields.
	return false
}

func statusOp(e *Expr, actual int) bool {
	want := int(e.num)
	switch e.op {
	case opEq:
		return actual == want
	case opNe:
		return actual != want
	case opLt:
		return actual < want
	case opLe:
		return actual <= want
	case opGt:
		return actual > want
	case opGe:
		return actual >= want
	case opIn:
		// Inclusive of both ends: `status in 200..299` matches 200 and 299.
		return actual >= int(e.lo) && actual <= int(e.hi)
	}
	// Unreachable: fieldAllows admits no other operator for status.
	return false
}
