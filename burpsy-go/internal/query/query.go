// Package query implements a small DSL for filtering traffic history.
// Grammar: or-expression over and-expressions over comparisons.
//   expr   := or-expr
//   or-expr := and-expr ("or" and-expr)*
//   and-expr := not-expr ("and" not-expr)*
//   not-expr := "not" not-expr | cmp
//   cmp    := field op value
//   field  := "host" | "method" | "status" | "mime" | "body"
//   op     := "=" | "!=" | "~" | ">" | ">=" | "<" | "<="
//   value  := STRING | NUMBER | IDENT
//
// Example: host ~ "example" and status >= 400
package query

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Expr is a parsed query expression.
type Expr struct {
	Kind ExprKind
	// And / Or
	Left  *Expr
	Right *Expr
	// Cmp
	Field string
	Op    string
	Val   string
	IsNum bool
}

type ExprKind int

const (
	KindAnd ExprKind = iota
	KindOr
	KindNot
	KindCmp
)

// Queryable is what the evaluator inspects on each exchange.
type Queryable interface {
	Host() string
	Method() string
	Status() int // 0 = absent
	Mime() string
	Body() []byte
}

// Parse parses a query string.
func Parse(input string) (*Expr, error) {
	p := &parser{src: input, pos: 0}
	return p.parseOr()
}

type parser struct {
	src string
	pos int
}

func (p *parser) peek() byte {
	if p.pos >= len(p.src) { return 0 }
	return p.src[p.pos]
}

func (p *parser) skipWs() {
	for p.pos < len(p.src) && unicode.IsSpace(rune(p.src[p.pos])) { p.pos++ }
}

func (p *parser) consumeIdent() string {
	p.skipWs()
	start := p.pos
	for p.pos < len(p.src) && (p.src[p.pos] == '_' || unicode.IsLetter(rune(p.src[p.pos])) || unicode.IsDigit(rune(p.src[p.pos]))) {
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *parser) consumeString() (string, error) {
	p.skipWs()
	if p.peek() != '"' { return "", p.errf("expected quoted string") }
	p.pos++
	start := p.pos
	for p.pos < len(p.src) && p.src[p.pos] != '"' { p.pos++ }
	if p.pos >= len(p.src) { return "", p.errf("unterminated string") }
	s := p.src[start:p.pos]
	p.pos++
	return s, nil
}

func (p *parser) consumeOp() string {
	p.skipWs()
	start := p.pos
	for p.pos < len(p.src) && strings.ContainsRune("=<>!~", rune(p.src[p.pos])) { p.pos++ }
	return p.src[start:p.pos]
}

func (p *parser) consumeValue() (string, bool, error) {
	p.skipWs()
	c := p.peek()
	if c == '"' {
		s, err := p.consumeStringSorted()
		return s, false, err
	}
	start := p.pos
	for p.pos < len(p.src) && !unicode.IsSpace(rune(p.src[p.pos])) &&
		p.src[p.pos] != ')' && !strings.ContainsRune("=<>!~", rune(p.src[p.pos])) {
		p.pos++
	}
	if start == p.pos { return "", false, p.errf("expected value") }
	s := p.src[start:p.pos]
	if _, err := strconv.Atoi(s); err == nil { return s, true, nil }
	return s, false, nil
}

func (p *parser) consumeStringSorted() (string, error) { return p.consumeString() }

func (p *parser) errf(format string, args ...interface{}) error {
	return fmt.Errorf("query parse error at pos %d: %s", p.pos, fmt.Sprintf(format, args...))
}

func (p *parser) parseOr() (*Expr, error) {
	left, err := p.parseAnd()
	if err != nil { return nil, err }
	for {
		p.skipWs()
		if !p.consumeKeyword("or") { break }
		right, err := p.parseAnd()
		if err != nil { return nil, err }
		left = &Expr{Kind: KindOr, Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (*Expr, error) {
	left, err := p.parseNot()
	if err != nil { return nil, err }
	for {
		p.skipWs()
		if !p.consumeKeyword("and") { break }
		right, err := p.parseNot()
		if err != nil { return nil, err }
		left = &Expr{Kind: KindAnd, Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseNot() (*Expr, error) {
	p.skipWs()
	if p.consumeKeyword("not") {
		sub, err := p.parseNot()
		if err != nil { return nil, err }
		return &Expr{Kind: KindNot, Left: sub}, nil
	}
	return p.parseCmp()
}

func (p *parser) parseCmp() (*Expr, error) {
	p.skipWs()
	field := p.consumeIdent()
	if field == "" { return nil, p.errf("expected field name (host/method/status/mime/body)") }
	op := p.consumeOp()
	if op == "" { return nil, p.errf("expected operator (=, !=, ~, >, >=, <, <=)") }
	val, isNum, err := p.consumeValue()
	if err != nil { return nil, err }
	return &Expr{Kind: KindCmp, Field: field, Op: op, Val: val, IsNum: isNum}, nil
}

func (p *parser) consumeKeyword(kw string) bool {
	saved := p.pos
	p.skipWs()
	ident := p.consumeIdent()
	if strings.EqualFold(ident, kw) { return true }
	p.pos = saved
	return false
}

// Match evaluates the parsed expression against a Queryable.
func (e *Expr) Match(q Queryable) bool {
	if e == nil { return true }
	switch e.Kind {
	case KindAnd:
		return e.Left.Match(q) && e.Right.Match(q)
	case KindOr:
		return e.Left.Match(q) || e.Right.Match(q)
	case KindNot:
		return !e.Left.Match(q)
	case KindCmp:
		return evalCmp(e, q)
	}
	return false
}

func evalCmp(e *Expr, q Queryable) bool {
	var fieldVal string
	var isNumField bool
	switch strings.ToLower(e.Field) {
	case "host":
		fieldVal = q.Host()
	case "method":
		fieldVal = q.Method()
	case "status":
		fieldVal = strconv.Itoa(q.Status())
		isNumField = true
	case "mime":
		fieldVal = q.Mime()
	case "body":
		return strings.Contains(string(q.Body()), e.Val)
	default:
		return false
	}
	switch e.Op {
	case "=":
		return strings.EqualFold(fieldVal, e.Val)
	case "!=":
		return !strings.EqualFold(fieldVal, e.Val)
	case "~":
		return strings.Contains(strings.ToLower(fieldVal), strings.ToLower(e.Val))
	case ">=", "<=", ">", "<":
		a, errA := strconv.ParseInt(fieldVal, 10, 64)
		b, errB := strconv.ParseInt(e.Val, 10, 64)
		if errA != nil || errB != nil {
			_ = isNumField
			return false
		}
		return compareNum(a, b, e.Op)
	}
	return false
}

func compareNum(a, b int64, op string) bool {
	switch op {
	case ">":
		return a > b
	case ">=":
		return a >= b
	case "<":
		return a < b
	case "<=":
		return a <= b
	}
	return false
}
