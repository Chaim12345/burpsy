package bcheck

import (
	"fmt"
	"strings"
)

// tokenKind enumerates lexer token types.
type tokenKind int

const (
	tokWord tokenKind = iota // bare word: keyword or identifier
	tokLitStr                // "..." — literal, no interpolation
	tokTemplate              // `...` — template string
	tokVarRef                // {...} — variable reference
	tokColon
	tokComma
	tokEquals
	tokLParen
	tokRParen
	tokEof
)

type token struct {
	kind tokenKind
	text string
	line int
	col  int
}

// lex tokenizes BCheck source. Whitespace and newlines are insignificant;
// `end if` is the only block terminator, so this is a flat token stream.
func lex(src string) ([]token, *ParseError) {
	var toks []token
	line, col := 1, 1
	i := 0
	n := len(src)

	emit := func(kind tokenKind, text string) {
		toks = append(toks, token{kind: kind, text: text, line: line, col: col})
	}

	for i < n {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
			col++
		case c == '\n':
			i++
			line++
			col = 1
		case c == '#':
			// Comment: skip to end of line.
			for i < n && src[i] != '\n' {
				i++
				col++
			}
		case c == ':':
			emit(tokColon, ":")
			i++
			col++
		case c == ',':
			emit(tokComma, ",")
			i++
			col++
		case c == '=':
			emit(tokEquals, "=")
			i++
			col++
		case c == '(':
			emit(tokLParen, "(")
			i++
			col++
		case c == ')':
			emit(tokRParen, ")")
			i++
			col++
		case c == '"':
			start := i
			i++
			col++
			var sb strings.Builder
			for i < n && src[i] != '"' {
				if src[i] == '\\' && i+1 < n {
					sb.WriteByte(src[i+1])
					i += 2
					col += 2
					continue
				}
				sb.WriteByte(src[i])
				if src[i] == '\n' {
					line++
					col = 1
				} else {
					col++
				}
				i++
			}
			if i >= n {
				return nil, &ParseError{Message: "unterminated string literal", Line: line, Column: col}
			}
			i++ // closing quote
			col++
			emit(tokLitStr, sb.String())
			_ = start
		case c == '`':
			i++
			col++
			var sb strings.Builder
			for i < n && src[i] != '`' {
				if src[i] == '\\' && i+1 < n && src[i+1] == '{' {
					// \{ escapes an interpolation brace; keep the brace.
					sb.WriteByte('{')
					i += 2
					col += 2
					continue
				}
				sb.WriteByte(src[i])
				if src[i] == '\n' {
					line++
					col = 1
				} else {
					col++
				}
				i++
			}
			if i >= n {
				return nil, &ParseError{Message: "unterminated template string", Line: line, Column: col}
			}
			i++
			col++
			emit(tokTemplate, sb.String())
		case c == '{':
			start := i
			i++
			col++
			for i < n && src[i] != '}' {
				i++
				col++
			}
			if i >= n {
				return nil, &ParseError{Message: "unterminated variable reference", Line: line, Column: col}
			}
			name := src[start+1 : i]
			i++
			col++
			emit(tokVarRef, name)
		default:
			// Bare word: letters, digits, and a few punctuation chars.
			start := i
			for i < n && !strings.ContainsRune(" \t\r\n:,=(){}`\"#", rune(src[i])) {
				i++
				col++
			}
			emit(tokWord, src[start:i])
		}
	}
	emit(tokEof, "")
	return toks, nil
}

// parser is a recursive-descent parser over the token stream.
type parser struct {
	toks []token
	i    int
}

// Parse parses a BCheck source string into a Check AST.
func Parse(src string) (*Check, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	return p.check()
}

func (p *parser) peek() token {
	return p.toks[p.i]
}

func (p *parser) at(off int) token {
	idx := p.i + off
	if idx >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[idx]
}

func (p *parser) bump() token {
	t := p.toks[p.i]
	if p.i < len(p.toks)-1 {
		p.i++
	}
	return t
}

func (p *parser) errf(format string, args ...interface{}) error {
	t := p.peek()
	return &ParseError{
		Message: fmt.Sprintf(format, args...),
		Line:    t.line,
		Column:  t.col,
	}
}

func (p *parser) isWord(off int, w string) bool {
	t := p.at(off)
	return t.kind == tokWord && strings.EqualFold(t.text, w)
}

func (p *parser) eatWord(w string) bool {
	if p.isWord(0, w) {
		p.bump()
		return true
	}
	return false
}

func (p *parser) expectWord(w string) error {
	if !p.eatWord(w) {
		return p.errf("expected %q, found %q", w, p.peek().text)
	}
	return nil
}

// isPhrase checks a multi-word keyword (e.g. "report issue", "end if").
func (p *parser) isPhrase(words ...string) bool {
	for k, w := range words {
		if !p.isWord(k, w) {
			return false
		}
	}
	return true
}

func (p *parser) eatPhrase(words ...string) bool {
	if p.isPhrase(words...) {
		for range words {
			p.bump()
		}
		return true
	}
	return false
}

func (p *parser) expectColon() error {
	if p.peek().kind != tokColon {
		return p.errf("expected ':', found %q", p.peek().text)
	}
	p.bump()
	return nil
}

// atSection reports whether the current token begins a new top-level section.
func (p *parser) atSection() bool {
	return p.isWord(0, "given") || p.isWord(0, "define") || p.isPhrase("run", "for", "each") ||
		p.peek().kind == tokEof
}

// check parses the whole file: metadata, defines, for-each, given/then, body.
func (p *parser) check() (*Check, error) {
	c := &Check{}

	// metadata: is optional in the corpus.
	if p.isWord(0, "metadata") && p.at(1).kind == tokColon {
		if err := p.metadata(c); err != nil {
			return nil, err
		}
	}

	// define: and run for each: may appear in either order, possibly both.
	for k := 0; k < 2; k++ {
		if err := p.defineBlock(&c.Defines); err != nil {
			return nil, err
		}
		if err := p.forEachBlock(&c.ForEach); err != nil {
			return nil, err
		}
	}

	if err := p.expectWord("given"); err != nil {
		return nil, err
	}
	given, err := p.frequency()
	if err != nil {
		return nil, err
	}
	c.Given = given
	if err := p.expectWord("then"); err != nil {
		return nil, err
	}
	body, err := p.statements()
	if err != nil {
		return nil, err
	}
	c.Statements = body
	return c, nil
}

func (p *parser) metadata(c *Check) error {
	p.bump() // metadata
	if err := p.expectColon(); err != nil {
		return err
	}
	for !p.atSection() {
		key := p.bump()
		if key.kind != tokWord {
			return p.errf("expected metadata field, found %q", key.text)
		}
		if err := p.expectColon(); err != nil {
			return err
		}
		val, err := p.value()
		if err != nil {
			return err
		}
		switch strings.ToLower(key.text) {
		case "name":
			c.Name = val.StringVal
		case "description":
			c.Metadata.Description = val.StringVal
		case "author":
			c.Metadata.Author = val.StringVal
		case "severity":
			c.Metadata.Severity = val.StringVal
		case "confidence":
			c.Metadata.Confidence = val.StringVal
		case "tags", "reference":
			c.Metadata.Reference = append(c.Metadata.Reference, val.StringVal)
			for p.peek().kind == tokComma {
				p.bump()
				v, err := p.value()
				if err != nil {
					return err
				}
				c.Metadata.Reference = append(c.Metadata.Reference, v.StringVal)
			}
		default:
			// Unknown metadata fields are tolerated (v2-beta extensions).
		}
	}
	return nil
}

// defineBlock parses `define: name = value, name = value`.
func (p *parser) defineBlock(defines *[]DefineStatement) error {
	if !(p.isWord(0, "define") && p.at(1).kind == tokColon) {
		return nil
	}
	p.bump()
	p.bump()
	for p.peek().kind == tokWord && !p.atSection() {
		name := p.bump().text
		if p.peek().kind != tokEquals {
			return p.errf("expected '=' in define")
		}
		p.bump()
		v, err := p.value()
		if err != nil {
			return err
		}
		*defines = append(*defines, DefineStatement{Name: name, Value: v})
		if p.peek().kind == tokComma {
			p.bump()
		}
	}
	return nil
}

// forEachBlock parses `run for each: name = v1, v2`.
func (p *parser) forEachBlock(forEach *[]RunForEachStatement) error {
	if !p.isPhrase("run", "for", "each") {
		return nil
	}
	p.bump()
	p.bump()
	p.bump()
	if err := p.expectColon(); err != nil {
		return err
	}
	for p.peek().kind == tokWord && !p.atSection() {
		name := p.bump().text
		if p.peek().kind != tokEquals {
			return p.errf("expected '=' in run for each")
		}
		p.bump()
		vals := []Value{}
		for {
			v, err := p.value()
			if err != nil {
				return err
			}
			vals = append(vals, v)
			if p.peek().kind == tokComma {
				p.bump()
				continue
			}
			break
		}
		*forEach = append(*forEach, RunForEachStatement{Iterator: name, Values: vals})
	}
	return nil
}

// frequency parses `response | host | request | path | insertion point | <type> or <type> insertion point`.
func (p *parser) frequency() (string, error) {
	t := p.peek()
	if t.kind != tokWord {
		return "", p.errf("expected host|path|request|response|insertion point, found %q", t.text)
	}
	// Consume one or more insertion point types joined by "or".
	var types []string
	for p.peek().kind == tokWord {
		w := strings.ToLower(p.peek().text)
		if w == "any" || w == "query" || w == "header" || w == "body" || w == "cookie" {
			types = append(types, w)
			p.bump()
			if !p.eatWord("or") {
				break
			}
			continue
		}
		break
	}
	if len(types) > 0 {
		if !p.eatPhrase("insertion", "point") {
			return "", p.errf("expected 'insertion point'")
		}
		return "insertion point", nil
	}
	if p.eatPhrase("insertion", "point") {
		return "insertion point", nil
	}
	if p.eatWord("response") {
		return "response", nil
	}
	if p.eatWord("host") {
		return "host", nil
	}
	if p.eatWord("request") {
		return "request", nil
	}
	if p.eatWord("path") {
		return "path", nil
	}
	return "", p.errf("expected host|path|request|response|insertion point, found %q", t.text)
}

// statements parses statements until a block terminator.
func (p *parser) statements() ([]Statement, error) {
	var out []Statement
	for {
		if p.peek().kind == tokEof || p.isPhrase("end", "if") || p.isWord(0, "else") {
			break
		}
		stmt, err := p.statement()
		if err != nil {
			return nil, err
		}
		out = append(out, stmt)
	}
	return out, nil
}

func (p *parser) statement() (Statement, error) {
	if p.isWord(0, "if") {
		return p.ifBlock()
	}
	if p.isPhrase("report", "issue") {
		return p.reportIssue()
	}
	if p.isPhrase("send", "request") {
		return p.sendRequest()
	}
	return nil, p.errf("unexpected statement start %q", p.peek().text)
}

func (p *parser) ifBlock() (Statement, error) {
	p.bump() // if
	cond, err := p.boolExpr()
	if err != nil {
		return nil, err
	}
	if err := p.expectWord("then"); err != nil {
		return nil, err
	}
	then, err := p.statements()
	if err != nil {
		return nil, err
	}
	var otherwise []Statement
	if p.isWord(0, "else") {
		p.bump()
		if p.isWord(0, "if") {
			// `else if ...` — nested chain, shares the outer `end if`.
			nested, err := p.ifBlockNoEnd()
			if err != nil {
				return nil, err
			}
			otherwise = []Statement{nested}
			return &IfStatement{Condition: cond, Then: then, Else: otherwise}, nil
		}
		if err := p.expectWord("then"); err != nil {
			return nil, err
		}
		otherwise, err = p.statements()
		if err != nil {
			return nil, err
		}
	}
	if !p.eatPhrase("end", "if") {
		return nil, p.errf("expected 'end if', found %q", p.peek().text)
	}
	return &IfStatement{Condition: cond, Then: then, Else: otherwise}, nil
}

// ifBlockNoEnd parses an `else if` chain tail that shares the outer `end if`.
func (p *parser) ifBlockNoEnd() (Statement, error) {
	p.bump() // if
	cond, err := p.boolExpr()
	if err != nil {
		return nil, err
	}
	if err := p.expectWord("then"); err != nil {
		return nil, err
	}
	then, err := p.statements()
	if err != nil {
		return nil, err
	}
	var otherwise []Statement
	if p.isWord(0, "else") {
		p.bump()
		if p.isWord(0, "if") {
			nested, err := p.ifBlockNoEnd()
			if err != nil {
				return nil, err
			}
			otherwise = []Statement{nested}
		} else {
			if err := p.expectWord("then"); err != nil {
				return nil, err
			}
			otherwise, err = p.statements()
			if err != nil {
				return nil, err
			}
		}
	}
	p.eatPhrase("end", "if")
	return &IfStatement{Condition: cond, Then: then, Else: otherwise}, nil
}

// reportIssue parses `report issue [and continue]: name: ... severity: ...`.
func (p *parser) reportIssue() (Statement, error) {
	p.bump() // report
	p.bump() // issue
	p.eatPhrase("and", "continue")
	if err := p.expectColon(); err != nil {
		return nil, err
	}
	stmt := &ReportIssueStatement{}
	for {
		t := p.peek()
		if t.kind != tokWord || p.at(1).kind != tokColon {
			break
		}
		// Stop at anything that starts a new statement or closes the block.
		if strings.EqualFold(t.text, "if") || strings.EqualFold(t.text, "end") ||
			strings.EqualFold(t.text, "else") || strings.EqualFold(t.text, "report") ||
			strings.EqualFold(t.text, "send") {
			break
		}
		p.bump()
		p.bump() // colon
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		switch strings.ToLower(t.text) {
		case "name":
			stmt.IssueName = val.StringVal
		case "severity":
			sev, err := normalizeSeverity(val.StringVal)
			if err != nil {
				return nil, p.errf("bad severity %q", val.StringVal)
			}
			stmt.Severity = sev
		case "confidence":
			conf, err := normalizeConfidence(val.StringVal)
			if err != nil {
				return nil, p.errf("bad confidence %q", val.StringVal)
			}
			stmt.Confidence = conf
		case "detail":
			stmt.Description = val.StringVal
		case "remediation":
			stmt.Remediation = val.StringVal
		default:
			return nil, p.errf("unknown report issue field %q", t.text)
		}
	}
	if stmt.Severity == "" {
		return nil, p.errf("report issue requires 'severity'")
	}
	if stmt.Confidence == "" {
		return nil, p.errf("report issue requires 'confidence'")
	}
	return stmt, nil
}

// normalizeSeverity maps DSL severity names to the canonical Severity strings.
func normalizeSeverity(v string) (string, error) {
	switch strings.ToLower(v) {
	case "high":
		return string(SeverityHigh), nil
	case "medium":
		return string(SeverityMedium), nil
	case "low":
		return string(SeverityLow), nil
	case "info", "informational":
		return string(SeverityInfo), nil
	}
	return "", fmt.Errorf("unknown severity %q", v)
}

// normalizeConfidence maps DSL confidence names to the canonical Confidence strings.
func normalizeConfidence(v string) (string, error) {
	switch strings.ToLower(v) {
	case "certain":
		return string(ConfidenceCertain), nil
	case "firm":
		return string(ConfidenceFirm), nil
	case "tentative":
		return string(ConfidenceTentative), nil
	}
	return "", fmt.Errorf("unknown confidence %q", v)
}

// sendRequest parses `send request [called name]: ...` structurally so M1
// never rejects an active check, even though M1 performs no outbound traffic.
func (p *parser) sendRequest() (Statement, error) {
	p.bump() // send
	p.bump() // request
	stmt := &SendRequestStatement{}
	if p.eatWord("called") {
		t := p.bump()
		stmt.StoreAs = t.text
	}
	if err := p.expectColon(); err != nil {
		return nil, err
	}
	// Raw request string, or modifier clauses — consumed loosely.
	if p.peek().kind == tokLitStr || p.peek().kind == tokTemplate {
		stmt.Template = p.bump().text
	} else {
		for {
			if p.peek().kind != tokWord || p.at(1).kind != tokColon {
				break
			}
			// A request modifier clause: target ":" value.
			p.bump()
			p.bump()
			if p.peek().kind == tokEquals {
				p.bump()
			}
			if _, err := p.value(); err != nil {
				return nil, err
			}
		}
	}
	return stmt, nil
}

// boolExpr parses `term (and|or term)*`.
func (p *parser) boolExpr() (BoolExpr, error) {
	lhs, err := p.boolTerm()
	if err != nil {
		return BoolExpr{}, err
	}
	for {
		if p.eatWord("and") {
			// `and continue` belongs to report issue, not a boolean chain.
			if p.isWord(0, "continue") {
				p.i--
				break
			}
			rhs, err := p.boolTerm()
			if err != nil {
				return BoolExpr{}, err
			}
			l := lhs
			lhs = BoolExpr{Operator: "and", LHS: &l, RHS: &rhs}
		} else if p.eatWord("or") {
			rhs, err := p.boolTerm()
			if err != nil {
				return BoolExpr{}, err
			}
			l := lhs
			lhs = BoolExpr{Operator: "or", LHS: &l, RHS: &rhs}
		} else {
			break
		}
	}
	return lhs, nil
}

func (p *parser) boolTerm() (BoolExpr, error) {
	if p.eatWord("not") {
		if p.peek().kind != tokLParen {
			return BoolExpr{}, p.errf("expected '(' after 'not'")
		}
		p.bump()
		e, err := p.boolExpr()
		if err != nil {
			return BoolExpr{}, err
		}
		if p.peek().kind != tokRParen {
			return BoolExpr{}, p.errf("expected ')'")
		}
		p.bump()
		return BoolExpr{Operator: "not", LHS: &e}, nil
	}
	if p.peek().kind == tokLParen {
		p.bump()
		e, err := p.boolExpr()
		if err != nil {
			return BoolExpr{}, err
		}
		if p.peek().kind != tokRParen {
			return BoolExpr{}, p.errf("expected ')'")
		}
		p.bump()
		return e, nil
	}

	lhs, err := p.value()
	if err != nil {
		return BoolExpr{}, err
	}
	var op string
	switch {
	case p.eatWord("matches"):
		op = "matches"
	case p.eatWord("in"):
		op = "in"
	case p.eatWord("is"):
		op = "is"
	case p.eatPhrase("differs", "from"):
		op = "ne"
	case p.eatWord("contains"):
		op = "contains"
	case p.eatWord("eq"):
		op = "eq"
	case p.eatWord("ne"):
		op = "ne"
	default:
		return BoolExpr{}, p.errf("expected matches|in|is|'differs from', found %q", p.peek().text)
	}
	rhs, err := p.value()
	if err != nil {
		return BoolExpr{}, err
	}
	return BoolExpr{Left: lhs, Operator: op, Right: rhs}, nil
}

// value parses a literal string, template string, variable reference, or bare word.
func (p *parser) value() (Value, error) {
	t := p.bump()
	switch t.kind {
	case tokLitStr:
		return Value{Type: "str", StringVal: t.text}, nil
	case tokTemplate:
		return Value{Type: "str", StringVal: t.text}, nil
	case tokVarRef:
		return Value{Type: "var", StringVal: t.text}, nil
	case tokWord:
		return Value{Type: "str", StringVal: t.text}, nil
	}
	p.i = p.i - 1
	return Value{}, p.errf("expected a value, found %q", t.text)
}
