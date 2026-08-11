package bcheck

import (
	"fmt"
	"strings"
)

// tokenKind enumerates lexer token types.
type tokenKind int

const (
	tokWord     tokenKind = iota // bare word: keyword or identifier
	tokLitStr                    // "..." — literal, no interpolation
	tokTemplate                  // `...` — template string
	tokVarRef                    // {...} — variable reference
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
				if src[i] == '\\' && i+1 < n && src[i+1] == '"' {
					// ONLY `\"` is an escape. `\\` is NOT — the corpus contains
					// JSON-in-JSON payloads like `\\"alert('x')\\"` where treating
					// `\\` as an escape would end the string at the next quote
					// and leave the rest to be lexed as code. Mirrors the Rust
					// lexer in crates/bcheck.
					sb.WriteByte('"')
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
			// A variable reference may nest braces inside a builtin call
			// (`{regex_replace({base.request.body}, "(\w+)=", `$1{poc}=`)}`), so the
			// closing brace is tracked by depth, and quoted strings inside the
			// reference are skipped whole — a `}` inside a string argument must not
			// close the reference early. Mirrors the Rust lexer in crates/bcheck.
			// The previous scan-to-first-`}` left a stray `}` on the token stream,
			// which the bare-word case emitted as an empty token forever: an
			// infinite loop that hung the whole process on five corpus files.
			i++
			col++
			var sb strings.Builder
			depth := 1
			closed := false
			for i < n && !closed {
				switch src[i] {
				case '"', '`':
					q := src[i]
					sb.WriteByte(q)
					i++
					col++
					for i < n && src[i] != q {
						if src[i] == '\\' && i+1 < n {
							sb.WriteByte(src[i])
							sb.WriteByte(src[i+1])
							i += 2
							col += 2
							continue
						}
						if src[i] == '\n' {
							line++
							col = 1
						} else {
							col++
						}
						sb.WriteByte(src[i])
						i++
					}
					if i < n {
						sb.WriteByte(q)
						i++
						col++
					}
				case '{':
					depth++
					sb.WriteByte('{')
					i++
					col++
				case '}':
					depth--
					i++
					col++
					if depth == 0 {
						closed = true
					} else {
						sb.WriteByte('}')
					}
				default:
					if src[i] == '\n' {
						line++
						col = 1
					} else {
						col++
					}
					sb.WriteByte(src[i])
					i++
				}
			}
			if !closed {
				return nil, &ParseError{Message: "unterminated variable reference", Line: line, Column: col}
			}
			emit(tokVarRef, strings.TrimSpace(sb.String()))
		default:
			// Bare word: letters, digits, and a few punctuation chars.
			start := i
			for i < n && !strings.ContainsRune(" \t\r\n:,=(){}`\"#", rune(src[i])) {
				i++
				col++
			}
			if start == i {
				// A terminator (e.g. a stray `}` with no matching `{`) must not
				// produce an empty token and spin: that was a hard hang. Erroring
				// here is honest — the input is malformed.
				return nil, &ParseError{Message: fmt.Sprintf("unexpected character %q", string(src[i])), Line: line, Column: col}
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
	given, kinds, err := p.frequency()
	if err != nil {
		return nil, err
	}
	c.Given = given
	c.InsertionKinds = kinds
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
// kinds holds the insertion-point types when given is "insertion point" ("any" when unqualified).
func (p *parser) frequency() (given string, kinds []string, err error) {
	t := p.peek()
	if t.kind != tokWord {
		return "", nil, p.errf("expected host|path|request|response|insertion point, found %q", t.text)
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
			return "", nil, p.errf("expected 'insertion point'")
		}
		return "insertion point", types, nil
	}
	if p.eatPhrase("insertion", "point") {
		return "insertion point", []string{"any"}, nil
	}
	if p.eatWord("response") {
		return "response", nil, nil
	}
	if p.eatWord("host") {
		return "host", nil, nil
	}
	if p.eatWord("request") {
		return "request", nil, nil
	}
	if p.eatWord("path") {
		return "path", nil, nil
	}
	return "", nil, p.errf("expected host|path|request|response|insertion point, found %q", t.text)
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
	if p.isPhrase("send", "payload") {
		return p.sendPayload()
	}
	if p.isPhrase("run", "tool") {
		return p.runTool()
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
			// `else if … then …` is nested and does NOT carry its own `end if`.
			// Returning here (instead of falling through to eat one) lets the
			// *innermost* if of the chain consume the single shared terminator.
			// Without this return, every intermediate level ate an `end if`
			// too, so a chain of three `else if` swallowed its parent's `end
			// if` and the enclosing if failed to find its own.
			return &IfStatement{Condition: cond, Then: then, Else: otherwise}, nil
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
	// The phrase is load-bearing, not decoration: it selects whether the check
	// keeps running after this report. Discarding it (which this did) collapses
	// both forms onto `and continue`.
	keepGoing := p.eatPhrase("and", "continue")
	if err := p.expectColon(); err != nil {
		return nil, err
	}
	stmt := &ReportIssueStatement{Continue: keepGoing}
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
			stmt.IssueName = val
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
			stmt.Description = val
		case "remediation":
			stmt.Remediation = val
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

// sendRequest parses `send request [called name]:` into a raw-request form or a list of
// modifier clauses, kept on the AST so the active evaluator can actually send.
//
// The raw form is a single literal or template string. The structural form is a sequence of
// clauses, each an optional `replacing`/`appending` prefix, a target word (`method`, `path`,
// `query_string`, `queries`, `headers`, `body`), a colon, then a value — a comma-separated
// list for `queries`, and `"Name": value` pairs for `headers`. A statement keyword where
// the target would sit ends the block.
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
	if p.peek().kind == tokLitStr || p.peek().kind == tokTemplate {
		stmt.Template = p.bump().text
		return stmt, nil
	}
	for {
		op := ModReplace
		opOff := 0
		if p.peek().kind == tokWord {
			switch strings.ToLower(p.peek().text) {
			case "replacing":
				op, opOff = ModReplace, 1
			case "appending":
				op, opOff = ModAppend, 1
			}
		}
		if p.at(opOff).kind != tokWord || p.at(opOff+1).kind != tokColon {
			break
		}
		target := strings.ToLower(p.at(opOff).text)
		if target == "if" || target == "end" || target == "else" || target == "report" || target == "send" {
			break
		}
		for i := 0; i <= opOff+1; i++ {
			p.bump()
		}
		if p.peek().kind == tokEquals {
			p.bump()
		}
		mod := RequestModifier{Target: target, Op: op}
		if target == "headers" || target == "header" {
			// `"Name": value` pairs, comma-separated — stored flat as
			// [name, value, name, value, …] so the evaluator applies them in
			// source order.
			for {
				n, err := p.value()
				if err != nil {
					return nil, err
				}
				if p.peek().kind != tokColon {
					return nil, p.errf("expected ':' in headers modifier")
				}
				p.bump()
				v, err := p.value()
				if err != nil {
					return nil, err
				}
				mod.Values = append(mod.Values, n, v)
				if p.peek().kind != tokComma {
					break
				}
				p.bump()
			}
		} else {
			for {
				v, err := p.value()
				if err != nil {
					return nil, err
				}
				mod.Values = append(mod.Values, v)
				if p.peek().kind != tokComma {
					break
				}
				p.bump()
			}
		}
		stmt.Modifiers = append(stmt.Modifiers, mod)
	}
	return stmt, nil
}

// runTool parses `run tool <tool> [called <name>]: args: v1, v2, ...`.
//
// The tool name is a value (usually a bare word — `sqlmap`), resolved against
// the caller's allowlist at execute time. `args:` is the one clause; each arg
// is a value, resolved like any other. A statement keyword where the next
// clause would sit ends the block, matching sendRequest.
func (p *parser) runTool() (Statement, error) {
	p.bump() // run
	p.bump() // tool
	stmt := &RunToolStatement{}
	tv, err := p.value()
	if err != nil {
		return nil, err
	}
	stmt.Tool = tv
	if p.eatWord("called") {
		t := p.bump()
		stmt.StoreAs = t.text
	}
	if err := p.expectColon(); err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind != tokWord || p.at(1).kind != tokColon {
			break
		}
		if strings.EqualFold(t.text, "if") || strings.EqualFold(t.text, "end") ||
			strings.EqualFold(t.text, "else") || strings.EqualFold(t.text, "report") ||
			strings.EqualFold(t.text, "send") || strings.EqualFold(t.text, "run") {
			break
		}
		p.bump()
		p.bump() // colon
		switch strings.ToLower(t.text) {
		case "args":
			for {
				v, err := p.value()
				if err != nil {
					return nil, err
				}
				stmt.Args = append(stmt.Args, v)
				if p.peek().kind != tokComma {
					break
				}
				p.bump()
			}
		default:
			return nil, p.errf("unknown run tool field %q", t.text)
		}
	}
	return stmt, nil
}

// sendPayload parses `send payload [called name]: appending|replacing: <value>`.
// Parsed structurally so the insertion-point checks parse and can be counted;
// sending is never performed by the passive evaluator.
func (p *parser) sendPayload() (Statement, error) {
	p.bump() // send
	p.bump() // payload
	stmt := &SendPayloadStatement{}
	if p.eatWord("called") {
		t := p.bump()
		stmt.StoreAs = t.text
	}
	if err := p.expectColon(); err != nil {
		return nil, err
	}
	// Only `appending:` / `replacing:` exist — there is no `inserting:`.
	if p.eatWord("appending") {
		stmt.Appending = true
	} else if !p.eatWord("replacing") {
		return nil, p.errf("expected 'appending' or 'replacing', found %q", p.peek().text)
	}
	if err := p.expectColon(); err != nil {
		return nil, err
	}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	stmt.Value = v
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

	// `<type> interactions` — Collaborator poll, as in the reference grammar.
	if p.peek().kind == tokWord {
		lw := strings.ToLower(p.peek().text)
		if (lw == "any" || lw == "dns" || lw == "http" || lw == "smtp") && p.isWord(1, "interactions") {
			p.bump()
			p.bump()
			return BoolExpr{Operator: "interactions", Left: Value{Type: "str", StringVal: lw}}, nil
		}
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
		// Distinct from a literal so the evaluator can interpolate `{…}` at
		// resolve time. Collapsing templates into literals corrupts the report
		// text of the corpus checks that build detail lines in a backtick string.
		return Value{Type: "tpl", StringVal: t.text}, nil
	case tokVarRef:
		return Value{Type: "var", StringVal: t.text}, nil
	case tokWord:
		return Value{Type: "str", StringVal: t.text}, nil
	}
	p.i = p.i - 1
	return Value{}, p.errf("expected a value, found %q", t.text)
}
