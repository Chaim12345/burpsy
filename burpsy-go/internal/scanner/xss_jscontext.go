// xss_jscontext.go decides whether a canary reflected into a <script> actually escaped the string
// literal that encloses it, or merely appears to have.
//
// This is the false-positive half of the context work, and it lands ahead of the payload work
// deliberately: a wrong finding against correctly-escaped code is worse than a missed one.
//
// The measured failure it fixes: an endpoint that reflects through json.Marshal into a <script>
// was reported as a JavaScript string breakout. JSON does not escape `'`, so the payload's quotes
// survive into the response and the marker substring is present — but JSON also doubles the
// payload's load-bearing backslash to `\\`, which turns it into a literal backslash and leaves the
// quote inert. The bytes that "prove" the breakout and the bytes that neutralise it are the same
// bytes; only their position in the script's grammar separates them.
//
// Implementation note. docs/RESEARCH-XSS-CONTEXT-AND-BROWSERS.md proposed walking goja's AST for
// ast.StringLiteral offsets. That does not work as written: this goja version exposes neither
// ast.Walk nor ast.Visitor, so there is no traversal to hang it on. What that research is right
// about is the reason a shortcut fails — a backslash-parity count cannot tell you WHICH quote
// opened the literal, and after an encoding layer has rewritten the backslashes you are no longer
// looking at the script's own escaping. The answer to both is a lexer, so this file has one. It
// tracks the enclosing construct at every byte, which is exactly the fact parity cannot supply.
//
// Where the lexer cannot be sure it says so, and an unsure verdict never becomes a finding.
package scanner

import (
	"strings"

	"github.com/dop251/goja/parser"
)

// jsEnclosure is what encloses a given byte offset in a script.
type jsEnclosure uint8

const (
	// jsEncCode is executable position: an escaped literal really did terminate, or the value was
	// never inside one.
	jsEncCode jsEnclosure = iota
	jsEncSingleQuote
	jsEncDoubleQuote
	jsEncTemplate
	jsEncLineComment
	jsEncBlockComment
	jsEncRegex
)

func (e jsEnclosure) inStringLiteral() bool {
	return e == jsEncSingleQuote || e == jsEncDoubleQuote || e == jsEncTemplate
}

// jsEnclosureAt reports what encloses offset in script.
//
// ok is false when the lexer could not decide — an unterminated construct, or an offset past the
// end. An undecided answer must not be turned into evidence in either direction.
func jsEnclosureAt(script string, offset int) (enc jsEnclosure, ok bool) {
	if offset < 0 || offset >= len(script) {
		return jsEncCode, false
	}

	state := jsEncCode
	// prevSignificant is the last non-space, non-comment byte emitted in code position. It decides
	// the regex-versus-division ambiguity: `/` starts a regex at the beginning of an expression and
	// divides after a value. Getting this wrong only matters when a quote character sits inside a
	// regex literal (`/['"]/`), but that is exactly the kind of thing a page minifier produces, so
	// it is worth tracking rather than ignoring.
	var prevSignificant byte

	for i := 0; i < len(script); i++ {
		c := script[i]
		if i == offset {
			return state, true
		}

		switch state {
		case jsEncCode:
			switch {
			case c == '\'':
				state = jsEncSingleQuote
			case c == '"':
				state = jsEncDoubleQuote
			case c == '`':
				state = jsEncTemplate
			case c == '/' && i+1 < len(script) && script[i+1] == '/':
				state = jsEncLineComment
				i++
			case c == '/' && i+1 < len(script) && script[i+1] == '*':
				state = jsEncBlockComment
				i++
			case c == '/' && regexCanStartAfter(prevSignificant):
				state = jsEncRegex
			default:
				if !isJSSpace(c) {
					prevSignificant = c
				}
			}

		case jsEncSingleQuote, jsEncDoubleQuote:
			quote := byte('\'')
			if state == jsEncDoubleQuote {
				quote = '"'
			}
			switch c {
			case '\\':
				// Skip the escaped byte. This is where the json.Marshal case is decided: a doubled
				// backslash consumes itself here, so the quote that follows is reached in string
				// state and closes nothing.
				if i+1 >= len(script) {
					return jsEncCode, false
				}
				if i+1 == offset {
					// The canary starts on an escaped byte — it is inside the literal, escaped.
					return state, true
				}
				i++
			case quote:
				state = jsEncCode
				prevSignificant = quote
			case '\n':
				// An unescaped newline cannot appear in a normal string literal. The input is not
				// what this lexer models, so it declines rather than guessing.
				return jsEncCode, false
			}

		case jsEncTemplate:
			switch c {
			case '\\':
				if i+1 >= len(script) {
					return jsEncCode, false
				}
				if i+1 == offset {
					return state, true
				}
				i++
			case '`':
				state = jsEncCode
				prevSignificant = '`'
			}

		case jsEncLineComment:
			if c == '\n' {
				state = jsEncCode
			}

		case jsEncBlockComment:
			if c == '*' && i+1 < len(script) && script[i+1] == '/' {
				state = jsEncCode
				i++
			}

		case jsEncRegex:
			switch c {
			case '\\':
				if i+1 >= len(script) {
					return jsEncCode, false
				}
				if i+1 == offset {
					return state, true
				}
				i++
			case '/':
				state = jsEncCode
				prevSignificant = '/'
			case '\n':
				return jsEncCode, false
			}
		}
	}

	if offset == len(script) {
		return state, true
	}
	return jsEncCode, false
}

// regexCanStartAfter reports whether a `/` following this byte begins a regex literal rather than a
// division. The standard lexer heuristic: a regex may start at the beginning of input or after an
// operator or opening bracket, and a division follows a value — an identifier, a number, or a
// closing bracket.
func regexCanStartAfter(prev byte) bool {
	switch prev {
	case 0:
		return true
	case ')', ']', '}':
		return false
	}
	if prev >= 'a' && prev <= 'z' || prev >= 'A' && prev <= 'Z' || prev >= '0' && prev <= '9' {
		return false
	}
	if prev == '_' || prev == '$' {
		return false
	}
	return true
}

func isJSSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// jsBreakoutConfirmed reports whether a canary reflected into script source really reached
// executable position.
//
// The rule is the one the false positive violates: a canary still enclosed by a string literal did
// not break out, however many quote characters surround it in the raw bytes. Only a canary the
// lexer places in code position counts, and only when the script as a whole still parses — a
// payload that leaves the script a syntax error executes nothing, so it is not evidence of
// execution either.
//
// A script that does not parse and a lexer that cannot decide both return false. Both are the safe
// direction: this function's answer becomes a reported vulnerability, and the cost of a wrong yes
// is a finding an operator will chase into correctly-written code.
func jsBreakoutConfirmed(script, canary string) bool {
	if script == "" || canary == "" {
		return false
	}
	idx := strings.Index(script, canary)
	if idx < 0 {
		return false
	}

	// Every occurrence gets a look: the same value reflected twice, once inside a literal and once
	// outside it, is a real breakout even though the first occurrence is inert.
	for idx >= 0 {
		enc, ok := jsEnclosureAt(script, idx)
		if ok && enc == jsEncCode {
			// Reached executable position. Require the script to still be parseable, so a payload
			// that merely corrupted the page is not read as one that ran.
			if _, err := parser.ParseFile(nil, "", script, 0); err == nil {
				return true
			}
			return false
		}
		next := strings.Index(script[idx+len(canary):], canary)
		if next < 0 {
			break
		}
		idx += len(canary) + next
	}
	return false
}

// scriptBodies returns the contents of every <script> element in body, with the offset of each
// within body, so a canary's position in the document can be mapped to a position in the script.
func scriptBodies(body string) []scriptBody {
	var out []scriptBody
	lower := strings.ToLower(body)
	i := 0
	for {
		start := strings.Index(lower[i:], "<script")
		if start < 0 {
			return out
		}
		start += i
		open := strings.IndexByte(body[start:], '>')
		if open < 0 {
			return out
		}
		contentStart := start + open + 1
		end := strings.Index(lower[contentStart:], "</script")
		if end < 0 {
			// An unterminated script element runs to the end of the document, which is what a
			// browser does with it too.
			out = append(out, scriptBody{Offset: contentStart, Source: body[contentStart:]})
			return out
		}
		contentEnd := contentStart + end
		out = append(out, scriptBody{Offset: contentStart, Source: body[contentStart:contentEnd]})
		i = contentEnd
	}
}

type scriptBody struct {
	// Offset is where Source begins within the containing document.
	Offset int
	Source string
}
