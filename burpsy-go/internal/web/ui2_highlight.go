package web

// Server-side syntax highlighting and pretty printing for the ui2 history detail panes.
//
// Everything here is a READING aid over captured bytes: tokenizers color the raw text and
// formatters re-indent it for display only — the store is never written, and the Raw view
// always shows the exact recorded message. Safety contract, pinned by
// ui2_highlight_test.go:
//
//   - All text passes through html/template escaping (the functions return escaped
//     template.HTML built from html.EscapeString pieces); hostile captured content —
//     scripts, markup, control bytes — is inert in the page.
//   - Highlighting never fails: tokenizers work on any byte sequence, valid or not, and
//     color what they recognise. Formatting can fail (invalid JSON etc.); the caller then
//     falls back to raw bytes with an explicit note, never to silence.
//   - Size is bounded (highlightMaxBytes): beyond it the pane renders escaped raw text
//     with a note and does NO detection, tokenization or formatting work at all.
//   - The Raw view's served bytes equal the recorded message for ordinary text
//     captures: head bytes (including CR) and the exact head/body separator are
//     preserved, with each CR kept adjacent to its LF so the HTML parser's CR/CRLF
//     normalization cannot invent extra line breaks. The browser DOM text is
//     LF-normalized per HTML parsing rules, invalid UTF-8 renders as replacement
//     characters — the pane is a reading aid over text, not a byte channel, and
//     makes no fidelity claim for arbitrary binary captures.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"strings"

	"github.com/tdewolff/minify/v2"
	mjs "github.com/tdewolff/minify/v2/js"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// highlightMaxBytes bounds the pretty/highlight path. 1 MiB covers real API traffic;
// beyond it the pane shows raw bytes plus an explicit note.
const highlightMaxBytes = 1 << 20

// bodyKind is the detected syntax of a message body.
type bodyKind int

const (
	bodyNone  bodyKind = iota // empty
	bodyPlain                 // no recognised structure: no highlighting claim
	bodyJSON
	bodyMarkup // HTML or XML
	bodyCSS
	bodyJS
	bodyForm // application/x-www-form-urlencoded
)

func (k bodyKind) String() string {
	switch k {
	case bodyJSON:
		return "JSON"
	case bodyMarkup:
		return "HTML/XML"
	case bodyCSS:
		return "CSS"
	case bodyJS:
		return "JavaScript"
	case bodyForm:
		return "form data"
	default:
		return "plain"
	}
}

// span renders one token. Content is escaped here, at the single choke point.
func span(class, text string) string {
	if text == "" {
		return ""
	}
	if class == "" {
		return html.EscapeString(text)
	}
	return `<span class="hl-` + class + `">` + html.EscapeString(text) + `</span>`
}

// splitHTTPMessage separates an HTTP message into its head (request/status line plus
// headers), the exact recorded head/body separator, and the body. The separator is
// returned so the raw pane can reproduce it verbatim. No blank line: the whole thing
// is head.
func splitHTTPMessage(raw string) (head, sep, body string) {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[:i], "\r\n\r\n", raw[i+4:]
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[:i], "\n\n", raw[i+2:]
	}
	return raw, "", ""
}

// detectBodyKind picks the syntax from the Content-Type header first and a conservative
// sniff second. Sniffing only ever PROMOTES to a tokenizer that renders the same text —
// it cannot change what the bytes say.
func detectBodyKind(head, body string) bodyKind {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return bodyNone
	}
	ct := contentTypeOf(head)
	switch k := kindFromContentType(ct); k {
	case bodyNone, bodyPlain:
	default:
		return k
	}
	// Sniff only shapes that are unambiguous on their first byte.
	switch {
	case strings.HasPrefix(trimmed, "{"), strings.HasPrefix(trimmed, "["):
		if json.Valid([]byte(trimmed)) {
			return bodyJSON
		}
	case strings.HasPrefix(trimmed, "<"):
		return bodyMarkup
	}
	return bodyPlain
}

// contentTypeOf extracts the Content-Type header value (lowercased) from a head.
func contentTypeOf(head string) string {
	for _, line := range strings.Split(head, "\n") {
		if i := strings.IndexByte(line, ':'); i > 0 && strings.EqualFold(strings.TrimSpace(line[:i]), "Content-Type") {
			return strings.ToLower(line[i+1:])
		}
	}
	return ""
}

// kindFromContentType maps a Content-Type to a body syntax, or bodyPlain when none fits.
func kindFromContentType(ct string) bodyKind {
	switch {
	case strings.Contains(ct, "json"), strings.HasSuffix(strings.TrimSpace(ct), "+json"):
		return bodyJSON
	case strings.Contains(ct, "html"), strings.Contains(ct, "xml"):
		return bodyMarkup
	case strings.Contains(ct, "css"):
		return bodyCSS
	case strings.Contains(ct, "javascript"), strings.Contains(ct, "ecmascript"):
		return bodyJS
	case strings.Contains(ct, "x-www-form-urlencoded"):
		return bodyForm
	}
	return bodyPlain
}

// highlightHTTPHead colors the request/status line and header names. Anything unusual —
// folded junk, binary smuggled into headers — is escaped text, never markup.
func highlightHTTPHead(head string, isRequest bool) template.HTML {
	var b strings.Builder
	// The served bytes keep each line's trailing CR, but the CR must sit ADJACENT to
	// its LF, outside the spans: the HTML parser normalizes the byte stream CR and
	// CRLF to LF before building the DOM, so a CR left inside a span with the LF
	// after it ("<span>x\r</span>\n") would surface as TWO line breaks in the pane.
	lines := strings.Split(head, "\n")
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		cr := strings.HasSuffix(line, "\r")
		if cr {
			line = line[:len(line)-1]
		}
		if i == 0 {
			b.WriteString(highlightStartLine(line, isRequest))
		} else if j := strings.IndexByte(line, ':'); j > 0 {
			b.WriteString(span("hdr", line[:j]+":"))
			b.WriteString(span("", line[j+1:]))
		} else {
			b.WriteString(span("", line))
		}
		if cr {
			b.WriteByte('\r')
		}
	}
	return template.HTML(b.String()) //nolint:gosec // every piece escaped in span()
}

// highlightStartLine colors "METHOD SP PATH SP HTTP/x" or "HTTP/x SP CODE SP reason".
// A line that does not fit either shape renders plain — highlighting is best-effort.
func highlightStartLine(line string, isRequest bool) string {
	parts := strings.SplitN(line, " ", 3)
	if isRequest && len(parts) == 3 && strings.HasPrefix(parts[2], "HTTP/") {
		return span("method", parts[0]) + " " + span("path", parts[1]) + " " + span("ver", parts[2])
	}
	if !isRequest && strings.HasPrefix(line, "HTTP/") && len(parts) >= 2 {
		rest := ""
		if len(parts) == 3 {
			rest = " " + span("", parts[2])
		}
		return span("ver", parts[0]) + " " + span("status", parts[1]) + rest
	}
	return span("", line)
}

// highlightJSON colors JSON text token by token. It is a scanner, not a parser: invalid
// JSON still renders, colored where the scanner is certain, plain elsewhere.
func highlightJSON(s string) template.HTML {
	var b strings.Builder
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case c == '"':
			j := i + 1
			for j < n && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j < n {
				j++
			}
			tok := s[i:j]
			// A string followed by ':' is a key.
			k := j
			for k < n && (s[k] == ' ' || s[k] == '\t' || s[k] == '\n' || s[k] == '\r') {
				k++
			}
			if k < n && s[k] == ':' {
				b.WriteString(span("key", tok))
			} else {
				b.WriteString(span("str", tok))
			}
			i = j
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < n && strings.ContainsRune("0123456789+-.eE", rune(s[j])) {
				j++
			}
			b.WriteString(span("num", s[i:j]))
			i = j
		case strings.HasPrefix(s[i:], "true"), strings.HasPrefix(s[i:], "false"):
			w := "true"
			if strings.HasPrefix(s[i:], "false") {
				w = "false"
			}
			b.WriteString(span("kw", w))
			i += len(w)
		case strings.HasPrefix(s[i:], "null"):
			b.WriteString(span("kw", "null"))
			i += 4
		case strings.ContainsRune("{}[]:", rune(c)):
			b.WriteString(span("punct", s[i:i+1]))
			i++
		case c == ',':
			b.WriteString(span("punct", ","))
			i++
		default:
			b.WriteString(span("", s[i:i+1]))
			i++
		}
	}
	return template.HTML(b.String()) //nolint:gosec // every piece escaped in span()
}

// highlightForm colors urlencoded pairs, one key=value per separator.
func highlightForm(s string) template.HTML {
	var b strings.Builder
	for i, pair := range strings.Split(s, "&") {
		if i > 0 {
			b.WriteString(span("punct", "&"))
		}
		if j := strings.IndexByte(pair, '='); j >= 0 {
			b.WriteString(span("key", pair[:j]))
			b.WriteString(span("punct", "="))
			b.WriteString(span("str", pair[j+1:]))
		} else {
			b.WriteString(span("key", pair))
		}
	}
	return template.HTML(b.String()) //nolint:gosec // every piece escaped in span()
}

// highlightMarkup colors tags, attribute names and comments in HTML/XML text. Text nodes
// are escaped verbatim. A '<' that does not open a valid tag renders as text.
func highlightMarkup(s string) template.HTML {
	var b strings.Builder
	i, n := 0, len(s)
	for i < n {
		if s[i] != '<' {
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				b.WriteString(span("", s[i:]))
				break
			}
			b.WriteString(span("", s[i:i+j]))
			i += j
			continue
		}
		// Comment or doctype: <!-- ... --> or <! ... >
		if strings.HasPrefix(s[i:], "<!--") {
			end := strings.Index(s[i:], "-->")
			if end < 0 {
				b.WriteString(span("com", s[i:]))
				break
			}
			b.WriteString(span("com", s[i:i+end+3]))
			i += end + 3
			continue
		}
		end := strings.IndexByte(s[i:], '>')
		if end < 0 {
			b.WriteString(span("", s[i:]))
			break
		}
		tag := s[i : i+end+1]
		b.WriteString(highlightTag(tag))
		i += end + 1
	}
	return template.HTML(b.String()) //nolint:gosec // every piece escaped in span()
}

// highlightTag colors one <...> run: angle brackets, tag name, attribute names, quoted
// values. Quoted '>' inside attributes is honoured so a stray bracket cannot split a tag.
func highlightTag(tag string) string {
	var b strings.Builder
	b.WriteString(span("punct", "<"))
	inner := tag[1 : len(tag)-1]
	i, n := 0, len(inner)
	// Tag name (skip the closing slash with the bracket).
	if strings.HasPrefix(inner, "/") {
		b.WriteString(span("punct", "/"))
		i++
	}
	j := i
	for j < n && (isAlnum(inner[j]) || inner[j] == '-' || inner[j] == ':' || inner[j] == '!') {
		j++
	}
	b.WriteString(span("tag", inner[i:j]))
	i = j
	for i < n {
		c := inner[i]
		if c == '"' || c == '\'' {
			k := strings.IndexByte(inner[i+1:], c)
			if k < 0 {
				b.WriteString(span("str", inner[i:]))
				break
			}
			b.WriteString(span("str", inner[i:i+k+2]))
			i += k + 2
			continue
		}
		if c == '=' {
			b.WriteString(span("punct", "="))
			i++
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '/' {
			b.WriteString(span("", string(c)))
			i++
			continue
		}
		k := i
		for k < n && inner[k] != '=' && inner[k] != ' ' && inner[k] != '\t' && inner[k] != '"' && inner[k] != '\'' && inner[k] != '/' {
			k++
		}
		b.WriteString(span("attr", inner[i:k]))
		i = k
	}
	b.WriteString(span("punct", ">"))
	return b.String()
}

var jsKeywords = map[string]bool{
	"function": true, "return": true, "var": true, "let": true, "const": true,
	"if": true, "else": true, "for": true, "while": true, "new": true, "class": true,
	"typeof": true, "instanceof": true, "throw": true, "try": true, "catch": true,
	"finally": true, "switch": true, "case": true, "default": true, "break": true,
	"continue": true, "do": true, "in": true, "of": true, "this": true, "null": true,
	"undefined": true, "true": true, "false": true, "async": true, "await": true,
	"yield": true, "import": true, "export": true, "from": true, "extends": true,
	"static": true, "get": true, "set": true, "delete": true, "void": true,
}

// highlightJS colors comments, strings, numbers and keywords. It is a display scanner —
// it never evaluates, and template literals render as plain strings (their interpolations
// are colored as text inside the string, which is a reading view, not a compiler).
// jsRegexContext tracks the previous significant token so '/' can be read: after an
// operand, identifier or ')' / ']' it divides; after an operator, at the start, or
// after a keyword like 'return' it opens a regex. When unsure, treat '/' as division:
// misreading a division as a regex could swallow code into a literal, the other way
// only loses coloring (highlight) or declines to re-indent (format).
type jsRegexContext struct{ last string }

func (c *jsRegexContext) allowed() bool {
	if c.last == "" {
		return true
	}
	switch c.last {
	case "return", "typeof", "case", "in", "of", "new", "delete", "void", "throw",
		"do", "else", "yield", "await", "instanceof":
		return true
	}
	if len(c.last) == 1 {
		return strings.ContainsRune("(,=:[!&|?{};+-*%^~<>", rune(c.last[0]))
	}
	return false
}

// scanJSRegex scans a regex literal starting at s[i]=='/': character classes are
// honored so a '/' or '*' inside […] does not end it, and a newline before the closing
// slash fails the scan. Returns the index just past any flags.
func scanJSRegex(s string, i int) (int, bool) {
	j := i + 1
	inClass := false
	for j < len(s) {
		d := s[j]
		switch {
		case d == '\\':
			j += 2
			continue
		case d == '\n':
			return 0, false
		case inClass:
			if d == ']' {
				inClass = false
			}
		case d == '[':
			inClass = true
		case d == '/':
			j++
			for j < len(s) && isAlpha(s[j]) { // flags
				j++
			}
			return j, true
		}
		j++
	}
	return 0, false
}

// scanJSNumber scans a JS numeric literal at s[i]: decimal with optional fraction and
// exponent (1e5, 1.5e-10), 0x/0o/0b radix forms, digit separators and a BigInt suffix.
func scanJSNumber(s string, i int) int {
	n := len(s)
	j := i
	if s[j] == '0' && j+1 < n && strings.ContainsRune("xXoObB", rune(s[j+1])) {
		j += 2
		for j < n && (isAlnum(s[j]) || s[j] == '_') {
			j++
		}
		return j
	}
	for j < n && ((s[j] >= '0' && s[j] <= '9') || s[j] == '_' || s[j] == '.') {
		j++
	}
	if j < n && (s[j] == 'e' || s[j] == 'E') {
		k := j + 1
		if k < n && (s[k] == '+' || s[k] == '-') {
			k++
		}
		if k < n && s[k] >= '0' && s[k] <= '9' {
			j = k
			for j < n && ((s[j] >= '0' && s[j] <= '9') || s[j] == '_') {
				j++
			}
		}
	}
	if j < n && s[j] == 'n' { // BigInt suffix
		j++
	}
	return j
}

// scanJSString scans a quoted string or template literal at s[i] as an opaque run.
func scanJSString(s string, i int) int {
	c := s[i]
	j := i + 1
	for j < len(s) && s[j] != c {
		if s[j] == '\\' {
			j++
		}
		j++
	}
	if j < len(s) {
		j++
	}
	return j
}

func highlightJS(s string) template.HTML {
	var b strings.Builder
	ctx := &jsRegexContext{}
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case strings.HasPrefix(s[i:], "//"):
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				b.WriteString(span("com", s[i:]))
				i = n
			} else {
				b.WriteString(span("com", s[i:i+j]))
				i += j
			}
		case strings.HasPrefix(s[i:], "/*"):
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				b.WriteString(span("com", s[i:]))
				i = n
			} else {
				b.WriteString(span("com", s[i:i+j+4]))
				i += j + 4
			}
		case c == '"' || c == '\'' || c == '`':
			j := scanJSString(s, i)
			b.WriteString(span("str", s[i:j]))
			ctx.last = "x"
			i = j
		case c >= '0' && c <= '9':
			j := scanJSNumber(s, i)
			b.WriteString(span("num", s[i:j]))
			ctx.last = "x"
			i = j
		case isAlpha(c) || c == '_' || c == '$':
			j := i + 1
			for j < n && (isAlnum(s[j]) || s[j] == '_' || s[j] == '$') {
				j++
			}
			w := s[i:j]
			if jsKeywords[w] {
				b.WriteString(span("kw", w))
			} else {
				b.WriteString(span("", w))
			}
			ctx.last = w
			i = j
		case c == '/' && ctx.allowed():
			if j, ok := scanJSRegex(s, i); ok {
				// A regex is a literal: color it like one. A failed scan falls
				// through to plain '/' — coloring is best-effort, never wrong.
				b.WriteString(span("str", s[i:j]))
				ctx.last = "x"
				i = j
				continue
			}
			b.WriteString(span("", s[i:i+1]))
			i++
		default:
			b.WriteString(span("", s[i:i+1]))
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				ctx.last = string(c)
			}
			i++
		}
	}
	return template.HTML(b.String()) //nolint:gosec // every piece escaped in span()
}

// highlightCSS colors selectors, property names, values, at-rules and comments.
func highlightCSS(s string) template.HTML {
	var b strings.Builder
	i, n := 0, len(s)
	depth := 0
	for i < n {
		c := s[i]
		switch {
		case strings.HasPrefix(s[i:], "/*"):
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				b.WriteString(span("com", s[i:]))
				i = n
			} else {
				b.WriteString(span("com", s[i:i+j+4]))
				i += j + 4
			}
		case c == '"' || c == '\'':
			j := i + 1
			for j < n && s[j] != c {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j < n {
				j++
			}
			b.WriteString(span("str", s[i:j]))
			i = j
		case c == '{':
			b.WriteString(span("punct", "{"))
			depth++
			i++
		case c == '}':
			b.WriteString(span("punct", "}"))
			if depth > 0 {
				depth--
			}
			i++
		case c == ':':
			b.WriteString(span("punct", ":"))
			i++
		case c == ';':
			b.WriteString(span("punct", ";"))
			i++
		case c == '@':
			j := i + 1
			for j < n && (isAlnum(s[j]) || s[j] == '-') {
				j++
			}
			b.WriteString(span("kw", s[i:j]))
			i = j
		case isAlpha(c) || c == '-' || c == '#' || c == '.' || c == '*' || c == '_' || c == '%':
			j := i + 1
			for j < n && !strings.ContainsRune("{};:\"'` \t\r\n", rune(s[j])) {
				j++
			}
			if depth > 0 {
				// Inside a block: before ':' a property, after ':' part of the value.
				k := i
				for k < n && (s[k] == ' ' || s[k] == '\t') {
					k++
				}
				if k < n && s[k] == ':' {
					b.WriteString(span("attr", s[i:j]))
				} else {
					b.WriteString(span("str", s[i:j]))
				}
			} else {
				b.WriteString(span("tag", s[i:j])) // selector
			}
			i = j
		default:
			b.WriteString(span("", s[i:i+1]))
			i++
		}
	}
	return template.HTML(b.String()) //nolint:gosec // every piece escaped in span()
}

// formatBody re-indents a body for the Pretty view. ok=false means the formatter could
// not prove the shape (invalid JSON, etc.) and the caller must fall back to raw with an
// explicit note — formatting NEVER produces a silently wrong rendering.
func formatBody(kind bodyKind, body string) (string, bool) {
	switch kind {
	case bodyJSON:
		var buf bytes.Buffer
		if err := json.Indent(&buf, []byte(body), "", "  "); err != nil {
			return "", false
		}
		return buf.String(), true
	case bodyForm:
		return strings.ReplaceAll(body, "&", "\n"), true
	case bodyCSS:
		return formatCSS(body), true
	case bodyJS:
		return formatJS(body)
	case bodyMarkup:
		return formatMarkup(body)
	default:
		return "", false
	}
}

// formatCSS puts each declaration and brace on its own line with two-space indent.
// Comments and strings are honored so a '{' inside them does not change the indent.
func formatCSS(s string) string {
	var b strings.Builder
	depth := 0
	writeNL := func() {
		trimmed := strings.TrimRight(b.String(), " \t")
		b.Reset()
		b.WriteString(trimmed)
		if !strings.HasSuffix(trimmed, "\n") && trimmed != "" {
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth))
	}
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		if strings.HasPrefix(s[i:], "/*") {
			j := strings.Index(s[i+2:], "*/")
			end := n
			if j >= 0 {
				end = i + j + 4
			}
			b.WriteString(s[i:end])
			i = end
			continue
		}
		if c == '"' || c == '\'' {
			j := i + 1
			for j < n && s[j] != c {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j < n {
				j++
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		switch c {
		case '{':
			b.WriteString(" {")
			depth++
			writeNL()
		case ';':
			b.WriteByte(';')
			writeNL()
		case '}':
			trimmed := strings.TrimRight(b.String(), " \t\n\r")
			b.Reset()
			b.WriteString(trimmed)
			if !strings.HasSuffix(trimmed, "\n") {
				b.WriteByte('\n')
			}
			if depth > 0 {
				depth--
			}
			b.WriteString(strings.Repeat("  ", depth))
			b.WriteByte('}')
			writeNL()
		case '\n', '\r':
			i++
			continue
		default:
			b.WriteByte(c)
		}
		i++
	}
	return strings.TrimSpace(b.String())
}

// formatMarkup indents tags one level per nesting depth. Text that shares a line with
// its tag stays on that line — the formatter only ever inserts line breaks between
// tokens, so text content is never reflowed into a different rendering.
// formatMarkup re-indents markup — but ONLY pure structural documents: tags and
// comments with no text runs at all and no phrasing-content (inline) tags. Re-flowing
// anything else can move or drop whitespace that changes what the captured document
// says ("Hello <b>world</b>" is a sentence, not a tree), so mixed content, inline
// tags, and even whitespace-only runs between tags all refuse (ok=false) and the pane
// falls back to the highlighted raw bytes with an explicit note. Pretty printing never
// gambles with captured content.
func formatMarkup(s string) (string, bool) {
	// Gate pass: any text run (even whitespace-only) or inline tag refuses the reflow.
	i, n := 0, len(s)
	for i < n {
		if s[i] != '<' {
			return "", false
		}
		if strings.HasPrefix(s[i:], "<!--") {
			e := strings.Index(s[i:], "-->")
			if e < 0 {
				return "", false
			}
			i += e + 3
			continue
		}
		e := strings.IndexByte(s[i:], '>')
		if e < 0 {
			return "", false
		}
		inner := strings.TrimSpace(s[i+1 : i+e])
		name := strings.TrimPrefix(inner, "/")
		if k := strings.IndexAny(name, " \t"); k > 0 {
			name = name[:k]
		}
		if inlineMarkupTags[strings.ToLower(name)] {
			return "", false
		}
		i += e + 1
	}
	// Re-indent pass: only tags and comments remain, so breaks between them are safe.
	var b strings.Builder
	depth := 0
	writeIndent := func() {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth))
	}
	i = 0
	for i < n {
		if strings.HasPrefix(s[i:], "<!--") {
			e := strings.Index(s[i:], "-->")
			writeIndent()
			b.WriteString(s[i : i+e+3])
			i += e + 3
			continue
		}
		e := strings.IndexByte(s[i:], '>')
		tag := s[i : i+e+1]
		inner := strings.TrimSpace(tag[1 : len(tag)-1])
		closing := strings.HasPrefix(inner, "/")
		selfClose := strings.HasSuffix(inner, "/") || strings.HasPrefix(inner, "!") || strings.HasPrefix(inner, "?")
		if closing && depth > 0 {
			depth--
		}
		writeIndent()
		b.WriteString(tag)
		if !closing && !selfClose {
			depth++
		}
		i += e + 1
	}
	return b.String(), true
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isAlpha(c) || (c >= '0' && c <= '9') }

// ui2PaneView is one rendered message pane: highlighted content plus the operator-facing
// notes that say exactly what the pane did and did not do.
type ui2PaneView struct {
	Highlighted template.HTML // escaped, token-colored content to render inside <pre>
	Kind        string        // detected body syntax label, "" when plain
	Note        string        // explicit fallback/limit note, "" when everything applied
}

// renderMessagePane builds the display for one recorded HTTP message. pretty selects the
// formatted reading; raw always shows exact recorded bytes. Display only — the store is
// never touched, and nothing here can fail closed on attacker bytes: unknown or hostile
// input renders escaped and plainly labeled.
func renderMessagePane(raw string, isRequest, pretty bool) ui2PaneView {
	head, sep, body := splitHTTPMessage(raw)
	var b strings.Builder
	b.WriteString(string(highlightHTTPHead(head, isRequest)))
	// The separator is CR/LF bytes only — nothing to escape, everything preserved.
	b.WriteString(sep)
	if strings.TrimSpace(body) == "" {
		return ui2PaneView{Highlighted: template.HTML(b.String())} //nolint:gosec // built from escaped spans
	}
	// Over the size bound the pane is escaped raw text ONLY: no detection, no
	// tokenization, no formatting — a giant capture costs one escape pass, never
	// tokenizer work quadratic in attacker-controlled bytes.
	if len(body) > highlightMaxBytes {
		note := fmt.Sprintf("body is %d bytes — over the %d-byte limit, showing it raw with no highlighting", len(body), highlightMaxBytes)
		b.WriteString(html.EscapeString(body))
		kind := kindFromContentType(contentTypeOf(head))
		label := ""
		if kind != bodyPlain && kind != bodyNone {
			label = kind.String()
		}
		return ui2PaneView{Highlighted: template.HTML(b.String()), Kind: label, Note: note} //nolint:gosec // built from escaped spans
	}
	kind := detectBodyKind(head, body)
	note := ""
	displayBody := body
	if pretty {
		if formatted, ok := formatBody(kind, body); ok {
			displayBody = formatted
		} else {
			// Every refusal says exactly why; the fallback is always the raw body.
			switch kind {
			case bodyJSON:
				note = "not valid JSON — showing the body raw"
			case bodyMarkup:
				note = "markup with text or inline content is never re-flowed (that could change what it says) — showing the body raw"
			case bodyJS:
				note = "a '/' in this body could not be proven regex or division — showing the body raw rather than risk breaking it"
			case bodyPlain:
			default:
				note = "not valid " + kind.String() + " — showing the body raw"
			}
		}
	}
	switch kind {
	case bodyJSON:
		b.WriteString(string(highlightJSON(displayBody)))
	case bodyForm:
		b.WriteString(string(highlightForm(displayBody)))
	case bodyMarkup:
		b.WriteString(string(highlightMarkup(displayBody)))
	case bodyCSS:
		b.WriteString(string(highlightCSS(displayBody)))
	case bodyJS:
		b.WriteString(string(highlightJS(displayBody)))
	default:
		b.WriteString(html.EscapeString(displayBody))
	}
	label := ""
	if kind != bodyPlain && kind != bodyNone {
		label = kind.String()
	}
	return ui2PaneView{Highlighted: template.HTML(b.String()), Kind: label, Note: note} //nolint:gosec // built from escaped spans
}

// formatJS re-indents JavaScript. The safety contract is parser-verified, not
// assumed: the input must parse with a real JS parser (tdewolff/parse), original
// line breaks are PRESERVED (ASI can make them significant — "return\nexpr" is not
// "return expr"), inserted breaks land only after '{', '}' and ';', and the finished
// candidate is accepted ONLY when an ASI-aware minifier (tdewolff/minify) reduces
// input and candidate to the identical canonical form. Any parse failure or
// equivalence mismatch refuses the format (ok=false → the pane shows raw with an
// explicit note). Strings, template literals and comments are skipped as opaque
// runs; a '/' whose regex/division role cannot be proven refuses.
func formatJS(s string) (string, bool) {
	if _, err := js.Parse(parse.NewInputString(s), js.Options{}); err != nil {
		return "", false // not parseable JavaScript: never re-indent on a guess
	}
	var b strings.Builder
	depth := 0
	writeNL := func() {
		cur := strings.TrimRight(b.String(), " \t")
		b.Reset()
		b.WriteString(cur)
		if cur != "" && !strings.HasSuffix(cur, "\n") {
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth))
	}
	prev := &jsRegexContext{}
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case strings.HasPrefix(s[i:], "//"):
			j := strings.IndexByte(s[i:], '\n')
			end := n
			if j >= 0 {
				end = i + j
			}
			b.WriteString(strings.TrimRight(s[i:end], " \t"))
			i = end
			continue
		case strings.HasPrefix(s[i:], "/*"):
			j := strings.Index(s[i+2:], "*/")
			end := n
			if j >= 0 {
				end = i + j + 4
			}
			b.WriteString(s[i:end])
			i = end
			continue
		case c == '"' || c == '\'' || c == '`':
			j := scanJSString(s, i)
			b.WriteString(s[i:j])
			i = j
			prev.last = "x"
			continue
		case c == '/':
			// Division vs regex must be PROVEN from the previous token (keyword-aware);
			// unproven or unterminated refuses the format — never re-indent a regex's
			// characters onto different lines on a guess.
			if !prev.allowed() {
				return "", false
			}
			j, ok := scanJSRegex(s, i)
			if !ok {
				return "", false
			}
			b.WriteString(s[i:j])
			i = j
			prev.last = "x"
			continue
		case isAlpha(c) || c == '_' || c == '$':
			j := i + 1
			for j < n && (isAlnum(s[j]) || s[j] == '_' || s[j] == '$') {
				j++
			}
			b.WriteString(s[i:j])
			prev.last = s[i:j]
			i = j
			continue
		case c == '{':
			b.WriteString(" {")
			depth++
			writeNL()
			prev.last = "{"
		case c == '}':
			cur := strings.TrimRight(b.String(), " \t\n\r")
			b.Reset()
			b.WriteString(cur)
			if cur != "" && !strings.HasSuffix(cur, "\n") {
				b.WriteByte('\n')
			}
			if depth > 0 {
				depth--
			}
			b.WriteString(strings.Repeat("  ", depth))
			b.WriteByte('}')
			prev.last = "}"
		case c == ';':
			b.WriteByte(';')
			writeNL()
			prev.last = ";"
		case c == '\n' || c == '\r':
			// Original line breaks are preserved (ASI can make one significant);
			// surrounding whitespace collapses into the current indent.
			j := i
			for j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			cur := strings.TrimRight(b.String(), " \t")
			b.Reset()
			b.WriteString(cur)
			if cur != "" && !strings.HasSuffix(cur, "\n") {
				b.WriteByte('\n')
			}
			b.WriteString(strings.Repeat("  ", depth))
			prev.last = ";" // a preserved line break is a statement-boundary context
			i = j
			continue
		default:
			b.WriteByte(c)
			if c != ' ' && c != '\t' {
				prev.last = string(c)
			}
		}
		i++
	}
	candidate := strings.TrimSpace(b.String())
	if !jsSemanticallyEqual(s, candidate) {
		return "", false // verifier disagreed: show raw, never risk it
	}
	return candidate, true
}

// jsMinifier is the ASI-aware canonicalizer behind jsSemanticallyEqual.
var jsMinifier = func() *minify.M {
	m := minify.New()
	m.Add("text/javascript", &mjs.Minifier{})
	return m
}()

// jsSemanticallyEqual reports whether two JavaScript sources reduce to the identical
// canonical minified form. The minifier is ASI-aware, so a formatting pass that
// changed automatic-semicolon behavior (return\nexpr, postfix ++/--, regex or '['/'('
// continuations at line start, template interpolation) fails this check and the
// formatter refuses. This — not whitespace-stripped string equality — is the safety
// proof for formatJS.
func jsSemanticallyEqual(a, b string) bool {
	ma, err := jsMinifier.String("text/javascript", a)
	if err != nil {
		return false
	}
	mb, err := jsMinifier.String("text/javascript", b)
	if err != nil {
		return false
	}
	return ma == mb
}

// inlineMarkupTags are the phrasing-content tags: between them, whitespace is a
// meaningful single space and no structural line break belongs.
var inlineMarkupTags = map[string]bool{
	"a": true, "abbr": true, "b": true, "bdi": true, "bdo": true, "br": true,
	"cite": true, "code": true, "data": true, "dfn": true, "em": true, "i": true,
	"img": true, "kbd": true, "mark": true, "q": true, "s": true, "samp": true,
	"small": true, "span": true, "strong": true, "sub": true, "sup": true,
	"time": true, "u": true, "var": true, "wbr": true,
}

// nextTagIsInline reports whether the markup at rest starts with a phrasing-content tag.
func nextTagIsInline(rest string) bool {
	if !strings.HasPrefix(rest, "<") {
		return false
	}
	i := 1
	if i < len(rest) && rest[i] == '/' {
		i++
	}
	j := i
	for j < len(rest) && (isAlpha(rest[j])) {
		j++
	}
	return inlineMarkupTags[strings.ToLower(rest[i:j])]
}
