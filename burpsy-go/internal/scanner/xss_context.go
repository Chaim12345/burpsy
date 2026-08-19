// xss_context.go classifies WHERE a reflected canary landed in a response body.
//
// The check this supports used to decide everything with strings.Contains over the whole body,
// which cannot answer the only question that matters for reflected XSS: a payload is exploitable
// or inert depending entirely on the context it lands in, and the same bytes are both. Four of the
// five failures cmd/xsschallenge measured trace to that one gap — three misses whose exploit needs
// no quote character at all (so no quote-based marker ever appears in the response), and a false
// positive against correctly-escaped code (so a marker appeared that the browser would never
// execute). docs/RESEARCH-XSS-CONTEXT-AND-BROWSERS.md has the measurements.
//
// The design is ZAP's HtmlContextAnalyser: find every occurrence of the canary, resolve the
// enclosing construct, record the surrounding quote character, the attribute name and the parent
// tag, then require a claimed breakout to be one that actually works IN THAT CONTEXT. The
// re-verification is the false-positive killer.
//
// Built on golang.org/x/net/html, already a dependency. Two facts about that package drive the
// implementation and were verified directly rather than assumed:
//
//   - Byte offsets are recoverable even though Tokenizer exposes no Position(): summing
//     len(z.Raw()) across tokens tracks the offset exactly, and the sum equals len(src) at EOF.
//   - Quoting is NOT recoverable from Token().Attr, which decodes and discards it — `value=X` and
//     `value='X'` both come back as value → X, with nothing to tell them apart. Raw() retains the
//     original start-tag text, so quoting has to be read off the raw bytes. That is the price of
//     not adding a dependency that reports both directly, and it is a scanner over one start tag.
//
// A third fact is not in that research and cost a measurement to find: the tokenizer does not
// distinguish script and RCDATA content from ordinary text. <script>x</script>, <textarea>x</textarea>
// and <p>x</p> all yield a Text token carrying x. The enclosing element has to be tracked here, or
// a canary inside a script would be classified as injectable markup — which is the more dangerous
// direction of the two, since it claims a tag injection a browser would never perform.
package scanner

import (
	"strings"

	"golang.org/x/net/html"
)

// xssContextKind is the construct a canary landed inside. It decides which breakout, if any, is
// worth claiming.
type xssContextKind uint8

const (
	// xssCtxUnknown means the classifier could not place the occurrence. Treated as
	// not-exploitable: an unplaced reflection is not evidence of anything.
	xssCtxUnknown xssContextKind = iota
	// xssCtxText is a text node in ordinary parsed markup, where a raw `<` opens an element.
	xssCtxText
	// xssCtxAttrValue is inside an attribute value. Exploitability depends on the quoting and on
	// which attribute it is, which is why xssContext carries both.
	xssCtxAttrValue
	// xssCtxComment is inside <!-- -->. Escaping the comment needs `-->`, which nothing else does.
	xssCtxComment
	// xssCtxRCDATA is <title>/<textarea> content. `<` does NOT open an element here; only the
	// element's own end tag terminates it, so a breakout must emit that end tag first.
	xssCtxRCDATA
	// xssCtxScript is <script> content, where the payload is JavaScript rather than markup and the
	// question becomes which string literal, if any, encloses it.
	xssCtxScript
)

func (k xssContextKind) String() string {
	switch k {
	case xssCtxText:
		return "text"
	case xssCtxAttrValue:
		return "attribute value"
	case xssCtxComment:
		return "comment"
	case xssCtxRCDATA:
		return "rcdata"
	case xssCtxScript:
		return "script"
	}
	return "unknown"
}

// xssContext is one placed occurrence of the canary.
type xssContext struct {
	Kind xssContextKind
	// Offset is the canary's byte offset in the body it was found in.
	Offset int
	// TagName is the enclosing element, lowercased. For an attribute value it is the element
	// carrying the attribute; for text/rcdata/script it is the containing element.
	TagName string
	// AttrName is the attribute whose value holds the canary, lowercased. Empty unless
	// Kind == xssCtxAttrValue.
	AttrName string
	// Quote is the delimiter around the attribute value: '"', '\'', or 0 when unquoted.
	// An unquoted value is the case substring matching could never see, because breaking out of it
	// needs no quote character at all — a space and an event-handler attribute suffice.
	Quote byte
}

// urlAttrs are attributes whose value a browser resolves as a URL, so a `javascript:` scheme in
// the value position executes without any tag ever being opened. Deliberately hand-maintained: the
// full HTML attribute surface is large and mostly irrelevant, and a wrong entry here either invents
// an exploit or hides one.
var urlAttrs = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true,
	"data": true, "poster": true, "background": true, "cite": true,
	"ping": true, "xlink:href": true,
}

// htmlAttrs are attributes whose value the parser unescapes back into markup and parses as a
// document. srcdoc is the case that defeats substring matching completely: the payload is
// HTML-encoded in the response — so an encoding check calls it safe — and the attribute parser
// decodes it back into live markup before the inner document is parsed.
var htmlAttrs = map[string]bool{
	"srcdoc": true,
}

// IsURLAttr reports whether this occurrence sits in a URL-valued attribute.
func (c xssContext) IsURLAttr() bool {
	return c.Kind == xssCtxAttrValue && urlAttrs[c.AttrName]
}

// IsHTMLAttr reports whether this occurrence sits in an attribute re-parsed as markup.
func (c xssContext) IsHTMLAttr() bool {
	return c.Kind == xssCtxAttrValue && htmlAttrs[c.AttrName]
}

// IsEventAttr reports whether this occurrence sits in an inline event handler, whose value is
// JavaScript rather than text.
func (c xssContext) IsEventAttr() bool {
	return c.Kind == xssCtxAttrValue && strings.HasPrefix(c.AttrName, "on")
}

// voidElements never have content and never take an end tag, so they must not be pushed onto the
// open-element stack — doing so would make every following text node look like it lived inside the
// last <br> or <input>.
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true,
	"img": true, "input": true, "link": true, "meta": true, "param": true,
	"source": true, "track": true, "wbr": true,
}

// rcdataElements hold text that is NOT parsed as markup: `<` is literal, and only the element's own
// end tag closes it.
var rcdataElements = map[string]bool{
	"title": true, "textarea": true,
}

// rawTextElements hold text that is not markup and not RCDATA. script is JavaScript; style is CSS,
// which is not executable on its own in any browser this targets and so classifies as unknown
// rather than as an injectable context.
var rawTextElements = map[string]bool{
	"script": true, "style": true,
}

// classifyXSSContexts finds every occurrence of canary in body and places each one.
//
// Returns nil when the canary does not appear. Occurrences are returned in source order. A canary
// appearing several times yields several contexts, and they routinely differ — the same value
// echoed into both a text node and an attribute is the ordinary case, not a corner one — so callers
// must consider all of them rather than only the first.
func classifyXSSContexts(body, canary string) []xssContext {
	if canary == "" || !strings.Contains(body, canary) {
		return nil
	}

	var out []xssContext
	// open tracks the element stack so a Text token can be told apart from script and RCDATA
	// content, which the tokenizer reports identically. Only the innermost entry is ever read, but
	// the stack is kept so an end tag restores the right parent rather than clearing to nothing.
	var open []string

	z := html.NewTokenizer(strings.NewReader(body))
	off := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		raw := string(z.Raw())
		enclosing := ""
		if len(open) > 0 {
			enclosing = open[len(open)-1]
		}

		switch tt {
		case html.TextToken:
			kind := xssCtxText
			switch {
			case rawTextElements[enclosing]:
				if enclosing == "script" {
					kind = xssCtxScript
				} else {
					kind = xssCtxUnknown // <style>: not an execution context on its own.
				}
			case rcdataElements[enclosing]:
				kind = xssCtxRCDATA
			}
			for _, i := range allIndexes(raw, canary) {
				c := xssContext{Kind: kind, Offset: off + i, TagName: enclosing}
				if kind == xssCtxScript {
					// Which string literal encloses it is a JavaScript question, and the payload
					// that works here depends on the answer, so it is resolved now rather than
					// guessed later. A quote of 0 means the lexer declined, and the caller then
					// tries both styles instead of assuming one.
					if enc, ok := jsEnclosureAt(raw, i); ok {
						switch enc {
						case jsEncSingleQuote:
							c.Quote = '\''
						case jsEncDoubleQuote:
							c.Quote = '"'
						}
					}
				}
				out = append(out, c)
			}

		case html.CommentToken:
			for _, i := range allIndexes(raw, canary) {
				out = append(out, xssContext{Kind: xssCtxComment, Offset: off + i, TagName: enclosing})
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			tag := strings.ToLower(string(name))
			for _, occ := range placeInStartTag(raw, canary, tag) {
				occ.Offset += off
				out = append(out, occ)
			}
			if tt == html.StartTagToken && !voidElements[tag] {
				open = append(open, tag)
			}

		case html.EndTagToken:
			name, _ := z.TagName()
			tag := strings.ToLower(string(name))
			// Pop to the matching element rather than popping blindly: unbalanced markup is the
			// norm in the wild, and a blind pop would misattribute every element after the first
			// stray end tag.
			for i := len(open) - 1; i >= 0; i-- {
				if open[i] == tag {
					open = open[:i]
					break
				}
			}
		}

		off += len(raw)
	}
	return out
}

// allIndexes returns every start offset of needle in s, including overlapping-adjacent repeats.
func allIndexes(s, needle string) []int {
	if needle == "" {
		return nil
	}
	var out []int
	for i := 0; ; {
		j := strings.Index(s[i:], needle)
		if j < 0 {
			return out
		}
		out = append(out, i+j)
		i += j + len(needle)
	}
}

// placeInStartTag resolves occurrences of canary inside one raw start tag, reporting which
// attribute value each landed in and how that value was quoted.
//
// It scans the raw bytes because Token().Attr decodes the value and discards the delimiter, and
// the delimiter is exactly what decides whether a breakout needs a quote character. A canary in
// the tag name or in an attribute NAME is reported as unknown: those are injectable in principle
// but need a different payload shape than this check sends, and claiming them would be a finding
// the evidence does not support.
func placeInStartTag(raw, canary, tag string) []xssContext {
	var out []xssContext
	i := 0
	n := len(raw)

	// Skip `<` and the tag name.
	if i < n && raw[i] == '<' {
		i++
	}
	for i < n && !isHTMLSpace(raw[i]) && raw[i] != '>' && raw[i] != '/' {
		i++
	}

	for i < n {
		for i < n && isHTMLSpace(raw[i]) {
			i++
		}
		if i >= n || raw[i] == '>' {
			break
		}
		if raw[i] == '/' {
			i++
			continue
		}

		nameStart := i
		for i < n && !isHTMLSpace(raw[i]) && raw[i] != '=' && raw[i] != '>' && raw[i] != '/' {
			i++
		}
		attrName := strings.ToLower(raw[nameStart:i])

		for i < n && isHTMLSpace(raw[i]) {
			i++
		}
		if i >= n || raw[i] != '=' {
			// Valueless attribute. If the canary is the attribute name itself we deliberately do
			// not claim it; see the doc comment.
			continue
		}
		i++ // consume '='
		for i < n && isHTMLSpace(raw[i]) {
			i++
		}
		if i >= n {
			break
		}

		var quote byte
		var valStart, valEnd int
		switch raw[i] {
		case '"', '\'':
			quote = raw[i]
			i++
			valStart = i
			for i < n && raw[i] != quote {
				i++
			}
			valEnd = i
			if i < n {
				i++ // consume the closing quote
			}
		default:
			valStart = i
			for i < n && !isHTMLSpace(raw[i]) && raw[i] != '>' {
				i++
			}
			valEnd = i
		}

		val := raw[valStart:valEnd]
		for _, j := range allIndexes(val, canary) {
			out = append(out, xssContext{
				Kind:     xssCtxAttrValue,
				Offset:   valStart + j,
				TagName:  tag,
				AttrName: attrName,
				Quote:    quote,
			})
		}
	}
	return out
}

// isHTMLSpace matches the space characters the HTML tokenizer treats as attribute separators.
func isHTMLSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}
