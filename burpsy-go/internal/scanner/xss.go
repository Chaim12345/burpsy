// xss.go ports the observable half of Java's reflected-XSS evidence model.
//
// Java classifies XSS_REFLECTED evidence into two disjoint modes (burp.Zwx_):
// CLIENT_SIDE_BREAKOUT, which re-parses the rendered DOM in a real browser, and
// SERVER_SIDE_BREAKOUT, which is decided from the raw HTTP response alone
// (burp.Zh7u / burp.Zukw). Zh7u builds exactly two breakout attempts per
// canary: an HTML/attribute breakout using the tag's own open/close pair
// (lambda$new$0: `open+canary+open`, `close+canary+close`), and a JavaScript
// string breakout using a backslash escape plus a `//` line comment
// (lambda$new$1: `\+canary+"//"`, `\+canary+"//"`) so the rest of the original
// script statement is silently commented out rather than breaking the page.
//
// CLIENT_SIDE_BREAKOUT requires a browser/DOM re-parse this port does not have
// (see checks_declined_dom.go) and is deliberately not approximated here.
// SERVER_SIDE_BREAKOUT needs only the request/response pair, so it is the
// evidence class ported below.
package scanner

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

const xssReflectedIssue = "Cross-site scripting (reflected)"

// newXSSCanary returns a per-probe unique token. A fixed test payload would
// let a static page that happens to contain the literal string produce a
// false breakout; a fresh token per probe makes reflection unambiguous.
func newXSSCanary() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "zxssz"
	}
	return "zxss" + hex.EncodeToString(buf)
}

// XSSEvidence mirrors Java's SERVER_SIDE_BREAKOUT decision: whether the canary
// reflected at all, whether it reflected with its HTML/JS metacharacters
// intact, and whether that survival was sufficient to close the surrounding
// HTML tag/attribute or JavaScript string literal.
type XSSEvidence uint16

const (
	XSSEvidenceReflected XSSEvidence = 1 << iota
	XSSEvidenceReflectedEncoded
	XSSEvidenceHTMLBreakout
	XSSEvidenceScriptBreakout
	// XSSEvidenceAttrInjection is an attribute added to an element that was already there, which
	// is the exploit when a host escapes `<` and `>` but leaves the quote alone. Distinct from
	// XSSEvidenceHTMLBreakout because no tag is injected and saying one was would describe
	// something that did not happen.
	XSSEvidenceAttrInjection
	// XSSEvidenceURLScheme is a javascript: scheme leading a URL-valued attribute. No tag, no
	// quote, and nothing a markup marker could ever show.
	XSSEvidenceURLScheme
)

// htmlBreakoutSuffix is Zh7u's lambda$new$0 shape specialised to the common
// case of breaking out of an HTML tag/attribute: close the current context
// with `"><` and open a new element that proves script execution would run.
// The canary is repeated so the probe is unambiguous even if the response
// HTML-encodes one copy but not the other (Burp reports exactly this split).
func htmlBreakoutPayload(canary string) string {
	return `"><svg id=` + canary + ` onload=alert(1)>`
}

// scriptBreakoutPayload closes the enclosing JavaScript string literal, puts the canary in
// expression position, and comments out the remainder of the original statement so the script
// still parses.
//
// The shape this replaced — `\'-alert(<canary>)-'\//` — could not work, and was measured not to
// rather than argued about. Run in a real JS engine against the three host shapes it targets:
//
//	var a = '\'-alert(C)-'\//';   SyntaxError, alert never called
//	var a = "\'-alert(C)-'\//";   no error, but the payload never leaves the string
//	var a = '\\'-alert(C)-\'\//'; SyntaxError, alert never called
//
// The leading `\'` was the defect: inside a string literal a backslash ESCAPES the quote that
// follows, so the payload extended the string it was trying to close, and the trailing bare `\`
// then made the statement unparseable. That means the script-breakout bit could only ever have
// been set by the substring marker matching the payload's own bytes — never by an actual breakout.
// The evidence and the thing it claimed to evidence had come apart.
//
// `';alert(C)//` closes the literal for real. Verified the same way: the engine reports
// `ReferenceError: C is not defined`, which is the interpreter evaluating the canary as an
// identifier in expression position — reaching executable position is exactly the claim.
//
// Burp's Zh7u lambda$new$1 is `\`+canary+`//`, which is the escape-the-escaper variant below
// rather than this one; the two target different host behaviour and both are sent.
func scriptBreakoutPayload(canary string) string {
	return scriptBreakoutPayloadFor('\'', canary)
}

// scriptBreakoutPayloadFor returns the breakout for a specific host-string quote.
//
// quote is the delimiter of the literal the canary landed in: '\” or '"'. Any other value gets
// the single-quote form, which is the more common host shape.
//
// A payload cannot serve both quote styles at once — `';…//` sits inertly inside a double-quoted
// host and vice versa — which is why the check learns the context before choosing, rather than
// sending one payload and hoping. That is ZAP's ordering and the reason its false-positive rate is
// what it is.
func scriptBreakoutPayloadFor(quote byte, canary string) string {
	q := "'"
	if quote == '"' {
		q = `"`
	}
	return q + `;alert(` + canary + `)//`
}

// scriptBreakoutPayloadEscaped is the escape-the-escaper variant, for a host that escapes a quote
// as \' but does not also escape the backslash.
//
// The leading backslash is consumed by the escape the application itself adds, so the quote that
// follows closes the literal for real. Measured: against a host applying `'` → `\'`, this reaches
// expression position where the plain variant does not. An application that escapes backslashes
// too — json.Marshal, and anything else doing it properly — defeats this, which is the correct
// outcome and is what xss_jscontext.go is there to notice.
func scriptBreakoutPayloadEscaped(quote byte, canary string) string {
	return `\` + scriptBreakoutPayloadFor(quote, canary)
}

// xssHTMLBreakoutMarker is the literal substring that only appears in the
// response if htmlBreakoutPayload survived unescaped: the closing `>` of the
// crafted tag right after the canary-tagged attribute.
func xssHTMLBreakoutMarker(canary string) string {
	return `<svg id=` + canary + ` onload=alert(1)>`
}

// xssScriptBreakoutMarker is the literal substring that only appears if the JavaScript string
// escape survived: the crafted expression WITH the surrounding single quotes.
//
// The quotes are load-bearing and were once omitted. A marker of `alert(<canary>)` alone is a
// substring of scriptBreakoutPayload itself, and HTML escaping transforms `'`, `"`, `<`, `>` and
// `&` while leaving `alert(`, the parentheses and an alphanumeric canary untouched — so an
// endpoint that escaped its output correctly still contained the marker and was reported as
// vulnerable. The discriminator has to be something the payload cannot carry through escaping,
// and for a quote breakout that means the quotes themselves: `'` survives as `'` only when
// unescaped, and becomes `&#39;` when not.
//
// This was latent for as long as the check appended a guessed parameter name and never reached a
// sink. Driving it through real insertion points is what surfaced it.
func xssScriptBreakoutMarker(canary string) string {
	return `;alert(` + canary + `)//`
}

// analyzeXSSReflection classifies one probe's response body without network
// or storage access, so the Java-derived decision table is independently
// testable. canary must be the exact unique token embedded in the payload
// sent for this probe; reusing a canary across probes would make evidence
// from one probe indistinguishable from another.
//
// contentType is the response's declared type and is REQUIRED to be one a browser will render as
// markup. Reflected XSS is a claim about what a browser does with the response, and a browser does
// not parse text/plain or application/json as HTML, so a payload coming back intact in one of those
// is a reflection and nothing more. Without this gate every plain-text echo endpoint confirms a
// breakout — internal/vulnapp alone has four (/safe/products, /safe/download, /safe/ping, and
// /ping's non-shell branch), all of them false positives that the corpus could not see because it
// only asked whether the row fired against its own declared endpoint. ZAP gates the same way
// (CrossSiteScriptingScanRule checks the type before classifying context).
func analyzeXSSReflection(body, canary, contentType string, htmlMarker, scriptMarker string) XSSEvidence {
	if canary == "" || !strings.Contains(body, canary) {
		return 0
	}
	evidence := XSSEvidenceReflected
	if !rendersAsMarkup(contentType) {
		// Reflected, but into something no browser will execute. Recorded as a reflection so the
		// observation is not lost, never as a breakout.
		return evidence | XSSEvidenceReflectedEncoded
	}

	if !strings.Contains(body, htmlMarker) {
		evidence |= XSSEvidenceReflectedEncoded
	}

	// The HTML claim is that a crafted element was injected. The marker's presence as a substring
	// is necessary but not sufficient: the same bytes inside a comment, inside <textarea>, or
	// inside a script string are text a browser never turns into an element. Requiring the marker
	// to sit where markup is actually parsed is ZAP's re-verification step, and it is the
	// difference between "these bytes came back" and "an element was created".
	if strings.Contains(body, htmlMarker) && htmlMarkerIsParsedAsMarkup(body, htmlMarker) {
		evidence |= XSSEvidenceHTMLBreakout
	}

	// The script claim rests on the lexer, not on a substring.
	//
	// It used to be `strings.Contains(body, scriptMarker)`, which is what reported an endpoint
	// reflecting through json.Marshal as vulnerable: JSON leaves `'` alone so the marker survived,
	// and doubled the payload's backslash so the quote it meant to escape with terminated nothing.
	// The bytes that "proved" the breakout and the bytes that neutralised it were the same bytes;
	// only their position in the grammar separated them, and a substring test cannot see position.
	//
	// scriptMarker is now a hint rather than a requirement. Requiring it would re-introduce the
	// same class of error in the opposite direction: a host that reflects the payload with its
	// punctuation rearranged, or that splits it across a template, can still put the canary in
	// executable position, and that is a breakout whether or not the crafted bytes survived
	// verbatim. The lexer answers the question the marker was standing in for.
	if xssScriptBreakoutReachesCode(body, canary) {
		evidence |= XSSEvidenceScriptBreakout
	}
	return evidence
}

// htmlMarkerIsParsedAsMarkup reports whether the injected marker sits somewhere a browser parses
// markup, rather than somewhere it is inert text.
//
// It classifies the canary's own occurrences rather than the marker's: the canary is what the
// classifier can find unambiguously, and it is embedded in the marker by construction. A canary in
// a text node means the surrounding crafted tag is parsed as a tag. A canary inside a comment,
// inside RCDATA or inside a script is inert as markup.
//
// An attribute-value occurrence counts, because that is where the crafted `"><svg …>` payload does
// its work: the quote closes the value, the `>` closes the tag, and the element that follows is
// real. That the classifier reports it as an attribute value is a statement about the ORIGINAL
// document's shape at that offset, not a claim the breakout failed.
func htmlMarkerIsParsedAsMarkup(body, marker string) bool {
	canary := canaryWithinMarker(marker)
	if canary == "" {
		return true // Nothing to place; fall back to the substring verdict rather than dropping it.
	}
	contexts := classifyXSSContexts(body, canary)
	if len(contexts) == 0 {
		return true
	}
	for _, c := range contexts {
		switch c.Kind {
		case xssCtxText, xssCtxAttrValue:
			return true
		}
	}
	return false
}

// xssScriptBreakoutReachesCode reports whether the canary reached executable position in any
// <script> in the body.
func xssScriptBreakoutReachesCode(body, canary string) bool {
	for _, sb := range scriptBodies(body) {
		if jsBreakoutConfirmed(sb.Source, canary) {
			return true
		}
	}
	return false
}

// canaryWithinMarker recovers the canary from a marker built by xssHTMLBreakoutMarker, whose shape
// is `<svg id=<canary> onload=alert(1)>`. Returns "" when the marker is not that shape, so a
// caller can tell "no canary to place" from "canary placed nowhere".
func canaryWithinMarker(marker string) string {
	const prefix = `<svg id=`
	const suffix = ` onload=alert(1)>`
	if !strings.HasPrefix(marker, prefix) || !strings.HasSuffix(marker, suffix) {
		return ""
	}
	return marker[len(prefix) : len(marker)-len(suffix)]
}

// rendersAsMarkup reports whether a browser will parse this content type as markup.
//
// An empty type counts as markup: a response with no Content-Type is sniffed, and sniffing HTML-ish
// bytes is exactly the case an attacker relies on. Everything else must say so explicitly.
func rendersAsMarkup(contentType string) bool {
	t := strings.ToLower(strings.TrimSpace(contentType))
	if t == "" {
		return true
	}
	if i := strings.IndexByte(t, ';'); i >= 0 {
		t = strings.TrimSpace(t[:i])
	}
	switch t {
	case "text/html", "application/xhtml+xml", "application/xml", "text/xml", "image/svg+xml":
		return true
	}
	return false
}

func xssBreakoutConfirmed(evidence XSSEvidence) bool {
	return evidence&(XSSEvidenceHTMLBreakout|XSSEvidenceScriptBreakout|
		XSSEvidenceAttrInjection|XSSEvidenceURLScheme) != 0
}

func xssEvidenceText(evidence XSSEvidence) string {
	parts := make([]string, 0, 2)
	if evidence&XSSEvidenceHTMLBreakout != 0 {
		parts = append(parts, "HTML/attribute breakout: injected tag reflected unescaped")
	}
	if evidence&XSSEvidenceAttrInjection != 0 {
		parts = append(parts, "attribute injection: an event-handler attribute was added to an existing element")
	}
	if evidence&XSSEvidenceURLScheme != 0 {
		parts = append(parts, "URL scheme injection: a javascript: URL leads a URL-valued attribute")
	}
	if evidence&XSSEvidenceScriptBreakout != 0 {
		parts = append(parts, "JavaScript string breakout: escaped literal reflected unescaped")
	}
	if len(parts) == 0 && evidence&XSSEvidenceReflected != 0 {
		if evidence&XSSEvidenceReflectedEncoded != 0 {
			return "canary reflected but HTML-encoded; no breakout achieved"
		}
		return "canary reflected without a confirmed breakout"
	}
	return strings.Join(parts, "; ")
}
