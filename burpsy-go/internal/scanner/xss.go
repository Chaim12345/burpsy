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
)

// htmlBreakoutSuffix is Zh7u's lambda$new$0 shape specialised to the common
// case of breaking out of an HTML tag/attribute: close the current context
// with `"><` and open a new element that proves script execution would run.
// The canary is repeated so the probe is unambiguous even if the response
// HTML-encodes one copy but not the other (Burp reports exactly this split).
func htmlBreakoutPayload(canary string) string {
	return `"><svg id=` + canary + ` onload=alert(1)>`
}

// scriptBreakoutSuffix is Zh7u's lambda$new$1 shape: escape out of a
// single-quoted or double-quoted JavaScript string with a backslash, then
// use `//` to comment out whatever followed on the original line, which is
// what makes the resulting script still parse.
func scriptBreakoutPayload(canary string) string {
	return `\'-alert(` + canary + `)-'\` + "//"
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
	return `'-alert(` + canary + `)-'`
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
	if strings.Contains(body, htmlMarker) {
		evidence |= XSSEvidenceHTMLBreakout
	}
	if strings.Contains(body, scriptMarker) {
		evidence |= XSSEvidenceScriptBreakout
	}
	return evidence
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
	return evidence&(XSSEvidenceHTMLBreakout|XSSEvidenceScriptBreakout) != 0
}

func xssEvidenceText(evidence XSSEvidence) string {
	parts := make([]string, 0, 2)
	if evidence&XSSEvidenceHTMLBreakout != 0 {
		parts = append(parts, "HTML/attribute breakout: injected tag reflected unescaped")
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
