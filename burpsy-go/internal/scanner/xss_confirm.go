package scanner

// Per-payload confirmation: what counts as evidence that THIS breakout worked.
//
// # The gap this closes
//
// xss_payloads.go got the first half of ZAP's design right - observe the context, then send the
// payload that works there. The second half was missing, and the call site gave it away: every
// context-specific payload was verified against the two generic markers, `<svg id=CANARY
// onload=alert(1)>` and `'-alert(CANARY)-'`. Most of those payloads cannot produce either.
//
// `javascript:alert(CANARY)` opens no tag. `CANARY autofocus onfocus=alert(CANARY)` opens no tag.
// srcdoc's payload is deliberately HTML-ENCODED in the response, so the raw marker is exactly what
// must NOT appear. Sending the right payload and then looking for the wrong evidence cannot report
// anything, and cmd/xsschallenge measured the result: detection fell from 16/22 to 12/22 while the
// false positive was being removed. The two attribute contexts the payloads were written for stayed
// missed, because nothing could confirm them.
//
// So each payload now states what success looks like in its own context, and the confirmation is
// the same re-classification ZAP performs: parse the response again and ask whether the canary
// ended up somewhere that executes. That is a stronger test than a substring, not a weaker one -
// `onfocus=alert(C)` appearing in the body proves nothing, whereas the canary sitting inside a
// parsed event-handler attribute on a real element is the defect itself.

import (
	"strings"

	"golang.org/x/net/html"
)

// xssConfirm reports whether a payload's own evidence is present in the response.
type xssConfirm func(body, canary string) bool

// confirmMarkupBreakout is the evidence for every payload that opens a tag: the crafted element
// must be present AS MARKUP, not as escaped text. Shared by the text-node, RCDATA, comment and
// quoted-attribute-tag-breakout payloads, all of which emit the same element.
func confirmMarkupBreakout(body, canary string) bool {
	marker := xssHTMLBreakoutMarker(canary)
	// Presence first. htmlMarkerIsParsedAsMarkup is a REFINEMENT of a presence check, not a
	// replacement for one: it answers "given the marker is here, is it markup rather than text",
	// and it deliberately returns true in the vacuous cases so a caller that already found the
	// marker does not lose a verdict. Calling it without establishing presence inverts that
	// courtesy into a false positive, which is exactly what happened - a body that escaped the
	// payload, and even one that stripped it to bare alphanumerics, was reported as a breakout
	// because there was no canary to place and the function said so by returning true.
	if !strings.Contains(body, marker) {
		return false
	}
	return htmlMarkerIsParsedAsMarkup(body, marker)
}

// confirmEventAttrInjection is the evidence for attribute injection: the canary must be inside the
// value of an event-handler attribute on a real element.
//
// This is the case a quote-closing marker could never see. When a host escapes `<` and `>` but
// leaves a quote alone, no tag can be opened and the exploit is to add an attribute to the element
// already there - so the evidence is not "markup appeared" but "the canary is now JavaScript that
// the browser will run on an event".
func confirmEventAttrInjection(body, canary string) bool {
	return anyAttr(body, func(tag, name, value string) bool {
		return isEventAttrName(name) && strings.Contains(value, canary)
	})
}

// confirmJavaScriptURL is the evidence for a scheme injection, and follows ZAP's
// isJavaScriptSchemeInjectionValid: the payload has to sit at the START of a URL-valued attribute,
// because `https://x/?q=javascript:alert(1)` is a reflection and nothing more.
func confirmJavaScriptURL(body, canary string) bool {
	want := javascriptURLPayload(canary)
	return anyAttr(body, func(tag, name, value string) bool {
		if !isURLAttrName(name) {
			return false
		}
		// ZAP's isJavaScriptSchemeInjectionValid: the scheme has to LEAD the value. A canary
		// somewhere inside a legitimate URL is a reflection and nothing more.
		return strings.HasPrefix(strings.TrimLeft(value, " \t\n\r\f"), want)
	})
}

// confirmSrcdocBreakout is the evidence for an HTML-valued attribute, and it is the inverse of
// every other confirmation here.
//
// srcdoc's value is HTML-unescaped by the attribute parser before the inner document is parsed, so
// the payload must survive as an ENCODED attribute value and must NOT appear as raw markup. The
// test is therefore: decode the response the way the attribute parser will, and look for the
// element in the decoded form.
func confirmSrcdocBreakout(body, canary string) bool {
	marker := xssHTMLBreakoutMarker(canary)
	if strings.Contains(body, marker) {
		// Raw markup in the response is a plain tag breakout, which the tag payload confirms.
		// Not this one.
		return false
	}
	// Token().Attr hands back the value already entity-decoded, which is precisely the transform
	// the attribute parser applies before parsing srcdoc's content as HTML. So the decoded value
	// containing the element IS the double-context defect.
	return anyAttr(body, func(tag, name, value string) bool {
		return name == "srcdoc" && strings.Contains(value, marker)
	})
}

// confirmScriptBreakout is the evidence for a JavaScript string breakout: the canary must reach
// code rather than sit inside the literal it was supposed to close.
func confirmScriptBreakout(body, canary string) bool {
	return xssScriptBreakoutReachesCode(body, canary)
}

// anyAttr walks every start tag's attributes as the HTML parser sees them and reports whether any
// satisfies pred, which receives the lowercased tag and attribute names and the DECODED value.
//
// Using the parser's own view is the whole point. A hand-rolled scan over the raw start tag cannot
// tell `value="&#34; onfocus=&#34;alert(C)"` - one attribute holding an escaped payload, which is
// correct output - from `value="" onfocus="alert(C)"` - two attributes, which is the defect. Both
// contain the bytes `onfocus=`. Only a parser knows the first quote never closed, and getting this
// wrong reports XSS against code that escaped properly.
func anyAttr(body string, pred func(tag, name, value string) bool) bool {
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return false
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			for _, a := range t.Attr {
				if pred(strings.ToLower(t.Data), strings.ToLower(a.Key), a.Val) {
					return true
				}
			}
		}
	}
}

// isEventAttrName reports whether the attribute is an inline event handler, whose value a browser
// executes as JavaScript.
func isEventAttrName(name string) bool {
	return strings.HasPrefix(name, "on") && len(name) > 2
}

// isURLAttrName reports whether the attribute's value is resolved as a URL, so a scheme in it is
// executable.
func isURLAttrName(name string) bool {
	switch name {
	case "href", "src", "action", "formaction", "data", "poster", "background", "cite", "longdesc":
		return true
	}
	return false
}
