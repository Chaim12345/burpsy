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
	// The crafted element must exist as a PARSED element carrying the canary as its own id.
	//
	// Presence of the marker bytes is not enough, and neither is "the canary landed in some
	// attribute value". htmlMarkerIsParsedAsMarkup answers the second question and returns true for
	// any attribute placement without checking which element or attribute, so a host that escapes
	// `"` to `&quot;` and leaves `<`/`>` alone - correct escaping for a quoted attribute, since
	// nothing can close the value - still had the marker bytes sitting inside its own value, was
	// classified as an attribute occurrence, and was reported as a tag breakout. The browser creates
	// zero elements there.
	//
	// The parser already knows the difference: it reports tag=svg attr=id for a real breakout and
	// tag=input attr=value for the escaped one. Asking it for the crafted element is both simpler
	// and strictly stronger than asking whether the bytes are present.
	return anyAttr(body, func(tag, name, value string) bool {
		return tag == "svg" && name == "id" && value == canary
	})
}

// confirmAltHandlerBreakout is confirmMarkupBreakout for the payload whose handler avoids the usual
// blocklist: the crafted <details> must exist with the canary inside its own ontoggle.
func confirmAltHandlerBreakout(body, canary string) bool {
	want := "alert(" + canary + ")"
	return anyAttr(body, func(tag, name, value string) bool {
		return tag == "details" && name == "ontoggle" && strings.TrimSpace(value) == want
	})
}

// confirmEventAttrInjection is the evidence for attribute injection: the canary must be inside the
// value of an event-handler attribute on a real element.
//
// This is the case a quote-closing marker could never see. When a host escapes `<` and `>` but
// leaves a quote alone, no tag can be opened and the exploit is to add an attribute to the element
// already there - so the evidence is not "markup appeared" but "the canary is now JavaScript that
// the browser will run on an event".
func confirmEventAttrInjection(body, canary string) bool {
	// The handler's value must be EXACTLY the expression the payload injected.
	//
	// "the canary sits in some on* attribute" is not evidence of an injection, and for the
	// inline-handler context it is not evidence of anything at all: that fact is what classified the
	// context in the first place, so the confirmation could never fail. A host reflecting into
	// `onclick="track('…')"` with correct JS-literal and attribute escaping was reported as XSS at
	// high/firm, which is this project's worst category.
	//
	// An injected handler carries the payload's expression and nothing else. A reflection into an
	// existing handler carries the surrounding call, so `track('alert(C)')` is not `alert(C)` and is
	// correctly refused. isKnownEventAttr keeps a renamed or unknown attribute from counting as
	// executable.
	want := "alert(" + canary + ")"
	return anyAttr(body, func(tag, name, value string) bool {
		return isKnownEventAttr(name) && strings.TrimSpace(value) == want
	})
}

// confirmEventAttrInjectionBacktick is confirmEventAttrInjection for the backtick-call payload.
//
// The same rule applies: the injected handler's value must be exactly the expression the payload
// put there, so a reflection into an existing handler is refused. The only difference is the call
// syntax — a tagged template literal instead of a parenthesised call — which is what lets the
// payload survive a host that strips parentheses.
func confirmEventAttrInjectionBacktick(body, canary string) bool {
	want := "alert`" + canary + "`"
	return anyAttr(body, func(tag, name, value string) bool {
		return isKnownEventAttr(name) && strings.TrimSpace(value) == want
	})
}

// confirmHandlerLiteralBreakout is the evidence for the inline-handler context, where the value is
// already JavaScript and the payload has to leave the string literal it landed in.
//
// The attribute value IS a script, so the same lexer that decides the <script> case decides this
// one. Correct escaping keeps the canary inside the literal and is refused; a real breakout puts it
// in code position.
func confirmHandlerLiteralBreakout(body, canary string) bool {
	return anyAttr(body, func(tag, name, value string) bool {
		return isKnownEventAttr(name) && strings.Contains(value, canary) &&
			jsBreakoutConfirmed(value, canary)
	})
}

// confirmJavaScriptURL is the evidence for a scheme injection, and follows ZAP's
// isJavaScriptSchemeInjectionValid: the payload has to sit at the START of a URL-valued attribute,
// because `https://x/?q=javascript:alert(1)` is a reflection and nothing more.
func confirmJavaScriptURL(body, canary string) bool {
	want := javascriptURLPayload(canary)
	return anyAttr(body, func(tag, name, value string) bool {
		if !isExecutableURLAttr(name) {
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
	// No early return on raw markup. That guard delegated to "the tag payload", but the chooser adds
	// exactly one payload for an HTML-valued attribute - this one - so there was nothing in flight to
	// delegate to, and a host that BOTH entity-decodes into srcdoc and echoes raw markup is
	// vulnerable twice over yet was confirmed by neither. The guard was inverted with respect to
	// severity. A raw-markup host is caught by the crafted-element check, and a decoding host by the
	// decoded-value check below.
	if anyAttr(body, func(tag, name, value string) bool {
		return tag == "svg" && name == "id" && value == canary
	}) {
		return true
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

// isExecutableURLAttr reports whether a javascript: value in this attribute actually RUNS in a
// current browser.
//
// Measured in Chrome rather than assumed, because the list of attributes that hold a URL is much
// longer than the list that will execute one: img src, iframe src, script src, video poster, body
// background, blockquote cite, object data and a ping all refuse the scheme. Only a navigation
// target runs it. Treating "holds a URL" as "executes a URL" reported reflection into <img src> - an
// everyday shape for avatars and image proxies - as XSS at high/firm, with evidence claiming an
// execution that cannot happen.
//
// formaction and a href both reach it through a user action, which is true of the real defect too.
func isExecutableURLAttr(name string) bool {
	switch name {
	case "href", "action", "formaction":
		return true
	}
	return false
}

// isKnownEventAttr reports whether the attribute is an inline handler a browser will execute.
//
// A prefix test on "on" was wrong in the direction that matters: it accepts on_focus, on-focus,
// onxyzzy and even "one", so a sanitiser that neutralises a handler by RENAMING it - a real defence -
// left something this predicate called executable, and the defence read as the defect. Only names
// browsers actually dispatch belong here.
func isKnownEventAttr(name string) bool {
	switch name {
	case "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover", "onmousemove",
		"onmouseout", "onmouseenter", "onmouseleave", "onkeydown", "onkeypress", "onkeyup",
		"onfocus", "onblur", "onfocusin", "onfocusout", "onchange", "oninput", "onsubmit",
		"onreset", "onselect", "onload", "onunload", "onerror", "onabort", "onbeforeunload",
		"onresize", "onscroll", "ontoggle", "onanimationstart", "onanimationend",
		"onanimationiteration", "ontransitionend", "onplay", "onplaying", "onpause", "onended",
		"oncanplay", "onloadeddata", "onloadstart", "onprogress", "onwheel", "oncontextmenu",
		"ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop",
		"oncopy", "oncut", "onpaste", "onpageshow", "onpagehide", "onbeforeinput", "onsearch",
		"onauxclick", "onpointerdown", "onpointerup", "onpointerover", "onpointerenter",
		"onpointerleave", "onpointermove", "ontouchstart", "ontouchend", "ontouchmove":
		return true
	}
	return false
}
