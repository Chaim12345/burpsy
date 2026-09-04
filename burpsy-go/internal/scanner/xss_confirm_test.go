package scanner

// Tests for the per-payload confirmation layer in xss_confirm.go.
//
// # Why these are direct unit tests and not only runtime coverage
//
// The confirmers are the code that stands between a reflection and a reported vulnerability, and
// every one of this project's worst historical defects lived exactly here: a presence substring
// that fired on escaped output, an attribute predicate that accepted renamed handlers, a URL
// attribute list that claimed <img src> executes javascript:. The runtime-coverage suite proves
// each row fires on its vulnapp fixture, but a fixture suite cannot enumerate the *negatives* —
// all the correctly-escaped hosts that must stay silent. Those negatives are pinned here, one per
// defence shape a real host actually ships: entity encoding, quote escaping, handler renaming,
// blocklist filtering, scheme-neutral URL attributes.
//
// Every test is a positive/negative pair or a single negative against a confirmed positive
// sibling, so a change that makes a confirmer more eager cannot pass by also breaking its
// positive case.

import (
	"html"
	"strings"
	"testing"
)

const confirmTestCanary = "zxssconf01"

// --- confirmMarkupBreakout ---------------------------------------------------

func TestAMarkupBreakoutIsConfirmedOnlyWhenTheCraftedElementParses(t *testing.T) {
	c := confirmTestCanary

	if !confirmMarkupBreakout(`<p>searched for </p><svg id=`+c+` onload=alert(1)>`, c) {
		t.Fatal("a verbatim tag breakout in element position was not confirmed")
	}
	// The same marker inside an attribute value that was never closed (the host escaped `"` but
	// left `<`/`>` alone) creates zero elements in a browser. The parser sees one attribute on
	// input; there is no svg element. Confirming here was the false positive that motivated this
	// layer.
	if confirmMarkupBreakout(`<input value="&quot;><svg id=`+c+` onload=alert(1)>">`, c) {
		t.Fatal("marker bytes inside an unclosed attribute value were confirmed as a tag breakout; no element exists there")
	}
	if confirmMarkupBreakout(`&lt;svg id=`+c+` onload=alert(1)&gt;`, c) {
		t.Fatal("an HTML-escaped payload was confirmed as a tag breakout")
	}
	if confirmMarkupBreakout(`<svg id=someoneelse onload=alert(1)>`, c) {
		t.Fatal("a crafted svg whose id is not the canary was confirmed")
	}
}

// The true-positive contrast for the unclosed-attribute case above: when the quote is NOT
// escaped, the payload really does close the attribute and the crafted element parses.
func TestAnUnescapedQuoteInAQuotedAttributeReallyIsATagBreakout(t *testing.T) {
	c := confirmTestCanary
	if !confirmMarkupBreakout(`<input value=""><svg id=`+c+` onload=alert(1)>">`, c) {
		t.Fatal("a payload that closed the attribute and opened the crafted element was not confirmed")
	}
}

// --- confirmAltHandlerBreakout ------------------------------------------------

func TestAnAltHandlerBreakoutRequiresADetailsElementCarryingItsOwnOntoggle(t *testing.T) {
	c := confirmTestCanary

	if !confirmAltHandlerBreakout(`"><details open ontoggle=alert(`+c+`)>`, c) {
		t.Fatal("the alt-handler payload reflected verbatim was not confirmed")
	}
	// Attribute values arrive whitespace-padded from some hosts; the expression is still exact.
	if !confirmAltHandlerBreakout(`<details open ontoggle="  alert(`+c+`)  ">`, c) {
		t.Fatal("an ontoggle value equal to the payload modulo surrounding whitespace was not confirmed")
	}
	// A blocklist that deletes ontoggle leaves the element but removes the execution.
	if confirmAltHandlerBreakout(`<details open>`, c) {
		t.Fatal("a details element with its handler filtered away was confirmed as a breakout")
	}
	// A defence that renames the attribute neutralises it; the old prefix-matching predicate read
	// that rename as executable.
	if confirmAltHandlerBreakout(`<details open data-ontoggle="alert(`+c+`)">`, c) {
		t.Fatal("a renamed (data-)ontoggle attribute was confirmed as executable")
	}
	if confirmAltHandlerBreakout(`<div ontoggle="alert(`+c+`)">`, c) {
		t.Fatal("the payload's handler on an element other than the one the payload crafts was confirmed")
	}
}

// --- confirmEventAttrInjection -------------------------------------------------

func TestEventAttributeInjectionIsConfirmedOnlyForExactlyTheInjectedExpression(t *testing.T) {
	c := confirmTestCanary

	// quotedAttrEventPayload spliced into a single-quoted host attribute: one attribute closed,
	// a new handler added, nothing else.
	if !confirmEventAttrInjection(`<input value='' autofocus onfocus='alert(`+c+`)' name=q>`, c) {
		t.Fatal("a genuine attribute injection carrying the payload's own expression was not confirmed")
	}
	// A reflection into a handler that already existed carries the surrounding call. Correct
	// JS-literal and attribute escaping means nothing executes; reporting this was the project's
	// worst historical category (high/firm XSS against correctly-written code).
	if confirmEventAttrInjection(`<a onclick="track('alert(`+c+`)')">link</a>`, c) {
		t.Fatal("a canary reflected inside an existing handler's string literal was confirmed as injection")
	}
	// Extra statements around the expression are not "exactly what the payload injected" either:
	// this confirmer's contract is that the whole value came from the payload.
	if confirmEventAttrInjection(`<a onclick="doThing();alert(`+c+`)">x</a>`, c) {
		t.Fatal("a handler value with statements beyond the injected expression was confirmed as injection")
	}
	// A sanitiser that renames the handler has defended; the value never runs.
	if confirmEventAttrInjection(`<img src=x onfocusx=alert(`+c+`)>`, c) {
		t.Fatal("an unknown on* attribute name was treated as an executable handler")
	}
	// An alphanumeric name that merely starts with "on" was accepted by the old prefix test.
	if confirmEventAttrInjection(`<img src=x online=alert(`+c+`)>`, c) {
		t.Fatal("an attribute named like the word 'online' was treated as an event handler")
	}
}

func TestEveryKnownEventAttributeNameIsAcceptedAndNearMissesRefused(t *testing.T) {
	for _, name := range []string{"onclick", "onerror", "onload", "onfocus", "ontoggle",
		"onpointerover", "onanimationend", "ontouchstart"} {
		if !isKnownEventAttr(name) {
			t.Fatalf("%s is a browser-dispatched handler but isKnownEventAttr refuses it", name)
		}
	}
	for _, name := range []string{"on", "o", "once", "only", "on_focus", "on-focus",
		"data-onclick", "handler", "onclickhandler"} {
		if isKnownEventAttr(name) {
			t.Fatalf("%s is not a browser-dispatched handler but isKnownEventAttr accepts it", name)
		}
	}
}

// --- confirmHandlerLiteralBreakout --------------------------------------------

func TestAHandlerLiteralBreakoutIsDecidedByTheScriptLexerNotSubstringPresence(t *testing.T) {
	c := confirmTestCanary

	// The closing-call breakout inside an existing handler: the payload's own quote and paren
	// close the host's literal and call, so the value the browser compiles is
	// track('');alert(C)//') — canary in statement position, handler still parses.
	if !confirmHandlerLiteralBreakout(`<div onclick="track('');alert(`+c+`)//')">x</div>`, c) {
		t.Fatal("a string-literal-and-call breakout inside an inline handler was not confirmed")
	}
	// Correct escaping keeps the canary inside the literal it landed in. Substring presence of
	// the canary in an on* attribute is not evidence of anything — that fact chose the context.
	if confirmHandlerLiteralBreakout(`<div onclick="track('`+c+`')">x</div>`, c) {
		t.Fatal("a canary still enclosed by its string literal was confirmed as a handler breakout")
	}
	// A breakout that closes the literal but NOT the enclosing call leaves a `;` inside an
	// argument list — a SyntaxError, so nothing runs. This is why the chooser sends the
	// closing-call variant beside the plain one instead of instead of it.
	if confirmHandlerLiteralBreakout(`<div onclick="track('';alert(`+c+`)//')">x</div>`, c) {
		t.Fatal("a breakout leaving a statement inside an argument list was confirmed despite being a SyntaxError")
	}
}

// --- confirmJavaScriptURL ------------------------------------------------------

func TestAJavascriptSchemeCountsOnlyWhereABrowserRunsItAndOnlyAtTheValueStart(t *testing.T) {
	c := confirmTestCanary
	payload := javascriptURLPayload(c)

	// The three attributes measured to execute the scheme in a current browser.
	for _, attr := range []struct{ tag, attr string }{
		{"a", "href"}, {"form", "action"}, {"button", "formaction"},
	} {
		body := `<` + attr.tag + ` ` + attr.attr + `="` + payload + `">x`
		if !confirmJavaScriptURL(body, c) {
			t.Fatalf("javascript: at the start of %s was not confirmed", attr.attr)
		}
	}
	// Leading whitespace before the scheme does not stop it being the scheme.
	if !confirmJavaScriptURL(`<a href="  `+payload+`">x</a>`, c) {
		t.Fatal("a javascript: scheme preceded only by whitespace was not confirmed")
	}
	if !confirmJavaScriptURL("<a href=\"\n\t"+payload+"\">x</a>", c) {
		t.Fatal("a javascript: scheme preceded by a newline was not confirmed")
	}

	// Attributes that hold URLs but refuse the scheme. Reporting reflection into <img src> was a
	// shipped false positive: avatars and image proxies reflect URLs all day.
	for _, attr := range []struct{ tag, attr string }{
		{"img", "src"}, {"iframe", "src"}, {"script", "src"}, {"video", "poster"},
		{"body", "background"}, {"blockquote", "cite"}, {"object", "data"}, {"a", "ping"},
	} {
		body := `<` + attr.tag + ` ` + attr.attr + `="` + payload + `">`
		if confirmJavaScriptURL(body, c) {
			t.Fatalf("javascript: in <%s %s> was confirmed, but a current browser refuses the scheme there", attr.tag, attr.attr)
		}
	}
	// A canary somewhere inside a legitimate URL is a reflection and nothing more.
	if confirmJavaScriptURL(`<a href="https://safe.test/?next=`+payload+`">x</a>`, c) {
		t.Fatal("javascript: buried mid-URL was confirmed; the scheme must lead the value")
	}
	// The scheme in a non-URL attribute is inert even at the start.
	if confirmJavaScriptURL(`<div title="`+payload+`">x</div>`, c) {
		t.Fatal("javascript: in a title attribute was confirmed")
	}
}

// --- confirmSrcdocBreakout -----------------------------------------------------

func TestASrcdocBreakoutIsConfirmedInBothItsEncodedAndRawForms(t *testing.T) {
	c := confirmTestCanary

	// The encoded form IS the live payload here: the attribute parser decodes it before parsing
	// the inner document.
	if !confirmSrcdocBreakout(`<iframe srcdoc="&lt;svg id=`+c+` onload=alert(1)&gt;"></iframe>`, c) {
		t.Fatal("an HTML-encoded payload inside srcdoc was not confirmed; decoding is the transform the defect needs")
	}
	// A host that both decodes into srcdoc AND echoes raw markup is vulnerable twice over. The
	// previous early-return on raw markup refused to confirm either — inverted severity.
	if !confirmSrcdocBreakout(`<iframe srcdoc="<p>hi</p>"></iframe><svg id=`+c+` onload=alert(1)>`, c) {
		t.Fatal("raw markup beside a srcdoc host was not confirmed; the guard must not refuse a second defect")
	}
	// The encoded marker outside a srcdoc attribute is inert text everywhere else.
	if confirmSrcdocBreakout(`<div title="&lt;svg id=`+c+` onload=alert(1)&gt;">x</div>`, c) {
		t.Fatal("the encoded marker in a non-srcdoc attribute was confirmed as a srcdoc breakout")
	}
	// A host that dropped the payload entirely stays silent.
	if confirmSrcdocBreakout(`<iframe srcdoc="<p>safe</p>"></iframe>`, c) {
		t.Fatal("a response with neither raw nor decoded payload was confirmed")
	}
}

// --- anyAttr --------------------------------------------------------------------

func TestAnyAttrTellsOneEscapedValueFromTwoRealAttributes(t *testing.T) {
	c := confirmTestCanary

	// One attribute holding an escaped payload — correct output, nothing executes.
	escaped := `<input value="&#34; onfocus=&#34;alert(` + c + `)">`
	// Two attributes — the quote genuinely closed and a live handler was added.
	real := `<input value="" onfocus="alert(` + c + `)">`

	if confirmEventAttrInjection(escaped, c) {
		t.Fatal("a payload held inside one escaped attribute value was confirmed as attribute injection")
	}
	if !confirmEventAttrInjection(real, c) {
		t.Fatal("a payload that closed the attribute and added a real handler was not confirmed")
	}
}

// --- round trips: builder → echo → confirmer ------------------------------------

// Every payload family's product must be confirmed by the confirmer wired to it when a host
// echoes it verbatim into the context it was built for, and refused when the host defends. This
// is the drift guard: the original defect class was one half changed while the other stayed
// behind, so the right payload was verified against the wrong evidence and detection silently
// fell while false positives rose.
func TestEachPayloadFamilyConfirmsOnAVerbatimEchoAndStaysSilentOnADefendedOne(t *testing.T) {
	c := confirmTestCanary
	escape := html.EscapeString

	cases := []struct {
		name    string
		payload string
		host    func(payload string) string // renders an echoed payload into a plausible host page
		confirm func(body, canary string) bool
		// safeHost, where set, replaces plain HTML escaping — srcdoc's escaped form is its LIVE
		// form, and javascript:'s contains no escapable bytes at all, so those families need a
		// different defended twin.
		safeHost func(payload string) string
	}{
		{
			name:    "tag breakout",
			payload: htmlBreakoutPayload(c),
			host:    func(p string) string { return `<p>results for ` + p + `</p>` },
			confirm: confirmMarkupBreakout,
		},
		{
			name:    "alt-handler breakout",
			payload: altHandlerBreakoutPayload(c),
			host:    func(p string) string { return `<div>` + p + `</div>` },
			confirm: confirmAltHandlerBreakout,
		},
		{
			name:    "quoted-attribute event injection",
			payload: quotedAttrEventPayload('\'', c),
			host:    func(p string) string { return `<input value='` + p + `'>` },
			confirm: confirmEventAttrInjection,
		},
		{
			name:     "javascript: scheme",
			payload:  javascriptURLPayload(c),
			host:     func(p string) string { return `<a href="` + p + `">x</a>` },
			confirm:  confirmJavaScriptURL,
			safeHost: func(p string) string { return `<a href="/search?q=` + p + `">x</a>` },
		},
		{
			name:    "srcdoc double context",
			payload: srcdocBreakoutPayload(c),
			host:    func(p string) string { return `<iframe srcdoc="` + p + `"></iframe>` },
			confirm: confirmSrcdocBreakout,
			// The escaped form decodes back into markup inside srcdoc, so escaping IS the defect
			// here; the silent twin is a host that drops the payload.
			safeHost: func(string) string { return `<iframe srcdoc="<p>safe</p>"></iframe>` },
		},
		{
			name:    "script string breakout",
			payload: scriptBreakoutPayloadFor('\'', c),
			host:    func(p string) string { return `<script>var q='` + p + `';</script>` },
			confirm: confirmScriptBreakout,
		},
		{
			name:    "handler literal-and-call breakout",
			payload: scriptBreakoutPayloadClosingCall('\'', c),
			host:    func(p string) string { return `<div onclick="track('` + p + `')">x</div>` },
			confirm: confirmHandlerLiteralBreakout,
			// HTML-escaping is NOT a defence here — the attribute parser decodes entities before
			// the handler compiles, so the escaped form executes identically. The honest defended
			// twin is a host that JS-escapes the quote inside its own literal.
			safeHost: func(p string) string {
				return `<div onclick="track('` + strings.ReplaceAll(p, "'", `\'`) + `')">x</div>`
			},
		},
	}

	for _, tc := range cases {
		body := tc.host(tc.payload)
		if !tc.confirm(body, c) {
			t.Fatalf("%s: the payload echoed verbatim was not confirmed by its own confirmer", tc.name)
		}
		safe := body
		if tc.safeHost != nil {
			safe = tc.safeHost(tc.payload)
		} else {
			safe = tc.host(escape(tc.payload))
		}
		if tc.confirm(safe, c) {
			t.Fatalf("%s: the defended host was confirmed — the confirmer fires on output that does not execute", tc.name)
		}
	}
}

// The chooser must wire every payload it builds to A confirmer: a nil confirm field means the
// evidence falls back to whatever generic marker check owns the call site, which is the exact
// mismatch this layer exists to remove.
func TestEveryContextSpecificPayloadCarriesItsOwnConfirmation(t *testing.T) {
	c := confirmTestCanary
	contexts := []xssContext{
		{Kind: xssCtxText, TagName: "p"},
		{Kind: xssCtxAttrValue, TagName: "input", AttrName: "value", Quote: '\''},
		{Kind: xssCtxAttrValue, TagName: "a", AttrName: "href"},
		{Kind: xssCtxComment},
		{Kind: xssCtxRCDATA, TagName: "textarea"},
		{Kind: xssCtxScript, TagName: "script", Quote: '\''},
	}
	payloads := xssPayloadsForContexts(contexts)
	if len(payloads) == 0 {
		t.Fatal("the chooser built no payloads for six real contexts")
	}
	for _, p := range payloads {
		if p.confirm == nil {
			t.Fatalf("payload %q carries no confirmation; it would be graded against generic markers", p.note)
		}
		if !strings.Contains(p.build(c), c) {
			t.Fatalf("payload %q does not embed its canary; no response could ever reflect it", p.note)
		}
	}
}
