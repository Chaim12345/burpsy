package scanner

import "strings"

import "testing"

func TestJavaXSSEvidenceRecognizesHTMLBreakout(t *testing.T) {
	canary := "zxsscafe01"
	htmlMarker := xssHTMLBreakoutMarker(canary)
	scriptMarker := xssScriptBreakoutMarker(canary)
	body := `<div class="result">value=` + htmlMarker + `</div>`

	evidence := analyzeXSSReflection(body, canary, "text/html", htmlMarker, scriptMarker)
	if evidence&XSSEvidenceReflected == 0 {
		t.Fatal("canary reflection was not recognized")
	}
	if evidence&XSSEvidenceHTMLBreakout == 0 {
		t.Fatal("HTML breakout evidence was not recognized")
	}
	if !xssBreakoutConfirmed(evidence) {
		t.Fatal("breakout should be confirmed when the HTML marker survived unescaped")
	}
}

func TestJavaXSSEvidenceRecognizesScriptBreakout(t *testing.T) {
	canary := "zxssbeef02"
	htmlMarker := xssHTMLBreakoutMarker(canary)
	scriptMarker := xssScriptBreakoutMarker(canary)
	body := `<script>var msg = 'hi'-alert(` + canary + `)-'\` + "//" + `';</script>`

	evidence := analyzeXSSReflection(body, canary, "text/html", htmlMarker, scriptMarker)
	if evidence&XSSEvidenceScriptBreakout == 0 {
		t.Fatal("script breakout evidence was not recognized")
	}
	if !xssBreakoutConfirmed(evidence) {
		t.Fatal("breakout should be confirmed when the script marker survived unescaped")
	}
}

func TestJavaXSSEvidenceTreatsHTMLEncodedReflectionAsNoBreakout(t *testing.T) {
	canary := "zxssdead03"
	htmlMarker := xssHTMLBreakoutMarker(canary)
	scriptMarker := xssScriptBreakoutMarker(canary)
	// The canary itself (alphanumeric) survives encoding; only the HTML
	// metacharacters around it are entity-encoded, so neither marker appears.
	body := `<div>value=&quot;&gt;&lt;svg id=` + canary + ` onload=alert(1)&gt;</div>`

	evidence := analyzeXSSReflection(body, canary, "text/html", htmlMarker, scriptMarker)
	if evidence&XSSEvidenceReflected == 0 {
		t.Fatal("canary reflection was not recognized")
	}
	if evidence&XSSEvidenceReflectedEncoded == 0 {
		t.Fatal("encoded reflection was not recognized")
	}
	if xssBreakoutConfirmed(evidence) {
		t.Fatal("HTML-encoded reflection must not be reported as a confirmed breakout")
	}
}

func TestJavaXSSEvidenceIsZeroWhenCanaryNotReflected(t *testing.T) {
	canary := "zxssnope04"
	htmlMarker := xssHTMLBreakoutMarker(canary)
	scriptMarker := xssScriptBreakoutMarker(canary)
	body := `<div>no user input reflected here</div>`

	if evidence := analyzeXSSReflection(body, canary, "text/html", htmlMarker, scriptMarker); evidence != 0 {
		t.Fatalf("expected zero evidence for an unreflected canary, got %#x", evidence)
	}
}

func TestJavaXSSProbePayloadsEmbedTheirCanary(t *testing.T) {
	canary := "zxsscanary05"
	if !strings.Contains(htmlBreakoutPayload(canary), canary) {
		t.Fatal("HTML breakout payload does not embed its own canary")
	}
	if !strings.Contains(scriptBreakoutPayload(canary), canary) {
		t.Fatal("script breakout payload does not embed its own canary")
	}
}

// An endpoint that escapes its output correctly must not be reported as vulnerable.
//
// This is the false positive a runtime scan of internal/vulnapp's /safe/search endpoint produced.
// The script-breakout marker was `alert(<canary>)`, a substring of the payload itself, and HTML
// escaping does not touch `alert(`, the parentheses or an alphanumeric canary — so the marker was
// present in a correctly-escaped reflection and the breakout "confirmed".
func TestEscapedReflectionIsNotAScriptBreakout(t *testing.T) {
	canary := "zxsssafe06"
	htmlMarker := xssHTMLBreakoutMarker(canary)
	scriptMarker := xssScriptBreakoutMarker(canary)

	// What an escaping endpoint returns: every character escaping touches, transformed.
	escape := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	)
	for _, payload := range []string{scriptBreakoutPayload(canary), htmlBreakoutPayload(canary)} {
		body := "<h2>Results for: " + escape.Replace(payload) + "</h2>"
		evidence := analyzeXSSReflection(body, canary, "text/html", htmlMarker, scriptMarker)

		if xssBreakoutConfirmed(evidence) {
			t.Errorf("a fully escaped reflection of %q was classified as a breakout (evidence %#x). "+
				"The marker must be something escaping destroys, or every correctly-written endpoint "+
				"is reported vulnerable.", payload, evidence)
		}
		// It should still be recognised as reflected-but-encoded: that is a real observation and
		// losing it would swap one dishonesty for another.
		if evidence&XSSEvidenceReflected == 0 {
			t.Errorf("the canary was in the body but the reflection was not recorded for %q", payload)
		}
		if evidence&XSSEvidenceReflectedEncoded == 0 {
			t.Errorf("an escaped reflection of %q was not marked as encoded", payload)
		}
	}
}

// The other direction: an unescaped reflection in a JavaScript string context IS a breakout, and
// tightening the evidence must not cost that.
//
// This test previously asserted the same thing about the OLD payload, `\'-alert(C)-'\//`, and was
// passing for a reason that did not hold. That payload does not break out of anything. Run in a
// real JS engine against the host below it raises `SyntaxError: Unexpected token ILLEGAL` and
// alert is never called: a backslash inside a string literal escapes the quote that follows, so
// the payload extended the literal it meant to close, and the trailing bare `\` made the statement
// unparseable. The old assertion held only because the check was matching the payload's own bytes
// as a substring — evidence and claim had come apart, and the test was pinning the gap open.
//
// The payload is now `';alert(C)//`, which closes the literal for real; the same engine reports
// `ReferenceError: C is not defined`, i.e. it evaluated the canary as an identifier in expression
// position. Reaching executable position is the claim, so that is what is asserted.
func TestUnescapedScriptContextIsStillABreakout(t *testing.T) {
	canary := "zxssraw07"
	payload := scriptBreakoutPayloadFor('\'', canary)
	body := "<script>var lastSearch = '" + payload + "';</script>"

	evidence := analyzeXSSReflection(body, canary, "text/html",
		xssHTMLBreakoutMarker(canary), xssScriptBreakoutMarker(canary))
	if evidence&XSSEvidenceScriptBreakout == 0 {
		t.Fatalf("an unescaped payload inside a single-quoted JavaScript string was not classified "+
			"as a script breakout (evidence %#x)", evidence)
	}
}

// The double-quoted host, which the single payload the check used to send could never reach:
// `';…//` sits inertly inside a double-quoted literal, so a fixed payload silently skipped every
// application using the other quote style.
func TestDoubleQuotedScriptHostIsABreakout(t *testing.T) {
	canary := "zxssraw08"
	payload := scriptBreakoutPayloadFor('"', canary)
	body := `<script>var lastSearch = "` + payload + `";</script>`

	evidence := analyzeXSSReflection(body, canary, "text/html",
		xssHTMLBreakoutMarker(canary), xssScriptBreakoutMarker(canary))
	if evidence&XSSEvidenceScriptBreakout == 0 {
		t.Fatalf("a double-quoted host was not classified as a script breakout (evidence %#x)", evidence)
	}
}

// The measured false positive this work exists to remove: a host that reflects through
// json.Marshal escapes the quote, so nothing breaks out, and must not be reported.
func TestJSONMarshalHostIsNotAScriptBreakout(t *testing.T) {
	canary := "zxssjson09"
	payload := scriptBreakoutPayloadFor('"', canary)
	// json.Marshal escapes the quote and the backslash; the canary never leaves the literal.
	escaped := strings.ReplaceAll(payload, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	body := `<script>var conf = "` + escaped + `";</script>`

	evidence := analyzeXSSReflection(body, canary, "text/html",
		xssHTMLBreakoutMarker(canary), xssScriptBreakoutMarker(canary))
	if evidence&XSSEvidenceScriptBreakout != 0 {
		t.Fatalf("a correctly-escaped json.Marshal host was reported as a script breakout "+
			"(evidence %#x); body: %s", evidence, body)
	}
	if evidence&XSSEvidenceReflected == 0 {
		t.Error("the reflection itself should still be recorded")
	}
}

// Markup that only appears inside a comment or inside RCDATA is inert: a browser creates no
// element from it. Claiming a tag breakout there is the same class of error as the JSON case.
func TestMarkerInInertContextIsNotAnHTMLBreakout(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"comment", "<!-- <svg id=%s onload=alert(1)> -->"},
		{"textarea", "<textarea><svg id=%s onload=alert(1)></textarea>"},
	} {
		canary := "zxssinert10"
		body := strings.ReplaceAll(tc.body, "%s", canary)
		evidence := analyzeXSSReflection(body, canary, "text/html",
			xssHTMLBreakoutMarker(canary), xssScriptBreakoutMarker(canary))
		if evidence&XSSEvidenceHTMLBreakout != 0 {
			t.Errorf("%s: inert markup was reported as an HTML breakout (evidence %#x)", tc.name, evidence)
		}
	}
}

// Reflected XSS is a claim about what a BROWSER does with the response. A payload echoed intact
// into text/plain or JSON is a reflection and nothing else, because nothing will parse it as markup.
//
// Without this gate every plain-text echo endpoint confirmed a breakout: the script marker is a
// substring of its own payload, so a verbatim reflection contains it. internal/vulnapp alone serves
// four such endpoints, and the runtime corpus could not see the false positives because it only
// asked whether the row fired against its own declared endpoint.
func TestAVerbatimReflectionIntoNonMarkupIsNotABreakout(t *testing.T) {
	canary := "zxssplain08"
	htmlMarker := xssHTMLBreakoutMarker(canary)
	scriptMarker := xssScriptBreakoutMarker(canary)

	for _, contentType := range []string{
		"text/plain",
		"text/plain; charset=utf-8",
		"application/json",
		"application/octet-stream",
	} {
		for _, payload := range []string{scriptBreakoutPayload(canary), htmlBreakoutPayload(canary)} {
			// Verbatim, unescaped — the worst case for the marker test.
			body := "PING " + payload + ": 64 bytes from 127.0.0.1"
			evidence := analyzeXSSReflection(body, canary, contentType, htmlMarker, scriptMarker)

			if xssBreakoutConfirmed(evidence) {
				t.Errorf("%s: a verbatim reflection of %q was classified as a breakout (evidence %#x). "+
					"No browser parses this type as markup, so nothing can execute.",
					contentType, payload, evidence)
			}
			if evidence&XSSEvidenceReflected == 0 {
				t.Errorf("%s: the reflection itself was not recorded; the observation must not be lost",
					contentType)
			}
		}
	}

	// A missing Content-Type still counts as markup: the browser sniffs, and sniffing HTML-ish bytes
	// is precisely the case an attacker relies on.
	body := `<div>` + htmlMarker + `</div>`
	if evidence := analyzeXSSReflection(body, canary, "", htmlMarker, scriptMarker); !xssBreakoutConfirmed(evidence) {
		t.Error("a response with no Content-Type was treated as non-markup; sniffing makes it markup")
	}
}
