package scanner

import "strings"

import "testing"

func TestJavaXSSEvidenceRecognizesHTMLBreakout(t *testing.T) {
	canary := "zxsscafe01"
	htmlMarker := xssHTMLBreakoutMarker(canary)
	scriptMarker := xssScriptBreakoutMarker(canary)
	body := `<div class="result">value=` + htmlMarker + `</div>`

	evidence := analyzeXSSReflection(body, canary, htmlMarker, scriptMarker)
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

	evidence := analyzeXSSReflection(body, canary, htmlMarker, scriptMarker)
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

	evidence := analyzeXSSReflection(body, canary, htmlMarker, scriptMarker)
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

	if evidence := analyzeXSSReflection(body, canary, htmlMarker, scriptMarker); evidence != 0 {
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
		evidence := analyzeXSSReflection(body, canary, htmlMarker, scriptMarker)

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
// tightening the marker must not have cost that.
func TestUnescapedScriptContextIsStillABreakout(t *testing.T) {
	canary := "zxssraw07"
	payload := scriptBreakoutPayload(canary)
	body := "<script>var lastSearch = '" + payload + "';</script>"

	evidence := analyzeXSSReflection(body, canary,
		xssHTMLBreakoutMarker(canary), xssScriptBreakoutMarker(canary))
	if evidence&XSSEvidenceScriptBreakout == 0 {
		t.Fatalf("an unescaped payload inside a single-quoted JavaScript string was not classified "+
			"as a script breakout (evidence %#x)", evidence)
	}
}
