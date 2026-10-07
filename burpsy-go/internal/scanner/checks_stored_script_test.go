package scanner

// The stored XSS row must confirm a script breakout, not a substring.
//
// # The defect this pins
//
// The row used contextInsideTag("script"), which asked only whether the canary appeared between
// <script and </script. That is true of correctly-escaped output - `var q = "CANARY";` inside a
// script element - so the row reported stored XSS for output that cannot execute. It is also true
// of a canary in a comment, and false for nothing that matters: the test could not distinguish
// landing in a literal from landing in code, which is the whole question.
//
// The script body is JavaScript, so the decision belongs to the JS lexer. These tests assert the
// outcome a consumer sees: a finding for a real breakout, no finding for an escaped one.

import (
	"testing"
)

// A canary that reaches code position inside a <script> is a stored script breakout.
//
// The payload closes the string literal the application put it in and starts a new statement, so
// the canary is bare JavaScript rather than a value. That is the case the row exists to report.
func TestStoredScriptXSSConfirmsACanaryThatReachedCode(t *testing.T) {
	const canary = "c4n4ryT0k3n"
	// The application put the value inside a string literal; the payload closed that literal with
	// `";` and started a new statement, so the canary is bare JavaScript. This is the shape a
	// successful breakout leaves on the wire.
	body := `<html><body><script>var q = "` + `";alert(` + canary + `)//</script></body></html>`

	_, matched := contextScriptBreakout(body, canary)
	if !matched {
		t.Errorf("no finding for a canary sitting in code position inside a <script>; the payload "+
			"closed the string literal and became a statement, which is the stored XSS the row must "+
			"report. Body: %s", body)
	}
}

// A canary that stays inside a JavaScript string literal is correct output, not a breakout.
//
// This is the false positive the old substring test produced: the canary is present between the
// script tags, so contextInsideTag matched, and the row reported stored XSS against an application
// that escaped its output. The lexer refuses it because the literal never closed.
func TestStoredScriptXSSRefusesACanaryStillInsideAStringLiteral(t *testing.T) {
	const canary = "c4n4ryT0k3n"
	body := `<html><body><script>var q = "` + canary + `";</script></body></html>`

	_, matched := contextScriptBreakout(body, canary)
	if matched {
		t.Errorf("reported stored XSS for a canary that never left the string literal it was "+
			"placed in; the application escaped its output and a browser runs nothing. Body: %s", body)
	}
}

// A canary in a script element's own comment is not executable either.
//
// A third shape the substring test could not distinguish: the text is inside <script>, so the old
// matcher fired, but a comment is not code.
func TestStoredScriptXSSRefusesACanaryInAJavaScriptComment(t *testing.T) {
	const canary = "c4n4ryT0k3n"
	body := `<html><body><script>// ` + canary + `</script></body></html>`

	_, matched := contextScriptBreakout(body, canary)
	if matched {
		t.Errorf("reported stored XSS for a canary inside a JavaScript comment; a comment is not "+
			"executable code. Body: %s", body)
	}
}

// A canary reflected into the body with no script element at all is not this row's finding.
//
// The stored script row answers a script-context question. A plain text-node reflection is a
// different row's business, and reporting it here would double-count the same sighting.
func TestStoredScriptXSSRefusesABodyWithNoScriptElement(t *testing.T) {
	const canary = "c4n4ryT0k3n"
	body := `<html><body><p>` + canary + `</p></body></html>`

	_, matched := contextScriptBreakout(body, canary)
	if matched {
		t.Errorf("reported stored XSS for a canary in a plain text node with no <script> element; "+
			"this row decides script-context breakouts and the reflection is another row's finding. "+
			"Body: %s", body)
	}
}
