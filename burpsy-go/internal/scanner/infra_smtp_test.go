package scanner

import (
	"strings"
	"testing"
)

// TestMailHeaderPayloadsBuildsAllNineDistinctSeparatorEncodingCombinations asserts
// the probe matrix is exactly 3 separators x 3 encodings, each producing a payload
// string distinct from every other — a caller relying on this set to actually probe
// all nine combinations would silently lose coverage if any two collapsed to the
// same request.
func TestMailHeaderPayloadsBuildsAllNineDistinctSeparatorEncodingCombinations(t *testing.T) {
	payloads := MailHeaderPayloads("canary123")
	if len(payloads) != 9 {
		t.Fatalf("got %d payloads, want 9 (3 separators x 3 encodings)", len(payloads))
	}

	seps := map[string]bool{}
	encs := map[string]bool{}
	seen := map[string]bool{}
	for _, p := range payloads {
		seps[p.Separator] = true
		encs[p.Encoding] = true
		if seen[p.Payload] {
			t.Errorf("payload %q was generated more than once; the probe matrix must not collapse combinations", p.Payload)
		}
		seen[p.Payload] = true
		if !strings.Contains(p.Payload, "canary123") {
			t.Errorf("payload %q does not carry the caller's canary", p.Payload)
		}
		if !strings.Contains(p.Payload, p.InjectedHeader) {
			t.Errorf("payload %q does not contain its own reported InjectedHeader %q", p.Payload, p.InjectedHeader)
		}
	}

	wantSeps := []string{"\r\n", "\n", "\r"}
	for _, s := range wantSeps {
		if !seps[s] {
			t.Errorf("separator %q missing from the matrix", s)
		}
	}
	if len(seps) != 3 {
		t.Errorf("got %d distinct separators, want 3", len(seps))
	}

	wantEncs := []string{mailEncodingRaw, mailEncodingPercent, mailEncodingPercentDoubled}
	for _, e := range wantEncs {
		if !encs[e] {
			t.Errorf("encoding %q missing from the matrix", e)
		}
	}
	if len(encs) != 3 {
		t.Errorf("got %d distinct encodings, want 3", len(encs))
	}
}

// TestMailHeaderPayloadsRawEncodingLeavesTheSeparatorUntouched asserts that the
// "raw" encoding really does submit the bare CR/LF-family separator, since that is
// the whole point of the raw variant (testing whether an app even needs the value
// URL-decoded before a header split happens).
func TestMailHeaderPayloadsRawEncodingLeavesTheSeparatorUntouched(t *testing.T) {
	payloads := MailHeaderPayloads("canary123")
	for _, p := range payloads {
		if p.Encoding != mailEncodingRaw {
			continue
		}
		if !strings.Contains(p.Payload, p.Separator) {
			t.Errorf("raw payload %q does not contain the literal separator %q", p.Payload, p.Separator)
		}
	}
}

// TestClassifyMailHeaderResponseRecognisesAJavaMailExceptionAsTheMailLayerSignal
// asserts that a jakarta/javax.mail MessagingException surfacing only in the probe
// response (never the baseline) is classified as the strong mail-layer signal — the
// one class of evidence in this primitive that means the separator actually reached
// mail-composition code, not just an HTTP-layer echo.
func TestClassifyMailHeaderResponseRecognisesAJavaMailExceptionAsTheMailLayerSignal(t *testing.T) {
	baseline := "<html><body>Message sent</body></html>"
	probe := "<html><body>Error: javax.mail.MessagingException: Illegal address</body></html>"

	got := ClassifyMailHeaderResponse(baseline, probe, 200, 500)
	if got&MailInjectionMailLibraryError == 0 {
		t.Fatalf("Text()=%q evidence=%d, want MailInjectionMailLibraryError set", got.Text(), got)
	}
}

// TestClassifyMailHeaderResponseTreatsVerbatimReflectionAsNotInjected asserts that
// when the entire payload — including its raw separator glued directly to the
// "Bcc: " header text — comes back unchanged in the response, that is classified
// as reflected-not-injected, not as evidence of a real header split. A caller
// treating verbatim reflection as a positive would produce a false positive on
// every app that just echoes form input back as inert text.
func TestClassifyMailHeaderResponseTreatsVerbatimReflectionAsNotInjected(t *testing.T) {
	baseline := "<p>You entered: </p>"
	probe := "<p>You entered: canary123\r\nBcc: canary123@example.invalid</p>"

	got := ClassifyMailHeaderResponse(baseline, probe, 200, 200)
	if got != MailInjectionReflectedVerbatim {
		t.Fatalf("got evidence %d (%s), want exactly MailInjectionReflectedVerbatim", got, got.Text())
	}
}

// TestClassifyMailHeaderResponseFindsNoEvidenceWhenProbeMatchesBaseline asserts the
// no-signal case: an identical status and body between baseline and probe must
// classify as MailInjectionNone, and its Text() must state the file-level limit —
// that this is "no signal observed", never "no injection exists" — so a caller
// cannot misread the zero value as a clean bill of health.
func TestClassifyMailHeaderResponseFindsNoEvidenceWhenProbeMatchesBaseline(t *testing.T) {
	body := "<html><body>OK</body></html>"

	got := ClassifyMailHeaderResponse(body, body, 200, 200)
	if got != MailInjectionNone {
		t.Fatalf("got evidence %d (%s), want MailInjectionNone", got, got.Text())
	}
	// The wording must report an absence of observed signal and must explicitly refuse to
	// claim injection is ruled out — this evaluator only sees the HTTP exchange, never the
	// mail layer, so "clean" here is not a clean bill of health.
	if !strings.Contains(got.Text(), "signal") || !strings.Contains(got.Text(), "does not rule out") {
		t.Errorf("Text()=%q must report no observed signal AND disclaim ruling injection out", got.Text())
	}
}

// TestClassifyMailHeaderResponseRecognisesAStrippedSeparatorAsDefended asserts that
// when the injected header text lands in the response but its separator does not
// (the app sanitised the CR/LF before echoing), that is a distinct classification
// from both verbatim reflection and a real mail-layer error.
func TestClassifyMailHeaderResponseRecognisesAStrippedSeparatorAsDefended(t *testing.T) {
	baseline := "<p>You entered: </p>"
	// The separator between the canary and "Bcc: " has been removed/collapsed by
	// the app's own sanitisation, unlike the verbatim-reflection case above.
	probe := "<p>You entered: canary123Bcc: canary123@example.invalid</p>"

	got := ClassifyMailHeaderResponse(baseline, probe, 200, 200)
	if got != MailInjectionSeparatorStripped {
		t.Fatalf("got evidence %d (%s), want exactly MailInjectionSeparatorStripped", got, got.Text())
	}
}

// TestClassifyMailHeaderResponseTreatsUnexplainedDivergenceAsWeakEvidence asserts
// that a status/body change with neither a mail-library error nor any trace of the
// injected header text is still recorded as evidence, but the weak class only — the
// file-level doc comment explicitly warns callers not to over-read this signal.
func TestClassifyMailHeaderResponseTreatsUnexplainedDivergenceAsWeakEvidence(t *testing.T) {
	baseline := "<html><body>OK</body></html>"
	probe := "<html><body>Internal Server Error</body></html>"

	got := ClassifyMailHeaderResponse(baseline, probe, 200, 500)
	if got != MailInjectionStatusOrBodyDivergence {
		t.Fatalf("got evidence %d (%s), want exactly MailInjectionStatusOrBodyDivergence", got, got.Text())
	}
}
