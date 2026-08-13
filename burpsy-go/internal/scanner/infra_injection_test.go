package scanner

import (
	"strings"
	"testing"
	"time"
)

// ---------- recovered payload banks ----------

func TestRecoveredOSCommandPayloadsCarryTheMarker(t *testing.T) {
	got := OSCommandPayloads("MARK1")
	if len(got) != 6 {
		t.Fatalf("got %d payloads, want the 6 recovered from burp.Zx8l", len(got))
	}
	for _, p := range got {
		if !strings.Contains(p, "MARK1") {
			t.Errorf("payload %q lost its marker", p)
		}
		if strings.Contains(p, InjectionMarkerPlaceholder) {
			t.Errorf("payload %q still carries the %%%% placeholder", p)
		}
	}
	// The single-quote form carries the recovered marker fragment as a suffix.
	var sawFragment bool
	for _, p := range got {
		if strings.Contains(p, OSCommandMarkerFragment) {
			sawFragment = true
		}
	}
	if !sawFragment {
		t.Errorf("no payload carried the recovered %q fragment", OSCommandMarkerFragment)
	}
}

func TestTimeDelaySubstitutesSecondsIntoRecoveredTemplates(t *testing.T) {
	payloads := TimeDelayPayloads()
	if len(payloads) != 4 {
		t.Fatalf("got %d time-delay payloads, want 4 (3 from Zxpy, 1 from Zuyg)", len(payloads))
	}
	for _, p := range payloads {
		got := RenderTimeDelay(p, 10)
		if strings.Contains(got, InjectionMarkerPlaceholder) {
			t.Errorf("%s payload %q kept its placeholder", p.Dialect, got)
		}
		if !strings.Contains(got, "10") {
			t.Errorf("%s payload %q lost the delay", p.Dialect, got)
		}
	}
}

func TestLDAPPayloadsWrapTheOriginalValue(t *testing.T) {
	got := LDAPPayloads("admin")
	if len(got) != 3 {
		t.Fatalf("got %d LDAP payloads, want the 3 recovered from burp.Zsna", len(got))
	}
	if got[0] != "objectClass=*" {
		t.Errorf("first payload = %q, want the recovered always-true filter", got[0])
	}
	if got[1] != "admin)(objectClass=*" {
		t.Errorf("filter breakout = %q", got[1])
	}
	if got[2] != "!(admin)" {
		t.Errorf("negation = %q", got[2])
	}
}

func TestArithmeticProofUsesTheRecoveredOperands(t *testing.T) {
	if ArithmeticProofProduct() != "42" {
		t.Fatalf("product = %q, want 42 from burp.Zxvv's 7*6", ArithmeticProofProduct())
	}
	for _, p := range PHPCodeInjectionPayloads() {
		if !strings.Contains(p, "7*6") {
			t.Errorf("payload %q does not carry the recovered arithmetic", p)
		}
	}
}

// The three-context loop is the structure burp.Zwvr / Zwug / Zwuj describe.
func TestCodeInjectionCoversAllThreeQuotingContexts(t *testing.T) {
	if len(AllQuotingContexts) != 3 {
		t.Fatalf("got %d contexts, want 3", len(AllQuotingContexts))
	}
	seen := map[string]bool{}
	for _, ctx := range AllQuotingContexts {
		seen[CodeInjectionPayloadsForContext("X", ctx)] = true
	}
	for _, want := range []string{"X", "'X'", `"X"`} {
		if !seen[want] {
			t.Errorf("no payload rendered for context form %q", want)
		}
	}
}

func TestQuotingContextLabelsMatchRecoveredPhrasing(t *testing.T) {
	if ContextUnquoted.Label() != "an unquoted" ||
		ContextSingleQuoted.Label() != "a single-quoted" ||
		ContextDoubleQuoted.Label() != "a double-quoted" {
		t.Error("context labels drifted from the phrasing recovered in burp.Zwvr")
	}
}

func TestTemplateOOBPayloadsTakeACollaboratorHost(t *testing.T) {
	for _, p := range TemplateOOBPayloads() {
		got := RenderTemplateOOB(p, "abc.oast.test")
		if !strings.Contains(got, "abc.oast.test") {
			t.Errorf("%s payload did not take the collaborator host: %q", p.Engine, got)
		}
		if strings.Contains(got, "%s") {
			t.Errorf("%s payload kept its verb: %q", p.Engine, got)
		}
	}
}

func TestSSIPayloadsAndOutOfBandFormAreRecovered(t *testing.T) {
	if len(SSIPayloads("DOCUMENT_NAME")) != 4 {
		t.Error("expected four SSI payload forms")
	}
	oob := SSIOutOfBandPayload("x.oast.test")
	if !strings.Contains(oob, `nslookup -q=cname `) || !strings.Contains(oob, "x.oast.test") {
		t.Errorf("SSI out-of-band payload = %q", oob)
	}
}

func TestErrorBanksAreDisjointFromPayloadFragments(t *testing.T) {
	// burp.Ze2s mixes signatures and payload fragments; splitting them wrong would make
	// the scanner search responses for its own SQL syntax.
	frag := map[string]bool{}
	for _, f := range SQLPayloadFragments {
		frag[f] = true
	}
	for _, s := range SQLErrorSignatures {
		if frag[s] {
			t.Errorf("%q is banked as both an error signature and a payload fragment", s)
		}
	}
	if len(SQLErrorSignatures) < 40 {
		t.Errorf("only %d SQL signatures banked; burp.Ze2s carried more", len(SQLErrorSignatures))
	}
	if len(XPathErrorSignatures) != 7 {
		t.Errorf("got %d XPath signatures, want the 7 recovered from burp.Ze2s", len(XPathErrorSignatures))
	}
}

// ---------- differential evidence ----------

// The property the whole file exists for: an error the baseline already produced is not
// evidence, and must not read as clean either.
func TestPreexistingErrorIsInconclusiveNotAFinding(t *testing.T) {
	base := "warning: You have an error in your SQL syntax near line 1"
	inj := "warning: You have an error in your SQL syntax near line 1"

	got := ClassifySQLError(base, inj)
	if got.Evidence != InjectionEvidenceInconclusive {
		t.Fatalf("Evidence = %v, want InjectionEvidenceInconclusive", got.Evidence)
	}
	if len(got.Matched) != 0 {
		t.Errorf("counted %v as newly introduced", got.Matched)
	}
	if len(got.Preexisting) == 0 {
		t.Error("the pre-existing signature was discarded instead of reported")
	}
	if got.Evidence.Confirms() {
		t.Error("inconclusive evidence reported as confirming")
	}
}

func TestNewErrorSignatureIsAFinding(t *testing.T) {
	got := ClassifySQLError("all good", "ORA-00933: SQL command not properly ended")
	if got.Evidence != InjectionEvidenceErrorSignature {
		t.Fatalf("Evidence = %v, want InjectionEvidenceErrorSignature", got.Evidence)
	}
	if !got.Evidence.Confirms() {
		t.Error("a newly introduced error signature does not confirm")
	}
}

func TestCleanResponsePairYieldsNoEvidence(t *testing.T) {
	got := ClassifySQLError("hello world", "hello world")
	if got.Evidence != InjectionEvidenceNone {
		t.Fatalf("Evidence = %v, want InjectionEvidenceNone", got.Evidence)
	}
}

func TestXPathErrorUsesItsOwnBank(t *testing.T) {
	got := ClassifyXPathError("ok", "javax.xml.xpath.XPathExpressionException: bad expr")
	if got.Evidence != InjectionEvidenceErrorSignature {
		t.Fatalf("Evidence = %v, want an XPath error signature match", got.Evidence)
	}
	if got := ClassifyXPathError("ok", "ORA-00933"); got.Evidence != InjectionEvidenceNone {
		t.Error("a SQL error matched the XPath bank")
	}
}

// The echo guard only bites when the payload text itself carries the expected value, which
// is the OS command case: `;echo MARK1;` contains MARK1, so a response that merely reflects
// the payload contains it without any command having run. An arithmetic payload cannot
// exercise this — `".(7*6)."` never contains "42" — so testing it there proves nothing.
func TestReflectedPayloadCarryingItsOwnMarkerIsNotEvaluation(t *testing.T) {
	payload := ";echo MARK1;"
	reflected := "searched for " + payload + " and found nothing"

	got := ClassifyMarkerEcho("searched for nothing", reflected, payload, "MARK1")
	if got == InjectionEvidenceEvaluated {
		t.Fatal("a verbatim reflection of the payload was reported as command execution")
	}
	if got != InjectionEvidenceInconclusive {
		t.Fatalf("got %v, want InjectionEvidenceInconclusive: the marker appeared but only inside an echo of the payload", got)
	}
}

// The same marker appearing *outside* any reflection of the payload is real execution.
func TestMarkerWithoutPayloadReflectionIsEvaluation(t *testing.T) {
	if got := ClassifyMarkerEcho("pinging", "pinging\nMARK1\n", ";echo MARK1;", "MARK1"); got != InjectionEvidenceEvaluated {
		t.Fatalf("got %v, want InjectionEvidenceEvaluated", got)
	}
}

func TestEvaluatedArithmeticIsAFinding(t *testing.T) {
	if got := ClassifyArithmeticProof("you searched for nothing", "you searched for 42", `".(7*6)."`); got != InjectionEvidenceEvaluated {
		t.Fatalf("got %v, want InjectionEvidenceEvaluated", got)
	}
}

func TestProductAlreadyInBaselineIsInconclusive(t *testing.T) {
	if got := ClassifyArithmeticProof("answer is 42", "answer is 42", `".(7*6)."`); got != InjectionEvidenceInconclusive {
		t.Fatalf("got %v, want InjectionEvidenceInconclusive", got)
	}
}

func TestMarkerEchoConfirmsCommandExecution(t *testing.T) {
	payload := ";echo MARK1;"
	if got := ClassifyMarkerEcho("pinging host", "pinging host MARK1", payload, "MARK1"); got != InjectionEvidenceEvaluated {
		t.Fatalf("got %v, want InjectionEvidenceEvaluated", got)
	}
}

func TestBooleanDifferentialNeedsBothHalves(t *testing.T) {
	base := NewResponseFingerprint(200, "welcome admin")
	same := NewResponseFingerprint(200, "welcome admin")
	diff := NewResponseFingerprint(200, "no such user")

	if got := ClassifyBooleanDifferential(base, same, diff); got != InjectionEvidenceBooleanDifferential {
		t.Fatalf("true==base, false!=base gave %v, want a boolean differential", got)
	}
	// Both differ: the payloads were rejected, not interpreted.
	if got := ClassifyBooleanDifferential(base, diff, diff); got != InjectionEvidenceInconclusive {
		t.Errorf("both-differ gave %v, want InjectionEvidenceInconclusive", got)
	}
	// Neither differs: the injection did not take.
	if got := ClassifyBooleanDifferential(base, same, same); got != InjectionEvidenceNone {
		t.Errorf("neither-differ gave %v, want InjectionEvidenceNone", got)
	}
}

func TestFingerprintIgnoresIncidentalWhitespace(t *testing.T) {
	a := NewResponseFingerprint(200, "welcome   admin\n")
	b := NewResponseFingerprint(200, "welcome admin")
	if !a.SameShape(b) {
		t.Error("whitespace-only difference registered as a behavioural change")
	}
}

func TestFingerprintTreatsStatusChangeAsDifferent(t *testing.T) {
	a := NewResponseFingerprint(200, "same")
	b := NewResponseFingerprint(500, "same")
	if a.SameShape(b) {
		t.Error("a status change did not register")
	}
}

// A slow endpoint must not read as injectable.
func TestSlowBaselineMakesTimingInconclusive(t *testing.T) {
	got := ClassifyTimingEvidence(6*time.Second, 12*time.Second, 10*time.Second)
	if got != InjectionEvidenceInconclusive {
		t.Fatalf("got %v, want InjectionEvidenceInconclusive for a baseline over half the delay", got)
	}
}

func TestObservedDelayAboveMarginIsAFinding(t *testing.T) {
	got := ClassifyTimingEvidence(100*time.Millisecond, 10*time.Second, 10*time.Second)
	if got != InjectionEvidenceTiming {
		t.Fatalf("got %v, want InjectionEvidenceTiming", got)
	}
}

func TestDelayBelowMarginIsNotAFinding(t *testing.T) {
	got := ClassifyTimingEvidence(100*time.Millisecond, 2*time.Second, 10*time.Second)
	if got != InjectionEvidenceNone {
		t.Fatalf("got %v, want InjectionEvidenceNone", got)
	}
}

func TestZeroDelayRequestIsInconclusive(t *testing.T) {
	if got := ClassifyTimingEvidence(0, time.Second, 0); got != InjectionEvidenceInconclusive {
		t.Fatalf("got %v, want InjectionEvidenceInconclusive", got)
	}
}

func TestTraversalReadNeedsFileContentNotAbsenceOfError(t *testing.T) {
	got := ClassifyTraversalRead("Not found", "root:x:0:0:root:/root:/bin/bash")
	if got.Evidence != InjectionEvidenceErrorSignature {
		t.Fatalf("Evidence = %v, want a content-signature match", got.Evidence)
	}
	if got := ClassifyTraversalRead("Not found", "Not found"); got.Evidence != InjectionEvidenceNone {
		t.Error("an unchanged response reported a successful read")
	}
}

func TestBestEvidencePrefersStrongerProofAndNeverHidesInconclusive(t *testing.T) {
	probes := []InjectionProbe{
		{Payload: "a", Evidence: InjectionEvidenceNone},
		{Payload: "b", Evidence: InjectionEvidenceErrorSignature},
		{Payload: "c", Evidence: InjectionEvidenceEvaluated},
	}
	best, confirmed := BestEvidence(probes)
	if !confirmed || best.Payload != "c" {
		t.Fatalf("best = %+v confirmed=%v, want the evaluated probe", best, confirmed)
	}

	// Nothing confirmed, but something was unmeasurable: must not look clean.
	best, confirmed = BestEvidence([]InjectionProbe{
		{Payload: "a", Evidence: InjectionEvidenceNone},
		{Payload: "b", Evidence: InjectionEvidenceInconclusive},
	})
	if confirmed {
		t.Error("an inconclusive-only set reported as confirmed")
	}
	if best.Evidence != InjectionEvidenceInconclusive {
		t.Errorf("best = %v, want the inconclusive probe surfaced over the empty one", best.Evidence)
	}
}

func TestBestEvidenceOnAnEmptySetReportsNothing(t *testing.T) {
	if _, confirmed := BestEvidence(nil); confirmed {
		t.Error("an empty probe set reported a confirmation")
	}
}

// The false positive a runtime scan of internal/vulnapp exposed.
//
// An OS-command payload is `&echo <marker>&`. An application that reflects input *correctly*
// HTML-escapes it, so the response carries `&amp;echo <marker>&amp;`. The marker is present, no
// command ran, and the old guard — a verbatim search for the payload — did not recognise the
// echo. Two endpoints of the demo target were reported as OS command injection at `certain`
// confidence purely for escaping their output properly.
func TestAnEscapedEchoOfThePayloadIsNotEvidenceOfEvaluation(t *testing.T) {
	const marker = "bsycmd42"
	payload := "&echo " + marker + "&"

	for _, tc := range []struct {
		name string
		body string
	}{
		{"html-escaped reflection", `Login attempted for user: &amp;echo ` + marker + `&amp;`},
		{"minimally escaped reflection", `<a href="/?x=&amp;echo ` + marker + `&amp;">Found</a>`},
		{"percent-encoded reflection", `redirecting to %26echo+` + marker + `%26`},
		{"verbatim reflection", `you searched for &echo ` + marker + `&`},
		// net/http's Redirect body writes `"` as `&#34;`, not `&quot;`. Enumerating encoder
		// styles missed this and reported http.Redirect as executing commands.
		{"numeric-entity reflection (net/http style)", `<a href="&#34;&echo ` + marker + `&amp;">Found</a>.`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyEvaluation("baseline with nothing interesting", tc.body, payload, marker)
			if got == InjectionEvidenceEvaluated {
				t.Errorf("an echo of the payload was read as command evaluation. "+
					"Body was %q; the marker is present only because the application reflected the "+
					"payload, and reflecting input is not executing it.", tc.body)
			}
			if got != InjectionEvidenceInconclusive {
				t.Errorf("evidence = %v, want Inconclusive: the marker is present but unattributable, "+
					"which is neither a finding nor a clean result", got)
			}
		})
	}
}

// The other side of the same guard: a marker that arrives on its own really is evaluation, and
// over-subtracting the echo must not suppress it.
func TestAMarkerThatArrivesWithoutThePayloadIsStillEvaluation(t *testing.T) {
	const marker = "bsycmd42"
	payload := "&echo " + marker + "&"

	// What a shell actually produces: the marker alone, with no trace of the command text.
	body := "PING 127.0.0.1: " + marker + "\n64 bytes from 127.0.0.1"
	if got := ClassifyEvaluation("PING 127.0.0.1: 64 bytes from 127.0.0.1", body, payload, marker); got != InjectionEvidenceEvaluated {
		t.Fatalf("evidence = %v, want Evaluated: the marker appears with none of the payload's own "+
			"text around it, which is the shell having run the command", got)
	}

	// And the mixed case: the payload is echoed *and* the command ran, so the marker appears
	// twice. Subtracting the echo must leave the produced one behind.
	mixed := "echoed &amp;echo " + marker + "&amp; then output: " + marker
	if got := ClassifyEvaluation("nothing", mixed, payload, marker); got != InjectionEvidenceEvaluated {
		t.Errorf("evidence = %v, want Evaluated: one occurrence is the echo, the other is not, "+
			"and stripping the echo must not consume both", got)
	}
}

// The false NEGATIVE mirror of the escaped-echo case, taken from ZAP's own regression test
// (CommandInjectionScanRuleUnitTest.shouldRaiseAlertIfResponseHasEscapedHtmlControlPattern).
//
// An application that reads /etc/passwd and echoes it into a page escapes it on the way out, so
// the proof arrives as `root&#x3a;x&#x3a;0&#x3a;0&#x3a;`. The vulnerability is identical to the
// unescaped case; only the presentation differs. Matching the raw bytes alone meant the targets
// that encode their output properly were exactly the targets this scanner failed to find a
// traversal read in.
func TestFileContentSignaturesSurviveHTMLEntityEncoding(t *testing.T) {
	const baseline = "<!DOCTYPE html><html><body>Nothing to see here.</body></html>"

	// ZAP's fixture verbatim: every colon and slash as a hex entity.
	escaped := "<!DOCTYPE html>\n<html><body>" +
		"root&#x3a;x&#x3a;0&#x3a;0&#x3a;root&#x3a;&#x2f;root&#x3a;&#x2f;bin&#x2f;bash<br>" +
		"daemon&#x3a;x&#x3a;1&#x3a;1&#x3a;daemon&#x3a;&#x2f;usr&#x2f;sbin&#x3a;&#x2f;usr&#x2f;sbin&#x2f;nologin<br>" +
		"</body></html>"

	got := ClassifyTraversalRead(baseline, escaped)
	if got.Evidence != InjectionEvidenceErrorSignature {
		t.Fatalf("evidence = %v, want ErrorSignature: the response carries /etc/passwd content as "+
			"HTML entities, which is what an application that escapes its output produces. A raw "+
			"substring search misses it and the read goes unreported.", got.Evidence)
	}
	if len(got.Matched) == 0 {
		t.Error("no signature was named, so a finding could not say what proved the read")
	}

	// Decimal entities are equally common.
	decimal := "<html><body>root&#58;x&#58;0&#58;0&#58;root</body></html>"
	if got := ClassifyTraversalRead(baseline, decimal); got.Evidence != InjectionEvidenceErrorSignature {
		t.Errorf("decimal-entity encoding was missed: evidence = %v", got.Evidence)
	}

	// And the guard still holds: content already in the baseline proves nothing, in either form.
	if got := ClassifyTraversalRead(escaped, escaped); got.Evidence != InjectionEvidenceInconclusive {
		t.Errorf("evidence = %v, want Inconclusive when the baseline already carried the escaped "+
			"signature; unescaping must not defeat the baseline comparison", got.Evidence)
	}
}

// A SQL error echoed into a page is escaped the same way, so the same normalisation has to reach
// the error banks and not just the file-content ones.
func TestSQLErrorSignaturesSurviveHTMLEntityEncoding(t *testing.T) {
	const baseline = "<html><body>Products: Widget</body></html>"
	// The quote in the error message is what gets encoded.
	escaped := "<html><body>SQL syntax error: you have an error in your sql syntax near &#39;x&#39; at line 1</body></html>"

	got := ClassifySQLError(baseline, escaped)
	if got.Evidence != InjectionEvidenceErrorSignature {
		t.Fatalf("evidence = %v, want ErrorSignature: a database error rendered into an HTML page "+
			"is still a database error", got.Evidence)
	}
}
