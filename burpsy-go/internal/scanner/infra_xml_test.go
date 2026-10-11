package scanner

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestXXEFilePayloadsReturnsThreeDistinctFileReadPayloads asserts the
// generator is not stubbed to a no-op: it must return exactly the three
// documented file-read variants (Unix passwd, Windows win.ini, Unix hostname,
// the php://filter base64 wrapper), each carrying XXEFileRead and a distinct
// Body/Marker, with the caller-supplied marker folded into the entity name.
func TestXXEFilePayloadsReturnsThreeDistinctFileReadPayloads(t *testing.T) {
	payloads := XXEFilePayloads("scan42")
	if len(payloads) != 4 {
		t.Fatalf("XXEFilePayloads returned %d payloads, want 4 (a caller relying on all four targets would silently lose coverage)", len(payloads))
	}

	seenBodies := map[string]bool{}
	seenMarkers := map[string]bool{}
	for _, p := range payloads {
		if p.Kind != XXEFileRead {
			t.Errorf("payload %q has Kind %d, want XXEFileRead — a caller filtering by Kind would miss or misclassify it", p.Name, p.Kind)
		}
		if seenBodies[p.Body] {
			t.Errorf("payload %q duplicates another payload's Body — two probes that produce the same request test nothing extra", p.Name)
		}
		seenBodies[p.Body] = true
		if seenMarkers[p.Marker] {
			t.Errorf("payload %q duplicates another payload's Marker %q", p.Name, p.Marker)
		}
		seenMarkers[p.Marker] = true
		if !strings.Contains(p.Body, "xxescan42") {
			t.Errorf("payload %q body does not contain the caller-supplied marker folded into the entity name (xxescan42): %s", p.Name, p.Body)
		}
	}

	wantMarkers := []string{
		"file:///etc/passwd",
		"file:///c:/windows/win.ini",
		"file:///etc/hostname",
		"php://filter/convert.base64-encode/resource=/etc/passwd",
	}
	for _, want := range wantMarkers {
		if !seenMarkers[want] {
			t.Errorf("no payload carries Marker %q — this exact target is documented as required and must not silently disappear", want)
		}
	}
}

// TestXXEOutOfBandPayloadsReturnsFourDistinctFormsWithTheHostNormalised
// asserts the four recovered OOB delivery channels are all present, exactly
// one of them is the parameter-entity form (the one that survives a filter
// blocking direct general-entity references), and a callbackURL passed with
// an "http://" scheme is not double-prefixed in the generated bodies.
func TestXXEOutOfBandPayloadsReturnsFourDistinctFormsWithTheHostNormalised(t *testing.T) {
	withScheme := XXEOutOfBandPayloads("http://collab.example.oastify.com")
	bare := XXEOutOfBandPayloads("collab.example.oastify.com")

	if len(withScheme) != 4 || len(bare) != 4 {
		t.Fatalf("XXEOutOfBandPayloads returned %d/%d payloads, want 4/4 (a caller relying on every OOB channel would silently lose coverage)", len(withScheme), len(bare))
	}

	paramEntityCount := 0
	seenBodies := map[string]bool{}
	for i, p := range withScheme {
		if strings.Contains(p.Body, "http://http://") {
			t.Errorf("payload %q double-prefixed the scheme: %s", p.Name, p.Body)
		}
		if p.Body != bare[i].Body {
			t.Errorf("passing callbackURL with vs without an http:// scheme produced different bodies for %q:\n  with scheme: %s\n  bare:        %s", p.Name, p.Body, bare[i].Body)
		}
		if seenBodies[p.Body] {
			t.Errorf("payload %q duplicates another payload's Body", p.Name)
		}
		seenBodies[p.Body] = true
		if p.Kind == XXEParameterEntity {
			paramEntityCount++
			if !strings.Contains(p.Body, "<!ENTITY % pxxe SYSTEM") {
				t.Errorf("parameter-entity payload does not contain the recovered <!ENTITY %% pxxe SYSTEM construction: %s", p.Body)
			}
		} else if p.Kind != XXEOOBHTTP {
			t.Errorf("payload %q has Kind %d, want XXEOOBHTTP or XXEParameterEntity", p.Name, p.Kind)
		}
	}
	if paramEntityCount != 1 {
		t.Errorf("got %d parameter-entity payloads, want exactly 1", paramEntityCount)
	}
}

// TestEntityExpansionPayloadsBillionLaughsFactorIsBoundedByTheNamedCap is
// the guard that this scanner never ships a real, unbounded billion-laughs
// DoS: it independently re-derives the nesting depth and expansion factor
// by counting entity declarations in the generated Body (not by trusting
// the source constants that built it), and separately asserts the named
// cap itself is a small, sane ceiling — so bumping xxeEntityExpansionLevels
// to something dangerous later cannot pass silently just because the cap
// was defined in terms of the same constant.
func TestEntityExpansionPayloadsBillionLaughsFactorIsBoundedByTheNamedCap(t *testing.T) {
	if MaxXMLEntityExpansionFactor > 1<<20 {
		t.Fatalf("MaxXMLEntityExpansionFactor is %d, which is no longer a safe test bound — an unbounded expansion payload is an attack, not a test", MaxXMLEntityExpansionFactor)
	}

	payloads := EntityExpansionPayloads()
	if len(payloads) != 2 {
		t.Fatalf("EntityExpansionPayloads returned %d payloads, want 2 (billion laughs and quadratic blowup)", len(payloads))
	}

	var laughs, quadratic *XXEPayload
	for i := range payloads {
		switch payloads[i].Kind {
		case XXEBillionLaughs:
			laughs = &payloads[i]
		case XXEQuadraticBlowup:
			quadratic = &payloads[i]
		}
	}
	if laughs == nil {
		t.Fatal("no payload with Kind XXEBillionLaughs — the exponential variant must not silently disappear")
	}
	if quadratic == nil {
		t.Fatal("no payload with Kind XXEQuadraticBlowup — the linear variant must not silently disappear")
	}
	if laughs.Body == quadratic.Body {
		t.Fatal("billion-laughs and quadratic-blowup payloads produced identical bodies")
	}

	declarations := strings.Count(laughs.Body, "<!ENTITY ")
	levels := declarations - 1 // one seed declaration plus `levels` doubling declarations
	factor := 1 << levels
	if factor != MaxXMLEntityExpansionFactor {
		t.Errorf("billion-laughs payload's re-derived expansion factor is %d (from %d <!ENTITY declarations), want exactly MaxXMLEntityExpansionFactor (%d)", factor, declarations, MaxXMLEntityExpansionFactor)
	}
	if factor > MaxXMLEntityExpansionFactor {
		t.Errorf("billion-laughs payload's re-derived expansion factor %d exceeds the named cap %d", factor, MaxXMLEntityExpansionFactor)
	}

	refs := strings.Count(quadratic.Body, "&xee;")
	if refs != MaxXMLEntityExpansionFactor {
		t.Errorf("quadratic-blowup payload references its entity %d times, want exactly MaxXMLEntityExpansionFactor (%d)", refs, MaxXMLEntityExpansionFactor)
	}
	if refs > MaxXMLEntityExpansionFactor {
		t.Errorf("quadratic-blowup payload's reference count %d exceeds the named cap %d", refs, MaxXMLEntityExpansionFactor)
	}
}

// TestXIncludePayloadEmbedsMarkerHostAndTheFixedFooSuffix asserts
// XIncludePayload reproduces burp.Zbiw's recovered fragment exactly,
// including the fixed "/foo" href suffix, rather than a paraphrase.
func TestXIncludePayloadEmbedsMarkerHostAndTheFixedFooSuffix(t *testing.T) {
	p := XIncludePayload("collab.example.oastify.com")
	if p.Kind != XXEXInclude {
		t.Errorf("XIncludePayload has Kind %d, want XXEXInclude", p.Kind)
	}
	want := `xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://collab.example.oastify.com/foo"/`
	if p.Body != want {
		t.Errorf("XIncludePayload.Body = %q, want %q", p.Body, want)
	}
	if p.Marker != "collab.example.oastify.com" {
		t.Errorf("XIncludePayload.Marker = %q, want the caller-supplied host", p.Marker)
	}
}

// TestXMLInjectionPayloadsReturnsFourDistinctStructuralProbes asserts the
// four documented structural-injection techniques (unclosed tag, sibling
// element, CDATA breakout, comment breakout) are all present, all carry
// XXEStructuralInjection, and none collapse to the same Body.
func TestXMLInjectionPayloadsReturnsFourDistinctStructuralProbes(t *testing.T) {
	payloads := XMLInjectionPayloads("CANARY123")
	if len(payloads) != 4 {
		t.Fatalf("XMLInjectionPayloads returned %d payloads, want 4", len(payloads))
	}

	wantBodies := map[string]bool{
		"<CANARY123":                      false,
		"<CANARY123>injected</CANARY123>": false,
		"]]>CANARY123<![CDATA[":           false,
		"-->CANARY123<!--":                false,
	}
	for _, p := range payloads {
		if p.Kind != XXEStructuralInjection {
			t.Errorf("payload %q has Kind %d, want XXEStructuralInjection", p.Name, p.Kind)
		}
		if _, ok := wantBodies[p.Body]; !ok {
			t.Errorf("unexpected payload body %q", p.Body)
			continue
		}
		wantBodies[p.Body] = true
	}
	for body, seen := range wantBodies {
		if !seen {
			t.Errorf("missing expected structural-injection payload body %q", body)
		}
	}
}

// TestDetectXXEEvidenceFindsPasswdFileContentSignature asserts the
// strongest evidence class — a resolved file's real content — is recognised
// when /etc/passwd's stock first line appears in a response.
func TestDetectXXEEvidenceFindsPasswdFileContentSignature(t *testing.T) {
	payload := XXEFilePayloads("")[0] // /etc/passwd
	body := "HTTP 200 OK\n\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

	ev := DetectXXEEvidence(body, payload)
	if ev&XXEEvidenceFileContentSignature == 0 {
		t.Fatalf("DetectXXEEvidence(%q, ...) = %d, missing XXEEvidenceFileContentSignature", body, ev)
	}
	if !strings.Contains(ev.Text(), "resolved") {
		t.Errorf("Text() = %q, want it to describe the file being resolved", ev.Text())
	}
}

// TestDetectXXEEvidenceFindsPhpFilterBase64Blob asserts the base64-blob
// heuristic fires for the php://filter variant specifically, given a
// response that is (once trimmed) nothing but a plausible base64 encoding
// of /etc/passwd's content.
func TestDetectXXEEvidenceFindsPhpFilterBase64Blob(t *testing.T) {
	payload := XXEFilePayloads("")[3] // php://filter variant
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("root:x:0:0:", 6)))
	body := "  \n" + encoded + "\n  "

	ev := DetectXXEEvidence(body, payload)
	if ev&XXEEvidenceFileContentSignature == 0 {
		t.Fatalf("DetectXXEEvidence did not recognise a base64 blob for the php://filter payload; ev=%d", ev)
	}
}

// TestDetectXXEEvidenceFindsLibxml2EntityError asserts a real libxml2/PHP
// DOMDocument error naming the rejected entity is recognised.
func TestDetectXXEEvidenceFindsLibxml2EntityError(t *testing.T) {
	payload := XXEOutOfBandPayloads("collab.example.oastify.com")[0]
	body := `Warning: DOMDocument::loadXML(): Entity 'xxe' not defined in Entity, line: 1 in /var/www/app/parse.php on line 42`

	ev := DetectXXEEvidence(body, payload)
	if ev&XXEEvidenceParserEntityError == 0 {
		t.Fatalf("DetectXXEEvidence(%q, ...) = %d, missing XXEEvidenceParserEntityError", body, ev)
	}
}

// TestDetectXXEEvidenceFindsExpansionLimitError asserts a real Xerces/JDK
// entity-expansion-limit error is recognised for a billion-laughs payload.
func TestDetectXXEEvidenceFindsExpansionLimitError(t *testing.T) {
	payload := EntityExpansionPayloads()[0]
	body := `org.xml.sax.SAXParseException: JAXP00010001: The parser has encountered more than "64000" entity expansions in this document; this is the limit imposed by the JDK.`

	ev := DetectXXEEvidence(body, payload)
	if ev&XXEEvidenceExpansionLimitHit == 0 {
		t.Fatalf("DetectXXEEvidence(%q, ...) = %d, missing XXEEvidenceExpansionLimitHit", body, ev)
	}
}

// TestDetectXXEEvidenceReturnsZeroForAnUnrelatedBody asserts the no-signal
// case: a body that shares nothing with the payload must classify as
// XXEEvidenceNone, and its Text() must say so explicitly rather than let a
// caller mistake the zero value for a clean bill of health.
func TestDetectXXEEvidenceReturnsZeroForAnUnrelatedBody(t *testing.T) {
	payload := XXEFilePayloads("")[0]
	body := "Hello, this is just a normal web page with a login form and nothing else on it."

	ev := DetectXXEEvidence(body, payload)
	if ev != XXEEvidenceNone {
		t.Fatalf("DetectXXEEvidence(%q, ...) = %d, want XXEEvidenceNone", body, ev)
	}
	if !strings.Contains(ev.Text(), "no XXE") {
		t.Errorf("Text() = %q, want it to explicitly say no signal was found", ev.Text())
	}
}

// TestWellFormedAcceptsCompleteXMLAndRejectsTruncatedXMLWithAReason asserts
// the safe well-formedness check: a complete document decodes cleanly, and
// a truncated one (missing its closing tag) fails with a non-empty reason
// rather than silently reporting ok.
func TestWellFormedAcceptsCompleteXMLAndRejectsTruncatedXMLWithAReason(t *testing.T) {
	ok, reason := WellFormed([]byte(`<root><child>text</child></root>`))
	if !ok {
		t.Fatalf("WellFormed rejected a complete document: %q", reason)
	}
	if reason != "" {
		t.Errorf("WellFormed returned ok=true but a non-empty reason %q", reason)
	}

	ok2, reason2 := WellFormed([]byte(`<root><child>text</child>`))
	if ok2 {
		t.Fatal("WellFormed accepted a truncated document missing its closing </root> tag")
	}
	if reason2 == "" {
		t.Error("WellFormed reported ok=false for a truncated document but gave no reason")
	}
}

// TestWellFormedReportsFalseForAnXXEPayloadBecauseGoNeverResolvesTheEntity
// pins the file-level design constraint down as an executable test: Go's
// encoding/xml has no notion of the "xxe" entity our own file-read payload
// declares, so WellFormed must report ok=false here — this is a property of
// Go's decoder, not evidence about how a real target's parser would treat
// the same bytes (see WellFormed's doc comment).
func TestWellFormedReportsFalseForAnXXEPayloadBecauseGoNeverResolvesTheEntity(t *testing.T) {
	payload := XXEFilePayloads("")[0]
	ok, reason := WellFormed([]byte(payload.Body))
	if ok {
		t.Fatalf("WellFormed accepted an XXE payload referencing an undeclared-to-Go entity; body: %s", payload.Body)
	}
	if reason == "" {
		t.Error("WellFormed reported ok=false for the XXE payload but gave no reason")
	}
}
