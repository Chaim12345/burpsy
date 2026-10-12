package scanner

import "testing"

// The XXE evidence bitmask mixes two DIRECTIONS: most classes say the entity was resolved or reached
// real resolution code, and XXEEvidenceReflectedVerbatim says the opposite — the payload came back as
// inert text, so the entity was NOT resolved. A caller that tests `!= XXEEvidenceNone` therefore
// fires on the negative signal, which is what the check did: the four SECURE OWASP VulnerableApp
// levels were reported as "the external entity was resolved". Positive() is the predicate a finding
// may rest on, and this pins both its halves.
func TestXXEEvidencePositiveExcludesTheReflectedVerbatimSignal(t *testing.T) {
	if XXEEvidence(XXEEvidenceReflectedVerbatim).Positive() {
		t.Fatal("reflected-verbatim evidence reported as Positive(); it means the payload was inert " +
			"text, i.e. the entity was NOT resolved — firing on it is a false positive on exactly the " +
			"targets that refuse the entity")
	}
	for _, ev := range []XXEEvidence{
		XXEEvidenceFileContentSignature,
		XXEEvidenceParserEntityError,
		XXEEvidenceExpansionLimitHit,
	} {
		if !ev.Positive() {
			t.Errorf("evidence %d (a resolution/parse signal) is not Positive()", ev)
		}
	}
	if XXEEvidenceNone.Positive() {
		t.Error("the zero evidence value is Positive()")
	}
	if !(XXEEvidenceFileContentSignature | XXEEvidenceReflectedVerbatim).Positive() {
		t.Error("a mask carrying both a positive and the negative signal is not Positive(); the " +
			"negative bit must not cancel a real resolution signal")
	}
}

// The XXE differential's discriminator: the external answer must be the internal-entity control's
// answer with the marker replaced by a non-empty value, and nothing else changed. Measured on OWASP
// VulnerableApp, a target that REFUSES external entities answers the external document with the
// entity expanded to the EMPTY string, so "the bodies differ" is true both of a read and of a refusal.
func TestXXEExternalSubstitutionRequiresTheControlsShapeWithAValue(t *testing.T) {
	const uri = "file:///etc/hostname"
	ok200 := func(body string) ProbeResponse { return ProbeResponse{Status: 200, Body: body} }
	control := ok200(`{"content":{"name":"` + xxeControlMarker + `","isbn":"1"}}`)

	if v, ok := xxeExternalSubstitution(ok200(`{"content":{"name":"a99db73497a9","isbn":"1"}}`), control,
		xxeEntityName, uri, xxeControlMarker); !ok || v != "a99db73497a9" {
		t.Errorf("a file's content in the control's place was not accepted (value %q, ok %v)", v, ok)
	}
	if _, ok := xxeExternalSubstitution(ok200(`{"content":{"name":"","isbn":"1"}}`), control,
		xxeEntityName, uri, xxeControlMarker); ok {
		t.Error("a refused entity (expanded to the empty string) was accepted as evidence")
	}
	if _, ok := xxeExternalSubstitution(control, control, xxeEntityName, uri, xxeControlMarker); ok {
		t.Error("an answer identical to the control was accepted as evidence")
	}

	// An application that echoes the whole document: the declaration differs between the two answers
	// for a reason that has nothing to do with resolution, and is normalised out.
	echo := func(decl, value string) string {
		return "parsed:\n<!DOCTYPE order [" + decl + " ]><order><item>" + value + "</item></order>\n"
	}
	ctlEcho := ok200(echo(`<!ENTITY `+xxeEntityName+` "`+xxeControlMarker+`">`, xxeControlMarker))
	extEcho := ok200(echo(`<!ENTITY `+xxeEntityName+` SYSTEM "`+uri+`">`, "vm\n"))
	if v, ok := xxeExternalSubstitution(extEcho, ctlEcho, xxeEntityName, uri, xxeControlMarker); !ok || v != "vm\n" {
		t.Errorf("an echoing parser that resolved the entity was not accepted (value %q, ok %v)", v, ok)
	}
}

// TestXXEASafeParsersErrorPageIsNotARead is the negative control for the fallback's worst false
// positive: a parser that refuses the external entity with a 500 and a stack trace. The error page is
// longer than the control's answer and does not carry the control's marker, which is exactly what the
// earlier "longer and marker-free" rule accepted as a read.
func TestXXEASafeParsersErrorPageIsNotARead(t *testing.T) {
	control := ProbeResponse{Status: 200, Body: `<order><item>` + xxeControlMarker + `</item></order>`}
	trace := ProbeResponse{Status: 500, Body: "org.xml.sax.SAXParseException: External Entity: Failed to read " +
		"external document, because 'file' access is not allowed due to restriction set by the " +
		"accessExternalDTD property.\n\tat com.sun.org.apache.xerces.internal.util.ErrorHandlerWrapper" +
		".createSAXParseException(ErrorHandlerWrapper.java:204)\n\tat ..."}
	if _, ok := xxeExternalSubstitution(trace, control, xxeEntityName, "file:///etc/hostname", xxeControlMarker); ok {
		t.Fatal("a safe parser's 500 stack trace was accepted as evidence that the file was read")
	}
	// Same body under a 200: still not the control's shape, still not a read.
	trace.Status = 200
	if _, ok := xxeExternalSubstitution(trace, control, xxeEntityName, "file:///etc/hostname", xxeControlMarker); ok {
		t.Fatal("an error message that does not share the control's shape was accepted as a read")
	}
}
