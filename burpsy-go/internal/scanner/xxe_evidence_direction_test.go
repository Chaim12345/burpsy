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

// The XXE differential's discriminator: the external answer must carry content the internal-entity
// control does not. Measured on OWASP VulnerableApp, a target that REFUSES external entities answers
// the external document with the entity expanded to the EMPTY string, so its answer differs from the
// control's marker substitution while no file was read. "The bodies differ" is therefore true for
// both a read and a refusal, and only longer-and-absent-the-marker content is evidence of a read.
func TestXXEInjectedExternallyRequiresContentTheControlDoesNotProduce(t *testing.T) {
	const marker = "bsyxxeint"
	control := `{"content":{"name":"` + marker + `","isbn":"1"}}`

	read := `{"content":{"name":"a99db73497a9\n","isbn":"1"}}`
	if !xxeInjectedExternally(read, control, marker) {
		t.Error("a file's content (longer than the control, without the marker) was not accepted as evidence")
	}
	refused := `{"content":{"name":"","isbn":"1"}}`
	if xxeInjectedExternally(refused, control, marker) {
		t.Error("a refused entity (expanded to the empty string) was accepted as evidence — the false " +
			"positive that fired on the SECURE levels: the bodies differ, but nothing was read")
	}
	if xxeInjectedExternally(control, control, marker) {
		t.Error("an answer identical to the control was accepted as evidence")
	}
}
