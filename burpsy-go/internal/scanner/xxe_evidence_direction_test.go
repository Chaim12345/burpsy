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
