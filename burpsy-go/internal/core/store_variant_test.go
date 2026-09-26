package core

import "testing"

// Burp's three readings of a message, held only where they differ (burpsy-react-ui-c05, under epic
// mrjw).
//
// The storage rule is that a stage is written only where it differs from the stage after it, so
// reading a variant back is a walk backwards from the bytes that travelled. These tests pin that
// walk at its four inputs, because the walk is what a viewer's tab labels depend on and every way of
// getting it wrong produces a *plausible* answer rather than a crash: a read that falls through in
// the wrong order shows the client's bytes under an "auto-modified" label, and nothing downstream
// can tell that apart from a rule that genuinely made no change.

func ptrMsg(id MsgId) *MsgId { return &id }

// fixed returns an exchange whose message ids are known constants, so a failing assertion says which
// id it wanted rather than printing two opaque addresses.
func fixedExchange() *Exchange {
	return &Exchange{
		Request:  MsgPtr(MsgId(10)),
		Response: ptrMsg(MsgId(20)),
	}
}

// Nothing modified: all three readings are the bytes that travelled, and the row retained nothing.
// This is the ordinary case for proxied traffic and the one the memory cost of the feature depends
// on, so it is asserted rather than assumed.
func TestAnUnmodifiedMessageReadsTheSameThreeWays(t *testing.T) {
	ex := fixedExchange()
	for _, variant := range []Variant{VariantOriginal, VariantAutoModified, VariantEdited} {
		if got, ok := ex.VariantFor(DirectionRequest, variant); !ok || got != MsgId(10) {
			t.Errorf("VariantFor(request, %s) = (%d, %v), want (10, true); an unmodified message has one set of bytes", variant, got, ok)
		}
		if got, ok := ex.VariantFor(DirectionResponse, variant); !ok || got != MsgId(20) {
			t.Errorf("VariantFor(response, %s) = (%d, %v), want (20, true)", variant, got, ok)
		}
	}
	if ex.HasRetainedStage(DirectionRequest) || ex.HasRetainedStage(DirectionResponse) {
		t.Error("an exchange with no retained stage reported one; nothing differed, so nothing may have been kept")
	}
}

// An automatic rule changed the message and nothing else did: the original is the earlier copy, and
// both the auto-modified and the edited readings are the bytes that travelled.
func TestAnAutoModifiedOnlyMessageReadsItsOriginalFromTheEarlierCopy(t *testing.T) {
	ex := fixedExchange()
	ex.RequestOriginal = ptrMsg(MsgId(11))

	if got, _ := ex.VariantFor(DirectionRequest, VariantOriginal); got != MsgId(11) {
		t.Errorf("original = %d, want 11 — the copy taken before the rules ran", got)
	}
	if got, _ := ex.VariantFor(DirectionRequest, VariantAutoModified); got != MsgId(10) {
		t.Errorf("auto-modified = %d, want 10 — with no manual edit the rules' output is what travelled", got)
	}
	if got, _ := ex.VariantFor(DirectionRequest, VariantEdited); got != MsgId(10) {
		t.Errorf("edited = %d, want 10", got)
	}
	if !ex.HasRetainedStage(DirectionRequest) {
		t.Error("HasRetainedStage = false for an exchange holding an earlier copy of its request")
	}
}

// The operator edited the message by hand and no rule fired. Stage 0 and stage 1 are the same bytes,
// so only stage 1 is stored — and *both* earlier readings must resolve to it. A walk that read stage
// 0's field directly would return the edited bytes here and label them "original", which is exactly
// the failure this test exists to catch.
func TestAManuallyEditedOnlyMessageReportsItsPreEditBytesAsTheOriginal(t *testing.T) {
	ex := fixedExchange()
	ex.RequestAuto = ptrMsg(MsgId(12))

	if got, _ := ex.VariantFor(DirectionRequest, VariantOriginal); got != MsgId(12) {
		t.Errorf("original = %d, want 12 — the bytes the client sent are the ones the post-rule stage holds", got)
	}
	if got, _ := ex.VariantFor(DirectionRequest, VariantAutoModified); got != MsgId(12) {
		t.Errorf("auto-modified = %d, want 12 — no rule fired, so the pre-edit bytes are the auto-modified reading too", got)
	}
	if got, _ := ex.VariantFor(DirectionRequest, VariantEdited); got != MsgId(10) {
		t.Errorf("edited = %d, want 10 — the edit is what travelled", got)
	}
}

// Changed both ways: three distinct sets of bytes, one per reading, in order.
func TestAMessageChangedTwiceKeepsThreeDistinctReadings(t *testing.T) {
	ex := fixedExchange()
	ex.RequestOriginal = ptrMsg(MsgId(11))
	ex.RequestAuto = ptrMsg(MsgId(12))

	for _, tc := range []struct {
		variant Variant
		want    MsgId
	}{
		{VariantOriginal, 11},
		{VariantAutoModified, 12},
		{VariantEdited, 10},
	} {
		if got, _ := ex.VariantFor(DirectionRequest, tc.variant); got != tc.want {
			t.Errorf("VariantFor(request, %s) = %d, want %d", tc.variant, got, tc.want)
		}
	}
}

// An exchange with no response yet has no response readings at all — not "three readings of nothing".
// ok=false is the answer that lets the caller decline to offer a comparison; returning the zero id
// with ok=true would make a viewer fetch message 0, which is a real message belonging to something
// else.
func TestAnExchangeWithNoResponseHasNoResponseReadings(t *testing.T) {
	ex := &Exchange{Request: MsgPtr(MsgId(10))}
	for _, variant := range []Variant{VariantOriginal, VariantAutoModified, VariantEdited} {
		if id, ok := ex.VariantFor(DirectionResponse, variant); ok {
			t.Errorf("VariantFor(response, %s) = (%d, true), want ok=false for an exchange with no response", variant, id)
		}
	}
	if ex.HasRetainedStage(DirectionResponse) {
		t.Error("HasRetainedStage(response) = true for an exchange with no response")
	}
}

// The response's own readings walk the same way, which is asserted separately rather than inferred
// from the request's: the request and response are two independent chains of stored ids, and a
// reader that shared one branch between them would look right on a test where only the request was
// changed.
func TestTheResponsesReadingsWalkIndependentlyOfTheRequests(t *testing.T) {
	ex := fixedExchange()
	ex.ResponseOriginal = ptrMsg(MsgId(21))
	ex.ResponseAuto = ptrMsg(MsgId(22))
	// The request is untouched, and must stay that way — a response-only edit is the ordinary shape
	// of a Match & Replace response rule.
	if ex.HasRetainedStage(DirectionRequest) {
		t.Error("the request reported a retained stage; only its response was changed")
	}
	for _, tc := range []struct {
		variant Variant
		want    MsgId
	}{
		{VariantOriginal, 21},
		{VariantAutoModified, 22},
		{VariantEdited, 20},
	} {
		if got, _ := ex.VariantFor(DirectionResponse, tc.variant); got != tc.want {
			t.Errorf("VariantFor(response, %s) = %d, want %d", tc.variant, got, tc.want)
		}
	}
}

// A nil exchange is a legal input on every path that resolves a variant — an exchange id that no
// longer resolves, a row deleted while a viewer holds it — and must answer "no reading" rather than
// panicking. Refuse-by-default on unreadable input is the project's rule elsewhere; this is the same
// rule applied to a missing row.
func TestANilExchangeAnswersNoReadingRatherThanPanicking(t *testing.T) {
	var ex *Exchange
	if _, ok := ex.VariantFor(DirectionRequest, VariantOriginal); ok {
		t.Error("a nil exchange answered a reading")
	}
	if ex.HasRetainedStage(DirectionRequest) {
		t.Error("a nil exchange reported a retained stage")
	}
}

// The wire tokens round-trip, and an unknown one is refused rather than silently defaulted. A query
// asking for a reading this build does not have must be an error, because answering it with the
// edited bytes is how a comparison shows the operator one message twice.
func TestVariantTokensRoundTripAndRefuseTheUnknown(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Variant
	}{
		{"", VariantEdited},
		{"edited", VariantEdited},
		{"original", VariantOriginal},
		{"auto-modified", VariantAutoModified},
		{"automodified", VariantAutoModified},
	} {
		got, ok := ParseVariant(tc.in)
		if !ok || got != tc.want {
			t.Errorf("ParseVariant(%q) = (%v, %v), want (%v, true)", tc.in, got, ok, tc.want)
		}
		if back, ok := ParseVariant(tc.want.String()); !ok || back != tc.want {
			t.Errorf("ParseVariant(%q) = (%v, %v), want a round trip back to %v", tc.want.String(), back, ok, tc.want)
		}
	}
	if _, ok := ParseVariant("untouched"); ok {
		t.Error("an unknown reading was accepted; a caller asking for a view that does not exist must be told so")
	}
}
