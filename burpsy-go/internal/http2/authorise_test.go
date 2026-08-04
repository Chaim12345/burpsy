package http2

import (
	"strings"
	"testing"
)

// headerBlockFor encodes a minimal request header block with the pseudo-headers a peer needs, using this
// package's own encoder — which never sets the Huffman flag, so the block decodes here exactly as a peer
// would decode it.
func headerBlockFor(t *testing.T, authority, path string) []byte {
	t.Helper()
	enc := NewEncoder(4096)
	return enc.Encode([]HeaderField{
		NewHeaderField(":method", "GET"),
		NewHeaderField(":scheme", "https"),
		NewHeaderField(":authority", authority),
		NewHeaderField(":path", path),
	})
}

// authorisableProgram is the shape a research payload takes when it is decidable: a settings frame and one
// complete header block.
func authorisableProgram(t *testing.T, authority, path string) H2FrameProgram {
	t.Helper()
	return NewH2FrameProgram(
		NewFrameSpec(TypeSettings, 0, 0, nil),
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, headerBlockFor(t, authority, path)),
	)
}

// refusalOf asserts the program is refused for exactly one named construct and returns it.
func refusalOf(t *testing.T, program H2FrameProgram, want RefusalKind) Refusal {
	t.Helper()
	got := Authorise(program)
	if got.Verdict != VerdictUndecidable {
		t.Fatalf("want a refusal, got %s", got.Explain())
	}
	if len(got.Refusals) == 0 {
		t.Fatal("an undecidable verdict with no refusal names nothing")
	}
	for _, r := range got.Refusals {
		if r.Kind == want {
			if r.String() == "" || !strings.Contains(r.String(), r.Kind.Why()) {
				t.Fatalf("the refusal does not say why: %q", r.String())
			}
			return r
		}
	}
	t.Fatalf("want %d named, got %s", int(want), got.Explain())
	return Refusal{}
}

func TestACleanlyDecodableProgramIsAuthorisablePerRequest(t *testing.T) {
	got := Authorise(authorisableProgram(t, "shop.test", "/basket"))
	if got.Verdict != VerdictAuthorisable {
		t.Fatalf("want authorisable, got %s", got.Explain())
	}
	if len(got.Requests) != 1 {
		t.Fatalf("want one addressed request, got %d", len(got.Requests))
	}
	req := got.Requests[0]
	if req.Method != "GET" || req.Authority != "shop.test" || req.Path != "/basket" || req.Scheme != "https" {
		t.Fatalf("the addressed request was read wrong: %+v", req)
	}
	if req.Frame != 1 || req.Stream != 1 {
		t.Fatalf("want the request placed at frame 1 on stream 1, got frame %d stream %d", req.Frame, req.Stream)
	}
	if len(got.Refusals) != 0 {
		t.Fatalf("an authorisable program must carry no refusals, got %s", got.Explain())
	}
}

// A program can break every framing rule in malformed.go and still be authorisable, provided the peer
// decodes the same header block we did. This is the case the classifier exists to *allow*.
func TestADeliberatelyIllegalButDecidableProgramIsStillAuthorisable(t *testing.T) {
	block := headerBlockFor(t, "shop.test", "/admin")
	program := H2FrameProgram{
		// No preface: Audit reports it, and it changes nothing about where these octets go.
		Preface: false,
		Frames: []FrameSpec{
			// An even client-initiated stream id with the reserved bit set, and END_HEADERS present.
			NewFrameSpec(TypeHeaders, FlagEndHeaders, 2, block).Malformed(SetReservedBit()),
			// A PING on a stream, which is a connection-level frame naming a stream.
			NewFrameSpec(TypePing, 0, 9, make([]byte, 8)),
		},
		ReadForMS: 100,
	}
	if got := Authorise(program); got.Verdict != VerdictAuthorisable {
		t.Fatalf("deliberate malformation must not be confused with undecidability: %s", got.Explain())
	}
	if len(Audit(program)) == 0 {
		t.Fatal("this program is supposed to break rules; Audit found none")
	}
}

func TestAProgramAddressingNoRequestIsHostLevelOnly(t *testing.T) {
	got := Authorise(NewH2FrameProgram(
		NewFrameSpec(TypeSettings, 0, 0, nil),
		NewFrameSpec(TypePing, 0, 0, make([]byte, 8)),
	))
	if got.Verdict != VerdictConnectionOnly {
		t.Fatalf("want a host-level verdict, got %s", got.Explain())
	}
	if len(got.Requests) != 0 {
		t.Fatalf("a connection-only program addresses nothing, got %+v", got.Requests)
	}
}

func TestADishonestLengthIsRefusedByName(t *testing.T) {
	block := headerBlockFor(t, "shop.test", "/basket")
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, block).Malformed(DeclareLength(uint32(len(block) - 3))),
	)
	r := refusalOf(t, program, RefusalDishonestLength)
	if r.Declared != uint32(len(block)-3) || r.Actual != len(block) {
		t.Fatalf("the refusal must name both numbers, got %+v", r)
	}
	if !strings.Contains(r.String(), "frames by the declared length") {
		t.Fatalf("the refusal must say why it is undecidable: %q", r.String())
	}
}

func TestAPayloadTooLongForTheLengthFieldIsRefusedByName(t *testing.T) {
	// One octet past what 24 bits can describe. Built with make rather than a literal so the test does not
	// carry 16 MB of source.
	program := NewH2FrameProgram(
		NewFrameSpec(TypeData, 0, 1, make([]byte, int(MaxFramePayload)+1)),
	)
	refusalOf(t, program, RefusalPayloadExceedsLengthField)
}

func TestAnUnterminatedHeaderBlockIsRefusedByName(t *testing.T) {
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, 0, 1, headerBlockFor(t, "shop.test", "/basket")),
	)
	r := refusalOf(t, program, RefusalUnterminatedHeaderBlock)
	if r.BlockOpenedAt != 0 || r.Stream != 1 {
		t.Fatalf("want the open block placed, got %+v", r)
	}
}

func TestAFrameInterleavedInAHeaderBlockIsRefusedByName(t *testing.T) {
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, 0, 1, headerBlockFor(t, "shop.test", "/basket")),
		NewFrameSpec(TypePing, 0, 0, make([]byte, 8)),
		NewFrameSpec(TypeContinuation, FlagEndHeaders, 1, nil),
	)
	r := refusalOf(t, program, RefusalFrameInterleavedInHeaderBlock)
	if r.Frame != 1 || r.BlockOpenedAt != 0 {
		t.Fatalf("want the interleaved frame and the block it broke, got %+v", r)
	}
}

func TestAContinuationWithNothingToContinueIsRefusedByName(t *testing.T) {
	program := NewH2FrameProgram(
		NewFrameSpec(TypeContinuation, FlagEndHeaders, 1, headerBlockFor(t, "shop.test", "/basket")),
	)
	refusalOf(t, program, RefusalContinuationWithNothingToContinue)
}

func TestAContinuationOnAnotherStreamIsRefusedByName(t *testing.T) {
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, 0, 1, headerBlockFor(t, "shop.test", "/basket")),
		NewFrameSpec(TypeContinuation, FlagEndHeaders, 3, nil),
	)
	r := refusalOf(t, program, RefusalContinuationOnAnotherStream)
	if r.Expected != 1 || r.Found != 3 {
		t.Fatalf("want both streams named, got %+v", r)
	}
}

func TestPaddingThatRunsPastThePayloadIsRefusedByName(t *testing.T) {
	block := headerBlockFor(t, "shop.test", "/basket")
	// The first octet is the pad length, and 255 cannot fit in what follows.
	payload := append([]byte{255}, block...)
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagPadded, 1, payload),
	)
	refusalOf(t, program, RefusalPaddingRunsPastPayload)
}

func TestPaddingThatFitsIsStrippedAndTheRequestIsStillFound(t *testing.T) {
	block := headerBlockFor(t, "shop.test", "/basket")
	payload := append(append([]byte{4}, block...), 0, 0, 0, 0)
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagPadded, 1, payload),
	)
	got := Authorise(program)
	if got.Verdict != VerdictAuthorisable {
		t.Fatalf("honest padding is decidable: %s", got.Explain())
	}
	if got.Requests[0].Path != "/basket" {
		t.Fatalf("the block was mis-cut: %+v", got.Requests[0])
	}
}

func TestAPriorityPrefixIsStrippedAndTheRequestIsStillFound(t *testing.T) {
	block := headerBlockFor(t, "shop.test", "/basket")
	payload := append([]byte{0, 0, 0, 0, 16}, block...)
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagPriority, 1, payload),
	)
	got := Authorise(program)
	if got.Verdict != VerdictAuthorisable {
		t.Fatalf("a PRIORITY prefix is decidable: %s", got.Explain())
	}
	if got.Requests[0].Path != "/basket" {
		t.Fatalf("the block was mis-cut: %+v", got.Requests[0])
	}
}

// A raw hand-written header-block fragment is authorisable exactly when it decodes. This is the "raw
// fragment" construct: the operative question is never how the bytes were produced.
func TestARawFragmentThatDoesNotDecodeIsRefusedByName(t *testing.T) {
	// 0x80 is an indexed header field naming index 0, which RFC 7541 §6.1 reserves.
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, []byte{0x80}),
	)
	r := refusalOf(t, program, RefusalHeaderBlockDoesNotDecode)
	if !strings.Contains(r.Detail, "index 0") {
		t.Fatalf("the refusal must carry the decode fault, got %q", r.Detail)
	}
}

func TestAHuffmanCodedFragmentIsRefusedByNameRatherThanGuessed(t *testing.T) {
	// A literal with an incremental index and a Huffman-coded name: the seam hpack.go documents.
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, []byte{0x40, 0x82, 0x00, 0x00}),
	)
	r := refusalOf(t, program, RefusalHeaderBlockDoesNotDecode)
	if !strings.Contains(r.Detail, "Huffman") {
		t.Fatalf("want the Huffman seam named, got %q", r.Detail)
	}
}

func TestABlockWithNoPathIsRefusedByName(t *testing.T) {
	enc := NewEncoder(4096)
	block := enc.Encode([]HeaderField{
		NewHeaderField(":method", "GET"),
		NewHeaderField(":authority", "shop.test"),
	})
	program := NewH2FrameProgram(NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, block))
	refusalOf(t, program, RefusalNoPathPseudoHeader)
}

func TestADuplicatePseudoHeaderIsRefusedByName(t *testing.T) {
	enc := NewEncoder(4096)
	block := enc.Encode([]HeaderField{
		NewHeaderField(":method", "GET"),
		NewHeaderField(":path", "/allowed"),
		NewHeaderField(":path", "/secret"),
	})
	program := NewH2FrameProgram(NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, block))
	r := refusalOf(t, program, RefusalDuplicatePseudoHeader)
	if r.Detail != ":path" {
		t.Fatalf("want the duplicated field named, got %q", r.Detail)
	}
}

// The one that would be a hole rather than a gap: core.Scope reads the second token of a request line, so
// a path with a space in it would be authorised up to the space and sent whole.
func TestAPathThatWouldSplitTheAuthorisationLineIsRefusedByName(t *testing.T) {
	enc := NewEncoder(4096)
	block := enc.Encode([]HeaderField{
		NewHeaderField(":method", "GET"),
		NewHeaderField(":authority", "shop.test"),
		NewHeaderField(":path", "/allowed /secret"),
	})
	program := NewH2FrameProgram(NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, block))
	r := refusalOf(t, program, RefusalUnauthorisablePseudoHeader)
	if !strings.Contains(r.Detail, ":path") || !strings.Contains(r.Detail, "space") {
		t.Fatalf("want the field and the octet named, got %q", r.Detail)
	}
}

func TestAnAuthorityWithALineFeedIsRefusedByName(t *testing.T) {
	enc := NewEncoder(4096)
	block := enc.Encode([]HeaderField{
		NewHeaderField(":method", "GET"),
		NewHeaderField(":authority", "shop.test\nHost: evil.test"),
		NewHeaderField(":path", "/allowed"),
	})
	program := NewH2FrameProgram(NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, block))
	r := refusalOf(t, program, RefusalUnauthorisablePseudoHeader)
	if !strings.Contains(r.Detail, ":authority") {
		t.Fatalf("want the field named, got %q", r.Detail)
	}
}

// A PUSH_PROMISE from a client is illegal, and the path it promises is still a path this program puts on
// the wire — so it is authorised, not ignored.
func TestAPushPromiseBlockIsAddressedTooRatherThanIgnored(t *testing.T) {
	block := headerBlockFor(t, "shop.test", "/pushed")
	payload := append([]byte{0, 0, 0, 2}, block...)
	program := NewH2FrameProgram(
		NewFrameSpec(TypePushPromise, FlagEndHeaders, 1, payload),
	)
	got := Authorise(program)
	if got.Verdict != VerdictAuthorisable {
		t.Fatalf("want authorisable, got %s", got.Explain())
	}
	if len(got.Requests) != 1 || got.Requests[0].Path != "/pushed" {
		t.Fatalf("the promised request must be addressed, got %+v", got.Requests)
	}
}

// Two blocks on one connection share one dynamic table, so the second must decode against what the first
// inserted — the same way the peer will.
func TestASecondBlockDecodesAgainstTheFirstsDynamicTable(t *testing.T) {
	enc := NewEncoder(4096)
	first := enc.Encode([]HeaderField{
		NewHeaderField(":method", "GET"),
		NewHeaderField(":authority", "shop.test"),
		NewHeaderField(":path", "/one"),
		NewHeaderField("x-probe", "value"),
	})
	// The same field again: the encoder now references its dynamic entry rather than spelling it out, which
	// only decodes if the decoder carries the first block's insertions.
	second := enc.Encode([]HeaderField{
		NewHeaderField(":method", "GET"),
		NewHeaderField(":authority", "shop.test"),
		NewHeaderField(":path", "/two"),
		NewHeaderField("x-probe", "value"),
	})
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, first),
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 3, second),
	)
	got := Authorise(program)
	if got.Verdict != VerdictAuthorisable {
		t.Fatalf("want authorisable, got %s", got.Explain())
	}
	if len(got.Requests) != 2 {
		t.Fatalf("want both requests, got %+v", got.Requests)
	}
	if got.Requests[0].Path != "/one" || got.Requests[1].Path != "/two" {
		t.Fatalf("blocks decoded in the wrong order or against the wrong table: %+v", got.Requests)
	}
}

// A block split across CONTINUATIONs is one block to the peer, so it must be one block here.
func TestAContinuedBlockIsDecodedAsOne(t *testing.T) {
	block := headerBlockFor(t, "shop.test", "/basket")
	split := len(block) / 2
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, 0, 1, block[:split]),
		NewFrameSpec(TypeContinuation, FlagEndHeaders, 1, block[split:]),
	)
	got := Authorise(program)
	if got.Verdict != VerdictAuthorisable {
		t.Fatalf("want authorisable, got %s", got.Explain())
	}
	if got.Requests[0].Path != "/basket" {
		t.Fatalf("the fragments were not joined: %+v", got.Requests[0])
	}
}

func TestEveryRefusalKindExplainsItselfAndIsDistinct(t *testing.T) {
	seen := map[string]RefusalKind{}
	for _, k := range RefusalKindAll {
		why := k.Why()
		if why == "" || strings.Contains(why, "unrecognised") {
			t.Fatalf("refusal %d does not say why", int(k))
		}
		if other, dup := seen[why]; dup {
			t.Fatalf("refusals %d and %d share an explanation", int(other), int(k))
		}
		seen[why] = k
		if s := (Refusal{Kind: k}).String(); s == "" || strings.Contains(s, "cannot name") {
			t.Fatalf("refusal %d does not render", int(k))
		}
	}
	if len(seen) != len(RefusalKindAll) {
		t.Fatalf("%d kinds produced %d explanations", len(RefusalKindAll), len(seen))
	}
	for _, v := range []ProgramVerdict{VerdictAuthorisable, VerdictConnectionOnly, VerdictUndecidable} {
		if s := v.String(); s == "" || strings.Contains(s, "unrecognised") {
			t.Fatalf("verdict %d does not render", int(v))
		}
	}
}

func TestExplainNamesEveryConstructItFound(t *testing.T) {
	block := headerBlockFor(t, "shop.test", "/basket")
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, block).Malformed(DeclareLength(1)),
		NewFrameSpec(TypeData, 0, 1, make([]byte, int(MaxFramePayload)+1)),
	)
	got := Authorise(program)
	if len(got.Refusals) != 2 {
		t.Fatalf("want both constructs named, got %s", got.Explain())
	}
	text := got.Explain()
	if !strings.Contains(text, "not authorisable") {
		t.Fatalf("the verdict must lead: %q", text)
	}
	if strings.Count(text, "\n  - ") != 2 {
		t.Fatalf("want one line per construct: %q", text)
	}
}

// A declared length above 24 bits whose low bits land on the payload's own length is decidable: the peer
// reads exactly the octets written. Audit still reports the overflow; this classifier has no reason to
// refuse it, and refusing would be the over-strict direction.
func TestALengthOverflowThatLandsOnThePayloadIsStillAuthorisable(t *testing.T) {
	block := headerBlockFor(t, "shop.test", "/basket")
	program := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, block).
			Malformed(DeclareLength(MaxFramePayload + 1 + uint32(len(block)))),
	)
	got := Authorise(program)
	if got.Verdict != VerdictAuthorisable {
		t.Fatalf("the peer reads exactly what was written, so this is decidable: %s", got.Explain())
	}
	found := false
	for _, v := range Audit(program) {
		if v.Kind == ViolationLengthFieldOverflowed {
			found = true
		}
	}
	if !found {
		t.Fatal("Audit must still report the overflow it is there to report")
	}
}

// The mirror case: an honest declaration that both sides agree on, of a payload too big for the field. Nobody
// lied and it is still undecidable, because the field carries the truncated value.
func TestAnHonestLengthTooBigForTheFieldIsRefused(t *testing.T) {
	payload := make([]byte, int(MaxFramePayload)+2)
	program := NewH2FrameProgram(
		NewFrameSpec(TypeData, 0, 1, payload).Malformed(DeclareLength(uint32(len(payload)))),
	)
	r := refusalOf(t, program, RefusalDishonestLength)
	if uint64(r.Declared) == uint64(len(payload)) {
		t.Fatalf("Declared must be what the peer acts on, not what was asked for: %+v", r)
	}
}
