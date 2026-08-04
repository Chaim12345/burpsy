package http2

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// Ported one-for-one from crates/http2/src/malformed.rs's `mod tests`. Rust test names are kept as
// the Go name in CamelCase so a reader can diff the two suites without a mapping table.

// compliantProgram breaks nothing this module checks: preface, a settings exchange, one request.
func compliantProgram() H2FrameProgram {
	return NewH2FrameProgram(
		NewFrameSpec(TypeSettings, 0, 0, nil),
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, []byte("block")),
	)
}

// wantNoViolations fails unless the audit is empty, printing every violation it did find so a
// failure names the rule rather than only the count.
func wantNoViolations(t *testing.T, p H2FrameProgram, what string) {
	t.Helper()
	if found := Audit(p); len(found) != 0 {
		t.Fatalf("%s: expected a clean audit, got %s", what, showViolations(found))
	}
}

// wantViolation fails unless the audit contains want exactly.
func wantViolation(t *testing.T, p H2FrameProgram, want Violation, what string) {
	t.Helper()
	found := Audit(p)
	if !slices.Contains(found, want) {
		t.Fatalf("%s: expected %+v, got %s", what, want, showViolations(found))
	}
}

// wantExactViolations fails unless the audit is exactly want, in order.
func wantExactViolations(t *testing.T, p H2FrameProgram, want []Violation, what string) {
	t.Helper()
	found := Audit(p)
	if !slices.Equal(found, want) {
		t.Fatalf("%s: audit = %s, want %s", what, showViolations(found), showViolations(want))
	}
}

func showViolations(in []Violation) string {
	if len(in) == 0 {
		return "(nothing)"
	}
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = v.RFC() + ": " + v.String()
	}
	return "[" + strings.Join(parts, " | ") + "]"
}

func TestACompliantProgramReportsNothing(t *testing.T) {
	wantNoViolations(t, compliantProgram(), "a compliant program")
}

func TestEveryMalformationReachesTheWireExactlyAsAskedFor(t *testing.T) {
	// The load-bearing property of the whole layer: what the caller asked for is what is written. Six
	// intents on one frame, and the expected octets are spelled out rather than computed, so a writer
	// that "helped" would have to change this literal to pass.
	spec := NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, []byte("block")).
		Malformed(DeclareLength(MaxFramePayload)).
		Malformed(SetType(0xEF)).
		Malformed(AddFlags(0x40)).
		Malformed(ClearFlags(FlagEndHeaders)).
		Malformed(SetStreamID(2)).
		Malformed(SetReservedBit())

	octets := H2FrameProgram{Frames: []FrameSpec{spec}}.Encode()
	want := []byte{
		0xFF, 0xFF, 0xFF, // declares 16777215 octets; five follow
		0xEF,                   // a type the registry does not define
		0x41,                   // END_STREAM kept, 0x40 undefined bit added, END_HEADERS cleared
		0x80, 0x00, 0x00, 0x02, // reserved bit set over an even client-initiated id
		'b', 'l', 'o', 'c', 'k',
	}
	if !bytes.Equal(octets, want) {
		t.Fatalf("octets = % x, want % x", octets, want)
	}
}

func TestAMalformationTouchesOnlyTheFieldItNames(t *testing.T) {
	base := NewFrameSpec(TypeHeaders, 0x05, 1, []byte("abc"))

	flagsOnly := base.Malformed(AddFlags(0x40))
	if flagsOnly.Flags != 0x45 {
		t.Fatalf("flags = %#x, want 0x45", flagsOnly.Flags)
	}
	if flagsOnly.Type != base.Type || flagsOnly.StreamID != base.StreamID {
		t.Fatalf("AddFlags disturbed the type or stream id: %+v", flagsOnly)
	}
	if flagsOnly.DeclaredLen != nil {
		t.Fatalf("AddFlags invented a declared length: %d", *flagsOnly.DeclaredLen)
	}
	if !bytes.Equal(flagsOnly.Payload, base.Payload) {
		t.Fatalf("AddFlags rewrote the payload: %q", flagsOnly.Payload)
	}

	// SetReservedBit keeps the identifier beneath it; SetStreamID replaces the whole field.
	reserved := base.Malformed(SetReservedBit())
	if reserved.StreamID != StreamIDReservedBit|1 {
		t.Fatalf("stream id = %#x, want the reserved bit over 1", reserved.StreamID)
	}
	if got := reserved.Header().StreamIDMasked(); got != 1 {
		t.Fatalf("masked stream id = %d, want 1", got)
	}
	if replaced := base.Malformed(SetStreamID(0)); replaced.StreamID != 0 {
		t.Fatalf("SetStreamID(0) left %#x", replaced.StreamID)
	}
	// The base itself is untouched: Malformed takes a value receiver so a chain never edits the
	// spec it was built from.
	if base.Flags != 0x05 || base.StreamID != 1 {
		t.Fatalf("chaining mutated the original spec: %+v", base)
	}
}

func TestTheAuditDoesNotRepairWhatItReports(t *testing.T) {
	program := H2FrameProgram{Frames: []FrameSpec{
		NewFrameSpec(TypeContinuation, 0, 0, []byte("x")).WithDeclaredLen(99),
	}}
	before := program.Encode()
	if len(Audit(program)) == 0 {
		t.Fatal("this program is malformed")
	}
	if !bytes.Equal(program.Encode(), before) {
		t.Fatal("auditing a program must not change what it emits")
	}
}

func TestOmittingThePrefaceIsReportedRatherThanAssumedDeliberate(t *testing.T) {
	p := compliantProgram()
	p.Preface = false
	wantViolation(t, p, Violation{Kind: ViolationMissingPreface}, "a program with no preface")
}

func TestALyingLengthIsNamedWithBothNumbers(t *testing.T) {
	p := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, []byte("abcd")).Malformed(DeclareLength(1)),
	)
	wantExactViolations(t, p, []Violation{{
		Kind: ViolationDeclaredLengthDisagrees, Frame: 0, Declared: 1, Actual: 4,
	}}, "a length that disagrees with the payload")
}

func TestADeclaredLengthWiderThanTheFieldReportsTheTruncation(t *testing.T) {
	// The one place the writer cannot do as it was told. Silence here would be a lie.
	p := NewH2FrameProgram(
		NewFrameSpec(TypeData, 0, 1, nil).Malformed(DeclareLength(MaxFramePayload + 1)),
	)
	wantViolation(t, p, Violation{
		Kind: ViolationLengthFieldOverflowed, Frame: 0, Requested: MaxFramePayload + 1, Written: 0,
	}, "0x1000000 truncates to 0 in a 24-bit field")
}

func TestAPayloadWiderThanTheLengthFieldReportsTheClamp(t *testing.T) {
	p := NewH2FrameProgram(
		NewFrameSpec(TypeData, 0, 1, make([]byte, int(MaxFramePayload)+1)),
	)
	wantViolation(t, p, Violation{
		Kind: ViolationPayloadExceedsLengthField, Frame: 0, PayloadLen: int(MaxFramePayload) + 1,
	}, "a payload no 24-bit length can describe")
}

func TestTheReservedBitIsReportedWithoutDisturbingTheIdentifier(t *testing.T) {
	p := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, nil).Malformed(SetReservedBit()),
	)
	wantExactViolations(t, p, []Violation{{Kind: ViolationReservedBitSet, Frame: 0}},
		"the reserved bit alone")
}

// Rust: stream_id_rules_are_judged_per_frame_type (malformed.rs:820).
func TestStreamIDRulesAreJudgedPerFrameType(t *testing.T) {
	cases := []struct {
		spec FrameSpec
		want Violation
	}{
		{
			NewFrameSpec(TypeData, 0, 0, []byte("x")),
			Violation{Kind: ViolationStreamIDZeroOnStreamFrame, Frame: 0, Type: TypeData},
		},
		{
			NewFrameSpec(TypeSettings, 0, 3, nil),
			Violation{
				Kind: ViolationStreamIDNonZeroOnConnectionFrame, Frame: 0,
				Type: TypeSettings, StreamID: 3,
			},
		},
		{
			NewFrameSpec(TypePing, 0, 1, []byte("12345678")),
			Violation{
				Kind: ViolationStreamIDNonZeroOnConnectionFrame, Frame: 0,
				Type: TypePing, StreamID: 1,
			},
		},
		{
			NewFrameSpec(TypeHeaders, FlagEndHeaders, 2, nil),
			Violation{Kind: ViolationEvenStreamIDFromClient, Frame: 0, StreamID: 2},
		},
	}
	for _, c := range cases {
		wantViolation(t, NewH2FrameProgram(c.spec), c.want, "per-frame-type stream id rule")
	}

	// A stream-level WINDOW_UPDATE is legal, and so is a connection-level one.
	for _, id := range []uint32{0, 1} {
		p := NewH2FrameProgram(NewFrameSpec(TypeWindowUpdate, 0, id, []byte{0, 0, 0, 1}))
		wantNoViolations(t, p, "WINDOW_UPDATE is legal on the connection and on a stream")
	}
}

func TestAStreamIDThatDoesNotIncreaseIsReportedButTrailersAreNot(t *testing.T) {
	p := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 3, nil),
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, nil),
	)
	wantViolation(t, p, Violation{
		Kind: ViolationStreamIDNotIncreasing, Frame: 1, StreamID: 1, Highest: 3,
	}, "opening a lower stream id after a higher one")

	// A second HEADERS on a stream already opened is trailers, not a reopening.
	trailers := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, nil),
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, nil),
	)
	wantNoViolations(t, trailers, "trailers on an already-open stream")
}

func TestFixedSizeFramesReportALengthTheSpecForbids(t *testing.T) {
	cases := []struct {
		ty         uint8
		payloadLen int
		required   uint32
	}{
		{TypePriority, 4, 5},
		{TypeRSTStream, 5, 4},
		{TypePing, 7, 8},
		{TypeWindowUpdate, 0, 4},
	}
	for _, c := range cases {
		p := NewH2FrameProgram(NewFrameSpec(c.ty, 0, 1, make([]byte, c.payloadLen)))
		wantViolation(t, p, Violation{
			Kind: ViolationFixedLength, Frame: 0, Type: c.ty,
			Declared: uint32(c.payloadLen), Required: c.required,
		}, "a fixed-size frame at the wrong length")
	}
}

func TestSettingsLengthRulesAreCheckedAgainstTheLengthAPeerReads(t *testing.T) {
	odd := NewH2FrameProgram(NewFrameSpec(TypeSettings, 0, 0, make([]byte, 7)))
	wantViolation(t, odd, Violation{
		Kind: ViolationSettingsLengthNotMultipleOfSix, Frame: 0, Declared: 7,
	}, "seven octets of SETTINGS")

	acked := NewH2FrameProgram(NewFrameSpec(TypeSettings, FlagAck, 0, make([]byte, 6)))
	wantViolation(t, acked, Violation{
		Kind: ViolationSettingsAckWithPayload, Frame: 0, Declared: 6,
	}, "SETTINGS with ACK and a payload")

	// The peer frames by the declared value, so that is what the rule is judged on: six real octets
	// under a declared 7 is still a SETTINGS a peer will reject.
	lying := NewH2FrameProgram(
		NewFrameSpec(TypeSettings, 0, 0, make([]byte, 6)).Malformed(DeclareLength(7)),
	)
	wantViolation(t, lying, Violation{
		Kind: ViolationSettingsLengthNotMultipleOfSix, Frame: 0, Declared: 7,
	}, "the length a peer reads, not the one we wrote")
}

func TestAHeaderBlockLeftOpenIsReportedAgainstTheFrameThatOpenedIt(t *testing.T) {
	p := NewH2FrameProgram(NewFrameSpec(TypeHeaders, 0, 1, []byte("first-fragment")))
	wantExactViolations(t, p, []Violation{{
		Kind: ViolationHeaderBlockNeverTerminated, BlockOpenedAt: 0, StreamID: 1,
	}}, "a HEADERS with no END_HEADERS and nothing after it")

	// A CONTINUATION carrying END_HEADERS closes it, and then nothing is reported.
	closed := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, 0, 1, []byte("first")),
		NewFrameSpec(TypeContinuation, FlagEndHeaders, 1, []byte("rest")),
	)
	wantNoViolations(t, closed, "a block a CONTINUATION terminates")
}

// Rust: a_frame_interleaved_inside_a_header_block_is_reported (malformed.rs:995).
func TestAFrameInterleavedInsideAHeaderBlockIsReported(t *testing.T) {
	// The design's named research target: a frame smuggled between HEADERS and its END_HEADERS.
	p := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, 0, 1, []byte("first")),
		NewFrameSpec(TypeData, 0, 1, []byte("payload")),
		NewFrameSpec(TypeContinuation, FlagEndHeaders, 1, []byte("rest")),
	)
	wantViolation(t, p, Violation{
		Kind: ViolationFrameInterleavedInHeaderBlock, Frame: 1, Type: TypeData, BlockOpenedAt: 0,
	}, "a DATA frame smuggled inside a header block")
}

func TestAContinuationReportsWhetherItHasABlockAndWhetherItIsTheRightStream(t *testing.T) {
	orphan := NewH2FrameProgram(NewFrameSpec(TypeContinuation, FlagEndHeaders, 1, []byte("c")))
	wantExactViolations(t, orphan, []Violation{{
		Kind: ViolationContinuationWithNothingToContinue, Frame: 0,
	}}, "a CONTINUATION with no block before it")

	wrongStream := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, 0, 1, []byte("first")),
		NewFrameSpec(TypeContinuation, FlagEndHeaders, 3, []byte("rest")),
	)
	wantViolation(t, wrongStream, Violation{
		Kind: ViolationContinuationOnAnotherStream, Frame: 1, Expected: 1, Found: 3,
	}, "a CONTINUATION on the wrong stream")
}

func TestDataOnAStreamNothingOpenedIsAnIllegalStateTransition(t *testing.T) {
	p := NewH2FrameProgram(NewFrameSpec(TypeData, 0, 1, []byte("body")))
	wantExactViolations(t, p, []Violation{{
		Kind: ViolationDataOnUnopenedStream, Frame: 0, StreamID: 1,
	}}, "DATA on an idle stream")
}

func TestSendingOnAFinishedStreamIsReportedExceptWhereTheSpecStillAllowsIt(t *testing.T) {
	afterEndStream := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, nil),
		NewFrameSpec(TypeData, 0, 1, []byte("more")),
	)
	wantViolation(t, afterEndStream, Violation{
		Kind: ViolationFrameAfterStreamClosed, Frame: 1, Type: TypeData, StreamID: 1, ClosedAt: 0,
	}, "DATA after END_STREAM")

	afterReset := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, nil),
		NewFrameSpec(TypeRSTStream, 0, 1, []byte{0, 0, 0, 8}),
		NewFrameSpec(TypeWindowUpdate, 0, 1, []byte{0, 0, 0, 1}),
	)
	wantNoViolations(t, afterReset, "WINDOW_UPDATE after RST_STREAM is legal")
}

// Rust: padding_that_runs_past_the_frame_is_reported (malformed.rs:1093).
func TestPaddingThatRunsPastTheFrameIsReported(t *testing.T) {
	// pad length 9 in a four-octet payload: three octets of padding are available.
	over := NewH2FrameProgram(
		NewFrameSpec(TypeData, FlagPadded|FlagEndStream, 1, []byte{9, 'a', 'b', 'c'}),
	)
	wantViolation(t, over, Violation{
		Kind: ViolationPadLengthExceedsPayload, Frame: 0, PadLength: 9, PayloadLen: 4,
	}, "padding that runs past the frame")

	empty := NewH2FrameProgram(NewFrameSpec(TypeData, FlagPadded, 1, nil))
	wantViolation(t, empty, Violation{Kind: ViolationPadLengthOctetMissing, Frame: 0},
		"PADDED with no octet to carry the pad length")

	// pad length 2 in a four-octet payload: one data octet, two of padding. Legal.
	fits := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, nil),
		NewFrameSpec(TypeData, FlagPadded, 1, []byte{2, 'x', 0, 0}),
	)
	wantNoViolations(t, fits, "padding that fits")
}

func TestPushPromiseFromAClientIsReported(t *testing.T) {
	p := NewH2FrameProgram(
		NewFrameSpec(TypePushPromise, FlagEndHeaders, 1, []byte("\x00\x00\x00\x02block")),
	)
	wantViolation(t, p, Violation{Kind: ViolationPushPromiseFromClient, Frame: 0},
		"a client sending PUSH_PROMISE")
}

func TestEveryViolationCitesTheSectionThatForbidsItAndReadsAsASentence(t *testing.T) {
	// A catalogue entry with no citation, or an empty message, is a report an operator cannot check
	// against the spec — so the shape is asserted rather than assumed.
	all := []Violation{
		{Kind: ViolationMissingPreface},
		{Kind: ViolationLengthFieldOverflowed, Frame: 0, Requested: 1, Written: 2},
		{Kind: ViolationPayloadExceedsLengthField, Frame: 0, PayloadLen: 1},
		{Kind: ViolationDeclaredLengthDisagrees, Frame: 0, Declared: 1, Actual: 2},
		{Kind: ViolationReservedBitSet, Frame: 0},
		{Kind: ViolationStreamIDZeroOnStreamFrame, Frame: 0, Type: TypeData},
		{Kind: ViolationStreamIDNonZeroOnConnectionFrame, Frame: 0, Type: TypePing, StreamID: 1},
		{Kind: ViolationEvenStreamIDFromClient, Frame: 0, StreamID: 2},
		{Kind: ViolationStreamIDNotIncreasing, Frame: 0, StreamID: 1, Highest: 3},
		{Kind: ViolationFixedLength, Frame: 0, Type: TypePing, Declared: 7, Required: 8},
		{Kind: ViolationSettingsLengthNotMultipleOfSix, Frame: 0, Declared: 7},
		{Kind: ViolationSettingsAckWithPayload, Frame: 0, Declared: 6},
		{Kind: ViolationPushPromiseFromClient, Frame: 0},
		{Kind: ViolationContinuationWithNothingToContinue, Frame: 0},
		{Kind: ViolationContinuationOnAnotherStream, Frame: 0, Expected: 1, Found: 3},
		{Kind: ViolationFrameInterleavedInHeaderBlock, Frame: 1, Type: 0xEF, BlockOpenedAt: 0},
		{Kind: ViolationHeaderBlockNeverTerminated, BlockOpenedAt: 0, StreamID: 1},
		{Kind: ViolationDataOnUnopenedStream, Frame: 0, StreamID: 1},
		{Kind: ViolationFrameAfterStreamClosed, Frame: 1, Type: TypeData, StreamID: 1, ClosedAt: 0},
		{Kind: ViolationPadLengthOctetMissing, Frame: 0},
		{Kind: ViolationPadLengthExceedsPayload, Frame: 0, PadLength: 9, PayloadLen: 4},
	}
	// Every kind the audit can emit must be in this catalogue: a kind added without a citation and
	// without a message would otherwise pass unnoticed.
	seen := map[ViolationKind]bool{}
	for _, v := range all {
		seen[v.Kind] = true
		if !strings.HasPrefix(v.RFC(), "RFC 9113 §") {
			t.Fatalf("%+v cites %q", v, v.RFC())
		}
		if len(v.String()) <= 10 {
			t.Fatalf("%+v renders as %q", v, v.String())
		}
	}
	for k := ViolationMissingPreface; k <= ViolationPadLengthExceedsPayload; k++ {
		if !seen[k] {
			t.Fatalf("violation kind %d is not in the catalogue this test checks", k)
		}
	}

	// An unregistered type renders as its octet, never as a name.
	got := Violation{
		Kind: ViolationFrameInterleavedInHeaderBlock, Frame: 1, Type: 0xEF, BlockOpenedAt: 0,
	}.String()
	if !strings.Contains(got, "type 0xEF") {
		t.Fatalf("an unregistered type must render as its octet; got %q", got)
	}
}

func TestAMalformationCitesTheSectionItBreaks(t *testing.T) {
	all := []Malformation{
		DeclareLength(1), SetType(0xEF), SetFlags(0xFF), AddFlags(0x40),
		ClearFlags(FlagEndHeaders), SetStreamID(0), SetReservedBit(),
	}
	seen := map[MalformationKind]bool{}
	for _, m := range all {
		seen[m.Kind] = true
		if !strings.HasPrefix(m.RFC(), "RFC 9113 §") {
			t.Fatalf("%+v cites %q", m, m.RFC())
		}
	}
	for k := MalformDeclareLength; k <= MalformSetReservedBit; k++ {
		if !seen[k] {
			t.Fatalf("malformation kind %d has no citation checked here", k)
		}
	}
}

// String must never print a field the Kind does not populate, because the Go union shape leaves those
// fields reading zero and "frame 0" is a claim about a real frame. Rust cannot make this mistake —
// its enum variants have no such fields — so this test has no Rust counterpart and exists because
// the divergence introduced the hazard.
func TestAProgramLevelViolationNeverClaimsAFrameIndex(t *testing.T) {
	for _, v := range []Violation{
		{Kind: ViolationMissingPreface},
		{Kind: ViolationHeaderBlockNeverTerminated, BlockOpenedAt: 2, StreamID: 1},
	} {
		if strings.Contains(v.String(), "frame 0") {
			t.Fatalf("%+v names frame 0, which its Kind does not populate: %q", v, v.String())
		}
	}
}

// An audit whose report an operator reads as exhaustive, when it is not, is worse than no report —
// so the checks the module declines to make are asserted to actually be declined, rather than left
// to a doc comment that could drift from the code.
func TestTheAuditDeclinesTheChecksItsDocsSayItDeclines(t *testing.T) {
	// SETTINGS_MAX_FRAME_SIZE: a 20000-octet DATA frame is over the 16384 default and is not
	// reported, because the peer's real limit is unknowable from a program.
	big := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, nil),
		NewFrameSpec(TypeData, 0, 1, make([]byte, 20_000)),
	)
	wantNoViolations(t, big, "a frame over the default SETTINGS_MAX_FRAME_SIZE")

	// SETTINGS payload contents: ENABLE_PUSH (id 2) set to 7 is out of range per §6.5.2 and is not
	// decoded here.
	settings := NewH2FrameProgram(
		NewFrameSpec(TypeSettings, 0, 0, []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x07}),
	)
	wantNoViolations(t, settings, "an out-of-range SETTINGS value")

	// Flow control: a WINDOW_UPDATE increment of 0 is a PROTOCOL_ERROR per §6.9 and is not reported,
	// because it needs both peers' windows modelled.
	zeroWindow := NewH2FrameProgram(NewFrameSpec(TypeWindowUpdate, 0, 0, []byte{0, 0, 0, 0}))
	wantNoViolations(t, zeroWindow, "a zero WINDOW_UPDATE increment")

	// GOAWAY/RST_STREAM payload semantics: an unregistered error code is not decoded, only the
	// length is checked.
	codes := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders, 1, nil),
		NewFrameSpec(TypeRSTStream, 0, 1, []byte{0xFF, 0xFF, 0xFF, 0xFF}),
		NewFrameSpec(TypeGoAway, 0, 0, []byte{0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF}),
	)
	wantNoViolations(t, codes, "an unregistered error code")

	// HPACK validity: a header block that is not decodable HPACK at all (index 0, §6.1 reserved) is
	// framing-legal and is not reported here.
	badBlock := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, []byte{0x80}),
	)
	wantNoViolations(t, badBlock, "a header block HPACK would refuse")
	if _, err := NewDecoder(4096).Decode([]byte{0x80}); err == nil {
		t.Fatal("the same block must be refused by the HPACK layer, which is where that rule lives")
	}

	// Field validity: an uppercase field name is invalid HTTP/2 (§8.2.1) and is normalisation's
	// subject, not framing's.
	block := NewEncoder(4096).Encode([]HeaderField{hf("X-Test", "v")})
	upper := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, block),
	)
	wantNoViolations(t, upper, "an uppercase field name inside the block")
}

// The two layers meet only through bytes: a header list becomes a block, the block becomes a frame
// payload, and the audit judges the framing without ever looking inside. Pinned because the seam is
// the whole reason FrameSpec.Payload is bytes rather than a header list.
func TestAnHPACKBlockTravelsThroughTheFrameLayerUntouched(t *testing.T) {
	fields := []HeaderField{
		hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"),
		hf(":authority", "example.com"), hf("x-probe", "1"),
	}
	block := NewEncoder(4096).Encode(fields)
	program := NewH2FrameProgram(
		NewFrameSpec(TypeSettings, 0, 0, nil),
		NewFrameSpec(TypeHeaders, FlagEndHeaders|FlagEndStream, 1, block),
	)
	wantNoViolations(t, program, "a compliant request carrying a real header block")

	rest, ok := StripPreface(program.Encode())
	if !ok {
		t.Fatal("preface present")
	}
	frames, tail := ReadFrames(rest)
	if tail.Kind != TailComplete || len(frames) != 2 {
		t.Fatalf("read %d frames, tail %+v", len(frames), tail)
	}
	out, err := NewDecoder(4096).Decode(frames[1].Payload)
	if err != nil {
		t.Fatalf("the block must survive the frame layer byte for byte: %v", err)
	}
	wantFields(t, out, fields, "header list through frame and back")
}

// Malformation.Apply must set DeclaredLen to its own copy: sharing the pointer between two frames
// malformed from the same intent would let a later edit to one silently change the other. The Go
// pointer field created this hazard where Rust's Option<u32> could not.
func TestDeclareLengthGivesEachFrameItsOwnLength(t *testing.T) {
	m := DeclareLength(10)
	a := NewFrameSpec(TypeData, 0, 1, nil).Malformed(m)
	b := NewFrameSpec(TypeData, 0, 3, nil).Malformed(m)
	if a.DeclaredLen == b.DeclaredLen {
		t.Fatal("two frames malformed from one intent must not share a length pointer")
	}
	*a.DeclaredLen = 99
	if *b.DeclaredLen != 10 {
		t.Fatalf("editing one frame's length changed another's to %d", *b.DeclaredLen)
	}
}
