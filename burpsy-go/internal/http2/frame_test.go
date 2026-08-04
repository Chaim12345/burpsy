package http2

import (
	"bytes"
	"testing"
)

// Ported one-for-one from crates/http2/src/frame.rs's `mod tests`. Rust test names are kept as the
// Go name in CamelCase so a reader can diff the two suites without a mapping table.

func TestAFrameHeaderRoundTripsEveryFieldIncludingReservedBits(t *testing.T) {
	cases := []FrameHeader{
		{Len: 0, Type: TypeData, Flags: 0, StreamID: 0},
		{Len: 1, Type: TypeHeaders, Flags: 0x05, StreamID: 1},
		{Len: MaxFramePayload, Type: 0xFF, Flags: 0xFF, StreamID: 0xFFFF_FFFF},
		{Len: 16_384, Type: TypeSettings, Flags: 0x01, StreamID: 0x7FFF_FFFF},
	}
	for _, want := range cases {
		octets := want.Encode()
		got, ok := DecodeFrameHeader(octets[:])
		if !ok || got != want {
			t.Fatalf("header did not survive an encode/decode round trip: got %+v ok=%v, want %+v",
				got, ok, want)
		}
	}
}

func TestTheHeaderIsBigEndian(t *testing.T) {
	h := FrameHeader{Len: 0x01_02_03, Type: 0x04, Flags: 0x05, StreamID: 0x0607_0809}
	got := h.Encode()
	want := [FrameHeaderLen]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	if got != want {
		t.Fatalf("HTTP/2 is network order; a little-endian length would frame every peer wrongly: "+
			"got % x, want % x", got, want)
	}
}

func TestFewerThanNineOctetsIsAFramingAnswerNotAValidityOne(t *testing.T) {
	for n := 0; n < FrameHeaderLen; n++ {
		if _, ok := DecodeFrameHeader(make([]byte, n)); ok {
			t.Fatalf("%d octets must not decode as a header", n)
		}
	}
	if _, ok := DecodeFrameHeader(make([]byte, FrameHeaderLen)); !ok {
		t.Fatal("nine zero octets are a valid header, because every field is raw")
	}
}

func TestTheReservedBitIsCarriedNotMaskedAway(t *testing.T) {
	h := FrameHeader{Len: 0, Type: TypeData, Flags: 0, StreamID: StreamIDReservedBit | 3}
	if !h.ReservedBitSet() {
		t.Fatal("the bit a compliant peer never sets must be visible")
	}
	if got := h.StreamIDMasked(); got != 3 {
		t.Fatalf("StreamIDMasked = %d, want 3", got)
	}
	// And it survives the wire, in both directions.
	octets := h.Encode()
	back, ok := DecodeFrameHeader(octets[:])
	if !ok {
		t.Fatal("decode")
	}
	if back.StreamID != StreamIDReservedBit|3 || !back.ReservedBitSet() {
		t.Fatalf("reserved bit lost on the way back: %#x", back.StreamID)
	}
}

// ---- the writer does not help ----

func TestADeclaredLengthThatDisagreesWithThePayloadIsEmittedAsWritten(t *testing.T) {
	spec := NewFrameSpec(TypeData, 0x01, 1, []byte("four")).WithDeclaredLen(9999)
	if !spec.LengthIsDishonest() {
		t.Fatal("a declared 9999 over a four-octet payload is a dishonest length")
	}
	octets := H2FrameProgram{Frames: []FrameSpec{spec}}.Encode()
	// Length field says 9999; exactly four payload octets follow.
	if !bytes.Equal(octets[0:3], []byte{0x00, 0x27, 0x0F}) {
		t.Fatalf("length field = % x, want 9999 big-endian", octets[0:3])
	}
	if len(octets) != FrameHeaderLen+4 || !bytes.Equal(octets[FrameHeaderLen:], []byte("four")) {
		t.Fatalf("payload was rewritten to match the lie: % x", octets)
	}
}

func TestStreamIDZeroOnADataFrameIsEmittedUnchanged(t *testing.T) {
	// Illegal per RFC 9113 §6.1, which is why it must be possible.
	octets := H2FrameProgram{Frames: []FrameSpec{NewFrameSpec(TypeData, 0, 0, []byte("x"))}}.Encode()
	if !bytes.Equal(octets[5:9], []byte{0, 0, 0, 0}) {
		t.Fatalf("stream id was renumbered: % x", octets[5:9])
	}
}

func TestAnEvenClientInitiatedStreamIDIsEmittedUnchanged(t *testing.T) {
	// Clients must use odd ids (§5.1.1). The writer does not renumber.
	octets := H2FrameProgram{
		Frames: []FrameSpec{NewFrameSpec(TypeHeaders, 0x04, 2, []byte("h"))},
	}.Encode()
	if !bytes.Equal(octets[5:9], []byte{0, 0, 0, 2}) {
		t.Fatalf("stream id was renumbered: % x", octets[5:9])
	}
}

func TestReservedFlagBitsSurviveTheWriter(t *testing.T) {
	// 0xFF sets every defined and every undefined flag at once.
	octets := H2FrameProgram{
		Frames: []FrameSpec{NewFrameSpec(TypeHeaders, 0xFF, 1, nil)},
	}.Encode()
	if octets[4] != 0xFF {
		t.Fatalf("the writer must not clear what it does not know: flags = %#x", octets[4])
	}
}

func TestContinuationWithNothingToContinueIsEmittedAnyway(t *testing.T) {
	octets := H2FrameProgram{
		Frames: []FrameSpec{NewFrameSpec(TypeContinuation, 0x04, 1, []byte("c"))},
	}.Encode()
	if octets[3] != TypeContinuation {
		t.Fatalf("type octet = %#x, want CONTINUATION", octets[3])
	}
	// No preceding HEADERS. The writer has no opinion.
	if len(octets) != FrameHeaderLen+1 {
		t.Fatalf("the writer inserted something: % x", octets)
	}
}

func TestAnUnknownFrameTypeIsEmittedUnchanged(t *testing.T) {
	octets := H2FrameProgram{Frames: []FrameSpec{NewFrameSpec(0xEF, 0, 1, nil)}}.Encode()
	if octets[3] != 0xEF {
		t.Fatalf("type octet = %#x, want 0xEF", octets[3])
	}
}

func TestThePrefaceIsWrittenVerbatimAndCanBeOmitted(t *testing.T) {
	with := H2FrameProgram{Preface: true}.Encode()
	if string(with) != ConnectionPreface {
		t.Fatalf("preface = %q, want %q", with, ConnectionPreface)
	}
	without := H2FrameProgram{Preface: false}.Encode()
	if len(without) != 0 {
		t.Fatalf("omitting the preface is a research target; got % x", without)
	}
}

// NewH2FrameProgram is Go's stand-in for Rust's Default impl, so its two non-zero fields are pinned
// here — a program built with it and never touched must be prefaced and must audit clean.
func TestNewH2FrameProgramCarriesRustsDefaults(t *testing.T) {
	p := NewH2FrameProgram()
	if !p.Preface {
		t.Fatal("Rust's H2FrameProgram::default() sends the preface")
	}
	if p.ReadForMS != 2_000 {
		t.Fatalf("ReadForMS = %d, want Rust's 2000", p.ReadForMS)
	}
	if len(p.Frames) != 0 {
		t.Fatalf("a default program has no frames, got %d", len(p.Frames))
	}
	// And the zero value, which cannot carry those, is a program Audit reports rather than fixes.
	if got := Audit(H2FrameProgram{}); len(got) != 1 || got[0].Kind != ViolationMissingPreface {
		t.Fatalf("the zero value must report MissingPreface, got %v", got)
	}
}

func TestFrameLayoutHonestyIsReportedForTheAuthoriser(t *testing.T) {
	honest := NewH2FrameProgram(NewFrameSpec(TypeHeaders, 0x04, 1, []byte("abc")))
	if !honest.FrameLayoutIsHonest() {
		t.Fatal("a program with no declared length is honest by construction")
	}

	lying := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, 0x04, 1, []byte("abc")).WithDeclaredLen(1))
	if lying.FrameLayoutIsHonest() {
		t.Fatal("a lying length means the peer decodes a block we did not")
	}

	// A declared length that agrees with the payload is not a lie.
	explicit := NewH2FrameProgram(
		NewFrameSpec(TypeHeaders, 0x04, 1, []byte("abc")).WithDeclaredLen(3))
	if !explicit.FrameLayoutIsHonest() {
		t.Fatal("an explicit length equal to the payload's own is honest")
	}
}

// ---- the reader does not drop ----

func TestAConcatenatedStreamSplitsAtFrameBoundaries(t *testing.T) {
	program := H2FrameProgram{Frames: []FrameSpec{
		NewFrameSpec(TypeSettings, 0, 0, nil),
		NewFrameSpec(TypeHeaders, 0x04, 1, []byte("hdr")),
		NewFrameSpec(TypeData, 0x01, 1, []byte("body-bytes")),
	}}
	frames, tail := ReadFrames(program.Encode())
	if tail.Kind != TailComplete {
		t.Fatalf("tail = %+v, want complete", tail)
	}
	if len(frames) != 3 {
		t.Fatalf("read %d frames, want 3", len(frames))
	}
	if frames[0].Header.Type != TypeSettings {
		t.Fatalf("frame 0 type = %#x", frames[0].Header.Type)
	}
	if !bytes.Equal(frames[1].Payload, []byte("hdr")) {
		t.Fatalf("frame 1 payload = %q", frames[1].Payload)
	}
	if !bytes.Equal(frames[2].Payload, []byte("body-bytes")) {
		t.Fatalf("frame 2 payload = %q", frames[2].Payload)
	}
	// Offsets name where each frame started, for fault reporting.
	wantOffsets := []int{0, FrameHeaderLen, FrameHeaderLen*2 + 3}
	for i, want := range wantOffsets {
		if frames[i].Offset != want {
			t.Fatalf("frame %d offset = %d, want %d", i, frames[i].Offset, want)
		}
	}
}

func TestWriteThenReadRoundTripsACompliantProgram(t *testing.T) {
	frames := []FrameSpec{
		NewFrameSpec(TypeSettings, 0, 0, []byte("\x00\x03\x00\x00\x00\x64")),
		NewFrameSpec(TypeHeaders, 0x05, 1, []byte("encoded-block")),
		NewFrameSpec(TypeData, 0x01, 1, []byte("payload")),
	}
	program := NewH2FrameProgram(frames...)
	rest, ok := StripPreface(program.Encode())
	if !ok {
		t.Fatal("preface present")
	}
	read, tail := ReadFrames(rest)
	if tail.Kind != TailComplete {
		t.Fatalf("tail = %+v, want complete", tail)
	}
	if len(read) != len(frames) {
		t.Fatalf("read %d frames, want %d", len(read), len(frames))
	}
	for i := range read {
		if read[i].Header != frames[i].Header() {
			t.Fatalf("frame %d header = %+v, want %+v", i, read[i].Header, frames[i].Header())
		}
		if !bytes.Equal(read[i].Payload, frames[i].Payload) {
			t.Fatalf("frame %d payload = %q, want %q", i, read[i].Payload, frames[i].Payload)
		}
	}
}

func TestATailTruncatedMidPayloadIsReportedIncompleteNotDropped(t *testing.T) {
	program := H2FrameProgram{Frames: []FrameSpec{
		NewFrameSpec(TypeHeaders, 0x04, 1, []byte("complete")),
		NewFrameSpec(TypeData, 0, 1, []byte("0123456789")),
	}}
	octets := program.Encode()
	cut := len(octets) - 4 // lose four payload octets of the last frame
	frames, tail := ReadFrames(octets[:cut])

	if len(frames) != 1 {
		t.Fatalf("the whole frame before the cut is still returned; got %d", len(frames))
	}
	want := Tail{
		Kind:      TailIncomplete,
		Offset:    FrameHeaderLen + 8,
		Have:      FrameHeaderLen + 6,
		Need:      FrameHeaderLen + 10,
		NeedKnown: true,
	}
	if tail != want {
		t.Fatalf("tail = %+v, want %+v", tail, want)
	}
}

func TestATailTooShortForAHeaderCannotStateWhatItNeeded(t *testing.T) {
	octets := H2FrameProgram{
		Frames: []FrameSpec{NewFrameSpec(TypeData, 0, 1, []byte("x"))},
	}.Encode()
	octets = append(octets, 0x00, 0x01) // two stray octets

	frames, tail := ReadFrames(octets)
	if len(frames) != 1 {
		t.Fatalf("read %d frames, want 1", len(frames))
	}
	want := Tail{Kind: TailIncomplete, Offset: FrameHeaderLen + 1, Have: 2}
	if tail != want {
		t.Fatalf("without nine octets the needed total is unknowable, and saying so is honest: "+
			"tail = %+v, want %+v", tail, want)
	}
}

func TestAFrameDeclaringMoreThanRemainsEndsTheScanRatherThanErroring(t *testing.T) {
	// The shape a lying DeclaredLen produces on the receiving side.
	octets := H2FrameProgram{Frames: []FrameSpec{
		NewFrameSpec(TypeData, 0, 1, []byte("short")).WithDeclaredLen(1000),
	}}.Encode()
	frames, tail := ReadFrames(octets)
	if len(frames) != 0 {
		t.Fatalf("no whole frame is present; got %d", len(frames))
	}
	want := Tail{
		Kind:      TailIncomplete,
		Offset:    0,
		Have:      FrameHeaderLen + 5,
		Need:      FrameHeaderLen + 1000,
		NeedKnown: true,
	}
	if tail != want {
		t.Fatalf("tail = %+v, want %+v", tail, want)
	}
}

func TestAnEmptyStreamIsCompleteNotIncomplete(t *testing.T) {
	frames, tail := ReadFrames(nil)
	if len(frames) != 0 {
		t.Fatalf("read %d frames from nothing", len(frames))
	}
	if tail.Kind != TailComplete {
		t.Fatalf("tail = %+v, want complete", tail)
	}
}

func TestAZeroLengthFrameIsARealFrame(t *testing.T) {
	octets := H2FrameProgram{
		Frames: []FrameSpec{NewFrameSpec(TypeSettings, 0x01, 0, nil)},
	}.Encode()
	frames, tail := ReadFrames(octets)
	if tail.Kind != TailComplete {
		t.Fatalf("tail = %+v, want complete", tail)
	}
	if len(frames) != 1 {
		t.Fatalf("read %d frames, want 1", len(frames))
	}
	if len(frames[0].Payload) != 0 || frames[0].Header.Len != 0 {
		t.Fatalf("frame = %+v, want an empty payload and a zero length", frames[0])
	}
}

func TestStripPrefaceDeclinesAStreamThatDoesNotBeginWithIt(t *testing.T) {
	if _, ok := StripPreface([]byte("GET / HTTP/1.1\r\n\r\n")); ok {
		t.Fatal("an HTTP/1 request line is not the preface")
	}
	rest, ok := StripPreface([]byte(ConnectionPreface))
	if !ok || len(rest) != 0 {
		t.Fatalf("StripPreface(preface) = %q, %v; want empty, true", rest, ok)
	}
	// A prefix of the preface is not the preface: a short read must not be accepted as one.
	if _, ok := StripPreface([]byte(ConnectionPreface[:10])); ok {
		t.Fatal("a partial preface must not strip")
	}
}

// A RawFrame must outlive the buffer it was read from, because a real reader reuses that buffer.
// Rust gets this from Bytes::copy_from_slice; Go has to be told, so it is pinned here.
func TestReadFramesCopiesThePayloadOutOfTheInput(t *testing.T) {
	octets := H2FrameProgram{
		Frames: []FrameSpec{NewFrameSpec(TypeData, 0, 1, []byte("body"))},
	}.Encode()
	frames, _ := ReadFrames(octets)
	if len(frames) != 1 {
		t.Fatalf("read %d frames, want 1", len(frames))
	}
	for i := range octets {
		octets[i] = 0xAA
	}
	if !bytes.Equal(frames[0].Payload, []byte("body")) {
		t.Fatalf("payload aliased the read buffer: %q", frames[0].Payload)
	}
}

func TestTypeNameNeverInventsANameForAnUnregisteredOctet(t *testing.T) {
	registered := map[uint8]string{
		TypeData: "DATA", TypeHeaders: "HEADERS", TypePriority: "PRIORITY",
		TypeRSTStream: "RST_STREAM", TypeSettings: "SETTINGS", TypePushPromise: "PUSH_PROMISE",
		TypePing: "PING", TypeGoAway: "GOAWAY", TypeWindowUpdate: "WINDOW_UPDATE",
		TypeContinuation: "CONTINUATION",
	}
	for ty, want := range registered {
		got, ok := TypeName(ty)
		if !ok || got != want {
			t.Fatalf("TypeName(%#x) = %q, %v; want %q, true", ty, got, ok, want)
		}
	}
	for _, ty := range []uint8{0x0A, 0x0B, 0x7F, 0xEF, 0xFF} {
		if got, ok := TypeName(ty); ok {
			t.Fatalf("TypeName(%#x) invented %q for an unregistered octet", ty, got)
		}
	}
}
