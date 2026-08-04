package http2

import (
	"fmt"
)

// Deliberate malformation: frames the spec forbids, plus a report naming which rules they break.
//
// # Why this exists when the writer already corrects nothing
//
// frame.go preserves whatever it is handed, so an operator who sets the fields of a FrameSpec
// directly can already put an illegal frame on the wire. That is not the same thing as *supporting*
// deliberate malformation, for three reasons.
//
// **A frame program cannot say what it meant.** A program with a lying length, an even
// client-initiated stream id and an unterminated header block is, at the type level,
// indistinguishable from a compliant one. So a probe malformed by accident looks exactly like a probe
// malformed on purpose — and when the target answers with RST_STREAM you cannot tell which of the
// three rules it objected to, or whether it objected to a fourth you did not know you had broken.
// Audit answers that question: it names every rule the program breaks and the section that forbids
// it.
//
// **Two silent corrections do exist, and they cannot be removed.** The length field is 24 bits, so a
// DeclaredLen above MaxFramePayload loses its top bits in FrameHeader.Encode, and a payload longer
// than that cannot be described honestly by FrameSpec.Header. No amount of discipline fixes those —
// the field is the size it is. What is available is to *report* them, which is what
// ViolationLengthFieldOverflowed and ViolationPayloadExceedsLengthField are for: the one place the
// writer cannot do as it was told is stated rather than hidden.
//
// **Malformation is an intent, and intents are worth naming.** Malformation is the vocabulary:
// ClearFlags(FlagEndHeaders) instead of `spec.Flags &= ^uint8(0x04)`. Applying one never refuses and
// never touches a field it does not name — this is the deliberate path, so a "helpful" adjustment
// here would be the same defect as one in the writer.
//
// # One direction
//
// Audit judges a program as **client-to-server**, because that is the only direction this layer
// emits. Hence an even stream id is a violation (ViolationEvenStreamIDFromClient) and a PUSH_PROMISE
// is one too (ViolationPushPromiseFromClient); both are correct for a server to send. Auditing
// captured server frames would need the mirror-image rule set, which does not exist here yet — in
// either language.
//
// # This layer does not send anything
//
// It produces octets and a report about them. Getting those octets onto a socket is deliberately not
// wired: nothing in internal/sender or internal/proxy calls Audit or Encode, and the authorisation
// rules for a frame program are stricter than for a request. A program with a dishonest length, a raw
// header-block fragment or an unterminated block cannot have its `:path` fields authorised
// individually, because the peer will not decode the block we decoded. That classifier and the
// transport behind it are a separate slice, in Go as in Rust. So today Audit is the capability an
// operator can actually reach from here — an emitted program still has no route to a socket, and
// saying otherwise would be an overclaim.
//
// # What the audit does not check, and why
//
// Stated because a report that looks exhaustive and is not would be worse than no report:
//
//   - **SETTINGS_MAX_FRAME_SIZE.** A frame larger than the peer's limit is a FRAME_SIZE_ERROR (§4.2),
//     but the limit is whatever the peer's own SETTINGS said, which a program cannot know. Checking
//     against the 16384 default would flag every legitimately large frame sent after a real settings
//     exchange.
//   - **SETTINGS payload contents** (§6.5.2) — an out-of-range ENABLE_PUSH or INITIAL_WINDOW_SIZE is
//     a violation this does not decode. Unknown identifiers are legal, so a report here would have to
//     distinguish the two, and nothing needs it yet.
//   - **Flow control** (§6.9) — a WINDOW_UPDATE of 0, or an increment overflowing the window,
//     requires modelling both peers' windows.
//   - **GOAWAY, PRIORITY and RST_STREAM payload semantics** — the shape is length-checked, the
//     contents are not.
//   - **HPACK validity** (RFC 7541) — an index into an empty table, a bad Huffman padding, a string
//     length overrunning the block. Those are hpack.go's subject, and on the emit side they are
//     reachable only through a raw header-block fragment.
//   - **Field validity** (§8.3) — a missing `:path`, an uppercase field name, a connection-specific
//     header. That is normalisation's subject, not framing's.
//
// # Length is judged twice, deliberately
//
// The padding and fixed-size checks read the length a **peer** will act on — the 24 bits actually
// written — while ViolationDeclaredLengthDisagrees compares that against the payload we actually
// wrote. A program that lies about a length therefore gets both a report of the lie and checks
// conducted in the peer's terms, which is the only combination that describes what will happen on
// the wire.
//
// # Divergences from crates/http2/src/malformed.rs, which is this module's spec
//
// The rule set, the order violations are reported in, and every number are the Rust ones. Three
// things differ, all named:
//
//   - Rust's Malformation and Violation are enums with per-variant fields; Go has no such thing, so
//     each is one struct with a Kind and the union of the fields, and only the fields its Kind names
//     are populated. This is the shape core.CorruptRecord established for exactly this problem. It
//     means a Violation for a Kind that has no frame index still has a Frame field reading 0, so
//     String never prints a field its Kind does not name.
//   - Rust builds a malformation as an enum literal (`Malformation::ClearFlags(x)`); Go uses
//     constructor functions of the same names (ClearFlags(x)), including SetReservedBit() for what
//     Rust spells as a unit variant. A function rather than an exported var, because an exported var
//     is writable by anything in the binary.
//   - Because every Violation field is comparable, a Violation compares with == and a report can be
//     searched with slices.Contains. Rust needs PartialEq derived for the same purpose; the effect is
//     the same, and it is only available because no field is a slice.
//
// MalformationKind, below, names which field-level mutation a Malformation performs.
type MalformationKind int

const (
	// MalformDeclareLength writes a length field other than the payload's own length (§4.1).
	//
	// The single most useful lie available: a receiver frames the connection by this value, so a
	// short one truncates the block it reads and a long one swallows the next frame's octets.
	MalformDeclareLength MalformationKind = iota
	// MalformSetType replaces the type octet (§4.1), including with one the registry does not define.
	MalformSetType
	// MalformSetFlags replaces the whole flags octet.
	MalformSetFlags
	// MalformAddFlags sets the named flag bits, leaving every other bit alone. Undefined bits
	// included — a receiver is required to ignore them, which is a requirement worth testing.
	MalformAddFlags
	// MalformClearFlags clears the named flag bits. ClearFlags(FlagEndHeaders) is how a header block
	// is left open.
	MalformClearFlags
	// MalformSetStreamID replaces the whole 32-bit stream-id field, reserved bit included (§5.1.1).
	MalformSetStreamID
	// MalformSetReservedBit sets the reserved top bit of the stream-id field, keeping the 31-bit
	// identifier beneath it (§5.1.1). A sender must leave it clear and a receiver must ignore it;
	// both halves are testable.
	MalformSetReservedBit
)

// Malformation is a spec violation requested on purpose.
//
// Every Kind is a field-level mutation, because that is the granularity the wire has. Composing them
// is how a research payload is built: a HEADERS with ClearFlags(FlagEndHeaders) and a DeclareLength
// shorter than its block is two intents and one frame.
//
// Only the fields its Kind names are populated; see the divergence note in this file's header.
type Malformation struct {
	Kind MalformationKind
	// Len is set for MalformDeclareLength.
	Len uint32
	// Type is set for MalformSetType.
	Type uint8
	// Flags is set for MalformSetFlags, MalformAddFlags, and MalformClearFlags.
	Flags uint8
	// StreamID is set for MalformSetStreamID.
	StreamID uint32
}

// DeclareLength writes a length field other than the payload's own (§4.1).
func DeclareLength(n uint32) Malformation {
	return Malformation{Kind: MalformDeclareLength, Len: n}
}

// SetType replaces the type octet (§4.1), including with one the registry does not define.
func SetType(ty uint8) Malformation {
	return Malformation{Kind: MalformSetType, Type: ty}
}

// SetFlags replaces the whole flags octet.
func SetFlags(f uint8) Malformation {
	return Malformation{Kind: MalformSetFlags, Flags: f}
}

// AddFlags sets the named flag bits, leaving every other bit alone.
func AddFlags(f uint8) Malformation {
	return Malformation{Kind: MalformAddFlags, Flags: f}
}

// ClearFlags clears the named flag bits.
func ClearFlags(f uint8) Malformation {
	return Malformation{Kind: MalformClearFlags, Flags: f}
}

// SetStreamID replaces the whole 32-bit stream-id field, reserved bit included (§5.1.1).
func SetStreamID(id uint32) Malformation {
	return Malformation{Kind: MalformSetStreamID, StreamID: id}
}

// SetReservedBit sets the reserved top bit of the stream-id field, keeping the 31-bit identifier
// beneath it (§5.1.1).
func SetReservedBit() Malformation {
	return Malformation{Kind: MalformSetReservedBit}
}

// Apply performs exactly the mutation this Kind names, and nothing else.
//
// Infallible on purpose. There is no input to reject: every uint8 is a legal type octet on the wire,
// every uint32 fits the stream-id field, and a length that does not fit 24 bits is reported by Audit
// rather than refused here. A validating setter on the deliberate-malformation path would be the same
// defect as a self-correcting writer.
func (m Malformation) Apply(spec *FrameSpec) {
	switch m.Kind {
	case MalformDeclareLength:
		n := m.Len
		spec.DeclaredLen = &n
	case MalformSetType:
		spec.Type = m.Type
	case MalformSetFlags:
		spec.Flags = m.Flags
	case MalformAddFlags:
		spec.Flags |= m.Flags
	case MalformClearFlags:
		spec.Flags &= ^m.Flags
	case MalformSetStreamID:
		spec.StreamID = m.StreamID
	case MalformSetReservedBit:
		spec.StreamID |= StreamIDReservedBit
	}
}

// RFC is the section a compliant sender would be breaking.
func (m Malformation) RFC() string {
	switch m.Kind {
	case MalformSetStreamID, MalformSetReservedBit:
		return "RFC 9113 §5.1.1"
	default:
		return "RFC 9113 §4.1"
	}
}

// Malformed applies a Malformation, chainable so a frame can be malformed several ways at once.
func (s FrameSpec) Malformed(m Malformation) FrameSpec {
	m.Apply(&s)
	return s
}

// ViolationKind names a rule a frame program breaks, so a caller can branch on the rule rather than
// matching on message text.
type ViolationKind int

const (
	// ViolationMissingPreface is §3.4 — the connection did not begin with the client preface.
	ViolationMissingPreface ViolationKind = iota
	// ViolationLengthFieldOverflowed is §4.1 — the declared length does not fit 24 bits, so the field
	// carries a different value.
	//
	// Written can coincidentally equal the payload length; the request was still not honoured, and
	// that is the fact this reports.
	ViolationLengthFieldOverflowed
	// ViolationPayloadExceedsLengthField is §4.1 — the payload is longer than the length field can
	// describe, so no honest length exists and the header states MaxFramePayload.
	ViolationPayloadExceedsLengthField
	// ViolationDeclaredLengthDisagrees is §4.1 — the length field disagrees with the payload actually
	// written. The peer will frame by the field, so it decodes something we did not.
	ViolationDeclaredLengthDisagrees
	// ViolationReservedBitSet is §5.1.1 — the reserved top bit of the stream-id field is set; a
	// sender must leave it clear.
	ViolationReservedBitSet
	// ViolationStreamIDZeroOnStreamFrame is §6.1/§6.2/§6.3/§6.4/§6.10 — a frame that belongs to a
	// stream names stream 0.
	ViolationStreamIDZeroOnStreamFrame
	// ViolationStreamIDNonZeroOnConnectionFrame is §6.5/§6.7/§6.8 — a connection-level frame names a
	// stream.
	ViolationStreamIDNonZeroOnConnectionFrame
	// ViolationEvenStreamIDFromClient is §5.1.1 — a client opened an even-numbered stream;
	// client-initiated streams are odd.
	ViolationEvenStreamIDFromClient
	// ViolationStreamIDNotIncreasing is §5.1.1 — a newly opened stream's id must be numerically
	// greater than every id this endpoint has already opened.
	ViolationStreamIDNotIncreasing
	// ViolationFixedLength is §6.3/§6.4/§6.7/§6.9 — a fixed-size frame declares a length the spec
	// does not allow.
	ViolationFixedLength
	// ViolationSettingsLengthNotMultipleOfSix is §6.5 — a SETTINGS payload is not a whole number of
	// six-octet entries.
	ViolationSettingsLengthNotMultipleOfSix
	// ViolationSettingsAckWithPayload is §6.5 — SETTINGS with ACK set must carry an empty payload.
	ViolationSettingsAckWithPayload
	// ViolationPushPromiseFromClient is §8.4 — a client sent PUSH_PROMISE, which only a server may
	// send.
	ViolationPushPromiseFromClient
	// ViolationContinuationWithNothingToContinue is §6.10 — a CONTINUATION with no unterminated
	// header block before it.
	ViolationContinuationWithNothingToContinue
	// ViolationContinuationOnAnotherStream is §6.10 — a CONTINUATION naming a different stream from
	// the block it continues.
	ViolationContinuationOnAnotherStream
	// ViolationFrameInterleavedInHeaderBlock is §6.2 — a frame other than CONTINUATION appears
	// between a header block's start and its END_HEADERS.
	ViolationFrameInterleavedInHeaderBlock
	// ViolationHeaderBlockNeverTerminated is §6.2 — a header block runs to the end of the program
	// without an END_HEADERS.
	ViolationHeaderBlockNeverTerminated
	// ViolationDataOnUnopenedStream is §5.1 — DATA on a stream no HEADERS in this program opened, so
	// the stream is idle.
	ViolationDataOnUnopenedStream
	// ViolationFrameAfterStreamClosed is §5.1 — a frame sent on a stream this program already
	// finished, by END_STREAM or RST_STREAM. PRIORITY, WINDOW_UPDATE and RST_STREAM stay legal there
	// and are not reported.
	ViolationFrameAfterStreamClosed
	// ViolationPadLengthOctetMissing is §6.1 — PADDED is set but the payload has no octet to carry
	// the pad length.
	ViolationPadLengthOctetMissing
	// ViolationPadLengthExceedsPayload is §6.1 — the pad length is the whole payload or more, so the
	// padding runs past the frame.
	ViolationPadLengthExceedsPayload
)

// Violation is a rule a frame program breaks, as found by Audit.
//
// Frame is an index into H2FrameProgram.Frames, so a report can be shown against the frame that
// caused it rather than as loose prose. Only the fields its Kind names are populated; the rest are
// zero, which for Frame means a Kind that names no frame reads as frame 0 — String is written never
// to print a field its Kind does not name, and callers should not either.
type Violation struct {
	Kind ViolationKind
	// Frame is set for every Kind except ViolationMissingPreface and
	// ViolationHeaderBlockNeverTerminated, which are program-level rather than frame-level.
	Frame int

	// Requested, Written are set for ViolationLengthFieldOverflowed.
	Requested, Written uint32
	// PayloadLen is set for ViolationPayloadExceedsLengthField and ViolationPadLengthExceedsPayload.
	PayloadLen int
	// Declared is the length a peer will act on: set for ViolationDeclaredLengthDisagrees,
	// ViolationFixedLength, ViolationSettingsLengthNotMultipleOfSix, and
	// ViolationSettingsAckWithPayload.
	Declared uint32
	// Actual is the payload actually written, set for ViolationDeclaredLengthDisagrees.
	Actual int
	// Required is set for ViolationFixedLength.
	Required uint32
	// Type is the frame type octet, set for every Kind whose message names the frame type.
	Type uint8
	// StreamID is set for the stream-scoped kinds.
	StreamID uint32
	// Highest is set for ViolationStreamIDNotIncreasing.
	Highest uint32
	// Expected, Found are set for ViolationContinuationOnAnotherStream.
	Expected, Found uint32
	// BlockOpenedAt is set for ViolationFrameInterleavedInHeaderBlock and
	// ViolationHeaderBlockNeverTerminated.
	BlockOpenedAt int
	// ClosedAt is set for ViolationFrameAfterStreamClosed.
	ClosedAt int
	// PadLength is set for ViolationPadLengthExceedsPayload.
	PadLength uint8
}

// RFC is the section that forbids this, for a report an operator can check against the spec.
func (v Violation) RFC() string {
	switch v.Kind {
	case ViolationMissingPreface:
		return "RFC 9113 §3.4"
	case ViolationLengthFieldOverflowed, ViolationPayloadExceedsLengthField,
		ViolationDeclaredLengthDisagrees:
		return "RFC 9113 §4.1"
	case ViolationReservedBitSet, ViolationEvenStreamIDFromClient, ViolationStreamIDNotIncreasing:
		return "RFC 9113 §5.1.1"
	case ViolationStreamIDZeroOnStreamFrame, ViolationStreamIDNonZeroOnConnectionFrame:
		return "RFC 9113 §4.1"
	case ViolationFixedLength:
		return "RFC 9113 §4.2"
	case ViolationSettingsLengthNotMultipleOfSix, ViolationSettingsAckWithPayload:
		return "RFC 9113 §6.5"
	case ViolationPushPromiseFromClient:
		return "RFC 9113 §8.4"
	case ViolationContinuationWithNothingToContinue, ViolationContinuationOnAnotherStream:
		return "RFC 9113 §6.10"
	case ViolationFrameInterleavedInHeaderBlock, ViolationHeaderBlockNeverTerminated:
		return "RFC 9113 §6.2"
	case ViolationDataOnUnopenedStream, ViolationFrameAfterStreamClosed:
		return "RFC 9113 §5.1"
	case ViolationPadLengthOctetMissing, ViolationPadLengthExceedsPayload:
		return "RFC 9113 §6.1"
	default:
		// An unrecognised kind cites nothing rather than citing something plausible: a wrong section
		// in a report is worse than an admitted gap. RFC() callers that assert the "RFC 9113 §"
		// prefix will fail loudly on it, which is the intent.
		return "unrecognised violation"
	}
}

// String renders the violation as a sentence an operator can read, naming only the fields this Kind
// populates.
func (v Violation) String() string {
	switch v.Kind {
	case ViolationMissingPreface:
		return "the connection preface is not sent"
	case ViolationLengthFieldOverflowed:
		return fmt.Sprintf("frame %d: declared length %d does not fit 24 bits; the field carries %d",
			v.Frame, v.Requested, v.Written)
	case ViolationPayloadExceedsLengthField:
		return fmt.Sprintf("frame %d: a %d-octet payload cannot be described by a 24-bit length; "+
			"the field carries %d", v.Frame, v.PayloadLen, MaxFramePayload)
	case ViolationDeclaredLengthDisagrees:
		return fmt.Sprintf("frame %d: declares %d octets, writes %d", v.Frame, v.Declared, v.Actual)
	case ViolationReservedBitSet:
		return fmt.Sprintf("frame %d: the stream-id reserved bit is set", v.Frame)
	case ViolationStreamIDZeroOnStreamFrame:
		return fmt.Sprintf("frame %d: %s names stream 0", v.Frame, tyLabel(v.Type))
	case ViolationStreamIDNonZeroOnConnectionFrame:
		return fmt.Sprintf("frame %d: %s names stream %d rather than the connection",
			v.Frame, tyLabel(v.Type), v.StreamID)
	case ViolationEvenStreamIDFromClient:
		return fmt.Sprintf("frame %d: a client opened even stream %d", v.Frame, v.StreamID)
	case ViolationStreamIDNotIncreasing:
		return fmt.Sprintf("frame %d: opens stream %d after already opening %d",
			v.Frame, v.StreamID, v.Highest)
	case ViolationFixedLength:
		return fmt.Sprintf("frame %d: %s declares %d octets, must declare %d",
			v.Frame, tyLabel(v.Type), v.Declared, v.Required)
	case ViolationSettingsLengthNotMultipleOfSix:
		return fmt.Sprintf("frame %d: SETTINGS declares %d octets, not a multiple of six",
			v.Frame, v.Declared)
	case ViolationSettingsAckWithPayload:
		return fmt.Sprintf("frame %d: SETTINGS with ACK declares %d octets, must be empty",
			v.Frame, v.Declared)
	case ViolationPushPromiseFromClient:
		return fmt.Sprintf("frame %d: PUSH_PROMISE sent by a client", v.Frame)
	case ViolationContinuationWithNothingToContinue:
		return fmt.Sprintf("frame %d: CONTINUATION with no open header block before it", v.Frame)
	case ViolationContinuationOnAnotherStream:
		return fmt.Sprintf("frame %d: CONTINUATION names stream %d, continuing a block on %d",
			v.Frame, v.Found, v.Expected)
	case ViolationFrameInterleavedInHeaderBlock:
		return fmt.Sprintf("frame %d: %s interleaved inside the header block opened at frame %d",
			v.Frame, tyLabel(v.Type), v.BlockOpenedAt)
	case ViolationHeaderBlockNeverTerminated:
		return fmt.Sprintf("the header block opened at frame %d on stream %d is never terminated",
			v.BlockOpenedAt, v.StreamID)
	case ViolationDataOnUnopenedStream:
		return fmt.Sprintf("frame %d: DATA on stream %d, which no HEADERS opened",
			v.Frame, v.StreamID)
	case ViolationFrameAfterStreamClosed:
		return fmt.Sprintf("frame %d: %s on stream %d, finished at frame %d",
			v.Frame, tyLabel(v.Type), v.StreamID, v.ClosedAt)
	case ViolationPadLengthOctetMissing:
		return fmt.Sprintf("frame %d: PADDED is set but the payload is empty", v.Frame)
	case ViolationPadLengthExceedsPayload:
		return fmt.Sprintf("frame %d: pad length %d does not fit a %d-octet payload",
			v.Frame, v.PadLength, v.PayloadLen)
	default:
		return fmt.Sprintf("frame %d breaks a rule this build cannot name (kind %d)",
			v.Frame, v.Kind)
	}
}

// tyLabel is a registered type name, or the octet when the registry does not define one.
//
// Never invents a name for an unregistered type: rendering 0xEF as UNKNOWN invites reading it as
// something the spec has an opinion about.
func tyLabel(ty uint8) string {
	if name, ok := TypeName(ty); ok {
		return name
	}
	return fmt.Sprintf("type 0x%02X", ty)
}

// Audit reports every rule the program breaks, in the order the frames appear.
//
// Reports rather than refuses — that is the whole point. An empty result means the framing is
// compliant as far as the checks listed in this file's header go; it does not mean the program is
// well formed at the HPACK or field-validity layer, neither of which framing can see. The list of
// what is deliberately not checked is in that header, and a caller rendering this report should carry
// that list with it.
func Audit(program H2FrameProgram) []Violation {
	var out []Violation
	if !program.Preface {
		out = append(out, Violation{Kind: ViolationMissingPreface})
	}

	// The block a CONTINUATION would be continuing: the frame that opened it, and its stream.
	blockOpen := false
	var blockOpenedAt int
	var blockStream uint32
	opened := map[uint32]bool{}
	var highestOpened uint32
	// Streams this program finished, and the frame that finished them.
	finished := map[uint32]int{}

	for i := range program.Frames {
		spec := program.Frames[i]
		ty := spec.Type
		stream := spec.StreamID & ^StreamIDReservedBit
		// What a peer will read: the header's 24 bits, after any truncation the field forces.
		declared := spec.Header().Len & MaxFramePayload

		if spec.DeclaredLen != nil {
			if *spec.DeclaredLen > MaxFramePayload {
				out = append(out, Violation{
					Kind:      ViolationLengthFieldOverflowed,
					Frame:     i,
					Requested: *spec.DeclaredLen,
					Written:   declared,
				})
			}
		} else if len(spec.Payload) > int(MaxFramePayload) {
			out = append(out, Violation{
				Kind:       ViolationPayloadExceedsLengthField,
				Frame:      i,
				PayloadLen: len(spec.Payload),
			})
		}
		if spec.DeclaredLen != nil && spec.LengthIsDishonest() {
			out = append(out, Violation{
				Kind:     ViolationDeclaredLengthDisagrees,
				Frame:    i,
				Declared: *spec.DeclaredLen,
				Actual:   len(spec.Payload),
			})
		}
		if spec.StreamID&StreamIDReservedBit != 0 {
			out = append(out, Violation{Kind: ViolationReservedBitSet, Frame: i})
		}

		switch ty {
		case TypeData, TypeHeaders, TypePriority, TypeRSTStream, TypePushPromise, TypeContinuation:
			if stream == 0 {
				out = append(out, Violation{
					Kind: ViolationStreamIDZeroOnStreamFrame, Frame: i, Type: ty,
				})
			}
		case TypeSettings, TypePing, TypeGoAway:
			if stream != 0 {
				out = append(out, Violation{
					Kind:     ViolationStreamIDNonZeroOnConnectionFrame,
					Frame:    i,
					Type:     ty,
					StreamID: stream,
				})
			}
			// WINDOW_UPDATE is legal on the connection and on a stream (§6.9), and an unregistered
			// type has no stream rule to break — a receiver must discard it whatever it names.
		}

		if required, fixed := fixedFrameLength(ty); fixed && declared != required {
			out = append(out, Violation{
				Kind:     ViolationFixedLength,
				Frame:    i,
				Type:     ty,
				Declared: declared,
				Required: required,
			})
		}
		if ty == TypeSettings {
			if declared%6 != 0 {
				out = append(out, Violation{
					Kind: ViolationSettingsLengthNotMultipleOfSix, Frame: i, Declared: declared,
				})
			}
			if spec.Flags&FlagAck != 0 && declared != 0 {
				out = append(out, Violation{
					Kind: ViolationSettingsAckWithPayload, Frame: i, Declared: declared,
				})
			}
		}
		if ty == TypePushPromise {
			out = append(out, Violation{Kind: ViolationPushPromiseFromClient, Frame: i})
		}

		if (ty == TypeData || ty == TypeHeaders || ty == TypePushPromise) &&
			spec.Flags&FlagPadded != 0 {
			if len(spec.Payload) == 0 {
				out = append(out, Violation{Kind: ViolationPadLengthOctetMissing, Frame: i})
			} else if pad := spec.Payload[0]; int(pad)+1 > len(spec.Payload) {
				out = append(out, Violation{
					Kind:       ViolationPadLengthExceedsPayload,
					Frame:      i,
					PadLength:  pad,
					PayloadLen: len(spec.Payload),
				})
			}
		}

		if blockOpen {
			if ty != TypeContinuation {
				out = append(out, Violation{
					Kind:          ViolationFrameInterleavedInHeaderBlock,
					Frame:         i,
					Type:          ty,
					BlockOpenedAt: blockOpenedAt,
				})
			} else if stream != blockStream {
				out = append(out, Violation{
					Kind:     ViolationContinuationOnAnotherStream,
					Frame:    i,
					Expected: blockStream,
					Found:    stream,
				})
			}
			// END_HEADERS closes the block whichever stream the CONTINUATION named. Holding it open
			// would report every later frame as interleaved too, burying the one violation that
			// matters under a cascade of consequences.
			if ty == TypeContinuation && spec.Flags&FlagEndHeaders != 0 {
				blockOpen = false
			}
		} else {
			if ty == TypeContinuation {
				out = append(out, Violation{
					Kind: ViolationContinuationWithNothingToContinue, Frame: i,
				})
			} else if (ty == TypeHeaders || ty == TypePushPromise) &&
				spec.Flags&FlagEndHeaders == 0 {
				blockOpen, blockOpenedAt, blockStream = true, i, stream
			}
		}

		if closedAt, ok := finished[stream]; ok {
			// PRIORITY, WINDOW_UPDATE and RST_STREAM stay legal on a stream we have finished with;
			// anything else is a send on a half-closed(local) or closed stream.
			if ty != TypePriority && ty != TypeWindowUpdate && ty != TypeRSTStream {
				out = append(out, Violation{
					Kind:     ViolationFrameAfterStreamClosed,
					Frame:    i,
					Type:     ty,
					StreamID: stream,
					ClosedAt: closedAt,
				})
			}
		}
		// Stream 0 is never opened, so DATA there is idle too — but it already earns
		// ViolationStreamIDZeroOnStreamFrame, and reporting one octet twice makes a report harder to
		// read.
		if ty == TypeData && stream != 0 && !opened[stream] {
			out = append(out, Violation{
				Kind: ViolationDataOnUnopenedStream, Frame: i, StreamID: stream,
			})
		}

		// HEADERS on a stream already open is trailers, which is legal and opens nothing.
		if ty == TypeHeaders && stream != 0 && !opened[stream] {
			if stream%2 == 0 {
				out = append(out, Violation{
					Kind: ViolationEvenStreamIDFromClient, Frame: i, StreamID: stream,
				})
			}
			if stream <= highestOpened {
				out = append(out, Violation{
					Kind:     ViolationStreamIDNotIncreasing,
					Frame:    i,
					StreamID: stream,
					Highest:  highestOpened,
				})
			}
			opened[stream] = true
			if stream > highestOpened {
				highestOpened = stream
			}
		}
		if ty == TypeRSTStream ||
			((ty == TypeData || ty == TypeHeaders) && spec.Flags&FlagEndStream != 0) {
			if _, already := finished[stream]; !already {
				finished[stream] = i
			}
		}
	}

	if blockOpen {
		out = append(out, Violation{
			Kind:          ViolationHeaderBlockNeverTerminated,
			BlockOpenedAt: blockOpenedAt,
			StreamID:      blockStream,
		})
	}

	return out
}

// fixedFrameLength is the length §6.3/§6.4/§6.7/§6.9 fix for a frame type, and whether the type has
// one at all. A switch rather than a map: the set is closed by the RFC, and a map lookup that missed
// would read as "no rule" rather than as a gap.
func fixedFrameLength(ty uint8) (uint32, bool) {
	switch ty {
	case TypePriority:
		return 5, true
	case TypeRSTStream:
		return 4, true
	case TypePing:
		return 8, true
	case TypeWindowUpdate:
		return 4, true
	}
	return 0, false
}
