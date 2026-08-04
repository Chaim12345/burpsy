package http2

import (
	"encoding/binary"
)

// The HTTP/2 frame layer: a 9-octet header, a writer that corrects nothing, and a reader that
// reports what it could not finish.
//
// # Why this is hand-written, next to a conformant library that already works
//
// The proxy's HTTP/2 transport (h2_relay.go, sender/h2.go, and the RenderRequest/RenderResponse
// half of this package) runs on golang.org/x/net/http2, and nothing here replaces it. This layer
// exists for the one capability that library structurally cannot provide: burpsy's reason to exist
// includes request smuggling, and a smuggling probe is a frame the spec forbids — a length field
// that disagrees with the payload, stream id 0 on a stream frame, an even client-initiated id, the
// reserved bit set, CONTINUATION with nothing to continue. A spec-compliant library refuses to emit
// those, correctly, that is its purpose; and it equally refuses to *show you* one a peer sent,
// because it resets the stream before the octets reach you.
//
// So this layer's contract is the inverse of a library's: **it never corrects its input, and it
// never discards what it cannot parse.**
//
// # This layer emits octets; it does not send them
//
// Encode returns bytes and Audit (malformed.go) returns a report about them. Nothing here opens a
// connection, and nothing in internal/sender or internal/proxy calls into it — deliberately.
// Authorising a malformed frame program is a harder problem than authorising a request: a program
// with a dishonest length, a raw header-block fragment, or an unterminated header block cannot have
// its `:path` fields authorised individually, because the peer will not decode the block we
// decoded. That classifier does not exist yet in either language, so today Audit is the capability
// an operator can actually reach from here, and saying otherwise would be an overclaim.
//
// # Byte order
//
// Big-endian, throughout — HTTP/2 is network order. Worth stating because core.RecordHeader's
// on-disk record header is deliberately little-endian, and the two live one package apart.
//
// # Divergences from crates/http2/src/frame.rs, which is this layer's spec
//
// The wire layout is the Rust one, field for field. Six things differ, all named, none of them
// behavioural:
//
//   - Rust namespaces the wire constants in `mod types` and `mod flags` (`types::DATA`,
//     `flags::END_HEADERS`). Go has no nested namespace inside a package, so they are prefixed:
//     TypeData, FlagEndHeaders. TypeName is `types::name`.
//   - Rust's `CONNECTION_PREFACE` is a `&[u8; 24]`. Go cannot make a byte slice constant, and an
//     exported `var` would let any caller in the binary rewrite the preface for every other caller,
//     so it is an untyped string constant; `[]byte(ConnectionPreface)` or `append(out,
//     ConnectionPreface...)` where octets are wanted.
//   - `FrameSpec.declared_len: Option<u32>` becomes `*uint32`. A `uint32` plus a `bool` would let a
//     caller set the number and forget the flag, silently emitting an honest length — which is
//     exactly the class of silent correction this layer exists to refuse. A pointer cannot be
//     half-set; use WithDeclaredLen to build one.
//   - `Tail::Incomplete { need: Option<usize> }` becomes `Tail` with a `Need`/`NeedKnown` pair (the
//     Kind-plus-union-of-fields shape core.CorruptRecord established for a Rust enum with
//     per-variant payload). The pair is safe here where the pointer was needed above, because a
//     Tail is *produced* by ReadFrames as a report, never hand-built as an intent.
//   - Rust's `H2FrameProgram::default()` sets `preface: true, read_for_ms: 2000`; Go's zero value
//     cannot. NewH2FrameProgram is the equivalent. A zero-valued H2FrameProgram is a program with no
//     preface, which Audit reports as ViolationMissingPreface rather than silently sending one.
//   - ReadFrames copies each payload out of the input, where Rust's `Bytes::copy_from_slice` does
//     the same. Stated because Go slices alias by default: a RawFrame must stay valid after the read
//     buffer it came from is reused.
const (
	// FrameHeaderLen is length(3) + type(1) + flags(1) + stream_id(4).
	FrameHeaderLen = 9

	// MaxFramePayload is the largest value a 24-bit length field can carry, and therefore the
	// largest payload a frame can declare. Not a policy choice — it is what the field can hold.
	MaxFramePayload uint32 = 0x00FF_FFFF

	// ConnectionPreface is the client connection preface, RFC 9113 §3.4. Sent verbatim before any
	// frame.
	ConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// StreamIDReservedBit is the reserved bit at the top of the stream-id field.
	//
	// The spec says a sender must leave it clear and a receiver must ignore it. Both halves are
	// things a tester needs to violate and observe, so this layer carries the full 32 bits and never
	// masks them away — see FrameHeader.StreamID.
	StreamIDReservedBit uint32 = 0x8000_0000
)

// The registered frame type octets, RFC 9113 §11.2.
//
// Constants rather than a defined type with a fixed set of values, for the reason FrameHeader gives:
// an unregistered type octet is a research target, and a narrower type would either reject it or
// lose it. Nothing here narrows what FrameSpec accepts — 0xEF is as valid an input as TypeData, and
// the writer emits both. These exist so a caller and a violation report can say HEADERS instead of
// 0x1.
const (
	TypeData         uint8 = 0x0
	TypeHeaders      uint8 = 0x1
	TypePriority     uint8 = 0x2
	TypeRSTStream    uint8 = 0x3
	TypeSettings     uint8 = 0x4
	TypePushPromise  uint8 = 0x5
	TypePing         uint8 = 0x6
	TypeGoAway       uint8 = 0x7
	TypeWindowUpdate uint8 = 0x8
	TypeContinuation uint8 = 0x9
)

// The defined flag bits.
//
// One bit position means different things on different frame types — 0x01 is END_STREAM on DATA and
// HEADERS but ACK on SETTINGS and PING — so these are named per meaning, not per position, and a
// caller has to know which frame it is setting a flag on. Undefined bits (0x02, 0x10, 0x40, 0x80)
// have no constant precisely because their only use here is to be set deliberately.
const (
	// FlagEndStream is DATA, HEADERS.
	FlagEndStream uint8 = 0x01
	// FlagAck is SETTINGS, PING. Same bit as FlagEndStream, different frames.
	FlagAck uint8 = 0x01
	// FlagEndHeaders is HEADERS, PUSH_PROMISE, CONTINUATION.
	FlagEndHeaders uint8 = 0x04
	// FlagPadded is DATA, HEADERS, PUSH_PROMISE.
	FlagPadded uint8 = 0x08
	// FlagPriority is HEADERS.
	FlagPriority uint8 = 0x20
)

// TypeName reports the registered name for a type octet, and false for one the registry does not
// define.
//
// False rather than a "UNKNOWN(0xEF)" string: a report that renders an unknown type as if it were a
// name invites reading it as one.
func TypeName(ty uint8) (string, bool) {
	switch ty {
	case TypeData:
		return "DATA", true
	case TypeHeaders:
		return "HEADERS", true
	case TypePriority:
		return "PRIORITY", true
	case TypeRSTStream:
		return "RST_STREAM", true
	case TypeSettings:
		return "SETTINGS", true
	case TypePushPromise:
		return "PUSH_PROMISE", true
	case TypePing:
		return "PING", true
	case TypeGoAway:
		return "GOAWAY", true
	case TypeWindowUpdate:
		return "WINDOW_UPDATE", true
	case TypeContinuation:
		return "CONTINUATION", true
	}
	return "", false
}

// FrameHeader is one frame's header, exactly as it appears on the wire.
//
// Every field is the raw wire field. Type and Flags are integers rather than a narrower type
// because an unknown type and a reserved flag bit are both research targets — anything narrower
// would either reject them or lose them.
type FrameHeader struct {
	// Len is the 24-bit length field as written. It may disagree with the payload that follows;
	// that disagreement is the point of several probes.
	Len   uint32
	Type  uint8
	Flags uint8
	// StreamID is the full 32-bit field, reserved bit included. Use StreamIDMasked for the 31-bit
	// identifier and ReservedBitSet to ask about the top bit.
	StreamID uint32
}

// StreamIDMasked is the 31-bit stream identifier, with the reserved bit cleared.
func (h FrameHeader) StreamIDMasked() uint32 {
	return h.StreamID & ^StreamIDReservedBit
}

// ReservedBitSet reports whether the reserved top bit is set — something a compliant peer never
// does, and therefore worth being able to see.
func (h FrameHeader) ReservedBitSet() bool {
	return h.StreamID&StreamIDReservedBit != 0
}

// Encode lays out the nine octets, big-endian. Writes Len as given, truncating to 24 bits because
// the field is 24 bits, and reports nothing, because a caller who set a larger value chose to.
//
// This truncation is one of the two places in the whole layer where the writer cannot do as it was
// told. It is not hidden: Audit reports it as ViolationLengthFieldOverflowed.
func (h FrameHeader) Encode() [FrameHeaderLen]byte {
	var out [FrameHeaderLen]byte
	out[0] = byte(h.Len >> 16)
	out[1] = byte(h.Len >> 8)
	out[2] = byte(h.Len)
	out[3] = h.Type
	out[4] = h.Flags
	binary.BigEndian.PutUint32(out[5:9], h.StreamID)
	return out
}

// DecodeFrameHeader reads nine octets. Total — every 9-byte input is a valid header, because every
// field is raw.
//
// Reports false only when there are fewer than nine bytes, which is a framing question rather than
// a validity one.
func DecodeFrameHeader(b []byte) (FrameHeader, bool) {
	if len(b) < FrameHeaderLen {
		return FrameHeader{}, false
	}
	return FrameHeader{
		Len:      uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]),
		Type:     b[3],
		Flags:    b[4],
		StreamID: binary.BigEndian.Uint32(b[5:9]),
	}, true
}

// FrameSpec is a frame to emit.
//
// Payload is bytes at this layer, deliberately. HPACK encoding is a different concern with a
// different failure mode, so a header list becomes bytes *before* it reaches the writer — which
// also means the writer has exactly one input shape and no branch that could treat a header block
// specially.
type FrameSpec struct {
	Type     uint8
	Flags    uint8
	StreamID uint32
	// DeclaredLen nil writes the payload's true length. Non-nil writes what it points at, whatever
	// the payload is.
	//
	// This is the single most useful lie the layer can tell: a receiver frames the connection by the
	// declared length, so a short value truncates the block it reads and a long one swallows the
	// next frame's octets into it.
	//
	// A pointer rather than a value-plus-flag pair, for the reason given in this file's divergence
	// list: a half-set pair would silently emit an honest length. WithDeclaredLen builds one.
	DeclaredLen *uint32
	Payload     []byte
}

// NewFrameSpec builds a frame whose declared length is honest.
func NewFrameSpec(ty, flags uint8, streamID uint32, payload []byte) FrameSpec {
	return FrameSpec{Type: ty, Flags: flags, StreamID: streamID, Payload: payload}
}

// WithDeclaredLen declares a length other than the payload's own, chainable.
func (s FrameSpec) WithDeclaredLen(n uint32) FrameSpec {
	s.DeclaredLen = &n
	return s
}

// Header is the header this spec will emit.
//
// When DeclaredLen is nil and the payload is longer than a 24-bit field can describe, the field
// carries MaxFramePayload: there is no honest value, and this is the second of the layer's two
// irreducible silent corrections. Audit reports it as ViolationPayloadExceedsLengthField.
func (s FrameSpec) Header() FrameHeader {
	var length uint32
	switch {
	case s.DeclaredLen != nil:
		length = *s.DeclaredLen
	case len(s.Payload) > int(MaxFramePayload):
		length = MaxFramePayload
	default:
		length = uint32(len(s.Payload))
	}
	return FrameHeader{Len: length, Type: s.Type, Flags: s.Flags, StreamID: s.StreamID}
}

// LengthIsDishonest reports whether the declared length disagrees with the payload actually
// written.
//
// The authorisation layer needs this: a program that lies about a length cannot have its header
// block authorised field-by-field, because the peer will not decode the block we decoded.
func (s FrameSpec) LengthIsDishonest() bool {
	return s.DeclaredLen != nil && uint64(*s.DeclaredLen) != uint64(len(s.Payload))
}

// H2FrameProgram is an ordered list of frames to put on one fresh connection, then read from.
type H2FrameProgram struct {
	// Preface says whether to send the 24-octet client preface first. Omitting it is a research
	// target.
	Preface bool
	Frames  []FrameSpec
	// ReadForMS is how long to keep reading after the last frame is written. Carried for the
	// transport that will eventually run a program; nothing in this package reads it.
	ReadForMS uint64
}

// NewH2FrameProgram is Rust's H2FrameProgram::default(): preface on, a two-second read window, no
// frames. Go's zero value cannot carry those, and a zero-valued program is a program with no
// preface — which Audit reports rather than quietly fixing.
func NewH2FrameProgram(frames ...FrameSpec) H2FrameProgram {
	return H2FrameProgram{Preface: true, Frames: frames, ReadForMS: 2_000}
}

// Encode serialises the whole program. Corrects nothing, reorders nothing, adds nothing.
func (p H2FrameProgram) Encode() []byte {
	size := 0
	if p.Preface {
		size += len(ConnectionPreface)
	}
	for i := range p.Frames {
		size += FrameHeaderLen + len(p.Frames[i].Payload)
	}
	out := make([]byte, 0, size)
	if p.Preface {
		out = append(out, ConnectionPreface...)
	}
	for i := range p.Frames {
		head := p.Frames[i].Header().Encode()
		out = append(out, head[:]...)
		out = append(out, p.Frames[i].Payload...)
	}
	return out
}

// FrameLayoutIsHonest reports whether every frame's length field agrees with the payload actually
// written.
//
// A lying length makes a program's effect on a peer un-inferable from our own decode — the peer
// frames by the declared value, so it decodes a header block we never saw — which is why the
// authorisation layer treats such a program as a whole-host question rather than a per-path one.
//
// This is one of the authorisation layer's triggers, not all of them. An unterminated header block,
// a CONTINUATION, and a raw header-block fragment each have the same consequence and none of them
// is a length question; Audit reports those, and the classifier that combines them is the
// authorisation layer's own.
func (p H2FrameProgram) FrameLayoutIsHonest() bool {
	for i := range p.Frames {
		if p.Frames[i].LengthIsDishonest() {
			return false
		}
	}
	return true
}

// RawFrame is a frame read off the wire, with the octets it was cut from.
type RawFrame struct {
	Header FrameHeader
	// Payload is exactly Header.Len octets, copied out of the input. What the peer framed, not what
	// it should have.
	Payload []byte
	// Offset is where this frame's header sits within the stream it was read from, so a fault can
	// name where.
	Offset int
}

// TailKind names what was left over after reading as many whole frames as possible.
type TailKind int

const (
	// TailComplete means every octet was consumed by a whole frame.
	TailComplete TailKind = iota
	// TailIncomplete means octets remain that do not form a whole frame.
	//
	// Reported rather than dropped. A truncated tail is frequently the *result* of a probe — a peer
	// that died mid-frame is a finding — so discarding it would discard the answer.
	TailIncomplete
)

// Tail is what ReadFrames could not turn into a whole frame.
//
// Only the fields its Kind names are populated; for TailComplete all of them are zero. This is the
// Go shape of Rust's Tail enum, which carries its fields per variant — see the divergence note at
// the top of this file.
type Tail struct {
	Kind TailKind
	// Offset, Have are set for TailIncomplete: where the leftover starts and how much of it there
	// is.
	Offset, Have int
	// Need is the total octets the leftover frame wanted, valid only when NeedKnown. NeedKnown is
	// false when there is not even a full header, because then the needed total is unknowable and
	// saying so is honest.
	Need      int
	NeedKnown bool
}

// ReadFrames splits a byte stream into whole frames.
//
// Framing follows the **declared** length, because that is what a peer does. A frame declaring more
// than remains does not consume what is there and does not error: it ends the scan and the remainder
// comes back as a TailIncomplete, naming the offset and what was needed.
func ReadFrames(b []byte) ([]RawFrame, Tail) {
	var frames []RawFrame
	at := 0
	for {
		remaining := len(b) - at
		if remaining == 0 {
			return frames, Tail{Kind: TailComplete}
		}
		header, ok := DecodeFrameHeader(b[at:])
		if !ok {
			return frames, Tail{Kind: TailIncomplete, Offset: at, Have: remaining}
		}
		want := FrameHeaderLen + int(header.Len)
		if remaining < want {
			return frames, Tail{
				Kind: TailIncomplete, Offset: at, Have: remaining, Need: want, NeedKnown: true,
			}
		}
		start := at + FrameHeaderLen
		// Copied, not aliased: a RawFrame must stay valid after the read buffer is reused.
		payload := make([]byte, header.Len)
		copy(payload, b[start:start+int(header.Len)])
		frames = append(frames, RawFrame{Header: header, Payload: payload, Offset: at})
		at += want
	}
}

// StripPreface removes the client preface if present, returning the rest.
//
// Reports false when the input begins with something else — a peer that did not send it, or a
// program that deliberately omitted it.
func StripPreface(b []byte) ([]byte, bool) {
	if len(b) < len(ConnectionPreface) || string(b[:len(ConnectionPreface)]) != ConnectionPreface {
		return nil, false
	}
	return b[len(ConnectionPreface):], true
}
