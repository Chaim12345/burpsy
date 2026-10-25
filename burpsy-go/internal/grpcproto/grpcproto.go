// Package grpcproto decodes and re-encodes protobuf wire bytes without a .proto schema
// (burpsy-react-ui-3x2g), so an operator can read and tamper with a single field of an otherwise
// opaque gRPC/protobuf body in the editor, history and Repeater.
//
// The protobuf wire format is self-describing enough to walk without a schema: every field is a tag
// (a varint whose low three bits are the wire type and whose rest is the field number) followed by a
// value whose shape the wire type fixes. What a schema would add is the *meaning* of each field — its
// name and declared type — which this package deliberately does without; name resolution from a
// .proto or a gRPC reflection response is a separate, larger piece.
//
// The one genuine ambiguity a schemaless walk cannot resolve is a length-delimited field (wire type
// 2): the bytes could be a nested message, a UTF-8 string, or opaque bytes. Decode guesses — a buffer
// that parses cleanly as protobuf is shown as a nested message, otherwise valid UTF-8 is a string and
// the rest is bytes — and records which guess it made so Encode reproduces it. A guess is only ever a
// presentation choice; the bytes round-trip exactly either way.
package grpcproto

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf8"
)

// Wire types (protobuf). 3 and 4 are the deprecated group start/end and are not supported — they do
// not occur in modern protobuf and a body using them is left to the raw/hex view.
const (
	wireVarint = 0
	wireI64    = 1
	wireLen    = 2
	wireI32    = 5
)

// LenKind is how a length-delimited field's bytes are presented.
type LenKind string

const (
	// LenMessage: the bytes parsed cleanly as a nested protobuf message.
	LenMessage LenKind = "message"
	// LenString: the bytes are valid UTF-8 and did not parse as a message.
	LenString LenKind = "string"
	// LenBytes: opaque bytes, shown as hex.
	LenBytes LenKind = "bytes"
)

// Field is one decoded protobuf field. Exactly the members its WireType selects are meaningful;
// the JSON tags are what the editor reads and writes.
//
// Varint and I64 are carried as decimal STRINGS, not numbers: a uint64 exceeds JavaScript's safe
// integer range, and a field value silently rounded on the way to the browser and back would be a
// tamper the operator did not make.
type Field struct {
	Number   int     `json:"number"`
	WireType int     `json:"wire_type"`
	Varint   string  `json:"varint,omitempty"` // wire 0, as decimal
	I64      string  `json:"i64,omitempty"`    // wire 1, as decimal
	I32      uint32  `json:"i32,omitempty"`    // wire 5
	LenKind  LenKind `json:"len_kind,omitempty"`
	String   string  `json:"string,omitempty"`    // wire 2, LenString
	BytesHex string  `json:"bytes_hex,omitempty"` // wire 2, LenBytes
	Message  []Field `json:"message,omitempty"`   // wire 2, LenMessage

	// Name, Type and EnumName are filled by Schema.Annotate when a .proto was supplied
	// (burpsy-react-ui-3pco) and are presentation only: Encode ignores them, so an annotated tree and
	// a bare one encode to the same bytes. Empty means the field is not in the schema (or there is no
	// schema), and the editor falls back to the number and wire type.
	Name     string `json:"name,omitempty"`      // declared field name
	Type     string `json:"type,omitempty"`      // declared type, e.g. "int32", "repeated string"
	EnumName string `json:"enum_name,omitempty"` // for an enum-typed varint, the value's name
	// Packed lists the values of a declared repeated numeric scalar riding the
	// wire as one packed length-delimited field (0rrb). Presentation only, like
	// Name/Type/EnumName: Encode ignores it, and the length-delimited field's
	// own bytes carry the values on re-encode.
	Packed []string `json:"packed,omitempty"`
}

// Decode walks raw as a protobuf message into a flat, ordered list of fields (nested messages recurse
// into Field.Message). It returns an error only when the bytes are not valid protobuf at the top
// level — a truncated tag, a length that runs off the end, an unsupported wire type — so a caller can
// fall back to the hex view rather than present a half-parsed tree.
func Decode(raw []byte) ([]Field, error) {
	fields, n, err := decodeMessage(raw)
	if err != nil {
		return nil, err
	}
	if n != len(raw) {
		return nil, fmt.Errorf("protobuf: %d trailing bytes after the message", len(raw)-n)
	}
	return fields, nil
}

// decodeMessage parses as many fields as it can from the front of b, returning the fields and how
// many bytes they consumed. It stops at the first byte that is not a valid field, which for a nested
// buffer of exactly one message is its end.
func decodeMessage(b []byte) ([]Field, int, error) {
	var out []Field
	i := 0
	for i < len(b) {
		tag, tn := binary.Uvarint(b[i:])
		if tn <= 0 {
			return nil, 0, fmt.Errorf("protobuf: bad field tag at offset %d", i)
		}
		number := int(tag >> 3)
		wire := int(tag & 7)
		if number == 0 {
			return nil, 0, fmt.Errorf("protobuf: field number 0 at offset %d", i)
		}
		j := i + tn
		f := Field{Number: number, WireType: wire}
		switch wire {
		case wireVarint:
			v, vn := binary.Uvarint(b[j:])
			if vn <= 0 {
				return nil, 0, fmt.Errorf("protobuf: bad varint for field %d", number)
			}
			f.Varint = strconv.FormatUint(v, 10)
			j += vn
		case wireI64:
			if j+8 > len(b) {
				return nil, 0, fmt.Errorf("protobuf: truncated 64-bit field %d", number)
			}
			f.I64 = strconv.FormatUint(binary.LittleEndian.Uint64(b[j:]), 10)
			j += 8
		case wireI32:
			if j+4 > len(b) {
				return nil, 0, fmt.Errorf("protobuf: truncated 32-bit field %d", number)
			}
			f.I32 = binary.LittleEndian.Uint32(b[j:])
			j += 4
		case wireLen:
			length, ln := binary.Uvarint(b[j:])
			if ln <= 0 {
				return nil, 0, fmt.Errorf("protobuf: bad length for field %d", number)
			}
			start := j + ln
			end := start + int(length)
			if int(length) < 0 || end > len(b) || end < start {
				return nil, 0, fmt.Errorf("protobuf: length-delimited field %d runs past the buffer", number)
			}
			payload := b[start:end]
			classifyLen(&f, payload)
			j = end
		default:
			return nil, 0, fmt.Errorf("protobuf: unsupported wire type %d for field %d", wire, number)
		}
		out = append(out, f)
		i = j
	}
	return out, i, nil
}

// classifyLen decides how a length-delimited field's bytes are presented, in the order a decoder
// trusts least-ambiguous first: a non-empty buffer that parses cleanly as a protobuf message is a
// message; otherwise valid UTF-8 is a string; otherwise opaque bytes.
func classifyLen(f *Field, payload []byte) {
	if len(payload) > 0 {
		if msg, n, err := decodeMessage(payload); err == nil && n == len(payload) {
			f.LenKind = LenMessage
			f.Message = msg
			return
		}
	}
	if utf8.Valid(payload) {
		f.LenKind = LenString
		f.String = string(payload)
		return
	}
	f.LenKind = LenBytes
	f.BytesHex = hex.EncodeToString(payload)
}

// Encode renders a field list back to protobuf wire bytes, the inverse of Decode. Fields are written
// in list order, so an operator who reordered or edited the tree gets exactly that on the wire.
func Encode(fields []Field) ([]byte, error) {
	var out []byte
	for _, f := range fields {
		tag := uint64(f.Number)<<3 | uint64(f.WireType)
		out = appendUvarint(out, tag)
		switch f.WireType {
		case wireVarint:
			v, err := strconv.ParseUint(f.Varint, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("protobuf: field %d varint %q: %w", f.Number, f.Varint, err)
			}
			out = appendUvarint(out, v)
		case wireI64:
			v, err := strconv.ParseUint(f.I64, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("protobuf: field %d i64 %q: %w", f.Number, f.I64, err)
			}
			out = binary.LittleEndian.AppendUint64(out, v)
		case wireI32:
			out = binary.LittleEndian.AppendUint32(out, f.I32)
		case wireLen:
			payload, err := encodeLen(f)
			if err != nil {
				return nil, err
			}
			out = appendUvarint(out, uint64(len(payload)))
			out = append(out, payload...)
		default:
			return nil, fmt.Errorf("protobuf: cannot encode wire type %d for field %d", f.WireType, f.Number)
		}
	}
	return out, nil
}

// encodeLen renders the payload of a length-delimited field from whichever presentation it carries.
func encodeLen(f Field) ([]byte, error) {
	switch f.LenKind {
	case LenMessage:
		return Encode(f.Message)
	case LenString:
		return []byte(f.String), nil
	case LenBytes:
		b, err := hex.DecodeString(f.BytesHex)
		if err != nil {
			return nil, fmt.Errorf("protobuf: field %d bytes_hex is not hex: %w", f.Number, err)
		}
		return b, nil
	default:
		// An edited field that lost its len_kind: fall back to the spelling it does carry, string
		// first, so a hand-built field with just a string value still encodes.
		if f.String != "" || (f.Message == nil && f.BytesHex == "") {
			return []byte(f.String), nil
		}
		if f.Message != nil {
			return Encode(f.Message)
		}
		b, err := hex.DecodeString(f.BytesHex)
		if err != nil {
			return nil, fmt.Errorf("protobuf: field %d has no usable length-delimited value", f.Number)
		}
		return b, nil
	}
}

func appendUvarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
