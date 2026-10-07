package grpcproto

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

// A real protobuf message, hand-encoded, exercises every wire type and a nested message:
//
//	field 1 (varint) = 150
//	field 2 (string) = "testing"
//	field 3 (message) { field 1 (varint) = 42 }
//	field 4 (i32 fixed32) = 7
//	field 5 (i64 fixed64) = 1<<40
func sampleMessage(t *testing.T) []byte {
	t.Helper()
	fields := []Field{
		{Number: 1, WireType: wireVarint, Varint: "150"},
		{Number: 2, WireType: wireLen, LenKind: LenString, String: "testing"},
		{Number: 3, WireType: wireLen, LenKind: LenMessage, Message: []Field{{Number: 1, WireType: wireVarint, Varint: "42"}}},
		{Number: 4, WireType: wireI32, I32: 7},
		{Number: 5, WireType: wireI64, I64: "1099511627776"},
	}
	raw, err := Encode(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecodeEncodeRoundTripsEveryWireType(t *testing.T) {
	raw := sampleMessage(t)
	fields, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(fields) != 5 {
		t.Fatalf("got %d fields, want 5: %+v", len(fields), fields)
	}
	if fields[0].Varint != "150" || fields[1].String != "testing" || fields[3].I32 != 7 || fields[4].I64 != "1099511627776" {
		t.Errorf("decoded values wrong: %+v", fields)
	}
	if fields[2].LenKind != LenMessage || len(fields[2].Message) != 1 || fields[2].Message[0].Varint != "42" {
		t.Errorf("nested message wrong: %+v", fields[2])
	}
	// Re-encode must reproduce the exact bytes.
	back, err := Encode(fields)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(back, raw) {
		t.Errorf("round-trip changed the bytes:\n in:  %s\n out: %s", hex.EncodeToString(raw), hex.EncodeToString(back))
	}
}

// Editing a single field and re-encoding changes only that field's bytes — the tamper the operator
// made and nothing else.
func TestEditingOneFieldReEncodes(t *testing.T) {
	fields, _ := Decode(sampleMessage(t))
	fields[1].String = "TAMPERED"
	back, err := Encode(fields)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Decode(back)
	if err != nil {
		t.Fatal(err)
	}
	if again[1].String != "TAMPERED" || again[0].Varint != "150" {
		t.Errorf("edit did not apply cleanly: %+v", again)
	}
}

// A length-delimited field whose bytes are not a message and not UTF-8 is shown as hex and
// round-trips.
func TestOpaqueBytesFieldRoundTrips(t *testing.T) {
	in := []Field{{Number: 1, WireType: wireLen, LenKind: LenBytes, BytesHex: "00ff80"}}
	raw, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].LenKind != LenBytes || out[0].BytesHex != "00ff80" {
		t.Errorf("opaque bytes field = %+v", out[0])
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	// A length-delimited field claiming more bytes than exist.
	if _, err := Decode([]byte{0x0a, 0x05, 0x01}); err == nil {
		t.Error("a truncated length-delimited field was accepted")
	}
}

// gRPC framing: one message framed and unframed round-trips; a multi-frame body splits.
func TestGRPCFramingRoundTrips(t *testing.T) {
	msg := sampleMessage(t)
	framed := FrameMessage(msg)
	if len(framed) != 5+len(msg) || framed[0] != 0 {
		t.Fatalf("frame header wrong: %s", hex.EncodeToString(framed[:5]))
	}
	frames, err := Unframe(framed)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || !bytes.Equal(frames[0].Message, msg) || frames[0].Compressed {
		t.Errorf("unframe wrong: %+v", frames)
	}
	// Reframe reproduces the body.
	if !bytes.Equal(Reframe(frames), framed) {
		t.Error("reframe did not reproduce the body")
	}
	// Two frames.
	two := append(FrameMessage([]byte("a")), FrameMessage([]byte("bb"))...)
	fs, err := Unframe(two)
	if err != nil || len(fs) != 2 || string(fs[0].Message) != "a" || string(fs[1].Message) != "bb" {
		t.Errorf("two-frame split wrong: %+v (%v)", fs, err)
	}
}

func TestContentTypeDetection(t *testing.T) {
	for _, ct := range []string{"application/grpc", "application/grpc+proto", "application/grpc-web", "application/grpc-web+proto; charset=utf-8"} {
		if !IsGRPCContentType(ct) {
			t.Errorf("IsGRPCContentType(%q) = false", ct)
		}
	}
	if IsGRPCContentType("application/json") {
		t.Error("json read as grpc")
	}
	if !IsProtobufContentType("application/x-protobuf") || IsProtobufContentType("application/grpc") {
		t.Error("protobuf content-type detection wrong")
	}
}

// A truncated gRPC frame header is an error, not a wrong decode.
func TestUnframeRejectsTruncation(t *testing.T) {
	if _, err := Unframe([]byte{0x00, 0x00, 0x00}); err == nil {
		t.Error("a truncated frame header was accepted")
	}
	if _, err := Unframe([]byte{0x00, 0x00, 0x00, 0x00, 0x09, 0x01}); err == nil {
		t.Error("a frame declaring bytes past the body was accepted")
	}
}

func TestDeepNestingRoundTrips(t *testing.T) {
	in := []Field{{Number: 1, WireType: wireLen, LenKind: LenMessage, Message: []Field{
		{Number: 1, WireType: wireLen, LenKind: LenMessage, Message: []Field{
			{Number: 1, WireType: wireVarint, Varint: "7"},
		}},
	}}}
	raw, _ := Encode(in)
	out, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("deep nesting did not round-trip:\n in:  %+v\n out: %+v", in, out)
	}
}
