package grpcproto

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The dynamicpb oracle (0rrb 2b): a conforming body validates, and what the raw
// protowire walk skims past is refused honestly.
func TestValidateRefusesWhatTheSchemaCannotHold(t *testing.T) {
	s := mustParse(t, `syntax = "proto3"; message M { int32 n = 1; string s = 2; }`)
	// Conforming: field 1 varint 150, field 2 LEN "hi".
	good, _ := hex.DecodeString("08960112026869")
	if err := s.Validate("M", good); err != nil {
		t.Fatalf("a conforming body must validate: %v", err)
	}
	// Invalid UTF-8 in a declared string: the walk shows hex, the schema says
	// string, and protobuf's unmarshal enforces the encoding.
	badUTF8, _ := hex.DecodeString("0896011201ff")
	err := s.Validate("M", badUTF8)
	if err == nil || !strings.Contains(err.Error(), "M") {
		t.Fatalf("invalid UTF-8 in a declared string must be refused, naming the message: %v", err)
	}
	// An unknown field number is not a violation: the schema may be older than
	// the body.
	newer, _ := hex.DecodeString("0896013001")
	if err := s.Validate("M", newer); err != nil {
		t.Fatalf("an unknown field is not a violation: %v", err)
	}
	// A wire type that does not match the declaration is NOT refused: protobuf's
	// unmarshal carries it as an unknown field by spec (forward compatibility).
	// Pinned so nobody "strengthens" the oracle into rejecting newer bodies.
	mismatch, _ := hex.DecodeString("0a029601")
	if err := s.Validate("M", mismatch); err != nil {
		t.Fatalf("a wire-type mismatch rides as unknown per spec: %v", err)
	}
}

func TestValidateEnforcesProto2Required(t *testing.T) {
	s := mustParse(t, `syntax = "proto2"; message R { required int32 n = 1; optional string s = 2; }`)
	present, _ := hex.DecodeString("089601")
	if err := s.Validate("R", present); err != nil {
		t.Fatalf("required present: %v", err)
	}
	absent, _ := hex.DecodeString("12026869")
	if err := s.Validate("R", absent); err == nil {
		t.Fatal("a missing required field must be refused")
	}
}
