package grpcproto

import (
	"encoding/hex"
	"strings"
	"testing"
)

// A proto3 repeated scalar rides the wire PACKED: one length-delimited field
// holding the values back to back. The schemaless walk shows those bytes as a
// hex blob; Annotate must read them as the repeated numbers they are - as
// presentation only, so the tree still encodes to the same bytes.
func TestAnnotateReadsAPackedRepeatedScalar(t *testing.T) {
	s := mustParse(t, `syntax = "proto3"; message M { repeated int32 nums = 1; repeated fixed32 fs = 2; repeated Status st = 3; }
enum Status { UNKNOWN = 0; ACTIVE = 1; }`)
	raw, _ := hex.DecodeString("0a040102ac02120" + "8" + "0100000002000000" + "1a020001")
	fields, _ := Decode(raw)
	out, err := s.Annotate(fields, "M")
	if err != nil {
		t.Fatal(err)
	}
	nums := find(out, 1)
	if got := strings.Join(nums.Packed, ","); got != "1,2,300" {
		t.Fatalf("packed varints = %q", got)
	}
	if nums.Type != "repeated int32" {
		t.Fatalf("type = %q", nums.Type)
	}
	fs := find(out, 2)
	if got := strings.Join(fs.Packed, ","); got != "1,2" {
		t.Fatalf("packed fixed32 = %q", got)
	}
	st := find(out, 3)
	if got := strings.Join(st.Packed, ","); got != "UNKNOWN,ACTIVE" {
		t.Fatalf("packed enums = %q", got)
	}
	assertSameBytes(t, raw, out)
}
