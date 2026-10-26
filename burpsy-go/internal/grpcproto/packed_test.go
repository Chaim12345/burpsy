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

// Packed boundary pins for the float and enum element conversions.
func TestAnnotatePackedConversionBoundaries(t *testing.T) {
	s := mustParse(t, `syntax = "proto3"; message M { repeated float xs = 1; repeated E es = 2; }
enum E { A = 0; NEG = -1; }`)

	// Extreme float bit patterns ride packed as four-byte little-endian chunks and
	// must render exactly: the uint64 the formatter receives is a zero-extended
	// uint32 from protowire.ConsumeFixed32, so the uint32(v) conversion drops nothing.
	raw, _ := hex.DecodeString("0a10" + "ffff7f7f" + "0000c0bf" + "01000000" + "0000c07f")
	fields, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Annotate(fields, "M")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(find(out, 1).Packed, ","); got != "3.4028235e+38,-1.5,1e-45,NaN" {
		t.Fatalf("packed floats = %q", got)
	}
	assertSameBytes(t, raw, out)

	// A packed canonical negative enum names NEG; the same no-alias rule applies.
	raw, _ = hex.DecodeString("12" + "0b" + "ffffffffffffffffff01" + "00")
	fields, _ = Decode(raw)
	out, _ = s.Annotate(fields, "M")
	if got := strings.Join(find(out, 2).Packed, ","); got != "NEG,A" {
		t.Fatalf("packed enums = %q", got)
	}

	// A truncated packed element is not silently dropped or half-read: decodePacked
	// fails as a whole and the schemaless guess stands, bytes untouched.
	raw, _ = hex.DecodeString("0a03" + "0000c0")
	fields, _ = Decode(raw)
	out, _ = s.Annotate(fields, "M")
	if got := find(out, 1); got.Packed != nil {
		t.Fatalf("truncated packed payload decoded to %v", got)
	}
	assertSameBytes(t, raw, out)

	// An over-wide varint inside a packed enum payload fails decodePacked likewise.
	raw, _ = hex.DecodeString("12" + "0b" + "ffffffffffffffffffff01")
	fields, _ = Decode(raw)
	out, _ = s.Annotate(fields, "M")
	if got := find(out, 2); got.Packed != nil {
		t.Fatalf("over-wide packed varint decoded to %v", got)
	}
	assertSameBytes(t, raw, out)
}
