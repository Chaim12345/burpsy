package grpcproto

import (
	"bytes"
	"strings"
	"testing"
)

// ---- .proto name resolution (burpsy-react-ui-3pco) -----------------------------------------------
//
// The invariant that carries the weight: a schema only adds meaning, so annotating must never change
// what a tree encodes to. Every test that annotates also re-encodes and compares to the original bytes.

const testProto = `
// A comment, and a block comment below.
/* block
   comment */
syntax = "proto3";
package acme.v1;
option java_package = "com.acme";
import "google/protobuf/timestamp.proto";

enum Status {
  UNKNOWN = 0;
  ACTIVE = 1;
  BANNED = -1;
}

message Address {
  string street = 1;
  int32 zip = 2;
}

message User {
  int32 user_id = 1;
  string name = 2;
  Address home = 3;
  repeated string tags = 4 [deprecated = true];
  Status status = 5;
  map<string, int32> scores = 6;
  oneof contact {
    string email = 7;
    string phone = 8;
  }
  message Prefs { bool dark = 1; }
  Prefs prefs = 9;
  bytes avatar = 10;
  reserved 20, 21 to 25;
}

service Users { rpc Get (User) returns (User); }
`

func mustParse(t *testing.T, src string) *Schema {
	t.Helper()
	s, err := ParseProto(src)
	if err != nil {
		t.Fatalf("ParseProto: %v", err)
	}
	return s
}

func find(fields []Field, number int) *Field {
	for i := range fields {
		if fields[i].Number == number {
			return &fields[i]
		}
	}
	return nil
}

func TestParseProtoListsEveryMessageNestedIncluded(t *testing.T) {
	s := mustParse(t, testProto)
	got := strings.Join(s.Messages(), ",")
	want := "acme.v1.Address,acme.v1.User,acme.v1.User.Prefs"
	if got != want {
		t.Fatalf("Messages = %s, want %s", got, want)
	}
	// Two top-level messages, so there is no default: the operator chooses.
	if d := s.DefaultMessage(); d != "" {
		t.Fatalf("DefaultMessage = %q, want empty for a two-message schema", d)
	}
	one := mustParse(t, `message Only { int32 a = 1; }`)
	if d := one.DefaultMessage(); d != "Only" {
		t.Fatalf("DefaultMessage = %q, want Only", d)
	}
}

func TestAnnotateNamesFieldsAndNestedMessages(t *testing.T) {
	s := mustParse(t, testProto)
	// User{user_id: 150, name: "ada", home: Address{street: "Elm", zip: 90210}, status: 1, email: "a@b"}
	home, _ := Encode([]Field{
		{Number: 1, WireType: 2, LenKind: LenString, String: "Elm"},
		{Number: 2, WireType: 0, Varint: "90210"},
	})
	raw, err := Encode([]Field{
		{Number: 1, WireType: 0, Varint: "150"},
		{Number: 2, WireType: 2, LenKind: LenString, String: "ada"},
		{Number: 3, WireType: 2, LenKind: LenBytes, BytesHex: hexOf(home)},
		{Number: 5, WireType: 0, Varint: "1"},
		{Number: 7, WireType: 2, LenKind: LenString, String: "a@b"},
		{Number: 99, WireType: 0, Varint: "7"}, // a number the schema does not declare
	})
	if err != nil {
		t.Fatal(err)
	}
	fields, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Annotate(fields, "User")
	if err != nil {
		t.Fatalf("Annotate: %v", err)
	}

	if f := find(out, 1); f.Name != "user_id" || f.Type != "int32" {
		t.Fatalf("field 1 = %q/%q, want user_id/int32", f.Name, f.Type)
	}
	if f := find(out, 5); f.Name != "status" || f.EnumName != "ACTIVE" || f.Type != "enum Status" {
		t.Fatalf("field 5 = %+v, want status / enum Status / ACTIVE", f)
	}
	if f := find(out, 7); f.Name != "email" {
		t.Fatalf("a oneof member must be named like any field, got %q", f.Name)
	}
	// The nested Address is reached by recursion: its inner fields are named too.
	h := find(out, 3)
	if h.Name != "home" || h.LenKind != LenMessage {
		t.Fatalf("field 3 = %+v, want home as a message", h)
	}
	if f := find(h.Message, 2); f.Name != "zip" {
		t.Fatalf("a nested field was not named: %+v", f)
	}
	// Unknown to the schema: left unlabelled, still present.
	if f := find(out, 99); f == nil || f.Name != "" {
		t.Fatalf("an undeclared field must survive unlabelled, got %+v", f)
	}

	assertSameBytes(t, raw, out)
}

func TestAnnotateCorrectsTheSchemalessGuess(t *testing.T) {
	s := mustParse(t, `message M { string note = 1; bytes blob = 2; Inner inner = 3; } message Inner { int32 n = 1; }`)

	// A declared string whose bytes happen to parse as protobuf: the schemaless guess says "message".
	lookalike := []byte{0x08, 0x01} // field 1 varint 1 — also the two bytes "\x08\x01"
	// A declared bytes field holding valid UTF-8 text: the guess says "string".
	// A declared message holding text that is not protobuf: the guess says "string", the declared
	// type cannot be honoured, and the guess must stand.
	raw, _ := Encode([]Field{
		{Number: 1, WireType: 2, LenKind: LenBytes, BytesHex: hexOf(lookalike)},
		{Number: 2, WireType: 2, LenKind: LenString, String: "hello"},
		{Number: 3, WireType: 2, LenKind: LenString, String: "not protobuf!"},
	})
	fields, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if find(fields, 1).LenKind != LenMessage {
		t.Fatalf("test premise: the lookalike should be guessed as a message, got %s", find(fields, 1).LenKind)
	}
	out, err := s.Annotate(fields, "M")
	if err != nil {
		t.Fatal(err)
	}
	if f := find(out, 1); f.LenKind != LenString || f.Message != nil {
		t.Fatalf("a declared string must be shown as a string, got %+v", f)
	}
	if f := find(out, 2); f.LenKind != LenBytes || f.BytesHex != hexOf([]byte("hello")) {
		t.Fatalf("declared bytes must be shown as bytes, got %+v", f)
	}
	if f := find(out, 3); f.LenKind != LenString || f.Name != "inner" {
		t.Fatalf("a declared message that does not parse keeps the guess (but is still named), got %+v", f)
	}
	assertSameBytes(t, raw, out)
}

func TestAnnotateMapEntriesAndNestedTypeScopes(t *testing.T) {
	s := mustParse(t, testProto)
	entry, _ := Encode([]Field{
		{Number: 1, WireType: 2, LenKind: LenString, String: "alice"},
		{Number: 2, WireType: 0, Varint: "42"},
	})
	prefs, _ := Encode([]Field{{Number: 1, WireType: 0, Varint: "1"}})
	raw, _ := Encode([]Field{
		{Number: 6, WireType: 2, LenKind: LenBytes, BytesHex: hexOf(entry)},
		{Number: 9, WireType: 2, LenKind: LenBytes, BytesHex: hexOf(prefs)},
	})
	fields, _ := Decode(raw)
	out, err := s.Annotate(fields, "acme.v1.User")
	if err != nil {
		t.Fatal(err)
	}
	m := find(out, 6)
	if m.Name != "scores" || m.Type != "map<string,int32>" {
		t.Fatalf("map field = %q/%q", m.Name, m.Type)
	}
	if k, v := find(m.Message, 1), find(m.Message, 2); k.Name != "key" || v.Name != "value" {
		t.Fatalf("a map entry must name key/value, got %q/%q", k.Name, v.Name)
	}
	// Prefs is declared inside User, so `Prefs prefs = 9` only resolves with scope-outward lookup.
	p := find(out, 9)
	if p.LenKind != LenMessage || find(p.Message, 1).Name != "dark" {
		t.Fatalf("a type declared in the enclosing message did not resolve: %+v", p)
	}
	assertSameBytes(t, raw, out)
}

func TestAnnotateRefusesAnUnknownOrAmbiguousMessage(t *testing.T) {
	s := mustParse(t, `package a; message X {} message Y { message X { int32 n = 1; } }`)
	if _, err := s.Annotate(nil, "Nope"); err == nil || !strings.Contains(err.Error(), "a.X") {
		t.Fatalf("an unknown message should be refused, listing the real ones; got %v", err)
	}
	// "X" matches a.X exactly (full name is a.X, so the suffix form is a.Y.X *and* a.X): the exact
	// full name wins, the bare short name is ambiguous.
	if _, err := s.Annotate(nil, "X"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("an ambiguous short name should be refused, got %v", err)
	}
	if _, err := s.Annotate(nil, "a.X"); err != nil {
		t.Fatalf("the full name must resolve: %v", err)
	}
}

func TestParseProtoRefusesWhatItCannotReadFaithfully(t *testing.T) {
	for name, src := range map[string]string{
		"a group":            `message M { optional group G = 1 { optional int32 a = 2; } }`,
		"no messages":        `syntax = "proto3";`,
		"unclosed message":   `message M { int32 a = 1;`,
		"a bad field number": `message M { int32 a = zero; }`,
		"unclosed comment":   `message M {} /* never ends`,
	} {
		if _, err := ParseProto(src); err == nil {
			t.Errorf("%s: want a parse error, got none", name)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func assertSameBytes(t *testing.T, want []byte, annotated []Field) {
	t.Helper()
	got, err := Encode(annotated)
	if err != nil {
		t.Fatalf("re-encode an annotated tree: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("annotation changed the encoded bytes:\n got %x\nwant %x", got, want)
	}
}

func TestMessageForRPCResolvesBothDirectionsFromTheCallPath(t *testing.T) {
	s := mustParse(t, `
syntax = "proto3";
package acme.v1;
import "google/protobuf/empty.proto";
message GetReq { int32 id = 1; }
message GetResp { string name = 1; }
service Users {
  option deprecated = false;
  rpc Get (GetReq) returns (GetResp);
  rpc Watch (stream GetReq) returns (stream GetResp) { option deprecated = true; }
  rpc Ping (google.protobuf.Empty) returns (GetResp);
}`)
	cases := []struct{ path, dir, want string }{
		{"/acme.v1.Users/Get", "request", "acme.v1.GetReq"},
		{"/acme.v1.Users/Get", "response", "acme.v1.GetResp"},
		{"/acme.v1.Users/Watch", "response", "acme.v1.GetResp"}, // streaming: same type per frame
		{"/grpc-web/acme.v1.Users/Get?x=1", "request", "acme.v1.GetReq"},
		{"/acme.v1.Users/Ping", "request", ""}, // an imported type is not declared here
		{"/acme.v1.Users/Nope", "request", ""},
		{"/", "request", ""},
	}
	for _, c := range cases {
		if got := s.MessageForRPC(c.path, c.dir); got != c.want {
			t.Errorf("MessageForRPC(%q, %q) = %q, want %q", c.path, c.dir, got, c.want)
		}
	}
}
