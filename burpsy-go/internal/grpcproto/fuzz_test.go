package grpcproto

import "testing"

// ibhs: native fuzz for the protobuf wire walker and the .proto schema parser.

// FuzzDecode: Decode never panics on arbitrary bytes.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0x08, 0x96, 0x01})
	f.Add([]byte{0x0a, 0x03, 'a', 'b', 'c'})
	f.Add([]byte{0x0a, 0x04, 0x08, 0x01, 0x10, 0x02})
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Add([]byte{0x0b})
	f.Add([]byte{0x80})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = Decode(raw)
	})
}

// FuzzParseProto: ParseProto never panics on arbitrary source text.
func FuzzParseProto(f *testing.F) {
	f.Add("syntax = \"proto3\";\nmessage M { int32 a = 1; string b = 2; repeated M c = 3; }")
	f.Add("syntax = \"proto3\";\nenum E { Z = 0; A = 1; }\nmessage M { E e = 1; map<string,int32> m = 2; }")
	f.Add("message")
	f.Add("syntax = \"proto3\"; message M { oneof x { int32 a = 1; } }")
	f.Add("")
	f.Fuzz(func(t *testing.T, src string) {
		_, _ = ParseProto(src)
	})
}
