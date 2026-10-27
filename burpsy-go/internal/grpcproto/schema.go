package grpcproto

// Name and type resolution from a .proto (burpsy-react-ui-3pco, descriptors since 0rrb).
//
// The schemaless walk in grpcproto.go shows `#1 varint 150`; given the message's .proto it can show
// `user_id (int32) 150`. This file is the schema half: the Schema model Annotate labels a decoded
// field tree with. ParseProto itself lives in descriptor_schema.go and is protocompile since 0rrb:
// imports resolve against the well-known types (an unresolved import is a hard fail naming its
// import string - rsu2, the multi-file upload bead, is the planned way to bring the rest of an
// import graph), groups read, and type references are the linked answer protoc would give.
//
// # What is deliberately not here
//
//   - gRPC server reflection. It needs a client that connects to the target and asks, which is an
//     egress surface with its own scoping decision; a pasted .proto is what an operator holding the
//     API's definition (or a captured copy of it) already has. Reflection is a separate bead (47id).
//   - recursion into messages declared outside the parsed file. An imported type keeps its declared
//     type name and the schemaless guess for its contents - named, not expanded.
//   - services beyond their rpc signatures: a gRPC call's path (/pkg.Service/Method) names the
//     request and response message types, so the operator does not have to pick them.
//
// # Annotation never changes the bytes
//
// A schema can only add meaning, so Annotate may change how a length-delimited field is *presented*
// (the schemaless guess is just a guess — `string` fields that happen to parse as a message are
// common) but never what it encodes to: every reclassification goes through the field's own encoded
// bytes, so Encode(Annotate(fields)) equals Encode(fields).

import (
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// scalarTypes are the proto scalar type names; anything else a field names is a message or enum.
var scalarTypes = map[string]bool{
	"double": true, "float": true, "int32": true, "int64": true, "uint32": true, "uint64": true,
	"sint32": true, "sint64": true, "fixed32": true, "fixed64": true, "sfixed32": true, "sfixed64": true,
	"bool": true, "string": true, "bytes": true,
}

// fieldDesc is one declared field.
type fieldDesc struct {
	name     string
	typeName string // as written, e.g. "int32", "Address", "foo.Bar"
	repeated bool
	// msg is the resolved message type, nil for a scalar, an enum, or a type this schema does not
	// define (an imported one).
	msg *messageDesc
	// enum is the resolved enum type, nil unless the field's type is an enum.
	enum *enumDesc
	// isMap marks a map<K,V> field; msg is then the synthetic entry message (1=key, 2=value).
	isMap bool
}

type enumDesc struct {
	full   string
	values map[int64]string
}

type messageDesc struct {
	full   string
	fields map[int]*fieldDesc
}

// Schema is a parsed .proto: every message and enum, nested ones included, keyed by full name.
type Schema struct {
	pkg   string
	msgs  map[string]*messageDesc
	enums map[string]*enumDesc
	order []string // message full names in source order
	// rpcs maps a gRPC call path, "/pkg.Service/Method", to its request and response message names.
	rpcs map[string]rpcDesc
	// descs carries the protoreflect descriptor behind each message, for the
	// dynamicpb validation oracle (0rrb 2b): descriptors own presentation and
	// conformance, protowire owns the bytes.
	descs map[string]protoreflect.MessageDescriptor
}

// rpcDesc is one service method's signature, by resolved message full name. A side whose type is not
// declared in this file (an import, e.g. google.protobuf.Empty) is "".
type rpcDesc struct {
	in, out string
}

// MessageForRPC names the message a gRPC call carries in the given direction ("request" or
// "response"), from the call's path — "/acme.v1.Users/Get" — and the schema's service blocks. It
// returns "" when the path names no rpc in this schema, or the rpc's type for that side is not declared
// here. A leading path prefix (a gRPC-web gateway mount) is tolerated: the last two segments decide.
func (s *Schema) MessageForRPC(path, direction string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	rpc, ok := s.rpcs["/"+parts[len(parts)-2]+"/"+parts[len(parts)-1]]
	if !ok {
		return ""
	}
	if direction == "response" {
		return rpc.out
	}
	return rpc.in
}

// Messages lists every message's full name (nested included) in source order, so a UI can offer the
// operator the choice of which message type the body is.
func (s *Schema) Messages() []string { return append([]string(nil), s.order...) }

// lookup finds a message by full name, or by a name that matches exactly one message's trailing
// components ("User" for "acme.v1.User"), so the operator may type the short form. The second result
// reports ambiguity, so a caller can list the candidates rather than guess.
func (s *Schema) lookup(name string) (*messageDesc, []string) {
	name = strings.TrimPrefix(name, ".")
	if m, ok := s.msgs[name]; ok {
		return m, nil
	}
	var hits []string
	for _, full := range s.order {
		if full == name || strings.HasSuffix(full, "."+name) {
			hits = append(hits, full)
		}
	}
	if len(hits) == 1 {
		return s.msgs[hits[0]], nil
	}
	return nil, hits
}

// DefaultMessage is the message to use when the operator named none: the only top-level message, or
// "" when there are several (or none) and the choice is theirs.
func (s *Schema) DefaultMessage() string {
	top := ""
	for _, full := range s.order {
		rel := full
		if s.pkg != "" {
			rel = strings.TrimPrefix(full, s.pkg+".")
		}
		if strings.Contains(rel, ".") {
			continue // nested
		}
		if top != "" {
			return ""
		}
		top = full
	}
	return top
}

// ---- annotation -----------------------------------------------------------------------------------

// Annotate labels fields with the names and declared types of the message called root in the schema,
// recursing into nested messages. A field number the schema does not declare is left unlabelled (the
// body may be a newer version of the message, which is itself worth seeing). It returns an error only
// when root names no message, or names one ambiguously.
func (s *Schema) Annotate(fields []Field, root string) ([]Field, error) {
	md, hits := s.lookup(root)
	if md == nil {
		if len(hits) > 1 {
			sort.Strings(hits)
			return nil, fmt.Errorf("message %q is ambiguous: %s", root, strings.Join(hits, ", "))
		}
		return nil, fmt.Errorf("no message named %q in the schema (messages: %s)", root, strings.Join(s.order, ", "))
	}
	return annotate(fields, md), nil
}

// Validate is the dynamicpb oracle (0rrb 2b, integrator ruling (a)+(b)): it reads
// raw as the message called root and refuses what the declared schema cannot
// hold and the raw protowire walk skims past - invalid UTF-8 in a declared
// string, a missing proto2 required field. It writes nothing and presents
// nothing: the field tree still comes from the byte-exact protowire walk. A
// body that fails here is not the message the schema declares (or the schema is
// stale); the caller reports the mismatch honestly rather than presenting a
// skimmed tree as conforming.
//
// A wire type that does not match the declaration is deliberately NOT refused:
// protobuf's unmarshal carries it as an unknown field by spec, so a body from a
// newer schema version still validates. Pinned in validate_test.go.
func (s *Schema) Validate(root string, raw []byte) error {
	md, hits := s.lookup(root)
	if md == nil {
		if len(hits) > 1 {
			sort.Strings(hits)
			return fmt.Errorf("message %q is ambiguous: %s", root, strings.Join(hits, ", "))
		}
		return fmt.Errorf("no message named %q in the schema", root)
	}
	desc := s.descs[md.full]
	if desc == nil {
		return fmt.Errorf("no descriptor for %q", md.full)
	}
	if err := proto.Unmarshal(raw, dynamicpb.NewMessage(desc)); err != nil {
		return fmt.Errorf("%s: %w", md.full, err)
	}
	return nil
}

func annotate(fields []Field, md *messageDesc) []Field {
	out := make([]Field, len(fields))
	for i, f := range fields {
		fd, ok := md.fields[f.Number]
		if !ok {
			out[i] = f
			continue
		}
		f.Name = fd.name
		f.Type = fd.label()
		switch {
		case f.WireType == wireVarint && fd.enum != nil:
			if v, err := strconv.ParseUint(f.Varint, 10, 64); err == nil {
				// The wire carries an enum as a (possibly negative) int32 widened to 64 bits.
				//nolint:gosec // G115: intentional exact inverse of the canonical encoding - encoders write a negative enum as its int32 number sign-extended to 64 bits (protobuf.dev "Signed Integers"; protobuf-go appendEnumValue), so int64(v) recovers exactly a declared number and nothing else. Over-long or undeclared values match no name and the raw decimal stands. Pinned in schema_test.go.
				if name, ok := fd.enum.values[int64(v)]; ok {
					f.EnumName = name
				}
			}
		case f.WireType == wireLen:
			f = reclassify(f, fd)
		}
		out[i] = f
	}
	return out
}

// label is the declared type as the editor shows it: "int32", "repeated string", "map<string,int32>".
func (fd *fieldDesc) label() string {
	t := fd.typeName
	if fd.enum != nil {
		t = "enum " + t
	}
	if fd.repeated && !fd.isMap {
		return "repeated " + t
	}
	return t
}

// lenBytes recovers a length-delimited field's payload from whichever presentation the schemaless
// walk gave it. Encode is the exact inverse of the walk, so this is the original payload.
func lenBytes(f Field) []byte {
	b, err := encodeLen(f)
	if err != nil {
		return nil
	}
	return b
}

// reclassify corrects the schemaless guess for a length-delimited field whose declared type is known:
// a declared string is a string even when its bytes happen to parse as protobuf, a declared message is
// a message even when the guess was a string, and declared bytes are bytes. Every branch rebuilds the
// field from its own payload, so what it encodes to is unchanged. Where the declared type cannot be
// honoured (a "string" that is not UTF-8, a "message" that does not parse) the guess stands.
func reclassify(f Field, fd *fieldDesc) Field {
	payload := lenBytes(f)
	switch {
	case fd.repeated && fd.msg == nil && packedKind(fd) != "":
		// A proto3 repeated numeric scalar rides packed: one length-delimited
		// field holding the values back to back. The values are read into
		// Packed as presentation; the field's own bytes are untouched, so the
		// tree encodes to exactly what it was.
		if values, ok := decodePacked(payload, fd); ok {
			f.Packed = values
		}
	case fd.msg != nil:
		if sub, n, err := decodeMessage(payload); err == nil && n == len(payload) {
			f.LenKind, f.String, f.BytesHex = LenMessage, "", ""
			f.Message = annotate(sub, fd.msg)
		}
	case fd.typeName == "string":
		if utf8.Valid(payload) {
			f.LenKind, f.Message, f.BytesHex = LenString, nil, ""
			f.String = string(payload)
		}
	case fd.typeName == "bytes":
		f.LenKind, f.Message, f.String = LenBytes, nil, ""
		f.BytesHex = hex.EncodeToString(payload)
	}
	return f
}

// packedKind classifies a declared repeated field's element for packed reading:
// "varint", "fixed32", "fixed64", or "" for a kind that never packs (string,
// bytes, message).
func packedKind(fd *fieldDesc) string {
	if fd.enum != nil {
		return "varint"
	}
	switch fd.typeName {
	case "int32", "int64", "uint32", "uint64", "sint32", "sint64", "bool":
		return "varint"
	case "fixed32", "sfixed32", "float":
		return "fixed32"
	case "fixed64", "sfixed64", "double":
		return "fixed64"
	}
	return ""
}

// decodePacked reads a packed payload into the element values as decimal (or
// enum-named, or float) strings. It returns false on any truncation: a partial
// element means the payload is not what the schema declares, and the schemaless
// guess stands - the same honesty rule reclassify's other branches follow.
func decodePacked(payload []byte, fd *fieldDesc) ([]string, bool) {
	var values []string
	format := func(v uint64) string {
		switch {
		case fd.enum != nil:
			//nolint:gosec // G115: same intentional inverse-of-sign-extension as the scalar enum path in annotate - only an exact declared number names, anything else stands as decimal. Pinned in packed_test.go.
			if name, ok := fd.enum.values[int64(v)]; ok {
				return name
			}
			return strconv.FormatUint(v, 10)
		case fd.typeName == "sint32" || fd.typeName == "sint64":
			return strconv.FormatInt(protowire.DecodeZigZag(v), 10)
		case fd.typeName == "bool":
			return strconv.FormatBool(protowire.DecodeBool(v))
		case fd.typeName == "float":
			//nolint:gosec // G115: lossless round trip - packedKind maps float to the "fixed32" path, whose protowire.ConsumeFixed32 zero-extends a uint32 into v, so uint32(v) drops no bits. Pinned in packed_test.go.
			return strconv.FormatFloat(float64(math.Float32frombits(uint32(v))), 'g', -1, 32)
		case fd.typeName == "double":
			return strconv.FormatFloat(math.Float64frombits(v), 'g', -1, 64)
		default:
			return strconv.FormatUint(v, 10)
		}
	}
	for len(payload) > 0 {
		var v uint64
		var n int
		switch packedKind(fd) {
		case "varint":
			v, n = protowire.ConsumeVarint(payload)
		case "fixed32":
			var u32 uint32
			u32, n = protowire.ConsumeFixed32(payload)
			v = uint64(u32)
		case "fixed64":
			v, n = protowire.ConsumeFixed64(payload)
		}
		if n < 0 {
			return nil, false
		}
		values = append(values, format(v))
		payload = payload[n:]
	}
	return values, true
}
