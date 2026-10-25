package grpcproto

// Name and type resolution from a .proto (burpsy-react-ui-3pco).
//
// The schemaless walk in grpcproto.go shows `#1 varint 150`; given the message's .proto it can show
// `user_id (int32) 150`. This file is the schema half: a small .proto parser — enough of proto2/proto3
// to name the fields of messages, including nested messages, oneofs, maps and enums — and Annotate,
// which labels a decoded field tree with it.
//
// # What is deliberately not here
//
//   - gRPC server reflection. It needs a client that connects to the target and asks, which is an
//     egress surface with its own scoping decision; a pasted .proto is what an operator holding the
//     API's definition (or a captured copy of it) already has. Reflection is a separate bead.
//   - imports. An `import` is skipped, so a field whose type lives in another file keeps its declared
//     type name and the schemaless guess for its contents — named, not expanded.
//   - extensions and proto2 groups. A group field is refused rather than half-read. Services ARE read,
//     but only for their rpc signatures: a gRPC call's path (/pkg.Service/Method) then names the
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
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
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
