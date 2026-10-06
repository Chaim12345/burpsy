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

// ---- tokenizer ------------------------------------------------------------------------------------

type protoTok struct {
	kind byte // 'i' ident, 'n' number, 's' string, 'p' punctuation, 0 end
	text string
}

// tokenize splits .proto source into identifiers (dotted names stay one token), numbers, strings and
// single-character punctuation, dropping // and /* */ comments.
func tokenize(src string) ([]protoTok, error) {
	var toks []protoTok
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("proto: unterminated /* comment")
			}
			i += 2 + end + 2
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("proto: unterminated string literal")
			}
			toks = append(toks, protoTok{'s', src[i+1 : j]})
			i = j + 1
		case isIdentStart(c) || (c == '.' && i+1 < len(src) && isIdentStart(src[i+1])):
			j := i + 1
			for j < len(src) && (isIdentStart(src[j]) || (src[j] >= '0' && src[j] <= '9') || src[j] == '.') {
				j++
			}
			toks = append(toks, protoTok{'i', src[i:j]})
			i = j
		case c >= '0' && c <= '9':
			j := i + 1
			for j < len(src) && (isIdentStart(src[j]) || (src[j] >= '0' && src[j] <= '9') || src[j] == '.') {
				j++
			}
			toks = append(toks, protoTok{'n', src[i:j]})
			i = j
		default:
			toks = append(toks, protoTok{'p', string(c)})
			i++
		}
	}
	return toks, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ---- parser ---------------------------------------------------------------------------------------

type protoParser struct {
	toks   []protoTok
	pos    int
	schema *Schema
	// fields holds each message's declared fields before type resolution, which has to wait until
	// every message and enum is known (a field may name a type declared later in the file).
	pending []*pendingMsg
	rpcs    []pendingRPC
}

// pendingRPC is an rpc signature before its type names are resolved.
type pendingRPC struct {
	path    string
	in, out string
}

type pendingMsg struct {
	desc   *messageDesc
	fields []pendingField
}

type pendingField struct {
	number int
	desc   *fieldDesc
	// mapKey/mapVal are set for a map<K,V> field.
	mapKey, mapVal string
}

func (p *protoParser) peek() protoTok {
	if p.pos >= len(p.toks) {
		return protoTok{}
	}
	return p.toks[p.pos]
}

func (p *protoParser) next() protoTok {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *protoParser) expect(kind byte, text string) error {
	t := p.next()
	if t.kind != kind || (text != "" && t.text != text) {
		want := text
		if want == "" {
			want = string(kind)
		}
		return fmt.Errorf("proto: expected %q, found %q", want, t.text)
	}
	return nil
}

// skipStatement advances past the next ';' at brace/bracket depth zero — an option's value may itself
// be a {...} aggregate containing semicolons-free braces.
func (p *protoParser) skipStatement() {
	depth := 0
	for p.pos < len(p.toks) {
		t := p.next()
		if t.kind != 'p' {
			continue
		}
		switch t.text {
		case "{", "[":
			depth++
		case "}", "]":
			depth--
		case ";":
			if depth <= 0 {
				return
			}
		}
	}
}

// skipBlock advances past a balanced { ... } whose opening brace is the next token (or is found
// before any other statement end), for services and extend blocks this parser does not read.
func (p *protoParser) skipBlock() {
	for p.pos < len(p.toks) && p.peek().text != "{" {
		p.pos++
	}
	depth := 0
	for p.pos < len(p.toks) {
		t := p.next()
		if t.kind == 'p' && t.text == "{" {
			depth++
		}
		if t.kind == 'p' && t.text == "}" {
			depth--
			if depth == 0 {
				return
			}
		}
	}
}

// ParseProto parses .proto source into a Schema. It reads proto2 and proto3 message and enum
// declarations and refuses what it cannot read faithfully (a group field), rather than returning a
// schema that silently names the wrong fields.
func ParseProto(src string) (*Schema, error) {
	toks, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	p := &protoParser{toks: toks, schema: &Schema{msgs: map[string]*messageDesc{}, enums: map[string]*enumDesc{}, rpcs: map[string]rpcDesc{}}}
	for p.pos < len(p.toks) {
		t := p.peek()
		switch {
		case t.kind == 'p' && t.text == ";":
			p.next()
		case t.kind == 'i' && t.text == "syntax", t.kind == 'i' && t.text == "import", t.kind == 'i' && t.text == "option":
			p.skipStatement()
		case t.kind == 'i' && t.text == "package":
			p.next()
			name := p.next()
			if name.kind != 'i' {
				return nil, fmt.Errorf("proto: package needs a name")
			}
			p.schema.pkg = name.text
			p.skipStatement()
		case t.kind == 'i' && t.text == "message":
			p.next()
			if err := p.parseMessage(p.schema.pkg); err != nil {
				return nil, err
			}
		case t.kind == 'i' && t.text == "enum":
			p.next()
			if err := p.parseEnum(p.schema.pkg); err != nil {
				return nil, err
			}
		case t.kind == 'i' && t.text == "service":
			p.next()
			if err := p.parseService(); err != nil {
				return nil, err
			}
		case t.kind == 'i' && t.text == "extend":
			p.next()
			p.skipBlock()
		default:
			return nil, fmt.Errorf("proto: unexpected %q at the top level", t.text)
		}
	}
	if len(p.schema.order) == 0 {
		return nil, fmt.Errorf("proto: no message declared")
	}
	p.resolve()
	return p.schema, nil
}

// parseService reads `service Name { rpc M (Req) returns (Resp); ... }`, keeping each rpc's signature
// under its gRPC call path. Streaming markers are accepted and ignored: a stream carries the same
// message type per frame, which is what the decoder needs. Options and rpc bodies are skipped.
func (p *protoParser) parseService() error {
	nameTok := p.next()
	if nameTok.kind != 'i' {
		return fmt.Errorf("proto: service needs a name")
	}
	if err := p.expect('p', "{"); err != nil {
		return err
	}
	service := qualify(p.schema.pkg, nameTok.text)
	for {
		t := p.next()
		switch {
		case t.kind == 0:
			return fmt.Errorf("proto: service %s is not closed", nameTok.text)
		case t.kind == 'p' && t.text == "}":
			return nil
		case t.kind == 'p' && t.text == ";":
		case t.kind == 'i' && t.text == "rpc":
			method := p.next()
			in, err := p.rpcType()
			if err != nil {
				return fmt.Errorf("proto: rpc %s: %w", method.text, err)
			}
			if r := p.next(); r.text != "returns" {
				return fmt.Errorf("proto: rpc %s: expected returns, found %q", method.text, r.text)
			}
			out, err := p.rpcType()
			if err != nil {
				return fmt.Errorf("proto: rpc %s: %w", method.text, err)
			}
			p.rpcs = append(p.rpcs, pendingRPC{path: "/" + service + "/" + method.text, in: in, out: out})
			// Either `;` or an options body `{ option ...; }`.
			if p.peek().kind == 'p' && p.peek().text == "{" {
				p.skipBlock()
			} else if p.peek().kind == 'p' && p.peek().text == ";" {
				p.next()
			}
		default:
			p.skipStatement() // option, or anything else this parser does not read
		}
	}
}

// rpcType reads `( [stream] Type )`.
func (p *protoParser) rpcType() (string, error) {
	if err := p.expect('p', "("); err != nil {
		return "", err
	}
	t := p.next()
	if t.kind == 'i' && t.text == "stream" {
		t = p.next()
	}
	if t.kind != 'i' {
		return "", fmt.Errorf("expected a message type, found %q", t.text)
	}
	if err := p.expect('p', ")"); err != nil {
		return "", err
	}
	return t.text, nil
}

func qualify(scope, name string) string {
	if scope == "" {
		return name
	}
	return scope + "." + name
}

func (p *protoParser) parseEnum(scope string) error {
	nameTok := p.next()
	if nameTok.kind != 'i' {
		return fmt.Errorf("proto: enum needs a name")
	}
	if err := p.expect('p', "{"); err != nil {
		return err
	}
	enum := &enumDesc{full: qualify(scope, nameTok.text), values: map[int64]string{}}
	for {
		t := p.next()
		switch {
		case t.kind == 0:
			return fmt.Errorf("proto: enum %s is not closed", nameTok.text)
		case t.kind == 'p' && t.text == "}":
			p.schema.enums[enum.full] = enum
			return nil
		case t.kind == 'i' && (t.text == "option" || t.text == "reserved"):
			p.skipStatement()
		case t.kind == 'i':
			if err := p.expect('p', "="); err != nil {
				return err
			}
			sign := int64(1)
			if p.peek().kind == 'p' && p.peek().text == "-" {
				p.next()
				sign = -1
			}
			num := p.next()
			v, err := strconv.ParseInt(num.text, 0, 64)
			if err != nil {
				return fmt.Errorf("proto: enum value %s = %q is not an integer", t.text, num.text)
			}
			if _, dup := enum.values[sign*v]; !dup { // an alias keeps the first name
				enum.values[sign*v] = t.text
			}
			p.skipStatement()
		}
	}
}

func (p *protoParser) parseMessage(scope string) error {
	nameTok := p.next()
	if nameTok.kind != 'i' {
		return fmt.Errorf("proto: message needs a name")
	}
	if err := p.expect('p', "{"); err != nil {
		return err
	}
	desc := &messageDesc{full: qualify(scope, nameTok.text), fields: map[int]*fieldDesc{}}
	pm := &pendingMsg{desc: desc}
	p.schema.msgs[desc.full] = desc
	p.schema.order = append(p.schema.order, desc.full)
	p.pending = append(p.pending, pm)

	for {
		t := p.peek()
		switch {
		case t.kind == 0:
			return fmt.Errorf("proto: message %s is not closed", nameTok.text)
		case t.kind == 'p' && t.text == "}":
			p.next()
			return nil
		case t.kind == 'p' && t.text == ";":
			p.next()
		case t.kind == 'i' && t.text == "message":
			p.next()
			if err := p.parseMessage(desc.full); err != nil {
				return err
			}
		case t.kind == 'i' && t.text == "enum":
			p.next()
			if err := p.parseEnum(desc.full); err != nil {
				return err
			}
		case t.kind == 'i' && (t.text == "option" || t.text == "reserved" || t.text == "extensions"):
			p.skipStatement()
		case t.kind == 'i' && t.text == "extend":
			p.next()
			p.skipBlock()
		case t.kind == 'i' && t.text == "oneof":
			p.next()
			p.next() // the oneof's name; its members are ordinary fields of the message
			if err := p.expect('p', "{"); err != nil {
				return err
			}
			for p.peek().kind != 0 && !(p.peek().kind == 'p' && p.peek().text == "}") {
				if p.peek().kind == 'i' && p.peek().text == "option" {
					p.skipStatement()
					continue
				}
				if err := p.parseField(pm, false); err != nil {
					return err
				}
			}
			p.next() // }
		default:
			if err := p.parseField(pm, true); err != nil {
				return err
			}
		}
	}
}

// parseField reads one `[label] type name = N [options];` (or a map field), appending it to pm.
// labels is false inside a oneof, where none is allowed.
func (p *protoParser) parseField(pm *pendingMsg, labels bool) error {
	repeated := false
	if t := p.peek(); labels && t.kind == 'i' && (t.text == "repeated" || t.text == "optional" || t.text == "required") {
		repeated = t.text == "repeated"
		p.next()
	}
	typ := p.next()
	if typ.kind != 'i' {
		return fmt.Errorf("proto: expected a field type, found %q", typ.text)
	}
	if typ.text == "group" {
		return fmt.Errorf("proto: group fields are not supported")
	}
	pf := pendingField{desc: &fieldDesc{repeated: repeated}}
	if typ.text == "map" && p.peek().kind == 'p' && p.peek().text == "<" {
		p.next()
		key, comma, valTok := p.next(), p.next(), p.next()
		if key.kind != 'i' || comma.kind != 'p' || comma.text != "," || valTok.kind != 'i' {
			return fmt.Errorf("proto: malformed map field")
		}
		if err := p.expect('p', ">"); err != nil {
			return err
		}
		pf.mapKey, pf.mapVal = key.text, valTok.text
		pf.desc.isMap = true
		pf.desc.repeated = true
		pf.desc.typeName = "map<" + key.text + "," + valTok.text + ">"
	} else {
		pf.desc.typeName = typ.text
	}
	nameTok := p.next()
	if nameTok.kind != 'i' {
		return fmt.Errorf("proto: expected a field name after %q, found %q", typ.text, nameTok.text)
	}
	pf.desc.name = nameTok.text
	if err := p.expect('p', "="); err != nil {
		return err
	}
	num := p.next()
	n, err := strconv.Atoi(num.text)
	if err != nil || n <= 0 {
		return fmt.Errorf("proto: field %s has the invalid number %q", nameTok.text, num.text)
	}
	pf.number = n
	p.skipStatement()
	pm.fields = append(pm.fields, pf)
	return nil
}

// resolve links every field's type to a message or enum declared in the schema, and builds the
// synthetic entry message of each map field. Run after the whole file is read, because a field may
// name a type declared below it.
func (p *protoParser) resolve() {
	for _, pm := range p.pending {
		for _, pf := range pm.fields {
			fd := pf.desc
			if fd.isMap {
				entry := &messageDesc{full: pm.desc.full + "." + fd.name + "Entry", fields: map[int]*fieldDesc{
					1: {name: "key", typeName: pf.mapKey},
					2: {name: "value", typeName: pf.mapVal},
				}}
				p.link(entry.fields[2], pm.desc.full)
				fd.msg = entry
			} else {
				p.link(fd, pm.desc.full)
			}
			pm.desc.fields[pf.number] = fd
		}
	}
	// An rpc type resolves exactly as a field type does, from the package scope outward.
	for _, r := range p.rpcs {
		p.schema.rpcs[r.path] = rpcDesc{in: p.resolveMessageName(r.in), out: p.resolveMessageName(r.out)}
	}
}

// resolveMessageName is link() for an rpc signature: the full name of the message typeName refers to
// from the package scope, or "" when this file does not declare it.
func (p *protoParser) resolveMessageName(typeName string) string {
	fd := &fieldDesc{typeName: typeName}
	p.link(fd, p.schema.pkg)
	if fd.msg == nil {
		return ""
	}
	return fd.msg.full
}

// link resolves fd.typeName against the scope it was declared in, innermost scope outward, the way
// protoc does (an absolute name starts with a dot).
func (p *protoParser) link(fd *fieldDesc, scope string) {
	if scalarTypes[fd.typeName] {
		return
	}
	if strings.HasPrefix(fd.typeName, ".") {
		p.bind(fd, strings.TrimPrefix(fd.typeName, "."))
		return
	}
	for {
		if p.bind(fd, qualify(scope, fd.typeName)) {
			return
		}
		if scope == "" {
			return
		}
		if i := strings.LastIndex(scope, "."); i >= 0 {
			scope = scope[:i]
		} else {
			scope = ""
		}
	}
}

func (p *protoParser) bind(fd *fieldDesc, full string) bool {
	if m, ok := p.schema.msgs[full]; ok {
		fd.msg = m
		return true
	}
	if e, ok := p.schema.enums[full]; ok {
		fd.enum = e
		return true
	}
	return false
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
