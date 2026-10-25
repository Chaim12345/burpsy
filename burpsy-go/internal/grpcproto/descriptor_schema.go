package grpcproto

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// descriptor_schema.go builds the Schema the annotator consumes from a real
// protocompile descriptor (0rrb) instead of the hand-rolled parser this package
// started with: imports resolve (the well-known types via protocompile's standard
// imports), groups read instead of being refused, and every type reference is the
// linked answer protoc would give rather than a scope-outward guess. The Schema
// model, the Annotate reclassification logic and the ParseProto signature are
// unchanged - the hand parser's tests pin the behavior this builder must keep.
//
// References to messages declared outside the parsed file (an imported type) still
// resolve to nil in the Schema model, exactly as the hand parser left them: the
// model only describes messages it can annotate against, and recursion into an
// imported message is the dynamicpb slice's job, not this one's.

// parseProtoDescriptors compiles src as a single in-memory .proto and returns the
// Schema built from its linked descriptor.
func parseProtoDescriptors(src string) (*Schema, error) {
	return parseProtoDescriptorsFile(src, "input.proto")
}

// CompileProto compiles a single in-memory .proto into its linked descriptor,
// resolving imports against the well-known types. Exported for the reflection
// surfaces' tests (registering a fixture schema into a protoregistry) and the
// multi-file upload bead (rsu2); ParseProto builds a Schema from it.
func CompileProto(src, filePath string) (protoreflect.FileDescriptor, error) {
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			Accessor: func(path string) (io.ReadCloser, error) {
				if path == filePath {
					return io.NopCloser(strings.NewReader(src)), nil
				}
				return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
			},
		}),
		SourceInfoMode: protocompile.SourceInfoNone,
		MaxParallelism: 1,
	}
	files, err := compiler.Compile(context.Background(), filePath)
	if err != nil {
		return nil, fmt.Errorf("proto: %w", err)
	}
	return files[0], nil
}

// parseProtoDescriptorsFile is parseProtoDescriptors with the file's own path
// named, so registries key it correctly.
func parseProtoDescriptorsFile(src, filePath string) (*Schema, error) {
	fd, err := CompileProto(src, filePath)
	if err != nil {
		return nil, err
	}
	s := &Schema{
		pkg:   string(fd.Package()),
		msgs:  map[string]*messageDesc{},
		enums: map[string]*enumDesc{},
		rpcs:  map[string]rpcDesc{},
		descs: map[string]protoreflect.MessageDescriptor{},
	}
	// Shells first, fields second: a field's message reference may name a type
	// declared later in the file, or the message itself.
	for i := 0; i < fd.Messages().Len(); i++ {
		buildMessageShells(s, fd.Messages().Get(i))
	}
	for i := 0; i < fd.Enums().Len(); i++ {
		buildEnum(s, fd.Enums().Get(i))
	}
	for i := 0; i < fd.Messages().Len(); i++ {
		buildMessageFields(s, fd.Messages().Get(i))
	}
	for i := 0; i < fd.Services().Len(); i++ {
		svc := fd.Services().Get(i)
		for j := 0; j < svc.Methods().Len(); j++ {
			m := svc.Methods().Get(j)
			// Streaming markers carry the same message type per frame; the descriptor
			// does not change what the decoder needs. A side whose type is declared
			// outside this file stays "", as the hand parser left it.
			rpc := rpcDesc{}
			if _, ok := s.msgs[string(m.Input().FullName())]; ok {
				rpc.in = string(m.Input().FullName())
			}
			if _, ok := s.msgs[string(m.Output().FullName())]; ok {
				rpc.out = string(m.Output().FullName())
			}
			s.rpcs["/"+string(svc.FullName())+"/"+string(m.Name())] = rpc
		}
	}
	if len(s.order) == 0 {
		return nil, fmt.Errorf("proto: no message declared")
	}
	return s, nil
}

// buildMessageShells registers every message - nested ones included - under its full
// name, in source order, so fields can resolve references in any order. Map-entry
// messages are synthetic and are not declared types.
func buildMessageShells(s *Schema, md protoreflect.MessageDescriptor) {
	full := string(md.FullName())
	if _, ok := s.msgs[full]; !ok {
		s.msgs[full] = &messageDesc{full: full, fields: map[int]*fieldDesc{}}
		s.order = append(s.order, full)
	}
	s.descs[full] = md
	for i := 0; i < md.Messages().Len(); i++ {
		if n := md.Messages().Get(i); !n.IsMapEntry() {
			buildMessageShells(s, n)
		}
	}
	for i := 0; i < md.Enums().Len(); i++ {
		buildEnum(s, md.Enums().Get(i))
	}
}

func buildMessageFields(s *Schema, md protoreflect.MessageDescriptor) {
	m := s.msgs[string(md.FullName())]
	if m == nil || len(m.fields) > 0 {
		return
	}
	for i := 0; i < md.Fields().Len(); i++ {
		f := md.Fields().Get(i)
		m.fields[int(f.Number())] = buildField(s, f)
	}
	for i := 0; i < md.Messages().Len(); i++ {
		if n := md.Messages().Get(i); !n.IsMapEntry() {
			buildMessageFields(s, n)
		}
	}
}

func buildEnum(s *Schema, ed protoreflect.EnumDescriptor) {
	vals := map[int64]string{}
	for i := 0; i < ed.Values().Len(); i++ {
		v := ed.Values().Get(i)
		vals[int64(v.Number())] = string(v.Name())
	}
	s.enums[string(ed.FullName())] = &enumDesc{full: string(ed.FullName()), values: vals}
}

func buildField(s *Schema, f protoreflect.FieldDescriptor) *fieldDesc {
	fd := &fieldDesc{
		name:     string(f.Name()),
		repeated: f.Cardinality() == protoreflect.Repeated && !f.IsMap(),
	}
	switch f.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		md := f.Message()
		if f.IsMap() {
			entry := &messageDesc{full: string(md.FullName()), fields: map[int]*fieldDesc{}}
			entry.fields[1] = buildField(s, f.MapKey())
			entry.fields[2] = buildField(s, f.MapValue())
			fd.isMap = true
			fd.msg = entry
			fd.typeName = "map<" + fieldTypeLabel(s, f.MapKey()) + "," + fieldTypeLabel(s, f.MapValue()) + ">"
		} else {
			fd.typeName = displayName(s.pkg, md)
			// Nil for a message declared outside this file - the hand parser's
			// "an imported one" case, kept deliberately (see the file comment).
			fd.msg = s.msgs[string(md.FullName())]
		}
	case protoreflect.EnumKind:
		fd.typeName = displayName(s.pkg, f.Enum())
		fd.enum = s.enums[string(f.Enum().FullName())]
	default:
		fd.typeName = f.Kind().String()
	}
	return fd
}

// fieldTypeLabel is a field reference as the editor shows it inside a map<K,V>: the
// scalar keyword, or the message/enum name as the file's own package would write it.
func fieldTypeLabel(s *Schema, f protoreflect.FieldDescriptor) string {
	switch f.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return displayName(s.pkg, f.Message())
	case protoreflect.EnumKind:
		return displayName(s.pkg, f.Enum())
	default:
		return f.Kind().String()
	}
}

// displayName is a type's full name minus the parsed file's own package prefix -
// what the source most likely wrote ("Address", "Outer.Inner") rather than the
// fully-qualified form.
func displayName(pkg string, d protoreflect.Descriptor) string {
	full := string(d.FullName())
	if pkg != "" {
		if rest, ok := strings.CutPrefix(full, pkg+"."); ok {
			return rest
		}
	}
	return full
}

// ParseProto compiles a .proto source into the Schema the annotator consumes.
// The compiler is protocompile (0rrb): imports resolve against the well-known
// types, groups read, and the file's own declarations become the Schema's
// message/enum maps. The schemaless protowire walk in grpcproto.go stays the
// fallback when no schema is available at all.
func ParseProto(src string) (*Schema, error) {
	return parseProtoDescriptors(src)
}

// compileProtoSources compiles an import graph held in memory: sources maps
// file path to .proto text, entryPath is the file to compile. protocompile
// follows the imports through the same map (plus the well-known types).
func compileProtoSources(sources map[string]string, entryPath string) ([]protoreflect.FileDescriptor, error) {
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			Accessor: func(path string) (io.ReadCloser, error) {
				if src, ok := sources[path]; ok {
					return io.NopCloser(strings.NewReader(src)), nil
				}
				return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
			},
		}),
		SourceInfoMode: protocompile.SourceInfoNone,
		MaxParallelism: 1,
	}
	files, err := compiler.Compile(context.Background(), entryPath)
	if err != nil {
		return nil, fmt.Errorf("proto: %w", err)
	}
	// Compile returns the entry file linked against its dependencies; the graph
	// itself is collected by walking imports, entry first, so SchemaFromFiles
	// sees every declaration and can take the entry's package from index 0.
	var out []protoreflect.FileDescriptor
	seen := map[string]bool{}
	var walk func(fd protoreflect.FileDescriptor)
	walk = func(fd protoreflect.FileDescriptor) {
		if seen[fd.Path()] {
			return
		}
		seen[fd.Path()] = true
		out = append(out, fd)
		for i := 0; i < fd.Imports().Len(); i++ {
			walk(fd.Imports().Get(i).FileDescriptor)
		}
	}
	walk(files[0])
	return out, nil
}

// SchemaFromFiles builds the Schema from every file of a fetched or compiled
// import graph (0rrb slice 4): unlike ParseProto, which describes one pasted
// file and leaves imported types named-but-unexpanded, a graph carries the
// declarations, so an imported message annotates recursively exactly like a
// local one. The entry file's package is the schema's.
func SchemaFromFiles(files []protoreflect.FileDescriptor) (*Schema, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("proto: no files in the graph")
	}
	s := &Schema{
		pkg:   string(files[0].Package()),
		msgs:  map[string]*messageDesc{},
		enums: map[string]*enumDesc{},
		rpcs:  map[string]rpcDesc{},
		descs: map[string]protoreflect.MessageDescriptor{},
	}
	for _, fd := range files {
		for i := 0; i < fd.Messages().Len(); i++ {
			buildMessageShells(s, fd.Messages().Get(i))
		}
		for i := 0; i < fd.Enums().Len(); i++ {
			buildEnum(s, fd.Enums().Get(i))
		}
	}
	for _, fd := range files {
		for i := 0; i < fd.Messages().Len(); i++ {
			buildMessageFields(s, fd.Messages().Get(i))
		}
		for i := 0; i < fd.Services().Len(); i++ {
			svc := fd.Services().Get(i)
			for j := 0; j < svc.Methods().Len(); j++ {
				m := svc.Methods().Get(j)
				rpc := rpcDesc{}
				if _, ok := s.msgs[string(m.Input().FullName())]; ok {
					rpc.in = string(m.Input().FullName())
				}
				if _, ok := s.msgs[string(m.Output().FullName())]; ok {
					rpc.out = string(m.Output().FullName())
				}
				s.rpcs["/"+string(svc.FullName())+"/"+string(m.Name())] = rpc
			}
		}
	}
	if len(s.order) == 0 {
		return nil, fmt.Errorf("proto: no message declared")
	}
	return s, nil
}
