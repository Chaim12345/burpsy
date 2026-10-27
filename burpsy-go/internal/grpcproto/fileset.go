package grpcproto

// fileset.go is the multi-file half of descriptor_schema.go (burpsy-react-ui-rsu2): a schema split
// across operator files compiles as a SET - a named entry point plus every file of its import
// graph - with relative imports resolving across the set and the well-known types still resolving
// against protocompile's standard imports. The 0rrb ruling is unchanged: an import the set does
// not contain is a hard fail naming the import string, because a partial schema read as complete
// misattributes fields.

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// CompileProtoSet compiles entry against files (path -> source), resolving imports across the set
// and against the well-known types. Entry must be a key of files; the error names it when it is
// not, and protocompile's own error names any import the set does not satisfy.
func CompileProtoSet(entry string, files map[string]string) (protoreflect.FileDescriptor, error) {
	if _, ok := files[entry]; !ok {
		known := make([]string, 0, len(files))
		for path := range files {
			known = append(known, path)
		}
		sort.Strings(known)
		return nil, fmt.Errorf("proto: the entry point %q is not one of the uploaded files (%s)",
			entry, strings.Join(known, ", "))
	}
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			Accessor: func(path string) (io.ReadCloser, error) {
				if src, ok := files[path]; ok {
					return io.NopCloser(strings.NewReader(src)), nil
				}
				return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
			},
		}),
		SourceInfoMode: protocompile.SourceInfoNone,
		MaxParallelism: 1,
	}
	compiled, err := compiler.Compile(context.Background(), entry)
	if err != nil {
		return nil, fmt.Errorf("proto: %w", err)
	}
	return compiled[0], nil
}

// ParseProtoSet builds the Schema of the ENTRY file of a multi-file set. Imported types stay
// outside the Schema model exactly as descriptor_schema.go documents for single-file compiles:
// the model describes messages it can annotate against, and recursion into an imported message is
// the dynamicpb slice's job.
func ParseProtoSet(entry string, files map[string]string) (*Schema, error) {
	fd, err := CompileProtoSet(entry, files)
	if err != nil {
		return nil, err
	}
	return schemaFromFile(fd)
}
