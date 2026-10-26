package grpcproto

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	reflectv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// reflection.go is the gRPC server-reflection client half of 0rrb: ask a target
// for the file descriptors behind a service, following the import graph until
// every dependency is fetched. Whoever dials owns the egress decision (scope,
// authorization); this package only speaks the reflection protocol on a
// connection it is handed. 47id wires this into the product surfaces.

// FetchServiceDescriptors walks server reflection for the file declaring
// symbol (a fully-qualified service or message name, e.g. "acme.v1.Users") and
// every file in its transitive dependency graph. The returned files are linked
// into one registry, so every type reference resolves.
func FetchServiceDescriptors(ctx context.Context, conn grpc.ClientConnInterface, symbol string) ([]protoreflect.FileDescriptor, error) {
	client := reflectv1.NewServerReflectionClient(conn)
	// byPath accumulates the raw FileDescriptorProtos keyed by file path;
	// arrival records fetch order, so the entry pick is deterministic.
	byPath := map[string]*descriptorpb.FileDescriptorProto{}
	var arrival []string
	request := func(makeReq func() *reflectv1.ServerReflectionRequest) error {
		stream, err := client.ServerReflectionInfo(ctx)
		if err != nil {
			return fmt.Errorf("reflection: open stream: %w", err)
		}
		if err := stream.Send(makeReq()); err != nil {
			return fmt.Errorf("reflection: send: %w", err)
		}
		resp, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("reflection: receive: %w", err)
		}
		switch r := resp.MessageResponse.(type) {
		case *reflectv1.ServerReflectionResponse_FileDescriptorResponse:
			for _, raw := range r.FileDescriptorResponse.FileDescriptorProto {
				fdp := &descriptorpb.FileDescriptorProto{}
				if err := proto.Unmarshal(raw, fdp); err != nil {
					return fmt.Errorf("reflection: undecodable FileDescriptorProto: %w", err)
				}
				if _, ok := byPath[fdp.GetName()]; !ok {
					arrival = append(arrival, fdp.GetName())
				}
				byPath[fdp.GetName()] = fdp
			}
			return nil
		case *reflectv1.ServerReflectionResponse_ErrorResponse:
			return fmt.Errorf("reflection: server: %s", r.ErrorResponse.ErrorMessage)
		default:
			return fmt.Errorf("reflection: unexpected response %T", r)
		}
	}

	if err := request(func() *reflectv1.ServerReflectionRequest {
		return &reflectv1.ServerReflectionRequest{
			MessageRequest: &reflectv1.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: symbol},
		}
	}); err != nil {
		return nil, err
	}
	// The entry is the file declaring the symbol: the only choice independent
	// of answer order and map iteration. grpc-go sends the declaring file
	// first, so arrival order is the fallback when no file's declarations
	// match (a server that answers a partially qualified symbol).
	entryPath := ""
	for _, path := range arrival {
		if declaresSymbol(byPath[path], symbol) {
			entryPath = path
			break
		}
	}
	if entryPath == "" && len(arrival) > 0 {
		entryPath = arrival[0]
	}
	// BFS the import graph: every dependency the graph names that we do not
	// already hold gets its own FileByFilename request.
	for {
		missing := ""
		for _, fdp := range byPath {
			for _, dep := range fdp.GetDependency() {
				if _, ok := byPath[dep]; !ok {
					missing = dep
					break
				}
			}
			if missing != "" {
				break
			}
		}
		if missing == "" {
			break
		}
		path := missing
		if err := request(func() *reflectv1.ServerReflectionRequest {
			return &reflectv1.ServerReflectionRequest{
				MessageRequest: &reflectv1.ServerReflectionRequest_FileByFilename{FileByFilename: path},
			}
		}); err != nil {
			return nil, fmt.Errorf("reflection: dependency %q: %w", path, err)
		}
	}

	set := &descriptorpb.FileDescriptorSet{}
	for _, fdp := range byPath {
		set.File = append(set.File, fdp)
	}
	registry, err := protodesc.NewFiles(set)
	if err != nil {
		return nil, fmt.Errorf("reflection: linking the fetched graph: %w", err)
	}
	// Order the result entry-first (SchemaFromFiles takes the package from
	// index 0), then the import graph breadth-first. The entry is the first
	// file the FileContainingSymbol answer brought back.
	entry, err := registry.FindFileByPath(entryPath)
	if err != nil {
		return nil, fmt.Errorf("reflection: the linked graph lost the entry file: %w", err)
	}
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
	walk(entry)
	// Any file the entry's graph does not reach (a public import's sibling)
	// still ships, after the reachable ones.
	registry.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !seen[fd.Path()] {
			out = append(out, fd)
		}
		return true
	})
	return out, nil
}

// declaresSymbol reports whether fdp declares the fully-qualified symbol as a
// top-level message (or nested message), enum, or service of its package.
func declaresSymbol(fdp *descriptorpb.FileDescriptorProto, symbol string) bool {
	prefix := fdp.GetPackage() + "."
	if !strings.HasPrefix(symbol, prefix) {
		return false
	}
	rest := symbol[len(prefix):]
	var inMessage func(d *descriptorpb.DescriptorProto, name string) bool
	inMessage = func(d *descriptorpb.DescriptorProto, name string) bool {
		if d.GetName() == name {
			return true
		}
		for _, n := range d.GetNestedType() {
			if strings.HasPrefix(name, d.GetName()+".") && inMessage(n, name[len(d.GetName())+1:]) {
				return true
			}
		}
		return false
	}
	for _, m := range fdp.GetMessageType() {
		if inMessage(m, rest) {
			return true
		}
	}
	for _, e := range fdp.GetEnumType() {
		if e.GetName() == rest {
			return true
		}
	}
	for _, svc := range fdp.GetService() {
		if svc.GetName() == rest {
			return true
		}
	}
	return false
}
