package grpcproto

import (
	"context"
	"fmt"

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
	// queue is the BFS frontier of paths not yet requested.
	byPath := map[string]*descriptorpb.FileDescriptorProto{}
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
	files, err := protodesc.NewFiles(set)
	if err != nil {
		return nil, fmt.Errorf("reflection: linking the fetched graph: %w", err)
	}
	var out []protoreflect.FileDescriptor
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		out = append(out, fd)
		return true
	})
	return out, nil
}
