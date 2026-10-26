package grpcproto

import (
	"context"
	"io"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	reflectv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// The reflection client against a real gRPC server (bufconn, in-process): the
// server reflects a service whose file protocompile built, and the client must
// fetch that file plus its transitive dependencies.

const reflectTestProto = `syntax = "proto3";
package reflecttest;
import "google/protobuf/timestamp.proto";
message Seen { google.protobuf.Timestamp at = 1; }
service Sightings { rpc List (Seen) returns (Seen); }
`

func TestFetchServiceDescriptorsWalksTheImportGraph(t *testing.T) {
	// A file compiled by protocompile, registered into the global registry the
	// reflection server answers from. The path and package are unique to this
	// test because the global registry has no unregister.
	compiled, err := CompileProto(reflectTestProto, "reflecttest/sightings.proto")
	if err != nil {
		t.Fatalf("compile the fixture: %v", err)
	}
	if err := protoregistry.GlobalFiles.RegisterFile(compiled); err != nil {
		t.Fatalf("register: %v", err)
	}

	srv := grpc.NewServer()
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "reflecttest.Sightings",
		Metadata:    "reflecttest/sightings.proto",
	}, nil)
	reflection.Register(srv)

	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	files, err := FetchServiceDescriptors(context.Background(), conn, "reflecttest.Sightings")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	var sawOwn, sawTimestamp bool
	for _, fd := range files {
		switch fd.Path() {
		case "reflecttest/sightings.proto":
			sawOwn = true
			if fd.Messages().ByName("Seen") == nil || fd.Services().ByName("Sightings") == nil {
				t.Fatalf("the fetched file lost its declarations")
			}
		case "google/protobuf/timestamp.proto":
			sawTimestamp = true
		}
	}
	if !sawOwn || !sawTimestamp {
		t.Fatalf("graph walk incomplete: own=%v timestamp=%v", sawOwn, sawTimestamp)
	}
}

func TestFetchServiceDescriptorsReportsAnUnknownSymbol(t *testing.T) {
	srv := grpc.NewServer()
	reflection.Register(srv)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := FetchServiceDescriptors(context.Background(), conn, "no.SuchService"); err == nil {
		t.Fatal("an unknown symbol must error, not return an empty graph")
	}
}

// A fake reflection server whose FileContainingSymbol answer ships the whole
// chain a -> b -> c DEPENDENCY-FIRST: the entry must still come out as the
// declaring file, not whichever path map iteration or arrival order hands over
// (PR #363 review).
type chainReflection struct {
	reflectv1.UnimplementedServerReflectionServer
	byPath map[string]*descriptorpb.FileDescriptorProto
	answer []*descriptorpb.FileDescriptorProto
}

func (f *chainReflection) ServerReflectionInfo(stream reflectv1.ServerReflection_ServerReflectionInfoServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var protos [][]byte
		switch r := req.MessageRequest.(type) {
		case *reflectv1.ServerReflectionRequest_FileContainingSymbol:
			for _, fdp := range f.answer {
				raw, _ := proto.Marshal(fdp)
				protos = append(protos, raw)
			}
		case *reflectv1.ServerReflectionRequest_FileByFilename:
			if fdp := f.byPath[r.FileByFilename]; fdp != nil {
				raw, _ := proto.Marshal(fdp)
				protos = append(protos, raw)
			}
		}
		if err := stream.Send(&reflectv1.ServerReflectionResponse{
			MessageResponse: &reflectv1.ServerReflectionResponse_FileDescriptorResponse{
				FileDescriptorResponse: &reflectv1.FileDescriptorResponse{FileDescriptorProto: protos},
			},
		}); err != nil {
			return err
		}
	}
}

func chainFDP(name, pkg, msg string, deps ...string) *descriptorpb.FileDescriptorProto {
	return &descriptorpb.FileDescriptorProto{
		Name:        proto.String(name),
		Package:     proto.String(pkg),
		Dependency:  deps,
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String(msg)}},
	}
}

func TestFetchServiceDescriptorsEntryIsTheDeclaringFileInAChain(t *testing.T) {
	fdpC := chainFDP("chaintest/c.proto", "rvc", "C")
	fdpB := chainFDP("chaintest/b.proto", "rvb", "B", "chaintest/c.proto")
	fdpA := chainFDP("chaintest/a.proto", "rva", "A", "chaintest/b.proto")
	fake := &chainReflection{
		byPath: map[string]*descriptorpb.FileDescriptorProto{
			"chaintest/a.proto": fdpA, "chaintest/b.proto": fdpB, "chaintest/c.proto": fdpC,
		},
		// Adversarial: deepest dependency first, declaring file last.
		answer: []*descriptorpb.FileDescriptorProto{fdpC, fdpB, fdpA},
	}
	srv := grpc.NewServer()
	reflectv1.RegisterServerReflectionServer(srv, fake)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// Map iteration order varies per call; enough rounds that the old
	// non-convergent pick cannot keep landing on the declaring file.
	for round := 0; round < 200; round++ {
		files, err := FetchServiceDescriptors(context.Background(), conn, "rva.A")
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if len(files) != 3 {
			t.Fatalf("round %d: got %d files, want the 3-file chain", round, len(files))
		}
		if files[0].Path() != "chaintest/a.proto" || string(files[0].Package()) != "rva" {
			t.Fatalf("round %d: entry is %s (package %s), want chaintest/a.proto (rva)", round, files[0].Path(), files[0].Package())
		}
	}
}
