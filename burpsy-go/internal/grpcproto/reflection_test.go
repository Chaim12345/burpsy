package grpcproto

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/reflect/protoregistry"
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
	compiled, err := compileProto(reflectTestProto, "reflecttest/sightings.proto")
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
		grpc.WithInsecure())
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
		grpc.WithInsecure())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := FetchServiceDescriptors(context.Background(), conn, "no.SuchService"); err == nil {
		t.Fatal("an unknown symbol must error, not return an empty graph")
	}
}
