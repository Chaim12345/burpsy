package grpcproto

import (
	"strings"
	"testing"
)

// The file-set compile (burpsy-react-ui-rsu2): schemas split across operator files resolve their
// relative imports across the set, with one named entry point. The 0rrb ruling stands - an import
// the set does not contain is still a hard fail naming the import string; the set is the way to
// bring the rest of an import graph, not a relaxation.

const (
	rsu2Common = `syntax = "proto3";
package common;
message Id { string value = 1; }
`
	rsu2Service = `syntax = "proto3";
package shop;
import "protos/common.proto";
message GetReq { common.Id id = 1; }
service Shop { rpc Get(GetReq) returns (GetReq); }
`
)

func TestParseProtoSetResolvesARelativeImportAcrossTheSet(t *testing.T) {
	s, err := ParseProtoSet("protos/shop.proto", map[string]string{
		"protos/shop.proto":   rsu2Service,
		"protos/common.proto": rsu2Common,
	})
	if err != nil {
		t.Fatalf("a two-file set failed to compile: %v", err)
	}
	if got := s.DefaultMessage(); got != "shop.GetReq" {
		t.Errorf("DefaultMessage = %q, want shop.GetReq from the entry file", got)
	}
	if got := s.MessageForRPC("/shop.Shop/Get", "request"); got != "shop.GetReq" {
		t.Errorf("MessageForRPC = %q, want shop.GetReq", got)
	}
}

func TestParseProtoSetStillResolvesWellKnownImports(t *testing.T) {
	src := `syntax = "proto3";
package wkt;
import "google/protobuf/empty.proto";
message Wrap { google.protobuf.Empty e = 1; }
`
	if _, err := ParseProtoSet("wkt.proto", map[string]string{"wkt.proto": src}); err != nil {
		t.Fatalf("a standard import must keep resolving: %v", err)
	}
}

func TestParseProtoSetRefusesAnImportOutsideTheSetByName(t *testing.T) {
	_, err := ParseProtoSet("protos/shop.proto", map[string]string{"protos/shop.proto": rsu2Service})
	if err == nil || !strings.Contains(err.Error(), "protos/common.proto") {
		t.Fatalf("err = %v, want a hard fail naming the unresolved import string", err)
	}
}

func TestParseProtoSetRefusesAnEntryPointOutsideTheSet(t *testing.T) {
	_, err := ParseProtoSet("protos/missing.proto", map[string]string{"protos/shop.proto": rsu2Service})
	if err == nil || !strings.Contains(err.Error(), "protos/missing.proto") {
		t.Fatalf("err = %v, want an error naming the missing entry point", err)
	}
}

func TestParseProtoSetKeepsImportedTypesOutOfTheSchemaModel(t *testing.T) {
	// The Schema model describes the ENTRY file's messages; an imported message still resolves to
	// nil in the model, as descriptor_schema.go documents - recursion into it is dynamicpb's job.
	s, err := ParseProtoSet("protos/shop.proto", map[string]string{
		"protos/shop.proto":   rsu2Service,
		"protos/common.proto": rsu2Common,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Annotate(nil, "common.Id"); err == nil {
		t.Error("the imported message must not be annotatable through the entry file's Schema")
	}
}
