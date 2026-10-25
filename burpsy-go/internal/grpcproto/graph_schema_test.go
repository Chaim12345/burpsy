package grpcproto

import (
	"encoding/hex"
	"testing"
)

// SchemaFromFiles: an imported message annotates recursively, where the
// single-file ParseProto leaves it named-but-unexpanded (0rrb slice 4).
func TestSchemaFromFilesAnnotatesAnImportedMessage(t *testing.T) {
	files, err := compileProtoSources(map[string]string{
		"base.proto": `syntax = "proto3"; package base; message Stamp { int64 seconds = 1; }`,
		"main.proto": `syntax = "proto3"; package main; import "base.proto";
message Event { base.Stamp at = 1; string what = 2; }`,
	}, "main.proto")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s, err := SchemaFromFiles(files)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	// field 1: length-delimited nested {field 1 varint 42}; field 2: "deploy"
	inner, _ := hex.DecodeString("082a")
	raw, _ := hex.DecodeString("0a02" + hex.EncodeToString(inner) + "12066465706c6f79")
	fields, _ := Decode(raw)
	out, err := s.Annotate(fields, "main.Event")
	if err != nil {
		t.Fatal(err)
	}
	at := find(out, 1)
	if at.LenKind != LenMessage {
		t.Fatalf("the imported type stayed unexpanded: %+v", at)
	}
	if inner1 := find(at.Message, 1); inner1.Name != "seconds" || inner1.Varint != "42" {
		t.Fatalf("imported field not named: %+v", inner1)
	}
	if find(out, 2).Name != "what" {
		t.Fatalf("local field lost its name: %+v", out)
	}
	assertSameBytes(t, raw, out)
}

// The same sources through the single-file ParseProto keep the old boundary:
// named, not expanded. Both behaviors are deliberate and pinned.
func TestParseProtoStillLeavesAnImportedTypeUnexpanded(t *testing.T) {
	// ParseProto resolves imports only against the well-known types, so a
	// same-graph import is a hard fail by ruling; what this pins is the WKT
	// case: Timestamp is known but stays named-not-expanded.
	s := mustParse(t, `syntax = "proto3";
import "google/protobuf/timestamp.proto";
message Event { google.protobuf.Timestamp at = 1; }`)
	inner, _ := hex.DecodeString("082a")
	raw, _ := hex.DecodeString("0a02" + hex.EncodeToString(inner))
	fields, _ := Decode(raw)
	out, err := s.Annotate(fields, "Event")
	if err != nil {
		t.Fatal(err)
	}
	at := find(out, 1)
	if at.Name != "at" || at.Type != "google.protobuf.Timestamp" {
		t.Fatalf("the WKT reference lost its declared name: %+v", at)
	}
	// The schemaless guess may still walk the payload as a message; the schema
	// boundary is that no names come from the imported declaration.
	if find(at.Message, 1) != nil && find(at.Message, 1).Name != "" {
		t.Fatalf("single-file semantics must not name an imported type's fields: %+v", at)
	}
	assertSameBytes(t, raw, out)
}
