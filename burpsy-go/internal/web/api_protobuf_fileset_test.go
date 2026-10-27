package web

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// The web half of the .proto file set (burpsy-react-ui-rsu2): POST /api/protobuf/decode accepts a
// file SET (proto_entry + proto_files) whose relative imports resolve across the set. The 0rrb
// ruling holds on the wire too - an import outside the set is a 400 naming the import string.

const (
	rsu2CommonProto = `syntax = "proto3";
package common;
message Id { string value = 1; }
`
	rsu2ShopProto = `syntax = "proto3";
package shop;
import "protos/common.proto";
message GetReq { common.Id id = 1; }
`
)

// common.Id{value:"x"} inside shop.GetReq field 1: field 1, LEN, embedded message(field 1, LEN, "x").
var rsu2Body = base64.StdEncoding.EncodeToString([]byte{0x0a, 0x03, 0x0a, 0x01, 'x'})

func rsu2DecodeBody(extra map[string]any) map[string]any {
	body := map[string]any{
		"body_base64": rsu2Body,
		"grpc":        false,
		"message":     "shop.GetReq",
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func TestProtobufDecodeAcceptsAFileSet(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/protobuf/decode", rsu2DecodeBody(map[string]any{
		"proto_entry": "protos/shop.proto",
		"proto_files": map[string]string{
			"protos/shop.proto":   rsu2ShopProto,
			"protos/common.proto": rsu2CommonProto,
		},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	// The entry file's field is named and carries the imported type's name; the nested fields stay
	// unnamed because imported messages are outside the Schema model by design (dynamicpb's job).
	if !strings.Contains(rec.Body.String(), `"name":"id"`) || !strings.Contains(rec.Body.String(), `"type":"common.Id"`) {
		t.Errorf("the fields were not named against the set's schema: %s", rec.Body.String())
	}
}

func TestProtobufDecodeRefusesProtoAndProtoFilesTogether(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/protobuf/decode", rsu2DecodeBody(map[string]any{
		"proto":       rsu2ShopProto,
		"proto_entry": "protos/shop.proto",
		"proto_files": map[string]string{"protos/shop.proto": rsu2ShopProto},
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want a 400 refusing the ambiguous schema input", rec.Code)
	}
}

func TestProtobufDecodeRefusesASetWithoutAnEntryPoint(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/protobuf/decode", rsu2DecodeBody(map[string]any{
		"proto_files": map[string]string{"protos/shop.proto": rsu2ShopProto},
	}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "proto_entry") {
		t.Fatalf("status = %d, body = %s; want a 400 naming proto_entry", rec.Code, rec.Body.String())
	}
}

func TestProtobufDecodeRefusesAnEntryPointOutsideTheSet(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/protobuf/decode", rsu2DecodeBody(map[string]any{
		"proto_entry": "protos/missing.proto",
		"proto_files": map[string]string{"protos/shop.proto": rsu2ShopProto},
	}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "protos/missing.proto") {
		t.Fatalf("status = %d, body = %s; want a 400 naming the missing entry", rec.Code, rec.Body.String())
	}
}

func TestProtobufDecodeSetRefusesAnUnresolvedImportByName(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/protobuf/decode", rsu2DecodeBody(map[string]any{
		"proto_entry": "protos/shop.proto",
		"proto_files": map[string]string{"protos/shop.proto": rsu2ShopProto},
	}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "protos/common.proto") {
		t.Fatalf("status = %d, body = %s; want a 400 naming the unresolved import", rec.Code, rec.Body.String())
	}
}

func TestProtobufDecodeSetRejectsEscapingPaths(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/protobuf/decode", rsu2DecodeBody(map[string]any{
		"proto_entry": "../etc/passwd.proto",
		"proto_files": map[string]string{"../etc/passwd.proto": rsu2ShopProto},
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want a 400 refusing a path that escapes the set", rec.Code)
	}
}
