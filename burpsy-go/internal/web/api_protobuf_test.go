package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/grpcproto"
)

func protoSample(t *testing.T) []byte {
	t.Helper()
	raw, err := grpcproto.Encode([]grpcproto.Field{
		{Number: 1, WireType: 0, Varint: "150"},
		{Number: 2, WireType: 2, LenKind: grpcproto.LenString, String: "testing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// burpsy-react-ui-3x2g: decode a bare protobuf body to a field tree, edit a field, re-encode, and
// confirm the body changed exactly as edited.
func TestProtobufDecodeEditEncode(t *testing.T) {
	s := newTestServer()
	raw := protoSample(t)

	dec := postJSON(t, s, "/api/protobuf/decode", map[string]any{"body_base64": base64.StdEncoding.EncodeToString(raw), "grpc": false})
	if dec.Code != http.StatusOK {
		t.Fatalf("decode = %d: %s", dec.Code, dec.Body.String())
	}
	var decResp protoDecodeResponse
	if err := json.Unmarshal(dec.Body.Bytes(), &decResp); err != nil {
		t.Fatal(err)
	}
	if len(decResp.Frames) != 1 || len(decResp.Frames[0].Fields) != 2 {
		t.Fatalf("decoded frames = %+v", decResp.Frames)
	}
	if decResp.Frames[0].Fields[0].Varint != "150" || decResp.Frames[0].Fields[1].String != "testing" {
		t.Errorf("decoded fields wrong: %+v", decResp.Frames[0].Fields)
	}

	// Edit field 2 and re-encode.
	decResp.Frames[0].Fields[1].String = "TAMPERED"
	enc := postJSON(t, s, "/api/protobuf/encode", map[string]any{"grpc": false, "frames": decResp.Frames})
	if enc.Code != http.StatusOK {
		t.Fatalf("encode = %d: %s", enc.Code, enc.Body.String())
	}
	var encResp struct {
		BodyBase64 string `json:"body_base64"`
	}
	json.Unmarshal(enc.Body.Bytes(), &encResp)
	newRaw, _ := base64.StdEncoding.DecodeString(encResp.BodyBase64)
	fields, err := grpcproto.Decode(newRaw)
	if err != nil || fields[1].String != "TAMPERED" || fields[0].Varint != "150" {
		t.Errorf("re-encoded body wrong: %+v (%v)", fields, err)
	}
}

// A gRPC-framed body decodes per frame and re-frames on encode.
func TestProtobufGRPCFramedDecode(t *testing.T) {
	s := newTestServer()
	framed := grpcproto.FrameMessage(protoSample(t))

	dec := postJSON(t, s, "/api/protobuf/decode", map[string]any{"body_base64": base64.StdEncoding.EncodeToString(framed), "grpc": true})
	var decResp protoDecodeResponse
	json.Unmarshal(dec.Body.Bytes(), &decResp)
	if !decResp.GRPC || len(decResp.Frames) != 1 || len(decResp.Frames[0].Fields) != 2 {
		t.Fatalf("grpc decode = %+v", decResp)
	}

	enc := postJSON(t, s, "/api/protobuf/encode", map[string]any{"grpc": true, "frames": decResp.Frames})
	var encResp struct {
		BodyBase64 string `json:"body_base64"`
	}
	json.Unmarshal(enc.Body.Bytes(), &encResp)
	out, _ := base64.StdEncoding.DecodeString(encResp.BodyBase64)
	frames, err := grpcproto.Unframe(out)
	if err != nil || len(frames) != 1 {
		t.Fatalf("re-framed body wrong: %v", err)
	}
}

// A body that is not protobuf decodes to an error on the frame, not a 500 or a wrong tree.
func TestProtobufDecodeReportsNonProtobuf(t *testing.T) {
	s := newTestServer()
	dec := postJSON(t, s, "/api/protobuf/decode", map[string]any{"body_base64": base64.StdEncoding.EncodeToString([]byte{0x0a, 0x05, 0x01}), "grpc": false})
	if dec.Code != http.StatusOK {
		t.Fatalf("decode = %d", dec.Code)
	}
	var decResp protoDecodeResponse
	json.Unmarshal(dec.Body.Bytes(), &decResp)
	if decResp.Frames[0].Error == "" {
		t.Error("a non-protobuf body did not report a decode error")
	}
}

// burpsy-react-ui-3pco: with a .proto supplied, decode names the fields; a schema that does not parse
// or names no such message is a 400 rather than a silently unnamed tree.
func TestProtobufDecodeNamesFieldsFromAProto(t *testing.T) {
	s := newTestServer()
	b64 := base64.StdEncoding.EncodeToString(protoSample(t))
	const proto = `syntax = "proto3"; package demo; message Req { int32 user_id = 1; string label = 2; }`

	rec := postJSON(t, s, "/api/protobuf/decode", map[string]any{"body_base64": b64, "proto": proto})
	if rec.Code != http.StatusOK {
		t.Fatalf("decode = %d: %s", rec.Code, rec.Body.String())
	}
	var resp protoDecodeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// One message in the schema, so it is chosen without the operator naming it.
	if resp.Message != "demo.Req" || len(resp.Messages) != 1 {
		t.Fatalf("message = %q, messages = %v", resp.Message, resp.Messages)
	}
	f := resp.Frames[0].Fields
	if f[0].Name != "user_id" || f[0].Type != "int32" || f[1].Name != "label" {
		t.Fatalf("fields were not named: %+v", f)
	}

	// Without a proto the response is the schemaless view, unchanged.
	plain := postJSON(t, s, "/api/protobuf/decode", map[string]any{"body_base64": b64})
	var plainResp protoDecodeResponse
	_ = json.Unmarshal(plain.Body.Bytes(), &plainResp)
	if plainResp.Frames[0].Fields[0].Name != "" || plainResp.Messages != nil {
		t.Fatalf("no proto must mean no names: %+v", plainResp)
	}

	for name, body := range map[string]map[string]any{
		"unparseable proto": {"body_base64": b64, "proto": "message {"},
		"unknown message":   {"body_base64": b64, "proto": proto, "message": "Nope"},
	} {
		if r := postJSON(t, s, "/api/protobuf/decode", body); r.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, r.Code)
		}
	}
}

// burpsy-react-ui-3pco: a gRPC call path names the message for each direction, so request and
// response are read as their own types without the operator choosing.
func TestProtobufDecodeResolvesTheMessageFromTheRPCPath(t *testing.T) {
	s := newTestServer()
	b64 := base64.StdEncoding.EncodeToString(protoSample(t))
	const proto = `syntax = "proto3"; package p; message A { int32 a_id = 1; string a_s = 2; } message B { int32 b_id = 1; string b_s = 2; }
service S { rpc Call (A) returns (B); }`
	for dir, want := range map[string]string{"request": "a_id", "response": "b_id"} {
		rec := postJSON(t, s, "/api/protobuf/decode", map[string]any{"body_base64": b64, "proto": proto, "rpc_path": "/p.S/Call", "direction": dir})
		var resp protoDecodeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", dir, rec.Code, rec.Body.String())
		}
		if got := resp.Frames[0].Fields[0].Name; got != want {
			t.Errorf("%s: field 1 named %q, want %q (message %q)", dir, got, want, resp.Message)
		}
	}
}

func TestProtobufDecodeAnUnresolvedImportNamesItselfAndTheFallback(t *testing.T) {
	s := newTestServer()
	body := map[string]any{
		"body_base64": base64.StdEncoding.EncodeToString(protoSample(t)),
		"proto":       "syntax = \"proto3\";\nimport \"acme/missing.proto\";\nmessage M { int32 a = 1; }",
	}
	r := postJSON(t, s, "/api/protobuf/decode", body)
	if r.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", r.Code)
	}
	text := r.Body.String()
	if !strings.Contains(text, "acme/missing.proto") {
		t.Fatalf("the error must name the unresolved import: %q", text)
	}
	if !strings.Contains(text, "omit the proto") {
		t.Fatalf("the error must point at the schemaless fallback: %q", text)
	}
}

func TestProtobufDecodeTheOracleRefusesANonconformingBodyHonestly(t *testing.T) {
	s := newTestServer()
	proto := `syntax = "proto3"; message M { int32 n = 1; string s = 2; }`
	// Field 2 declared string, bytes 0xff: invalid UTF-8. The schemaless walk
	// shows it as hex; the oracle refuses the schema's claims over it.
	b64 := base64.StdEncoding.EncodeToString([]byte{0x08, 0x96, 0x01, 0x12, 0x01, 0xff})
	r := postJSON(t, s, "/api/protobuf/decode", map[string]any{"body_base64": b64, "proto": proto, "message": "M"})
	if r.Code != http.StatusOK {
		t.Fatalf("a nonconforming body is reported, not a 400: got %d", r.Code)
	}
	var resp protoDecodeResponse
	if err := json.Unmarshal(r.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	fr := resp.Frames[0]
	if fr.Error == "" || !strings.Contains(fr.Error, "M") {
		t.Fatalf("the mismatch must be named: %+v", fr)
	}
	if len(fr.Fields) != 2 {
		t.Fatalf("the schemaless structure stays visible: %+v", fr)
	}
	if fr.Fields[0].Name != "" || fr.Fields[1].Name != "" {
		t.Fatalf("a nonconforming body drops the schema's names: %+v", fr.Fields)
	}
}
