package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
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
