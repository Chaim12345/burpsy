package web

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/grpcproto"
)

// ---- Protobuf / gRPC body decoding (burpsy-react-ui-3x2g) ----------------------------------------
//
// gRPC and protobuf bodies are opaque binary in the editor, history and Repeater; these two
// endpoints make one readable and editable without a .proto. Decode turns a body into a field tree
// (optionally after stripping gRPC framing); Encode turns an edited tree back into the body bytes,
// re-framing it when it was gRPC. Pure transforms — they read a body the operator is already looking
// at and send nothing, so riskLocal.

// protoFrameView is one decoded frame: a bare protobuf body is one frame with no flags, a gRPC body
// is one per length-prefixed frame.
type protoFrameView struct {
	Compressed bool              `json:"compressed,omitempty"`
	Trailer    bool              `json:"trailer,omitempty"`
	Fields     []grpcproto.Field `json:"fields,omitempty"`
	// Text is set for a frame that is not a protobuf message to decode — a gRPC-web trailer block, or
	// a compressed frame this build does not inflate — so the view shows something rather than an
	// empty tree.
	Text string `json:"text,omitempty"`
	// Error is why a frame did not decode as protobuf (so the view falls back to its raw bytes rather
	// than claiming an empty message).
	Error string `json:"error,omitempty"`
}

type protoDecodeResponse struct {
	GRPC   bool             `json:"grpc"`
	Frames []protoFrameView `json:"frames"`
}

// handleProtobufDecode serves POST /api/protobuf/decode. riskLocal.
func (s *Server) handleProtobufDecode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		BodyBase64 string `json:"body_base64"`
		GRPC       bool   `json:"grpc"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&body); err != nil {
		http.Error(w, `the body must be {"body_base64":"...","grpc":bool}`, http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.BodyBase64)
	if err != nil {
		http.Error(w, "body_base64 is not valid base64", http.StatusBadRequest)
		return
	}

	resp := protoDecodeResponse{GRPC: body.GRPC}
	if body.GRPC {
		frames, err := grpcproto.Unframe(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, fr := range frames {
			view := protoFrameView{Compressed: fr.Compressed, Trailer: fr.Trailer}
			switch {
			case fr.Trailer:
				view.Text = string(fr.Message)
			case fr.Compressed:
				view.Text = "(compressed frame — burpsy does not inflate gRPC frames; strip the compression flag to edit)"
			default:
				if fields, derr := grpcproto.Decode(fr.Message); derr != nil {
					view.Error = derr.Error()
				} else {
					view.Fields = fields
				}
			}
			resp.Frames = append(resp.Frames, view)
		}
	} else {
		fields, derr := grpcproto.Decode(raw)
		view := protoFrameView{}
		if derr != nil {
			view.Error = derr.Error()
		} else {
			view.Fields = fields
		}
		resp.Frames = []protoFrameView{view}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleProtobufEncode serves POST /api/protobuf/encode. riskLocal.
func (s *Server) handleProtobufEncode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		GRPC   bool             `json:"grpc"`
		Frames []protoFrameView `json:"frames"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&body); err != nil {
		http.Error(w, `the body must be {"grpc":bool,"frames":[...]}`, http.StatusBadRequest)
		return
	}
	if !body.GRPC {
		if len(body.Frames) != 1 {
			http.Error(w, "a bare protobuf body is exactly one frame", http.StatusBadRequest)
			return
		}
		raw, err := grpcproto.Encode(body.Frames[0].Fields)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"body_base64": base64.StdEncoding.EncodeToString(raw)})
		return
	}

	var frames []grpcproto.Frame
	for _, fv := range body.Frames {
		var message []byte
		switch {
		case fv.Trailer, fv.Compressed:
			// A frame burpsy did not decode is written back from its text verbatim — the operator
			// cannot edit its fields, but its bytes must survive a re-encode of the other frames.
			message = []byte(fv.Text)
		default:
			enc, err := grpcproto.Encode(fv.Fields)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			message = enc
		}
		frames = append(frames, grpcproto.Frame{Compressed: fv.Compressed, Trailer: fv.Trailer, Message: message})
	}
	writeJSON(w, http.StatusOK, map[string]string{"body_base64": base64.StdEncoding.EncodeToString(grpcproto.Reframe(frames))})
}
