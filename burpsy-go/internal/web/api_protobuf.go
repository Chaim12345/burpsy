package web

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	// Messages and Message are set only when a .proto was supplied (burpsy-react-ui-3pco): every
	// message the schema declares, and the one the fields were named against ("" when the schema has
	// several and the operator has not chosen, in which case the fields are shown unnamed).
	Messages []string `json:"messages,omitempty"`
	Message  string   `json:"message,omitempty"`
	// SchemaSource and SchemaFiles are the names' provenance (47id): "reflection"
	// means a TARGET supplied the schema over the network - adversary-controllable
	// input that must never read as operator-supplied .proto - and SchemaFiles is
	// what it served. Empty means an operator-pasted .proto or no schema.
	SchemaSource string   `json:"schema_source,omitempty"`
	SchemaFiles  []string `json:"schema_files,omitempty"`
}

// protobufDecodeReq is the request body handleProtobufDecode decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type protobufDecodeReq struct {
	BodyBase64 string `json:"body_base64"`
	GRPC       bool   `json:"grpc"`
	// Proto is optional .proto source and Message the message type to read the body as; together
	// they turn `#1 varint 150` into `user_id (int32) 150`. Without Proto the response is the
	// schemaless view, unchanged.
	Proto   string `json:"proto"`
	Message string `json:"message"`
	// RPCPath and Direction let a gRPC body name its own type: the call path (/pkg.Service/Method)
	// plus the schema's service block give the request and response messages, so the operator
	// need not pick one. Direction is "request" or "response". Message, when set, wins.
	RPCPath   string `json:"rpc_path"`
	Direction string `json:"direction"`
	// ProtoEntry and ProtoFiles are the multi-file form (burpsy-react-ui-rsu2): a schema split
	// across operator files, sent as the entry point's path plus every file of its import graph
	// (path -> source). Imports resolve across the set; one the set does not contain is the same
	// hard 400 the single-file form gives, naming the import string. Mutually exclusive with
	// Proto: one request carries one schema form.
	ProtoEntry string            `json:"proto_entry"`
	ProtoFiles map[string]string `json:"proto_files"`
}

// handleProtobufDecode serves POST /api/protobuf/decode. riskLocal.
func (s *Server) handleProtobufDecode(w http.ResponseWriter, r *http.Request) {
	var body protobufDecodeReq
	if err := requestJSON(w, r, io.LimitReader(r.Body, 8<<20)).Decode(&body); err != nil {
		http.Error(w, `the body must be {"body_base64":"...","grpc":bool,"proto":"...","message":"..."}`, http.StatusBadRequest)
		return
	}
	// 400, not a silent schemaless fallback, when a supplied schema does not parse: an operator who
	// pasted a schema and sees unnamed fields would assume the schema did not match the body, when
	// it did not parse. Per the 0rrb integrator ruling this holds for unresolved imports too - the
	// error names the exact import string (a decode built on a partial schema would not read as
	// partial, and a wrong field attribution in a security tool reads as evidence). The schemaless
	// fallback stays reachable, and the error says so: resubmit without the proto.
	schema, serr := protoSchemaFromRequest(body.Proto, body.ProtoEntry, body.ProtoFiles)
	if serr != nil {
		http.Error(w, serr.Error(), http.StatusBadRequest)
		return
	}
	if schema != nil {
		if body.Message == "" && body.RPCPath != "" {
			body.Message = schema.MessageForRPC(body.RPCPath, body.Direction)
		}
		if body.Message == "" {
			body.Message = schema.DefaultMessage()
		}
		if body.Message != "" {
			// Validate the name up front so a typo is a clear 400 rather than an unnamed tree.
			if _, aerr := schema.Annotate(nil, body.Message); aerr != nil {
				http.Error(w, aerr.Error(), http.StatusBadRequest)
				return
			}
		}
	}
	raw, err := decodeBase64Body(w, body.BodyBase64)
	if err != nil {
		return // decodeBase64Body already wrote the 400
	}

	resp, herr := decodeProtobufBody(schema, body.Message, raw, body.GRPC)
	if herr != "" {
		http.Error(w, herr, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// protoSchemaFromRequest resolves the request's schema form, or nil when none was sent. Three
// forms: none (schemaless decode), proto (a single pasted file), proto_entry + proto_files (the
// rsu2 file set). The forms are mutually exclusive and the set's paths must stay inside the set -
// a compile that reached outside it would read host files the operator never sent.
func protoSchemaFromRequest(proto, entry string, files map[string]string) (*grpcproto.Schema, error) {
	if len(files) == 0 {
		if strings.TrimSpace(entry) != "" {
			return nil, errors.New("proto_entry names a file of proto_files; send the set with it")
		}
		if strings.TrimSpace(proto) == "" {
			return nil, nil
		}
		parsed, err := grpcproto.ParseProto(proto)
		if err != nil {
			return nil, fmt.Errorf("%s; the body still decodes without a schema (omit the proto)", err)
		}
		return parsed, nil
	}
	if strings.TrimSpace(proto) != "" {
		return nil, errors.New("send proto or proto_files, not both: one request carries one schema form")
	}
	if strings.TrimSpace(entry) == "" {
		return nil, errors.New("proto_files needs proto_entry naming the entry point file of the set")
	}
	if len(files) > 256 {
		return nil, fmt.Errorf("proto_files carries %d files; the set is bounded at 256", len(files))
	}
	for path := range files {
		if err := protoSetPathOK(path); err != nil {
			return nil, err
		}
	}
	if err := protoSetPathOK(entry); err != nil {
		return nil, err
	}
	parsed, err := grpcproto.ParseProtoSet(entry, files)
	if err != nil {
		return nil, fmt.Errorf("%s; the body still decodes without a schema (omit the proto)", err)
	}
	return parsed, nil
}

// protoSetPathOK refuses a set path that could reach outside the set: absolute paths, drive
// letters, backslashes, and any ".." segment.
func protoSetPathOK(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") || strings.Contains(path, ":") {
		return fmt.Errorf("proto_files path %q is not a relative slash path inside the set", path)
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == ".." || segment == "." || segment == "" {
			return fmt.Errorf("proto_files path %q has an empty, dot, or parent segment; it must stay inside the set", path)
		}
	}
	return nil
}

// annotateFields names fields against the chosen message, or returns them untouched when there is no
// schema or no message chosen. The message was validated before decoding began, so an Annotate error
// here cannot happen; falling back to the unnamed tree keeps the handler total regardless.
// decodeProtobufBody decodes raw (gRPC-framed when grpcFramed) against schema and
// message, shared by the local decode route and the reflection fetch route (47id).
// The second return is the client error for framing so broken there is nothing
// to show; per-frame failures ride in the frame views.
func decodeProtobufBody(schema *grpcproto.Schema, message string, raw []byte, grpcFramed bool) (protoDecodeResponse, string) {
	resp := protoDecodeResponse{GRPC: grpcFramed}
	if grpcFramed {
		frames, err := grpcproto.Unframe(raw)
		if err != nil {
			return resp, err.Error()
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
					view.Fields, view.Error = validateAndAnnotate(schema, message, fr.Message, fields)
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
			view.Fields, view.Error = validateAndAnnotate(schema, message, raw, fields)
		}
		resp.Frames = []protoFrameView{view}
	}
	if schema != nil {
		resp.Messages = schema.Messages()
		resp.Message = message
	}
	return resp, ""
}

// validateAndAnnotate runs the 0rrb 2b oracle before the schema's names are
// applied: a body the descriptor cannot hold (invalid UTF-8 in a declared
// string, a missing proto2 required field) is reported as the mismatch it is,
// and the tree drops the schema's names - they are the schema's claims about a
// body that does not conform to it. The schemaless structure stays visible: it
// makes no claims.
func validateAndAnnotate(schema *grpcproto.Schema, message string, raw []byte, fields []grpcproto.Field) ([]grpcproto.Field, string) {
	if schema != nil && message != "" {
		if verr := schema.Validate(message, raw); verr != nil {
			return fields, verr.Error()
		}
	}
	return annotateFields(schema, message, fields), ""
}

func annotateFields(schema *grpcproto.Schema, message string, fields []grpcproto.Field) []grpcproto.Field {
	if schema == nil || message == "" {
		return fields
	}
	named, err := schema.Annotate(fields, message)
	if err != nil {
		return fields
	}
	return named
}

// protobufEncodeReq is the request body handleProtobufEncode decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type protobufEncodeReq struct {
	GRPC   bool             `json:"grpc"`
	Frames []protoFrameView `json:"frames"`
}

// handleProtobufEncode serves POST /api/protobuf/encode. riskLocal.
func (s *Server) handleProtobufEncode(w http.ResponseWriter, r *http.Request) {
	var body protobufEncodeReq
	if err := requestJSON(w, r, io.LimitReader(r.Body, 8<<20)).Decode(&body); err != nil {
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
