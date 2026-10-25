package web

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/grpcproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// api_protobuf_reflect.go is 47id: name protobuf fields via gRPC server reflection
// when no .proto is supplied. The egress boundary the reflection client's own docs
// state holds here - the DIALER owns scope and authorization:
//
//   - The fetch is per-request opt-in only: the operator names the target in the
//     request, so the network act is written in the request itself. Nothing
//     fetches automatically, and there is no settings toggle (integrator ruling 1).
//   - The dial clears core.Scope.AuthoriseRequest first, the same gate Repeater's
//     egress clears; a refusal names scope and no dial happens (ruling 2).
//   - No jar credentials ever ride a reflection request: session material is the
//     operator's, and a target requiring authenticated reflection is a later
//     explicit feature, never a silent fallback (ruling 8b, load-bearing).
//   - The schema the target serves is adversary-controllable input: the response
//     marks schema_source "reflection" and lists the fetched files, so
//     target-claimed names never read as operator-supplied .proto (ruling 4, hard
//     requirement). No cache: every fetch is fresh and visible (ruling 5).

// protobufReflectDial is the dial seam, a variable so tests can count dials and
// redirect them to an in-process server. Production dials TLS or plaintext per
// the request, with no credentials from anywhere.
var protobufReflectDial = func(target string, useTLS bool) (*grpc.ClientConn, error) {
	var opt grpc.DialOption
	if useTLS {
		opt = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	} else {
		opt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	return grpc.NewClient(target, opt)
}

// protobufReflectReq is the request body handleProtobufReflectDecode decodes.
type protobufReflectReq struct {
	BodyBase64 string `json:"body_base64"`
	GRPC       bool   `json:"grpc"`
	// Reflect is the opt-in: the target to ask for its own schema. Target is
	// host:port (port defaults to 443 with TLS, 80 without); Service is the
	// fully-qualified gRPC service the body belongs to. TLS says how to dial.
	Reflect struct {
		Target  string `json:"target"`
		Service string `json:"service"`
		TLS     bool   `json:"tls"`
	} `json:"reflect"`
	// Message, when set, overrides the schema's default message choice.
	Message string `json:"message"`
}

// handleProtobufReflectDecode serves POST /api/protobuf/reflect-decode. riskEgress:
// it sends one bounded exchange to the engagement target, the reflection fetch the
// operator named.
func (s *Server) handleProtobufReflectDecode(w http.ResponseWriter, r *http.Request) {
	var body protobufReflectReq
	if err := requestJSON(w, r, io.LimitReader(r.Body, 8<<20)).Decode(&body); err != nil {
		http.Error(w, `the body must be {"body_base64":"...","grpc":bool,"reflect":{"target":"host:port","service":"pkg.Service","tls":bool}}`, http.StatusBadRequest)
		return
	}
	host, port, err := reflectTarget(body.Reflect.Target, body.Reflect.TLS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.Reflect.Service) == "" {
		http.Error(w, "reflect.service is required: the fetch asks for the file declaring it", http.StatusBadRequest)
		return
	}
	// The authorised path, cleared before any dial: the reflection call path is
	// the one constant path the fetch will request.
	if !s.scope.AuthoriseRequest(host, port, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", body.Reflect.TLS) {
		http.Error(w, fmt.Sprintf("scope refuses %s:%d - out-of-scope request handling is set to drop; no fetch was attempted", host, port), http.StatusForbidden)
		return
	}
	raw, err := decodeBase64Body(w, body.BodyBase64)
	if err != nil {
		return // decodeBase64Body already wrote the 400
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	conn, err := protobufReflectDial(net.JoinHostPort(host, strconv.Itoa(int(port))), body.Reflect.TLS)
	if err != nil {
		writeSchemalessReflectMiss(w, body, raw, fmt.Sprintf("reflection dial: %v", err))
		return
	}
	defer conn.Close()
	files, err := grpcproto.FetchServiceDescriptors(ctx, conn, body.Reflect.Service)
	if err != nil {
		writeSchemalessReflectMiss(w, body, raw, err.Error())
		return
	}
	schema, err := grpcproto.SchemaFromFiles(files)
	if err != nil {
		writeSchemalessReflectMiss(w, body, raw, fmt.Sprintf("the served schema: %v", err))
		return
	}
	message := body.Message
	if message == "" {
		message = schema.DefaultMessage()
	}
	resp, herr := decodeProtobufBody(schema, message, raw, body.GRPC)
	if herr != "" {
		http.Error(w, herr, http.StatusBadRequest)
		return
	}
	// The provenance, hard requirement: these names are the target's claims.
	resp.SchemaSource = "reflection"
	for _, fd := range files {
		resp.SchemaFiles = append(resp.SchemaFiles, fd.Path())
	}
	writeJSON(w, http.StatusOK, resp)
}

// reflectTarget splits the operator's target, supplying the scheme's default port
// when it names a bare host.
func reflectTarget(target string, useTLS bool) (string, uint16, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, fmt.Errorf("reflect.target is required: the fetch never guesses a host")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port") {
			return "", 0, fmt.Errorf("reflect.target %q: %v", target, err)
		}
		host, portStr = target, map[bool]string{true: "443", false: "80"}[useTLS]
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, fmt.Errorf("reflect.target %q: bad port", target)
	}
	return host, uint16(p), nil
}

// writeSchemalessReflectMiss is 47id's failure honesty: a fetch that failed is
// named, and the body still decodes schemalessly - the tree makes no claims.
func writeSchemalessReflectMiss(w http.ResponseWriter, body protobufReflectReq, raw []byte, why string) {
	resp, herr := decodeProtobufBody(nil, "", raw, body.GRPC)
	if herr != "" {
		http.Error(w, herr, http.StatusBadRequest)
		return
	}
	for i := range resp.Frames {
		resp.Frames[i].Error = "reflection: " + why
	}
	writeJSON(w, http.StatusOK, resp)
}

// decodeBase64Body is the shared body_base64 check (hoisted from
// handleProtobufDecode when 47id gained a second reader).
func decodeBase64Body(w http.ResponseWriter, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		http.Error(w, "body_base64 is not valid base64", http.StatusBadRequest)
		return nil, err
	}
	return raw, nil
}
