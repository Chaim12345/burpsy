package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// Two HTTP surfaces for the HTTP/2 work: what protocol this tool's own traffic actually used (H2-04), and
// a way to send a deliberately malformed frame program (H2-03).
//
// Both exist because a capability nothing can reach is not a capability. The protocol report is countable
// in Go and would have been invisible to an operator; the frame-program send path was authorised, tested
// and reachable only from a Go call site. There is no UI pane here on purpose — that is a separate
// session's file — so these are the API the pane will read.

// protocolAuthorityView is one authority and what its ALPN said.
type protocolAuthorityView struct {
	Authority  string `json:"authority"`
	State      string `json:"state"`
	Negotiated string `json:"negotiated,omitempty"`
}

// handleProtocols serves GET /api/protocols: which protocol carried this tool's sends, and why the
// HTTP/1.1 ones did.
//
// The per-reason counts are the point, not the totals. "412 sends, 0 as h2" invites the reading that the
// targets do not speak h2; the reasons are what tell an operator whether that is true or whether every
// probe they wrote carries a Transfer-Encoding.
func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sender == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"enabled": false,
			"hint":    "no sender is wired, so nothing has been sent from this process",
		})
		return
	}
	report := s.sender.Protocols()
	authorities := make([]protocolAuthorityView, 0, len(report.Authorities))
	for _, a := range report.Authorities {
		authorities = append(authorities, protocolAuthorityView{
			Authority:  a.Authority,
			State:      a.State,
			Negotiated: a.Negotiated,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"enabled":              true,
		"summary":              report.Summary(),
		"sent_as_http2":        report.SentAsHTTP2,
		"sent_as_http1":        report.SentAsHTTP1,
		"downgrades":           report.Downgrades,
		"rewrites":             report.Rewrites,
		"discovery_handshakes": report.DiscoveryHandshakes,
		"cache_hits":           report.CacheHits,
		"authorities":          authorities,
	})
}

// Named bounds on a submitted frame program. A program is operator-written and goes out verbatim, so the
// only thing these stop is this process spending memory on a request body that was never a program — and
// they refuse by name rather than truncating, because a truncated frame program is a different program.
const (
	// maxProgramFrames is how many frames one program may carry.
	maxProgramFrames = 512
	// maxProgramPayloadBytes bounds the total payload across every frame. A single frame's payload can
	// legally reach 16 MiB, and a program that needs more than this is asking for a stress test of this
	// process rather than of the target.
	maxProgramPayloadBytes = 8 << 20
)

// frameSpecReq is one frame to emit. Payload is base64 because a frame payload is octets, not text: an
// HPACK block is not valid UTF-8 and JSON cannot carry it as a string.
type frameSpecReq struct {
	Type   uint8  `json:"type"`
	Flags  uint8  `json:"flags"`
	Stream uint32 `json:"stream"`
	// Payload is base64, empty for a frame with none.
	Payload string `json:"payload_base64,omitempty"`
	// DeclaredLen overrides the length field. Absent writes the payload's own length; present writes
	// whatever it says, which is the single most useful lie the frame layer can tell — and the construct
	// http2.Authorise refuses to authorise, because the peer then frames by a value we did not write to.
	DeclaredLen *uint32 `json:"declared_len,omitempty"`
}

// frameProgramReq is one program to authorise and send.
type frameProgramReq struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	TLS  bool   `json:"tls"`
	// Preface sends the 24-octet client preface first. Absent means false, which Audit reports as a
	// violation rather than quietly correcting — so a caller wanting a normal connection must say so.
	Preface bool `json:"preface"`
	// ReadForMS is how long to keep reading after the last frame. Zero reads nothing.
	ReadForMS uint64         `json:"read_for_ms"`
	Frames    []frameSpecReq `json:"frames"`
}

// frameView is one frame read back off the wire.
type frameView struct {
	Type   string `json:"type"`
	Flags  uint8  `json:"flags"`
	Stream uint32 `json:"stream"`
	Len    uint32 `json:"len"`
}

// handleHTTP2Program serves POST /api/http2/program: authorise a frame program and, if the engagement
// scope agrees, send it.
//
// A refusal answers 403 with the same body shape as a success, refusals filled in. That is deliberate: an
// operator doing smuggling research needs to read *which construct* stopped them, and an error string
// would drop the structure the classifier worked to produce.
func (s *Server) handleHTTP2Program(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sender == nil {
		http.Error(w, "no sender is wired, so nothing can be sent", http.StatusServiceUnavailable)
		return
	}
	var req frameProgramReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "unreadable frame program: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Host == "" || req.Port == 0 {
		http.Error(w, "a frame program needs a host and a port to be authorised against", http.StatusBadRequest)
		return
	}
	program, err := buildProgram(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	auth := sender.NewAuthorisedSender(s.scope, s.sender, req.Host, req.Port, req.TLS)
	res, sendErr := auth.SendFrameProgram(r.Context(), program)

	body := map[string]any{
		"verdict":    res.Authorisation.Verdict.String(),
		"refusals":   refusalStrings(res.Authorisation.Refusals),
		"violations": violationStrings(res.Violations),
		"requests":   programRequestViews(res.Authorisation.Requests),
		"negotiated": res.Negotiated,
		"read_ended": res.ReadEnded,
		"sent": map[string]any{
			"octets": len(res.Sent),
			"base64": base64.StdEncoding.EncodeToString(res.Sent),
		},
		"reply": map[string]any{
			"octets": len(res.Response),
			"base64": base64.StdEncoding.EncodeToString(res.Response),
			"frames": frameViews(res.ReplyFrames),
		},
		"duration_ms": res.Duration.Milliseconds(),
	}
	if res.ReplyTail.Kind == http2.TailIncomplete {
		// Reported rather than dropped: a peer that died mid-frame is frequently the result the probe was
		// looking for.
		body["reply_partial_frame"] = map[string]any{
			"offset": res.ReplyTail.Offset,
			"have":   res.ReplyTail.Have,
			"need":   res.ReplyTail.Need,
			"known":  res.ReplyTail.NeedKnown,
		}
	}

	if sendErr != nil {
		body["error"] = sendErr.Error()
		status := http.StatusBadGateway
		if auth.Refused() > 0 {
			// The chokepoint's own counter decides which bucket this is, rather than the error text: a
			// refusal and a dial failure both leave nothing written, and the refusal message is
			// operator-facing prose that matching on would break the next time it is improved. This
			// sender was built for this one request, so a nonzero count is this request's.
			status = http.StatusForbidden
		}
		writeJSON(w, status, body)
		return
	}

	// Through the one capture path, like every other producer (CRAWL-02). A capture failure is reported and
	// does not fail the send: the program went out and its reply is in the body either way, and saying
	// otherwise would be the opposite lie from the usual one.
	capture := scanner.Capture{
		Store:    s.store,
		Scanner:  s.passiveScanner,
		Findings: s.findings,
		Logger:   s.logger,
		Source:   core.SourceRepeater,
	}
	if ex, cerr := capture.RecordFrameProgram(res); cerr != nil {
		body["capture_error"] = cerr.Error()
	} else {
		body["exchange_id"] = ex.ID
	}
	writeJSON(w, http.StatusOK, body)
}

// buildProgram turns the request into a program, refusing by name rather than clamping.
func buildProgram(req frameProgramReq) (http2.H2FrameProgram, error) {
	if len(req.Frames) > maxProgramFrames {
		return http2.H2FrameProgram{}, fmt.Errorf(
			"a frame program may carry %d frames and this one carries %d", maxProgramFrames, len(req.Frames))
	}
	program := http2.H2FrameProgram{Preface: req.Preface, ReadForMS: req.ReadForMS}
	total := 0
	for i, f := range req.Frames {
		payload, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return http2.H2FrameProgram{}, fmt.Errorf("frame %d's payload is not base64: %w", i, err)
		}
		total += len(payload)
		if total > maxProgramPayloadBytes {
			return http2.H2FrameProgram{}, fmt.Errorf(
				"the program's payloads exceed the %d-byte bound at frame %d", maxProgramPayloadBytes, i)
		}
		spec := http2.NewFrameSpec(f.Type, f.Flags, f.Stream, payload)
		if f.DeclaredLen != nil {
			spec = spec.WithDeclaredLen(*f.DeclaredLen)
		}
		program.Frames = append(program.Frames, spec)
	}
	return program, nil
}

func refusalStrings(in []http2.Refusal) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, r.String())
	}
	return out
}

func violationStrings(in []http2.Violation) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, v.String()+" ("+v.RFC()+")")
	}
	return out
}

func programRequestViews(in []http2.ProgramRequest) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, r := range in {
		out = append(out, map[string]any{
			"frame":     r.Frame,
			"stream":    r.Stream,
			"method":    r.Method,
			"scheme":    r.Scheme,
			"authority": r.Authority,
			"path":      r.Path,
		})
	}
	return out
}

func frameViews(in []http2.RawFrame) []frameView {
	out := make([]frameView, 0, len(in))
	for _, f := range in {
		name, ok := http2.TypeName(f.Header.Type)
		if !ok {
			// Never invents a name for an unregistered type — the same rule malformed.go's tyLabel follows.
			name = fmt.Sprintf("type 0x%02X", f.Header.Type)
		}
		out = append(out, frameView{
			Type:   name,
			Flags:  f.Header.Flags,
			Stream: f.Header.StreamIDMasked(),
			Len:    f.Header.Len,
		})
	}
	return out
}
