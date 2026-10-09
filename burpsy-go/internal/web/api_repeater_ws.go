package web

// The Repeater's WebSocket send (burpsy-react-ui-6ex).
//
// Burp's Repeater is not HTTP-only: a WebSocket message can be sent there, edited and
// resent, with a choice of direction. burpsy's Repeater was HTTP-only, and WebSockets history
// was read-only, so a frame could not even leave the page.
//
// This endpoint is the wire half of closing that. The UI half — a WS tab type in the
// Repeater's store and a "Send to Repeater" action on a wshistory frame — drives this same
// path; the endpoint is the seam, tested on its own, exactly like /api/repeater/send is.
//
// # The direction choice, honestly implemented
//
// Burp offers "send to server" or "send to client". This endpoint offers to-server, and
// refuses to-client with the reason in the body — never a silent success and never a hidden
// control: a fresh dial has no client to send to, and pretending otherwise would send
// nothing while reporting a send. The to-client half exists only through the proxy's own
// intercept hold, which is a different surface, and the refusal text says exactly that.
//
// # The two scope gates, same as the HTTP send
//
// prepareRepeaterSend applies the host-level gate; the WS send applies the same gate at
// prepare time and then hands the handshake's raw bytes to sender.AuthorisedSender, which
// runs AuthoriseRaw on the bytes about to go out — the same two layers, because a WS resend
// is a send and the same scope the operator set to constrain outbound traffic must not be
// bypassable by framing instead of requesting.
//
// # What is recorded
//
// The resend is recorded the way the original conversation was: the handshake exchange
// (request + 101) through the store's ordinary Put, the sent frame and every reply frame as
// WsMessages attached to it — FromClient true for the operator's own frame, false for the
// target's — so the resend is visible in WebSockets history as its own conversation and the
// operator can compare the reply with the original.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"github.com/burpsy-go/burpsy/internal/wsclient"
	"go.uber.org/zap"
)

// repeaterWsSendReq is the POST body of /api/repeater/ws-send.
type repeaterWsSendReq struct {
	// Message is the wshistory frame id being resent, 0 for a frame the operator authored
	// from scratch. When non-zero, the frame's payload and opcode prefill the editor and its
	// handshake exchange supplies the target; either way, Target below can override.
	Message uint64 `json:"message"`
	// Target is "host:port" with the scheme carried by TLS, the same string the HTTP send
	// takes. Optional when Message names a frame.
	Target  string `json:"target,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
	Path    string `json:"path,omitempty"`
	Opcode  string `json:"opcode"`  // "text" | "binary"
	Payload string `json:"payload"` // the frame's payload, edited by the operator
	// ToClient asks for the other half of Burp's direction choice: the frame toward the browser
	// rather than toward the target. It is refused with its reason rather than ignored, and it is
	// refused BEFORE anything is dialled — a request that has already opened a socket to the
	// target by the time it says "I cannot do that" has sent traffic the operator did not choose to
	// send. The half that can run is the proxy's own intercept hold, which is a different surface.
	// snake_case like every other field on this endpoint, and camelCase accepted alongside it
	// because a client written against Burp's own "to client" wording will reach for that
	// spelling — a field silently ignored for want of a name is the exact failure the refusal
	// below exists to prevent, so both spellings mean the same thing.
	ToClient      bool `json:"to_client,omitempty"`
	ToClientCamel bool `json:"toClient,omitempty"`
	// Clone is Burp's "clone" of a connection (burpsy-react-ui-wuwf): the new connection is opened
	// with the captured handshake of the connection Socket names — its cookies, Origin,
	// Authorization and subprotocol offer — rather than the minimal handshake a plain resend
	// builds, so the target treats it as the same client. Only the nonce and the extension offer
	// change (wsclient.CloneHandshake says why). Requires Socket, and refuses Target: the cloned
	// bytes carry the original Host, and dialling them at a different authority would send a
	// request that names one host to another.
	Clone bool `json:"clone,omitempty"`
	// Socket is the WebSocket ID (the handshake exchange) to clone. A pointer because exchange 0
	// is a real id: an absent field and the store's first connection must not read the same.
	Socket *uint64 `json:"socket,omitempty"`
}

// repeaterWsSendResp is the reply.
type repeaterWsSendResp struct {
	// ExchangeID names the recorded handshake exchange, so the UI can offer "view in
	// WebSockets history" on the result rather than leaving the operator to find it.
	ExchangeID core.ExchangeID `json:"exchange_id"`
	// Handshake is the 101's status line, for the pane's header.
	Handshake string `json:"handshake"`
	// Messages is what the target sent back, in order: opcode, direction (always
	// server_to_client here), payload text, and the length the row shows.
	Messages []repeaterWsMessage `json:"messages"`
	// ClosedByPeer, CloseCode, CloseReason say how the conversation ended.
	ClosedByPeer bool   `json:"closed_by_peer,omitempty"`
	CloseCode    uint16 `json:"close_code,omitempty"`
	CloseReason  string `json:"close_reason,omitempty"`
	// ElapsedMs is the whole send's duration, handshake included.
	ElapsedMs int64 `json:"elapsed_ms"`
}

// repeaterWsMessage is one reply frame.
type repeaterWsMessage struct {
	Opcode  string `json:"opcode"`
	Payload string `json:"payload"`
	Len     int    `json:"len"`
}

// wsSchemeTarget translates a ws:// or wss:// target into the host:port form targetParts
// speaks, reporting whether the scheme asked for TLS. A target with no ws scheme passes
// through untouched (the bare host:port spelling the API also accepts).
//
// A malformed ws URL is refused rather than guessed at: "ws://" with nothing after it names
// no host, and dialling localhost on the operator's behalf would be a send nobody asked for.
func wsSchemeTarget(target string) (string, bool, error) {
	trimmed := strings.TrimSpace(target)
	if rest, ok := strings.CutPrefix(trimmed, "wss://"); ok {
		if strings.TrimSpace(rest) == "" {
			return "", false, fmt.Errorf("the target %q names no host", target)
		}
		return rest, true, nil
	}
	if rest, ok := strings.CutPrefix(trimmed, "ws://"); ok {
		if strings.TrimSpace(rest) == "" {
			return "", false, fmt.Errorf("the target %q names no host", target)
		}
		return rest, false, nil
	}
	return trimmed, false, nil
}

// handleRepeaterWsSend resends one WebSocket frame over a fresh connection.
func (s *Server) handleRepeaterWsSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req repeaterWsSendReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// The direction gate comes before the target is even resolved. A refusal that has already
	// dialled the target is a refusal that sent traffic, and "I cannot inject into a third party's
	// client socket from here" is a fact the operator should learn before anything leaves the box.
	if req.ToClient || req.ToClientCamel {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "to-client cannot run from a resend: this sends on a fresh connection, and a fresh " +
				"connection has no client to send to. To put a frame in front of the browser, intercept the " +
				"WebSocket first (Proxy > WebSockets > interception) and release the frame from there.",
		})
		return
	}
	plan, code, err := s.prepareWsSend(req)
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	host, port, tls, path, opcode, payload := plan.host, plan.port, plan.tls, plan.path, plan.opcode, plan.payload

	started := time.Now()
	reply, err := wsclient.SendFrameWithHandshake(r.Context(), s.sender, host, port, tls, plan.handshake, wsclient.Frame{Opcode: opcode, Payload: payload})
	elapsed := time.Since(started).Milliseconds()
	if err != nil {
		// The tool log row is written for the same reason the HTTP send writes one: a send
		// that failed before any reply is still traffic this tool attempted, and the
		// operator's audit of what left the machine includes it.
		s.toolLog.Record(toollog.ToolRepeater, host, port, tls, "WS-SEND", path, 0, nil, 0, err.Error(), nil)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	resp := s.recordWsSend(host, port, tls, path, plan.handshake, opcode, payload, reply, started)
	resp.ElapsedMs = elapsed
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// wsSendPlan is a resolved, authorised WebSocket send: where it goes, the exact handshake bytes
// the gates passed (which are the bytes sent and the bytes recorded), and the frame.
type wsSendPlan struct {
	host      string
	port      uint16
	tls       bool
	path      string
	handshake []byte
	opcode    core.WsOpcode
	payload   []byte
}

// wsOpcodeOf parses the opcode a send may carry: data frames only.
func wsOpcodeOf(name, payload string) (core.WsOpcode, error) {
	var opcode core.WsOpcode
	switch name {
	case "text":
		opcode = core.WsOpcodeText
	case "binary":
		opcode = core.WsOpcodeBinary
	default:
		return 0, fmt.Errorf("opcode must be text or binary, got %q", name)
	}
	if strings.TrimSpace(payload) == "" && opcode == core.WsOpcodeText {
		return 0, errors.New("a text frame needs a payload")
	}
	return opcode, nil
}

// prepareWsSend resolves the frame's target and payload, and applies the two scope gates.
//
// The frame's own message row is the source of truth for the target when one was given: the
// handshake exchange it names carries the host, port, TLS and path the original connection
// used, and the stored request's Sec-WebSocket-Protocol is re-offered so a subprotocol-
// expecting target does not close the fresh socket. An explicit Target in the request
// overrides the host — the operator may be resending at a different instance — but the
// payload and opcode always come from the request body, which is the edited text the
// operator sees in the pane.
func (s *Server) prepareWsSend(req repeaterWsSendReq) (plan wsSendPlan, code int, err error) {
	var (
		host        string
		port        uint16
		tls         bool
		path        string
		subprotocol string
		opcode      core.WsOpcode
	)
	opcode, err = wsOpcodeOf(req.Opcode, req.Payload)
	if err != nil {
		return wsSendPlan{}, http.StatusBadRequest, err
	}
	if req.Clone {
		return s.prepareWsClone(req, opcode)
	}

	if req.Message != 0 {
		m, merr := s.store.WsMessage(core.MsgId(req.Message))
		if merr != nil {
			return wsSendPlan{}, http.StatusNotFound, fmt.Errorf("no ws message %d", req.Message)
		}
		if opcode == 0 {
			opcode = m.Opcode
		}
		ex, exErr := s.store.GetExchange(m.Exchange)
		if exErr != nil {
			return wsSendPlan{}, http.StatusNotFound,
				fmt.Errorf("the frame's handshake exchange %d could not be read: %v", m.Exchange, exErr)
		}
		host, port, tls, path = ex.Host, ex.Port, ex.TLS, ex.Path
		// The subprotocol comes off the ORIGINAL request bytes: the server's answer to
		// "which protocol" is a fact of the conversation, and re-offering exactly what the
		// original offered is the only way a fresh dial speaks the same one.
		if msg, rerr := s.store.Get(core.MsgOrZero(ex.Request)); rerr == nil {
			subprotocol = strings.TrimSpace(string(msg.Header("Sec-WebSocket-Protocol")))
		}
	}
	if req.Target != "" {
		// The ws spellings (burpsy-react-ui-6ex): a WebSocket target is written ws://host:port or
		// wss://host:port, and the Repeater's own ws tab offers exactly that in its Target field.
		// targetParts speaks the HTTP spellings only — widening IT would let an HTTP send be given
		// a ws:// target and silently dial plaintext, so the translation lives here, on the one
		// path where ws:// is what the operator meant.
		wsTarget, wsTLS, wsErr := wsSchemeTarget(req.Target)
		if wsErr != nil {
			return wsSendPlan{}, http.StatusBadRequest, wsErr
		}
		h, p, t, terr := targetParts(wsTarget)
		if terr != nil {
			return wsSendPlan{}, http.StatusBadRequest, terr
		}
		if wsTLS {
			t = true
		}
		host, port, tls = h, p, t
	}
	if req.TLS {
		tls = true
	}
	if host == "" {
		return wsSendPlan{}, http.StatusBadRequest,
			errors.New("give the frame a target: a wshistory message id, or an explicit host:port")
	}
	if path == "" {
		path = "/"
	}
	// The host-level gate, the same first layer the HTTP send applies: the operator may send
	// to whatever target they type, and the scope they set to constrain outbound traffic is
	// not bypassable by framing instead of requesting.
	if !s.scope.MayContainHost(host, port, tls) {
		return wsSendPlan{}, http.StatusForbidden,
			errors.New("refused: " + s.scope.Explain(host, port, path, tls))
	}
	// The raw-bytes gate, the second layer: the handshake's bytes about to go out are
	// authorised against the scope by the same AuthoriseRaw the intruder's payloads pass,
	// because a payload spliced into a path position can rewrite the request line and only
	// the bytes about to be written can be trusted.
	handshake, herr := wsclient.HandshakeRequest(host, port, tls, path, subprotocol)
	if herr != nil {
		return wsSendPlan{}, http.StatusInternalServerError, herr
	}
	if aerr := s.scope.AuthoriseRaw(host, port, tls, handshake); aerr != nil {
		return wsSendPlan{}, http.StatusForbidden, fmt.Errorf("refused: %v", aerr)
	}
	return wsSendPlan{host: host, port: port, tls: tls, path: path, handshake: handshake,
		opcode: opcode, payload: []byte(req.Payload)}, 0, nil
}

// recordWsSend stores the resend as its own conversation: the handshake exchange through the
// ordinary Put, the operator's frame and every reply as WsMessages on it.
//
// handshake is the request that actually went out. It used to be rebuilt here with a new key and
// no subprotocol, so the recorded request was not the one sent — and for a clone, whose whole
// point is the original's headers, the record would have hidden exactly what was replayed.
func (s *Server) recordWsSend(
	host string, port uint16, tls bool, path string, handshake []byte, opcode core.WsOpcode, payload []byte, reply wsclient.Reply, started time.Time,
) repeaterWsSendResp {
	// The actual 101 is in reply.RawHandshake; fall back to the request we would have sent
	// only if the target answered with bytes we did not keep (which cannot happen today, but
	// the row must never reference a response that does not exist).
	respBytes := reply.RawHandshake
	if len(respBytes) == 0 {
		respBytes = []byte("HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n")
	}
	reqID, rerr := s.store.Put(handshake, core.DirectionRequest)
	if rerr != nil {
		s.logger.Error("ws send: failed to store the handshake request", zap.Error(rerr))
	}
	respID, perr := s.store.Put(respBytes, core.DirectionResponse)
	if perr != nil {
		s.logger.Error("ws send: failed to store the handshake response", zap.Error(perr))
	}
	status := uint16(101)
	ex := &core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID,
		Host: host, Port: port, TLS: tls, Method: "GET", Path: path,
		Status: &status, Protocol: core.ProtocolHTTP1,
	}
	s.store.AddExchange(ex)

	// The operator's frame, then the target's replies, both as WsMessages so the resend
	// reads in WebSockets history exactly like the conversation it came from.
	s.store.AddWsMessage(&core.WsMessage{
		Exchange: ex.ID, FromClient: true, Opcode: opcode, Len: len(payload),
		AtMs: uint64(time.Since(started).Milliseconds()),
	}, payload)
	for _, ev := range reply.Messages {
		s.store.AddWsMessage(&core.WsMessage{
			Exchange: ex.ID, FromClient: false, Opcode: ev.Opcode, Len: len(ev.Payload),
			AtMs: uint64(time.Since(started).Milliseconds()),
		}, ev.Payload)
	}

	resp := repeaterWsSendResp{ExchangeID: ex.ID, ClosedByPeer: reply.ClosedByPeer,
		CloseCode: reply.CloseCode, CloseReason: reply.CloseReason}
	resp.Handshake = strings.TrimSpace(strings.SplitN(string(reply.RawHandshake), "\r\n", 2)[0])
	for _, ev := range reply.Messages {
		resp.Messages = append(resp.Messages, repeaterWsMessage{
			Opcode: ev.Opcode.Name(), Payload: string(ev.Payload), Len: len(ev.Payload),
		})
	}
	s.toolLog.Record(toollog.ToolRepeater, host, port, tls, "WS-SEND", path, 101, nil, uint64(len(reply.Messages)), "", &ex.ID)
	s.live.notify(changeHistory)
	return resp
}
