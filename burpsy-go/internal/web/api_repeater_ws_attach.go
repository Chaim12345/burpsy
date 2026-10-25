package web

// Repeater's attach to, and clone of, a proxied WebSocket (burpsy-react-ui-wuwf).
//
// Burp: "You can clone or attach to any open connection, create a new connection, or reconnect a
// closed connection." burpsy's WebSocket tab could only create a new connection with a minimal
// handshake. This file adds the other two operator-facing halves:
//
//   - attach (POST /api/repeater/ws-attach): the frame goes into the live socket the browser
//     opened through the proxy, toward the server or toward the client. The replies are the
//     browser's own conversation, captured on that connection's history like every other frame,
//     so the tab reads them from /api/ws/history?exchange=<socket>.
//   - clone (POST /api/repeater/ws-send with clone:true): a NEW connection opened with the
//     captured handshake — cookies, Origin, Authorization, subprotocol — rather than a synthetic
//     one, so the target sees the same client.
//
// # The gates
//
// Attach reaches only a connection the proxy holds right now: the id is looked up in the relay's
// own registry (proxy.Server.LiveWebSockets), never dialled, so there is no address an attach
// can be pointed at. It is still scope-gated against the connection's handshake target — a frame
// written into a socket is traffic to that socket's peer, and scope is what the operator set to
// say which peers they are authorised to send to. A connection the relay does not capture is not
// registered at all.
//
// Clone is a send like any other: the cloned bytes pass the host gate and AuthoriseRaw before the
// dial, exactly as the plain resend's synthetic handshake does.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"github.com/burpsy-go/burpsy/internal/wsclient"
)

// repeaterWsAttachReq is the POST body of /api/repeater/ws-attach.
type repeaterWsAttachReq struct {
	// Socket is the WebSocket ID — the handshake exchange WebSockets history shows. Required, and a
	// pointer because exchange 0 is a real id.
	Socket  *uint64 `json:"socket"`
	Opcode  string  `json:"opcode"` // "text" | "binary"
	Payload string  `json:"payload"`
	// ToClient sends the frame to the browser instead of the server — the half of Burp's
	// direction choice that only an attached connection can do.
	ToClient bool `json:"to_client,omitempty"`
}

// repeaterWsAttachResp is the reply.
type repeaterWsAttachResp struct {
	Socket core.ExchangeID `json:"socket"`
	// MessageID is the injected frame's row in the connection's history.
	MessageID uint64 `json:"message_id"`
	Direction string `json:"direction"` // "client_to_server" | "server_to_client"
	Len       int    `json:"len"`
}

// handleRepeaterWsAttach writes one frame into a live proxied WebSocket.
func (s *Server) handleRepeaterWsAttach(w http.ResponseWriter, r *http.Request) {
	var req repeaterWsAttachReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Socket == nil {
		http.Error(w, "socket is required: the WebSocket ID of a connection open through the proxy", http.StatusBadRequest)
		return
	}
	opcode, err := wsOpcodeOf(req.Opcode, req.Payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.proxyServer == nil {
		http.Error(w, "no proxy is attached to this console, so there is no live connection to attach to", http.StatusServiceUnavailable)
		return
	}
	id := core.ExchangeID(*req.Socket)
	conn, live := s.proxyServer.LiveWebSocket(id)
	if !live {
		http.Error(w, fmt.Sprintf("WebSocket #%d is not open through the proxy (it may have closed); clone it to open a new connection with the same handshake", id), http.StatusNotFound)
		return
	}
	// The scope decision is about the peer the relay actually dialled — the live connection's own
	// host and port, from the relay's registry — not about what the stored row says, so the check
	// and the socket the frame goes into cannot disagree. The scheme comes from the handshake row:
	// the relay's plain-HTTP upgrade path does not carry a forced-TLS flag into the registry, and the
	// row records the scheme the handshake really used. Nothing in the request body can re-aim it.
	ex, err := s.store.GetExchange(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("WebSocket #%d's handshake exchange could not be read: %v", id, err), http.StatusNotFound)
		return
	}
	if !s.scope.Contains(conn.Host, conn.Port, conn.Path, ex.TLS) {
		http.Error(w, "refused: "+s.scope.Explain(conn.Host, conn.Port, conn.Path, ex.TLS), http.StatusForbidden)
		return
	}

	msgID, err := s.proxyServer.InjectWsFrame(r.Context(), id, req.ToClient, opcode, []byte(req.Payload))
	method := "WS-ATTACH"
	if req.ToClient {
		method = "WS-ATTACH-TO-CLIENT"
	}
	if err != nil {
		s.toolLog.Record(toollog.ToolRepeater, conn.Host, conn.Port, ex.TLS, method, conn.Path, 0, nil, 0, err.Error(), &ex.ID)
		code := http.StatusBadGateway
		switch {
		case errors.Is(err, proxy.ErrWsNotLive):
			code = http.StatusNotFound
		case errors.Is(err, proxy.ErrWsDirectionEnded), errors.Is(err, proxy.ErrWsMidMessage), errors.Is(err, proxy.ErrWsBoundaryLost),
			errors.Is(err, proxy.ErrWsRelayStalled):
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}
	s.toolLog.Record(toollog.ToolRepeater, conn.Host, conn.Port, ex.TLS, method, conn.Path, 0, nil, 0, "", &ex.ID)
	direction := "client_to_server"
	if req.ToClient {
		direction = "server_to_client"
	}
	writeJSON(w, http.StatusOK, repeaterWsAttachResp{Socket: id, MessageID: uint64(msgID), Direction: direction, Len: len(req.Payload)})
}

// prepareWsClone resolves a clone send: the captured handshake of the connection req.Socket
// names, re-keyed by wsclient.CloneHandshake, through the same two scope gates as every send.
func (s *Server) prepareWsClone(req repeaterWsSendReq, opcode core.WsOpcode) (wsSendPlan, int, error) {
	if req.Socket == nil {
		return wsSendPlan{}, http.StatusBadRequest, errors.New("clone needs socket: the WebSocket ID whose handshake to replay")
	}
	if req.Target != "" {
		return wsSendPlan{}, http.StatusBadRequest, errors.New("clone replays the captured handshake to its own target; " +
			"its Host header names that target, so a different target cannot be given — send on a new connection instead")
	}
	id := core.ExchangeID(*req.Socket)
	ex, err := s.store.GetExchange(id)
	if err != nil {
		return wsSendPlan{}, http.StatusNotFound, fmt.Errorf("no WebSocket #%d: %v", id, err)
	}
	msg, err := s.store.Get(core.MsgOrZero(ex.Request))
	if err != nil {
		return wsSendPlan{}, http.StatusNotFound, fmt.Errorf("WebSocket #%d's handshake request could not be read: %v", id, err)
	}
	handshake, err := wsclient.CloneHandshake(msg.Raw())
	if err != nil {
		return wsSendPlan{}, http.StatusUnprocessableEntity, fmt.Errorf("WebSocket #%d cannot be cloned: %v", id, err)
	}
	if !s.scope.MayContainHost(ex.Host, ex.Port, ex.TLS) {
		return wsSendPlan{}, http.StatusForbidden, errors.New("refused: " + s.scope.Explain(ex.Host, ex.Port, ex.Path, ex.TLS))
	}
	if aerr := s.scope.AuthoriseRaw(ex.Host, ex.Port, ex.TLS, handshake); aerr != nil {
		return wsSendPlan{}, http.StatusForbidden, fmt.Errorf("refused: %v", aerr)
	}
	path := ex.Path
	if path == "" {
		path = "/"
	}
	return wsSendPlan{host: ex.Host, port: ex.Port, tls: ex.TLS, path: path, handshake: handshake,
		opcode: opcode, payload: []byte(req.Payload)}, 0, nil
}

// prepareWsEditedHandshake plans a send whose negotiation request the operator edited
// (burpsy-react-ui-ws3e). The edited head is refreshed through wsclient.CloneHandshake - the same
// wire invariants a clone gets - so what dials is legal HTTP and a legal upgrade, and what the
// operator wrote is otherwise exactly what the target reads. The authority never comes from the
// edited bytes: Socket names a captured connection's target, Target names one outright, and the
// Host line stays the operator's to change under test. The gate sees the bytes that will go on
// the wire, refreshed included, because those are the bytes being authorised.
func (s *Server) prepareWsEditedHandshake(req repeaterWsSendReq, opcode core.WsOpcode) (wsSendPlan, int, error) {
	if req.Clone {
		return wsSendPlan{}, http.StatusBadRequest, errors.New("clone replays the captured handshake " +
			"and handshake replaces it - one send cannot take its negotiation request from two places")
	}
	if req.Message != 0 {
		return wsSendPlan{}, http.StatusBadRequest, errors.New("handshake replaces the negotiation " +
			"request; message names a frame to resend - give one")
	}
	var host string
	var port uint16
	var tls bool
	switch {
	case req.Socket != nil && req.Target != "":
		return wsSendPlan{}, http.StatusBadRequest, errors.New("socket and target both name the " +
			"authority to dial - give one")
	case req.Socket != nil:
		id := core.ExchangeID(*req.Socket)
		ex, err := s.store.GetExchange(id)
		if err != nil {
			return wsSendPlan{}, http.StatusNotFound, fmt.Errorf("no WebSocket #%d: %v", id, err)
		}
		host, port, tls = ex.Host, ex.Port, ex.TLS
	case req.Target != "":
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
	default:
		return wsSendPlan{}, http.StatusBadRequest, errors.New("an edited handshake still needs the " +
			"authority to dial: a socket whose target to use, or an explicit target")
	}
	handshake, err := wsclient.CloneHandshake([]byte(req.Handshake))
	if err != nil {
		return wsSendPlan{}, http.StatusUnprocessableEntity, fmt.Errorf("the edited handshake cannot go on the wire: %v", err)
	}
	if !s.scope.MayContainHost(host, port, tls) {
		return wsSendPlan{}, http.StatusForbidden, errors.New("refused: " + s.scope.Explain(host, port, "", tls))
	}
	if aerr := s.scope.AuthoriseRaw(host, port, tls, handshake); aerr != nil {
		return wsSendPlan{}, http.StatusForbidden, fmt.Errorf("refused: %v", aerr)
	}
	// History records the path the wire carried, which the operator may have edited - read it off
	// the refreshed head, not off the connection the dial authority came from.
	path := "/"
	if line, _, ok := strings.Cut(string(handshake), "\r\n"); ok {
		if parts := strings.SplitN(line, " ", 3); len(parts) == 3 && parts[1] != "" {
			path = parts[1]
		}
	}
	return wsSendPlan{host: host, port: port, tls: tls, path: path, handshake: handshake,
		opcode: opcode, payload: []byte(req.Payload)}, 0, nil
}
