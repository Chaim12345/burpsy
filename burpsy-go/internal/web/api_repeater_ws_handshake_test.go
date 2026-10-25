package web

// Editing the negotiation request before the dial (burpsy-react-ui-ws3e): Burp's "You can then
// manipulate the negotiation request". The operator's edited head goes through the same wire
// invariants as a clone - fresh nonce, no extension offer, origin-form target, no body - and
// everything else reaches the wire byte for byte: an Origin or Cookie under test is the point of
// the feature, so normalising them away would be the feature refusing to exist.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func editedHandshake() string {
	return "GET /edited?q=1 HTTP/1.1\r\n" +
		"Host: placeholder.test\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Origin: http://operator-chosen.example\r\n" +
		"Cookie: session=edited\r\n" +
		"\r\n"
}

func TestRepeaterWsSendDialsTheEditedHandshake(t *testing.T) {
	target, seen := cloneTarget(t)
	host, port := repeaterWsTargetOf(target)
	s := newTestServer()
	s.scope.AddInclude(host)
	socket := seedHandshake(t, s, host, port)

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"socket": uint64(socket), "handshake": editedHandshake(), "opcode": "text", "payload": "edited frame",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("edited-handshake send: %d %s", rec.Code, rec.Body.String())
	}
	var resp repeaterWsSendResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Messages) != 1 || resp.Messages[0].Payload != "echo: edited frame" {
		t.Fatalf("reply = %+v", resp.Messages)
	}
	h := seen()
	if h.Get("Origin") != "http://operator-chosen.example" || h.Get("Cookie") != "session=edited" {
		t.Errorf("the dial did not carry the operator's edits: %v", h)
	}
	if h.Get("Sec-WebSocket-Key") == "dGhlIHNhbXBsZSBub25jZQ==" || h.Get("Sec-WebSocket-Key") == "" {
		t.Errorf("the edited handshake replayed its nonce: %q", h.Get("Sec-WebSocket-Key"))
	}
	if h.Get("Sec-WebSocket-Extensions") != "" {
		t.Errorf("the edited handshake offered extensions: %q", h.Get("Sec-WebSocket-Extensions"))
	}
	// The recorded handshake is the one sent, edits and all: history must not show a negotiation
	// the wire never saw.
	ex, _ := s.store.GetExchange(resp.ExchangeID)
	msg, _ := s.store.Get(core.MsgOrZero(ex.Request))
	if raw := string(msg.Raw()); !strings.Contains(raw, "Origin: http://operator-chosen.example") {
		t.Errorf("the recorded handshake is not the one sent:\n%s", raw)
	}
}

func TestRepeaterWsEditedHandshakeOutOfScopeIsRefusedBeforeTheDial(t *testing.T) {
	var reached bool
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true }))
	defer guard.Close()
	host, port := repeaterWsTargetOf(guard)
	s := newTestServer()
	s.scope.AddInclude("in-scope.example")
	socket := seedHandshake(t, s, host, port)

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"socket": uint64(socket), "handshake": editedHandshake(), "opcode": "text", "payload": "x",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("edited handshake out of scope: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if reached {
		t.Fatal("the refused send dialled: a scope refusal that sent traffic is not a refusal")
	}
}

func TestRepeaterWsHandshakeAndCloneNameTwoSourcesOfBytes(t *testing.T) {
	target, _ := cloneTarget(t)
	host, port := repeaterWsTargetOf(target)
	s := newTestServer()
	s.scope.AddInclude(host)
	socket := seedHandshake(t, s, host, port)

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"clone": true, "socket": uint64(socket), "handshake": editedHandshake(),
		"opcode": "text", "payload": "x",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("clone + handshake: %d %s, want 400 - one send cannot take its negotiation "+
			"request from two places", rec.Code, rec.Body.String())
	}
}
