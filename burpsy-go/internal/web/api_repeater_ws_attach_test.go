package web

// Repeater's attach to and clone of a proxied WebSocket (burpsy-react-ui-wuwf), through the API.
//
// A real proxy relays a real WebSocket between a test "browser" and a test origin; the tests
// then drive /api/repeater/ws-attach and /api/repeater/ws-send{clone} the way the console does.

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"go.uber.org/zap"
)

type attachFixture struct {
	s      *Server
	px     *proxy.Server
	client net.Conn
	cr     *bufio.Reader
	origin *bufio.Reader
	socket core.ExchangeID
	host   string
}

// openProxiedWs runs a proxy over s's store and scope, opens one WebSocket through it to a held
// origin, and returns once the relay has registered the connection.
func openProxiedWs(t *testing.T, s *Server) *attachFixture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	originCh := make(chan *bufio.Reader, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { conn.Close() })
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"))
		originCh <- br
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	s.scope.AddInclude(host)

	px := proxy.NewServer(proxy.NewProxyConfig(s.store).WithScope(s.scope).WithLogger(zap.NewNop()))
	s.WithProxyServer(px)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go px.ListenAndServe(ctx, "127.0.0.1:0")
	deadline := time.Now().Add(5 * time.Second)
	for px.ListenerAddr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	client, err := net.Dial("tcp", px.ListenerAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	authority := net.JoinHostPort(host, portStr)
	client.Write([]byte("GET http://" + authority + "/chat HTTP/1.1\r\nHost: " + authority + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" +
		"Cookie: session=abc123\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"))
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	cr := bufio.NewReader(client)
	for {
		line, err := cr.ReadString('\n')
		if err != nil {
			t.Fatalf("read 101: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	var origin *bufio.Reader
	select {
	case origin = <-originCh:
	case <-time.After(5 * time.Second):
		t.Fatal("origin never upgraded")
	}
	for {
		if live := px.LiveWebSockets(); len(live) == 1 {
			return &attachFixture{s: s, px: px, client: client, cr: cr, origin: origin, socket: live[0].Exchange, host: host}
		}
		if time.Now().After(deadline) {
			t.Fatal("the proxied WebSocket never became attachable")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRepeaterAttachSendsIntoTheLiveProxiedConnectionBothWays(t *testing.T) {
	f := openProxiedWs(t, newTestServer())

	// The browser speaks first, so the connection has a frame and WebSockets history lists it
	// (the connection list is a fold over frames).
	mask := [4]byte{9, 8, 7, 6}
	f.client.Write(core.EncodeWsFrame(core.WsOpcodeText, []byte("browser hello"), &mask))
	if payload, err := readOneFrame(f.origin); err != nil || string(payload) != "browser hello" {
		t.Fatalf("relay: origin read %q (%v)", payload, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(f.s.store.WsConnections()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// WebSockets history says the connection is live, which is what offers attach in the console.
	if body := get200(t, f.s, "/api/ws/connections"); !strings.Contains(body, `"live":true`) {
		t.Fatalf("/api/ws/connections does not report the open connection as live: %s", body)
	}

	rec := postJSON(t, f.s, "/api/repeater/ws-attach", map[string]any{
		"socket": uint64(f.socket), "opcode": "text", "payload": "hello origin",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("attach to server: %d %s", rec.Code, rec.Body.String())
	}
	var resp repeaterWsAttachResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Direction != "client_to_server" {
		t.Errorf("direction = %q", resp.Direction)
	}
	if payload, err := readOneFrame(f.origin); err != nil || string(payload) != "hello origin" {
		t.Fatalf("the origin read %q (%v), want the attached frame", payload, err)
	}
	// The frame is on the connection's own history — the pane the tab reads its replies from.
	if body := get200(t, f.s, "/api/ws/message/"+strconv.FormatUint(resp.MessageID, 10)); !strings.Contains(body, "hello origin") || !strings.Contains(body, "Repeater") {
		t.Errorf("the attached frame is not on the connection's history with its note: %s", body)
	}

	rec = postJSON(t, f.s, "/api/repeater/ws-attach", map[string]any{
		"socket": uint64(f.socket), "opcode": "text", "payload": "hello browser", "to_client": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("attach to client: %d %s", rec.Code, rec.Body.String())
	}
	if payload, err := readOneFrame(f.cr); err != nil || string(payload) != "hello browser" {
		t.Fatalf("the browser read %q (%v), want the frame sent to the client", payload, err)
	}
}

// Attach is gated on the connection's target being in scope NOW: a connection captured while in
// scope does not stay writable after the operator narrows scope.
func TestRepeaterAttachToAConnectionNowOutOfScopeIsRefused(t *testing.T) {
	f := openProxiedWs(t, newTestServer())
	f.s.scope.AddExclude(f.host)

	rec := postJSON(t, f.s, "/api/repeater/ws-attach", map[string]any{
		"socket": uint64(f.socket), "opcode": "text", "payload": "nope",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("attach out of scope: %d %s, want 403", rec.Code, rec.Body.String())
	}
	// Nothing reached the origin.
	f.client.Close()
	done := make(chan []byte, 1)
	go func() { b, _ := readOneFrame(f.origin); done <- b }()
	select {
	case b := <-done:
		if len(b) > 0 {
			t.Fatalf("the origin received %q after the refusal", b)
		}
	case <-time.After(2 * time.Second):
	}
}

func TestRepeaterAttachRefusesWhatTheProxyDoesNotHold(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/repeater/ws-attach", map[string]any{"socket": 0, "opcode": "text", "payload": "x"}); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("attach with no proxy: %d, want 503", rec.Code)
	}
	f := openProxiedWs(t, s)
	if rec := postJSON(t, s, "/api/repeater/ws-attach", map[string]any{"opcode": "text", "payload": "x"}); rec.Code != http.StatusBadRequest {
		t.Errorf("attach without a socket: %d, want 400", rec.Code)
	}
	if rec := postJSON(t, s, "/api/repeater/ws-attach", map[string]any{"socket": uint64(f.socket) + 99, "opcode": "text", "payload": "x"}); rec.Code != http.StatusNotFound {
		t.Errorf("attach to a connection the proxy does not hold: %d, want 404", rec.Code)
	}
}

// cloneTarget is a WebSocket origin that records the handshake it received and echoes one frame.
func cloneTarget(t *testing.T) (*httptest.Server, func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: x\r\n\r\n")
		rw.Flush()
		frame, err := readOneFrame(rw.Reader)
		if err != nil {
			return
		}
		conn.Write(core.EncodeWsFrame(core.WsOpcodeText, []byte("echo: "+string(frame)), nil))
		conn.Write(core.EncodeWsFrame(core.WsOpcodeClose, []byte{0x03, 0xe8}, nil))
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header { mu.Lock(); defer mu.Unlock(); return seen }
}

// seedHandshake records a captured upgrade the way the proxy does, and returns its WebSocket ID.
func seedHandshake(t *testing.T, s *Server, host string, port uint16) core.ExchangeID {
	t.Helper()
	authority := net.JoinHostPort(host, strconv.Itoa(int(port)))
	raw := "GET http://" + authority + "/chat?room=1 HTTP/1.1\r\nHost: " + authority + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" +
		"Cookie: session=abc123\r\nOrigin: http://" + authority + "\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	reqID, err := s.store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, _ := s.store.Put([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"), core.DirectionResponse)
	status := uint16(101)
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: port,
		Method: "GET", Path: "/chat?room=1", Status: &status, Protocol: core.ProtocolHTTP1}
	s.store.AddExchange(ex)
	return ex.ID
}

func TestRepeaterCloneOpensANewConnectionWithTheCapturedHandshake(t *testing.T) {
	target, seen := cloneTarget(t)
	host, port := repeaterWsTargetOf(target)
	s := newTestServer()
	s.scope.AddInclude(host)
	socket := seedHandshake(t, s, host, port)

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"clone": true, "socket": uint64(socket), "opcode": "text", "payload": "cloned frame",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("clone send: %d %s", rec.Code, rec.Body.String())
	}
	var resp repeaterWsSendResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Messages) != 1 || resp.Messages[0].Payload != "echo: cloned frame" {
		t.Fatalf("reply = %+v", resp.Messages)
	}
	h := seen()
	if h.Get("Cookie") != "session=abc123" || h.Get("Origin") == "" {
		t.Errorf("the clone did not carry the captured handshake's Cookie/Origin: %v", h)
	}
	if h.Get("Sec-WebSocket-Key") == "dGhlIHNhbXBsZSBub25jZQ==" || h.Get("Sec-WebSocket-Key") == "" {
		t.Errorf("the clone replayed the original nonce: %q", h.Get("Sec-WebSocket-Key"))
	}
	if h.Get("Sec-WebSocket-Extensions") != "" {
		t.Errorf("the clone re-offered extensions: %q", h.Get("Sec-WebSocket-Extensions"))
	}
	// The recorded handshake is the one sent: it carries the cookie, and the new key.
	ex, _ := s.store.GetExchange(resp.ExchangeID)
	msg, _ := s.store.Get(core.MsgOrZero(ex.Request))
	if raw := string(msg.Raw()); !strings.Contains(raw, "Cookie: session=abc123") || !strings.Contains(raw, h.Get("Sec-WebSocket-Key")) {
		t.Errorf("the recorded handshake is not the one sent:\n%s", raw)
	}
}

func TestRepeaterCloneOutOfScopeIsRefusedBeforeTheDial(t *testing.T) {
	var reached bool
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true }))
	defer guard.Close()
	host, port := repeaterWsTargetOf(guard)
	s := newTestServer()
	s.scope.AddInclude("in-scope.example")
	socket := seedHandshake(t, s, host, port)

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"clone": true, "socket": uint64(socket), "opcode": "text", "payload": "x",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("clone out of scope: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if reached {
		t.Fatal("the out-of-scope target was contacted")
	}
	// A clone cannot be re-aimed: the bytes name their own Host.
	s.scope.AddInclude(host)
	if rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"clone": true, "socket": uint64(socket), "target": "elsewhere.example:80", "opcode": "text", "payload": "x",
	}); rec.Code != http.StatusBadRequest {
		t.Errorf("clone with a target: %d, want 400", rec.Code)
	}
}
