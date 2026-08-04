package proxy

// These exercise the handshake rewrite and the compression note end to end —
// through a real listener, a real proxy goroutine and a real origin — rather
// than by calling stripWsHandshake directly. The whole point of the strip is
// what the *origin* receives and what *history* then shows, and neither of
// those is observable from a unit test of the rewrite function.

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// startWsOrigin runs a raw origin that completes one WebSocket handshake,
// publishes the request bytes it received, and then writes afterUpgrade to the
// socket as frames. Raw rather than net/http because the request bytes as they
// arrived are exactly what is under test, and any HTTP library would normalise
// them on the way through.
func startWsOrigin(t *testing.T, afterUpgrade []byte) (host string, port uint16, received chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	received = make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var raw []byte
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			raw = append(raw, line...)
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		received <- raw
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"))
		if len(afterUpgrade) > 0 {
			conn.Write(afterUpgrade)
		}
		// Held open so the relay's two goroutines are still pumping when the
		// test reads; the origin closing immediately would race the capture.
		time.Sleep(500 * time.Millisecond)
	}()

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, uint16(n), received
}

// startProxy runs the proxy on an ephemeral port and returns its address.
func startProxy(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()
	return ln.Addr().String()
}

// openWsThroughProxy sends an upgrade request offering permessage-deflate and
// reads the 101 back. The returned connection stays open so the relay lives.
func openWsThroughProxy(t *testing.T, proxyAddr, host string, port uint16) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := fmt.Sprintf("GET http://%s:%d/chat HTTP/1.1\r\n", host, port) +
		fmt.Sprintf("Host: %s:%d\r\n", host, port) +
		"Upgrade: websocket\r\n" +
		"Connection: keep-alive, Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	if !strings.Contains(line, "101") {
		t.Fatalf("origin did not switch protocols: %q", line)
	}
	return conn
}

func awaitOrigin(t *testing.T, received chan []byte) string {
	t.Helper()
	select {
	case raw := <-received:
		return string(raw)
	case <-time.After(5 * time.Second):
		t.Fatal("the origin never received a handshake")
		return ""
	}
}

func TestTheExtensionOfferIsStrippedBeforeTheHandshakeReachesTheOrigin(t *testing.T) {
	host, port, received := startWsOrigin(t, nil)
	store := core.NewTrafficStore()
	proxyAddr := startProxy(t, NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop())))

	openWsThroughProxy(t, proxyAddr, host, port)
	got := awaitOrigin(t, received)

	if strings.Contains(strings.ToLower(got), core.WsExtensionsHeader) {
		t.Fatalf("the origin was offered permessage-deflate, so it may negotiate compression and every captured payload becomes a DEFLATE block:\n%s", got)
	}
	if !strings.Contains(got, "Upgrade: websocket") || !strings.Contains(got, "Sec-WebSocket-Key:") {
		t.Errorf("the strip damaged the rest of the handshake:\n%s", got)
	}
}

func TestARewrittenHandshakeDoesNotLookPristineInHistory(t *testing.T) {
	host, port, received := startWsOrigin(t, nil)
	store := core.NewTrafficStore()
	proxyAddr := startProxy(t, NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop())))

	openWsThroughProxy(t, proxyAddr, host, port)
	awaitOrigin(t, received)

	ex := awaitExchange(t, store)
	if ex.Notes == nil {
		t.Fatal("the handshake was rewritten and history says nothing about it; an operator comparing their client's request against this row would find a header missing with no explanation")
	}
	if !strings.Contains(*ex.Notes, "permessage-deflate; client_max_window_bits") {
		t.Errorf("the note does not repeat the offer that was removed, so the only record of what the client actually asked for is gone: %q", *ex.Notes)
	}

	// What history shows for the request must be what upstream received.
	req, err := store.Get(ex.Request)
	if err != nil {
		t.Fatalf("stored request: %v", err)
	}
	if strings.Contains(strings.ToLower(string(req.Raw())), core.WsExtensionsHeader) {
		t.Error("history shows the client's original request while a different one went upstream; the recorded bytes must be the bytes sent")
	}
}

func TestStrippingCanBeTurnedOffForAnOriginThatRequiresTheExtension(t *testing.T) {
	host, port, received := startWsOrigin(t, nil)
	store := core.NewTrafficStore()
	proxyAddr := startProxy(t, NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithStripWsExtensions(false).
		WithLogger(zap.NewNop())))

	openWsThroughProxy(t, proxyAddr, host, port)
	got := awaitOrigin(t, received)

	if !strings.Contains(strings.ToLower(got), core.WsExtensionsHeader) {
		t.Fatalf("stripping was disabled and the offer was removed anyway, leaving no escape hatch for an origin that refuses the handshake without it:\n%s", got)
	}
	ex := awaitExchange(t, store)
	if ex.Notes != nil {
		t.Errorf("history claims a rewrite that never happened: %q", *ex.Notes)
	}
}

func TestACompressedFrameIsRecordedWithANoteRatherThanAsPlaintext(t *testing.T) {
	// A server→client text frame with RSV1 set: what a peer sends once
	// permessage-deflate has been negotiated. Reachable only with stripping
	// off, which is exactly the configuration Burp leaves silent.
	deflated := []byte{0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}
	frame := append([]byte{0xc1, byte(len(deflated))}, deflated...)

	host, port, received := startWsOrigin(t, frame)
	store := core.NewTrafficStore()
	proxyAddr := startProxy(t, NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithStripWsExtensions(false).
		WithLogger(zap.NewNop())))

	openWsThroughProxy(t, proxyAddr, host, port)
	awaitOrigin(t, received)

	m := awaitWsMessage(t, store)
	if m.Note == "" {
		t.Fatalf("a compressed payload was captured with no note; history presents %d bytes of DEFLATE stream as though they were the message text", m.Len)
	}
	if !strings.Contains(m.Note, "RSV1") {
		t.Errorf("the note does not say why the payload is unreadable: %q", m.Note)
	}
	payload, err := store.WsPayload(m.Payload)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if string(payload) != string(deflated) {
		t.Error("the recorded payload is not the bytes that arrived; an undecoded frame must be kept verbatim or the note describes something other than what is shown")
	}
}

// awaitExchange waits for the first exchange to reach the store and returns it.
//
// The one waiting idiom for "has the capture happened yet" in this package, used by the handshake
// tests, the plain and TLS interception tests and the tunnel test. Every capture site records from the
// connection's own goroutine, and all of them now do it *after* the response bytes have gone to the
// client, so a bare read races the capture in every one of these tests rather than only in the relay's.
// Two hand-rolled poll loops for the same question is how one of them ends up with the wrong bound.
func awaitExchange(t *testing.T, store *core.TrafficStore) *core.Exchange {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ex := store.Exchanges(); len(ex) > 0 {
			return ex[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no exchange was ever recorded")
	return nil
}

func awaitWsMessage(t *testing.T, store *core.TrafficStore) *core.WsMessage {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if msgs := store.WsMessages(0, 1); len(msgs) > 0 {
			return msgs[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no WebSocket message was ever captured")
	return nil
}
