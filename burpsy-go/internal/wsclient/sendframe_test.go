package wsclient

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// echoWS is a loopback WebSocket peer: it answers the upgrade, decodes the one client frame with the
// proxy's own reassembler (which checks the mask), echoes its payload as text, then closes with 1000.
// It reports the decoded client frame and whether it arrived masked.
func echoWS(t *testing.T) (addr string, got chan *core.WsEvent, masked chan bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got, masked = make(chan *core.WsEvent, 1), make(chan bool, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		h := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(h[:]) + "\r\n\r\n"))
		b0, _ := br.Peek(2)
		masked <- len(b0) == 2 && b0[1]&0x80 != 0
		rs := core.NewWsReassembler(1 << 20)
		buf := make([]byte, 4096)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				_ = rs.Feed(buf[:n])
				if ev := rs.Pop(); ev != nil {
					got <- ev
					_, _ = c.Write(core.EncodeWsFrame(core.WsOpcodeText, append([]byte("echo:"), ev.Payload...), nil))
					closePayload := binary.BigEndian.AppendUint16(nil, 1000)
					_, _ = c.Write(core.EncodeWsFrame(core.WsOpcodeClose, append(closePayload, "bye"...), nil))
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), got, masked
}

// SendFrame end to end against a loopback peer (burpsy-react-ui-live-only-paths): the resend
// handshakes, writes one MASKED client frame the peer decodes intact, reads the echo, and reports
// the peer's close with its code and reason. Previously only CloneHandshake had a test.
func TestSendFrameRoundTripsAgainstALoopbackPeer(t *testing.T) {
	addr, got, masked := echoWS(t)
	host, portStr, _ := net.SplitHostPort(addr)
	var port uint16
	for _, c := range portStr {
		port = port*10 + uint16(c-'0')
	}
	s := sender.NewSender(&sender.SenderConfig{Timeout: 5 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reply, err := SendFrame(ctx, s, host, port, false, "/chat", "", Frame{Opcode: core.WsOpcodeText, Payload: []byte("hello")})
	if err != nil {
		t.Fatalf("SendFrame: %v", err)
	}
	if !<-masked {
		t.Error("the client frame arrived unmasked; RFC 6455 §5.3 requires a client to mask")
	}
	if ev := <-got; string(ev.Payload) != "hello" {
		t.Errorf("the peer decoded %q, want hello", ev.Payload)
	}
	if len(reply.Messages) != 1 || string(reply.Messages[0].Payload) != "echo:hello" {
		t.Errorf("reply messages = %v, want one echo:hello", reply.Messages)
	}
	if !reply.ClosedByPeer || reply.CloseCode != 1000 || reply.CloseReason != "bye" {
		t.Errorf("close = (%v, %d, %q), want (true, 1000, bye)", reply.ClosedByPeer, reply.CloseCode, reply.CloseReason)
	}
	if !strings.HasPrefix(string(reply.RawHandshake), "HTTP/1.1 101") {
		t.Errorf("handshake recorded as %q", reply.RawHandshake)
	}
}
