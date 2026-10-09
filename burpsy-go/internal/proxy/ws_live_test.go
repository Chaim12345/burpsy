package proxy

// Repeater's attach to a live proxied WebSocket (burpsy-react-ui-wuwf), through a real listener,
// a real relay and a real origin. What is pinned:
//   - a frame injected toward the server reaches the origin masked and whole, and one injected
//     toward the client reaches the browser unmasked and whole, while the relay keeps relaying;
//   - both are recorded on the connection's own history with a note naming the real sender;
//   - a frame is never spliced into the middle of a message the relay is still passing;
//   - only a connection the relay holds right now can be attached to.

import (
	"bufio"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// startHeldWsOrigin accepts one handshake, answers 101 and hands the test the raw socket, so the
// test reads exactly what the origin received.
type heldOrigin struct {
	*bufio.ReadWriter
	conn net.Conn
}

func startHeldWsOrigin(t *testing.T) (host string, port uint16, conns chan heldOrigin) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	conns = make(chan heldOrigin, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { conn.Close() })
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"))
		conns <- heldOrigin{bufio.NewReadWriter(br, bufio.NewWriter(conn)), conn}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, uint16(n), conns
}

// readWsFrame reads one whole frame and returns its header and unmasked payload.
func readWsFrame(t *testing.T, br *bufio.Reader) (*core.WsFrameHeader, []byte) {
	t.Helper()
	var head []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			t.Fatalf("read frame header: %v", err)
		}
		head = append(head, b)
		hdr, need, perr := core.ParseWsFrameHeader(head)
		if perr != nil {
			t.Fatalf("parse frame header: %v", perr)
		}
		if need {
			continue
		}
		payload := make([]byte, hdr.PayloadLen)
		for read := 0; read < len(payload); {
			n, err := br.Read(payload[read:])
			if err != nil {
				t.Fatalf("read frame payload: %v", err)
			}
			read += n
		}
		if hdr.Masked {
			core.WsUnmask(payload, hdr.Mask, 0)
		}
		return hdr, payload
	}
}

type liveWsFixture struct {
	srv    *Server
	store  *core.TrafficStore
	client net.Conn
	cr     *bufio.Reader
	origin heldOrigin
	id     core.ExchangeID
}

func openLiveWs(t *testing.T) *liveWsFixture {
	t.Helper()
	host, port, conns := startHeldWsOrigin(t)
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).WithScope(testScope()).WithLogger(zap.NewNop()))
	proxyAddr := startProxy(t, srv)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	req := "GET http://" + net.JoinHostPort(host, strconv.Itoa(int(port))) + "/chat HTTP/1.1\r\n" +
		"Host: " + net.JoinHostPort(host, strconv.Itoa(int(port))) + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	client.Write([]byte(req))
	cr := bufio.NewReader(client)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		line, err := cr.ReadString('\n')
		if err != nil {
			t.Fatalf("read 101: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	var origin heldOrigin
	select {
	case origin = <-conns:
	case <-time.After(5 * time.Second):
		t.Fatal("the origin never completed the handshake")
	}
	ex := awaitExchange(t, store)
	// The registry is filled by the relay goroutine just after the 101 is written; wait for it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := srv.LiveWebSocket(ex.ID); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the relayed connection never appeared among the live WebSockets")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return &liveWsFixture{srv: srv, store: store, client: client, cr: cr, origin: origin, id: ex.ID}
}

func TestAnAttachedFrameReachesEachPeerWholeAndIsRecordedAsTheOperators(t *testing.T) {
	f := openLiveWs(t)

	// Toward the server: masked (a client frame), whole, carrying the operator's bytes.
	if _, err := f.srv.InjectWsFrame(f.id, false, core.WsOpcodeText, []byte("from repeater")); err != nil {
		t.Fatalf("inject to server: %v", err)
	}
	hdr, payload := readWsFrame(t, f.origin.Reader)
	if !hdr.Masked || string(payload) != "from repeater" || !hdr.FIN {
		t.Fatalf("the origin received masked=%v fin=%v %q, want a masked whole frame carrying the operator's text",
			hdr.Masked, hdr.FIN, payload)
	}

	// Toward the client: unmasked (a server frame).
	if _, err := f.srv.InjectWsFrame(f.id, true, core.WsOpcodeText, []byte("to the browser")); err != nil {
		t.Fatalf("inject to client: %v", err)
	}
	hdr, payload = readWsFrame(t, f.cr)
	if hdr.Masked || string(payload) != "to the browser" {
		t.Fatalf("the client received masked=%v %q, want an unmasked frame carrying the operator's text", hdr.Masked, payload)
	}

	// The relay still relays afterwards: the connection is the browser's, not ours to break.
	f.origin.Write(core.EncodeWsFrame(core.WsOpcodeText, []byte("origin speaks"), nil))
	f.origin.Flush()
	if _, payload = readWsFrame(t, f.cr); string(payload) != "origin speaks" {
		t.Fatalf("after the injections the relay delivered %q, want the origin's own frame", payload)
	}

	// Both injected frames are in the connection's history, in their directions, and say who sent them.
	deadline := time.Now().Add(5 * time.Second)
	var msgs []*core.WsMessage
	for time.Now().Before(deadline) {
		if msgs = f.store.WsMessagesFor(f.id, 0, 10); len(msgs) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var toServer, toClient bool
	for _, m := range msgs {
		p, _ := f.store.WsPayload(m.Payload)
		switch string(p) {
		case "from repeater":
			toServer = m.FromClient && strings.Contains(m.Note, "Repeater")
		case "to the browser":
			toClient = !m.FromClient && strings.Contains(m.Note, "Repeater")
		}
	}
	if !toServer || !toClient {
		t.Errorf("history does not hold both injected frames in their directions with the Repeater note: %+v", msgs)
	}
}

// A frame must never land inside a message the relay is still passing: a client that has sent a
// header and half a payload leaves the client→server stream mid-frame, and a frame written there
// would be read by the origin as the rest of the first frame's payload.
func TestAnAttachedFrameIsNotSplicedIntoAMessageInFlight(t *testing.T) {
	old := wsInjectBoundaryWait
	wsInjectBoundaryWait = 200 * time.Millisecond
	t.Cleanup(func() { wsInjectBoundaryWait = old })
	f := openLiveWs(t)

	mask := [4]byte{1, 2, 3, 4}
	whole := core.EncodeWsFrame(core.WsOpcodeText, []byte("0123456789abcdef"), &mask)
	half := len(whole) - 8
	f.client.Write(whole[:half])
	// Let the relay pass the first half on.
	got := make([]byte, half)
	for read := 0; read < half; {
		n, err := f.origin.Read(got[read:])
		if err != nil {
			t.Fatalf("origin read: %v", err)
		}
		read += n
	}

	_, err := f.srv.InjectWsFrame(f.id, false, core.WsOpcodeText, []byte("spliced"))
	if !errors.Is(err, ErrWsMidMessage) {
		t.Fatalf("inject mid-frame: err = %v, want ErrWsMidMessage — anything else means the frame was written inside another", err)
	}

	// The client finishes its frame; the origin sees exactly that frame, uncorrupted, and the
	// stream is at a boundary again, so the next injection goes through.
	f.client.Write(whole[half:])
	rest := make([]byte, len(whole)-half)
	for read := 0; read < len(rest); {
		n, err := f.origin.Read(rest[read:])
		if err != nil {
			t.Fatalf("origin read: %v", err)
		}
		read += n
	}
	if string(append(got, rest...)) != string(whole) {
		t.Fatal("the origin did not receive the client's frame byte-for-byte")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err = f.srv.InjectWsFrame(f.id, false, core.WsOpcodeText, []byte("now"))
		if err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("inject at a boundary: %v", err)
	}
	if _, p := readWsFrame(t, f.origin.Reader); string(p) != "now" {
		t.Fatalf("origin received %q, want the injected frame", p)
	}
}

func TestOnlyAConnectionTheRelayHoldsCanBeAttachedTo(t *testing.T) {
	f := openLiveWs(t)
	if _, err := f.srv.InjectWsFrame(f.id+1000, false, core.WsOpcodeText, []byte("x")); !errors.Is(err, ErrWsNotLive) {
		t.Fatalf("inject into an unknown id: err = %v, want ErrWsNotLive", err)
	}
	if _, err := f.srv.InjectWsFrame(f.id, false, core.WsOpcodeClose, nil); err == nil {
		t.Fatal("a close frame was accepted: attach sends data frames only")
	}

	// Both peers hang up; the relay returns and the connection leaves the registry.
	f.client.Close()
	f.origin.conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := f.srv.LiveWebSocket(f.id); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a closed connection stayed attachable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := f.srv.InjectWsFrame(f.id, false, core.WsOpcodeText, []byte("x")); !errors.Is(err, ErrWsNotLive) {
		t.Fatalf("inject into a closed connection: err = %v, want ErrWsNotLive", err)
	}
}
