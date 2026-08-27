package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"go.uber.org/zap"
)

// ---- WebSocket interception -----------------------------------------------------------------
//
// Burp holds WebSocket messages, so burpsy has to. The relay was built on an explicit
// "relay first, capture second" invariant — every byte written to the sink before anything
// looks at it — and interception is the one deliberate exception to it, because a frame that
// has already been relayed cannot be held. See wsIntercept's doc comment for the argument.
//
// That makes the two most important tests in this file the negative ones: that interception
// OFF leaves the byte stream untouched, and that the frames burpsy refuses to hold (control,
// compressed, fragmented) are relayed rather than silently swallowed. A feature that can stall
// a live application's socket is only safe if it is provably inert when switched off.
//
// Everything here drives wsDirection directly over net.Pipe rather than standing up a full
// WebSocket origin: the hold decision, the frame buffering and the re-encoding all live in the
// relay, and a real origin would add a handshake without adding coverage of any of it.

const wsTestTimeout = 5 * time.Second

func wsTestServer(engine *intercept.Engine) *Server {
	store := core.NewTrafficStore()
	return NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithIntercept(engine))
}

// wsRun pumps the bytes produced by write through wsDirection and returns everything that
// reached the sink, plus the fault wsDirection reported and the counters it updated.
//
// capture is nil throughout: these tests are about what goes on the wire, and an uncaptured
// connection is the case where interception must still work — a handshake that failed to record
// does not suspend the operator's rules.
func wsRun(t *testing.T, srv *Server, fromClient bool, write func(io.Writer)) ([]byte, string, *wsCaptureStats) {
	t.Helper()

	srcR, srcW := net.Pipe()
	dstR, dstW := net.Pipe()
	stats := &wsCaptureStats{}

	sink := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, dstR)
		sink <- buf.Bytes()
	}()

	faultCh := make(chan string, 1)
	go func() {
		fault := srv.wsDirection(0, bufio.NewReader(srcR), dstW, fromClient,
			wsPeer{host: "chat.test", port: 443, tls: true, path: "/ws"}, nil, stats)
		// Closing the sink is what ends the collector's io.Copy.
		_ = dstW.Close()
		faultCh <- fault
	}()

	write(srcW)
	_ = srcW.Close()

	var fault string
	select {
	case fault = <-faultCh:
	case <-time.After(wsTestTimeout):
		t.Fatal("wsDirection never returned — a frame is probably still held with no operator to " +
			"resolve it, which is the deadlock this feature can cause if the gate is wrong")
	}
	select {
	case got := <-sink:
		return got, fault, stats
	case <-time.After(wsTestTimeout):
		t.Fatal("the sink never closed")
		return nil, "", nil
	}
}

// wsOperator answers held messages until the returned stop function is called. Real operators
// are slow and arrive after the frame is already held, which is exactly the ordering that makes
// the hold path block, so this polls rather than being driven by the test.
func wsOperator(engine *intercept.Engine, decide func(*intercept.Held)) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-done:
				return
			default:
			}
			for _, h := range engine.Held() {
				decide(h)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	return func() { close(done); <-stopped }
}

// holdEverything activates an unconditional rule list for one direction, which is Burp's
// "intercept everything" and keeps these tests about the frame path rather than rule matching.
func holdEverything(t *testing.T, dir intercept.Direction) *intercept.Engine {
	t.Helper()
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(dir, true, nil); err != nil {
		t.Fatalf("SetRules(%s): %v", dir, err)
	}
	return engine
}

// wsDecodeOne parses exactly one frame and returns its opcode and unmasked payload, failing if
// the bytes are not exactly one whole frame. Deliberately strict: a test that accepted trailing
// bytes would pass while the encoder emitted a frame plus garbage.
func wsDecodeOne(t *testing.T, raw []byte) (core.WsOpcode, []byte, bool) {
	t.Helper()
	hdr, need, err := core.ParseWsFrameHeader(raw)
	if err != nil || need {
		t.Fatalf("could not parse the relayed frame: err=%v need=%v bytes=% x", err, need, raw)
	}
	end := hdr.HeaderLen + int(hdr.PayloadLen)
	if len(raw) != end {
		t.Fatalf("expected exactly one frame, got %d bytes for a frame of %d", len(raw), end)
	}
	payload := make([]byte, hdr.PayloadLen)
	copy(payload, raw[hdr.HeaderLen:end])
	if hdr.Masked {
		core.WsUnmask(payload, hdr.Mask, 0)
	}
	return hdr.Opcode, payload, hdr.Masked
}

// The headline case: a frame is held, an operator forwards it untouched, and the bytes that
// reach the server are the bytes the client sent — mask included. "Forwarded unchanged" must be
// indistinguishable on the wire from "never intercepted", or enabling interception would itself
// be detectable by the application.
func TestAForwardedWebSocketFrameIsRelayedByteIdentically(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"msg":"hello"}`), &mask)

	stop := wsOperator(engine, func(h *intercept.Held) {
		_ = engine.Forward(h.ID, "", false)
	})
	defer stop()

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("relayed % x, want % x — an untouched frame must be byte-identical", got, frame)
	}
}

// A held frame must actually be held: it must not reach the peer before the operator decides.
// Without this, everything else here would pass on a path that forwarded first and offered the
// frame afterwards, which is a review tool rather than an interception tool.
func TestAHeldWebSocketFrameDoesNotReachThePeerUntilResolved(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	mask := [4]byte{1, 2, 3, 4}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte("do not send me yet"), &mask)

	srcR, srcW := net.Pipe()
	dstR, dstW := net.Pipe()

	go func() {
		_ = srv.wsDirection(0, bufio.NewReader(srcR), dstW, true,
			wsPeer{host: "chat.test", port: 443, tls: true, path: "/ws"}, nil, &wsCaptureStats{})
		_ = dstW.Close()
	}()
	go func() { _, _ = srcW.Write(frame) }()

	// The sink must stay silent while the frame is held. A read deadline is the only way to
	// assert "nothing arrived": net.Pipe has no buffer, so a successful read here means
	// wsDirection wrote the frame through without waiting.
	_ = dstR.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var probe [1]byte
	if n, err := dstR.Read(probe[:]); err == nil || n > 0 {
		t.Fatalf("a byte reached the peer while the frame was held (n=%d, err=%v)", n, err)
	}

	// And it must be visible to the operator while it waits, with its direction and frame type
	// intact — an operator cannot decide about a frame the API does not show them.
	held := engine.Held()
	if len(held) != 1 {
		t.Fatalf("%d held messages, want 1", len(held))
	}
	if held[0].Direction != intercept.DirectionWebSocketToServer {
		t.Errorf("held as %s, want websocket_to_server", held[0].Direction)
	}
	if held[0].Opcode != "text" {
		t.Errorf("opcode %q, want \"text\" — without it the operator cannot tell text from binary",
			held[0].Opcode)
	}
	if string(held[0].Raw) != "do not send me yet" {
		t.Errorf("held payload %q; the operator must see it unmasked", held[0].Raw)
	}

	// Release it so the goroutine can exit.
	_ = dstR.SetReadDeadline(time.Time{})
	go func() { _, _ = io.Copy(io.Discard, dstR) }()
	_ = engine.Drop(held[0].ID, "end of test")
	_ = srcW.Close()
}

// An edit must reach the server, and a client-to-server frame must be masked on the way —
// RFC 6455 §5.1 requires it and a server receiving an unmasked frame is required to fail the
// connection, so an unmasked edit would drop the socket rather than corrupt one message.
func TestAnEditedClientFrameIsReMaskedAndCarriesTheEdit(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	mask := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}
	original := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)
	const edited = `{"role":"admin"}`

	stop := wsOperator(engine, func(h *intercept.Held) {
		// fixContentLength false: a WebSocket frame has no Content-Length, and asking the HTTP
		// rewriter to find one in a JSON payload is how a frame gets mangled.
		_ = engine.Forward(h.ID, edited, false)
	})
	defer stop()

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(original) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}

	opcode, payload, masked := wsDecodeOne(t, got)
	if opcode != core.WsOpcodeText {
		t.Errorf("opcode %v, want text — the edit must not change the frame type", opcode)
	}
	if !masked {
		t.Error("the edited client frame went out unmasked; the server must fail the connection")
	}
	if string(payload) != edited {
		t.Errorf("server received %q, want %q", payload, edited)
	}
	if bytes.Contains(got, []byte("admin")) {
		t.Error("the edited payload is readable on the wire, so it was not masked")
	}
}

// The mirror case. A server-to-client frame must NOT be masked, and the direction decides that,
// not whatever happened to arrive — so an edit to an inbound frame must go out unmasked.
func TestAnEditedServerFrameGoesOutUnmasked(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToClient)
	srv := wsTestServer(engine)

	original := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"balance":10}`), nil)
	const edited = `{"balance":999999}`

	stop := wsOperator(engine, func(h *intercept.Held) {
		_ = engine.Forward(h.ID, edited, false)
	})
	defer stop()

	got, fault, _ := wsRun(t, srv, false, func(w io.Writer) { _, _ = w.Write(original) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}

	_, payload, masked := wsDecodeOne(t, got)
	if masked {
		t.Error("a server→client frame was masked; RFC 6455 forbids it and the client must fail")
	}
	if string(payload) != edited {
		t.Errorf("client received %q, want %q", payload, edited)
	}
}

// A dropped frame must never appear on the wire at all, and must be counted as dropped rather
// than as skipped — "the peer never got this" and "we did not record this" are different facts.
func TestADroppedWebSocketFrameNeverReachesThePeer(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	mask := [4]byte{5, 6, 7, 8}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte("rm -rf /"), &mask)

	stop := wsOperator(engine, func(h *intercept.Held) {
		_ = engine.Drop(h.ID, "not on my watch")
	})
	defer stop()

	got, fault, stats := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if len(got) != 0 {
		t.Errorf("%d bytes reached the peer for a dropped frame: % x", len(got), got)
	}
	if n := stats.dropped.Load(); n != 1 {
		t.Errorf("dropped counter = %d, want 1", n)
	}
	if n := stats.skipped.Load(); n != 0 {
		t.Errorf("skipped counter = %d, want 0 — a dropped frame is not an out-of-scope one", n)
	}
}

// A frame split across reads must be held once, whole. TCP splits wherever it likes, and a
// hold decision on half a frame would offer the operator a truncated payload and then put a
// malformed frame on the wire.
func TestAFrameSplitAcrossReadsIsHeldOnceAndWhole(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	payload := bytes.Repeat([]byte("x"), 400) // 400 > 125, so a 2-byte extended length
	mask := [4]byte{9, 8, 7, 6}
	frame := core.EncodeWsFrame(core.WsOpcodeBinary, payload, &mask)

	var offered int
	stop := wsOperator(engine, func(h *intercept.Held) {
		if len(h.Raw) != len(payload) {
			t.Errorf("offered %d payload bytes, want %d — a partial frame was held",
				len(h.Raw), len(payload))
		}
		offered++
		_ = engine.Forward(h.ID, "", false)
	})
	defer stop()

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) {
		// Split mid-header, then mid-payload: both boundaries a real read can land on.
		_, _ = w.Write(frame[:1])
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write(frame[1:5])
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write(frame[5:200])
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write(frame[200:])
	})
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("reassembled frame differs from the original (%d vs %d bytes)", len(got), len(frame))
	}
	if offered != 1 {
		t.Errorf("the frame was offered %d times, want 1", offered)
	}
}

// Several frames in one read must each be offered, in order. A read carrying three frames that
// held only the first would reorder the stream.
func TestSeveralFramesInOneReadAreEachHeldInOrder(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	mask := [4]byte{2, 4, 6, 8}
	var input []byte
	for _, s := range []string{"first", "second", "third"} {
		input = append(input, core.EncodeWsFrame(core.WsOpcodeText, []byte(s), &mask)...)
	}

	var seen []string
	stop := wsOperator(engine, func(h *intercept.Held) {
		seen = append(seen, string(h.Raw))
		_ = engine.Forward(h.ID, "", false)
	})
	defer stop()

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(input) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("relayed %d bytes, want %d", len(got), len(input))
	}
	if want := []string{"first", "second", "third"}; len(seen) != 3 ||
		seen[0] != want[0] || seen[1] != want[1] || seen[2] != want[2] {
		t.Errorf("offered %v, want %v — order must be preserved", seen, want)
	}
}

// ---- the frames burpsy refuses to hold -------------------------------------------------------
//
// Each of these is relayed untouched with hold-everything active and NO operator running. That
// is the strong form of the assertion: if any of them were offered for interception, the test
// would block until wsTestTimeout and fail, because nobody is there to resolve it.

func TestControlFramesAreRelayedWithoutBeingHeld(t *testing.T) {
	for _, op := range []core.WsOpcode{core.WsOpcodePing, core.WsOpcodePong, core.WsOpcodeClose} {
		t.Run(op.Name(), func(t *testing.T) {
			engine := holdEverything(t, intercept.DirectionWebSocketToServer)
			srv := wsTestServer(engine)

			mask := [4]byte{1, 1, 1, 1}
			frame := core.EncodeWsFrame(op, []byte("k"), &mask)

			got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
			if fault != "" {
				t.Fatalf("unexpected fault: %s", fault)
			}
			if !bytes.Equal(got, frame) {
				t.Errorf("%v was not relayed untouched: got % x want % x — holding a ping stalls "+
					"the peer's keepalive and holding a close makes the socket unendable",
					op, got, frame)
			}
		})
	}
}

func TestCompressedFramesAreRelayedWithoutBeingHeld(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	// RSV1 set is permessage-deflate's marker. Built by hand because EncodeWsFrame
	// deliberately cannot express a compressed frame.
	frame := []byte{0x81 | 0x40, 0x03, 'a', 'b', 'c'}

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("a compressed frame was altered: got % x want % x — its payload is a DEFLATE "+
			"block, so offering it as editable text would be fiction", got, frame)
	}
}

func TestFragmentedFramesAreRelayedWithoutBeingHeld(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	// FIN clear on a text frame, then a continuation with FIN set: the two-fragment message.
	first := []byte{0x01, 0x03, 'a', 'b', 'c'}
	cont := []byte{0x80, 0x03, 'd', 'e', 'f'}
	input := append(append([]byte{}, first...), cont...)

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(input) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("a fragmented message was altered: got % x want % x", got, input)
	}
}

// ---- interception off must be inert ----------------------------------------------------------

// The safety test. With interception disabled the relay must behave exactly as it did before
// this feature existed, byte for byte, and must not buffer waiting for frame boundaries.
func TestWithInterceptionDisabledTheStreamIsUntouched(t *testing.T) {
	engine := intercept.NewEngine() // never enabled
	srv := wsTestServer(engine)

	// Includes a deliberately truncated final frame: on the relay-first path a partial frame is
	// still forwarded immediately, because the peer's bytes are the peer's. If the intercept path
	// engaged here it would hold these bytes back and this test would see them missing.
	mask := [4]byte{3, 3, 3, 3}
	input := core.EncodeWsFrame(core.WsOpcodeText, []byte("hello"), &mask)
	input = append(input, 0x81, 0x7f) // a header promising a payload that never comes

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(input) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("relayed % x, want % x — with interception off nothing may be held back", got, input)
	}
}

// Interception enabled for HTTP but with no active WebSocket rule list must also be inert. This
// is the specific mistake worth pinning: gating on Enabled() alone would start buffering every
// frame in the process the moment an operator turned interception on for requests.
func TestInterceptEnabledWithNoWebSocketListDoesNotHoldFrames(t *testing.T) {
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	srv := wsTestServer(engine)

	mask := [4]byte{4, 4, 4, 4}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte("unaffected"), &mask)

	// No operator: if this holds, the test times out rather than passing quietly.
	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("HTTP interception affected a WebSocket frame: got % x want % x", got, frame)
	}
	if n := len(engine.Held()); n != 0 {
		t.Errorf("%d messages held, want 0", n)
	}
}

// An unmatched frame — active list, but a rule that does not match this connection — must be
// relayed byte-identically rather than re-encoded, so it stays indistinguishable from a frame
// on a connection burpsy never inspected.
func TestAnUnmatchedFrameIsRelayedByteIdentically(t *testing.T) {
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionWebSocketToServer, true, []intercept.Rule{{
		Field:       intercept.FieldHost,
		Category:    intercept.CategoryLiteral,
		StringMatch: "somewhere-else.invalid",
		Enabled:     true,
	}}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	srv := wsTestServer(engine)

	mask := [4]byte{7, 7, 7, 7}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte("passing through"), &mask)

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("an unmatched frame was re-encoded: got % x want % x", got, frame)
	}
}

// A frame stream whose boundaries cannot be located must degrade to a plain relay rather than
// swallowing the bytes it had buffered. Those bytes belong to the peer; our inability to parse
// them is not a reason to withhold them.
func TestAnUnparseableFrameStreamStillRelaysWhatItBuffered(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	// A 64-bit length with the reserved high bit set is the one header the parser calls
	// unrecoverable, because the next frame's start becomes unknowable.
	frame := []byte{0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 1, 'z'}

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault == "" {
		t.Error("an unparseable frame stream reported no fault, so nothing would be recorded " +
			"about the gap in the index")
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("relayed % x, want % x — buffered bytes must still reach the peer", got, frame)
	}
}
