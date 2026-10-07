package proxy

// The "Edited" fact for a WebSocket message (burpsy-react-ui-d7bu). sd0d gave HTTP history an Edited
// column that reports the operator's own hold edit and not burpsy's rewrites; a WebSocket frame had no
// row-level home for the same fact, so an operator's edit to a frame was relayed correctly and
// reported nowhere. These tests drive the recording path — capture set, so drainWs writes to the store
// — and assert the fact lands on the WsMessage the store keeps. The wire behaviour is covered by
// ws_intercept_test.go and deliberately not re-proven here.

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
)

// wsRunCaptured drives one direction with a capture set — unlike wsRun, whose subject is the wire and
// which passes capture=nil — so drainWs records what the reassembler produced. It returns what reached
// the peer; the recorded rows are read from the store afterwards. The exchange id is non-zero because a
// recorded message names its handshake and 0 is the marker recordWsCaptureStopped refuses to key to.
func wsRunCaptured(t *testing.T, srv *Server, fromClient bool, write func(io.Writer)) []byte {
	t.Helper()
	srcR, srcW := net.Pipe()
	dstR, dstW := net.Pipe()
	stats := &wsCaptureStats{}
	peer := wsPeer{host: "chat.test", port: 443, tls: true, path: "/ws"}
	capture := &wsCapture{scope: testScope(), host: peer.host, port: peer.port, tls: peer.tls, path: peer.path}

	sink := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, dstR)
		sink <- buf.Bytes()
	}()
	faultCh := make(chan string, 1)
	go func() {
		fault := srv.wsDirection(1, bufio.NewReader(srcR), dstW, fromClient, peer, capture, stats)
		_ = dstW.Close()
		faultCh <- fault
	}()
	write(srcW)
	_ = srcW.Close()

	select {
	case fault := <-faultCh:
		if fault != "" {
			t.Fatalf("unexpected fault: %s", fault)
		}
	case <-time.After(wsTestTimeout):
		t.Fatal("wsDirection never returned — a frame is probably still held with no operator")
	}
	select {
	case got := <-sink:
		return got
	case <-time.After(wsTestTimeout):
		t.Fatal("the sink never closed")
		return nil
	}
}

// theOneRecordedMessage returns the single message the store captured, failing if there is not exactly
// one: a count wrong in either direction means the recording path — not the flag — is what to inspect.
func theOneRecordedMessage(t *testing.T, srv *Server) *core.WsMessage {
	t.Helper()
	msgs := srv.config.store.WsMessages(0, 100)
	if len(msgs) != 1 {
		t.Fatalf("recorded %d WebSocket messages, want exactly 1", len(msgs))
	}
	return msgs[0]
}

// The headline case the bead is about: an operator edits a held frame, and the recorded row says so.
func TestAnOperatorEditToAWebSocketFrameIsRecordedAsEdited(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	mask := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}
	original := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	stop := wsOperator(engine, func(h *intercept.Held) {
		_ = engine.Forward(h.ID, ptr(`{"role":"admin"}`), false, nil)
	})
	defer stop()

	_ = wsRunCaptured(t, srv, true, func(w io.Writer) { _, _ = w.Write(original) })

	m := theOneRecordedMessage(t, srv)
	if !m.UserEdited {
		t.Fatal("an operator edit to a WebSocket frame recorded UserEdited=false: the edit is reported " +
			"nowhere, which is exactly the gap burpsy-react-ui-d7bu closes")
	}
	if m.FromClient != true {
		t.Errorf("recorded direction FromClient=%v, want true — a to-server edit", m.FromClient)
	}
}

// The mirror direction, so the fact is not accidentally tied to a masked client frame.
func TestAnOperatorEditToAServerFrameIsRecordedAsEdited(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToClient)
	srv := wsTestServer(engine)

	original := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"balance":10}`), nil)

	stop := wsOperator(engine, func(h *intercept.Held) {
		_ = engine.Forward(h.ID, ptr(`{"balance":999999}`), false, nil)
	})
	defer stop()

	_ = wsRunCaptured(t, srv, false, func(w io.Writer) { _, _ = w.Write(original) })

	m := theOneRecordedMessage(t, srv)
	if !m.UserEdited {
		t.Fatal("an operator edit to a server→client frame recorded UserEdited=false")
	}
}

// The control that makes the flag mean something: a frame the operator forwarded untouched must not be
// flagged. Without it the test above would pass on a flag stuck at true.
func TestAWebSocketFrameForwardedUntouchedIsNotRecordedAsEdited(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsTestServer(engine)

	mask := [4]byte{1, 2, 3, 4}
	original := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	stop := wsOperator(engine, func(h *intercept.Held) {
		_ = engine.Forward(h.ID, nil, false, nil)
	})
	defer stop()

	_ = wsRunCaptured(t, srv, true, func(w io.Writer) { _, _ = w.Write(original) })

	m := theOneRecordedMessage(t, srv)
	if m.UserEdited {
		t.Fatal("a frame the operator forwarded untouched was recorded as edited")
	}
}

// sd0d's exact distinction, on the WebSocket path: a Match & Replace rewrite is the tool's, not the
// operator's, so a rewritten message the operator then forwarded untouched must read as not edited.
// This is the test that proves the fact comes from the hold's decision and not from the bytes changing.
func TestAWebSocketMatchReplaceRewriteIsNotRecordedAsAUserEdit(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsRuleServer(t, engine, wsRule(t, matchreplace.TargetWebSocketToServer, "user", "admin"))

	mask := [4]byte{9, 10, 11, 12}
	original := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	stop := wsOperator(engine, func(h *intercept.Held) {
		// nil: forward exactly the bytes the operator was shown, which are already the rewritten ones.
		_ = engine.Forward(h.ID, nil, false, nil)
	})
	defer stop()

	got := wsRunCaptured(t, srv, true, func(w io.Writer) { _, _ = w.Write(original) })

	// The rule must actually have fired, or this proves nothing.
	_, payload, _ := wsDecodeOne(t, got)
	if string(payload) != `{"role":"admin"}` {
		t.Fatalf("the match & replace rule did not fire: server received %q", payload)
	}

	m := theOneRecordedMessage(t, srv)
	if m.UserEdited {
		t.Fatal("a Match & Replace rewrite was recorded as the operator's own edit; that is the bug " +
			"burpsy-react-ui-sd0d fixed on the HTTP path and it must not reappear on WebSocket rows")
	}
}
