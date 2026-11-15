package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func ui2WSSeed(t *testing.T, s *Server) (text, closeID uint64) {
	t.Helper()
	exID := seedUI2Exchange(t, s, "GET /chat HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
	m1 := &core.WsMessage{Exchange: exID, FromClient: true, Opcode: core.WsOpcodeText}
	s.store.AddWsMessage(m1, []byte(`<script>alert(1)</script> hello`))
	m2 := &core.WsMessage{Exchange: exID, FromClient: false, Opcode: core.WsOpcodeClose}
	s.store.AddWsMessage(m2, []byte{0x03, 0xe8, 'b', 'y', 'e'})
	return uint64(m1.ID), uint64(m2.ID)
}

// Server-side filters narrow the frame table, and the metrics count every frame.
func TestUI2WSFilters(t *testing.T) {
	s := newTestServer()
	ui2WSSeed(t, s)
	body := ui2HX(t, s, "/ui2/ws?direction=server_to_client").Body.String()
	if !strings.Contains(body, "<code>close</code>") || strings.Contains(body, "<code>text</code>") {
		t.Fatalf("direction filter did not narrow the frames")
	}
	if body := ui2HX(t, s, "/ui2/ws?payload=hello").Body.String(); !strings.Contains(body, "<code>text</code>") || strings.Contains(body, "<code>close</code>") {
		t.Fatalf("payload filter did not narrow the frames")
	}
	if body := ui2HX(t, s, "/ui2/ws?opcode=bogus").Body.String(); !strings.Contains(body, "opcode must be one of") {
		t.Fatalf("an invalid opcode was not reported")
	}
}

// The frame view decodes a close frame and escapes an attacker-controlled payload; download
// serves the raw bytes.
func TestUI2WSFrameView(t *testing.T) {
	s := newTestServer()
	text, closeID := ui2WSSeed(t, s)
	body := ui2HX(t, s, "/ui2/ws/frame/"+itoa(closeID)).Body.String()
	if !strings.Contains(body, "Close code") || !strings.Contains(body, "1000") || !strings.Contains(body, "bye") {
		t.Fatalf("close frame not decoded: %.300s", body)
	}
	body = ui2HX(t, s, "/ui2/ws/frame/"+itoa(text)).Body.String()
	if strings.Contains(body, "<script>alert(1)") || !strings.Contains(body, "&lt;script&gt;alert(1)") {
		t.Fatalf("payload not escaped")
	}
	if !strings.Contains(body, "/ui2/repeater/ws?frame="+itoa(text)) || !strings.Contains(body, `data-seed="comparer.b"`) {
		t.Errorf("frame actions missing")
	}
	dl := getUI2(t, s, "/ui2/ws/frame/"+itoa(text)+"?download=1")
	if dl.Code != http.StatusOK || dl.Body.String() != `<script>alert(1)</script> hello` || !strings.Contains(dl.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("download = %d %q", dl.Code, dl.Header().Get("Content-Disposition"))
	}
	// Negative control: an unknown frame is reported, not rendered blank.
	if body := ui2HX(t, s, "/ui2/ws/frame/9999").Body.String(); !strings.Contains(body, "unavailable") {
		t.Errorf("unknown frame not reported: %.200s", body)
	}
}

// The handshake view renders the upgrade request/response of the connection's exchange.
func TestUI2WSHandshake(t *testing.T) {
	s := newTestServer()
	ui2WSSeed(t, s)
	body := ui2HX(t, s, "/ui2/ws/handshake/0").Body.String()
	if !strings.Contains(body, "Switching Protocols") || !strings.Contains(body, "/chat") {
		t.Fatalf("handshake not rendered: %.300s", body)
	}
	if body := ui2HX(t, s, "/ui2/ws/handshake/77").Body.String(); !strings.Contains(body, "Handshake unavailable") {
		t.Errorf("unknown exchange not reported")
	}
}
