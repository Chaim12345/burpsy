package intercept

import (
	"strings"
	"testing"
)

// ---- absent, empty, and Content-Length (ICPT-EMPTY-EDIT) -----------------------------------
//
// Forward took a plain string and treated "" as "unchanged". For HTTP that is harmless: an empty
// request or response is meaningless, so nobody could want one. For a WebSocket frame an empty
// payload is ordinary — a keepalive, a cleared field — so an operator who selected the payload and
// deleted it got the ORIGINAL forwarded, answered 200, with nothing to indicate their edit had been
// discarded.
//
// It now takes *string: nil forwards what was held, and a pointer to "" clears the payload. The
// tests below pin both, plus a second bug found while fixing it — see the Content-Length one.

// holdOne holds a message in the given direction and returns it.
func holdOne(t *testing.T, dir Direction, raw string) (*Engine, *Held) {
	t.Helper()
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(dir, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	held := e.Hold(&Message{Direction: dir, Host: "chat.test", Port: 443, Path: "/ws", Raw: []byte(raw)})
	if held == nil {
		t.Fatal("an unconditional active list did not hold")
	}
	return e, held
}

// nil means unchanged, which is what every existing caller relies on.
func TestForwardWithNilKeepsTheHeldBytes(t *testing.T) {
	e, held := holdOne(t, DirectionWebSocketToServer, "original payload")

	done := make(chan struct{})
	var action Action
	var out []byte
	go func() { action, out = held.Wait(); close(done) }()

	if err := e.Forward(held.ID, nil, false); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	<-done
	if action != ActionForward {
		t.Errorf("action = %v, want forward", action)
	}
	if string(out) != "original payload" {
		t.Errorf("forwarded %q, want the held bytes unchanged", out)
	}
}

// The bug. A pointer to the empty string must clear the payload, not silently forward the original.
func TestForwardWithAnEmptyStringClearsThePayload(t *testing.T) {
	e, held := holdOne(t, DirectionWebSocketToServer, "delete me")

	done := make(chan struct{})
	var out []byte
	go func() { _, out = held.Wait(); close(done) }()

	empty := ""
	if err := e.Forward(held.ID, &empty, false); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	<-done
	if len(out) != 0 {
		t.Errorf("forwarded %q, want an empty payload — clearing a WebSocket frame is a real "+
			"operation and used to be indistinguishable from making no edit at all", out)
	}
}

// The second bug, found while fixing the first: the console's fix-Content-Length toggle defaults to
// ON, and rewriteContentLength splits on the first CRLFCRLF. A frame payload has no Content-Length,
// but a payload that happens to contain a blank line looks like a header block to that function — so
// forwarding a held WebSocket message with default settings injected a header into application data.
func TestForwardDoesNotRewriteContentLengthOnAWebSocketFrame(t *testing.T) {
	// A payload with a blank line, which is what rewriteContentLength reads as a header/body split.
	const payload = "field: value\r\n\r\nthe body"
	e, held := holdOne(t, DirectionWebSocketToServer, payload)

	done := make(chan struct{})
	var out []byte
	go func() { _, out = held.Wait(); close(done) }()

	// fixContentLength true, exactly as the console sends by default.
	if err := e.Forward(held.ID, nil, true); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	<-done
	if strings.Contains(string(out), "Content-Length") {
		t.Errorf("a Content-Length header was injected into a WebSocket payload: %q", out)
	}
	if string(out) != payload {
		t.Errorf("the payload was altered: %q, want %q", out, payload)
	}
}

// And the HTTP behaviour it must not disturb: for a real HTTP message, the toggle still works.
func TestForwardStillRewritesContentLengthOnHTTP(t *testing.T) {
	const req = "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 999\r\n\r\nshort"
	e, held := holdOne(t, DirectionRequest, req)

	done := make(chan struct{})
	var out []byte
	go func() { _, out = held.Wait(); close(done) }()

	if err := e.Forward(held.ID, nil, true); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	<-done
	if !strings.Contains(string(out), "Content-Length: 5") {
		t.Errorf("Content-Length was not corrected for an HTTP request: %q", out)
	}
}

// An edit plus the toggle, on HTTP: the length must match the edited body, not the original.
func TestForwardRewritesContentLengthToMatchAnEdit(t *testing.T) {
	const req = "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n\r\nshort"
	e, held := holdOne(t, DirectionRequest, req)

	done := make(chan struct{})
	var out []byte
	go func() { _, out = held.Wait(); close(done) }()

	edited := "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n\r\nmuch longer body"
	if err := e.Forward(held.ID, &edited, true); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	<-done
	if !strings.Contains(string(out), "Content-Length: 16") {
		t.Errorf("Content-Length does not match the edited body: %q", out)
	}
}
