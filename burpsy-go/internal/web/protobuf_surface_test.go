package web

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/intercept"
)

// ---- binary bodies on every editable surface (burpsy-react-ui-3pco) ------------------------------
//
// The Protobuf tab can only name and edit what the editor can hold byte-exact, so every surface that
// shows a message carries its body octets when `text` cannot. These pin the two editable surfaces
// beyond Repeater: a held intercept carries its body, and a forward of an edit is byte-exact.

func TestEditableBodyBase64OnlyForThePlainWireBody(t *testing.T) {
	bin := "\x08\x96\x01"
	cases := map[string]struct {
		raw  string
		want string
	}{
		"binary, plain":  {"POST /p.S/M HTTP/1.1\r\nContent-Type: application/grpc\r\n\r\n" + bin, base64.StdEncoding.EncodeToString([]byte(bin))},
		"text body":      {"POST / HTTP/1.1\r\n\r\nhello", ""},
		"no body":        {"GET / HTTP/1.1\r\n\r\n", ""},
		"gzip-encoded":   {"POST / HTTP/1.1\r\nContent-Encoding: gzip\r\n\r\n" + bin, ""},
		"chunked":        {"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + bin, ""},
		"identity is ok": {"POST / HTTP/1.1\r\nContent-Encoding: identity\r\n\r\n" + bin, base64.StdEncoding.EncodeToString([]byte(bin))},
	}
	for name, c := range cases {
		if got := editableBodyBase64([]byte(c.raw)); got != c.want {
			t.Errorf("%s: editableBodyBase64 = %q, want %q", name, got, c.want)
		}
	}
}

func TestInterceptForwardRawBase64IsByteExact(t *testing.T) {
	s := newTestServer()
	s.intercept.SetEnabled(true)
	if err := s.intercept.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatal(err)
	}
	held := []byte("POST /p.S/M HTTP/1.1\r\nHost: t\r\nContent-Type: application/grpc\r\nContent-Length: 3\r\n\r\n\x08\x96\x01")
	h := s.intercept.Hold(&intercept.Message{Direction: intercept.DirectionRequest, Host: "t", Port: 80, Method: "POST", Path: "/p.S/M", Raw: held})
	if h == nil {
		t.Fatal("not held")
	}

	// The held view carries the binary body the `raw` string cannot.
	status := getJSON(t, s, "/api/intercept")
	if !bytes.Contains(status.Body.Bytes(), []byte(`"raw_body_base64":"`+base64.StdEncoding.EncodeToString([]byte("\x08\x96\x01"))+`"`)) {
		t.Fatalf("held view lacks raw_body_base64: %s", status.Body.String())
	}

	// An edit that changes the varint 150 to 200 (0xC8 0x01) — a byte >= 0x80 that a JSON string
	// would turn into U+FFFD — forwarded as raw_base64.
	edited := []byte("POST /p.S/M HTTP/1.1\r\nHost: t\r\nContent-Type: application/grpc\r\nContent-Length: 3\r\n\r\n\x08\xc8\x01")
	done := make(chan []byte, 1)
	go func() {
		_, raw, _, _ := h.Wait()
		done <- raw
	}()
	rec := postJSON(t, s, "/api/intercept/"+strconv.FormatUint(h.ID, 10)+"/forward", map[string]any{
		"raw_base64": base64.StdEncoding.EncodeToString(edited),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("forward = %d: %s", rec.Code, rec.Body.String())
	}
	select {
	case got := <-done:
		if !bytes.Equal(got, edited) {
			t.Fatalf("forwarded bytes differ:\n got %q\nwant %q", got, edited)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait never returned")
	}

	if r := postJSON(t, s, "/api/intercept/999/forward", map[string]any{"raw_base64": "%%%"}); r.Code != http.StatusBadRequest {
		t.Errorf("bad base64 should be 400, got %d", r.Code)
	}
}
