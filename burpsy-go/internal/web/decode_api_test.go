package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// A body that is not valid UTF-8 is exactly what the lossy text transport destroys: encoding/json
// replaces the high bytes with U+FFFD, so a Windows-1252 body comes out of /api/message as a run
// of replacement characters. b64 must carry the exact original bytes so the UI can decode the
// declared charset and render what the peer actually sent.
func TestMessageViewB64CarriesBytesTheLossyTextCannot(t *testing.T) {
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=windows-1252\r\n\r\ncach"),
		'\xe8') // "cachè" in Windows-1252; 0xE8 is not valid UTF-8.

	s := newTestServer()
	id, err := s.store.Put(raw, core.DirectionResponse)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	rec := get(t, s, fmt.Sprintf("/api/message/%d", id))
	if rec.Code != http.StatusOK {
		t.Fatalf("message: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var view MessageView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode message view: %v", err)
	}
	// The lossy text copy must actually be lossy here, or the test is not testing the b64 path.
	if view.Text == string(raw) {
		t.Fatalf("text came back byte-identical for non-UTF-8 bytes; the lossless path is untested")
	}
	got, err := base64.StdEncoding.DecodeString(view.B64)
	if err != nil {
		t.Fatalf("b64 is not valid base64: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("b64 round-trip = %q, want the exact original bytes %q", got, raw)
	}
}

// The same claim for the Repeater send path: the inline response must carry the exact bytes the
// peer sent, not the U+FFFD-replaced rendering, so a latin-1 or compressed response renders
// correctly without a second round-trip to /api/message.
func TestRepeaterResponseB64CarriesTheExactBody(t *testing.T) {
	body := append([]byte("<!doctype html>"), 0xe8, 0x00, 0xff)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=windows-1252")
		_, _ = w.Write(body)
	}))
	defer target.Close()

	host, port, _, err := targetParts(target.URL[len("http://"):])
	if err != nil {
		t.Fatal(err)
	}

	scope := core.NewScope()
	scope.AddInclude(host)
	s := NewServer(core.NewTrafficStore(), scope)
	s.WithSender(sender.NewSender(sender.DefaultSenderConfig()))

	req := repeaterSendReq{
		Target:  fmt.Sprintf("%s:%d", host, port),
		Request: "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n",
	}
	reqBody, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	s.handleRepeaterSend(rec, httptest.NewRequest(http.MethodPost, "/api/repeater/send", bytes.NewReader(reqBody)))

	if rec.Code != http.StatusOK {
		t.Fatalf("send: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp repeaterSendResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode send response: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(resp.ResponseB64)
	if err != nil {
		t.Fatalf("response_b64 is not valid base64: %v", err)
	}
	// The target adds its own Date/Content-Length headers, so the exact body is a suffix of the
	// full response — what matters is that the body bytes survive byte-for-byte, headers included.
	if !bytes.HasSuffix(got, body) {
		t.Fatalf("response_b64 round-trip = %q, want it to end with the exact body %q", got, body)
	}
}
