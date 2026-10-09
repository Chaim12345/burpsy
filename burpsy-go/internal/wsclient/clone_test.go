package wsclient

import (
	"strings"
	"testing"
)

func TestCloneHandshakeKeepsTheClientsHeadersAndRenewsOnlyTheNonce(t *testing.T) {
	orig := "GET http://chat.test:8080/ws?room=1 HTTP/1.1\r\nHost: chat.test:8080\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nCookie: s=1\r\nAuthorization: Bearer t\r\nSec-WebSocket-Protocol: chat\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	got, err := CloneHandshake([]byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if !strings.HasPrefix(s, "GET /ws?room=1 HTTP/1.1\r\n") {
		t.Errorf("the absolute-form target was not made origin-form: %q", strings.SplitN(s, "\r\n", 2)[0])
	}
	for _, want := range []string{"Host: chat.test:8080\r\n", "Cookie: s=1\r\n", "Authorization: Bearer t\r\n", "Sec-WebSocket-Protocol: chat\r\n", "Sec-WebSocket-Version: 13\r\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("clone lost %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "dGhlIHNhbXBsZSBub25jZQ==") || !strings.Contains(s, "Sec-WebSocket-Key: ") {
		t.Errorf("the nonce was replayed or dropped:\n%s", s)
	}
	if strings.Contains(strings.ToLower(s), "sec-websocket-extensions") {
		t.Errorf("the extension offer survived:\n%s", s)
	}
	if !strings.HasSuffix(s, "\r\n\r\n") {
		t.Error("the clone's head is not terminated")
	}
}

func TestCloneHandshakeRefusesWhatIsNotAnUpgrade(t *testing.T) {
	for _, raw := range []string{
		"POST /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\n\r\n",
		"GET /ws HTTP/1.1\r\nHost: a\r\n\r\n",
		"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n",
	} {
		if _, err := CloneHandshake([]byte(raw)); err == nil {
			t.Errorf("CloneHandshake accepted %q", raw)
		}
	}
}

// Review fix: a head-only replay must not keep framing headers that announce a body.
func TestCloneHandshakeDropsBodyFramingHeaders(t *testing.T) {
	orig := "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Content-Length: 5\r\nTransfer-Encoding: chunked\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\nhello"
	got, err := CloneHandshake([]byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(got))
	if strings.Contains(s, "content-length") || strings.Contains(s, "transfer-encoding") || strings.Contains(s, "hello") {
		t.Errorf("the clone kept body framing or the body:\n%s", got)
	}
}
