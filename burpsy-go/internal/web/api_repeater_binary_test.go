package web

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// burpsy-react-ui-ytkk: a Repeater send carrying request_base64 transmits the exact body bytes,
// including non-UTF-8 ones (a protobuf body) that a JSON `request` string would have mangled.
func TestRepeaterSendBase64TransmitsExactBytes(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	s := newTestServer()
	s.WithSender(sender.NewSender(sender.DefaultSenderConfig()))
	s.scope.AddInclude("*")

	// A protobuf body: field 1 varint 150, field 2 string "testing" — byte 0x96 is not valid UTF-8.
	body := []byte{0x08, 0x96, 0x01, 0x12, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g'}
	raw := []byte(fmt.Sprintf("POST /x HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/x-protobuf\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", host, port, len(body)))
	raw = append(raw, body...)

	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":         srv.URL,
		"protocol":       "http",
		"request_base64": base64.StdEncoding.EncodeToString(raw),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("send = %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(got, body) {
		t.Errorf("target received %x, want the exact protobuf body %x", got, body)
	}
}
