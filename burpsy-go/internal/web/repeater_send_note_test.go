package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// What the sender did to a send reaches the stored exchange. An origin that answers close-delimited
// (no Content-Length, then closes) makes the sender add "Connection: close" to the next request that
// carries no Connection header; the stored request is the one the operator wrote, so the row's note
// must say so (PR #363 review).
func TestARepeaterSendRecordsWhatTheSenderChanged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nclose-delimited"))
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	s, store := kettledServer("127.0.0.1", "/")
	send := func() core.ExchangeID {
		rec := postJSON(t, s, "/api/repeater/send", map[string]any{
			"target":   fmt.Sprintf("http://127.0.0.1:%d", addr.Port),
			"protocol": "http",
			"request":  fmt.Sprintf("GET /n HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", addr.Port),
			"note":     "tab note",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("send = %d (%s)", rec.Code, rec.Body.String())
		}
		var resp struct {
			ExchangeID core.ExchangeID `json:"exchange_id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.ExchangeID
	}
	first, err := store.GetExchange(send())
	if err != nil {
		t.Fatal(err)
	}
	if first.Notes == nil || *first.Notes != "tab note" {
		t.Fatalf("the first send changed nothing, so its note is the tab's alone: %v", first.Notes)
	}
	second, err := store.GetExchange(send())
	if err != nil {
		t.Fatal(err)
	}
	if second.Notes == nil || !strings.HasPrefix(*second.Notes, "tab note\n\n[burpsy] Connection: close added") {
		t.Fatalf("the stored exchange does not say the sender added Connection: close: %v", second.Notes)
	}
}
