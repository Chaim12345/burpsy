package sender

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestSendRawRefusesAHostileChunkSize is burpsy-react-ui-negchunk-panic on the sender leg (Repeater,
// Intruder and every scanner worker send through it): an origin answering chunk size "-1" used to
// panic the sending goroutine inside httputil.ReadResponseBody. It must come back as an error, with
// no response presented as if it had arrived whole.
func TestSendRawRefusesAHostileChunkSize(t *testing.T) {
	for _, size := range []string{"-1", "+1", "1000000000000000", "0x4"} {
		t.Run(size, func(t *testing.T) {
			host, port := rawServer(t, func(conn net.Conn) {
				defer conn.Close()
				if !readRequestHeads(bufio.NewReader(conn), 1) {
					return
				}
				fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%s\r\nabcd\r\n0\r\n\r\n", size)
			})
			s := NewSender(DefaultSenderConfig())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			raw := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port))
			resp, err := s.SendRaw(ctx, host, port, false, raw)
			if err == nil {
				t.Fatalf("SendRaw accepted chunk size %q: %q", size, resp)
			}
			if !strings.Contains(err.Error(), "bad chunk size") {
				t.Fatalf("the error does not name the fault: %v", err)
			}
		})
	}
}
