package sender

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// overCapServer answers every request on a connection with a body httputil.MaxResponseBodyBytes+16
// long, framed as framing says. The 16 bytes past the cap are written after a pause, so when the
// sender stops at the cap nothing past it is buffered yet: the only thing between that connection
// and the pool is the sender knowing the body was cut (burpsy-react-ui-h1-cap-silent).
func overCapServer(t *testing.T, framing string) (host string, port uint16, conns *atomic.Int64) {
	t.Helper()
	conns = &atomic.Int64{}
	payload := bytes.Repeat([]byte("a"), httputil.MaxResponseBodyBytes)
	tail := strings.Repeat("z", 16)
	host, port = rawServer(t, func(conn net.Conn) {
		conns.Add(1)
		defer conn.Close()
		br := bufio.NewReader(conn)
		for readRequestHeads(br, 1) {
			switch framing {
			case "content-length":
				fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(payload)+len(tail))
				_, _ = conn.Write(payload)
				time.Sleep(300 * time.Millisecond)
				_, _ = conn.Write([]byte(tail))
			case "chunked":
				fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n", len(payload))
				_, _ = conn.Write(payload)
				_, _ = conn.Write([]byte("\r\n"))
				time.Sleep(300 * time.Millisecond)
				fmt.Fprintf(conn, "%x\r\n%s\r\n0\r\n\r\n", len(tail), tail)
			}
		}
	})
	return host, port, conns
}

func TestAnHTTP1BodyCutAtTheCapIsNotedAndItsConnectionNotReused(t *testing.T) {
	for _, framing := range []string{"content-length", "chunked"} {
		t.Run(framing, func(t *testing.T) {
			host, port, conns := overCapServer(t, framing)
			s := senderWithHTTP(t, true, false)
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				resp, outcome, err := s.SendRawOutcome(ctx, host, port, false, rawGet(host, port), ProtocolPreferenceHTTP1)
				cancel()
				if err != nil {
					t.Fatalf("send %d: %v", i, err)
				}
				if !strings.HasPrefix(string(resp), "HTTP/1.1 200 OK\r\n") {
					t.Fatalf("send %d: response does not start with the origin's head: %.80q", i, resp)
				}
				if bytes.Contains(resp, []byte("zzzz")) {
					t.Fatalf("send %d: bytes past the cap are in the response", i)
				}
				if !strings.Contains(outcome.Note, "byte cap and was cut there") {
					t.Fatalf("send %d: the cut body is not noted; Note = %q", i, outcome.Note)
				}
			}
			if got := conns.Load(); got != 2 {
				t.Fatalf("%d connection(s) for 2 sends, want 2: a connection whose body was cut at the cap still carries the rest of it", got)
			}
		})
	}
}
