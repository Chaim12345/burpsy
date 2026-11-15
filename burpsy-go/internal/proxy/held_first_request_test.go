package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// A first request that waited (an intercept hold) can outlast the origin's idle timeout. The
// upstream dialled at CONNECT is then gone, and the request must go out on a fresh connection
// rather than into the closed socket.
func TestAFirstRequestThatWaitedSurvivesTheOriginsIdleClose(t *testing.T) {
	cert, _ := generateSelfSigned(t, t.TempDir())
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for n := 0; ; n++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn, first bool) {
				defer c.Close()
				if first { // the idle timeout: handshake, then close before any request
					_ = c.(*tls.Conn).Handshake()
					time.Sleep(100 * time.Millisecond)
					return
				}
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}(c, n == 0)
		}
	}()
	origin := ln.Addr().String()
	conn, br := openReusedTunnel(t, origin)
	time.Sleep(upstreamFreshFor + 200*time.Millisecond) // the hold
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /held HTTP/1.1\r\nHost: %s\r\n\r\n", origin)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("the held first request got no answer: %v", err)
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("the held first request: %d %q, want the origin's 200", resp.StatusCode, body)
	}
}
