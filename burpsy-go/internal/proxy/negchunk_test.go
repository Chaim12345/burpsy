package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// hostileChunkOrigin answers every request with a chunked response whose first chunk size is
// size, the shape that used to reach make([]byte, -1) in httputil.ReadResponseBody and panic.
func hostileChunkOrigin(t *testing.T, size string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%s\r\nabcd\r\n0\r\n\r\n", size)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func proxyGet(t *testing.T, proxyAddr, origin, path string) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, origin)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got bytes.Buffer
	_, _ = got.ReadFrom(conn)
	return got.String()
}

// TestAHostileChunkSizeDoesNotPanicTheProxy is burpsy-react-ui-negchunk-panic end to end: an origin
// answering chunk size "-1" (and the other shapes the strict parser refuses) is a refused response,
// not a panic. Before the fix this test killed the test binary — the relay goroutine had no recover,
// so the panic took the process. The panic counter is the second witness: the backstop recover must
// not be what saved it.
func TestAHostileChunkSizeDoesNotPanicTheProxy(t *testing.T) {
	store := core.NewTrafficStore()
	srv, proxyAddr := startPlainProxy(t, store, testScope())
	for _, size := range []string{"-1", "+1", "-8000000000000000", "1000000000000000", "zz"} {
		got := proxyGet(t, proxyAddr, hostileChunkOrigin(t, size), "/hostile")
		if strings.Contains(got, "abcd") {
			t.Errorf("chunk size %q: the refused body reached the client: %q", size, got)
		}
	}
	if n := srv.ConnectionPanics(); n != 0 {
		t.Fatalf("%d relay goroutines panicked on hostile chunk sizes; the parser must refuse them", n)
	}
	// The proxy is still serving: a well-formed chunked answer goes through after them.
	good := hostileChunkOrigin(t, "4")
	if got := proxyGet(t, proxyAddr, good, "/fine"); !strings.Contains(got, "abcd") {
		t.Fatalf("a well-formed response after the hostile ones did not get through: %q", got)
	}
}

// TestRecoverConnectionContainsARelayPanic: the backstop at the root of every client connection
// turns a panic into one closed connection and a count, rather than a dead process.
func TestRecoverConnectionContainsARelayPanic(t *testing.T) {
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).WithLogger(zap.NewNop()))
	client, server := net.Pipe()
	defer client.Close()
	func() {
		defer server.Close()
		defer srv.recoverConnection(server)
		panic("relay bug a peer's bytes reached")
	}()
	if n := srv.ConnectionPanics(); n != 1 {
		t.Fatalf("ConnectionPanics = %d, want 1", n)
	}
	// The deferred Close ran after the recover: the client end sees the connection end.
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection stayed open after a contained panic")
	}
}
