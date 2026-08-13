package sender

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// rawServer starts a plaintext TCP listener on 127.0.0.1 and runs handle once per accepted
// connection, for the tests below that need control over exact bytes and connection lifecycle that
// net/http's own test server actively prevents — a response carrying both a Content-Length and a
// chunked Transfer-Encoding, or a connection that closes mid-batch, being exactly the shapes net/http
// will not let a handler produce.
func rawServer(t *testing.T, handle func(conn net.Conn)) (host string, port uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go handle(conn)
		}
	}()
	host, port, err = hostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("listener address: %v", err)
	}
	return host, port
}

// readRequestHeads consumes n bodyless request heads off br — every raw request this file sends is a
// GET with no body, so "until the blank line" is the whole request. It reports whether all n were
// read. A fixture running in its own goroutine must never call t.Fatalf itself (only the goroutine
// running the test may call that), so a short read here just stops the handler; the client-side
// assertions are what fail the test, from the goroutine that is allowed to fail it.
func readRequestHeads(br *bufio.Reader, n int) bool {
	for range n {
		head := ""
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return false
			}
			head += line
			if strings.HasSuffix(head, "\r\n\r\n") {
				break
			}
		}
	}
	return true
}

// SendPipelined reads two Content-Length responses off one socket, in the order they were written,
// which is the ordinary case a smuggling check's comparison baseline needs: no disagreement, no
// ambiguity, just two exchanges sharing a connection.
func TestSendPipelinedReadsTwoContentLengthResponsesBackToBackInOrder(t *testing.T) {
	host, port := rawServer(t, func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		if !readRequestHeads(br, 2) {
			return
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst"))
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond"))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raws := [][]byte{
		[]byte("GET /one HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
		[]byte("GET /two HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
	}
	exchanges, err := NewSender(DefaultSenderConfig()).SendPipelined(ctx, host, port, false, raws)
	if err != nil {
		t.Fatalf("SendPipelined: %v", err)
	}
	if len(exchanges) != 2 {
		t.Fatalf("got %d exchanges, want 2", len(exchanges))
	}

	if exchanges[0].ReadErr != nil || !exchanges[0].ResponseComplete {
		t.Fatalf("exchange 0: ReadErr=%v complete=%v, want nil/true", exchanges[0].ReadErr, exchanges[0].ResponseComplete)
	}
	if exchanges[0].Framing != framingContentLength {
		t.Errorf("exchange 0 framing = %q, want %q", exchanges[0].Framing, framingContentLength)
	}
	if !strings.Contains(string(exchanges[0].Response), "first") {
		t.Errorf("exchange 0 response missing its body: %q", exchanges[0].Response)
	}

	if exchanges[1].ReadErr != nil || !exchanges[1].ResponseComplete {
		t.Fatalf("exchange 1: ReadErr=%v complete=%v, want nil/true", exchanges[1].ReadErr, exchanges[1].ResponseComplete)
	}
	if exchanges[1].Framing != framingContentLength {
		t.Errorf("exchange 1 framing = %q, want %q", exchanges[1].Framing, framingContentLength)
	}
	if !strings.Contains(string(exchanges[1].Response), "second") {
		t.Errorf("exchange 1 response missing its body: %q", exchanges[1].Response)
	}
}

// SendPipelined names framingChunked for a chunked response and framingContentLength for the
// Content-Length response that follows it on the same socket, proving the framing decision is made
// per exchange rather than sticking to whatever the first response used.
func TestSendPipelinedNamesChunkedFramingBeforeAContentLengthResponseOnTheSameSocket(t *testing.T) {
	host, port := rawServer(t, func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		if !readRequestHeads(br, 2) {
			return
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raws := [][]byte{
		[]byte("GET /one HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
		[]byte("GET /two HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
	}
	exchanges, err := NewSender(DefaultSenderConfig()).SendPipelined(ctx, host, port, false, raws)
	if err != nil {
		t.Fatalf("SendPipelined: %v", err)
	}
	if len(exchanges) != 2 {
		t.Fatalf("got %d exchanges, want 2", len(exchanges))
	}

	if exchanges[0].ReadErr != nil || !exchanges[0].ResponseComplete {
		t.Fatalf("exchange 0: ReadErr=%v complete=%v, want nil/true", exchanges[0].ReadErr, exchanges[0].ResponseComplete)
	}
	if exchanges[0].Framing != framingChunked {
		t.Errorf("exchange 0 framing = %q, want %q", exchanges[0].Framing, framingChunked)
	}
	if !strings.Contains(string(exchanges[0].Response), "hello") {
		t.Errorf("exchange 0 response missing its chunked body: %q", exchanges[0].Response)
	}

	if exchanges[1].ReadErr != nil || !exchanges[1].ResponseComplete {
		t.Fatalf("exchange 1: ReadErr=%v complete=%v, want nil/true", exchanges[1].ReadErr, exchanges[1].ResponseComplete)
	}
	if exchanges[1].Framing != framingContentLength {
		t.Errorf("exchange 1 framing = %q, want %q", exchanges[1].Framing, framingContentLength)
	}
	if !strings.Contains(string(exchanges[1].Response), "done") {
		t.Errorf("exchange 1 response missing its body: %q", exchanges[1].Response)
	}
}

// A response naming both Content-Length and a chunked Transfer-Encoding is the disagreement this
// whole primitive exists to surface: RFC 7230 §3.3.3 gives chunked precedence, and Framing must say
// so rather than silently trusting whichever header a naive reader checked first. The Content-Length
// here also lies (999, far larger than the real chunked body), so honouring it instead would either
// hang waiting for bytes that never come or read far past the real response — proof that the
// precedence is not just a label but the thing that made this read actually succeed.
func TestSendPipelinedHonoursChunkedFramingOverContentLengthWhenBothHeadersArePresent(t *testing.T) {
	host, port := rawServer(t, func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		if !readRequestHeads(br, 1) {
			return
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raws := [][]byte{[]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")}
	exchanges, err := NewSender(DefaultSenderConfig()).SendPipelined(ctx, host, port, false, raws)
	if err != nil {
		t.Fatalf("SendPipelined: %v", err)
	}
	if len(exchanges) != 1 {
		t.Fatalf("got %d exchanges, want 1", len(exchanges))
	}

	if exchanges[0].ReadErr != nil {
		t.Fatalf("ReadErr = %v, want nil: honouring chunked framing must read this response cleanly despite the lying Content-Length", exchanges[0].ReadErr)
	}
	if !exchanges[0].ResponseComplete {
		t.Fatalf("ResponseComplete = false, want true")
	}
	if exchanges[0].Framing != framingChunked {
		t.Errorf("Framing = %q, want %q: the Content-Length header must not silently win the disagreement", exchanges[0].Framing, framingChunked)
	}
	if !strings.Contains(string(exchanges[0].Response), "hello") {
		t.Errorf("response missing its chunked body: %q", exchanges[0].Response)
	}
}

// SendKeepAlive surfaces a ReadErr and ResponseComplete=false for the request a peer never answers,
// rather than fabricating an empty success — the case that matters for a desync check, where the
// second request's fate on a reused connection is the evidence.
func TestSendKeepAliveSurfacesAReadErrWhenTheServerClosesAfterTheFirstResponse(t *testing.T) {
	host, port := rawServer(t, func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		if !readRequestHeads(br, 1) {
			return
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		// Deliberately returns here without reading the second request: closing now, mid-batch, is
		// the scenario under test.
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raws := [][]byte{
		[]byte("GET /one HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
		[]byte("GET /two HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
	}
	exchanges, err := NewSender(DefaultSenderConfig()).SendKeepAlive(ctx, host, port, false, raws)
	if err != nil {
		t.Fatalf("SendKeepAlive: %v", err)
	}
	if len(exchanges) != 2 {
		t.Fatalf("got %d exchanges, want 2", len(exchanges))
	}

	if exchanges[0].ReadErr != nil || !exchanges[0].ResponseComplete {
		t.Fatalf("exchange 0: ReadErr=%v complete=%v, want nil/true", exchanges[0].ReadErr, exchanges[0].ResponseComplete)
	}
	if !strings.Contains(string(exchanges[0].Response), "ok") {
		t.Errorf("exchange 0 response missing its body: %q", exchanges[0].Response)
	}

	if exchanges[1].ReadErr == nil {
		t.Fatalf("exchange 1: ReadErr = nil, want an error naming the closed connection rather than a fabricated success")
	}
	if exchanges[1].ResponseComplete {
		t.Errorf("exchange 1: ResponseComplete = true, want false: the server never answered this request")
	}
}

// TimedRead reports timedOut=true with a nil error when a peer accepts a request and stays silent —
// the CL.TE/TE.CL timing signal a socket that goes quiet is supposed to produce, distinct from a
// transport error.
func TestTimedReadReportsATimeoutRatherThanAnErrorWhenTheServerNeverReplies(t *testing.T) {
	host, port := rawServer(t, func(conn net.Conn) {
		// Deliberately does nothing: accepted, never read, never answered and never closed from this
		// side — rawServer's cleanup closes it once the test ends.
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	response, timedOut, err := NewSender(DefaultSenderConfig()).TimedRead(ctx, host, port, false, raw, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("TimedRead: %v", err)
	}
	if !timedOut {
		t.Fatalf("timedOut = false, want true: the server never sent a byte back")
	}
	if len(response) != 0 {
		t.Errorf("response = %q, want empty: nothing was ever sent back", response)
	}
}
