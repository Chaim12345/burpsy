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
)

// truncatingListingServer mimics OWASP Juice Shop's serve-index /ftp/ page: it declares a
// Content-Length larger than the body it sends, then - unless the request already asked for it -
// holds the connection open for a keep-alive period before closing, which is what made every
// audit fetch of that page wait seconds for bytes that never come. When the request carries
// "Connection: close" it closes with the body, so the truncation's EOF frames the response
// immediately.
type truncatingListingServer struct {
	addr          string
	hold          time.Duration
	requests      atomic.Int32
	sawClose      atomic.Int32
	body          string
	declaredExtra int
}

func startTruncatingListingServer(t *testing.T, hold time.Duration) *truncatingListingServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &truncatingListingServer{
		addr:          ln.Addr().String(),
		hold:          hold,
		body:          "<!DOCTYPE html><html><head><title>listing directory /ftp/</title></head></html>",
		declaredExtra: 59,
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *truncatingListingServer) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	s.requests.Add(1)
	askedClose := strings.Contains(strings.ToLower(head.String()), "connection: close")
	if askedClose {
		s.sawClose.Add(1)
	}
	declared := len(s.body) + s.declaredExtra
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", declared, s.body)
	if askedClose {
		// The request asked for the close: the body is the end of the stream.
		return
	}
	time.Sleep(s.hold)
}

// A truncated-then-held response teaches the sender to ask for the close next time: the second
// fetch to the same authority carries Connection: close and does not wait out the peer's
// keep-alive hold for the phantom remainder.
func TestACloseDelimitedResponseDowngradesTheNextSendToConnectionClose(t *testing.T) {
	hold := 3 * time.Second
	srv := startTruncatingListingServer(t, hold)
	host, port := mustHostPort(t, srv.addr)

	s := NewSender(DefaultSenderConfig())
	ctx := context.Background()
	raw := []byte("GET /ftp/ HTTP/1.1\r\nHost: " + srv.addr + "\r\n\r\n")

	start := time.Now()
	resp, _, err := s.SendRawOutcome(ctx, host, port, false, raw, ProtocolPreferenceHTTP1)
	first := time.Since(start)
	if err != nil {
		t.Fatalf("first send: %v", err)
	}
	if !bytes.Contains(resp, []byte("listing directory /ftp/")) {
		t.Fatalf("first send lost the partial body: %q", resp)
	}
	if first < hold/2 {
		t.Fatalf("first send should have waited out the hold (%v < %v)", first, hold/2)
	}

	start = time.Now()
	resp, _, err = s.SendRawOutcome(ctx, host, port, false, raw, ProtocolPreferenceHTTP1)
	second := time.Since(start)
	if err != nil {
		t.Fatalf("second send: %v", err)
	}
	if !bytes.Contains(resp, []byte("listing directory /ftp/")) {
		t.Fatalf("second send lost the partial body: %q", resp)
	}
	if srv.sawClose.Load() != 1 {
		t.Fatalf("second request did not ask for the close (sawClose=%d of %d)", srv.sawClose.Load(), srv.requests.Load())
	}
	if second > hold/2 {
		t.Fatalf("second send still waited (%v); want well under the %v hold", second, hold)
	}
}
