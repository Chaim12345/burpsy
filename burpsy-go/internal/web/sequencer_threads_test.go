package web

import (
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Burp's "Number of threads" for live capture (burpsy-react-ui-9t1): the maximum concurrent
// requests the capture makes. 1 is the historical sequential capture; a wider pool trades
// per-request pacing for wall-clock speed, and the operator opts into that.

// concurrentOrigin counts how many requests overlap: in-flight when a new one arrives.
func concurrentOrigin(t *testing.T) (host string, port uint16, hits *atomic.Int64, maxInFlight *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var inFlight, maxSeen, hitsN atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// The token is stamped at ACCEPT time, not at write time: overlapping connections
			// would otherwise all read the counter after their sleeps and stamp the same
			// number — a fixture race that looks exactly like the duplicate-claim defect the
			// test exists to catch.
			n := hitsN.Add(1)
			cur := inFlight.Add(1)
			for {
				old := maxSeen.Load()
				if cur <= old || maxSeen.CompareAndSwap(old, cur) {
					break
				}
			}
			go func(c net.Conn, ordinal int64) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				time.Sleep(30 * time.Millisecond) // hold the connection: overlap is observable
				// The cookie rides a real header: the token location extracts from response
				// headers, so a body string would be a miss for every request.
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nSet-Cookie: SESSIONID=tok-%d\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", ordinal)
				inFlight.Add(-1)
			}(conn, n)
		}
	}()
	hp, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p64, _ := strconv.ParseUint(portStr, 10, 16)
	return hp, uint16(p64), &hitsN, &maxSeen
}

// Threads=1 stays sequential: overlapping requests never exceed one.
func TestACaptureWithOneThreadNeverOverlaps(t *testing.T) {
	host, port, _, maxInFlight := concurrentOrigin(t)
	s := captureServer(t, host, port)
	view := startCapture(t, s, map[string]any{
		"target":   fmt.Sprintf("http://%s:%d", host, port),
		"request":  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port),
		"count":    8,
		"threads":  1,
		"location": map[string]any{"kind": "cookie", "name": "SESSIONID"},
	})
	awaitCapture(t, s, view.ID)
	if got := maxInFlight.Load(); got > 1 {
		t.Errorf("a 1-thread capture reached %d concurrent requests; sequential must stay at 1", got)
	}
}

// Threads=4 overlaps: the pool is real, and the capture still collects every token.
func TestACaptureWithFourThreadsRunsConcurrently(t *testing.T) {
	host, port, _, maxInFlight := concurrentOrigin(t)
	s := captureServer(t, host, port)
	view := startCapture(t, s, map[string]any{
		"target":   fmt.Sprintf("http://%s:%d", host, port),
		"request":  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port),
		"count":    12,
		"threads":  4,
		"location": map[string]any{"kind": "cookie", "name": "SESSIONID"},
	})
	final := awaitCapture(t, s, view.ID)
	if final.Total != 12 {
		t.Errorf("the pooled capture collected %d of 12 tokens; concurrency must not lose tokens", final.Total)
	}
	if got := maxInFlight.Load(); got < 2 {
		t.Errorf("a 4-thread capture never overlapped (max in flight %d); the pool is not concurrent", got)
	}
}

// The bound: a pool wider than the cap is refused rather than silently clamped — a panel that
// says 64 and a server that runs 32 disagree about what was tested.
func TestACaptureRefusesAThreadCountOverTheCap(t *testing.T) {
	host, port, _, _ := concurrentOrigin(t)
	s := captureServer(t, host, port)
	rec := postJSON(t, s, "/api/sequencer/capture", map[string]any{
		"target":   fmt.Sprintf("http://%s:%d", host, port),
		"request":  "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"count":    4,
		"threads":  33,
		"location": map[string]any{"kind": "cookie", "name": "SESSIONID"},
	})
	if rec.Code == 0 || (rec.Code >= 200 && rec.Code < 300) {
		t.Errorf("threads=33 answered %d, want 4xx — the cap must be visible to the operator", rec.Code)
	}
}

// No two workers hold the same ordinal: with a wide pool against a fast origin, every collected
// token must be distinct. Duplicate claims would show up as duplicate tokens.
func TestAPooledCaptureNeverClaimsTheSameOrdinalTwice(t *testing.T) {
	host, port, _, _ := concurrentOrigin(t)
	s := captureServer(t, host, port)
	view := startCapture(t, s, map[string]any{
		"target":   fmt.Sprintf("http://%s:%d", host, port),
		"request":  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port),
		"count":    16,
		"threads":  8,
		"location": map[string]any{"kind": "cookie", "name": "SESSIONID"},
	})
	final := awaitCapture(t, s, view.ID)
	if final.Total != 16 {
		t.Errorf("16 claims produced %d tokens; duplicate or lost ordinals under the pool", final.Total)
	}
	tokens := map[string]bool{}
	for _, tok := range final.Tokens {
		if tokens[tok] {
			t.Errorf("token %q collected twice — two workers held one ordinal", tok)
		}
		tokens[tok] = true
	}
}
