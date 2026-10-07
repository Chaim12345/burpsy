package web

import (
	"fmt"
	"sync/atomic"
	"testing"
)

// A pooled capture against a real token-issuing origin sends exactly one request per attempt: the
// origin's own hit counter must equal the capture's attempts, and every token is collected. Counted
// at the SERVER, because a pool that retried or double-sent a request would still report a clean
// Total — the duplicate is only visible from the side that received it. (Grew out of a debugging
// probe, dbgpool3_test.go, that logged hits beside attempts and asserted nothing.)
func TestAPooledCaptureSendsExactlyOneRequestPerAttempt(t *testing.T) {
	host, port, hits := tokenServer(t, func(n int) string {
		return fmt.Sprintf("Set-Cookie: SESSIONID=tok-%d\r\n", n)
	})
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
		t.Errorf("collected %d of 12 tokens", final.Total)
	}
	if got := atomic.LoadInt64(hits); got != int64(final.Attempts) {
		t.Errorf("the origin was hit %d times for %d attempts: the pool sent a request it did not count, or counted one it did not send", got, final.Attempts)
	}
}
