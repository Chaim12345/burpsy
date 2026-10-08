package web

import (
	"fmt"
	"sync/atomic"
	"testing"
)

func TestDebugRealTokenServerConcurrent(t *testing.T) {
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
	t.Logf("hits=%d total=%d attempts=%d", atomic.LoadInt64(hits), final.Total, final.Attempts)
}
