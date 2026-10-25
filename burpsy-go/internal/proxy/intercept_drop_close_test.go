package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"go.uber.org/zap"
)

// Burp drop semantics (xrq5 follow-up, integrator ruling "drops vanish, period"): an
// operator's drop of a held plaintext request closes the connection without a byte.
// The tunnel path has always done this; the plaintext path answered a fabricated 403 —
// bytes no server sent — under a neighbor comment that already stated "a drop closes
// the connection without reaching upstream".

func TestAHeldRequestDroppedByTheOperatorClosesSilently(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	ohost, oportStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	oport, _ := strconv.Atoi(oportStr)

	// An empty rule list on an active list intercepts every request, as in
	// egress_after_intercept_test.go.
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScope()).
		WithIntercept(engine).
		WithLogger(zap.NewNop()))

	// The operator: drop whatever is held.
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			for _, held := range engine.Held() {
				if held.Direction != intercept.DirectionRequest {
					continue
				}
				_ = engine.Drop(held.ID, "operator drop")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	req := "GET http://" + ohost + ":" + strconv.Itoa(oport) + "/ HTTP/1.1\r\n" +
		"Host: " + ohost + ":" + strconv.Itoa(oport) + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("a dropped request must vanish - the connection closes without a byte; read %d bytes (%q), err %v", n, buf[:n], err)
	}
	if originHits.Load() != 0 {
		t.Fatalf("dropped request reached the origin %d times", originHits.Load())
	}
}
