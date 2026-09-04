package intruder

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/httputil"

	"go.uber.org/zap"
)

func testLogger() *zap.Logger {
	return zap.NewNop()
}

// TestRunSendsOverPlainHTTP starts a local HTTP server and drives a real
// intruder attack against it, verifying status parsing and result delivery.
// testSend is a plain dialling send, used to exercise the engine's own mechanics (splicing,
// concurrency, cancellation) without involving the scope chokepoint.
//
// The engine deliberately has no built-in way out any more: it used to dial targets itself with no
// scope check, which made `burpsy intruder run` ignore -scope-include entirely. Authorisation is
// asserted where the gate actually lives — see cmd/burpsy/cli_scope_test.go, which proves an
// out-of-scope target receives nothing. Here it would only be testing the stub.
func testSend(t *testing.T) AttackSendFunc {
	t.Helper()
	return func(ctx context.Context, host string, port uint16, useTLS bool, raw []byte) ([]byte, error) {
		d := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(dl)
		} else {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		}
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-ctx.Done():
				conn.Close()
			case <-stop:
			}
		}()
		if _, err := conn.Write(raw); err != nil {
			return nil, err
		}
		return httputil.ReadHTTPResponse(conn)
	}
}

// The new invariant: an engine with no authorised way out refuses rather than falling back to
// dialling directly, which is exactly the defect the injected send replaced.
func TestAnIntruderWithNoAuthorisedSenderRefusesToSend(t *testing.T) {
	intr := NewIntruder(testLogger())
	results, err := intr.Run(context.Background(),
		"GET /?q=\u00a7x\u00a7 HTTP/1.1\r\nHost: h\r\n\r\n",
		"127.0.0.1", 1, false, []string{"a"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	n := 0
	for res := range results {
		n++
		if res.Error == nil {
			t.Error("a payload reported success with no authorised sender wired")
		}
	}
	if n == 0 {
		t.Fatal("no results at all; the refusal must be reported per payload, not silently dropped")
	}
}

func TestRunSendsOverPlainHTTP(t *testing.T) {
	var mu sync.Mutex
	received := make([]string, 0)
	srv := &http.Server{Addr: "127.0.0.1:0"}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			received = append(received, r.URL.Query().Get("q"))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		}))
	}()
	_ = srv

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portU64, _ := strconv.ParseUint(portStr, 10, 16)
	port := uint16(portU64)

	intr := NewIntruder(testLogger()).
		WithConfig(&AttackConfig{MaxConcurrency: 4, Timeout: 5 * time.Second}).
		WithSend(testSend(t))

	base := "GET /search?q=§test§ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
	payloads := []string{"one", "two", "three"}
	results, err := intr.Run(context.Background(), base, "127.0.0.1", port, false, payloads, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	count := 0
	for res := range results {
		count++
		if res.Error != nil {
			t.Errorf("result error: %v", res.Error)
		}
		if res.StatusCode != 200 {
			t.Errorf("status = %d, want 200", res.StatusCode)
		}
		if res.Payload == "" {
			t.Error("result payload empty")
		}
	}
	if count != len(payloads) {
		t.Errorf("results = %d, want %d", count, len(payloads))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != len(payloads) {
		t.Errorf("server received %d requests, want %d", len(received), len(payloads))
	}
	for _, p := range payloads {
		found := false
		for _, r := range received {
			if r == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("server never saw payload %q in %v", p, received)
		}
	}
}

func TestInjectPayloadMarkers(t *testing.T) {
	intr := NewIntruder(testLogger())
	base := "GET /search?q=§x§ HTTP/1.1\r\nHost: h\r\n\r\n"
	got := intr.injectPayload(base, nil, "boom")
	if !strings.Contains(got, "q=boom") {
		t.Errorf("marker not replaced: %q", got)
	}
	if strings.Contains(got, "§") {
		t.Errorf("markers left in request: %q", got)
	}
}

func TestIntruderStopCancelsRunningAttack(t *testing.T) {
	// Regression for M9/H2/H3: Stop() used to only flip the status string, so a
	// run blocked on the caller's never-cancelled context kept going, and the
	// eventual cancel could hit a closed channel. Stop now cancels the derived
	// runCtx, the driver drains workers via wg.Wait(), and the channel closes
	// cleanly (no send-on-closed-channel panic).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	payloads := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		payloads = append(payloads, fmt.Sprintf("p%d", i))
	}
	base := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"

	intr := NewIntruder(testLogger()).WithSend(testSend(t))
	intr.WithConfig(&AttackConfig{MaxConcurrency: 8, Timeout: 2 * time.Second})

	results, err := intr.Run(context.Background(), base, host, uint16(port), false, payloads, []int{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Stop after a short delay while workers are in flight.
	go func() {
		time.Sleep(20 * time.Millisecond)
		intr.Stop()
	}()
	// Drain. Any send-on-closed-channel would panic (crashing the test); this
	// confirms the driver waited for all workers before closing.
	got := 0
	for range results {
		got++
	}
	if got == 0 {
		t.Fatalf("drained 0 results — run ended before doing any work")
	}
	if st := intr.GetProgress().Status; st != "stopped" {
		t.Fatalf("status = %q, want stopped", st)
	}
	// A second Stop must be safe (no-op) once the run has finished.
	intr.Stop()
}
