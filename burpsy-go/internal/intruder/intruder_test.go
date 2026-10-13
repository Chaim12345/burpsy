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

// gatedServer answers the first `free` requests at once and holds every later one open until the
// client goes away or the test ends. It makes "the attack is still in flight" a fact the test
// establishes, rather than a bet that the run outlasts a sleep: a 500-request run against a local
// server finishes in tens of milliseconds, so the old 20ms sleep before Stop lost to any scheduler
// stall of that size and the run reported "completed" (CI run 38360049157).
func gatedServer(t *testing.T, free int) (host string, port uint16, arrived <-chan struct{}) {
	t.Helper()
	release := make(chan struct{})
	arrivedCh := make(chan struct{}, 1024)
	var mu sync.Mutex
	served := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case arrivedCh <- struct{}{}:
		default:
		}
		mu.Lock()
		served++
		n := served
		mu.Unlock()
		if n > free {
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		fmt.Fprint(w, "ok")
	}))
	// Cleanups run last-in first-out: release the held handlers before Close waits on them.
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(release) })
	u, _ := url.Parse(ts.URL)
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), uint16(p), arrivedCh
}

// drainWithin collects every result until the channel closes, failing if the run does not end in
// time: a Stop that does not actually halt the run would leave 500 requests to time out one batch
// after another.
func drainWithin(t *testing.T, results <-chan *AttackResult, first int, d time.Duration) int {
	t.Helper()
	got := first
	deadline := time.After(d)
	for {
		select {
		case _, ok := <-results:
			if !ok {
				return got
			}
			got++
		case <-deadline:
			t.Fatalf("run still open %v after Stop (drained %d results): Stop did not halt it", d, got)
		}
	}
}

func TestIntruderStopCancelsRunningAttack(t *testing.T) {
	// Regression for M9/H2/H3: Stop() used to only flip the status string, so a
	// run blocked on the caller's never-cancelled context kept going, and the
	// eventual cancel could hit a closed channel. Stop now cancels the derived
	// runCtx, the driver drains workers via wg.Wait(), and the channel closes
	// cleanly (no send-on-closed-channel panic).
	const total, free = 500, 8
	host, port, _ := gatedServer(t, free)

	payloads := make([]string, 0, total)
	for i := 0; i < total; i++ {
		payloads = append(payloads, fmt.Sprintf("p%d", i))
	}
	base := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"

	intr := NewIntruder(testLogger()).WithSend(testSend(t))
	// The per-request timeout is far beyond the drain deadline below, so only Stop can end the
	// held requests in time.
	intr.WithConfig(&AttackConfig{MaxConcurrency: 8, Timeout: 2 * time.Second})

	results, err := intr.Run(context.Background(), base, host, port, false, payloads, []int{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Wait for the answered requests to come back: the run has demonstrably done work, and every
	// later request is held open by the server, so the run cannot finish on its own.
	got := 0
	for got < free {
		select {
		case _, ok := <-results:
			if !ok {
				t.Fatalf("run ended after %d results, before Stop", got)
			}
			got++
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of the %d answered requests came back", got, free)
		}
	}
	if st := intr.GetProgress().Status; st != "running" {
		t.Fatalf("status before Stop = %q, want running", st)
	}
	intr.Stop()
	// Drain. Any send-on-closed-channel would panic (crashing the test); this
	// confirms the driver waited for all workers before closing.
	got = drainWithin(t, results, got, 10*time.Second)
	prog := intr.GetProgress()
	if prog.Status != "stopped" {
		t.Fatalf("status = %q, want stopped", prog.Status)
	}
	if prog.Completed >= total {
		t.Fatalf("completed %d of %d payloads: Stop did not cut the attack short", prog.Completed, total)
	}
	// A second Stop must be safe (no-op) once the run has finished.
	intr.Stop()
	if st := intr.GetProgress().Status; st != "stopped" {
		t.Fatalf("status after second Stop = %q, want stopped", st)
	}
}

// A Stop that lands after the driver dispatched the last payload, while those workers are still
// in flight, halted the attack all the same. The driver used to overwrite Stop's "stopped" with
// "completed" once wg.Wait returned, presenting a cut-short attack as an exhausted one.
func TestIntruderStopAfterLastDispatchReportsStopped(t *testing.T) {
	const n = 4
	host, port, arrived := gatedServer(t, 0) // hold every request
	payloads := []string{"a", "b", "c", "d"}
	base := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"

	intr := NewIntruder(testLogger()).WithSend(testSend(t))
	intr.WithConfig(&AttackConfig{MaxConcurrency: n, Timeout: 2 * time.Second})
	results, err := intr.Run(context.Background(), base, host, port, false, payloads, []int{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// All n requests reaching the server means all n payloads were dispatched: the driver loop is
	// done and sitting in wg.Wait.
	for i := 0; i < n; i++ {
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d requests reached the server", i, n)
		}
	}
	intr.Stop()
	drainWithin(t, results, 0, 10*time.Second)
	if st := intr.GetProgress().Status; st != "stopped" {
		t.Fatalf("status = %q, want stopped: every payload was dispatched but none was answered", st)
	}
}

// Stop on a run that already ended is a no-op: it must not relabel a completed attack.
func TestIntruderStopAfterCompletionKeepsCompleted(t *testing.T) {
	host, port, _ := gatedServer(t, 1<<30) // answer everything
	base := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	intr := NewIntruder(testLogger()).WithSend(testSend(t))
	intr.WithConfig(&AttackConfig{MaxConcurrency: 2, Timeout: 2 * time.Second})
	results, err := intr.Run(context.Background(), base, host, port, false, []string{"a", "b", "c"}, []int{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := drainWithin(t, results, 0, 10*time.Second); got != 3 {
		t.Fatalf("drained %d results, want 3", got)
	}
	if st := intr.GetProgress().Status; st != "completed" {
		t.Fatalf("status = %q, want completed", st)
	}
	intr.Stop()
	if st := intr.GetProgress().Status; st != "completed" {
		t.Fatalf("status after Stop on a finished run = %q, want completed", st)
	}
}
