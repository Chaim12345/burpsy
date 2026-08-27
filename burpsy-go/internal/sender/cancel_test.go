package sender

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// ---- cancellation reaches the socket (burpsy-react-ui-0c2) -------------------------------------
//
// The claim under test is not "the function returns an error when cancelled" — it did that already,
// eventually, by timing out. The claim is that it returns *promptly*, because the operator cancelled,
// and that it says so.
//
// Every test here therefore asserts on elapsed time against a read timeout deliberately set far
// longer than the test's patience. A regression that removed watchCancel would still produce an
// error, so an assertion that only checked `err != nil` would pass through the bug.

// silentServer accepts one connection, reads the request, and then answers nothing at all — the
// wedged-host case an operator reaches for Cancel over. It stays open until the test finishes, so a
// read against it blocks for exactly as long as something makes it stop.
func silentServer(t *testing.T) (addr string, connected chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	connected = make(chan struct{}, 1)

	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case connected <- struct{}{}:
			default:
			}
			// Hold the connection open, reading and discarding, answering nothing.
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					select {
					case <-done:
						return
					default:
					}
					conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					if _, err := conn.Read(buf); err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), connected
}

// mustHostPort is hostPort (authorised_test.go) with the error turned into a fatal, which is all
// these tests want from it. Named to avoid the package's existing splitAddr.
func mustHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, port, err := hostPort(addr)
	if err != nil {
		t.Fatalf("hostPort(%q): %v", addr, err)
	}
	return host, port
}

// The test that matters. A cancelled context must unblock the read immediately rather than at the
// read timeout, and the error must say the send was cancelled rather than that the target was slow.
func TestCancellingASendUnblocksTheReadImmediately(t *testing.T) {
	addr, connected := silentServer(t)
	host, port := mustHostPort(t, addr)

	s := NewSender(&SenderConfig{})
	// A read bound far longer than this test will wait. If cancellation did not reach the socket this
	// send would block for 30 seconds and the elapsed assertion below would fail — which is exactly
	// what happened before cancel.go existed.
	if err := s.ApplyNetwork(NetworkSettings{Timeouts: TimeoutSettings{ReadMS: 30_000}}); err != nil {
		t.Fatalf("ApplyNetwork: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel once the server has the connection, so the send is genuinely blocked in its read rather
	// than being cancelled during the dial — the dial already honoured the context and would have
	// passed this test for the wrong reason.
	go func() {
		<-connected
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	raw := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	started := time.Now()
	_, err := s.SendRaw(ctx, host, port, false, raw)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("a cancelled send returned no error")
	}
	if elapsed > 5*time.Second {
		t.Errorf("the send took %v to notice cancellation; the read was not unblocked, it timed out. "+
			"That is the bug this test exists for: the operator's Cancel stopped the browser waiting "+
			"while the request continued to the target", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v; it must wrap context.Canceled so callers can tell a cancellation from "+
			"a network failure", err)
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("error = %q; it must say the send was cancelled. Reporting this as a timeout blames "+
			"the target for a decision the operator made, and that text goes into the tool log", err)
	}
}

// A context with no cancellation must not pay for a goroutine, and must still work. context.TODO()
// and context.Background() both reach this path, and both are common in tests and CLI paths.
func TestAnUncancellableContextStillSends(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		conn.Read(buf)
		conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
	}()

	host, port := mustHostPort(t, listener.Addr().String())
	s := NewSender(&SenderConfig{})
	if err := s.ApplyNetwork(NetworkSettings{Timeouts: TimeoutSettings{ReadMS: 5_000}}); err != nil {
		t.Fatalf("ApplyNetwork: %v", err)
	}

	//nolint:staticcheck // Background() deliberately: ctx.Done() is nil, which is the path under test.
	resp, err := s.SendRaw(context.Background(), host, port, false,
		[]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"))
	if err != nil {
		t.Fatalf("an uncancellable context failed to send: %v", err)
	}
	if !strings.Contains(string(resp), "204") {
		t.Errorf("response = %q, want the 204", resp)
	}
}

// A real timeout on a live context must keep being reported as a timeout. Without this, the
// cancellation wording could be applied to every slow target and the distinction would be lost in
// the direction that matters least but is easiest to break.
func TestARealTimeoutIsNotReportedAsACancellation(t *testing.T) {
	addr, _ := silentServer(t)
	host, port := mustHostPort(t, addr)

	s := NewSender(&SenderConfig{})
	// Short enough that the read bound, not the test, ends this.
	if err := s.ApplyNetwork(NetworkSettings{Timeouts: TimeoutSettings{ReadMS: 150}}); err != nil {
		t.Fatalf("ApplyNetwork: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // never fired during the send

	_, err := s.SendRaw(ctx, host, port, false, []byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"))
	if err == nil {
		t.Fatal("a send against a silent server returned no error")
	}
	if errors.Is(err, context.Canceled) {
		t.Errorf("error = %v; nothing cancelled this send, and calling a slow target a cancellation "+
			"is the same class of lie in the other direction", err)
	}
	if strings.Contains(err.Error(), "cancelled") {
		t.Errorf("error = %q, want it to report a timeout", err)
	}
}

// watchCancel's stop function must end its goroutine, and must be safe to call when the context was
// never cancelled. A leaked watcher would fire a past deadline onto a connection a later request is
// using, failing an unrelated read — the reason it is installed per connection rather than per
// request.
func TestStoppingTheWatcherLeavesTheConnectionUsable(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	stop := watchCancel(ctx, client)
	stop()

	// Cancel AFTER stopping. A watcher that ignored its stop channel would set a past deadline here
	// and the read below would fail.
	cancel()
	time.Sleep(20 * time.Millisecond)

	go func() { server.Write([]byte("still working")) }()
	client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read after stop(): %v — the stopped watcher still acted on the connection", err)
	}
	if string(buf[:n]) != "still working" {
		t.Errorf("read %q", buf[:n])
	}
}
