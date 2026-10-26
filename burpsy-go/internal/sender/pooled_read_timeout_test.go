package sender

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Pooled exchanges wait on a connection the peer has every reason to keep open and none to answer:
// the read must carry a deadline of ours, not the peer's. These tests pin the three rules of bead
// 757d: a configured timeouts.read_ms bounds every pooled exchange, a deadline trip discards the
// connection rather than pooling it again, and an operator who set no timeout still gets a bounded
// read. The server answers each connection's first request and then goes silent, which is the
// shape an unbounded read cannot survive.
func startAnswerOnceThenSilentServer(t *testing.T) (addr string, accepted *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cl := &countingListener{Listener: ln}
	// u5jf: the accepted connections are closed at test cleanup, not only the listener, so a
	// peer that holds its end open cannot strand the read goroutine.
	var openMu sync.Mutex
	var open []net.Conn
	t.Cleanup(func() {
		openMu.Lock()
		for _, c := range open {
			c.Close()
		}
		openMu.Unlock()
		cl.Close()
	})
	go func() {
		for {
			conn, err := cl.Accept()
			if err != nil {
				return
			}
			openMu.Lock()
			open = append(open, conn)
			openMu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
				// Nothing after the first answer: the second request on this connection is read
				// and never answered.
				io.Copy(io.Discard, br)
			}(conn)
		}
	}()
	return cl.Addr().String(), &cl.accepted
}

func keepAliveSender(t *testing.T, readMS int) *Sender {
	t.Helper()
	s := NewSender(DefaultSenderConfig())
	n := s.Network()
	n.HTTP1 = &HTTP1Settings{EnableKeepAlive: true}
	n.Timeouts = TimeoutSettings{ReadMS: readMS}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}
	return s
}

const silentProbeReq = "GET /p HTTP/1.1\r\nHost: target.test\r\n\r\n"

func TestAKeptConnectionHonoursTimeoutsReadMS(t *testing.T) {
	addr, accepted := startAnswerOnceThenSilentServer(t)
	host, port := mustHostPort(t, addr)
	s := keepAliveSender(t, 150)

	resp, _, err := s.SendRawOutcome(context.Background(), host, port, false, []byte(silentProbeReq), ProtocolPreferenceAuto)
	if err != nil || !strings.Contains(string(resp), "first") {
		t.Fatalf("first send: resp=%q err=%v", resp, err)
	}

	start := time.Now()
	_, _, err = s.SendRawOutcome(context.Background(), host, port, false, []byte(silentProbeReq), ProtocolPreferenceAuto)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("the silent pooled connection produced a response")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the pooled read took %v against timeouts.read_ms of 150ms", elapsed)
	}
	if !strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("the trip reported %v, not its read deadline", err)
	}

	// The tripped connection was discarded, never pooled again: the next send dials fresh and the
	// server answers its first request.
	resp, _, err = s.SendRawOutcome(context.Background(), host, port, false, []byte(silentProbeReq), ProtocolPreferenceAuto)
	if err != nil || !strings.Contains(string(resp), "first") {
		t.Fatalf("send after the trip: resp=%q err=%v", resp, err)
	}
	if got := accepted.Load(); got != 2 {
		t.Fatalf("%d sockets for 3 sends: one pool, one reuse of it, one fresh dial after the "+
			"trip is 2 - the deadline-tripped connection was reused", got)
	}
}

func TestAConnPoolExchangeHonoursTimeoutsReadMS(t *testing.T) {
	addr, accepted := startAnswerOnceThenSilentServer(t)
	host, port := mustHostPort(t, addr)
	auth := NewAuthorisedSender(allowAll{}, keepAliveSender(t, 150), host, port, false)
	pool := NewConnPool(2)
	defer pool.Close()

	res, err := auth.SendReusing(context.Background(), pool, []byte(silentProbeReq), ProtocolPreferenceAuto)
	if err != nil || !strings.Contains(string(res.Raw), "first") {
		t.Fatalf("first send: resp=%q err=%v", res.Raw, err)
	}

	start := time.Now()
	_, err = auth.SendReusing(context.Background(), pool, []byte(silentProbeReq), ProtocolPreferenceAuto)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("the silent pooled connection produced a response")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the pooled read took %v against timeouts.read_ms of 150ms", elapsed)
	}

	res, err = auth.SendReusing(context.Background(), pool, []byte(silentProbeReq), ProtocolPreferenceAuto)
	if err != nil || !strings.Contains(string(res.Raw), "first") {
		t.Fatalf("send after the trip: resp=%q err=%v", res.Raw, err)
	}
	if got := accepted.Load(); got != 2 {
		t.Fatalf("%d sockets for 3 sends: one pool, one reuse of it, one fresh dial after the "+
			"trip is 2 - the deadline-tripped connection was reused", got)
	}
}

// No timeouts.read_ms, no timeouts.total_ms, no context deadline: the exchange must still end.
// The built-in bound stands in — the test shrinks it rather than waiting out the real one — and
// before 757d there was no bound at all and this read ran until the caller's patience, not a
// deadline, ended it - the unbounded primitive the bead names.
func TestAPooledReadIsBoundedWhenTheOperatorSetNoTimeout(t *testing.T) {
	defer func(orig time.Duration) { defaultExchangeBound = orig }(defaultExchangeBound)
	defaultExchangeBound = 150 * time.Millisecond

	addr, _ := startAnswerOnceThenSilentServer(t)
	host, port := mustHostPort(t, addr)
	s := keepAliveSender(t, 0)

	resp, _, err := s.SendRawOutcome(context.Background(), host, port, false, []byte(silentProbeReq), ProtocolPreferenceAuto)
	if err != nil || !strings.Contains(string(resp), "first") {
		t.Fatalf("first send: resp=%q err=%v", resp, err)
	}

	// No context deadline either: if the built-in bound ever stops answering, this read hangs and
	// only the test binary's own timeout says so - which is the failure this test exists to name.
	start := time.Now()
	_, _, err = s.SendRawOutcome(context.Background(), host, port, false, []byte(silentProbeReq), ProtocolPreferenceAuto)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("the silent pooled connection produced a response")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("with no operator timeout and no context deadline the pooled read ran %v, "+
			"past the shrunk built-in bound", elapsed)
	}
}
