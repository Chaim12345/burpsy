package intruder

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Measured against a real socket: the rate limiter is only a correctness feature if it holds when
// requests really go out over TCP with real scheduling jitter, so these two tests measure
// arrivals at the far end rather than trusting the bucket arithmetic.

type probe struct {
	addr     string
	mu       sync.Mutex
	arrivals []time.Time
	peak     int
	live     int
}

// probeServer is a server that timestamps every connection, tracks peak concurrency, and
// optionally holds each request open for delay before answering.
func probeServer(t *testing.T, delay time.Duration) *probe {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &probe{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				p.mu.Lock()
				p.arrivals = append(p.arrivals, time.Now())
				p.live++
				if p.live > p.peak {
					p.peak = p.live
				}
				p.mu.Unlock()
				buf := make([]byte, 8192)
				c.Read(buf)
				if delay > 0 {
					time.Sleep(delay)
				}
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
				p.mu.Lock()
				p.live--
				p.mu.Unlock()
			}(conn)
		}
	}()
	return p
}

// tcpSender is one connection per request, closed by the server. Deliberately not the repeater:
// this package must not know about the network stack, and the test proves the seam works.
func tcpSender(addr string) SendFn {
	return func(raw []byte) (Sent, error) {
		started := time.Now()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return Sent{}, err
		}
		defer conn.Close()
		if _, err := conn.Write(raw); err != nil {
			return Sent{}, err
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, conn); err != nil {
			return Sent{}, err
		}
		return Sent{Raw: buf.Bytes(), Duration: time.Since(started), Status: ptr(200)}, nil
	}
}

func numPayloads(n int) PayloadSet {
	return numItems(n, "p%d")
}

// Measured at the target: no window of length T received more than burst + rps*T requests, and
// the whole attack could not finish before (n - burst) / rps.
func TestTheTargetNeverReceivesMoreThanTheConfiguredRate(t *testing.T) {
	rps := 50.0
	burst := 1
	n := 40
	p := probeServer(t, 0)

	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n")
	sel := pts[:1]
	payloads := []PayloadSet{numPayloads(n)}
	plan := NewAttackPlan(AttackKindSniper, 1, []int{n}, 1_000)

	a := NewAttack(base, sel, payloads, plan).WithLimits(NewRateLimit(&rps, burst, 8))
	t0 := time.Now()
	r := Run(a, tcpSender(p.addr), nil)
	elapsed := time.Since(t0)

	if r.Sent != n {
		t.Fatalf("every request must have actually gone out: %+v", r)
	}
	floor := time.Duration((float64(n) - float64(burst)) / rps * float64(time.Second))
	if elapsed < floor {
		t.Fatalf("%d requests at %g/s finished in %v, faster than the %v floor", n, rps, elapsed, floor)
	}

	p.mu.Lock()
	at := append([]time.Time(nil), p.arrivals...)
	p.mu.Unlock()
	if len(at) != n {
		t.Fatalf("the server did not see every request: %d", len(at))
	}
	window := 500 * time.Millisecond
	// The bucket's clock and these arrival timestamps are both wall-clock, and when the whole
	// workspace suite runs at once the two drift by tens of milliseconds. A request the limiter
	// admitted legitimately just outside the window can then be *timestamped* just inside it — a
	// measurement artefact, not a limiter that let an extra request through. The allowance is
	// that drift expressed in requests; it is not slack in the bound under test, which is the
	// `floor` assertion above.
	jitter := 60 * time.Millisecond
	allowed := float64(burst) + rps*(window+jitter).Seconds()
	for i, start := range at {
		count := 0
		for _, tm := range at[i:] {
			if tm.Sub(start) <= window {
				count++
			} else {
				break
			}
		}
		if float64(count) > allowed {
			t.Fatalf("%d requests arrived within %v; burst %d + %g/s allows %g", count, window, burst, rps, allowed)
		}
	}
}

// The other half: the limiter must bound the attack without serialising it. With a slow target
// and eight slots, wall time is a fraction of the sequential cost — and the target never sees a
// ninth concurrent request.
func TestRequestsRunConcurrentlyUpToTheInFlightCap(t *testing.T) {
	perRequest := 60 * time.Millisecond
	slots := 8
	n := 32
	p := probeServer(t, perRequest)

	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n")
	sel := pts[:1]
	payloads := []PayloadSet{numPayloads(n)}
	plan := NewAttackPlan(AttackKindSniper, 1, []int{n}, 1_000)

	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(slots))
	t0 := time.Now()
	r := Run(a, tcpSender(p.addr), nil)
	elapsed := time.Since(t0)

	if r.Sent != n {
		t.Fatalf("sent = %d, want %d", r.Sent, n)
	}
	p.mu.Lock()
	peak := p.peak
	p.mu.Unlock()
	if peak > slots {
		t.Fatalf("the target saw %d concurrent requests against a cap of %d", peak, slots)
	}
	sequential := perRequest * time.Duration(n)
	if elapsed >= sequential/2 {
		t.Fatalf("%d requests over %d slots took %v; sequential would be %v, so this did not run concurrently",
			n, slots, elapsed, sequential)
	}
}
