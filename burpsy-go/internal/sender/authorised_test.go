package sender

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// hostPort splits an address into host and numeric port for the sender's typed API.
func hostPort(addr string) (string, uint16, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, uint16(n), nil
}

// localServer answers every request with a fixed 200, recording nothing but proving bytes arrived.
func localServer(t *testing.T) (string, []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	addr := ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				// Read the head; the body (if any) is drained so the request fully arrives before
				// the response is written.
				head := ""
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					head += line
					if strings.HasSuffix(head, "\r\n\r\n") || strings.HasSuffix(head, "\n\n") {
						break
					}
				}
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()
	return addr, nil
}

func TestAnOutOfScopeRequestIsRefusedBeforeTheTransportIsReached(t *testing.T) {
	sc := core.NewScope()
	sc.AddExclude("127.0.0.1")
	// Port 1 is closed everywhere; reaching it would be a dial error, so a scope-shaped error
	// proves the transport was never touched.
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), "127.0.0.1", 1, false)
	_, err := a.Send(context.Background(), []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("want a scope refusal, got %v", err)
	}
	if a.Sent() != 0 {
		t.Fatalf("sent = %d, want 0: nothing passed the gate", a.Sent())
	}
	if a.Refused() != 1 {
		t.Fatalf("refused = %d, want 1", a.Refused())
	}
}

func TestAnInScopeRequestIsSentAndReturnsTheResponse(t *testing.T) {
	addr, _ := localServer(t)
	_, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	sc := core.NewScopeAllowEverything()
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), "127.0.0.1", port, false)
	res, err := a.Send(context.Background(), []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Status == nil || *res.Status != 200 {
		t.Fatalf("status = %v, want 200", res.Status)
	}
	if !strings.Contains(string(res.Raw), "ok") {
		t.Fatalf("response lost its body: %q", res.Raw)
	}
	if res.Duration <= 0 {
		t.Fatalf("duration = %v, want > 0", res.Duration)
	}
	if a.Sent() != 1 || a.Refused() != 0 {
		t.Fatalf("sent/refused = %d/%d, want 1/0", a.Sent(), a.Refused())
	}
}

// The named host is fully in scope; the request bytes are not. This is the sender half of the
// intruder guarantee: a payload spliced into a path position rewrites the request line, and only
// the bytes actually going on the wire can be trusted.
func TestTheSplicedBytesNotTheNamedTargetAreChecked(t *testing.T) {
	addr, _ := localServer(t)
	_, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	sc := core.NewScope()
	sc.AddInclude("127.0.0.1")
	sc.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "127.0.0.1", "/admin"))
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), "127.0.0.1", port, false)

	if _, err := a.Send(context.Background(), []byte("GET /admin/delete HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")); err == nil {
		t.Fatal("a request whose path is excluded must be refused even though the host is in scope")
	}
	if _, err := a.Send(context.Background(), []byte("GET /search HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")); err != nil {
		t.Fatalf("the in-scope path must be sent: %v", err)
	}
	if a.Sent() != 1 || a.Refused() != 1 {
		t.Fatalf("sent/refused = %d/%d, want 1/1", a.Sent(), a.Refused())
	}
}

func TestConcurrentSendsDoNotLoseCounters(t *testing.T) {
	addr, _ := localServer(t)
	_, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	sc := core.NewScopeAllowEverything()
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), "127.0.0.1", port, false)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Send(context.Background(), []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
		}()
	}
	wg.Wait()
	if a.Sent() != 16 {
		t.Fatalf("sent = %d, want 16 (no counter may be lost under the race detector)", a.Sent())
	}
	if a.Refused() != 0 {
		t.Fatalf("refused = %d, want 0", a.Refused())
	}
}
