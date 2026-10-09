package sender

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- per-send response timeout on the context (burpsy-react-ui-mmca) ------------------------------
//
// The claim: one send can carry its own read bound, it fires, and nothing else changes — not a
// sibling send in flight at the same time, and not the shared NetworkSettings every other tool reads.

// slowServer answers every request after delay, with a framed body, then closes.
func slowServer(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
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
				time.Sleep(delay)
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow")
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestAContextResponseTimeoutBoundsOneSendAndLeavesTheNetworkAlone(t *testing.T) {
	s := NewSender(DefaultSenderConfig())
	before := s.Network()

	silentAddr, _ := silentServer(t)
	silentHost, silentPort := mustHostPort(t, silentAddr)
	// The sibling answers after 600ms: longer than the override, far shorter than the standing read
	// bound. If the override leaked into the shared settings (or into another send's context), the
	// sibling would fail on it.
	slowAddr := slowServer(t, 600*time.Millisecond)
	slowHost, slowPort := mustHostPort(t, slowAddr)
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")

	var wg sync.WaitGroup
	var siblingErr error
	var siblingResp []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		siblingResp, siblingErr = s.SendRaw(context.Background(), slowHost, slowPort, false, raw)
	}()

	// An outer deadline, the shape every Intruder attempt has (its total per-attempt timeout_ms).
	// setDeadline used to let any context deadline short-circuit everything; the override must still
	// fire inside it. 5s is the bound a regression would hit, so the elapsed assertion below fails
	// loudly rather than hanging.
	outer, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx := WithSendOptions(outer, SendOptions{ResponseTimeout: 200 * time.Millisecond})
	started := time.Now()
	_, err := s.SendRaw(ctx, silentHost, silentPort, false, raw)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("a send to a silent listener returned no error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the response timeout of 200ms did not bound the send: it took %s (%v)", elapsed, err)
	}
	if !strings.Contains(err.Error(), "response timeout") {
		t.Fatalf("the error does not name the send's own response timeout: %v", err)
	}

	wg.Wait()
	if siblingErr != nil {
		t.Fatalf("a sibling send without the override failed: %v", siblingErr)
	}
	if !strings.HasSuffix(string(siblingResp), "slow") {
		t.Fatalf("the sibling's response is not the slow server's: %q", siblingResp)
	}
	if after := s.Network(); !reflect.DeepEqual(before, after) {
		t.Fatalf("a per-send override changed the shared network settings:\nbefore %+v\nafter  %+v", before, after)
	}
}

// An override longer than the context deadline must not extend it: the earlier bound wins.
func TestAContextDeadlineEarlierThanTheResponseTimeoutStillWins(t *testing.T) {
	s := NewSender(DefaultSenderConfig())
	silentAddr, _ := silentServer(t)
	host, port := mustHostPort(t, silentAddr)
	outer, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	ctx := WithSendOptions(outer, SendOptions{ResponseTimeout: 10 * time.Second})
	started := time.Now()
	if _, err := s.SendRaw(ctx, host, port, false, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err == nil {
		t.Fatal("a send to a silent listener returned no error")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("a 10s response timeout extended a 200ms context deadline: took %s", elapsed)
	}
}

// The override must also cover the h2-independent pipeline primitives, which bound their exchange
// through the same setDeadline.
func TestTheResponseTimeoutReachesTheKeepAlivePath(t *testing.T) {
	s := NewSender(DefaultSenderConfig())
	silentAddr, _ := silentServer(t)
	host, port := mustHostPort(t, silentAddr)
	outer, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx := WithSendOptions(outer, SendOptions{ResponseTimeout: 200 * time.Millisecond})
	started := time.Now()
	ex, err := s.SendKeepAlive(ctx, host, port, false, [][]byte{[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if ex[0].ReadErr == nil {
		t.Fatal("a keep-alive read against a silent listener reported no error")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the response timeout did not bound the keep-alive read: took %s", elapsed)
	}
}
