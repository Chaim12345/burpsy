package sender

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- HTTP/1 connection reuse (burpsy-react-ui-xhqr) -------------------------------------------------
//
// Every count here is taken on the SERVER side — accepted sockets and requests served — because a
// client-side counter would only prove the pool agrees with itself.

type keepAliveMode int

const (
	// framed answers with Content-Length and keeps the connection open for the next request.
	framed keepAliveMode = iota
	// saysClose answers with Content-Length and "Connection: close" — and then keeps serving on the
	// same socket anyway, so a pool that ignored the header would succeed at reusing it and be caught
	// by the accept count rather than by a dead socket.
	saysClose
	// unframed answers with no Content-Length and no chunking, and closes its write side to end the
	// body (the only way such a body can end).
	unframed
)

type keepAliveServer struct {
	addr    string
	accepts atomic.Int64
	served  atomic.Int64
	// live is the number of connections open right now, and peak the most there ever were.
	live, peak atomic.Int64
}

func startKeepAliveServer(t *testing.T, mode keepAliveMode, delay time.Duration) *keepAliveServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &keepAliveServer{addr: ln.Addr().String()}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepts.Add(1)
			n := s.live.Add(1)
			for {
				p := s.peak.Load()
				if n <= p || s.peak.CompareAndSwap(p, n) {
					break
				}
			}
			go func(c net.Conn) {
				defer s.live.Add(-1)
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					c.SetReadDeadline(time.Now().Add(5 * time.Second))
					for {
						line, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if line == "\r\n" {
							break
						}
					}
					if delay > 0 {
						time.Sleep(delay)
					}
					n := s.served.Add(1)
					body := "served " + strconv.FormatInt(n, 10)
					switch mode {
					case framed:
						fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
					case saysClose:
						fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
					case unframed:
						fmt.Fprintf(c, "HTTP/1.1 200 OK\r\n\r\n%s", body)
						if tc, ok := c.(*net.TCPConn); ok {
							tc.CloseWrite()
						}
						// Keep reading: a pool that pooled this socket would write its next request
						// here and wait for an answer that never comes.
						io.Copy(io.Discard, br)
						return
					}
				}
			}(conn)
		}
	}()
	return s
}

type allowAll struct{}

func (allowAll) AuthoriseRaw(string, uint16, bool, []byte) error { return nil }

func poolSender(t *testing.T, addr string) *AuthorisedSender {
	t.Helper()
	host, port := mustHostPort(t, addr)
	return NewAuthorisedSender(allowAll{}, NewSender(DefaultSenderConfig()), host, port, false)
}

const keepAliveReq = "GET /p HTTP/1.1\r\nHost: target.test\r\n\r\n"

// N concurrent sends over a pool bounded at k: at most k sockets ever exist, the server sees every
// request, and the pool's own counts agree with the server's.
func TestAPoolOfKNeverOpensMoreThanKSockets(t *testing.T) {
	const k, n = 4, 48
	srv := startKeepAliveServer(t, framed, 2*time.Millisecond)
	auth := poolSender(t, srv.addr)
	pool := NewConnPool(k)
	defer pool.Close()

	// All n at once, with no limiter in front: the pool's own bound is what is under test.
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := auth.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto)
			if err != nil {
				errs <- err
				return
			}
			if !strings.Contains(string(res.Raw), "served ") {
				errs <- fmt.Errorf("unexpected response %q", res.Raw)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a pooled send failed: %v", err)
	}
	accepts := srv.accepts.Load()
	if got := srv.served.Load(); got != n {
		t.Fatalf("the server served %d requests, want %d", got, n)
	}
	if accepts > k {
		t.Fatalf("%d sockets were accepted for a pool bounded at %d", accepts, k)
	}
	if peak := srv.peak.Load(); peak > k {
		t.Fatalf("%d sockets were open at once for a pool bounded at %d", peak, k)
	}
	if pool.Opened() != accepts {
		t.Fatalf("the pool says it opened %d connections and the server accepted %d", pool.Opened(), accepts)
	}
	if pool.Reused() != n-accepts {
		t.Fatalf("the pool says %d sends reused a connection; %d sends over %d sockets means %d did",
			pool.Reused(), n, accepts, n-accepts)
	}
	if auth.Sent() != n {
		t.Fatalf("the authorising sender counted %d sends, want %d", auth.Sent(), n)
	}
}

// A response carrying Connection: close is never reused, even when the server would have answered on
// the same socket.
func TestAConnectionCloseResponseIsNeverReused(t *testing.T) {
	const n = 6
	srv := startKeepAliveServer(t, saysClose, 0)
	auth := poolSender(t, srv.addr)
	pool := NewConnPool(2)
	defer pool.Close()
	for i := 0; i < n; i++ {
		if _, err := auth.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if got := srv.accepts.Load(); got != n {
		t.Fatalf("%d sockets for %d sends whose responses said Connection: close; every one must be fresh", got, n)
	}
	if pool.Reused() != 0 {
		t.Fatalf("the pool reports %d reuses after Connection: close", pool.Reused())
	}
}

// A request that says Connection: close is never reused either, whatever the server does.
func TestAConnectionCloseRequestIsNeverReused(t *testing.T) {
	const n = 5
	srv := startKeepAliveServer(t, framed, 0)
	auth := poolSender(t, srv.addr)
	pool := NewConnPool(2)
	defer pool.Close()
	req := "GET /p HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n"
	for i := 0; i < n; i++ {
		if _, err := auth.SendReusing(context.Background(), pool, []byte(req), ProtocolPreferenceAuto); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if got := srv.accepts.Load(); got != n {
		t.Fatalf("%d sockets for %d requests that said Connection: close", got, n)
	}
}

// A body delimited only by the peer closing is never reused. The server half-closes and keeps reading,
// so a pooled socket would take the next request and never answer it.
func TestAnUnframedBodyIsNeverReused(t *testing.T) {
	const n = 4
	srv := startKeepAliveServer(t, unframed, 0)
	auth := poolSender(t, srv.addr)
	pool := NewConnPool(2)
	defer pool.Close()
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		res, err := auth.SendReusing(ctx, pool, []byte(keepAliveReq), ProtocolPreferenceAuto)
		cancel()
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if !strings.HasSuffix(string(res.Raw), "served "+strconv.Itoa(i+1)) {
			t.Fatalf("send %d read %q", i, res.Raw)
		}
	}
	if got := srv.accepts.Load(); got != n {
		t.Fatalf("%d sockets for %d unframed responses", got, n)
	}
	if pool.Reused() != 0 {
		t.Fatalf("the pool reports %d reuses of an unframed response's connection", pool.Reused())
	}
}

// The rule itself, without a liveness probe in the way: the integration test above cannot tell the
// framing rule from the probe that would discard a closed socket anyway.
func TestExchangeAllowsReuseNamesEachRule(t *testing.T) {
	get := []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")
	ok := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	cases := []struct {
		name      string
		req, resp []byte
		want      bool
	}{
		{"framed keep-alive", get, ok, true},
		{"chunked", get, []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"), true},
		{"204 carries no body", get, []byte("HTTP/1.1 204 No Content\r\n\r\n"), true},
		{"unframed body", get, []byte("HTTP/1.1 200 OK\r\n\r\nok"), false},
		{"response says close", get, []byte("HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\nContent-Length: 2\r\n\r\nok"), false},
		{"request says close", []byte("GET / HTTP/1.1\r\nHost: h\r\nConnection: Close\r\n\r\n"), ok, false},
		{"HTTP/1.0 request", []byte("GET / HTTP/1.0\r\nHost: h\r\n\r\n"), ok, false},
		{"HTTP/1.0 response", get, []byte("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"), false},
		{"HEAD", []byte("HEAD / HTTP/1.1\r\nHost: h\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"), false},
		{"interim 100", get, []byte("HTTP/1.1 100 Continue\r\n\r\n"), false},
		{"101 upgrade", get, []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"), false},
		{"request with bytes past its framing", []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n"), ok, false},
		{"request with a framed body", []byte("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nok"), ok, true},
	}
	for _, tc := range cases {
		if got := exchangeAllowsReuse(tc.req, tc.resp); got != tc.want {
			t.Errorf("%s: exchangeAllowsReuse = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A connection the server closed while it sat idle is not handed to the next request: the liveness
// probe discards it and the send dials fresh, so the operator sees a response, not an error.
func TestAnIdleConnectionTheServerClosedIsNotUsed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var accepts atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
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
				// Framed and keep-alive, then the server closes anyway — an idle timeout.
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}(c)
		}
	}()
	auth := poolSender(t, ln.Addr().String())
	pool := NewConnPool(1)
	defer pool.Close()
	// POST, deliberately: a non-idempotent request is never retried on a fresh connection after a
	// reused one fails, so only the liveness probe stands between it and the dead socket.
	post := "POST /p HTTP/1.1\r\nHost: target.test\r\nContent-Length: 0\r\n\r\n"
	for i := 0; i < 3; i++ {
		if _, err := auth.SendReusing(context.Background(), pool, []byte(post), ProtocolPreferenceAuto); err != nil {
			t.Fatalf("send %d after the server closed its idle socket: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if accepts.Load() != 3 {
		t.Fatalf("%d sockets for 3 sends to a server that closes after each", accepts.Load())
	}
}

// A reused connection that dies between the probe and the write is retried on a fresh connection for
// an idempotent request — net/http's rule — and the retry is not counted as a reuse.
func TestAStaleReusedConnectionIsRetriedFreshForAGet(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var accepts atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
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
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}(c)
		}
	}()
	auth := poolSender(t, ln.Addr().String())
	pool := NewConnPool(1)
	defer pool.Close()
	if _, err := auth.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto); err != nil {
		t.Fatalf("first send: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	// The server has closed the pooled socket. The race this covers — the close landing between the
	// probe and the write — cannot be timed from a test, so the probe is switched off and the dead
	// socket is handed out as though it had passed.
	if pc := pool.takeIdle(formatAuthority(mustHostOnly(t, ln.Addr().String()))); pc == nil {
		t.Fatal("the first send's connection was not pooled")
	} else {
		pool.mu.Lock()
		pool.idle[pc.key] = append(pool.idle[pc.key], pc)
		pool.nIdle++
		pool.mu.Unlock()
	}
	restore := disableLiveness()
	defer restore()
	res, err := auth.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("a GET on a connection the server had closed was not retried: %v", err)
	}
	if !strings.HasSuffix(string(res.Raw), "ok") || accepts.Load() != 2 {
		t.Fatalf("response %q over %d sockets; want ok over 2", res.Raw, accepts.Load())
	}
	if pool.Reused() != 0 {
		t.Fatalf("a retried send was counted as a reuse (%d)", pool.Reused())
	}
}

func mustHostOnly(t *testing.T, addr string) (string, uint16, bool) {
	t.Helper()
	h, p := mustHostPort(t, addr)
	return h, p, false
}

// The pool authorises every request: a refused one never reaches a socket, pooled or not.
type refuseAll struct{}

func (refuseAll) AuthoriseRaw(string, uint16, bool, []byte) error { return fmt.Errorf("refused") }

func TestSendReusingStillAuthorisesEveryRequest(t *testing.T) {
	srv := startKeepAliveServer(t, framed, 0)
	host, port := mustHostPort(t, srv.addr)
	ok := NewAuthorisedSender(allowAll{}, NewSender(DefaultSenderConfig()), host, port, false)
	pool := NewConnPool(1)
	defer pool.Close()
	if _, err := ok.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	no := NewAuthorisedSender(refuseAll{}, NewSender(DefaultSenderConfig()), host, port, false)
	if _, err := no.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto); err == nil {
		t.Fatal("a refused request was sent over the pool")
	}
	if no.Refused() != 1 || srv.served.Load() != 1 {
		t.Fatalf("refused=%d served=%d; the refusal must count and the server must see nothing", no.Refused(), srv.served.Load())
	}
}

// disableLiveness makes every idle connection pass the probe, returning the function that restores it.
func disableLiveness() func() {
	old := aliveCheck
	aliveCheck = func(*pooledConn) bool { return true }
	return func() { aliveCheck = old }
}

// The ConnPool counterpart of keepalive_test.go's TestARequestWithBytesPastItsFramingDoesNotPoolItsConnection:
// a request carrying a second request past its own framing — pipelined, or a smuggling payload an
// Intruder attack sends on purpose — must not leave its connection pooled. The second request's
// response arrives after the first was read, and the next payload's send would read it as its own:
// a fabricated per-payload result, which is exactly what this pool's reuse rules exist to prevent.
func TestAConnPoolRequestWithBytesPastItsFramingDoesNotPoolItsConnection(t *testing.T) {
	host, port, conns := startPathEchoServer(t, 50*time.Millisecond)
	auth := NewAuthorisedSender(allowAll{}, NewSender(DefaultSenderConfig()), host, port, false)
	pool := NewConnPool(1)
	defer pool.Close()
	hostHeader := "Host: " + formatHostPort(host, port) + "\r\n"
	send := func(raw string) string {
		t.Helper()
		res, err := auth.SendReusing(context.Background(), pool, []byte(raw), ProtocolPreferenceHTTP1)
		if err != nil {
			t.Fatalf("send %q: %v", firstLineOf(raw), err)
		}
		_, body, _ := strings.Cut(string(res.Raw), "\r\n\r\n")
		return body
	}

	if got := send("GET /first HTTP/1.1\r\n" + hostHeader + "\r\nGET /smuggled HTTP/1.1\r\n" + hostHeader + "\r\n"); got != "/first" {
		t.Fatalf("the pipelined send read %q, want /first", got)
	}
	if got := send("GET /second HTTP/1.1\r\n" + hostHeader + "\r\n"); got != "/second" {
		t.Fatalf("the next send to the host read %q, want its own /second", got)
	}
	if got := pool.Reused(); got != 0 {
		t.Errorf("the pool reused a connection %d time(s); the pipelined send's must not be", got)
	}
	if got := conns.Load(); got != 2 {
		t.Errorf("%d connection(s) for 2 sends, want 2: the pipelined one must not be reused", got)
	}

	// The check must not cost an ordinary request its reuse: a single request with a body is exactly
	// its framing, so both ride the connection /second left pooled.
	before := conns.Load()
	for _, raw := range []string{
		"POST /cl HTTP/1.1\r\n" + hostHeader + "Content-Length: 5\r\n\r\nhello",
		"POST /chunked HTTP/1.1\r\n" + hostHeader + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	} {
		send(raw)
	}
	if got := conns.Load() - before; got != 0 {
		t.Errorf("%d new connection(s) for two single-request sends with bodies, want 0: each is exactly its framing", got)
	}
}
