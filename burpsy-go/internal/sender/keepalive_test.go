package sender

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
)

// Burp's project-wide HTTP/1 keep-alive and "Default to HTTP/2" (burpsy-react-ui-ry5n), driven
// through SendRawOutcome against real listeners that count the connections they accept.

type connCountingServer struct {
	host  string
	port  uint16
	conns atomic.Int64
	srv   *httptest.Server
}

func startConnCounting(t *testing.T, useTLS bool, protos []string, handler http.HandlerFunc) *connCountingServer {
	t.Helper()
	c := &connCountingServer{}
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			c.conns.Add(1)
		}
	}
	if useTLS {
		srv.EnableHTTP2 = false
		for _, p := range protos {
			if p == alpn.H2 {
				srv.EnableHTTP2 = true
			}
		}
		srv.TLS = &tls.Config{NextProtos: protos}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://")
	host, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	c.host, c.port, c.srv = host, port, srv
	return c
}

func okHandler(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }

func senderWithHTTP(t *testing.T, keepAlive bool, h2 bool) *Sender {
	t.Helper()
	s := testSender()
	n := s.Network()
	n.HTTP1 = &HTTP1Settings{EnableKeepAlive: keepAlive}
	n.HTTP2 = &HTTP2Settings{EnableHTTP2: h2}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}
	return s
}

func sendN(t *testing.T, s *Sender, srv *connCountingServer, useTLS bool, n int, raw []byte) {
	t.Helper()
	for i := 0; i < n; i++ {
		resp, _, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, useTLS, raw, ProtocolPreferenceAuto)
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if !strings.HasSuffix(string(resp), "ok") {
			t.Fatalf("send %d answered %q", i, resp)
		}
	}
}

func TestKeepAliveIsOffByDefaultAndEachSendDialsItsOwnConnection(t *testing.T) {
	srv := startConnCounting(t, false, nil, okHandler)
	sendN(t, testSender(), srv, false, 3, rawGet(srv.host, srv.port))
	if got := srv.conns.Load(); got != 3 {
		t.Errorf("three sends with keep-alive off opened %d connection(s), want 3", got)
	}
}

func TestKeepAliveReusesOneConnectionForPlaintextAndTLS(t *testing.T) {
	plain := startConnCounting(t, false, nil, okHandler)
	sendN(t, senderWithHTTP(t, true, true), plain, false, 3, rawGet(plain.host, plain.port))
	if got := plain.conns.Load(); got != 1 {
		t.Errorf("plaintext: three keep-alive sends opened %d connection(s), want 1", got)
	}
	// A TLS target that declines h2: the connection kept after the h2 offer serves the next sends.
	secure := startConnCounting(t, true, []string{alpn.HTTP11}, okHandler)
	sendN(t, senderWithHTTP(t, true, true), secure, true, 3, rawGet(secure.host, secure.port))
	if got := secure.conns.Load(); got != 1 {
		t.Errorf("TLS http/1.1: three keep-alive sends opened %d connection(s), want 1", got)
	}
}

func TestAConnectionCloseOrUnframedResponseIsNotReused(t *testing.T) {
	closing := startConnCounting(t, false, nil, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		w.Write([]byte("ok"))
	})
	sendN(t, senderWithHTTP(t, true, true), closing, false, 2, rawGet(closing.host, closing.port))
	if got := closing.conns.Load(); got != 2 {
		t.Errorf("Connection: close was ignored: %d connection(s) for 2 sends, want 2", got)
	}
	// The request asking for close is honoured too.
	plain := startConnCounting(t, false, nil, okHandler)
	raw := []byte("GET /probe HTTP/1.1\r\nHost: " + formatHostPort(plain.host, plain.port) + "\r\nConnection: close\r\n\r\n")
	sendN(t, senderWithHTTP(t, true, true), plain, false, 2, raw)
	if got := plain.conns.Load(); got != 2 {
		t.Errorf("a request's Connection: close was ignored: %d connection(s), want 2", got)
	}
}

func TestReusableAfterReadsTheFraming(t *testing.T) {
	get := []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	for _, c := range []struct {
		resp string
		want bool
	}{
		{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", true},
		{"HTTP/1.1 204 No Content\r\n\r\n", true},
		{"HTTP/1.1 200 OK\r\n\r\nread until close", false},
		{"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", false},
		{"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", false},
		{"HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\nContent-Length: 2\r\n\r\nok", false},
	} {
		if got := reusableAfter(get, []byte(c.resp)); got != c.want {
			t.Errorf("reusableAfter(%q) = %v, want %v", firstLineOf(c.resp), got, c.want)
		}
	}
}

// A kept connection the server closed while it sat idle is retried on a fresh one, not reported as
// a failed send.
func TestAKeptConnectionTheServerClosedIsRetriedOnAFreshOne(t *testing.T) {
	srv := startConnCounting(t, false, nil, okHandler)
	s := senderWithHTTP(t, true, true)
	sendN(t, s, srv, false, 1, rawGet(srv.host, srv.port))
	srv.srv.CloseClientConnections()
	time.Sleep(50 * time.Millisecond)
	sendN(t, s, srv, false, 1, rawGet(srv.host, srv.port))
	if got := srv.conns.Load(); got != 2 {
		t.Errorf("%d connection(s), want 2: the dead one, then a fresh one", got)
	}
}

func TestAKeptConnectionIsClosedAfterTheIdleTimeoutAndOnASettingsChange(t *testing.T) {
	prev := http1IdleTimeout
	http1IdleTimeout = 100 * time.Millisecond
	t.Cleanup(func() { http1IdleTimeout = prev })

	srv := startConnCounting(t, false, nil, okHandler)
	s := senderWithHTTP(t, true, true)
	sendN(t, s, srv, false, 1, rawGet(srv.host, srv.port))
	if s.pool.idleCount() != 1 {
		t.Fatalf("after one send %d connection(s) kept, want 1", s.pool.idleCount())
	}
	time.Sleep(300 * time.Millisecond)
	if n := s.pool.idleCount(); n != 0 {
		t.Errorf("%d connection(s) still kept past the idle timeout", n)
	}

	sendN(t, s, srv, false, 1, rawGet(srv.host, srv.port))
	if err := s.ApplyNetwork(s.Network()); err != nil {
		t.Fatal(err)
	}
	if n := s.pool.idleCount(); n != 0 {
		t.Errorf("%d connection(s) survived a settings change", n)
	}
}

func TestDefaultToHTTP2OffSendsHTTP1AndSaysWhy(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2, alpn.HTTP11}, true)
	s := senderWithHTTP(t, false, false)
	_, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true, rawGet(srv.host, srv.port), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.lastProto(t); got != "HTTP/1.1" {
		t.Errorf("with Default to HTTP/2 off the send arrived as %s", got)
	}
	if !outcome.Downgraded() || outcome.Downgrade.Reason != DowngradeProjectDefaultHTTP1 {
		t.Errorf("outcome %+v, want the project-default reason", outcome.Downgrade)
	}

	// A request written as HTTP/2, and a caller's h2 pin, still ride h2: the per-request choice
	// overrides the project default, as Burp's Inspector toggle does.
	h2raw := []byte("GET /h2path HTTP/2\r\nHost: " + formatHostPort(srv.host, srv.port) + "\r\n\r\n")
	if _, _, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true, h2raw, ProtocolPreferenceAuto); err != nil {
		t.Fatal(err)
	}
	if got := srv.lastProto(t); got != "HTTP/2.0" {
		t.Errorf("an HTTP/2-written request arrived as %s", got)
	}
	if _, _, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true, rawGet(srv.host, srv.port), ProtocolPreferenceForceH2); err != nil {
		t.Fatal(err)
	}
	if got := srv.lastProto(t); got != "HTTP/2.0" {
		t.Errorf("a caller's h2 pin arrived as %s", got)
	}

	// The default (nil) is Burp's: h2 on.
	if _, _, err := testSender().SendRawOutcome(context.Background(), srv.host, srv.port, true, rawGet(srv.host, srv.port), ProtocolPreferenceAuto); err != nil {
		t.Fatal(err)
	}
	if got := srv.lastProto(t); got != "HTTP/2.0" {
		t.Errorf("with the default settings the send arrived as %s, want h2", got)
	}
}

// A response followed by bytes the request did not ask for — a desync probe's smuggled second
// response, say — leaves the connection carrying another exchange's bytes. It is never kept: the next
// send must read its own response, not those.
func TestAConnectionWithBytesPastTheResponseIsNotKept(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var conns atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n := conns.Add(1)
			go func(c net.Conn, n int64) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					// Two responses in one write: the second is not an answer to anything sent.
					c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nconn" + string(rune('0'+n)) +
						"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nSTALE"))
				}
			}(c, n)
		}
	}()
	host, port, _ := hostPort(ln.Addr().String())
	s := senderWithHTTP(t, true, true)
	for i := 0; i < 2; i++ {
		resp, _, err := s.SendRawOutcome(context.Background(), host, port, false, rawGet(host, port), ProtocolPreferenceAuto)
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if strings.Contains(string(resp), "STALE") {
			t.Fatalf("send %d read the previous exchange's leftover bytes as its response: %q", i, resp)
		}
	}
	if got := conns.Load(); got != 2 {
		t.Errorf("%d connection(s) for 2 sends, want 2: a connection with buffered bytes must not be kept", got)
	}
}

// A non-idempotent request whose kept connection died after it was written is not resent: the server
// may already have acted on it.
func TestRetryOnFreshIsLimitedToUnwrittenOrIdempotentRequests(t *testing.T) {
	post := []byte("POST /pay HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n")
	get := []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	readEOF := fmt.Errorf("read failed: %w", io.EOF)
	if retryOnFresh(readEOF, post) {
		t.Error("a POST that was written and then met EOF would be resent")
	}
	if !retryOnFresh(readEOF, get) {
		t.Error("a GET that met EOF on a kept connection is not retried")
	}
	if !retryOnFresh(&writeFailure{err: syscall.EPIPE}, post) {
		t.Error("a POST that could not be written at all is not retried")
	}
}

type certRecorder struct {
	hosts  []string
	chains [][]*x509.Certificate
}

func (r *certRecorder) Record(host string, port uint16, chain []*x509.Certificate) {
	r.hosts = append(r.hosts, formatHostPort(host, port))
	r.chains = append(r.chains, chain)
}

// Burp's "Server TLS certificates" (burpsy-react-ui-t75m): the chain a TLS target presents is handed
// to the recorder on the raw path and on the typed path.
func TestTheSenderRecordsTheCertificateATargetPresents(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.HTTP11}, false)
	rec := &certRecorder{}
	cfg := DefaultSenderConfig()
	cfg.TLSVerify = false
	cfg.ServerCerts = rec
	s := NewSender(cfg)
	if _, _, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true, rawGet(srv.host, srv.port), ProtocolPreferenceHTTP1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(context.Background(), &Request{Method: "GET", URL: "https://" + formatHostPort(srv.host, srv.port) + "/typed",
		Host: srv.host, Port: srv.port, TLS: true}); err != nil {
		t.Fatal(err)
	}
	if len(rec.chains) != 2 || len(rec.chains[0]) == 0 || len(rec.chains[1]) == 0 {
		t.Fatalf("recorded %d chain(s) for 2 TLS sends: %v", len(rec.chains), rec.hosts)
	}
	if rec.hosts[0] != formatHostPort(srv.host, srv.port) || !rec.chains[0][0].Equal(rec.chains[1][0]) {
		t.Errorf("hosts %v; the raw and typed paths must record the same leaf", rec.hosts)
	}
}
