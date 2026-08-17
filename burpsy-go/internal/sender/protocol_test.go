package sender

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/core"
)

// Test support: two shapes of TLS server, both counting ClientHellos.
//
// The handshake count is the load-bearing number in several of these tests, and it is counted on the
// *server* side on purpose: a client-side counter would prove only that our own bookkeeping agrees with
// itself, which is exactly the claim under test.

// alpnServer is an httptest server that can actually serve h2, for the tests that need a real HTTP/2
// exchange rather than recorded bytes.
type alpnServer struct {
	host   string
	port   uint16
	hellos atomic.Int64
	served atomic.Int64
	mu     sync.Mutex
	protos []string
}

// startALPNServer starts a TLS server offering exactly protos. enableH2 wires httptest's own h2 support,
// without which an "h2" offer would negotiate a protocol nothing serves.
func startALPNServer(t *testing.T, protos []string, enableH2 bool) *alpnServer {
	t.Helper()
	s := &alpnServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.served.Add(1)
		s.mu.Lock()
		s.protos = append(s.protos, r.Proto)
		s.mu.Unlock()
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = enableH2
	srv.TLS = &tls.Config{
		NextProtos: protos,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			s.hellos.Add(1)
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("server address: %v", err)
	}
	s.host, s.port = host, port
	return s
}

// lastProto is the protocol the server saw on its most recent request.
func (s *alpnServer) lastProto(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.protos) == 0 {
		t.Fatal("the server was never reached")
	}
	return s.protos[len(s.protos)-1]
}

// recordingServer is a raw TLS listener that keeps the exact request bytes it was sent, for the tests that
// are about byte fidelity rather than about an HTTP exchange.
type recordingServer struct {
	host   string
	port   uint16
	hellos atomic.Int64
	mu     sync.Mutex
	got    []string
}

func startRecordingServer(t *testing.T, protos []string) *recordingServer {
	t.Helper()
	s := &recordingServer{}
	base := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	// Borrow httptest's certificate rather than minting one: it is the certificate the sender's tests
	// already trust with TLSVerify off, and generating a second one here would test the generator.
	base.StartTLS()
	cert := base.TLS.Certificates
	base.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg := &tls.Config{
		Certificates: cert,
		NextProtos:   protos,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			s.hellos.Add(1)
			return nil, nil
		},
	}
	tlsLn := tls.NewListener(ln, cfg)
	t.Cleanup(func() { tlsLn.Close() })
	host, port, err := hostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("listener address: %v", err)
	}
	s.host, s.port = host, port
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				head := ""
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					head += line
					if strings.HasSuffix(head, "\r\n\r\n") {
						break
					}
				}
				s.mu.Lock()
				s.got = append(s.got, head)
				s.mu.Unlock()
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()
	return s
}

func (s *recordingServer) lastRequest(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.got) == 0 {
		t.Fatal("the server received nothing")
	}
	return s.got[len(s.got)-1]
}

// testSender is a sender with certificate verification off, because every server here uses httptest's
// self-signed certificate.
func testSender() *Sender {
	cfg := DefaultSenderConfig()
	cfg.TLSVerify = false
	// Short, because several of these probes are requests a server will never answer — an unterminated
	// header section, a Content-Length that outruns the body — and the claim under test is what protocol
	// carried them, not what came back. The default 30s would spend it waiting for silence. 500ms, not
	// merely "shorter than 30s", because every server in this file is an httptest loopback listener:
	// a real response is on the wire in microseconds, so this is headroom, not a race against a
	// server that might still be about to answer. Three subtests in
	// TestSendRawKeepsAProbeOnHTTP11AndNamesTheConstruct construct exactly this kind of hang, and at
	// 2s each they were three quarters of this package's wall time.
	cfg.Timeout = 500 * time.Millisecond
	return NewSender(cfg)
}

// rawGet is an ordinary origin-form HTTP/1.1 request, the shape the intruder and the crawler produce.
func rawGet(host string, port uint16) []byte {
	return []byte("GET /probe HTTP/1.1\r\nHost: " + formatHostPort(host, port) + "\r\n\r\n")
}

func formatHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// H2-04: a request the tool constructed itself reaches an h2 target over h2.
func TestSendRawUsesHTTP2WhenTheTargetNegotiatesIt(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	s := testSender()

	resp, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := srv.lastProto(t); got != "HTTP/2.0" {
		t.Fatalf("the target served %s, so the request did not go out as h2", got)
	}
	if outcome.Protocol != core.ProtocolHTTP2 {
		t.Fatalf("outcome says %v, want HTTP/2", outcome.Protocol)
	}
	if outcome.Downgraded() {
		t.Fatalf("an h2 send must carry no downgrade, got %v", outcome.Downgrade)
	}
	if outcome.Negotiated != alpn.H2 {
		t.Fatalf("negotiated %q, want h2", outcome.Negotiated)
	}
	if !strings.HasPrefix(string(resp), "HTTP/2 200") {
		t.Fatalf("response was not rendered as h2: %q", firstLine(resp))
	}
	if rep := s.Protocols(); rep.SentAsHTTP2 != 1 || rep.SentAsHTTP1 != 0 {
		t.Fatalf("report should count one h2 send, got %+v", rep.Summary())
	}
}

// H2-04: a downgrade is reported, never silent — the target declined h2.
func TestSendRawReportsTheDowngradeWhenTheTargetChoosesHTTP11(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.HTTP11}, false)
	s := testSender()

	_, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if outcome.Protocol != core.ProtocolHTTP1 || !outcome.Downgraded() {
		t.Fatalf("want a reported HTTP/1.1 send, got %+v", outcome)
	}
	if outcome.Downgrade.Reason != DowngradeNegotiatedHTTP11 {
		t.Fatalf("want DowngradeNegotiatedHTTP11, got %v", outcome.Downgrade)
	}
	if got := srv.lastProto(t); got != "HTTP/1.1" {
		t.Fatalf("target served %s", got)
	}
	rep := s.Protocols()
	if rep.SentAsHTTP1 != 1 {
		t.Fatalf("want one HTTP/1.1 send counted, got %+v", rep)
	}
	if got := rep.Downgrades[DowngradeNegotiatedHTTP11.slot()].Count; got != 1 {
		t.Fatalf("the reason itself must be counted, got %d", got)
	}
}

// H2-04: a peer that never answers the ALPN question is a different report from one that declined.
func TestSendRawReportsTheDowngradeWhenTheTargetOffersNoALPN(t *testing.T) {
	srv := startALPNServer(t, []string{}, false)
	s := testSender()

	_, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !outcome.Downgraded() || outcome.Downgrade.Reason != DowngradeNoALPN {
		t.Fatalf("want DowngradeNoALPN, got %+v", outcome)
	}
	if outcome.Negotiated != "" {
		t.Fatalf("negotiated %q, want nothing", outcome.Negotiated)
	}
}

// H2-04: the h2c decision, stated as a test. A plaintext target has no ALPN, so the send is HTTP/1.1 and
// says so rather than guessing at prior knowledge.
func TestSendRawReportsTheDowngradeOnAPlaintextTargetRatherThanGuessingH2c(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("server address: %v", err)
	}
	s := testSender()

	_, outcome, err := s.SendRawOutcome(context.Background(), host, port, false,
		rawGet(host, port), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !outcome.Downgraded() || outcome.Downgrade.Reason != DowngradePlaintextTarget {
		t.Fatalf("want DowngradePlaintextTarget, got %+v", outcome)
	}
	// A cleartext authority is answered without a handshake, and is not recorded as an observed one.
	if rep := s.Protocols(); len(rep.Authorities) != 0 {
		t.Fatalf("a cleartext send must record no negotiated authority, got %+v", rep.Authorities)
	}
}

// H2-04: the upgrade never changes what is being asked. One case per construct, each naming itself.
func TestSendRawKeepsAProbeOnHTTP11AndNamesTheConstruct(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2, alpn.HTTP11}, true)
	authority := formatHostPort(srv.host, srv.port)
	cases := []struct {
		name string
		raw  string
		want DowngradeReason
	}{
		{"transfer-encoding", "GET /p HTTP/1.1\r\nHost: " + authority + "\r\nTransfer-Encoding: chunked\r\n\r\n", DowngradeTransferEncoding},
		{"upgrade", "GET /p HTTP/1.1\r\nHost: " + authority + "\r\nUpgrade: websocket\r\n\r\n", DowngradeUpgradeHeader},
		{"te-not-trailers", "GET /p HTTP/1.1\r\nHost: " + authority + "\r\nTE: gzip\r\n\r\n", DowngradeTEOtherThanTrailers},
		{"duplicate-content-length", "POST /p HTTP/1.1\r\nHost: " + authority + "\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx", DowngradeDuplicateContentLength},
		{"unreadable-content-length", "POST /p HTTP/1.1\r\nHost: " + authority + "\r\nContent-Length: 5 5\r\n\r\nx", DowngradeContentLengthUnreadable},
		{"content-length-disagrees", "POST /p HTTP/1.1\r\nHost: " + authority + "\r\nContent-Length: 9\r\n\r\nx", DowngradeContentLengthDisagreesWithBody},
		{"http-1.0", "GET /p HTTP/1.0\r\nHost: " + authority + "\r\n\r\n", DowngradeHTTP10RequestLine},
		{"connect", "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n", DowngradeConnectMethod},
		{"absolute-form", "GET http://" + authority + "/p HTTP/1.1\r\nHost: " + authority + "\r\n\r\n", DowngradeNonOriginFormTarget},
		{"asterisk-form", "OPTIONS * HTTP/1.1\r\nHost: " + authority + "\r\n\r\n", DowngradeNonOriginFormTarget},
		{"no-host", "GET /p HTTP/1.1\r\nAccept: */*\r\n\r\n", DowngradeNoHostHeader},
		{"duplicate-host", "GET /p HTTP/1.1\r\nHost: " + authority + "\r\nHost: evil.test\r\n\r\n", DowngradeDuplicateHostHeader},
		{"header-line-without-colon", "GET /p HTTP/1.1\r\nHost: " + authority + "\r\nBroken\r\n\r\n", DowngradeHeaderLineUnreadable},
		{"field-name-with-space", "GET /p HTTP/1.1\r\nHost: " + authority + "\r\nX Bad: 1\r\n\r\n", DowngradeForbiddenFieldOctet},
		{"request-line-unreadable", "GET /p\r\nHost: " + authority + "\r\n\r\n", DowngradeRequestLineUnreadable},
		{"unknown-version", "GET /p HTTP/3.0\r\nHost: " + authority + "\r\n\r\n", DowngradeRequestLineUnreadable},
		{"headers-not-terminated", "GET /p HTTP/1.1\r\nHost: " + authority + "\r\n", DowngradeHeadersNotTerminated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testSender()
			_, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
				[]byte(tc.raw), ProtocolPreferenceAuto)
			// Some of these are requests a Go HTTP/1.1 server rejects or never answers; the claim under
			// test is which protocol carried them and what was reported, not what came back.
			_ = err
			if outcome.Protocol != core.ProtocolHTTP1 {
				t.Fatalf("%s went out as %v", tc.name, outcome.Protocol)
			}
			if !outcome.Downgraded() {
				t.Fatalf("%s was downgraded silently", tc.name)
			}
			if outcome.Downgrade.Reason != tc.want {
				t.Fatalf("%s reported %v, want %v", tc.name, outcome.Downgrade, tc.want.Explanation())
			}
		})
	}
}

// H2-04: the refused upgrade really does put the operator's own bytes on the wire.
func TestARefusedUpgradeSendsTheBytesVerbatim(t *testing.T) {
	srv := startRecordingServer(t, []string{alpn.H2, alpn.HTTP11})
	s := testSender()
	raw := "POST /smuggle HTTP/1.1\r\nHost: " + formatHostPort(srv.host, srv.port) +
		"\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"

	_, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		[]byte(raw), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if outcome.Downgrade == nil || outcome.Downgrade.Reason != DowngradeTransferEncoding {
		t.Fatalf("want the Transfer-Encoding construct named, got %+v", outcome)
	}
	got := srv.lastRequest(t)
	if !strings.Contains(got, "Transfer-Encoding: chunked") || !strings.Contains(got, "Content-Length: 6") {
		t.Fatalf("the probe was not delivered as written:\n%q", got)
	}
	if !strings.HasPrefix(got, "POST /smuggle HTTP/1.1\r\n") {
		t.Fatalf("request line was rewritten: %q", firstLine([]byte(got)))
	}
}

// H2-04: the cache tells "not yet known" apart from "known to be HTTP/1.1".
func TestTheProtocolCacheTellsNotYetKnownFromHTTP11(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.HTTP11}, false)
	s := testSender()

	if got := s.KnownProtocol(srv.host, srv.port, true); got != ProtocolSupportUnknown {
		t.Fatalf("before any handshake the answer must be unknown, got %v", got)
	}
	if got := ProtocolSupportUnknown.String(); got != "not yet known" {
		t.Fatalf("unknown must render as itself, got %q", got)
	}
	if _, _, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceAuto); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := s.KnownProtocol(srv.host, srv.port, true); got != ProtocolSupportHTTP11 {
		t.Fatalf("after an h2-offering handshake that chose http/1.1, want HTTP11, got %v", got)
	}
	// A different port on the same host is a different authority and is still unknown.
	if got := s.KnownProtocol(srv.host, srv.port+1, true); got != ProtocolSupportUnknown {
		t.Fatalf("another authority must stay unknown, got %v", got)
	}
}

// H2-04: a probe that cannot be carried over h2 offers http/1.1 alone, so its own handshake says nothing
// about h2 — and the cache must not turn our choice into a claim about the target.
func TestAnHTTP11OnlyOfferTeachesTheCacheNothing(t *testing.T) {
	srv := startRecordingServer(t, []string{alpn.H2, alpn.HTTP11})
	s := testSender()
	raw := "GET /p HTTP/1.1\r\nHost: " + formatHostPort(srv.host, srv.port) +
		"\r\nTransfer-Encoding: chunked\r\n\r\n"

	if _, _, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		[]byte(raw), ProtocolPreferenceAuto); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := s.KnownProtocol(srv.host, srv.port, true); got != ProtocolSupportUnknown {
		t.Fatalf("want the authority still unknown, got %v", got)
	}
}

// H2-04: the cache does not re-handshake to answer the same question.
func TestTheProtocolCacheDoesNotRehandshake(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	s := testSender()

	for i := 0; i < 3; i++ {
		got, err := s.ProtocolFor(context.Background(), srv.host, srv.port, true)
		if err != nil {
			t.Fatalf("discovery %d: %v", i, err)
		}
		if got != ProtocolSupportH2 {
			t.Fatalf("discovery %d says %v", i, got)
		}
	}
	if got := srv.hellos.Load(); got != 1 {
		t.Fatalf("three lookups caused %d handshakes, want 1", got)
	}
	rep := s.Protocols()
	if rep.DiscoveryHandshakes != 1 || rep.CacheHits != 2 {
		t.Fatalf("want 1 discovery handshake and 2 cache hits, got %+v", rep)
	}
}

// H2-04: a send never handshakes for discovery — it learns from the connection it needed anyway.
func TestSendsDoNotHandshakeForDiscovery(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	s := testSender()

	for i := 0; i < 3; i++ {
		if _, _, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
			rawGet(srv.host, srv.port), ProtocolPreferenceAuto); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if got := srv.hellos.Load(); got != 3 {
		t.Fatalf("three sends caused %d handshakes, want exactly one each", got)
	}
	if rep := s.Protocols(); rep.DiscoveryHandshakes != 0 {
		t.Fatalf("sends must not count as discovery, got %d", rep.DiscoveryHandshakes)
	}
}

// H2-04: pinning HTTP/1.1 is a protocol choice, and it is still reported.
func TestPinningHTTP11IsReportedRatherThanSilent(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2, alpn.HTTP11}, true)
	s := testSender()

	_, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceHTTP1)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !outcome.Downgraded() || outcome.Downgrade.Reason != DowngradePinnedByCaller {
		t.Fatalf("want DowngradePinnedByCaller, got %+v", outcome)
	}
	if got := srv.lastProto(t); got != "HTTP/1.1" {
		t.Fatalf("pinned send arrived as %s", got)
	}
}

// H2-04: h2-shaped bytes at a target that will not speak h2 go out as HTTP/1.1 and say so, rather than
// failing the handshake the way an h2-only offer used to.
func TestH2ShapedBytesDowngradeRatherThanFailingTheHandshake(t *testing.T) {
	srv := startRecordingServer(t, []string{alpn.HTTP11})
	s := testSender()
	raw := "GET /h2path HTTP/2\r\nHost: " + formatHostPort(srv.host, srv.port) + "\r\nAccept: */*\r\n\r\n"

	_, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		[]byte(raw), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !outcome.Downgraded() || outcome.Downgrade.Reason != DowngradeNegotiatedHTTP11 {
		t.Fatalf("want DowngradeNegotiatedHTTP11, got %+v", outcome)
	}
	got := srv.lastRequest(t)
	if !strings.HasPrefix(got, "GET /h2path HTTP/1.1\r\n") {
		t.Fatalf("want an HTTP/1.1 rendering, got %q", firstLine([]byte(got)))
	}
	if !strings.Contains(got, "Host: "+formatHostPort(srv.host, srv.port)) {
		t.Fatalf("the authority was lost in translation:\n%q", got)
	}
}

// H2-04: an upgrade that drops a connection-management header says which one.
func TestHopByHopFieldsAreDroppedAndReported(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	s := testSender()
	raw := "GET /p HTTP/1.1\r\nHost: " + formatHostPort(srv.host, srv.port) +
		"\r\nConnection: keep-alive\r\nUser-Agent: burpsy\r\n\r\n"

	_, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		[]byte(raw), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if outcome.Protocol != core.ProtocolHTTP2 {
		t.Fatalf("an ordinary browser-shaped request must still reach h2, got %v", outcome.Protocol)
	}
	var dropped, lowered []string
	for _, rw := range outcome.Rewrites {
		switch rw.Kind {
		case RewriteHopFieldDropped:
			dropped = append(dropped, rw.Field)
		case RewriteFieldNameLowercased:
			lowered = append(lowered, rw.Field)
		}
	}
	if len(dropped) != 1 || dropped[0] != "Connection" {
		t.Fatalf("want Connection reported as dropped, got %v", dropped)
	}
	if len(lowered) != 2 {
		t.Fatalf("want both canonical field names reported as lowercased, got %v", lowered)
	}
	rep := s.Protocols()
	if rep.Rewrites[RewriteHopFieldDropped.slot()].Count != 1 {
		t.Fatalf("the drop must be counted, got %+v", rep.Rewrites)
	}
}

// H2-04: the scanner's path. Sender.Send builds its own request, so it was already h2-capable through the
// stdlib transport — what was missing is that nothing said which protocol carried it.
func TestTheTypedPathReportsTheProtocolItUsed(t *testing.T) {
	h2 := startALPNServer(t, []string{alpn.H2}, true)
	s := testSender()
	resp, err := s.Send(context.Background(), &Request{
		Method: "GET", Host: h2.host, Port: h2.port, Path: "/typed", TLS: true,
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Outcome.Protocol != core.ProtocolHTTP2 || resp.Outcome.Downgraded() {
		t.Fatalf("want a reported h2 send, got %+v", resp.Outcome)
	}
	if resp.Version != "HTTP/2.0" {
		t.Fatalf("stdlib says %q", resp.Version)
	}
	if got := s.KnownProtocol(h2.host, h2.port, true); got != ProtocolSupportH2 {
		t.Fatalf("the typed path must teach the cache too, got %v", got)
	}

	h1 := startALPNServer(t, []string{alpn.HTTP11}, false)
	resp, err = s.Send(context.Background(), &Request{
		Method: "GET", Host: h1.host, Port: h1.port, Path: "/typed", TLS: true,
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !resp.Outcome.Downgraded() || resp.Outcome.Downgrade.Reason != DowngradeNegotiatedHTTP11 {
		t.Fatalf("want the downgrade named, got %+v", resp.Outcome)
	}
}

// H2-04: the authorised chokepoint carries the outcome, so an intruder run can report what it travelled
// over.
func TestTheAuthorisedSenderCarriesTheOutcome(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	a := NewAuthorisedSender(core.NewScope(), testSender(), srv.host, srv.port, true)

	res, err := a.Send(context.Background(), rawGet(srv.host, srv.port))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Outcome.Protocol != core.ProtocolHTTP2 {
		t.Fatalf("want h2, got %+v", res.Outcome)
	}
	pinned, err := a.SendAs(context.Background(), rawGet(srv.host, srv.port), ProtocolPreferenceHTTP1)
	if err != nil {
		t.Fatalf("pinned send: %v", err)
	}
	if !pinned.Outcome.Downgraded() || pinned.Outcome.Downgrade.Reason != DowngradePinnedByCaller {
		t.Fatalf("want the pin reported, got %+v", pinned.Outcome)
	}
	// The pin changes the protocol and nothing else: the scope gate still ran on both sends.
	if a.Sent() != 2 || a.Refused() != 0 {
		t.Fatalf("counters say sent=%d refused=%d", a.Sent(), a.Refused())
	}
}

// H2-04: every HTTP/1.1 send carries a reason, so the per-reason counts add up to the HTTP/1.1 total.
// This is the invariant that makes the report countable rather than indicative.
func TestEveryHTTP11SendIsCountedAgainstExactlyOneReason(t *testing.T) {
	h1 := startALPNServer(t, []string{alpn.HTTP11}, false)
	dual := startALPNServer(t, []string{alpn.H2, alpn.HTTP11}, true)
	s := testSender()
	ctx := context.Background()

	if _, _, err := s.SendRawOutcome(ctx, h1.host, h1.port, true, rawGet(h1.host, h1.port), ProtocolPreferenceAuto); err != nil {
		t.Fatalf("h1 send: %v", err)
	}
	if _, _, err := s.SendRawOutcome(ctx, dual.host, dual.port, true, rawGet(dual.host, dual.port), ProtocolPreferenceHTTP1); err != nil {
		t.Fatalf("pinned send: %v", err)
	}
	if _, _, err := s.SendRawOutcome(ctx, dual.host, dual.port, true, rawGet(dual.host, dual.port), ProtocolPreferenceAuto); err != nil {
		t.Fatalf("h2 send: %v", err)
	}

	rep := s.Protocols()
	var summed uint64
	for _, d := range rep.Downgrades {
		summed += d.Count
	}
	if summed != rep.SentAsHTTP1 {
		t.Fatalf("reasons sum to %d but %d sends went out as HTTP/1.1", summed, rep.SentAsHTTP1)
	}
	if rep.SentAsHTTP1 != 2 || rep.SentAsHTTP2 != 1 {
		t.Fatalf("want two HTTP/1.1 sends and one h2 send, got %s", rep.Summary())
	}
	if len(rep.Authorities) != 2 {
		t.Fatalf("want both authorities recorded, got %+v", rep.Authorities)
	}
}

// The vocabulary itself: every reason and rewrite must be explainable and must own exactly one counter
// slot, so a reason added later cannot silently share another's count.
func TestEveryDowngradeReasonIsExplainableAndOwnsOneSlot(t *testing.T) {
	seenSlots := map[int]DowngradeReason{}
	seenText := map[string]DowngradeReason{}
	for _, r := range DowngradeReasonAll {
		text := r.Explanation()
		if text == "" || strings.Contains(text, "unrecognised") {
			t.Fatalf("reason %d has no explanation", int(r))
		}
		if other, dup := seenText[text]; dup {
			t.Fatalf("reasons %d and %d share an explanation", int(other), int(r))
		}
		seenText[text] = r
		slot := r.slot()
		if other, dup := seenSlots[slot]; dup {
			t.Fatalf("reasons %d and %d share slot %d", int(other), int(r), slot)
		}
		seenSlots[slot] = r
	}
	if len(seenSlots) != len(DowngradeReasonAll) {
		t.Fatalf("%d reasons hold %d slots", len(DowngradeReasonAll), len(seenSlots))
	}
	for _, k := range RewriteKindAll {
		if text := k.Explanation(); text == "" || strings.Contains(text, "unrecognised") {
			t.Fatalf("rewrite %d has no explanation", int(k))
		}
	}
	for _, p := range ProtocolSupportAll {
		if got := p.String(); got == "" || strings.Contains(got, "unrecognised") {
			t.Fatalf("support state %d does not render", int(p))
		}
	}
}

// An HTTP/1.1 outcome with no downgrade would be a silent one, so the constructor cannot make one.
func TestAnHTTP11OutcomeAlwaysCarriesADowngrade(t *testing.T) {
	out := newOutcome("", ProtocolSupportUnknown, nil, nil, nil)
	if out.Protocol != core.ProtocolHTTP2 || out.Downgraded() {
		t.Fatalf("no downgrade must mean h2, got %+v", out)
	}
	out = newOutcome(alpn.HTTP11, ProtocolSupportHTTP11, &Downgrade{Reason: DowngradeNoALPN}, nil, nil)
	if out.Protocol != core.ProtocolHTTP1 || !out.Downgraded() {
		t.Fatalf("a downgrade must mean HTTP/1.1, got %+v", out)
	}
	if out.Downgrade.String() == "" {
		t.Fatal("a downgrade must render")
	}
}

// String on a Downgrade names its detail only when the reason has one.
func TestADowngradeRendersItsDetailOnlyWhenItHasOne(t *testing.T) {
	plain := Downgrade{Reason: DowngradePlaintextTarget}
	if strings.Contains(plain.String(), "(") {
		t.Fatalf("a detail-less reason must not print an empty detail: %q", plain)
	}
	detailed := Downgrade{Reason: DowngradeForbiddenFieldOctet, Detail: "X Bad"}
	if !strings.Contains(detailed.String(), "X Bad") {
		t.Fatalf("want the field named, got %q", detailed)
	}
}

func firstLine(b []byte) string {
	if i := strings.Index(string(b), "\r\n"); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// An h2 send carries the rendering a capture site should store, because storing the caller's HTTP/1.1 bytes
// beside an "HTTP/2 200" response would record two halves of different exchanges.
func TestAnH2SendCarriesTheRequestAsItWentOut(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	s := testSender()

	_, outcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(outcome.Rendered) == 0 {
		t.Fatal("an h2 send must carry its rendering")
	}
	if got := firstLine(outcome.Rendered); got != "GET /probe HTTP/2" {
		t.Fatalf("want the h2-shaped request line, got %q", got)
	}
	if !strings.Contains(string(outcome.Rendered), "Host: "+formatHostPort(srv.host, srv.port)) {
		t.Fatalf("want the authority carried:\n%s", outcome.Rendered)
	}

	// An HTTP/1.1 send carries none, because the caller's own bytes are already what went on the wire.
	_, pinned, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceHTTP1)
	if err != nil {
		t.Fatalf("pinned send: %v", err)
	}
	if pinned.Rendered != nil {
		t.Fatalf("an HTTP/1.1 send must carry no rendering, got %q", pinned.Rendered)
	}
}
