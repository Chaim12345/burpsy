package proxy

// Selection half of vln3 slice 3: once an origin's advertisement is learned, a later forward to
// that origin rides QUIC and the exchange record says so; when the endpoint does not answer, the
// SAME request falls back to HTTP/1.1 with the attempt and the carrier both on the record
// (integrator ruling A). Never the reverse lie: HTTP/3 is stamped only when QUIC actually
// carried the bytes.

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	core "github.com/burpsy-go/burpsy/internal/core"
)

// startRideH3Server runs an HTTP/3 server on a loopback UDP port and reports what arrives.
func startRideH3Server(t *testing.T) (port uint16, seen <-chan string) {
	t.Helper()
	cert := selfSignedCert(t, "altsvc.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	arrived := make(chan string, 4)
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			arrived <- fmt.Sprintf("%s %s %q", r.Method, r.URL.RequestURI(), body)
			_, _ = w.Write([]byte("rode-h3"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(udp) }()
	t.Cleanup(func() { _ = server.Close(); _ = udp.Close() })
	_, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())
	var portNum uint16
	_, _ = fmt.Sscanf(portStr, "%d", &portNum)
	return portNum, arrived
}

// startAdvertiser runs a TLS origin that answers HTTP/1.1 and advertises the given h3 port.
func startAdvertiser(t *testing.T, h3Port uint16) (host string, port uint16) {
	t.Helper()
	cert := selfSignedCert(t, "altsvc.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=3600`, h3Port))
		_, _ = w.Write([]byte("plain-h1"))
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	host, port = splitHostPort(t, origin.URL)
	return host, port
}

func forwardTwice(t *testing.T, srv *Server, host string, port uint16) forwardResult {
	t.Helper()
	raw := []byte(fmt.Sprintf("POST /ride?q=1 HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\n\r\ntest", host))
	// The first forward is the browser's first visit: HTTP/1.1, and the response teaches the
	// advertisement.
	first, err := srv.forwardRequest(raw, host, port, true)
	if err != nil {
		t.Fatalf("first forwardRequest: %v", err)
	}
	second, err := srv.forwardRequest(raw, host, port, true)
	if err != nil {
		t.Fatalf("second forwardRequest: %v", err)
	}
	_ = first
	return second
}

// A learned advertisement moves the NEXT forward onto QUIC, honestly stamped.
func TestALearnedAdvertisementMovesTheNextForwardOntoQUIC(t *testing.T) {
	h3Port, seen := startRideH3Server(t)
	host, port := startAdvertiser(t, h3Port)
	srv := NewServer(NewProxyConfig(nil).WithScope(testScope()).WithUpstreamTLS(NewTLSPolicy().WithVerify(false)))

	result := forwardTwice(t, srv, host, port)

	if result.protocol != core.ProtocolHTTP3 {
		t.Fatalf("protocol = %v, want HTTP/3 once the advertisement is learned", result.protocol)
	}
	if !strings.Contains(string(result.response), "rode-h3") {
		t.Fatalf("response did not come from the h3 endpoint:\n%s", result.response)
	}
	select {
	case got := <-seen:
		if got != `POST /ride?q=1 "test"` {
			t.Fatalf("the h3 endpoint saw %q, want the request re-expressed as written", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the h3 endpoint never saw the request")
	}
}

// An advertised endpoint that never answers QUIC falls back to HTTP/1.1 in the same request, with
// the attempt and the carrier both named - the ruling-A record.
func TestAnUnansweredQUICAttemptFallsBackWithAnHonestRecord(t *testing.T) {
	// Nothing listens on this UDP port: the advertisement points at a dead endpoint.
	host, port := startAdvertiser(t, 9)
	srv := NewServer(NewProxyConfig(nil).WithScope(testScope()).WithUpstreamTLS(NewTLSPolicy().WithVerify(false)))

	result := forwardTwice(t, srv, host, port)

	if result.protocol != core.ProtocolHTTP1 {
		t.Fatalf("protocol = %v, want HTTP/1.1 after the fallback", result.protocol)
	}
	if !strings.Contains(string(result.response), "plain-h1") {
		t.Fatalf("the fallback did not carry the h1 response:\n%s", result.response)
	}
	if result.note == nil || !strings.Contains(*result.note, "did not answer QUIC") {
		t.Fatalf("note = %v, want the attempt and the fallback named", result.note)
	}
}

// The kill switch off means no attempt even with a live advertisement: the feature is inert.
func TestTheKillSwitchOffRidesNothing(t *testing.T) {
	h3Port, seen := startRideH3Server(t)
	host, port := startAdvertiser(t, h3Port)
	srv := NewServer(NewProxyConfig(nil).WithScope(testScope()).WithUpstreamTLS(NewTLSPolicy().WithVerify(false)))
	srv.config.network.SetHTTP3AltSvc(false)

	// With the switch off the first forward teaches nothing (3a), so the second has nothing to
	// ride: HTTP/1.1, no note, and the h3 endpoint never hears a word.
	result := forwardTwice(t, srv, host, port)
	if result.protocol != core.ProtocolHTTP1 {
		t.Fatalf("protocol = %v with the switch off", result.protocol)
	}
	select {
	case got := <-seen:
		t.Fatalf("the h3 endpoint saw %q with the switch off", got)
	case <-time.After(300 * time.Millisecond):
	}
}
