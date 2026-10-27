package proxy

// Per-target browser fingerprints on the proxy's upstream leg (63pf-followup). 63pf proved the
// mapping at the alpn seam; these tests pin that the PROXY's upstream dial actually consults the
// bindings - the original gap was that dialUpstreamTLS never set Fingerprint at all, so an
// intercepted session to a bound host still presented Go's ClientHello while Repeater presented
// the browser's.

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// hasGREASE reports whether the offered cipher suites carry a GREASE value (0x?a?a). Go's TLS
// client never offers GREASE; every utls browser preset leads with it, so this is the binary
// "browser hello vs Go hello" signal on the wire.
func hasGREASE(suites []uint16) bool {
	for _, s := range suites {
		if s&0x0f0f == 0x0a0a {
			return true
		}
	}
	return false
}

// startHelloCapturingOrigin runs a TLS listener that records the ClientHello's cipher suites and
// answers one handshake, so a test can see exactly what the upstream leg presented.
func startHelloCapturingOrigin(t *testing.T, cert tls.Certificate) (host string, port uint16, suitesFor func() []uint16) {
	t.Helper()
	var mu sync.Mutex
	var suites []uint16
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			suites = append([]uint16(nil), hello.CipherSuites...)
			mu.Unlock()
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var portNum uint16
	for _, c := range portStr {
		portNum = portNum*10 + uint16(c-'0')
	}
	return host, portNum, func() []uint16 {
		mu.Lock()
		defer mu.Unlock()
		return append([]uint16(nil), suites...)
	}
}

func dialUpstreamForTest(t *testing.T, srv *Server, host string, port uint16) {
	t.Helper()
	conn, _, err := srv.dialUpstreamTLS(host, net.JoinHostPort(host, strconv.Itoa(int(port))), nil)
	if err != nil {
		t.Fatalf("dialUpstreamTLS: %v", err)
	}
	_ = conn.Close()
	// The client's Dial returns when its own flight leaves; give the server a moment to run its
	// side of the handshake before asserting on what it captured.
	time.Sleep(100 * time.Millisecond)
}

func fingerprintingServer(fingerprints *sender.TLSFingerprints) *Server {
	return NewServer(NewProxyConfig(nil).
		WithScope(testScope()).
		WithUpstreamTLS(NewTLSPolicy().WithVerify(false)).
		WithTLSFingerprints(fingerprints))
}

// A host bound to a browser fingerprint reaches the origin with that browser's ClientHello, so an
// intercepted session and a Repeater send to the same host present the same client.
func TestTheUpstreamLegPresentsTheBoundFingerprint(t *testing.T) {
	cert := selfSignedCert(t, "fingerprint.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	host, port, suitesFor := startHelloCapturingOrigin(t, cert)

	bindings := &sender.TLSFingerprints{}
	bindings.Add("*", alpn.FingerprintChrome)
	dialUpstreamForTest(t, fingerprintingServer(bindings), host, port)

	if !hasGREASE(suitesFor()) {
		t.Fatalf("upstream leg offered Go's cipher suites despite a chrome binding: %x", suitesFor())
	}
}

// No bindings means byte-identical to before the option existed: Go's own hello, no GREASE.
func TestTheUpstreamLegDefaultsToTheGoHello(t *testing.T) {
	cert := selfSignedCert(t, "fingerprint.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	host, port, suitesFor := startHelloCapturingOrigin(t, cert)

	dialUpstreamForTest(t, fingerprintingServer(nil), host, port)

	if hasGREASE(suitesFor()) {
		t.Fatalf("an unconfigured upstream leg offered GREASE - something fingerprinted it: %x", suitesFor())
	}
}

// A binding for another host must not leak onto this dial.
func TestANonMatchingBindingLeavesTheGoHello(t *testing.T) {
	cert := selfSignedCert(t, "fingerprint.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	host, port, suitesFor := startHelloCapturingOrigin(t, cert)

	bindings := &sender.TLSFingerprints{}
	bindings.Add("*.other.test", alpn.FingerprintChrome)
	dialUpstreamForTest(t, fingerprintingServer(bindings), host, port)

	if hasGREASE(suitesFor()) {
		t.Fatalf("a binding for *.other.test fingerprinted a dial to %s: %x", host, suitesFor())
	}
}
