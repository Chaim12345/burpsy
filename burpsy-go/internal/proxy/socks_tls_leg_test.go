package proxy

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
	"go.uber.org/zap"
)

// burpsy-react-ui-socks-tls-bypass: dialUpstreamTLS set alpn.Dialer.Carry only when an upstream
// POLICY was configured, so an operator who configured only the global SOCKS carrier — the
// ordinary "I only want a SOCKS hop" case — had every intercepted HTTPS leg dialled straight at
// the origin. alpn.Dialer with no Carry opens its own socket, and the carrier never saw it.
//
// The assertion is traversal, not configuration: the SOCKS server must record the CONNECT for the
// origin, and the origin must have accepted no connection the SOCKS server did not open for it.

// countingTLSOrigin is a TLS origin that counts accepted TCP connections.
func countingTLSOrigin(t *testing.T) (addr string, accepts *atomic.Int64) {
	t.Helper()
	cert := selfSignedCert(t, "carried.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepts = &atomic.Int64{}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_ = conn.Handshake()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
			}()
		}
	}()
	return ln.Addr().String(), accepts
}

func TestAnInterceptedTLSLegGoesThroughACarrierWithNoUpstreamPolicy(t *testing.T) {
	origin, accepts := countingTLSOrigin(t)
	socks := upstreamtest.StartSOCKS5(t, "", "")

	carrier := upstream.NewCarrier()
	if err := carrier.SetSocks("socks5://"+socks.Addr(), nil, false); err != nil {
		t.Fatal(err)
	}
	// No upstream policy at all: the carrier is the only egress setting, which is the case the
	// policy-only gate dropped.
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScopeAllowEverything()).
		WithUpstreamTLS(NewTLSPolicy().WithVerify(false)).
		WithUpstreamCarrier(carrier).
		WithLogger(zap.NewNop()))
	if p := srv.upstreamPolicy(); p != nil && !p.Empty() {
		t.Fatal("test precondition: the proxy must have no upstream policy")
	}

	host, _, _ := net.SplitHostPort(origin)
	conn, _, err := srv.dialUpstreamTLS(host, origin, []string{"http/1.1"})
	if err != nil {
		t.Fatalf("dialUpstreamTLS through the carrier: %v (socks errors: %v)", err, socks.Errors())
	}
	conn.Close()

	if errs := socks.Errors(); len(errs) > 0 {
		t.Fatalf("the SOCKS server could not parse the client: %v", errs)
	}
	connects := len(socks.Requests())
	if !socks.Saw(origin) || connects != 1 {
		t.Fatalf("SOCKS CONNECTs = %v, want exactly one for %s: the intercepted TLS leg bypassed the "+
			"carrier the operator configured", socks.Requests(), origin)
	}
	// Every origin accept must be one the SOCKS server opened. A direct dial would be an extra
	// accept with no matching CONNECT.
	if got := accepts.Load(); got != int64(connects) {
		t.Errorf("origin accepted %d connections for %d SOCKS CONNECTs; %d came direct", got, connects, got-int64(connects))
	}
}

// The other side of the gate: no carrier and no policy still dials directly, so the fix did not
// put an unconfigured proxy on a different path.
func TestAnInterceptedTLSLegWithNoCarrierStillDialsDirect(t *testing.T) {
	origin, accepts := countingTLSOrigin(t)
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScopeAllowEverything()).
		WithUpstreamTLS(NewTLSPolicy().WithVerify(false)).
		WithLogger(zap.NewNop()))
	host, _, _ := net.SplitHostPort(origin)
	conn, _, err := srv.dialUpstreamTLS(host, origin, nil)
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	conn.Close()
	if got := accepts.Load(); got != 1 {
		t.Errorf("origin accepted %d connections, want 1", got)
	}
}
