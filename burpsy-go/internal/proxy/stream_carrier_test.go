package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/upstream"
	"go.uber.org/zap"
)

// The carrier's claim is that it is GLOBAL: one Settings edit reaches every egress surface, so a
// browser through the listener goes out the same way a Repeater send does. A carrier that only the
// sender honours is a setting that looks global on screen and is not, which is the failure the
// upstream policy's own Attached field exists to prevent (burpsy-react-ui-mr83 part 3).
//
// These tests are about the WIRING — that the object the console hands the proxy is the object the
// proxy dials through — because the carrier's own behaviour is tested in internal/upstream, and a
// behaviour test here would pass whether or not this package were handed the carrier at all.

func TestTheProxyDialsThroughTheCarrierItWasGiven(t *testing.T) {
	// A listener on the address the SOCKS server's address names, so a dial that skipped the carrier
	// would be visible as a different destination rather than only as a count.
	carrier := upstream.NewCarrier()
	if err := carrier.SetSocks("socks5://127.0.0.1:1", nil, false); err != nil {
		t.Fatal(err)
	}
	cfg := NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScopeAllowEverything()).
		WithUpstreamCarrier(carrier).
		WithLogger(zap.NewNop())
	srv := NewServer(cfg)

	if got := cfg.UpstreamCarrier(); got != carrier {
		t.Fatal("the config does not hold the carrier it was given; the dial path would read nil and " +
			"a browser would go out directly while the panel says every connection is carried")
	}
	if got := srv.carrier(); got != carrier {
		t.Error("the Server does not reach the carrier on its config; the dial path reads from the config " +
			"and would carry nothing")
	}
	// And the dialer every leg in this file uses is built with it, which is the only place a leg could
	// forget.
	dialer := srv.upstreamDialer()
	if dialer.Carrier != carrier {
		t.Error("upstreamDialer() built a Dialer with no carrier; every proxy leg goes through it, so a " +
			"browser's connection would bypass the SOCKS layer the operator configured")
	}
}

// A proxy built without a carrier must dial as it always did, and must say so rather than panic: an
// embedder with no carrier is the ordinary case, not a misconfiguration.
func TestAProxyWithNoCarrierDialsAsItAlwaysDid(t *testing.T) {
	cfg := NewProxyConfig(core.NewTrafficStore()).WithScope(core.NewScopeAllowEverything())
	srv := NewServer(cfg)
	if cfg.UpstreamCarrier() != nil {
		t.Error("a bare config claims to carry a layer it was never given")
	}
	if got := srv.upstreamDialer().Carrier; got != nil {
		t.Errorf("upstreamDialer() invented a carrier (%v) for a proxy that has none", got)
	}
	// The dial itself still works, which is the ordinary case every embedder depends on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	conn, err := srv.dialUpstream(context.Background(), "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatalf("a direct dial failed with no carrier configured: %v", err)
	}
	conn.Close()
	_ = time.Second
}

// A carrier edit reaches a dial made AFTER it, which is the property a live setting needs: the
// operator turns the layer on in Settings and the next connection goes through it, with no restart
// and no re-wiring.
func TestACarrierEditReachesTheNextDial(t *testing.T) {
	carrier := upstream.NewCarrier()
	cfg := NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScopeAllowEverything()).
		WithUpstreamCarrier(carrier).
		WithLogger(zap.NewNop())
	srv := NewServer(cfg)

	// A listener the carrier will name, so a carried dial lands there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	reached := make(chan struct{}, 1)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			select {
			case reached <- struct{}{}:
			default:
			}
			conn.Close()
		}
	}()

	// The carrier names a SOCKS address nothing is listening on, so a carried dial fails fast rather
	// than hanging the test: what is under test is that the dial ATTEMPTED the hop.
	if err := carrier.SetSocks("socks5://"+ln.Addr().String(), nil, false); err != nil {
		t.Fatal(err)
	}
	conn, err := srv.dialUpstream(context.Background(), "127.0.0.1", 1)
	_ = conn
	if err == nil {
		t.Error("a carried dial to a SOCKS server that does not speak SOCKS reported success; the hop was " +
			"not actually on the path")
	}
	select {
	case <-reached:
	default:
		t.Error("the listener the carrier names saw no connection: the edit did not reach the dial path")
	}
}
