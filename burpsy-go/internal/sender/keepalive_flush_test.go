package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/upstream"
)

// The upstream proxy policy and the client-certificate store are both live objects: the
// network settings screens mutate them in place, and the next dial honours the new rule
// immediately. A pooled keep-alive connection was dialled under whatever route and identity
// were configured at dial time, so a rule that changes afterwards must not see that
// connection reused - a request the operator aimed at the new proxy would leave through the
// old one, or reach the server without the client certificate the operator just bound.
func Test_a_pooled_connection_is_not_reused_after_its_upstream_route_changes(t *testing.T) {
	policy := upstream.NewPolicy()

	config := DefaultSenderConfig()
	config.Upstream = policy
	config.TLSVerify = false

	s := NewSender(config)
	n := s.Network()
	n.HTTP1 = &HTTP1Settings{EnableKeepAlive: true}
	n.HTTP2 = &HTTP2Settings{EnableHTTP2: false}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}

	target := startConnCounting(t, true, []string{alpn.HTTP11}, okHandler)
	raw := rawGet(target.host, target.port)

	sendOnce := func() error {
		resp, _, err := s.SendRawOutcome(context.Background(), target.host, target.port, true, raw, ProtocolPreferenceAuto)
		if err != nil {
			return err
		}
		if !strings.HasSuffix(string(resp), "ok") {
			t.Fatalf("send answered %q", resp)
		}
		return nil
	}

	for i := 0; i < 2; i++ {
		if err := sendOnce(); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if got := target.conns.Load(); got != 1 {
		t.Fatalf("two sends opened %d connections, want one kept alive", got)
	}

	// A rule that does not match this authority must not disturb its pool entry.
	if _, err := policy.Set("other.example", "http://127.0.0.1:1"); err != nil {
		t.Fatalf("setting an unrelated upstream rule: %v", err)
	}
	if err := sendOnce(); err != nil {
		t.Fatalf("a rule for another authority broke this send: %v", err)
	}
	if got := target.conns.Load(); got != 1 {
		t.Fatalf("an unrelated rule dropped the pooled connection; %d connections opened", got)
	}

	// Now aim this authority at an unreachable proxy. The pooled connection was dialled
	// direct, so the next send has to follow the new route and fail - reusing the old
	// connection would silently bypass the proxy the operator just configured.
	if _, err := policy.Set("*", "http://127.0.0.1:1"); err != nil {
		t.Fatalf("setting the wildcard upstream rule: %v", err)
	}
	if err := sendOnce(); err == nil {
		t.Fatal("after the upstream route changed, the send still went through the pooled connection dialled under the old route")
	}
	if got := target.conns.Load(); got != 1 {
		t.Fatalf("the failed send still reached the origin; %d connections opened", got)
	}

	// Removing the rule restores the direct route, which is itself a route change: the next
	// send must dial fresh rather than resurrect the old-route entry.
	if !policy.Remove("*") {
		t.Fatal("the wildcard rule just set was not there to remove")
	}
	if err := sendOnce(); err != nil {
		t.Fatalf("the send through the restored direct route failed: %v", err)
	}
	if got := target.conns.Load(); got != 2 {
		t.Fatalf("restoring the direct route opened %d connections, want one fresh dial", got)
	}
}

// The client-certificate side of the same contract: binding or unbinding a certificate for
// a host changes what the handshake presents, so a connection opened before the change must
// not answer a request sent after it.
func Test_a_pooled_connection_is_not_reused_after_its_client_certificate_changes(t *testing.T) {
	certs := netauth.NewClientCerts()

	config := DefaultSenderConfig()
	config.ClientCerts = certs
	config.TLSVerify = false

	s := NewSender(config)
	n := s.Network()
	n.HTTP1 = &HTTP1Settings{EnableKeepAlive: true}
	n.HTTP2 = &HTTP2Settings{EnableHTTP2: false}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var presented [][]byte

	target := &connCountingServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(okHandler))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			target.conns.Add(1)
		}
	}
	srv.TLS = &tls.Config{
		// The server asks for a certificate but accepts its absence, so the connection
		// pooled before any binding exists stays legal; VerifyPeerCertificate runs on
		// every handshake with whatever the client presented, empty or not.
		ClientAuth: tls.RequestClientCert,
		NextProtos: []string{alpn.HTTP11},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			mu.Lock()
			defer mu.Unlock()
			if len(rawCerts) == 0 {
				presented = append(presented, nil)
			} else {
				presented = append(presented, rawCerts[0])
			}
			return nil
		},
	}
	srv.StartTLS()
	defer srv.Close()
	target.srv = srv
	var err error
	target.host, target.port, err = hostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	raw := rawGet(target.host, target.port)
	sendOnce := func() {
		t.Helper()
		resp, _, err := s.SendRawOutcome(context.Background(), target.host, target.port, true, raw, ProtocolPreferenceAuto)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		if !strings.HasSuffix(string(resp), "ok") {
			t.Fatalf("send answered %q", resp)
		}
	}

	sendOnce()
	sendOnce()
	if got := target.conns.Load(); got != 1 {
		t.Fatalf("two sends opened %d connections, want one kept alive", got)
	}

	identity, leafDER := generateClientIdentity(t)
	certs.Add(identity)
	sendOnce()
	if got := target.conns.Load(); got != 2 {
		t.Fatalf("binding a certificate did not force a fresh dial; %d connections opened", got)
	}
	mu.Lock()
	if len(presented) != 2 || len(presented[1]) == 0 {
		mu.Unlock()
		t.Fatalf("handshakes observed: %d; the fresh dial presented no certificate", len(presented))
	}
	if !bytes.Equal(presented[1], leafDER) {
		t.Error("the fresh dial presented a different certificate than the one just bound")
	}
	mu.Unlock()

	certs.Remove("127.0.0.1")
	sendOnce()
	if got := target.conns.Load(); got != 3 {
		t.Fatalf("unbinding the certificate did not force a fresh dial; %d connections opened", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(presented) != 3 || len(presented[2]) != 0 {
		t.Fatal("the dial after unbinding still presented a certificate")
	}
}
