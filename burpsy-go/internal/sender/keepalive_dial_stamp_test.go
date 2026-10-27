package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/upstream"
)

// burpsy-react-ui-o388 (reopened): the pool stamp must name what the connection was dialled
// under, not what is configured when its response comes back. These tests hold a fresh
// connection's first exchange open, change the route or the client certificate while it is
// in flight, and then check the NEXT send: the connection was dialled under the old
// configuration, so handing it to a send under the new one would leave through the old
// proxy, or without the certificate the operator just bound.

// midExchangeSender builds a keep-alive sender and a target whose handler holds the first
// exchange open until told to finish, so the test can change configuration mid-flight.
type midExchange struct {
	target  *connCountingServer
	arrived chan struct{}
	release chan struct{}
	once    sync.Once
}

func newMidExchange(t *testing.T, useTLS bool) *midExchange {
	t.Helper()
	m := &midExchange{arrived: make(chan struct{}), release: make(chan struct{})}
	protos := []string{alpn.HTTP11}
	if !useTLS {
		protos = nil
	}
	m.target = startConnCounting(t, useTLS, protos, func(w http.ResponseWriter, _ *http.Request) {
		m.once.Do(func() { close(m.arrived) })
		<-m.release
		_, _ = w.Write([]byte("ok"))
	})
	return m
}

func keepAliveSenderFor(t *testing.T, config *SenderConfig) *Sender {
	t.Helper()
	s := NewSender(config)
	n := s.Network()
	n.HTTP1 = &HTTP1Settings{EnableKeepAlive: true}
	n.HTTP2 = &HTTP2Settings{EnableHTTP2: false}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}
	return s
}

// sendHeldOpen runs one send against the blocking target, applies change while the exchange
// is in flight, and lets the response through. The send itself must succeed.
func (m *midExchange) sendHeldOpen(t *testing.T, s *Sender, useTLS bool, change func()) {
	t.Helper()
	raw := rawGet(m.target.host, m.target.port)
	sendErr := make(chan error, 1)
	go func() {
		resp, _, err := s.SendRawOutcome(context.Background(), m.target.host, m.target.port, useTLS, raw, ProtocolPreferenceAuto)
		if err == nil && !strings.HasSuffix(string(resp), "ok") {
			err = fmt.Errorf("send answered %q", resp)
		}
		sendErr <- err
	}()
	// The handler being entered means the dial completed and the request is on the wire.
	<-m.arrived
	change()
	close(m.release)
	if err := <-sendErr; err != nil {
		t.Fatalf("the in-flight send: %v", err)
	}
}

func Test_a_connection_returned_after_a_mid_exchange_route_change_keeps_its_dialled_route(t *testing.T) {
	for _, useTLS := range []bool{true, false} {
		t.Run(map[bool]string{true: "tls", false: "cleartext"}[useTLS], func(t *testing.T) {
			policy := upstream.NewPolicy()
			config := DefaultSenderConfig()
			config.Upstream = policy
			config.TLSVerify = false
			s := keepAliveSenderFor(t, config)
			m := newMidExchange(t, useTLS)

			// The dial has happened (the request reached the target) and the exchange is
			// still open when the operator aims this authority at an unreachable proxy.
			m.sendHeldOpen(t, s, useTLS, func() {
				if _, err := policy.Set("*", "http://127.0.0.1:1"); err != nil {
					t.Fatalf("setting the wildcard upstream rule: %v", err)
				}
			})

			// The pooled connection was dialled direct. A send under the new route must
			// follow it - and fail, the proxy being unreachable - rather than ride the
			// connection dialled under the old route.
			raw := rawGet(m.target.host, m.target.port)
			resp, _, err := s.SendRawOutcome(context.Background(), m.target.host, m.target.port, useTLS, raw, ProtocolPreferenceAuto)
			if err == nil {
				t.Fatalf("after the mid-exchange route change, the send still went through the connection dialled under the old route: %q", resp)
			}
			if got := m.target.conns.Load(); got != 1 {
				t.Fatalf("the send under the new route reached the origin; %d connections opened", got)
			}
		})
	}
}

func Test_a_connection_returned_after_a_mid_exchange_cert_bind_presents_no_certificate(t *testing.T) {
	certs := netauth.NewClientCerts()
	config := DefaultSenderConfig()
	config.ClientCerts = certs
	config.TLSVerify = false
	s := keepAliveSenderFor(t, config)

	var mu sync.Mutex
	var presented [][]byte
	m := &midExchange{arrived: make(chan struct{}), release: make(chan struct{})}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m.once.Do(func() { close(m.arrived) })
		<-m.release
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
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
	target := &connCountingServer{srv: srv}
	var err error
	target.host, target.port, err = hostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	m.target = target

	// Dialled with no certificate bound; the binding lands while the exchange is open.
	identity, leafDER := generateClientIdentity(t)
	m.sendHeldOpen(t, s, true, func() {
		certs.Add(identity)
	})

	// The next send must present the certificate the operator bound, which only a fresh
	// handshake can do: the pooled connection's handshake presented nothing.
	raw := rawGet(target.host, target.port)
	resp, _, err := s.SendRawOutcome(context.Background(), target.host, target.port, true, raw, ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("the send after the mid-exchange bind: %v", err)
	}
	if !strings.HasSuffix(string(resp), "ok") {
		t.Fatalf("send answered %q", resp)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(presented) != 2 {
		t.Fatalf("handshakes observed: %d, want the fresh dial the new binding requires", len(presented))
	}
	if !bytes.Equal(presented[1], leafDER) {
		t.Error("the dial after the binding presented a different certificate than the one bound")
	}
}
