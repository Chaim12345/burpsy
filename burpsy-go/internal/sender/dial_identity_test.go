package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/upstream"
)

// burpsy-react-ui-o388-predial-vs-dial: the identity a pooled connection or h2 session is
// stamped with is captured before the dial begins, but the dial reads the mutable stores
// again when it actually consumes them - the certificate at the handshake's
// CertificateRequest, the upstream rule and carrier inside the dial itself. A change that
// lands between the capture and the consumption stamps the connection with an identity it
// does not have, and because the stamp is the pool's reuse check, every later send under the
// original configuration rides a connection that never presented it. These tests pin the
// dial to the captured identity: what the stamp claims is what the wire carried.

// The certificate leg, with the flip landing deterministically between the capture and the
// consumption: the server's GetConfigForClient holds the handshake open while the test
// removes the binding, so the dial-time read the current code makes cannot see the state the
// stamp read. RequestClientCert rather than RequireAndVerify so the dial completes either
// way; the observation is which certificate each request's connection actually presented.
func TestH2DialPresentsTheClientCertificateCapturedBeforeTheDial(t *testing.T) {
	identity, leafDER := generateClientIdentity(t)
	certs := netauth.NewClientCerts()
	certs.Add(identity)

	config := DefaultSenderConfig()
	config.ClientCerts = certs
	config.TLSVerify = false
	config.Timeout = 5 * time.Second
	s := NewSender(config)

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	var mu sync.Mutex
	var peerCerts [][]byte // per request: the leaf the connection presented, nil when none
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peerCerts = append(peerCerts, r.TLS.PeerCertificates[0].Raw)
		} else {
			peerCerts = append(peerCerts, nil)
		}
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			// Only the first handshake is held; a fix that dials again must not deadlock.
			once.Do(func() {
				close(entered)
				<-release
			})
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()
	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	pool := NewH2Sessions(4, time.Minute)
	defer pool.Close()
	ctx := WithSendOptions(context.Background(), SendOptions{H2Sessions: pool, H2SessionKey: "tab"})

	// The first send dials while the binding is live; the server holds the handshake open so
	// the removal below lands strictly between the stamp's capture and the dial's read.
	first := make(chan error, 1)
	go func() {
		_, _, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceAuto)
		first <- err
	}()
	<-entered
	if !certs.Remove("127.0.0.1") {
		t.Fatal("the binding just added was not there to remove")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first send: %v", err)
	}

	// Flip back, so the store looks exactly as it did when the stamp was captured: any reuse
	// check answers "this connection matches". The connection it matches on is the one that
	// dialled while the binding was gone.
	certs.Add(identity)
	if _, _, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceAuto); err != nil {
		t.Fatalf("second send: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(peerCerts) != 2 {
		t.Fatalf("requests observed: %d, want two sends over the pooled session", len(peerCerts))
	}
	for i, got := range peerCerts {
		if !bytes.Equal(got, leafDER) {
			t.Errorf("request %d ran on a connection that did not present the bound certificate", i+1)
		}
	}
}

// The settings leg: the resolver, the dial-address override and the TLS policy all live in
// NetworkSettings, reach the dial only through ApplyNetwork, and are not individually
// hashable, so the stamp carries a settings generation that ApplyNetwork bumps. The h1 pool
// is already flushed there (keepalive.go's closeAll); the caller-owned h2 sessions are what
// survived. A timeout-only change leaves routing untouched, so the red run reuses the
// session and the fixed run must redial.
func TestH2SessionsDoNotOutliveASettingsChange(t *testing.T) {
	srv := startSNIServer(t, true)
	host, port := srv.hostPort(t)

	config := DefaultSenderConfig()
	config.TLSVerify = false
	config.Timeout = 500 * time.Millisecond
	s := NewSender(config)
	pool := NewH2Sessions(4, time.Minute)
	defer pool.Close()

	sendPooled(t, s, pool, "tab", host, port)
	if pool.Opened() != 1 {
		t.Fatalf("opened = %d, want the one session the first send dialled", pool.Opened())
	}

	n := s.Network()
	n.TLS.MinVersion = tls.VersionTLS12
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}

	sendPooled(t, s, pool, "tab", host, port)
	if pool.Opened() != 2 {
		t.Fatalf("opened = %d, want the session dialled before the settings change retired, not reused", pool.Opened())
	}
}

// The carrier leg: the global SOCKS layer is mutable through WithUpstreamCarrier, the stamp
// says nothing about it, and the caller-owned h2 sessions are not flushed there either. A
// session dialled direct must not answer sends made after the operator aimed every outbound
// connection at a SOCKS hop; the unreachable hop turns the wrong answer into a send that
// should have failed but succeeded.
func TestH2SessionsDoNotOutliveACarrierChange(t *testing.T) {
	srv := startSNIServer(t, true)
	host, port := srv.hostPort(t)

	config := DefaultSenderConfig()
	config.TLSVerify = false
	config.Timeout = 500 * time.Millisecond
	s := NewSender(config)
	pool := NewH2Sessions(4, time.Minute)
	defer pool.Close()

	sendPooled(t, s, pool, "tab", host, port)
	if pool.Opened() != 1 {
		t.Fatalf("opened = %d, want the one session the first send dialled", pool.Opened())
	}

	carrier := upstream.NewCarrier()
	if err := carrier.SetSocks("socks5://127.0.0.1:1", nil, false); err != nil {
		t.Fatalf("configuring the SOCKS hop: %v", err)
	}
	s.WithUpstreamCarrier(carrier)

	ctx := WithSendOptions(context.Background(), SendOptions{H2Sessions: pool, H2SessionKey: "tab"})
	resp, _, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceAuto)
	if err == nil {
		t.Fatalf("after the carrier change, the send still rode the session dialled direct: %q", resp)
	}
}
