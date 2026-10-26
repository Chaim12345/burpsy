package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/upstream"
)

// burpsy-react-ui-h2sess-stamp: an open h2 session is the same kind of dialled identity as a
// pooled HTTP/1 connection - it was opened under one upstream route and one client
// certificate, and a change to either must retire it. The session key (tab, authority, SNI)
// says nothing about the route or the identity, so without a stamp a session opened before
// the change answers sends made after it.

func TestH2SessionsDoNotOutliveARouteChange(t *testing.T) {
	srv := startSNIServer(t, true)
	host, port := srv.hostPort(t)

	policy := upstream.NewPolicy()
	config := DefaultSenderConfig()
	config.Upstream = policy
	config.TLSVerify = false
	config.Timeout = 500 * time.Millisecond
	s := NewSender(config)
	pool := NewH2Sessions(4, time.Minute)
	defer pool.Close()

	sendPooled(t, s, pool, "tab", host, port)
	if pool.Opened() != 1 {
		t.Fatalf("opened = %d, want the one session the first send dialled", pool.Opened())
	}

	// The operator aims this authority at an unreachable proxy. The open session was dialled
	// direct, so the next send must follow the new route - and fail - rather than ride it.
	if _, err := policy.Set("*", "http://127.0.0.1:1"); err != nil {
		t.Fatalf("setting the wildcard upstream rule: %v", err)
	}
	ctx := WithSendOptions(context.Background(), SendOptions{H2Sessions: pool, H2SessionKey: "tab"})
	resp, _, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceAuto)
	if err == nil {
		t.Fatalf("after the route change, the send still rode the session dialled under the old route: %q", resp)
	}
}

func TestH2SessionsDoNotOutliveAClientCertificateChange(t *testing.T) {
	certs := netauth.NewClientCerts()
	config := DefaultSenderConfig()
	config.ClientCerts = certs
	config.TLSVerify = false
	config.Timeout = 500 * time.Millisecond
	s := NewSender(config)

	var mu sync.Mutex
	var presented [][]byte
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
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
	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	pool := NewH2Sessions(4, time.Minute)
	defer pool.Close()
	sendPooled(t, s, pool, "tab", host, port)
	mu.Lock()
	if len(presented) != 1 || presented[0] != nil {
		mu.Unlock()
		t.Fatalf("handshakes observed: %d, want one certificate-free dial", len(presented))
	}
	mu.Unlock()

	// Binding a certificate changes what the handshake must present; only a fresh dial can
	// honour that, so the open session has to go.
	identity, leafDER := generateClientIdentity(t)
	certs.Add(identity)
	sendPooled(t, s, pool, "tab", host, port)
	mu.Lock()
	defer mu.Unlock()
	if len(presented) != 2 {
		t.Fatalf("handshakes observed: %d, want the fresh dial the new binding requires", len(presented))
	}
	if !bytes.Equal(presented[1], leafDER) {
		t.Error("the dial after the binding presented a different certificate than the one bound")
	}
}

// take closes a route-mismatched session rather than skipping it, so flipping the route back
// cannot resurrect the session dialled under what is now the wrong configuration. (A design
// pin within the fix: against the unfixed tree the second send fails earlier, when the stale
// session is handed out at all.)
func TestH2SessionsAClosedRouteMismatchIsNotResurrectedByAFlipBack(t *testing.T) {
	srv := startSNIServer(t, true)
	host, port := srv.hostPort(t)

	policy := upstream.NewPolicy()
	config := DefaultSenderConfig()
	config.Upstream = policy
	config.TLSVerify = false
	config.Timeout = 500 * time.Millisecond
	s := NewSender(config)
	pool := NewH2Sessions(4, time.Minute)
	defer pool.Close()

	sendPooled(t, s, pool, "tab", host, port)
	if pool.Opened() != 1 {
		t.Fatalf("opened = %d, want the one session the first send dialled", pool.Opened())
	}

	// Route flips away: the stale session is refused and closed (the dial through the
	// unreachable proxy fails).
	if _, err := policy.Set("*", "http://127.0.0.1:1"); err != nil {
		t.Fatalf("setting the wildcard upstream rule: %v", err)
	}
	ctx := WithSendOptions(context.Background(), SendOptions{H2Sessions: pool, H2SessionKey: "tab"})
	if _, _, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceAuto); err == nil {
		t.Fatal("the send under the changed route rode the stale session")
	}

	// Route flips back: the next send must dial fresh, not resurrect the closed session.
	if !policy.Remove("*") {
		t.Fatal("the wildcard rule just set was not there to remove")
	}
	out := sendPooled(t, s, pool, "tab", host, port)
	if out.ConnectionReused {
		t.Fatal("the flipped-back route resurrected the closed session")
	}
	if pool.Opened() != 2 || pool.Reused() != 0 {
		t.Fatalf("opened/reused = %d/%d, want 2/0 - every send dialled fresh", pool.Opened(), pool.Reused())
	}
}
