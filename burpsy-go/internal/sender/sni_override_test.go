package sender

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Override SNI (burpsy-react-ui-k011): only the ClientHello's server name changes. These tests read
// the name the server actually received in the handshake, and the Host header that arrived after it.

type sniServer struct {
	*httptest.Server
	mu    sync.Mutex
	names []string
	hosts []string
}

func startSNIServer(t *testing.T, h2 bool) *sniServer {
	t.Helper()
	s := &sniServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hosts = append(s.hosts, r.Host)
		s.mu.Unlock()
		w.Write([]byte("ok"))
	}))
	s.EnableHTTP2 = h2
	s.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		s.names = append(s.names, hello.ServerName)
		s.mu.Unlock()
		return nil, nil
	}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func (s *sniServer) hostPort(t *testing.T) (string, uint16) {
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(port)
}

func (s *sniServer) last() (name, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.names) > 0 {
		name = s.names[len(s.names)-1]
	}
	if len(s.hosts) > 0 {
		host = s.hosts[len(s.hosts)-1]
	}
	return name, host
}

func TestOverrideSNIChangesOnlyTheClientHelloServerName(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		srv := startSNIServer(t, h2)
		host, port := srv.hostPort(t)
		s := testSender()
		raw := rawGet(host, port)

		// Baseline: 127.0.0.1 is an IP, so no SNI at all goes out.
		if _, _, err := s.SendRawOutcome(context.Background(), host, port, true, raw, ProtocolPreferenceAuto); err != nil {
			t.Fatalf("h2=%v baseline: %v", h2, err)
		}
		if name, _ := srv.last(); name != "" {
			t.Fatalf("h2=%v baseline SNI = %q, want none for an IP target", h2, name)
		}

		ctx := WithSendOptions(context.Background(), SendOptions{SNI: "probe.oast.example"})
		resp, outcome, err := s.SendRawOutcome(ctx, host, port, true, raw, ProtocolPreferenceAuto)
		if err != nil {
			t.Fatalf("h2=%v override send: %v", h2, err)
		}
		name, gotHost := srv.last()
		if name != "probe.oast.example" {
			t.Fatalf("h2=%v ClientHello server name = %q, want the override", h2, name)
		}
		if gotHost != formatHostPort(host, port) {
			t.Fatalf("h2=%v Host = %q — the override must not touch the Host header", h2, gotHost)
		}
		if !strings.Contains(string(resp), "200") {
			t.Fatalf("h2=%v response = %q", h2, resp)
		}
		if h2 && outcome.Negotiated != "h2" {
			t.Fatalf("negotiated %q on the h2 server", outcome.Negotiated)
		}
	}
}

// With verification on, the certificate is still verified — against the authority dialled, not the
// probe name the certificate was never issued for.
func TestOverrideSNIStillVerifiesTheCertificateAgainstTheTarget(t *testing.T) {
	srv := startSNIServer(t, false)
	host, port := srv.hostPort(t)
	pemPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultSenderConfig()
	cfg.TLSVerify = true
	cfg.Timeout = 2 * time.Second
	s := NewSender(cfg)
	settings := s.Network()
	settings.TLS.RootCAPath = pemPath
	if err := s.ApplyNetwork(settings); err != nil {
		t.Fatal(err)
	}
	ctx := WithSendOptions(context.Background(), SendOptions{SNI: "probe.oast.example"})
	if _, _, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceHTTP1); err != nil {
		t.Fatalf("verified send under an SNI override failed: %v — verification must be against %s, not the probe name", err, host)
	}
	if name, _ := srv.last(); name != "probe.oast.example" {
		t.Fatalf("server name = %q", name)
	}

	// And verification is real: without the bundle the same send is refused.
	settings.TLS.RootCAPath = ""
	if err := s.ApplyNetwork(settings); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceHTTP1); err == nil {
		t.Fatal("an untrusted certificate was accepted under an SNI override — the override must not switch verification off")
	}
}

// What a server negotiates for a probe name is not evidence about the target, so it is not learnt.
func TestOverrideSNIDoesNotTeachTheProtocolCache(t *testing.T) {
	srv := startSNIServer(t, true)
	host, port := srv.hostPort(t)
	s := testSender()
	ctx := WithSendOptions(context.Background(), SendOptions{SNI: "probe.oast.example"})
	if _, _, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceAuto); err != nil {
		t.Fatal(err)
	}
	if got := s.KnownProtocol(host, port, true); got != ProtocolSupportUnknown {
		t.Fatalf("protocol cache = %v after an SNI-override send, want unknown", got)
	}
}

func TestHopContextDropsTheSNIOverrideAndKeepsTheTimeouts(t *testing.T) {
	ctx := WithSendOptions(context.Background(), SendOptions{SNI: "x.example", ResponseTimeout: time.Second})
	hop, _ := SendOptionsFrom(HopContext(ctx))
	if hop.SNI != "" || hop.ResponseTimeout != time.Second {
		t.Fatalf("hop options = %+v, want no SNI and the response timeout kept", hop)
	}
}

func TestValidateSNI(t *testing.T) {
	for _, ok := range []string{"a.example", "x_y-z.oast.example", "localhost"} {
		if err := ValidateSNI("sni", ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "127.0.0.1", "a b", "a\x00b", strings.Repeat("a", 254)} {
		if err := ValidateSNI("sni", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
