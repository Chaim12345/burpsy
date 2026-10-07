package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// NoteFailedNegotiation adds a host exactly once, only when auto-add is on, as an exact pattern, and
// the counter makes it visible (burpsy-react-ui-n1fi).
func TestAutoAddOnFailureAddsTheHostExactlyOnce(t *testing.T) {
	p := NewTlsPolicy()
	if p.NoteFailedNegotiation("pinned.test") || p.AutoAddedCount() != 0 {
		t.Fatal("auto-add fired while off")
	}
	p.SetAutoAddOnFailure(true)
	if !p.NoteFailedNegotiation("Pinned.Test") {
		t.Fatal("the first rejection did not add the host")
	}
	if p.NoteFailedNegotiation("pinned.test") {
		t.Error("a second rejection of the same host added it again")
	}
	if p.AutoAddedCount() != 1 {
		t.Errorf("auto-added count = %d, want 1", p.AutoAddedCount())
	}
	if !p.ShouldPassthrough("pinned.test", 443) {
		t.Error("the auto-added host is not passed through")
	}
	// Exact, not a wildcard: a sibling the client never pinned is still intercepted.
	if p.ShouldPassthrough("api.pinned.test", 443) {
		t.Error("auto-add widened to a wildcard; it must add the exact host only")
	}
}

// Apply-to-out-of-scope: with the switch on, an out-of-scope HTTPS host is tunnelled opaque (the
// client sees the ORIGIN's cert, not burpsy's leaf, and no request message is stored) without the
// operator naming it in the passthrough list.
func TestApplyOutOfScopeTunnelsAnOutOfScopeHostWithoutListingIt(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	target := httptestNewTLS(t, cert, "tunneled")
	thost, tport := hostPortOf(t, target)

	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatal(err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)
	policy.SetApplyOutOfScope(true) // the switch, no passthrough entry for thost

	scope := core.NewScope()
	scope.AddInclude("in-scope.test") // the target host is NOT in scope

	store := core.NewTrafficStore()
	proxyAddr := startProxyForTLS(t, store, policy, scope)

	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get(fmt.Sprintf("https://%s:%s/", thost, tport))
	if err != nil {
		t.Fatalf("https to an out-of-scope host with the switch on: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tunneled" {
		t.Errorf("body = %q, want tunneled", body)
	}
	ex := awaitExchange(t, store)
	if ex.Method != "CONNECT" || !ex.TLS {
		t.Errorf("exchange = %+v, want a CONNECT tunnel record", ex)
	}
	if _, err := store.Get(core.MsgOrZero(ex.Request)); err == nil {
		t.Error("an out-of-scope passthrough tunnel stored request bytes; it must stay opaque")
	}
}

func httptestNewTLS(t *testing.T, cert tls.Certificate, body string) *tlsTestServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &tlsTestServer{addr: ln.Addr().String()}
}

type tlsTestServer struct{ addr string }

func hostPortOf(t *testing.T, s *tlsTestServer) (string, string) {
	t.Helper()
	h, p, err := net.SplitHostPort(s.addr)
	if err != nil {
		t.Fatal(err)
	}
	return h, p
}

func startProxyForTLS(t *testing.T, store *core.TrafficStore, policy *TlsPolicy, scope *core.Scope) string {
	t.Helper()
	srv := NewServer(NewProxyConfig(store).
		WithScope(scope).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithLogger(zap.NewNop()))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			go srv.handleConnection(conn)
		}
	}()
	_ = strings.TrimSpace
	return ln.Addr().String()
}
