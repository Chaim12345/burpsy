package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

func testScope() *core.Scope {
	s := core.NewScope()
	s.AddInclude("*")
	return s
}

// TestPlainHTTPInterceptionAndPassiveScan verifies the full proxy flow for a
// plain HTTP request: forward, record exchange, and passive-scan findings.
func TestPlainHTTPInterceptionAndPassiveScan(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "hello")
	}))
	defer target.Close()

	thost, tportStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	tport, _ := strconv.Atoi(tportStr)

	store := core.NewTrafficStore()
	findings := core.NewFindingStore()
	proxySrv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())).
		WithFindings(findings))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxySrv.handleConnection(conn)
		}
	}()

	// Send a request through the proxy using its advertised proxy address.
	proxyAddr := ln.Addr().String()
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
	}}
	// u5jf: close idle transport connections at test end so persist-conn
	// and relay goroutines cannot outlive the test.
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/", thost, tport))
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}

	// Exchange must be recorded. Waited for, because the exchange is recorded by the proxy's connection
	// goroutine *after* the response bytes have been written to the client, so a client that has already
	// read its body proves nothing about whether that goroutine has reached AddExchange yet. Reading the
	// store immediately passed on an idle machine and failed under load, which is the worst of both.
	awaitExchange(t, store)
	exchanges := store.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("exchanges = %d, want 1", len(exchanges))
	}
	if exchanges[0].TLS {
		t.Error("plain exchange marked TLS")
	}

	// Passive scan findings: missing security headers on the target response.
	var names map[string]bool
	if awaitFindings(findings, 3*time.Second) == 0 {
		t.Fatal("passive scanner produced no findings")
	}
	names = map[string]bool{}
	for _, f := range findings.All() {
		names[f.Name] = true
	}
	// X-Content-Type-Options rather than X-Frame-Options, and the swap is deliberate.
	//
	// This assertion is about the proxy: it proves the captured response reached the passive
	// scanner and came back with findings. Any missing-header finding serves that purpose, and
	// the X-Frame-Options one was removed from the passive path as a duplicate — it aliased onto
	// the same catalogue entry as checkFrameableResponse and, unlike that check, ignored CSP
	// frame-ancestors, so it reported clickjacking on sites correctly defended against it. See
	// scanner.go's comment in checkSecurityHeaders and BURP_PARITY_GAP_ANALYSIS.md §3.0.3b.
	if !names["Missing X-Content-Type-Options Header"] {
		t.Errorf("expected a missing-security-header finding, got %v", names)
	}
}

// TestTLSInterceptionMITM verifies CONNECT MITM: leaf cert signed by the CA,
// decrypted traffic recorded with TLS=true, and passive findings produced.
func TestTLSInterceptionMITM(t *testing.T) {
	// TLS target with a self-signed cert.
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "secure hello")
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	target.StartTLS()
	defer target.Close()

	thost, tportStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "https://"))
	tport, _ := strconv.Atoi(tportStr)

	// Generate the burpsy CA.
	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)

	store := core.NewTrafficStore()
	findings := core.NewFindingStore()
	proxySrv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())).
		WithFindings(findings))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxySrv.handleConnection(conn)
		}
	}()

	// Client trusts the burpsy CA.
	caPEM, err := os.ReadFile(filepath.Join(certDir, "burpsy-ca", "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse CA cert")
	}

	proxyAddr := ln.Addr().String()
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	// u5jf: close idle transport connections at test end so persist-conn
	// and relay goroutines cannot outlive the test.
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/", thost, tport))
	if err != nil {
		t.Fatalf("https through MITM proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure hello" {
		t.Errorf("body = %q, want secure hello", body)
	}

	// Exchange recorded as TLS. Polled, for the same reason the plain-HTTP test above polls: the TLS
	// path now captures the exchange *after* the response has been written to the client, where it used
	// to index the row before the operator's hold queue had even seen the response. The new order is
	// what puts the delivered bytes in history rather than the origin's pre-rewrite ones — see
	// handleTLSResponse — and it means a client holding its body no longer proves the capture goroutine
	// has reached AddExchange.
	awaitExchange(t, store)
	exchanges := store.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("exchanges = %d, want 1", len(exchanges))
	}
	if !exchanges[0].TLS {
		t.Error("intercepted exchange not marked TLS")
	}
	if exchanges[0].Host != thost {
		t.Errorf("host = %q, want %q", exchanges[0].Host, thost)
	}

	// Passive findings from decrypted traffic.
	if awaitFindings(findings, 3*time.Second) == 0 {
		t.Error("passive scanner produced no findings for intercepted TLS traffic")
	}
}

// awaitFindings waits for the passive scan to reach the finding store, returning the count it
// settled on.
//
// Needed because an exchange being visible in the store says nothing about whether its findings are.
// scanner.Capture.Record publishes the exchange with AddExchange and only *then* runs ScanExchange,
// so a test that asserts on exchanges and then immediately on findings is racing the scan. That
// ordering is correct and should not change — a finding references its exchange, so the exchange must
// have its id first — but it is the opposite of what a reader tends to assume.
//
// The window used to be microseconds, which is why asserting straight away passed for as long as it
// did. It is now milliseconds, because the shared scan path also runs the static DOM pass, and a
// millisecond is long enough to lose reliably. Note this waits for the scan to *finish*; it does not
// weaken what is asserted afterwards, so a genuine regression — a scan that never runs — still fails
// here, just three seconds later.
func awaitFindings(findings *core.FindingStore, within time.Duration) int {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if n := findings.Count(); n > 0 {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
	return findings.Count()
}

// TestConnectPassthroughBlind verifies passthrough hosts are blind-tunnelled
// (no exchange recorded, no interception).
func TestConnectPassthroughBlind(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "tunneled")
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	target.StartTLS()
	defer target.Close()

	thost, tportStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "https://"))

	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)
	policy.AddPassthrough(thost)

	store := core.NewTrafficStore()
	proxySrv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithLogger(zap.NewNop()))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxySrv.handleConnection(conn)
		}
	}()

	proxyAddr := ln.Addr().String()
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // passthrough: client sees the origin's real cert
	}}
	// u5jf: close idle transport connections at test end so persist-conn
	// and relay goroutines cannot outlive the test.
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Get(fmt.Sprintf("https://%s:%s/", thost, tportStr))
	if err != nil {
		t.Fatalf("https through passthrough: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tunneled" {
		t.Errorf("body = %q, want tunneled", body)
	}
	// The CONNECT tunnel itself is recorded as an exchange (no request/response
	// messages, since passthrough traffic is not decrypted).
	awaitExchange(t, store)
	exchanges := store.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("exchanges = %d, want 1 (CONNECT tunnel record)", len(exchanges))
	}
	if exchanges[0].Method != "CONNECT" || !exchanges[0].TLS {
		t.Errorf("exchange = %+v, want CONNECT tunnel marked TLS", exchanges[0])
	}
	if _, err := store.Get(core.MsgOrZero(exchanges[0].Request)); err == nil {
		t.Error("passthrough tunnel should not store request messages")
	}
}

// generateSelfSigned writes a self-signed cert/key pair and returns the cert.
func generateSelfSigned(t *testing.T, dir string) (tls.Certificate, []byte) {
	t.Helper()
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", filepath.Join(dir, "key.pem"),
		"-out", filepath.Join(dir, "cert.pem"),
		"-days", "1", "-nodes", "-subj", "/CN=localhost")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v: %s", err, out)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}
	return cert, nil
}

func TestRemovePassthroughRemovesOnlyTheExactPattern(t *testing.T) {
	p := NewTlsPolicy()
	p.AddPassthrough("*.bank.test")
	p.AddPassthrough("safe.test")

	if got := p.Passthrough(); len(got) != 2 {
		t.Fatalf("passthrough = %v, want both patterns", got)
	}
	if !p.RemovePassthrough("*.bank.test") {
		t.Fatal("removing a pattern that is present reported false")
	}
	if p.RemovePassthrough("*.bank.test") {
		t.Error("removing an absent pattern reported true")
	}
	got := p.Passthrough()
	if len(got) != 1 || got[0] != "safe.test" {
		t.Fatalf("passthrough = %v; the sibling pattern must survive an exact-pattern removal", got)
	}
}
