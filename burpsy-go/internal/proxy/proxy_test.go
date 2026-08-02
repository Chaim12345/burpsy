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
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/", thost, tport))
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}

	// Exchange must be recorded.
	exchanges := store.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("exchanges = %d, want 1", len(exchanges))
	}
	if exchanges[0].TLS {
		t.Error("plain exchange marked TLS")
	}

	// Passive scan findings: missing security headers on the target response.
	// The scan runs in the proxy goroutine, so poll briefly.
	var names map[string]bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && findings.Count() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if findings.Count() == 0 {
		t.Fatal("passive scanner produced no findings")
	}
	names = map[string]bool{}
	for _, f := range findings.All() {
		names[f.Name] = true
	}
	if !names["Missing X-Frame-Options Header"] {
		t.Errorf("expected X-Frame-Options finding, got %v", names)
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
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/", thost, tport))
	if err != nil {
		t.Fatalf("https through MITM proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure hello" {
		t.Errorf("body = %q, want secure hello", body)
	}

	// Exchange recorded as TLS.
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
	if findings.Count() == 0 {
		t.Error("passive scanner produced no findings for intercepted TLS traffic")
	}
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
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(store.Exchanges()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	exchanges := store.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("exchanges = %d, want 1 (CONNECT tunnel record)", len(exchanges))
	}
	if exchanges[0].Method != "CONNECT" || !exchanges[0].TLS {
		t.Errorf("exchange = %+v, want CONNECT tunnel marked TLS", exchanges[0])
	}
	if _, err := store.Get(exchanges[0].Request); err == nil {
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
