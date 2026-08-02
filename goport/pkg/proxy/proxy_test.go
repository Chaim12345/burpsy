package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"burpsy-go/pkg/scope"
	"burpsy-go/pkg/store"
)

func TestCertAuthorityGenerationAndSigning(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ca-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ca, err := LoadOrGenerateCA(tempDir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA failed: %v", err)
	}

	cert, err := ca.SignCertificate("example.com")
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Errorf("expected signed certificate slices, got 0")
	}
}

func TestProxyHandlingPlainHTTPAndDecryption(t *testing.T) {
	// Setup simple backend target server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello from backend!"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse ts URL failed: %v", err)
	}

	// Setup Proxy dependencies
	tempDir, _ := os.MkdirTemp("", "proxy-test")
	defer os.RemoveAll(tempDir)
	ca, _ := LoadOrGenerateCA(tempDir)

	trafficStore := store.NewTrafficStore()
	scopeEngine := scope.NewAllowEverythingScope()
	policy := NewTlsPolicy()

	// Initialize proxy on ephemeral port
	proxyAddr := "127.0.0.1:0"
	p := NewProxy(proxyAddr, trafficStore, scopeEngine, ca, policy, true)
	err = p.Start()
	if err != nil {
		t.Fatalf("Start proxy failed: %v", err)
	}
	defer p.Close()

	// Standard client with proxy configured
	proxyUrl, _ := url.Parse("http://" + p.listener.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 2 * time.Second,
	}

	// 1. Check plain HTTP proxying
	resp, err := client.Get("http://" + u.Host + "/")
	if err != nil {
		t.Fatalf("HTTP get through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(bodyBytes) != "Hello from backend!" {
		t.Errorf("expected Hello from backend!, got %q", string(bodyBytes))
	}

	// Check if traffic reached back-end correctly
	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Check if recorded correctly in TrafficStore
	time.Sleep(20 * time.Millisecond) // Allow async capture processing
	exchanges := trafficStore.Exchanges(0, 10)
	if len(exchanges) == 0 {
		t.Fatalf("expected at least 1 exchange recorded in store")
	}

	ex := exchanges[0]
	if ex.Host != u.Hostname() {
		t.Errorf("expected host %q, got %q", u.Hostname(), ex.Host)
	}
}

func TestTlsPolicyShouldPassthrough(t *testing.T) {
	policy := NewTlsPolicy()
	policy.AddPassthrough("*.apple.com")
	policy.AddPassthrough("microsoft.com")

	if !policy.ShouldPassthrough("test.apple.com", 443) {
		t.Errorf("expected test.apple.com to match passthrough pattern *.apple.com")
	}
	if !policy.ShouldPassthrough("microsoft.com", 443) {
		t.Errorf("expected microsoft.com to match passthrough")
	}
	if policy.ShouldPassthrough("google.com", 443) {
		t.Errorf("google.com should not match passthrough")
	}
}
