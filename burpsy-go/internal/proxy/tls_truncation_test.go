package proxy

// The TLS leg gets the same truncation salvage the plaintext leg has: an origin that
// closes short of its declared Content-Length yields a forwarded partial body (head
// rewritten close-delimited) and a recorded exchange that says exactly what was lost -
// not a dropped exchange. Arch review: the TLS leg kept the old shape after the
// plaintext fix.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

func TestATruncatedTLSContentLengthResponseIsSalvagedNotDropped(t *testing.T) {
	body := "<!DOCTYPE html><html><body>partial tls listing</body></html>"
	declared := len(body) + 59

	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack FIRST and write the raw response: the server's own buffered
		// writer would take the pending bytes with it on hijack.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("origin cannot hijack")
			return
		}
		conn, bw, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprintf(bw, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n\r\n", declared)
		if _, err := bw.WriteString(body); err != nil {
			t.Logf("origin body write: %v", err)
			return
		}
		bw.Flush()
		// Close short of the declaration: the defect under test.
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
	target.StartTLS()
	defer target.Close()

	thost, tportStr, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "https://"))
	tport, _ := strconv.Atoi(tportStr)

	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)

	store := core.NewTrafficStore()
	proxySrv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))

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

	caPEM, err := os.ReadFile(filepath.Join(certDir, "burpsy-ca", "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse CA cert")
	}

	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
		TLSClientConfig: &tls.Config{RootCAs: pool, NextProtos: []string{"http/1.1"}},
	}}
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/ftp/", thost, tport))
	if err != nil {
		t.Fatalf("https through MITM proxy: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), body) {
		t.Errorf("the partial body the origin sent never reached the client: %q", got)
	}
	if resp.Header.Get("Content-Length") != "" {
		t.Errorf("the salvaged response still declares a Content-Length it does not satisfy: %v", resp.Header)
	}

	// The exchange must be recorded, and its note must say what was lost.
	awaitExchange(t, store)
	var found *core.Exchange
	for _, ex := range store.Exchanges() {
		if ex != nil && strings.Contains(ex.Path, "/ftp/") && ex.Method != "CONNECT" {
			found = ex
			break
		}
	}
	if found == nil {
		t.Fatal("no exchange was recorded for the truncated TLS response: the client got bytes and history got nothing")
	}
	if found.Notes == nil || !strings.Contains(*found.Notes, "short of its declared Content-Length") {
		t.Errorf("the recorded exchange does not say the body was truncated; notes = %v", found.Notes)
	}
	_ = bufio.NewReader
}
