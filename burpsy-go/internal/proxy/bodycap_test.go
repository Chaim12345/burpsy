package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// burpsy-react-ui-h1-cap-silent, proxy legs: an HTTP/1 body past httputil.MaxResponseBodyBytes used
// to be forwarded as if whole — its head still declaring the full Content-Length — and recorded with
// no word, while the keep-alive loop went back to the upstream connection with the rest of the body
// still on it. Now the prefix is forwarded close-delimited, the record carries the h2/h3 cap
// sentence, and the connection ends with the response.

// serveOverCap writes one response whose Content-Length is the cap plus 16, the 16 bytes past the
// cap after a pause, and then holds the connection open the way a keep-alive origin does.
func serveOverCap(conn net.Conn) {
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", httputil.MaxResponseBodyBytes+16)
	_, _ = conn.Write(bytes.Repeat([]byte("a"), httputil.MaxResponseBodyBytes))
	time.Sleep(300 * time.Millisecond)
	_, _ = conn.Write([]byte(strings.Repeat("z", 16)))
	// Held open until the proxy closes it (or the test's cleanup does).
	_, _ = io.Copy(io.Discard, br)
}

// trackConns closes every accepted origin connection at cleanup, so a proxy that never closes its
// upstream (the defect) cannot leave serveOverCap blocked past the test.
func trackConns(t *testing.T) func(net.Conn) {
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return func(c net.Conn) {
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
	}
}

func checkCappedRecord(t *testing.T, store *core.TrafficStore, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, ex := range store.Exchanges() {
			if ex == nil || ex.Path != path {
				continue
			}
			if ex.Notes == nil || !strings.Contains(*ex.Notes, "byte cap and was cut there") {
				t.Fatalf("the exchange for a body cut at the cap does not say so; notes = %v", ex.Notes)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no exchange was recorded for the capped response")
}

func TestAPlainResponsePastTheCapIsForwardedCloseDelimitedAndNoted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	track := trackConns(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			track(c)
			go func() { defer c.Close(); serveOverCap(c) }()
		}
	}()

	store := core.NewTrafficStore()
	_, proxyAddr := startPlainProxy(t, store, testScope())
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /big HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr().String())
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading the forwarded response: %v", err)
	}
	defer resp.Body.Close()
	if resp.ContentLength != -1 {
		t.Errorf("the forwarded head still declares Content-Length %d for a cut body", resp.ContentLength)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("the close-delimited body did not end with the connection: %v (after %d bytes)", err, n)
	}
	if n != httputil.MaxResponseBodyBytes {
		t.Errorf("forwarded %d body bytes, want the %d that fit under the cap", n, httputil.MaxResponseBodyBytes)
	}
	checkCappedRecord(t, store, "/big")
}

func TestATLSKeepAliveResponsePastTheCapEndsTheConnectionAndIsNoted(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	originLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { originLn.Close() })
	track := trackConns(t)
	go func() {
		for {
			c, err := originLn.Accept()
			if err != nil {
				return
			}
			track(c)
			go func() { defer c.Close(); serveOverCap(c) }()
		}
	}()

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
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
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
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
			TLSClientConfig: &tls.Config{RootCAs: pool, NextProtos: []string{"http/1.1"}},
		},
	}
	resp, err := client.Get("https://" + originLn.Addr().String() + "/big")
	if err != nil {
		t.Fatalf("https through the MITM proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.ContentLength != -1 {
		t.Errorf("the forwarded head still declares Content-Length %d for a cut body", resp.ContentLength)
	}
	// Before the fix this read hung: the head promised 16 bytes more than were forwarded, and the
	// proxy kept the tunnel open waiting for the next request.
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("the cut body did not end with the connection: %v (after %d bytes)", err, n)
	}
	if n != httputil.MaxResponseBodyBytes {
		t.Errorf("forwarded %d body bytes, want %d", n, httputil.MaxResponseBodyBytes)
	}
	checkCappedRecord(t, store, "/big")
}
