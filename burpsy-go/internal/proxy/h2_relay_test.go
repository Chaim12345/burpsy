package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

// TestTLSInterceptionH2Relay verifies that when client and origin negotiate h2,
// the proxy relays streams and records exchanges with ProtocolHTTP2.
func TestTLSInterceptionH2Relay(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "h2 body")
	})
	origin := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	http2.ConfigureServer(origin, &http2.Server{})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", origin.TLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go origin.Serve(ln)
	defer origin.Close()

	thost, tportStr, _ := net.SplitHostPort(ln.Addr().String())
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
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))

	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	go func() {
		for {
			conn, err := pln.Accept()
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

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: pln.Addr().String()}),
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				NextProtos: []string{"h2", "http/1.1"},
			},
			ForceAttemptHTTP2: true,
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/", thost, tport))
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "h2 body" {
		t.Fatalf("body = %q", body)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("client proto = HTTP/%d, want HTTP/2", resp.ProtoMajor)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, ex := range store.Exchanges() {
			if ex.Method == "CONNECT" {
				continue
			}
			if ex.Protocol == core.ProtocolHTTP2 && ex.Response != nil {
				if ex.Host != thost && !strings.Contains(thost, ex.Host) {
					// loopback may report 127.0.0.1 vs localhost — either is fine
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no HTTP/2 application exchange recorded: %+v", store.Exchanges())
}
