package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

type recordedChains struct {
	mu     sync.Mutex
	hosts  []string
	chains [][]*x509.Certificate
}

func (r *recordedChains) Record(host string, port uint16, chain []*x509.Certificate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hosts = append(r.hosts, host)
	r.chains = append(r.chains, chain)
}

// Burp's "Server TLS certificates" (burpsy-react-ui-t75m) on the proxy leg: browser HTTPS traffic the
// listener intercepts hands the origin's own certificate (not burpsy's leaf) to the recorder.
func TestTheProxyRecordsTheOriginsCertificateOnAnInterceptedConnection(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	target.StartTLS()
	defer target.Close()
	thost, tport, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "https://"))

	engine, err := LoadOrGenerateCA(filepath.Join(certDir, "burpsy-ca"))
	if err != nil {
		t.Fatal(err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)
	rec := &recordedChains{}
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScopeAllowEverything()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithServerCerts(rec).
		WithLogger(zap.NewNop()))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	// u5jf: close idle transport connections at test end so persist-conn
	// and relay goroutines cannot outlive the test.
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Get("https://" + net.JoinHostPort(thost, tport) + "/")
	if err != nil {
		t.Fatalf("https through proxy: %v", err)
	}
	resp.Body.Close()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.chains) == 0 || len(rec.chains[0]) == 0 {
		t.Fatal("no certificate chain was recorded for the intercepted connection")
	}
	if !bytesEqual(rec.chains[0][0].Raw, cert.Certificate[0]) {
		t.Error("the recorded leaf is not the origin's certificate")
	}
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }
