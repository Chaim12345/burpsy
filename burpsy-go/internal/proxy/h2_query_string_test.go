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
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

// An h2 exchange records the whole request target, query string included.
//
// The relay used to run the captured path through a pathOnly() helper that truncated at the first
// '?', which made HTTP/2 the one protocol whose stored Path disagreed with the request bytes stored
// beside it: the request line read `GET /search?q=secret HTTP/2` and the exchange read `/search`.
// Every HTTP/1 path in this package records the full target, so the two protocols described the same
// traffic differently.
//
// It was not cosmetic. The site map derives a node's parameter list by splitting the stored path on
// '?' (splitPathQuery in internal/web/api_toolkit.go), so every h2 node reported no parameters at
// all — and h2 is what nearly every TLS origin negotiates, so parameters were visible only for the
// plaintext minority. Query filtering, reporting and issue attribution all read the same value.
//
// The assertion is deliberately made against the *request message* rather than a literal, so the test
// pins the invariant "the exchange agrees with the bytes" rather than one hard-coded string.
func TestH2ExchangeRecordsTheQueryString(t *testing.T) {
	const target = "/search?q=secret&page=2"

	store, proxyAddr, originHost, originPort, pool := startH2ProxyAndOrigin(t)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				NextProtos: []string{"h2", "http/1.1"},
			},
			ForceAttemptHTTP2: true,
		},
	}
	// u5jf: close idle transport connections at test end so persist-conn
	// and relay goroutines cannot outlive the test.
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Get(fmt.Sprintf("https://%s:%d%s", originHost, originPort, target))
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.ProtoMajor != 2 {
		t.Fatalf("client proto = HTTP/%d, want HTTP/2 — this test only means something over h2", resp.ProtoMajor)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, ex := range store.Exchanges() {
			if ex.Method == "CONNECT" || ex.Protocol != core.ProtocolHTTP2 || ex.Response == nil {
				continue
			}
			if ex.Path != target {
				t.Fatalf("exchange path = %q, want %q — the query string was dropped", ex.Path, target)
			}
			// And it agrees with the request bytes the store holds, which is the property that
			// actually broke: the two disagreed while each looked plausible alone.
			msg, err := store.Get(core.MsgOrZero(ex.Request))
			if err != nil {
				t.Fatalf("get request message: %v", err)
			}
			if line := firstLine(string(msg.Raw())); !containsTarget(line, target) {
				t.Fatalf("request line %q does not carry %q, so the fixture is wrong", line, target)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no HTTP/2 application exchange recorded: %+v", store.Exchanges())
}

func firstLine(s string) string {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '\r' && s[i+1] == '\n' {
			return s[:i]
		}
	}
	return s
}

func containsTarget(line, target string) bool {
	for i := 0; i+len(target) <= len(line); i++ {
		if line[i:i+len(target)] == target {
			return true
		}
	}
	return false
}

// startH2ProxyAndOrigin brings up an h2 origin behind an intercepting proxy and returns the store the
// proxy records into, the proxy's address, the origin's host and port, and the CA pool a client needs
// to trust the interception.
func startH2ProxyAndOrigin(t *testing.T) (*core.TrafficStore, string, string, int, *x509.CertPool) {
	t.Helper()
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
	t.Cleanup(func() { ln.Close() })
	go origin.Serve(ln)
	t.Cleanup(func() { origin.Close() })

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

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

	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pln.Close() })
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
	return store, pln.Addr().String(), host, port, pool
}
