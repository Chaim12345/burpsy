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

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

// A listener's "Support HTTP/2" switch (burpsy-react-ui-34rd). With it off, a client that offers h2
// through an intercepting listener is answered over HTTP/1.1 even though interception is off and the
// origin speaks h2, and the row says why. With it on (the default), the same client gets h2.
func TestAListenerWithHTTP2OffHoldsTheClientToHTTP11(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)
	origin := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
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
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(certDir, "burpsy-ca", "ca.crt"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	protoThrough := func(spec ListenerSpec) (int, *core.TrafficStore) {
		policy := NewTlsPolicy()
		policy.WithEngine(engine)
		store := core.NewTrafficStore()
		srv := NewServer(NewProxyConfig(store).
			WithScope(testScope()).
			WithTlsPolicy(policy).
			WithUpstreamTLS(permissiveTLS()).
			WithLogger(zap.NewNop()))
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
				go srv.handleConnectionOn(conn, spec)
			}
		}()
		client := &http.Client{Transport: &http.Transport{
			Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: pln.Addr().String()}),
			TLSClientConfig:   &tls.Config{RootCAs: pool, NextProtos: []string{"h2", "http/1.1"}},
			ForceAttemptHTTP2: true,
		}}
		// u5jf: close idle transport connections at test end so persist-conn
		// and relay goroutines cannot outlive the test.
		t.Cleanup(client.CloseIdleConnections)
		resp, err := client.Get(fmt.Sprintf("https://%s:%d/p", thost, tport))
		if err != nil {
			t.Fatalf("request through proxy: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.ProtoMajor, store
	}

	if major, _ := protoThrough(ListenerSpec{}); major != 2 {
		t.Fatalf("control: a default listener gave the client HTTP/%d, want HTTP/2", major)
	}
	off := false
	major, store := protoThrough(ListenerSpec{HTTP2: &off})
	if major != 1 {
		t.Errorf("a listener with Support HTTP/2 off gave the client HTTP/%d, want HTTP/1.1", major)
	}
	ex := awaitExchangeFor(t, store, "/p", "proxy")
	if ex.Notes == nil || !strings.Contains(*ex.Notes, "Support HTTP/2") {
		t.Errorf("the row does not say why h2 was refused: %v", ex.Notes)
	}
}
