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
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

// This is the end-to-end shape of burpsy-react-ui-y0l2: an h2-capable client asks an h2 origin for
// HTTP/2, interception is on, and the exchange that lands in history says HTTP/1.1. Before the fix
// that row was indistinguishable from a target that only ever spoke HTTP/1.1, so the operator had no
// way to learn that the protocol under test was never exercised.
//
// It reuses the origin and client of TestTLSInterceptionH2Relay — same h2 server, same h2 client —
// and differs in exactly one thing: the intercept engine is enabled, which is what narrows the
// offer. Everything else is held identical so a failure cannot be blamed on the harness.
func TestAnH2ClientDowngradedByInterceptionIsRecordedAsSuch(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)

	origin := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The origin reports the protocol it actually served. An h2 request arriving as HTTP/1.1
			// is the downgrade, measured at the far end rather than inferred from burpsy's own
			// bookkeeping — a test that reads only burpsy's state would pass if burpsy's state were
			// wrong in the same direction twice.
			w.Header().Set("X-Origin-Proto", r.Proto)
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "body")
		}),
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

	// Interception ON. This is the single difference from the h2 relay test, and it is what forces
	// the offer down to http/1.1.
	hold := intercept.NewEngine()
	hold.SetEnabled(true)

	store := core.NewTrafficStore()
	proxySrv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
		WithIntercept(hold).
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
	// u5jf: close idle transport connections at test end so persist-conn
	// and relay goroutines cannot outlive the test.
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/", thost, tport))
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// The premise, measured: the origin really was spoken to over HTTP/1.1 even though this client
	// offered h2. If it were not, the test below would be asserting a note on an un-downgraded row.
	if got := resp.Header.Get("X-Origin-Proto"); got != "HTTP/1.1" {
		t.Skipf("the origin served %s, so no downgrade happened and this test has nothing to assert", got)
	}

	// The client believed it got what it asked for, which is the deception half of the bead: Go's
	// transport reports its own protocol, and over an intercepting proxy it is the client's own
	// view rather than the origin's.
	if resp.ProtoMajor != 2 {
		t.Logf("client saw %s (the client leg is offered what the upstream chose)", resp.Proto)
	}

	// Now the record: it must carry HTTP/1.1 AND say why. The record lands asynchronously after the
	// response reaches the client, so it is awaited rather than read once: a single read raced the
	// relay and failed CI under load.
	var found *core.Exchange
	for deadline := time.Now().Add(5 * time.Second); found == nil && time.Now().Before(deadline); {
		for _, ex := range store.Exchanges() {
			if ex != nil && strings.Contains(ex.Host, thost) {
				found = ex
				break
			}
		}
		if found == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if found == nil {
		t.Fatal("no exchange was recorded for the request; the downgrade note could not have been attached to anything")
	}
	if found.Protocol != core.ProtocolHTTP1 {
		t.Errorf("recorded protocol = %v, want HTTP/1: the origin reported it served HTTP/1.1", found.Protocol)
	}
	if found.Notes == nil || !strings.Contains(*found.Notes, "client offered HTTP/2") {
		t.Errorf("recorded notes = %v, want the downgrade explanation: without it this row is "+
			"identical to a target that only ever spoke HTTP/1.1, which is the whole defect (y0l2)", found.Notes)
	}

	// And the UI's detector must recognise the string the server actually wrote.
	if !strings.HasPrefix(*found.Notes, "client offered HTTP/2;") {
		t.Errorf("recorded notes = %q; the UI matches this exact prefix, so a wording change here "+
			"hides every badge in history", *found.Notes)
	}
}
