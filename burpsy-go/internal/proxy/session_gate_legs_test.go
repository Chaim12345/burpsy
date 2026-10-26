package proxy

// The W8 acceptance claim: the session gate's request half rides EVERY relay leg that can
// read a request's bytes, not only the plaintext HTTP/1 leg. Before this change the gate
// fired in handleHTTP alone; the decrypted tunnel's keep-alive loop (ordinary requests,
// retargets, WebSocket upgrades) and the HTTP/2 relay forwarded the browser's bytes
// unconsulted, so on an HTTP/2-first or TLS-only app the expiry the response half had
// already detected never triggered a re-login on the leg the browser was actually using.
//
// Both tests share the shape of the plaintext gate test: the origin answers the login
// page at 200 when no cookie arrives (the pattern signal), the first request flags the
// template through record(), and the second request must carry the cookie the rule's
// login macro established. What differs is the leg under test.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// gatedLegFixture is one origin/proxy pair wired the way both leg tests need it: an origin
// that answers "please log in" without a cookie, a coordinator whose rule re-logs in, and
// a proxy listener fronting both.
type gatedLegFixture struct {
	originAddr string
	proxyAddr  string
	store      *core.TrafficStore
	macroSends *int
	mu         *sync.Mutex
	cookieSeen chan string // the Cookie header each origin request carried, "" for none
}

// newGatedLegFixtureWithCertDir builds the origin with the given TLS next-protos
// ("http/1.1" for the tunnel leg, "h2","http/1.1" for the h2 leg) and starts the proxy
// with the session gate wired exactly as the acceptance test for the plaintext leg wires
// it. The cert dir comes from the caller so the test's client can trust the same CA.
func newGatedLegFixtureWithCertDir(t *testing.T, nextProtos []string, certDir string) *gatedLegFixture {
	t.Helper()
	cert, _ := generateSelfSigned(t, certDir)

	cookieSeen := make(chan string, 16)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookieSeen <- r.Header.Get("Cookie")
		if r.Header.Get("Cookie") == "" {
			// The login page AT 200 — the pattern signal, since a status flip cannot
			// fire without an earlier 200 baseline.
			_, _ = w.Write([]byte("please log in"))
			return
		}
		_, _ = w.Write([]byte("application content"))
	})
	origin := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   nextProtos,
		},
	}
	for _, p := range nextProtos {
		if p == "h2" {
			_ = http2.ConfigureServer(origin, &http2.Server{})
		}
	}
	oln, err := tls.Listen("tcp", "127.0.0.1:0", origin.TLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { oln.Close(); origin.Close() })
	go origin.Serve(oln)

	thost, tportStr, _ := net.SplitHostPort(oln.Addr().String())
	tport, _ := strconv.Atoi(tportStr)

	coord := session.NewCoordinator(zap.NewNop())
	rule := session.NewSessionRule("login", []string{thost}, []session.MacroStep{
		{Method: "GET", URL: "http://" + oln.Addr().String() + "/login"},
	})
	if _, err := coord.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	var macroSends int
	var mu sync.Mutex
	runner := func(_ context.Context) session.MacroStepRunner {
		return func(step session.MacroStep) (*session.StepResult, error) {
			mu.Lock()
			macroSends++
			mu.Unlock()
			coord.AbsorbCookie(thost, uint16(tport), true, "sessid=fresh")
			return &session.StepResult{Status: 200, Headers: map[string]string{"Set-Cookie": "sessid=fresh"}, Body: []byte("logged in")}, nil
		}
	}

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
		WithSessionCoordinator(coord, runner).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))
	proxySrv.config.LoginPagePattern = regexp.MustCompile("please log in")

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

	return &gatedLegFixture{
		originAddr: oln.Addr().String(),
		proxyAddr:  pln.Addr().String(),
		store:      store,
		macroSends: &macroSends,
		mu:         &mu,
		cookieSeen: cookieSeen,
	}
}

// caPool reads the fixture's generated CA into a pool the test client trusts.
func caPool(t *testing.T, certDir string) *x509.CertPool {
	t.Helper()
	caPEM, err := os.ReadFile(filepath.Join(certDir, "burpsy-ca", "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse CA cert")
	}
	return pool
}

// awaitRecorded waits for the first non-CONNECT exchange to land in history: record()
// flags the template before it indexes the row, so once the row exists the second
// request cannot race ahead of the flag (the plaintext leg's test documents the race).
func (f *gatedLegFixture) awaitRecorded(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, ex := range f.store.Exchanges() {
			if ex.Method != "CONNECT" && ex.Response != nil {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the first request's exchange never reached history, so the template could " +
		"not have been flagged before the second request")
}

func (f *gatedLegFixture) sends() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.macroSends
}

// The decrypted tunnel's keep-alive loop (interceptTLS): the leg TLS-only browser apps
// actually live on, and the one the retarget and WebSocket-over-TLS branches share.
func TestSessionGateAppliesOnTheTLSTunnelLeg(t *testing.T) {
	certDir := t.TempDir()
	f := newGatedLegFixtureWithCertDir(t, []string{"http/1.1"}, certDir)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: f.proxyAddr}),
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool(t, certDir),
				NextProtos: []string{"http/1.1"},
			},
		},
	}
	// u5jf: close idle transport connections at test end so persist-conn
	// and relay goroutines cannot outlive the test.
	t.Cleanup(client.CloseIdleConnections)

	for i := 0; i < 2; i++ {
		resp, err := client.Get("https://" + f.originAddr + "/protected")
		if err != nil {
			t.Fatalf("request %d through proxy: %v", i, err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if i == 0 {
			f.awaitRecorded(t)
		}
	}

	if got := f.sends(); got != 1 {
		t.Fatalf("login macro ran %d times on the TLS tunnel leg, want 1", got)
	}
	// The second origin request carried the fresh cookie: drain the two observed headers.
	first, second := <-f.cookieSeen, <-f.cookieSeen
	if first != "" {
		t.Errorf("first request carried cookie %q, want none", first)
	}
	if second != "sessid=fresh" {
		t.Errorf("second request carried cookie %q, want sessid=fresh (the re-login's)", second)
	}
}

// The HTTP/2 relay (relayH2Stream): on an h2-first app this is the whole session, and it
// used to forward without ever consulting the gate.
func TestSessionGateAppliesOnTheH2RelayLeg(t *testing.T) {
	certDir := t.TempDir()
	f := newGatedLegFixtureWithCertDir(t, []string{"h2", "http/1.1"}, certDir)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: f.proxyAddr}),
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool(t, certDir),
				NextProtos: []string{"h2", "http/1.1"},
			},
			ForceAttemptHTTP2: true,
		},
	}
	// u5jf: close idle transport connections at test end so persist-conn
	// and relay goroutines cannot outlive the test.
	t.Cleanup(client.CloseIdleConnections)

	var protoMajor int
	for i := 0; i < 2; i++ {
		resp, err := client.Get("https://" + f.originAddr + "/protected")
		if err != nil {
			t.Fatalf("request %d through proxy: %v", i, err)
		}
		_, _ = io.ReadAll(resp.Body)
		protoMajor = resp.ProtoMajor
		resp.Body.Close()
		if i == 0 {
			f.awaitRecorded(t)
		}
	}
	if protoMajor != 2 {
		t.Fatalf("client proto = HTTP/%d, want HTTP/2 - this test exercises nothing otherwise", protoMajor)
	}

	if got := f.sends(); got != 1 {
		t.Fatalf("login macro ran %d times on the h2 relay leg, want 1", got)
	}
	first, second := <-f.cookieSeen, <-f.cookieSeen
	if first != "" {
		t.Errorf("first request carried cookie %q, want none", first)
	}
	if second != "sessid=fresh" {
		t.Errorf("second request carried cookie %q, want sessid=fresh (the re-login's)", second)
	}
}
