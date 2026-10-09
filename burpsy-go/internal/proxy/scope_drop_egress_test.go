package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// ---- "Drop all out-of-scope requests" is an EGRESS fence, and the proxy is where most of the
//      traffic is (burpsy-react-ui-ckqx) ----------------------------------------------------
//
// The switch existed on core.Scope, was persisted, was reported by the settings page, and was
// read by nothing on either relay path. So the proxy forwarded excluded hosts exactly as before
// while the UI said the fence was up. For a tool whose scope list is how an operator keeps
// inside an authorised engagement boundary, a fence that reports itself and is not there is
// worse than no fence, because it is trusted.
//
// These tests assert the only thing that actually matters: whether the ORIGIN was contacted.
// A test that only checked the client's reply would pass against a proxy that forwarded the
// request and then discarded the response.

// countingOrigin serves a page and counts how many requests actually reached it.
func countingOrigin(t *testing.T) (host string, port int, hits *atomic.Int64) {
	t.Helper()
	var seen atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>origin was reached</body></html>"))
	}))
	t.Cleanup(srv.Close)
	h, p, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ = strconv.Atoi(p)
	return h, port, &seen
}

// driveThroughProxyResponse is driveThroughProxy with the status kept: a refusal is a status,
// not a body, and this suite's subject is the refusal.
func driveThroughProxyResponse(t *testing.T, srv *Server, host string, port int) (int, string) {
	t.Helper()
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
			go srv.handleConnection(conn)
		}
	}()

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
	}}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/page", host, port))
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func dropScopeExcludingOrigin() *core.Scope {
	s := core.NewScope()
	s.AddInclude("scoped-target.test")
	s.SetDropOutOfScope(true)
	return s
}

// The fence: with the switch on, an excluded host is never dialed.
func TestDropOutOfScopeStopsTheProxyFromReachingAnExcludedOrigin(t *testing.T) {
	host, port, hits := countingOrigin(t)

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(dropScopeExcludingOrigin()).
		WithLogger(zap.NewNop()))

	status, body := driveThroughProxyResponse(t, srv, host, port)

	if got := hits.Load(); got != 0 {
		t.Errorf("the origin was contacted %d time(s); the drop switch means the request is not issued at all", got)
	}
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — a refusal the operator can see, not a closed socket they must guess at", status)
	}
	// The reply has to name the setting. This refusal comes from a switch that may have been
	// flipped hours earlier, and "403" alone sends the operator to look at the target.
	if !strings.Contains(body, "out-of-scope request handling is set to drop") {
		t.Errorf("the refusal does not say why it happened: %q", body)
	}
}

// The default: with the switch off, the pre-existing contract holds — an excluded request is
// still forwarded, it is simply not kept. Flipping this on upgrade would break every session
// for operators who never touched the setting, which is why the seed is off.
func TestWithoutTheDropSwitchAnExcludedOriginIsStillReached(t *testing.T) {
	host, port, hits := countingOrigin(t)

	scope := core.NewScope()
	scope.AddInclude("scoped-target.test") // switch deliberately left off

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(scope).
		WithLogger(zap.NewNop()))

	status, body := driveThroughProxyResponse(t, srv, host, port)

	if got := hits.Load(); got != 1 {
		t.Errorf("the origin was contacted %d time(s), want 1 — scope decides retention, not egress, until the switch says otherwise", got)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !strings.Contains(body, "origin was reached") {
		t.Errorf("the client did not get the origin's page: %q", body)
	}
}

// An in-scope host is untouched by the switch — the fence refuses what the rules exclude, and
// nothing else. Without this, a fence that refused everything would pass the first test.
func TestDropOutOfScopeLetsAnIncludedOriginThrough(t *testing.T) {
	host, port, hits := countingOrigin(t)

	scope := core.NewScope()
	scope.AddInclude(host)
	scope.SetDropOutOfScope(true)

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(scope).
		WithLogger(zap.NewNop()))

	status, _ := driveThroughProxyResponse(t, srv, host, port)

	if got := hits.Load(); got != 1 {
		t.Errorf("an included origin was contacted %d time(s), want 1 — the switch must not refuse what scope allows", got)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
}

// The drop is senior to the retention branch. dont_log_out_of_scope's "forward without storing"
// path calls forwardOnly, which reaches the origin; if the egress check sat after it, the switch
// would be defeated by the setting that happens to be seeded ON.
func TestTheDropIsCheckedBeforeTheDontLogForwardPath(t *testing.T) {
	host, port, hits := countingOrigin(t)

	options := NewOptions()
	setFlag(t, options, OptDontLogOutOfScope, true) // the seed, stated rather than assumed

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(dropScopeExcludingOrigin()).
		WithOptions(options).
		WithLogger(zap.NewNop()))

	status, _ := driveThroughProxyResponse(t, srv, host, port)

	if got := hits.Load(); got != 0 {
		t.Errorf("the origin was contacted %d time(s): the retention path forwarded a request egress had refused", got)
	}
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
}

// The TLS relay path carries the same fence. It is a separate code path with its own scope
// check, and a fix applied to one and not the other would leave https — the majority of real
// traffic — outside the fence while the tests looked green.
func TestDropOutOfScopeStopsTheTLSPathFromReachingAnExcludedOrigin(t *testing.T) {
	certDir := t.TempDir()
	cert, _ := generateSelfSigned(t, certDir)

	var hits atomic.Int64
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("<html><body>origin was reached</body></html>"))
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

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(dropScopeExcludingOrigin()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(permissiveTLS()).
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
			go srv.handleConnection(conn)
		}
	}()

	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + net.JoinHostPort(thost, tportStr) + "/")
	if err != nil {
		t.Fatalf("https through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if got := hits.Load(); got != 0 {
		t.Errorf("the TLS origin was contacted %d time(s); the drop switch means the request is not issued at all", got)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(string(body), "out-of-scope request handling is set to drop") {
		t.Errorf("the TLS refusal does not say why it happened: %q", body)
	}
}

// Burp's "Use custom scope" arm (burpsy-react-ui-47ed): the drop gate asks the custom scope, not the
// suite scope. An origin the suite scope includes is still dropped when the custom scope leaves it
// out, and one the suite scope leaves out is forwarded when the custom scope names it.
func TestACustomDropScopeDecidesWhatTheProxyDrops(t *testing.T) {
	host, port, hits := countingOrigin(t)

	suiteIncludes := core.NewScope()
	suiteIncludes.AddInclude(host)
	suiteIncludes.SetDropOutOfScope(true)
	custom := core.NewScope()
	custom.AddInclude("elsewhere.test")
	suiteIncludes.SetDropScope(custom, true)
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).WithScope(suiteIncludes).WithLogger(zap.NewNop()))
	if status, _ := driveThroughProxyResponse(t, srv, host, port); status != http.StatusForbidden || hits.Load() != 0 {
		t.Errorf("suite scope includes the origin, custom scope does not: status %d, %d hit(s); want 403 and none",
			status, hits.Load())
	}

	suiteExcludes := core.NewScope()
	suiteExcludes.AddInclude("elsewhere.test")
	suiteExcludes.SetDropOutOfScope(true)
	named := core.NewScope()
	named.AddInclude(host)
	suiteExcludes.SetDropScope(named, true)
	srv = NewServer(NewProxyConfig(core.NewTrafficStore()).WithScope(suiteExcludes).WithLogger(zap.NewNop()))
	if status, _ := driveThroughProxyResponse(t, srv, host, port); status != http.StatusOK || hits.Load() != 1 {
		t.Errorf("custom scope names the origin, suite scope does not: status %d, %d hit(s); want 200 and one",
			status, hits.Load())
	}
}
