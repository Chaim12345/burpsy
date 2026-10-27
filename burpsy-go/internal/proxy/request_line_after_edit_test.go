package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// A request's method and path are read once, from the client's first line, and everything after that
// point can rewrite that line: the operator's hold in Intercept, and the request-direction rules that
// run in the same slot. Until these tests existed the locals kept the client's original answer, so
// both the scope check and the recorded index row were describing a URL the exchange does not
// contain.
//
// The two halves are asserted separately because they fail differently and one can be fixed without
// the other: the index row is a reporting defect (history names an endpoint nothing was sent to),
// while the scope check is an egress-fence bypass (a path-scoped rule evaluated against the wrong
// path). The second is the one that matters.

// editTargetProxy starts a proxy holding every request for the operator, and rewrites each held
// request's first-line target from `from` to `to` as soon as it appears — the automated stand-in for
// an operator typing in the held request, which is the only way to produce these bytes.
func editTargetProxy(t *testing.T, scope *core.Scope, from, to string) (*http.Client, *core.TrafficStore) {
	t.Helper()
	return editTargetProxyWith(t, scope, nil, from, to)
}

// editTargetProxyWith is the same proxy with an explicit option set, for the tests that need an
// out-of-scope exchange to be recorded so its row can be inspected.
func editTargetProxyWith(t *testing.T, scope *core.Scope, options *Options, from, to string) (*http.Client, *core.TrafficStore) {
	t.Helper()
	if options == nil {
		options = NewOptions()
	}
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	// An empty rule list on an active list is Burp's "intercept everything".
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(scope).
		WithIntercept(engine).
		WithOptions(options).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())).
		WithFindings(core.NewFindingStore()))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	// The operator stops with the test (not after a fixed deadline), so no loop outlives it for
	// goleak to find when a narrow -run selection finishes in milliseconds.
	stop, stopped := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(stop); <-stopped })
	go func() {
		defer close(stopped)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-stop:
				return
			default:
			}
			for _, held := range engine.Held() {
				if held.Direction != intercept.DirectionRequest {
					continue
				}
				// The target sits in the middle of the request line, so replacing the substring is
				// exactly the edit an operator makes in the raw pane — and it leaves Content-Length
				// alone, which is what makes this a first-line edit rather than a body edit.
				edited := strings.Replace(string(held.Raw), " "+from+" ", " "+to+" ", 1)
				_ = engine.Forward(held.ID, &edited, false, nil)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	return &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
	}}, store
}

// The recorded row names the endpoint the bytes name. Before this, an operator who edited the target
// in Intercept got a history row pointing at the URL the client asked for — with an Edited badge on
// it saying the row had been changed — and no way to tell which endpoint the scan had actually hit.
func TestAnInterceptEditToTheRequestLineIsWhatHistoryRecords(t *testing.T) {
	var originSaw string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originSaw = r.URL.Path
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	host, port := originHostPort(t, origin)

	client, store := editTargetProxy(t, testScope(), "/before", "/after")

	resp, err := client.Get(fmt.Sprintf("http://%s:%d/before", host, port))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if originSaw != "/after" {
		t.Fatalf("the origin was asked for %q, want the operator's edit; the rest of this test would be vacuous", originSaw)
	}
	// Fail-first: the assertion is that an exchange is findable *by the edited path*. If the index row
	// still held the client's path, this lookup finds nothing and reports so.
	ex := awaitExchangeFor(t, store, "/after", "proxy")
	if ex.Path != "/after" {
		t.Errorf("history shows path %q for an exchange whose bytes request /after; the row names an endpoint nothing was sent to", ex.Path)
	}
	if ex.Method != http.MethodGet {
		t.Errorf("recorded method = %q, want GET", ex.Method)
	}
	// And it is still marked edited, so the two halves of the feature agree: the row is flagged as
	// hand-modified *and* describes what the modification produced.
	if !ex.HasRetainedStage(core.DirectionRequest) {
		t.Error("an edited request retained nothing, so the operator cannot compare what was sent with what the client asked for")
	}
}

// The half that is a fencing question rather than a reporting one. A scope rule may carry a path
// prefix, and it is evaluated against the path the proxy is about to send — so an edit that moves a
// request under an excluded prefix has to be refused at egress. While the path local kept the client's
// answer, that edit walked straight through a fence the settings page said was up.
func TestAnEditIntoAnExcludedPathIsRefusedAtEgress(t *testing.T) {
	var reached int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	host, port := originHostPort(t, origin)

	scope := core.NewScope()
	scope.AddInclude(host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/forbidden"))
	// Burp's "Drop all out-of-scope requests": the setting that makes scope an egress fence rather
	// than only a retention rule. Without it an excluded request is forwarded and unrecorded, which is
	// the other legitimate answer — and the one asserted in the next test.
	scope.SetDropOutOfScope(true)

	client, store := editTargetProxy(t, scope, "/allowed", "/forbidden/deeper")

	resp, err := client.Get(fmt.Sprintf("http://%s:%d/allowed", host, port))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if reached != 0 {
		t.Fatalf("the origin was reached %d time(s); the edit moved the request under an excluded path prefix and the egress fence did not notice", reached)
	}
	if !strings.Contains(string(body), "scope") && !strings.Contains(string(body), "Scope") {
		t.Errorf("the client received %q; a refusal the operator cannot attribute is indistinguishable from a network fault", body)
	}
	if _, total := store.Count(); total != 0 {
		t.Errorf("a refused exchange was recorded (%d exchange(s)); nothing reached the origin, so nothing may be stored as though it had", total)
	}
}

// The same edit with the fence switched off is forwarded and honestly marked out of scope. This is
// the pair that keeps the fix from being "refuse more": the path the operator typed decides the
// retention answer too, and a row that claimed to be in scope while sitting under an excluded prefix
// was the other half of the same stale-path bug.
func TestAnEditIntoAnExcludedPathIsMarkedOutOfScopeWhenTheFenceIsOff(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	host, port := originHostPort(t, origin)

	scope := core.NewScope()
	scope.AddInclude(host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/forbidden"))
	scope.SetDropOutOfScope(false)

	// Burp's seeding forwards out-of-scope traffic without keeping it, so the exchange this test wants
	// to read back has to be asked for explicitly. Turning it off is a documented option, not a
	// back door: an operator who wants excluded hosts in their history sets exactly this.
	options := NewOptions()
	if err := options.Set(OptDontLogOutOfScope, false); err != nil {
		t.Fatalf("set %s: %v", OptDontLogOutOfScope, err)
	}

	client, store := editTargetProxyWith(t, scope, options, "/allowed", "/forbidden/deeper")

	resp, err := client.Get(fmt.Sprintf("http://%s:%d/allowed", host, port))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("the origin answered %q; with the drop switch off an excluded request is still issued", body)
	}

	ex := awaitExchangeFor(t, store, "/forbidden/deeper", "proxy")
	if scope.Contains(ex.Host, ex.Port, ex.Path, ex.TLS) {
		t.Errorf("the recorded request to %s is reported in scope; the operator's edit moved it under an excluded path prefix", ex.Path)
	}
}
