package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"go.uber.org/zap"
)

// Burp's intercept header bar carries an "Edit target" pencil (BurpClass9694.java:196-206,
// tooltip "Click to modify"): the operator can send the item they are holding somewhere other than
// where the client asked. burpsy's authority was read-only and the forward body carried no
// destination, so the capability was absent end to end (burpsy-react-ui-akv).
//
// Three things have to be true for that to be a feature rather than a hole:
//
//  1. the request actually reaches the edited destination;
//  2. the recorded exchange names that destination, because history must show where the bytes went;
//  3. and the scope is answered about the edited destination — a host typed into the intercept pane
//     must not be a way past the egress fence the operator set up.
//
// Each of those has its own test below, and (3) is the one that would be a security defect if it
// were missing.

// retargetProxy starts a proxy on an ephemeral port with intercept holding every request, an
// operator goroutine that forwards each held request to a destination the test chooses, and returns
// the proxy address plus the exchange store.
func retargetProxy(t *testing.T, scope *core.Scope, choose func(held *intercept.Held) *intercept.Target) (string, *core.TrafficStore, *intercept.Engine) {
	t.Helper()

	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	// An empty rule list on an active list is Burp's "intercept everything": this test is about
	// where the request goes, not about rule matching.
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(scope).
		WithIntercept(engine).
		WithLogger(zap.NewNop()))

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

	// The operator. Forwards each request-direction hold exactly once, to whatever destination the
	// test names, and ignores response holds (a retarget is a request-side decision; a response has
	// already come back from somewhere).
	go func() {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			for _, held := range engine.Held() {
				if held.Direction != intercept.DirectionRequest {
					continue
				}
				_ = engine.Forward(held.ID, nil, false, choose(held))
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	return ln.Addr().String(), store, engine
}

// originAddr returns the host and port of an httptest server.
func originAddr(t *testing.T, srv *httptest.Server) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		// A TLS test server's URL is https://, which TrimPrefix above does not strip.
		host, portStr, err = net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://"))
		if err != nil {
			t.Fatalf("split %q: %v", srv.URL, err)
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return host, uint16(port)
}

// proxyOnce sends one absolute-form request through the proxy and returns the response text.
func proxyOnce(t *testing.T, proxyAddr, targetAddr, path string) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	req := "GET http://" + targetAddr + path + " HTTP/1.1\r\n" +
		"Host: " + targetAddr + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(raw)
}

// TestARetargetedHeldRequestReachesTheEditedDestinationAndIsRecordedAgainstIt is the ordinary case:
// the client asked for A, the operator sent it to B, B answered, and history says B.
func TestARetargetedHeldRequestReachesTheEditedDestinationAndIsRecordedAgainstIt(t *testing.T) {
	var aHits, bHits atomic.Int32
	originA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aHits.Add(1)
		_, _ = w.Write([]byte("answered-by-A"))
	}))
	defer originA.Close()
	originB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHits.Add(1)
		_, _ = w.Write([]byte("answered-by-B"))
	}))
	defer originB.Close()

	aHost, aPort := originAddr(t, originA)
	bHost, bPort := originAddr(t, originB)

	proxyAddr, store, _ := retargetProxy(t, core.NewScope(), func(*intercept.Held) *intercept.Target {
		return &intercept.Target{Host: bHost, Port: bPort, TLS: false}
	})

	response := proxyOnce(t, proxyAddr, net.JoinHostPort(aHost, strconv.Itoa(int(aPort))), "/retarget-me")
	if !strings.Contains(response, "answered-by-B") {
		t.Fatalf("response did not come from the edited destination:\n%s", response)
	}
	if aHits.Load() != 0 {
		t.Errorf("the original origin received %d requests; a retarget must not also send it there", aHits.Load())
	}
	if bHits.Load() != 1 {
		t.Errorf("the edited destination received %d requests, want 1", bHits.Load())
	}

	// History follows the wire, not the client's intent: a row naming the original host would make
	// the retarget invisible to every later reader, replay and report.
	exchanges := store.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("store holds %d exchanges, want exactly the retargeted one", len(exchanges))
	}
	ex := exchanges[0]
	if ex.Host != bHost || ex.Port != bPort {
		t.Errorf("recorded destination is %s:%d, want the edited %s:%d", ex.Host, ex.Port, bHost, bPort)
	}
	if ex.TLS {
		t.Error("recorded TLS = true, but the edited destination was served in plaintext")
	}
}

// TestARetargetCanChangeTheScheme proves the TLS axis is real rather than a third field nothing
// reads: an http client request sent to an https origin has to be dialled with TLS, and the row has
// to say so.
func TestARetargetCanChangeTheScheme(t *testing.T) {
	originA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("answered-by-A"))
	}))
	defer originA.Close()
	originTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("answered-by-tls-B"))
	}))
	defer originTLS.Close()

	aHost, aPort := originAddr(t, originA)
	bHost, bPort := originAddr(t, originTLS)

	proxyAddr, store, _ := retargetProxy(t, core.NewScope(), func(*intercept.Held) *intercept.Target {
		return &intercept.Target{Host: bHost, Port: bPort, TLS: true}
	})

	response := proxyOnce(t, proxyAddr, net.JoinHostPort(aHost, strconv.Itoa(int(aPort))), "/upgrade-me")
	if !strings.Contains(response, "answered-by-tls-B") {
		t.Fatalf("response did not come from the TLS destination:\n%s", response)
	}

	exchanges := store.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("store holds %d exchanges, want 1", len(exchanges))
	}
	if !exchanges[0].TLS {
		t.Error("recorded TLS = false for an https destination; the scheme axis is not reaching the record")
	}
}

// TestARetargetIsRefusedWhenTheEditedDestinationIsOutOfScope is the decision that keeps this feature
// from being a hole in the egress fence.
//
// The scope and "drop all out-of-scope requests" are the control the operator sets up so burpsy
// cannot be pointed at hosts outside the engagement. If the intercept pane's target editor ignored
// them, anyone at the keyboard — or anything that can reach the web API — could send traffic to any
// host by typing it in, which is precisely what the control exists to prevent. So the edited
// destination is authorised, not the original one.
func TestARetargetIsRefusedWhenTheEditedDestinationIsOutOfScope(t *testing.T) {
	var bHits atomic.Int32
	originA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("answered-by-A"))
	}))
	defer originA.Close()

	// B is bound to a second loopback address rather than another port on the first, because a scope
	// rule without a port arm covers every port on its host — two ports on 127.0.0.1 would both be in
	// scope, and this test would pass without the fence doing anything.
	lnB, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2 (second loopback address unavailable): %v", err)
	}
	originB := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHits.Add(1)
		_, _ = w.Write([]byte("answered-by-B"))
	}))
	originB.Listener.Close()
	originB.Listener = lnB
	originB.Start()
	defer originB.Close()

	aHost, aPort := originAddr(t, originA)
	bHost, bPort := originAddr(t, originB)
	if bHost == aHost {
		t.Fatalf("the two origins share host %q, so this test could not tell the scope fence from a rule that covers both", bHost)
	}

	// Only A is in scope, and the fence is up.
	scope := core.NewScope()
	scope.AddInclude(aHost)
	scope.SetDropOutOfScope(true)

	proxyAddr, store, _ := retargetProxy(t, scope, func(*intercept.Held) *intercept.Target {
		return &intercept.Target{Host: bHost, Port: bPort, TLS: false}
	})

	response := proxyOnce(t, proxyAddr, net.JoinHostPort(aHost, strconv.Itoa(int(aPort))), "/should-be-fenced")
	if !strings.Contains(response, "403") {
		t.Fatalf("an out-of-scope retarget was not refused:\n%s", response)
	}
	if bHits.Load() != 0 {
		t.Fatalf("the out-of-scope destination received %d requests; the fence was bypassed by the target editor", bHits.Load())
	}
	if got := len(store.Exchanges()); got != 0 {
		t.Errorf("store holds %d exchanges for a refused retarget, want 0", got)
	}
}

// TestARetargetEqualToTheCurrentDestinationTakesTheOrdinaryPath: the console sends the authority it
// is showing on every forward, including a forward where the operator changed nothing. Treating that
// as a retarget would dial a fresh connection for every ordinary forward through the tunnel, which is
// both slower and a behaviour change nobody asked for.
func TestARetargetEqualToTheCurrentDestinationTakesTheOrdinaryPath(t *testing.T) {
	originA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("answered-by-A"))
	}))
	defer originA.Close()
	aHost, aPort := originAddr(t, originA)

	proxyAddr, _, engine := retargetProxy(t, core.NewScope(), func(held *intercept.Held) *intercept.Target {
		// Exactly the authority the hold already carries.
		return &intercept.Target{Host: held.Host, Port: held.Port, TLS: held.TLS}
	})

	target := net.JoinHostPort(aHost, strconv.Itoa(int(aPort)))
	response := proxyOnce(t, proxyAddr, target, "/unchanged")
	if !strings.Contains(response, "answered-by-A") {
		t.Fatalf("an unchanged target did not reach the origin:\n%s", response)
	}

	// The engine collapses the no-op to nil, which is what makes the ordinary path ordinary. Asserted
	// through Wait rather than by inspecting internals, because the collapse is a contract the proxy
	// relies on.
	//
	// The rules list was consumed by the ordinary request above (a rule list is not a one-shot), so it
	// is re-armed with the empty "intercept everything" list before holding the second message.
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	held := engine.Hold(intercept.ParseMessage(intercept.DirectionRequest, aHost, aPort, false, "GET", "/x", []byte("GET /x HTTP/1.1\r\nHost: h\r\n\r\n")))
	if held == nil {
		t.Fatal("nothing was held")
	}
	done := make(chan *intercept.Target, 1)
	go func() {
		_, _, target, _ := held.Wait()
		done <- target
	}()
	if err := engine.Forward(held.ID, nil, false, &intercept.Target{Host: aHost, Port: aPort, TLS: false}); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	select {
	case target := <-done:
		if target != nil {
			t.Errorf("an unchanged target came back as %+v, want nil so the proxy takes its ordinary path", *target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait never returned")
	}
}
