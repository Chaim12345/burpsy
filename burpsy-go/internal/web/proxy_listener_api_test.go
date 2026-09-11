package web

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/proxy"
)

// ---- /api/proxy/listener: Burp's "Proxy listeners" Binding tab -------------------
//
// The decision recorded on burpsy-react-ui-77m scopes this to one re-bindable
// listener: GET answers the address the accept loop actually serves, PUT moves it,
// and a bind that fails is an error the operator sees while the old listener keeps
// serving. The endpoint rides a real proxy.Server and a real socket — a listener
// API tested against a mock listener would prove nothing about sockets.

// startAPIProxy builds the shape main.go builds — one proxy.Server with a live
// ListenAndServe loop, the same instance attached to the web server — and answers
// both addresses.
func startAPIProxy(t *testing.T) (webServer *Server, proxyServer *proxy.Server) {
	t.Helper()
	proxyServer = proxy.NewServer(proxy.NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScopeAllowEverything()))
	webServer = NewServer(core.NewTrafficStore(), core.NewScope()).WithProxyServer(proxyServer)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = proxyServer.ListenAndServe(ctx, "127.0.0.1:0")
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if proxyServer.ListenerAddr() != "" {
			return webServer, proxyServer
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("fixture proxy never started listening")
	return webServer, proxyServer
}

func TestProxyListenerGetReportsTheLiveAddress(t *testing.T) {
	ts, ps := startAPIProxy(t)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/proxy/listener", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/proxy/listener = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Bind string `json:"bind"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Bind != ps.ListenerAddr() {
		t.Errorf("GET reported %q, want the listener's live address %q", view.Bind, ps.ListenerAddr())
	}
	// An ephemeral bind must come back resolved: ":0" or a bare host would leave the
	// panel describing an address nothing can be pointed at.
	if view.Bind == "" || strings.HasSuffix(view.Bind, ":0") {
		t.Errorf("GET reported %q, want a resolved host:port", view.Bind)
	}
}

func TestProxyListenerPutRebindsAndTheNewSocketServes(t *testing.T) {
	ts, _ := startAPIProxy(t)

	// The replacement port is taken out from under nothing: it is simply a free port
	// the new socket can bind, found by listening and closing.
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	target := free.Addr().String()
	free.Close()

	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/proxy/listener",
		strings.NewReader(`{"bind":"`+target+`"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/proxy/listener = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Bind         string `json:"bind"`
		PreviousBind string `json:"previous_bind"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Bind != target {
		t.Errorf("PUT confirmed %q, want %q", view.Bind, target)
	}
	if view.PreviousBind == "" {
		t.Error("PUT answered without the address it moved from; the panel would lose the before picture")
	}

	// The moved socket accepts, and a GET reflects the same address: the response
	// body and the listener must not be allowed to disagree.
	rec = httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/proxy/listener", nil))
	var after struct {
		Bind string `json:"bind"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatalf("decode follow-up GET: %v", err)
	}
	if after.Bind != target {
		t.Errorf("GET after PUT reports %q, want %q", after.Bind, target)
	}
}

// burpsy-react-ui-459i: every Rebind failure used to answer 400 here, though the close note on
// -77m already claimed "an occupied port or unmeaning address leaves the previous listener serving
// and is answered 409/400 with the reason" — the first half was true, the status code half was not.
// An occupied port is a state conflict the caller can resolve by picking another address (409); a
// malformed or unresolvable one is the caller's own mistake (400). This test used to assert the bug
// (400 here) and is corrected to assert the note's original claim instead.
func TestProxyListenerPutToAnOccupiedPortAnswers409AndKeepsTheOldListener(t *testing.T) {
	ts, ps := startAPIProxy(t)
	before := ps.ListenerAddr()

	squatter, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("squat listen: %v", err)
	}
	defer squatter.Close()

	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/proxy/listener",
		strings.NewReader(`{"bind":"`+squatter.Addr().String()+`"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("PUT onto an occupied port = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "listen") {
		t.Errorf("the 409 should carry the bind failure, got: %s", rec.Body.String())
	}
	if got := ps.ListenerAddr(); got != before {
		t.Fatalf("after a failed rebind the listener is %q, want the untouched %q", got, before)
	}
}

// A bind failure that is not "address already in use" stays 400: the caller asked for something
// this host cannot do, not something merely unavailable right now. 10.255.255.1 is a valid IPv4
// literal — it passes normalizeListenerAddr's host:port and port-range checks (a non-empty host and
// a 0-65535 port are all that requires) and needs no DNS lookup, so the failure is immediate — but
// it is not an address assigned to any local interface, so net.Listen fails with EADDRNOTAVAIL, not
// EADDRINUSE. This exercises the same Rebind error branch the occupied-port case does and pins that
// the branch actually distinguishes the errno rather than answering 409 for every Rebind failure.
func TestProxyListenerPutToAnUnassignableAddressStays400(t *testing.T) {
	ts, ps := startAPIProxy(t)
	before := ps.ListenerAddr()

	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/proxy/listener",
		strings.NewReader(`{"bind":"10.255.255.1:0"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT to an unassignable address = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := ps.ListenerAddr(); got != before {
		t.Fatalf("after a failed rebind the listener is %q, want the untouched %q", got, before)
	}
}

func TestProxyListenerPutRejectsAddressesItCannotMean(t *testing.T) {
	ts, _ := startAPIProxy(t)
	cases := []struct {
		name   string
		body   string
		reason string
	}{
		{"empty bind", `{"bind":""}`, "required"},
		{"missing port", `{"bind":"127.0.0.1"}`, "host:port"},
		{"missing host", `{"bind":":8080"}`, "host"},
		{"port out of range", `{"bind":"127.0.0.1:70000"}`, "0 and 65535"},
		{"port not a number", `{"bind":"127.0.0.1:web"}`, "number"},
		{"not JSON", `bind`, "JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/proxy/listener",
				strings.NewReader(tc.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PUT %s = %d, want 400: %s", tc.body, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.reason) {
				t.Errorf("the 400 should name the problem (%q), got: %s", tc.reason, rec.Body.String())
			}
		})
	}
}

func TestProxyListenerWithoutAServerAttachedReports503(t *testing.T) {
	ts := NewServer(core.NewTrafficStore(), core.NewScope())
	for _, verb := range []string{http.MethodGet, http.MethodPut} {
		rec := httptest.NewRecorder()
		ts.mux.ServeHTTP(rec, httptest.NewRequest(verb, "/api/proxy/listener",
			strings.NewReader(`{"bind":"127.0.0.1:8080"}`)))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s /api/proxy/listener with no proxy attached = %d, want 503", verb, rec.Code)
		}
	}
}

func TestProxyListenerWrongVerbIs405(t *testing.T) {
	ts, _ := startAPIProxy(t)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/proxy/listener",
		strings.NewReader(`{}`)))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/proxy/listener = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") || !strings.Contains(allow, "PUT") {
		t.Errorf("Allow header = %q, want GET, PUT", allow)
	}
}
