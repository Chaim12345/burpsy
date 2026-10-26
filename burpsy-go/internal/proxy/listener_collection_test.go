package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// Burp's proxy settings page leads with a LIST of listeners, each carrying its own
// "Redirect to host" / "Redirect to port" / "Force use of TLS" / "Support invisible
// proxying" (burpsy-react-ui-pfeg). Everything here is driven through real sockets and real
// origins for the reason the single-listener tests already give: a listener API tested
// against a mock proves nothing about sockets, and the whole claim of this change is that
// the added listeners actually bind and actually relay.
//
// Each per-listener control is pinned by a test that would fail if the control were merely
// stored — the redirect tests dial a name that cannot resolve, so only an honoured redirect
// can produce a response at all.

func newCollectionServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		// The force-TLS case dials a self-signed origin, so the test declares that rather than
		// relying on the unconditional skip the proxy used to carry (burpsy-react-ui-f365).
		WithUpstreamTLS(permissiveTLS()).
		WithLogger(zap.NewNop()))
}

// getThrough sends an absolute-form request through proxyAddr, the way a proxy-aware client
// does, and answers the whole response (or "" when the relay closed on it).
func getThrough(t *testing.T, proxyAddr, rawURL string) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %s: %v", rawURL, err)
	}
	req := "GET " + rawURL + " HTTP/1.1\r\nHost: " + u.Host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	out, _ := io.ReadAll(bufio.NewReader(conn))
	return string(out)
}

func Test_a_second_listener_binds_and_relays_alongside_the_first(t *testing.T) {
	srv := newCollectionServer(t)
	boot := startLiveProxy(t, srv)
	host, port := originSaying(t, "relayed")

	added, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	if added.BoundAddr == "" || strings.HasSuffix(added.BoundAddr, ":0") {
		t.Fatalf("added listener reported %q, want a resolved host:port", added.BoundAddr)
	}
	if added.BoundAddr == boot {
		t.Fatalf("the added listener bound the boot listener's own address %q", boot)
	}

	target := "http://" + host + ":" + strconv.Itoa(int(port)) + "/"
	for _, addr := range []string{boot, added.BoundAddr} {
		if got := getThrough(t, addr, target); !strings.Contains(got, "relayed") {
			t.Errorf("request through %s did not reach the origin; got %q", addr, got)
		}
	}

	// Both are reported, boot first, and the collection is a real collection.
	list := srv.Listeners()
	if len(list) != 2 || list[0].ID != BootListenerID || list[1].ID != added.ID {
		t.Fatalf("Listeners() = %+v, want the boot listener then %s", list, added.ID)
	}
}

func Test_a_listener_redirect_sends_the_request_to_the_configured_origin(t *testing.T) {
	srv := newCollectionServer(t)
	boot := startLiveProxy(t, srv)
	host, port := originSaying(t, "landed-on-the-redirect-target")

	added, err := srv.AddListener(ListenerSpec{
		Bind:         "127.0.0.1:0",
		RedirectHost: host,
		RedirectPort: port,
	})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}

	// The name cannot resolve, so a response can only come from an honoured redirect —
	// this is what makes the assertion about the relay and not about luck.
	const unreachable = "http://redirect-target-must-be-used.invalid/probe"

	if got := getThrough(t, added.BoundAddr, unreachable); !strings.Contains(got, "landed-on-the-redirect-target") {
		t.Errorf("the redirecting listener did not reach the configured origin; got %q", got)
	}
	// The control: the same request through a listener with no redirect reaches nothing.
	if got := getThrough(t, boot, unreachable); strings.Contains(got, "landed-on-the-redirect-target") {
		t.Errorf("the boot listener reached the redirect origin, so the redirect was not what moved the request: %q", got)
	}
}

func Test_a_redirect_port_alone_keeps_the_host_the_client_asked_for(t *testing.T) {
	srv := newCollectionServer(t)
	startLiveProxy(t, srv)
	host, port := originSaying(t, "port-only-redirect")

	added, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0", RedirectPort: port})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	// A port the origin is not on, against the origin's own host: only the port moves.
	got := getThrough(t, added.BoundAddr, "http://"+host+":9/probe")
	if !strings.Contains(got, "port-only-redirect") {
		t.Errorf("a port-only redirect did not reach the origin; got %q", got)
	}
}

func Test_a_listener_that_forces_TLS_reaches_the_origin_over_TLS(t *testing.T) {
	srv := newCollectionServer(t)
	startLiveProxy(t, srv)

	// A TLS-only origin: it answers nothing at all to a plaintext request, so a response
	// body is proof the proxy's own leg was TLS. It records the scheme it was reached over
	// for the same reason.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "reached in the clear", http.StatusBadRequest)
			return
		}
		io.WriteString(w, "reached-over-tls")
	}))
	t.Cleanup(origin.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	if err != nil {
		t.Fatalf("split origin addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	added, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0", ForceTLS: true})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}

	// The client speaks plaintext HTTP to the listener and names an http:// URL — the
	// sslstrip-shaped setup the setting exists for.
	got := getThrough(t, added.BoundAddr, "http://"+host+":"+strconv.Itoa(port)+"/probe")
	if !strings.Contains(got, "reached-over-tls") {
		t.Fatalf("force-TLS did not make the upstream leg TLS; got %q", got)
	}

	// And it is not merely stored: the same request on a listener without it cannot be
	// served by a TLS-only origin.
	plain, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	if got := getThrough(t, plain.BoundAddr, "http://"+host+":"+strconv.Itoa(port)+"/probe"); strings.Contains(got, "reached-over-tls") {
		t.Errorf("a listener without force-TLS reached the TLS origin anyway: %q", got)
	}

	// The exchange is recorded as the TLS exchange it was on the wire, not as the http://
	// the client typed.
	var sawTLS bool
	for _, ex := range srv.config.store.Exchanges() {
		if ex.Path == "/probe" && ex.TLS {
			sawTLS = true
		}
	}
	if !sawTLS {
		t.Error("no recorded exchange for /probe says TLS, so history disagrees with the wire")
	}
}

func Test_the_invisible_tick_is_per_listener_and_overrides_the_global_switch(t *testing.T) {
	srv := newCollectionServer(t)
	boot := startLiveProxy(t, srv)
	host, port := originSaying(t, "origin-form-served")

	// The process-wide switch is seeded ON, which is exactly why a per-listener control
	// that only ORed with it would be a no-op.
	if !srv.config.options.Get(OptInvisibleProxy) {
		t.Fatal("fixture expects invisible_proxy seeded on")
	}
	off := false
	on := true

	// nil inherits: the boot listener behaves as it always has.
	if got := proxiedGetWithHostHeader(t, boot, host, port); !strings.Contains(got, "origin-form-served") {
		t.Errorf("the boot listener refused an origin-form request while the global switch is on: %q", got)
	}

	tightened, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0", Invisible: &off})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	if got := proxiedGetWithHostHeader(t, tightened.BoundAddr, host, port); !strings.Contains(got, "400 Bad Request") {
		t.Errorf("a listener with invisible proxying ticked off still served an origin-form request: %q", got)
	}

	// And the other direction: global off, one listener ticked on.
	_ = srv.config.options.Set(OptInvisibleProxy, false)
	if got := proxiedGetWithHostHeader(t, boot, host, port); !strings.Contains(got, "400 Bad Request") {
		t.Errorf("the boot listener served an origin-form request with the global switch off: %q", got)
	}
	loosened, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0", Invisible: &on})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	if got := proxiedGetWithHostHeader(t, loosened.BoundAddr, host, port); !strings.Contains(got, "origin-form-served") {
		t.Errorf("a listener with invisible proxying ticked on refused an origin-form request: %q", got)
	}
}

func Test_a_listener_that_cannot_bind_is_refused_and_nothing_is_added(t *testing.T) {
	srv := newCollectionServer(t)
	startLiveProxy(t, srv)

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	defer taken.Close()

	before := len(srv.Listeners())
	if _, err := srv.AddListener(ListenerSpec{Bind: taken.Addr().String()}); err == nil {
		t.Fatal("AddListener accepted an address already in use")
	} else if !strings.Contains(err.Error(), taken.Addr().String()) {
		t.Errorf("the refusal does not name the address that failed: %v", err)
	}
	if got := len(srv.Listeners()); got != before {
		t.Errorf("a listener that could not bind was still added: %d listeners, want %d", got, before)
	}

	if _, err := srv.AddListener(ListenerSpec{Bind: "no-such-host-anywhere.invalid:8080"}); err == nil {
		t.Error("AddListener accepted an unresolvable address")
	}
	if got := len(srv.Listeners()); got != before {
		t.Errorf("an unbindable listener was still added: %d listeners, want %d", got, before)
	}
}

func Test_the_boot_listener_is_refused_removal_and_a_removed_listener_stops_accepting(t *testing.T) {
	srv := newCollectionServer(t)
	startLiveProxy(t, srv)
	host, port := originSaying(t, "still-here")

	if err := srv.RemoveListener(BootListenerID); err != ErrBootListenerNotRemovable {
		t.Errorf("RemoveListener(boot) = %v, want it refused", err)
	}
	if err := srv.RemoveListener("listener-does-not-exist"); err != ErrNoSuchListener {
		t.Errorf("RemoveListener(unknown) = %v, want ErrNoSuchListener", err)
	}

	added, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	target := "http://" + host + ":" + strconv.Itoa(int(port)) + "/"
	if got := getThrough(t, added.BoundAddr, target); !strings.Contains(got, "still-here") {
		t.Fatalf("the added listener did not relay before removal: %q", got)
	}

	if err := srv.RemoveListener(added.ID); err != nil {
		t.Fatalf("RemoveListener: %v", err)
	}
	if len(srv.Listeners()) != 1 {
		t.Errorf("after removal the collection is %+v, want the boot listener alone", srv.Listeners())
	}
	// The socket is gone: a new client cannot reach the proxy through it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", added.BoundAddr, 200*time.Millisecond)
		if err != nil {
			break
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("%s still accepts connections after the listener was removed", added.BoundAddr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func Test_removing_a_listener_leaves_the_exchange_it_is_relaying_alone(t *testing.T) {
	srv := newCollectionServer(t)
	startLiveProxy(t, srv)

	// An origin that will not answer until the test says so, so the removal lands while the
	// listener is demonstrably mid-relay.
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		io.WriteString(w, "finished-after-removal")
	}))
	t.Cleanup(origin.Close)

	added, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}

	conn, err := net.Dial("tcp", added.BoundAddr)
	if err != nil {
		t.Fatalf("dial the added listener: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET " + origin.URL + "/slow HTTP/1.1\r\nHost: " + strings.TrimPrefix(origin.URL, "http://") + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// Give the relay a moment to be inside the forward before the listener goes away.
	time.Sleep(150 * time.Millisecond)

	if err := srv.RemoveListener(added.ID); err != nil {
		t.Fatalf("RemoveListener while relaying: %v", err)
	}
	close(release)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	out, _ := io.ReadAll(bufio.NewReader(conn))
	if !strings.Contains(string(out), "finished-after-removal") {
		t.Errorf("removing the listener killed the exchange it was relaying; got %q", string(out))
	}
}

func Test_updating_a_listener_moves_its_socket_and_a_failed_move_leaves_it_serving(t *testing.T) {
	srv := newCollectionServer(t)
	startLiveProxy(t, srv)
	host, port := originSaying(t, "after-the-move")

	added, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	first := added.BoundAddr

	// A concrete free port, so the move is observable — an ephemeral bind is treated as
	// unchanged on purpose, which the last assertion in this test pins.
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	freeAddr := free.Addr().String()
	free.Close()

	moved, err := srv.UpdateListener(added.ID, ListenerSpec{Bind: freeAddr, RedirectPort: port})
	if err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	if moved.BoundAddr == first {
		t.Fatalf("the listener did not move: still %s", first)
	}
	if got := getThrough(t, moved.BoundAddr, "http://"+host+":9/probe"); !strings.Contains(got, "after-the-move") {
		t.Errorf("the moved listener did not relay with its new spec: %q", got)
	}

	// A move that cannot bind is an error, and the listener keeps serving where it is.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	defer taken.Close()
	if _, err := srv.UpdateListener(added.ID, ListenerSpec{Bind: taken.Addr().String()}); err == nil {
		t.Fatal("UpdateListener accepted an address already in use")
	}
	if got := getThrough(t, moved.BoundAddr, "http://"+host+":9/probe"); !strings.Contains(got, "after-the-move") {
		t.Errorf("a failed move took the listener down; got %q from %s", got, moved.BoundAddr)
	}

	// A spec-only edit must not recycle the socket: an ephemeral bind would come back on a
	// different port than the one the operator is pointing a client at, and re-binding the
	// address this listener already holds would answer address-in-use.
	for _, bind := range []string{moved.Bind, moved.BoundAddr} {
		same, err := srv.UpdateListener(added.ID, ListenerSpec{Bind: bind, RedirectPort: port})
		if err != nil {
			t.Fatalf("spec-only UpdateListener with bind %q: %v", bind, err)
		}
		if same.BoundAddr != moved.BoundAddr {
			t.Errorf("a spec-only edit (bind %q) moved the socket from %s to %s", bind, moved.BoundAddr, same.BoundAddr)
		}
	}
}

func Test_a_listener_cannot_be_added_before_the_proxy_is_listening(t *testing.T) {
	srv := newCollectionServer(t)
	if _, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0"}); err != ErrNotListening {
		t.Errorf("AddListener before ListenAndServe = %v, want ErrNotListening — a socket nothing accepts on is the dead listener this refuses to create", err)
	}
}

// A PUT that lands before main.go's ListenAndServe goroutine has bound seeds the boot entry,
// and the loop then adopts it. One socket has to be one row: listing it twice would have the
// panel offering two Edit buttons for the same listener.
func Test_a_rebind_before_the_loop_starts_leaves_exactly_one_boot_listener(t *testing.T) {
	srv := newCollectionServer(t)
	if _, err := srv.Rebind("127.0.0.1:0"); err != nil {
		t.Fatalf("Rebind before ListenAndServe: %v", err)
	}
	addr := startLiveProxy(t, srv)
	list := srv.Listeners()
	if len(list) != 1 || list[0].ID != BootListenerID {
		t.Fatalf("Listeners() = %+v, want exactly one boot listener", list)
	}
	if list[0].BoundAddr != addr || strings.HasSuffix(addr, ":0") {
		t.Errorf("the boot listener reports %q, want the resolved address %q", list[0].BoundAddr, addr)
	}
}

func Test_normalize_redirect_host_refuses_what_it_cannot_mean(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		bad  bool
	}{
		{in: "", want: ""},
		{in: "  example.com  ", want: "example.com"},
		{in: "127.0.0.1", want: "127.0.0.1"},
		{in: "[::1]", want: "[::1]"},
		{in: "::1", want: "[::1]"},
		{in: "http://example.com", bad: true},
		{in: "example.com/path", bad: true},
		{in: "example.com:8080", bad: true},
	} {
		got, err := NormalizeRedirectHost(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("NormalizeRedirectHost(%q) = %q, want a refusal", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeRedirectHost(%q): %v", tc.in, err)
		} else if got != tc.want {
			t.Errorf("NormalizeRedirectHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// An edit to a listener has to reach the very next connection, not the one after it.
//
// The accept loop reads the spec and then blocks in Accept, so the spec a connection is relayed
// under was read before the connection existed — and for an idle listener, before the edit did.
// That made every setting on this page quietly one connection late: an operator who set a redirect
// and sent a request watched it go to the origin they had just redirected away from, with nothing
// anywhere saying why, and the second identical request behaving differently from the first. A
// standing setting that skips one request is worse than one that does not work at all, because
// the evidence that it works arrives right after the evidence that it does not.
func Test_an_edited_listener_relays_the_very_next_connection_under_the_new_spec(t *testing.T) {
	srv := newCollectionServer(t)
	startLiveProxy(t, srv)
	host, port := originSaying(t, "reached-after-the-edit")

	added, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}

	// One request first, so the loop has gone round and is parked in Accept holding a spec
	// with no redirect — the state an idle listener is in when an operator edits it.
	const unreachable = "http://redirect-target-must-be-used.invalid/probe"
	if got := getThrough(t, added.BoundAddr, unreachable); strings.Contains(got, "reached-after-the-edit") {
		t.Fatalf("the listener reached the origin before any redirect was set: %q", got)
	}

	if _, err := srv.UpdateListener(added.ID, ListenerSpec{
		Bind:         added.BoundAddr,
		RedirectHost: host,
		RedirectPort: port,
	}); err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}

	// The FIRST connection after the edit. The name cannot resolve, so only an honoured
	// redirect answers at all.
	if got := getThrough(t, added.BoundAddr, unreachable); !strings.Contains(got, "reached-after-the-edit") {
		t.Errorf("the first connection after the edit was relayed under the old spec, so the redirect was one connection late; got %q", got)
	}
}
