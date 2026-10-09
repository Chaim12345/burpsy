package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// The listener's in-browser interface (burpsy-react-ui-beof), and the Miscellaneous switches that sit
// beside its disable switch (0q9d): HTTP/1.0 to the server and to the client, and suppressing burpsy's
// own error messages.

// rawExchange sends one raw request to the proxy and returns everything it answered before closing.
func rawExchange(t *testing.T, proxyAddr, request string) []byte {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(conn)
	return out
}

func newInterfaceProxy(t *testing.T, opts *Options) (*Server, string, *core.TrafficStore) {
	t.Helper()
	engine, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy := NewTlsPolicy()
	policy.WithEngine(engine)
	store := core.NewTrafficStore()
	cfg := NewProxyConfig(store).WithScope(testScope()).WithLogger(zap.NewNop()).WithTlsPolicy(policy)
	if opts != nil {
		cfg = cfg.WithOptions(opts)
	}
	srv := NewServer(cfg)
	return srv, startProxy(t, srv), store
}

func TestTheWebInterfaceServesTheCACertificateAndIsNotRecorded(t *testing.T) {
	srv, addr, store := newInterfaceProxy(t, nil)

	page := rawExchange(t, addr, "GET http://burpsuite/ HTTP/1.1\r\nHost: burpsuite\r\n\r\n")
	if !bytes.HasPrefix(page, []byte("HTTP/1.1 200 OK")) || !bytes.Contains(page, []byte(`href="/cert"`)) {
		t.Fatalf("http://burpsuite/ answered %q", page)
	}

	cert := rawExchange(t, addr, "GET http://burpsy/cert HTTP/1.1\r\nHost: burpsy\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(cert)), nil)
	if err != nil {
		t.Fatalf("reading /cert: %v (%q)", err, cert)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-x509-ca-cert" ||
		!bytes.Equal(body, srv.config.tls.engine.caCert.Raw) {
		t.Errorf("/cert = %d %q, %d bytes; want 200, the CA's own DER", resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
	}

	// The listener's own address, the way a browser pointed straight at the listener sends it.
	self := rawExchange(t, addr, "GET / HTTP/1.1\r\nHost: "+addr+"\r\n\r\n")
	if !bytes.Contains(self, []byte("burpsy proxy listener")) {
		t.Errorf("a request for the listener itself was not answered by the interface: %q", self)
	}

	time.Sleep(50 * time.Millisecond)
	if n := len(store.Exchanges()); n != 0 {
		t.Errorf("%d interface request(s) were recorded as traffic", n)
	}
}

func TestDisablingTheWebInterfaceStopsItAnswering(t *testing.T) {
	opts := NewOptions()
	setFlag(t, opts, OptDisableWebInterface, true)
	_, addr, _ := newInterfaceProxy(t, opts)
	got := rawExchange(t, addr, "GET http://burpsuite/ HTTP/1.1\r\nHost: burpsuite\r\n\r\n")
	if bytes.Contains(got, []byte("burpsy proxy listener")) {
		t.Errorf("the disabled interface still answered: %q", got)
	}
}

func TestSuppressingErrorMessagesSendsNothing(t *testing.T) {
	opts := NewOptions()
	setFlag(t, opts, OptInvisibleProxy, false) // so an origin-form request is unattributable
	_, addr, _ := newInterfaceProxy(t, opts)
	if got := rawExchange(t, addr, "GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n"); !bytes.HasPrefix(got, []byte("HTTP/1.1 400")) {
		t.Fatalf("control: an unattributable request answered %q, want burpsy's 400", got)
	}
	setFlag(t, opts, OptSuppressErrorMessages, true)
	if got := rawExchange(t, addr, "GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n"); len(got) != 0 {
		t.Errorf("with error messages suppressed the client still received %q", got)
	}
}

func TestHTTP10SwitchesRewriteTheVersionTowardsServerAndClient(t *testing.T) {
	var gotProto string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Proto
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	}))
	defer origin.Close()
	target := strings.TrimPrefix(origin.URL, "http://")

	opts := NewOptions()
	_, addr, _ := newInterfaceProxy(t, opts)
	request := fmt.Sprintf("GET http://%s/v HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, target)

	plain := rawExchange(t, addr, request)
	if gotProto != "HTTP/1.1" || !bytes.HasPrefix(plain, []byte("HTTP/1.1 200")) {
		t.Fatalf("control: origin saw %s, client got %q", gotProto, firstLine(string(plain)))
	}

	// Each switch on its own, because an origin answers an HTTP/1.0 request with an HTTP/1.0 status line
	// by itself, so the two together could not show that the client switch did anything.
	setFlag(t, opts, OptUseHTTP10ToClient, true)
	got := rawExchange(t, addr, request)
	if gotProto != "HTTP/1.1" || !bytes.HasPrefix(got, []byte("HTTP/1.0 200")) {
		t.Errorf("client switch alone: origin saw %s, client got %q; want HTTP/1.1 upstream and an HTTP/1.0 status line",
			gotProto, firstLine(string(got)))
	}
	setFlag(t, opts, OptUseHTTP10ToClient, false)
	setFlag(t, opts, OptUseHTTP10ToServer, true)
	rawExchange(t, addr, request)
	if gotProto != "HTTP/1.0" {
		t.Errorf("server switch: the origin received %s, want HTTP/1.0", gotProto)
	}
}

// newLiveInterfaceProxy is newInterfaceProxy served through ListenAndServe, which AddListener needs.
func newLiveInterfaceProxy(t *testing.T) (*Server, *core.TrafficStore) {
	t.Helper()
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).WithScope(testScope()).WithLogger(zap.NewNop()))
	startLiveProxy(t, srv)
	return srv, store
}

// A redirecting listener that a thick client hits directly (PR #311 review): the client is not
// proxy-aware, so every request it sends names the listener itself in the Host header, and the
// listener's redirect is what carries it to the real origin. The listener's-own-address match must not
// swallow those requests into the interface page; the magic names still reach the interface there.
func TestARedirectingListenerHitDirectlyIsRedirectedNotShownTheInterface(t *testing.T) {
	srv, store := newLiveInterfaceProxy(t)
	host, port := originSaying(t, "reached-the-redirect-origin")
	on := true
	added, err := srv.AddListener(ListenerSpec{
		Bind:         "127.0.0.1:0",
		RedirectHost: host,
		RedirectPort: port,
		Invisible:    &on,
	})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	self := added.BoundAddr

	got := rawExchange(t, self, "GET /probe HTTP/1.1\r\nHost: "+self+"\r\nConnection: close\r\n\r\n")
	if !bytes.Contains(got, []byte("reached-the-redirect-origin")) {
		t.Fatalf("a request naming the redirecting listener's own address was not redirected; got %q", got)
	}
	if bytes.Contains(got, []byte("burpsy proxy interface")) || bytes.Contains(got, []byte("burpsy proxy listener")) {
		t.Errorf("the interface answered a request the listener should have redirected: %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(store.Exchanges()); n != 1 {
		t.Errorf("%d exchange(s) recorded for the redirected request, want 1", n)
	}

	// The explicit names still address the proxy, redirect or not.
	if page := rawExchange(t, self, "GET http://burpsuite/ HTTP/1.1\r\nHost: burpsuite\r\n\r\n"); !bytes.Contains(page, []byte("burpsy proxy listener")) {
		t.Errorf("http://burpsuite/ on a redirecting listener did not reach the interface: %q", page)
	}
}

// The control for the test above: an invisible listener with no redirect forwards by the Host header,
// so a request whose Host is the listener itself would be relayed straight back into the listener. It
// keeps getting the interface rather than looping.
func TestAnInvisibleListenerWithoutRedirectStillAnswersItsOwnAddress(t *testing.T) {
	srv, store := newLiveInterfaceProxy(t)
	on := true
	added, err := srv.AddListener(ListenerSpec{Bind: "127.0.0.1:0", Invisible: &on})
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	self := added.BoundAddr
	got := rawExchange(t, self, "GET /probe HTTP/1.1\r\nHost: "+self+"\r\nConnection: close\r\n\r\n")
	if !bytes.HasPrefix(got, []byte("HTTP/1.1 404")) || !bytes.Contains(got, []byte("burpsy proxy interface has no page at /probe")) {
		t.Errorf("a non-redirecting listener's own address was not answered by the interface: %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(store.Exchanges()); n != 0 {
		t.Errorf("%d exchange(s) recorded: the request for the listener itself was forwarded", n)
	}
}
