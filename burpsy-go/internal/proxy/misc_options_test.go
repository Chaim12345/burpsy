package proxy

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// The two Miscellaneous knobs that shape a request (burpsy-react-ui-6s2):
// strip Proxy-* headers and set Connection: close. Both ride the same option
// set the response rules already use, so the panel's switches are the relay's
// switches.

// proxyGet sends one origin-form request through the proxy and reports what
// the origin received (its full request bytes) and what came back.
func miscProxyGet(t *testing.T, proxyAddr, target string, extraHeaders string) (received string, respHeaders string) {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := "GET " + u.Path + " HTTP/1.1\r\nHost: " + u.Host + "\r\n" + extraHeaders + "Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	all := string(buf[:n])
	parts := strings.SplitN(all, "\r\n\r\n", 2)
	if len(parts) == 2 {
		return parts[1], parts[0]
	}
	return all, ""
}

// With the strip on (the seed), a client's Proxy-Connection and
// Proxy-Authorization never reach the origin. The dangerous direction is the
// seed: a header family that talks to proxies has no business reaching an
// origin, and the engine has always stripped it — the seed preserves that.
func TestProxyHeaderFamilyIsStrippedByDefault(t *testing.T) {
	// The raw bytes on the wire, read from a TCP origin: the header block as sent.
	received := make(chan string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		conn.Close()
	}()
	defer ln.Close()
	originURL := "http://" + ln.Addr().String() + "/target"

	addr := serveProxy(t, NewServer(NewProxyConfig(core.NewTrafficStore()).WithScope(testScope()).WithLogger(zap.NewNop())))

	miscProxyGet(t, addr, originURL, "Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\n")

	got := <-received
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "proxy-") {
			t.Errorf("the origin received %q with the strip on (the seed)", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(got, "Host:") {
		t.Errorf("the strip ate more than the Proxy- family; origin received:\n%s", got)
	}
}

// The switch's other direction: turn it off and the headers go through, which
// is occasionally what testing an origin's own Proxy-header handling needs.
func TestProxyHeadersPassWhenTheSwitchIsOff(t *testing.T) {
	received := make(chan string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		conn.Close()
	}()
	defer ln.Close()
	originURL := "http://" + ln.Addr().String() + "/target"

	cfg := NewProxyConfig(core.NewTrafficStore()).WithScope(testScope()).WithLogger(zap.NewNop())
	if err := cfg.options.Set(OptStripProxyHeaders, false); err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, NewServer(cfg))

	miscProxyGet(t, addr, originURL, "Proxy-Connection: keep-alive\r\n")

	got := <-received
	if !strings.Contains(got, "Proxy-Connection:") {
		t.Errorf("with the switch off the header should pass; origin received:\n%s", got)
	}
}

// Connection: close, response half: with the switch on, the response carries
// the header and the connection does not serve a second request.
func TestConnectionCloseRewritesBothSides(t *testing.T) {
	requests := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer origin.Close()

	cfg := NewProxyConfig(core.NewTrafficStore()).WithScope(testScope()).WithLogger(zap.NewNop())
	if err := cfg.options.Set(OptSetConnectionClose, true); err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, NewServer(cfg))

	u, _ := url.Parse(origin.URL)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// HTTP/1.1 with keep-alive implied — the response must still say close.
	conn.Write([]byte("GET " + u.Path + " HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n"))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(strings.ToLower(resp), "connection: close") {
		t.Errorf("the response does not carry Connection: close with the switch on:\n%s", resp)
	}
	// A second request on the same socket must not be served: the relay closed.
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte("GET " + u.Path + " HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n"))
	n2, err := conn.Read(buf)
	if err == nil && n2 > 0 && strings.Contains(string(buf[:n2]), "200") {
		t.Error("the connection served a second request with Connection: close forced; the response lied")
	}
}

// serveProxy starts the server on an ephemeral listener and returns its address.
func serveProxy(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
	return ln.Addr().String()
}

var _ = bytes.MinRead
