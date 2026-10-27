package proxy

import (
	"bufio"
	"context"
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

// The listener's runtime surface (burpsy-react-ui-77m, decision recorded on the issue:
// one re-bindable listener, not a listener list). Two contracts are pinned here:
//
//   - Rebind moves the live listener without a process restart, and a bind failure
//     leaves the current listener serving — an operator who typos a port gets an error,
//     not an outage.
//   - The invisible-proxying switch decides whether an origin-form request whose only
//     authority is a Host header is forwarded or refused, live.
//
// Both are driven through a real listener and a real origin, because the whole point
// of Rebind is what happens to a socket that is already Accept-ing.

// startLiveProxy runs a Server through ListenAndServe — the real loop, not the
// handleConnection-per-conn shim startProxy uses — and answers its bound address.
func startLiveProxy(t *testing.T, srv *Server) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = srv.ListenAndServe(ctx, "127.0.0.1:0")
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if addr := srv.ListenerAddr(); addr != "" {
			return addr
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("proxy never started listening")
	return ""
}

func originSaying(t *testing.T, body string) (string, uint16) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	t.Cleanup(origin.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatalf("split origin addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("origin port: %v", err)
	}
	return host, uint16(port)
}

// proxiedGetWithHostHeader sends an origin-form request — `GET /path` — with the
// authority only in the Host header, which is the shape a non-proxy-aware client
// speaks. It answers the response head, whatever it is.
func proxiedGetWithHostHeader(t *testing.T, proxyAddr, host string, port uint16) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	req := "GET /invisible HTTP/1.1\r\n" +
		"Host: " + host + ":" + strconv.Itoa(int(port)) + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	head, err := io.ReadAll(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(head)
}

func Test_the_listener_rebinds_without_a_restart_and_the_old_port_stops_serving(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()))
	first := startLiveProxy(t, srv)

	host, port := originSaying(t, "after-rebind")
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: first}),
		DisableKeepAlives: true,
	}}
	resp, err := client.Get("http://" + host + ":" + strconv.Itoa(int(port)) + "/")
	if err != nil {
		t.Fatalf("request through the first bind: %v", err)
	}
	resp.Body.Close()

	second := ":0"
	prev, err := srv.Rebind(second)
	if err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if prev != first {
		t.Errorf("Rebind reported previous %q, want the address it was serving on (%q)", prev, first)
	}
	rebound := srv.ListenerAddr()
	if rebound == "" || rebound == first {
		t.Fatalf("listener did not move: %q", rebound)
	}

	// The new socket serves. The origin-form-with-Host shape doubles here as a
	// request the relay handles without any proxy-aware client machinery.
	got := proxiedGetWithHostHeader(t, rebound, host, port)
	if !strings.Contains(got, "after-rebind") {
		t.Errorf("request through the rebound listener got %q", got)
	}

	// The old socket is retired: connecting to it fails rather than hanging or,
	// worse, being served by the same accept loop twice.
	deadline := time.Now().Add(5 * time.Second)
	for {
		oldConn, dialErr := net.DialTimeout("tcp", first, time.Second)
		if dialErr != nil {
			break
		}
		oldConn.Close()
		if time.Now().After(deadline) {
			t.Errorf("the previous bind %q still accepts connections after the rebind", first)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func Test_a_failed_rebind_leaves_the_current_listener_serving(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()))
	current := startLiveProxy(t, srv)

	// Take a port out from under the rebind, so the failure is a real bind clash
	// rather than a crafted one.
	squatter, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("squat listen: %v", err)
	}
	defer squatter.Close()

	if _, err := srv.Rebind(squatter.Addr().String()); err == nil {
		t.Fatal("rebinding onto an occupied port succeeded, which would have been an outage")
	}
	if got := srv.ListenerAddr(); got != current {
		t.Fatalf("after a failed rebind the listener is %q, want the untouched %q", got, current)
	}

	host, port := originSaying(t, "still-here")
	got := proxiedGetWithHostHeader(t, current, host, port)
	if !strings.Contains(got, "still-here") {
		t.Errorf("the untouched listener stopped serving after a failed rebind: %q", got)
	}
}

func Test_the_invisible_proxying_switch_decides_the_host_header_fallback_live(t *testing.T) {
	host, port := originSaying(t, "invisible-ok")

	newServer := func() *Server {
		return NewServer(NewProxyConfig(core.NewTrafficStore()).
			WithScope(testScope()).
			WithLogger(zap.NewNop()))
	}

	// Seeded on: the fallback works, matching the behaviour this engine has always had.
	on := newServer()
	onAddr := startLiveProxy(t, on)
	got := proxiedGetWithHostHeader(t, onAddr, host, port)
	if !strings.Contains(got, "invisible-ok") {
		t.Errorf("with invisible proxying seeded on, the origin-form request got %q", got)
	}

	// Off, live, no restart: the same request is refused with 400 — an honest answer
	// for a listener that was sent an authority it was told not to take from headers.
	off := newServer()
	offAddr := startLiveProxy(t, off)
	if err := off.config.options.Set(OptInvisibleProxy, false); err != nil {
		t.Fatalf("disable invisible proxying: %v", err)
	}
	got = proxiedGetWithHostHeader(t, offAddr, host, port)
	if !strings.Contains(got, "400") {
		t.Errorf("with invisible proxying off, the origin-form request got %q, want a 400 refusal", got)
	}
}

// burpsy-react-ui-6858 fix round: a Host field name padded with whitespace before its colon can
// never steer invisible routing. The request validation ahead of the routing read already refuses
// it with a 400, and the routing read itself (proxy.go's invisible branch) uses the strict
// HeaderValueExact — the unit test beside requestHead pins that second layer.
func Test_an_invisible_listener_ignores_a_padded_host_header(t *testing.T) {
	host, port := originSaying(t, "invisible-ok")
	s := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()))
	addr := startLiveProxy(t, s)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	req := "GET /invisible HTTP/1.1\r\n" +
		"Host : " + host + ":" + strconv.Itoa(int(port)) + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	resp, err := io.ReadAll(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if strings.Contains(string(resp), "invisible-ok") {
		t.Errorf("a Host header padded before its colon steered invisible routing:\n%q", resp)
	}
}
