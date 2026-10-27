package egressgate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingServer counts the TCP connections it ACCEPTS, so a connection that never carried a request
// still counts as egress.
func countingServer(t *testing.T, h http.Handler) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var accepts atomic.Int64
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			accepts.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &accepts
}

// authorityGate allows one host:port, and refuses one path prefix on it.
type authorityGate struct {
	host       string
	port       uint16
	denyPrefix string
}

func gateFor(t *testing.T, raw, denyPrefix string) authorityGate {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return authorityGate{host: u.Hostname(), port: uint16(port), denyPrefix: denyPrefix}
}

func (g authorityGate) AllowURL(u *url.URL) error {
	port, _ := strconv.Atoi(u.Port())
	if u.Hostname() != g.host || uint16(port) != g.port {
		return fmt.Errorf("%s is out of scope", u.Host)
	}
	if g.denyPrefix != "" && strings.HasPrefix(u.Path, g.denyPrefix) {
		return fmt.Errorf("%s is out of scope", u.Path)
	}
	return nil
}

func (g authorityGate) AllowAuthority(host string, port uint16, _ bool) error {
	if host != g.host || port != g.port {
		return errors.New(host + " is out of scope")
	}
	return nil
}

func connect(t *testing.T, proxyAddr, authority string) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	return &bufferedConn{Conn: conn, r: br}, status
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// burpsy-react-ui-browser-render-unscoped / -extscan-egress: the gate refuses out-of-scope requests
// (plain, path-scoped and CONNECT) without dialling anything, and sends what it allows through the
// egress dialer it was given rather than a direct dial.
func TestTheGateDialsThroughTheEgressDialerAndRefusesOutOfScope(t *testing.T) {
	t.Parallel()
	inside, insideAccepts := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "inside "+r.URL.Path)
	}))
	outside, outsideAccepts := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	var dials atomic.Int64
	var dialed atomic.Value
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		dialed.Store(addr)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	var refusals []string
	p, err := Start(gateFor(t, inside.URL, "/admin"), func(s string) { refusals = append(refusals, s) }, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	proxyURL, _ := url.Parse(p.URL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}

	// In scope, plain HTTP: forwarded, through the dialer.
	resp, err := client.Get(inside.URL + "/page")
	if err != nil {
		t.Fatalf("in-scope request through the proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "inside /page" {
		t.Fatalf("in-scope request was not forwarded: %d %q", resp.StatusCode, body)
	}
	if dials.Load() == 0 || insideAccepts.Load() == 0 {
		t.Fatalf("the in-scope request did not go through the egress dialer (dials=%d accepts=%d)", dials.Load(), insideAccepts.Load())
	}
	if got := dialed.Load().(string); got != strings.TrimPrefix(inside.URL, "http://") {
		t.Errorf("dialled %q, want the in-scope authority", got)
	}

	// In scope, CONNECT: tunnelled, through the dialer, and the bytes reach the origin.
	before := dials.Load()
	conn, status := connect(t, p.Addr(), strings.TrimPrefix(inside.URL, "http://"))
	if !strings.Contains(status, "200") {
		t.Fatalf("in-scope CONNECT answered %q", status)
	}
	_, _ = io.WriteString(conn, "GET /tunnelled HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	got, _ := io.ReadAll(conn)
	conn.Close()
	if !strings.Contains(string(got), "inside /tunnelled") {
		t.Errorf("the tunnel did not reach the origin: %q", got)
	}
	if dials.Load() != before+1 {
		t.Errorf("the tunnel was not dialled through the egress dialer")
	}

	// Out of scope: an other-host request, an excluded path on the in-scope host, a CONNECT to the
	// other host. None is dialled.
	before = dials.Load()
	insideBefore := insideAccepts.Load()
	for _, u := range []string{outside.URL + "/x", inside.URL + "/admin/users"} {
		resp, err = client.Get(u)
		if err != nil {
			t.Fatalf("out-of-scope request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", u, resp.StatusCode)
		}
	}
	conn, status = connect(t, p.Addr(), strings.TrimPrefix(outside.URL, "http://"))
	conn.Close()
	if !strings.Contains(status, "403") {
		t.Errorf("out-of-scope CONNECT answered %q, want 403", status)
	}
	if dials.Load() != before {
		t.Errorf("a refused request still reached the dialer")
	}
	if n := outsideAccepts.Load(); n != 0 {
		t.Fatalf("the out-of-scope host accepted %d connection(s)", n)
	}
	if insideAccepts.Load() != insideBefore {
		t.Errorf("the excluded path on the in-scope host was still connected")
	}
	if len(refusals) != 3 || p.Refused() != 3 {
		t.Errorf("refusals recorded = %d (counter %d), want 3: %v", len(refusals), p.Refused(), refusals)
	}
	if p.Forwarded() != 2 {
		t.Errorf("Forwarded = %d, want 2", p.Forwarded())
	}
}

func TestRedactURLDropsQueryValuesUserinfoAndFragment(t *testing.T) {
	got := RedactURL("https://u:p@idp.test/cb?code=SECRET&state=x#access_token=T")
	if strings.Contains(got, "SECRET") || strings.Contains(got, "u:p") || strings.Contains(got, "access_token") {
		t.Errorf("RedactURL leaked: %q", got)
	}
	if !strings.Contains(got, "code=") || !strings.Contains(got, "idp.test/cb") {
		t.Errorf("RedactURL dropped what identifies the page: %q", got)
	}
}
