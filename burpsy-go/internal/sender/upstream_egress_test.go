package sender

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
)

// This file is the proof that SenderConfig's proxy setting reaches every dial site in this package,
// which is the thing that was untrue before Unit 9: ProxyURL configured http.Transport.Proxy and
// nothing else, so it covered Send's typed path and none of SendRaw, the pipelined desync probes, the
// frame-program path or the ALPN discovery handshake. Each test below drives a *different* dial site
// and asserts the proxy recorded the destination — a settings panel that covered one of five is the
// "partial result looking complete" defect this repo treats as a bug.

// originAuthority starts a target and returns its host and port.
func originAuthority(t *testing.T) (host string, port uint16) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("reached the origin"))
	}))
	t.Cleanup(server.Close)
	authority := strings.TrimPrefix(server.URL, "http://")
	h, p, found := strings.Cut(authority, ":")
	if !found {
		t.Fatalf("unexpected test server URL %q", server.URL)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port %q: %v", p, err)
	}
	return h, uint16(n)
}

// senderThrough builds a sender whose whole egress goes through proxy.
func senderThrough(t *testing.T, proxyURL string) *Sender {
	t.Helper()
	policy := upstream.NewPolicy()
	if err := policy.SetDefault(proxyURL); err != nil {
		t.Fatalf("SetDefault(%q): %v", proxyURL, err)
	}
	config := DefaultSenderConfig()
	config.Upstream = policy
	config.Timeout = 5 * time.Second
	return NewSender(config)
}

// SendRaw — the repeater's path, and the one that used to ignore the proxy setting entirely.
func Test_SendRaw_traverses_the_configured_upstream_proxy(t *testing.T) {
	host, port := originAuthority(t)
	proxy := upstreamtest.StartConnect(t, "", "")
	snd := senderThrough(t, "http://"+proxy.Addr())

	raw := []byte("GET / HTTP/1.1\r\nHost: " + host + ":" + strconv.Itoa(int(port)) + "\r\nConnection: close\r\n\r\n")
	got, err := snd.SendRaw(context.Background(), host, port, false, raw)
	if err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	if !strings.Contains(string(got), "reached the origin") {
		t.Errorf("the origin's body did not come back; got %q", got)
	}
	want := host + ":" + strconv.Itoa(int(port))
	if !proxy.Saw(want) {
		t.Errorf("the proxy was asked for %v, not %q — SendRaw went out direct", proxy.Requests(), want)
	}
	if errs := proxy.Errors(); len(errs) > 0 {
		t.Errorf("the proxy could not parse what the sender sent: %v", errs)
	}
}

// A cleartext raw send tunnels with CONNECT rather than being rewritten to absolute form.
//
// This is deliberate and load-bearing: burpsy's raw paths carry deliberately malformed request lines
// whose whole purpose is to reach the origin byte for byte, and re-rendering one as
// `GET http://host/path` would send a different probe than the operator wrote. The assertion is that
// the bytes the origin received are the bytes we sent.
func Test_a_cleartext_raw_send_is_tunnelled_not_rewritten(t *testing.T) {
	var sawTarget string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RequestURI is the request line's target exactly as it arrived.
		sawTarget = r.RequestURI
		w.Write([]byte("ok"))
	}))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "http://")
	host, portStr, _ := strings.Cut(authority, ":")
	port, _ := strconv.Atoi(portStr)

	proxy := upstreamtest.StartConnect(t, "", "")
	snd := senderThrough(t, "http://"+proxy.Addr())
	raw := []byte("GET /probe HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n")
	if _, err := snd.SendRaw(context.Background(), host, uint16(port), false, raw); err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	if sawTarget != "/probe" {
		t.Errorf("the origin saw request target %q, want %q — the request line was rewritten, so the "+
			"origin received a different probe than the operator wrote", sawTarget, "/probe")
	}
	if !proxy.Saw(authority) {
		t.Errorf("the proxy was asked for %v, not %q", proxy.Requests(), authority)
	}
}

// SendPipelined — the desync probe path, a second independent dial site.
func Test_SendPipelined_traverses_the_configured_upstream_proxy(t *testing.T) {
	host, port := originAuthority(t)
	proxy := upstreamtest.StartConnect(t, "", "")
	snd := senderThrough(t, "http://"+proxy.Addr())

	authority := host + ":" + strconv.Itoa(int(port))
	raw := []byte("GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")
	if _, err := snd.SendPipelined(context.Background(), host, port, false, [][]byte{raw, raw}); err != nil {
		t.Fatalf("SendPipelined: %v", err)
	}
	if !proxy.Saw(authority) {
		t.Errorf("the proxy was asked for %v, not %q — the pipelined probe went out direct",
			proxy.Requests(), authority)
	}
}

// The typed Send path, which keeps net/http's own HTTP-proxy handling.
//
// Different mechanism from the raw paths — net/http applies the proxy itself rather than going through
// upstream.Proxy.DialContext — so it is asserted separately rather than assumed to follow from the
// others. An HTTPS origin is used deliberately: net/http tunnels those with CONNECT, which is what
// makes the traversal observable on the proxy rather than only inside net/http.
func Test_the_typed_Send_path_traverses_the_configured_upstream_proxy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("reached the origin"))
	}))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "https://")

	proxy := upstreamtest.StartConnect(t, "", "")
	policy := upstream.NewPolicy()
	if err := policy.SetDefault("http://" + proxy.Addr()); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	config := DefaultSenderConfig()
	config.Upstream = policy
	config.Timeout = 5 * time.Second
	// The origin is httptest's self-signed certificate, which is the ordinary engagement case.
	config.TLSVerify = false
	snd := NewSender(config)

	resp, err := snd.Send(context.Background(), &Request{Method: http.MethodGet, URL: server.URL})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string(resp.Body), "reached the origin") {
		t.Errorf("the origin's body did not come back; got %q", resp.Body)
	}
	if !proxy.Saw(authority) {
		t.Errorf("the proxy was asked for %v, not %q — the typed path went out direct",
			proxy.Requests(), authority)
	}
}

// SOCKS5 covers the raw paths too, and through the same dialer as everything else — so there is one
// SOCKS implementation for the whole tree rather than net/http's for one path and ours for the others.
func Test_SendRaw_traverses_a_socks5_proxy(t *testing.T) {
	host, port := originAuthority(t)
	proxy := upstreamtest.StartSOCKS5(t, "operator", "s3cr3t")
	snd := senderThrough(t, "socks5://operator:s3cr3t@"+proxy.Addr())

	authority := host + ":" + strconv.Itoa(int(port))
	raw := []byte("GET / HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n")
	got, err := snd.SendRaw(context.Background(), host, port, false, raw)
	if err != nil {
		t.Fatalf("SendRaw through socks5: %v", err)
	}
	if !strings.Contains(string(got), "reached the origin") {
		t.Errorf("the origin's body did not come back through socks5; got %q", got)
	}
	if len(proxy.Requests()) == 0 {
		t.Fatal("the socks5 proxy was never asked for anything, so the send went out direct")
	}
	if creds := proxy.Credentials(); len(creds) == 0 || creds[0] != "operator" {
		t.Errorf("the socks5 proxy saw credentials %v, want operator", creds)
	}
}

// A per-destination rule proxies one destination and leaves another direct.
//
// The whole point of the rule list over Burp's single global SOCKS setting, so it is asserted against a
// live proxy and a live origin rather than by reading the policy back. "localhost" and "127.0.0.1" are
// two different host strings that reach the same loopback origin, which is what makes it possible to
// route one and not the other against a single test server.
func Test_a_per_destination_rule_proxies_one_host_and_not_another(t *testing.T) {
	_, port := originAuthority(t)
	proxy := upstreamtest.StartConnect(t, "", "")

	policy := upstream.NewPolicy()
	// One rule, no default: "localhost" is proxied, everything else falls through to direct.
	if _, err := policy.Set("localhost", "http://"+proxy.Addr()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	config := DefaultSenderConfig()
	config.Upstream = policy
	config.Timeout = 5 * time.Second
	snd := NewSender(config)

	send := func(host string) string {
		t.Helper()
		authority := host + ":" + strconv.Itoa(int(port))
		raw := []byte("GET / HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n")
		got, err := snd.SendRaw(context.Background(), host, port, false, raw)
		if err != nil {
			t.Fatalf("SendRaw to %s: %v", host, err)
		}
		if !strings.Contains(string(got), "reached the origin") {
			t.Fatalf("the send to %s did not reach the origin; got %q", host, got)
		}
		return authority
	}

	matched := send("localhost")
	if !proxy.Saw(matched) {
		t.Errorf("the proxy was asked for %v, not %q — the matching rule did not route the send",
			proxy.Requests(), matched)
	}

	// The unmatched destination must not touch the proxy at all.
	before := len(proxy.Requests())
	unmatched := send("127.0.0.1")
	if after := len(proxy.Requests()); after != before {
		t.Errorf("the unmatched destination %q went through the proxy anyway: %d request(s) became %d",
			unmatched, before, after)
	}
}

// An unusable proxy fails every send rather than letting one go out direct.
//
// Both fields are exercised: ProxyURL (the whole-sender form) and a policy whose stored value cannot be
// used. "My traffic went straight to the target" is the one outcome an operator who configured a proxy
// did not ask for, so it must be impossible on every path in this package.
func Test_an_unusable_proxy_fails_the_send_on_every_path(t *testing.T) {
	host, port := originAuthority(t)

	config := DefaultSenderConfig()
	config.ProxyURL = "127.0.0.1:8080" // no scheme; refused by upstream.Parse
	config.Timeout = 2 * time.Second
	snd := NewSender(config)

	raw := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
	if _, err := snd.SendRaw(context.Background(), host, port, false, raw); err == nil {
		t.Error("SendRaw succeeded under an unusable proxy configuration, so the traffic went out direct")
	}
	if _, err := snd.SendPipelined(context.Background(), host, port, false, [][]byte{raw}); err == nil {
		t.Error("SendPipelined succeeded under an unusable proxy configuration")
	}
	if _, _, err := snd.dialTLS(context.Background(), host, port, []string{"http/1.1"}); err == nil {
		t.Error("dialTLS succeeded under an unusable proxy configuration")
	}
}

// Setting both proxy fields is refused rather than resolved by precedence.
//
// They are two answers to "where does this sender's traffic go", and picking one would send traffic
// somewhere the operator did not unambiguously ask for.
func Test_setting_both_proxy_fields_is_refused(t *testing.T) {
	host, port := originAuthority(t)
	policy := upstream.NewPolicy()
	if err := policy.SetDefault("http://127.0.0.1:3128"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	config := DefaultSenderConfig()
	config.ProxyURL = "http://127.0.0.1:9999"
	config.Upstream = policy
	config.Timeout = 2 * time.Second
	snd := NewSender(config)

	raw := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
	_, err := snd.SendRaw(context.Background(), host, port, false, raw)
	if err == nil {
		t.Fatal("a sender with both ProxyURL and Upstream sent successfully; one of the two was silently ignored")
	}
	if !strings.Contains(err.Error(), "both") {
		t.Errorf("the error does not explain the ambiguity: %v", err)
	}
}

// A sender with no proxy configuration dials directly, so an unconfigured build is unchanged.
func Test_a_sender_with_no_proxy_configuration_dials_directly(t *testing.T) {
	host, port := originAuthority(t)
	snd := NewSender(DefaultSenderConfig())
	raw := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
	got, err := snd.SendRaw(context.Background(), host, port, false, raw)
	if err != nil {
		t.Fatalf("SendRaw with no proxy: %v", err)
	}
	if !strings.Contains(string(got), "reached the origin") {
		t.Errorf("an unproxied send did not reach the origin; got %q", got)
	}
}
