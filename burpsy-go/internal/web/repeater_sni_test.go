package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Override SNI (burpsy-react-ui-k011) through POST /api/repeater/send: the ClientHello carries the
// override, the Host header does not, a redirect hop does not, and a plaintext target refuses it.

type helloRecorder struct {
	mu    sync.Mutex
	names []string
}

func (h *helloRecorder) config() *tls.Config {
	return &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		h.mu.Lock()
		h.names = append(h.names, hello.ServerName)
		h.mu.Unlock()
		return nil, nil
	}}
}

func (h *helloRecorder) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.names...)
}

func TestOverrideSNIReachesTheHandshakeAndNotTheRedirectHop(t *testing.T) {
	var second helloRecorder
	hop := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("landed")) }))
	hop.TLS = second.config()
	hop.StartTLS()
	defer hop.Close()

	var first helloRecorder
	var hostSeen string
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostSeen = r.Host
		http.Redirect(w, r, hop.URL+"/next", http.StatusFound)
	}))
	origin.TLS = first.config()
	origin.StartTLS()
	defer origin.Close()

	s := newTestServer()
	s.sender.WithTLSVerify(false)
	authority := strings.TrimPrefix(origin.URL, "https://")
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":  origin.URL,
		"request": "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
		"sni":     "probe.oast.example",
		"options": map[string]any{"redirect_mode": "always"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("send = %d: %s", rec.Code, rec.Body.String())
	}
	if got := first.all(); len(got) != 1 || got[0] != "probe.oast.example" {
		t.Fatalf("target ClientHello names = %v, want the override", got)
	}
	if hostSeen != authority {
		t.Fatalf("Host = %q, want %q — only the ClientHello changes", hostSeen, authority)
	}
	if !strings.Contains(rec.Body.String(), `"followed":true`) {
		t.Fatalf("the hop was not followed: %s", rec.Body.String())
	}
	if got := second.all(); len(got) != 1 || got[0] != "" {
		t.Fatalf("redirect hop ClientHello names = %v, want the hop's own (none, for an IP) — the override names one target", got)
	}
}

func TestOverrideSNIIsRefusedWhereItCannotApply(t *testing.T) {
	s := newTestServer()
	plain := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target": "http://127.0.0.1:1", "request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "sni": "a.example",
	})
	if plain.Code != http.StatusBadRequest || !strings.Contains(plain.Body.String(), "plain HTTP") {
		t.Fatalf("plaintext + sni = %d %q", plain.Code, plain.Body.String())
	}
	ip := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target": "https://127.0.0.1:1", "request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "sni": "10.0.0.1",
	})
	if ip.Code != http.StatusBadRequest || !strings.Contains(ip.Body.String(), "IP address") {
		t.Fatalf("ip sni = %d %q", ip.Code, ip.Body.String())
	}
	group := postJSON(t, s, "/api/repeater/send-group", map[string]any{
		"mode": "sequence_single_conn",
		"items": []map[string]any{
			{"tab_id": "a", "target": "https://127.0.0.1:1", "request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "sni": "a.example"},
			{"tab_id": "b", "target": "https://127.0.0.1:1", "request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n"},
		},
	})
	if group.Code != http.StatusBadRequest || !strings.Contains(group.Body.String(), "one TLS handshake") {
		t.Fatalf("mixed-SNI single-connection group = %d %q", group.Code, group.Body.String())
	}
}
