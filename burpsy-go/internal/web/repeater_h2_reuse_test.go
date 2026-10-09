package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Repeater's HTTP/2 connection reuse and cross-domain protocol enforcement (burpsy-react-ui-adkx),
// through POST /api/repeater/send against real TLS origins, counting the connections the origin
// actually accepted.

func countingTLSOrigin(t *testing.T, h2 bool, handler http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var accepted atomic.Int64
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = h2
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &accepted
}

type h2SendWire struct {
	Status       int    `json:"status"`
	Response     string `json:"response"`
	H2Connection string `json:"h2_connection"`
	Redirects    *struct {
		Hops []struct {
			Followed bool   `json:"followed"`
			Protocol string `json:"protocol"`
			To       string `json:"to"`
		} `json:"hops"`
	} `json:"redirects"`
}

func sendTLS(t *testing.T, s *Server, url, tabID string, options map[string]any) (h2SendWire, string) {
	t.Helper()
	authority := strings.TrimPrefix(url, "https://")
	body := map[string]any{"target": url, "request": "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"}
	if tabID != "" {
		body["tab_id"] = tabID
	}
	if options != nil {
		body["options"] = options
	}
	rec := postJSON(t, s, "/api/repeater/send", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("send = %d: %s", rec.Code, rec.Body.String())
	}
	var out h2SendWire
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out, rec.Body.String()
}

func TestH2ConnectionReuseRidesOneConnectionAndSaysWhichRequestWasFirst(t *testing.T) {
	origin, accepted := countingTLSOrigin(t, true, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.Proto)) })
	s := newTestServer()
	s.sender.WithTLSVerify(false)
	reuse := map[string]any{"h2_connection_reuse": true}

	first, raw := sendTLS(t, s, origin.URL, "tab-1", reuse)
	if first.H2Connection != "new" || !strings.HasPrefix(first.Response, "HTTP/2 200") {
		t.Fatalf("first send = %s, want h2 on a new connection", raw)
	}
	if strings.Contains(raw, "cannot be read well enough") {
		t.Fatalf("an h2 response must be readable for the redirect decision: %s", raw)
	}
	second, raw := sendTLS(t, s, origin.URL, "tab-1", reuse)
	if second.H2Connection != "reused" {
		t.Fatalf("second send = %s, want the same tab's connection reused", raw)
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("origin accepted %d connections for two reused sends, want 1", got)
	}

	// Another tab gets its own connection: reuse is per tab, so one tab's first request is never
	// another tab's fifth.
	other, _ := sendTLS(t, s, origin.URL, "tab-2", reuse)
	if other.H2Connection != "new" || accepted.Load() != 2 {
		t.Fatalf("another tab = %q with %d accepted, want its own new connection", other.H2Connection, accepted.Load())
	}
}

func TestWithoutH2ConnectionReuseEveryRequestIsFirstOnItsConnection(t *testing.T) {
	origin, accepted := countingTLSOrigin(t, true, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	s := newTestServer()
	s.sender.WithTLSVerify(false)
	for i := 0; i < 2; i++ {
		out, raw := sendTLS(t, s, origin.URL, "tab-1", nil)
		if out.H2Connection != "" || strings.Contains(raw, "h2_connection") {
			t.Fatalf("reuse off still reported a connection state: %s", raw)
		}
	}
	if got := accepted.Load(); got != 2 {
		t.Fatalf("origin accepted %d connections for two sends with reuse off, want 2", got)
	}
}

func TestH2ConnectionReuseSaysWhenTheSendDidNotRideH2(t *testing.T) {
	origin, _ := countingTLSOrigin(t, false, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	s := newTestServer()
	s.sender.WithTLSVerify(false)
	out, raw := sendTLS(t, s, origin.URL, "tab-1", map[string]any{"h2_connection_reuse": true})
	if out.H2Connection != "not-h2" {
		t.Fatalf("an HTTP/1.1-only target = %s, want h2_connection not-h2", raw)
	}
}

func TestCrossDomainRedirectsKeepTheSelectedProtocolWhenEnforced(t *testing.T) {
	hop, _ := countingTLSOrigin(t, true, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.Proto)) })
	_, hopPort, _ := net.SplitHostPort(strings.TrimPrefix(hop.URL, "https://"))
	// "localhost" rather than 127.0.0.1: a different host name, which is what makes the hop
	// cross-domain, on the same loopback listener.
	crossDomain := "https://localhost:" + hopPort + "/landed"
	origin, _ := countingTLSOrigin(t, true, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, crossDomain, http.StatusFound)
	})
	s := newTestServer()
	s.sender.WithTLSVerify(false)

	// The original goes out pinned to HTTP/1.1 — the "selected protocol".
	base := map[string]any{"redirect_mode": "always", "protocol_preference": "http1"}
	negotiated, raw := sendTLS(t, s, origin.URL, "", base)
	if negotiated.Redirects == nil || len(negotiated.Redirects.Hops) != 1 || !negotiated.Redirects.Hops[0].Followed {
		t.Fatalf("the cross-domain hop was not followed: %s", raw)
	}
	if strings.Contains(raw, "cannot be read well enough") {
		t.Fatalf("the h2 hop's response must be readable so the chain can continue: %s", raw)
	}
	if got := negotiated.Redirects.Hops[0].Protocol; got != "HTTP/2" {
		t.Fatalf("with enforcement off the hop negotiated %q, want HTTP/2 — Burp's default negotiates each hop", got)
	}

	enforced := map[string]any{"redirect_mode": "always", "protocol_preference": "http1", "enforce_protocol_cross_domain": true}
	pinned, raw := sendTLS(t, s, origin.URL, "", enforced)
	if pinned.Redirects == nil || len(pinned.Redirects.Hops) != 1 || pinned.Redirects.Hops[0].Protocol != "HTTP/1.1" {
		t.Fatalf("with enforcement on the cross-domain hop = %s, want HTTP/1.1 like the request that started the chain", raw)
	}
}
