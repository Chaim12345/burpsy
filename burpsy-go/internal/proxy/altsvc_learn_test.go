package proxy

// Learning half of vln3 slice 3: a response burpsy itself forwarded is the only source of h3
// advertisements, and the NetworkSettings kill switch (integrator ruling C - mandatory, default
// ON) makes the whole feature inert when off: nothing learned, nothing ridden.

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A forwarded response carrying Alt-Svc teaches the table the origin's h3 endpoint.
func TestAForwardedResponseTeachesTheH3Advertisement(t *testing.T) {
	cert := selfSignedCert(t, "altsvc.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":8443"; ma=3600`)
		_, _ = w.Write([]byte("ok"))
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	host, port := splitHostPort(t, origin.URL)

	srv := NewServer(NewProxyConfig(nil).WithScope(testScope()).WithUpstreamTLS(NewTLSPolicy().WithVerify(false)))
	raw := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host))
	if _, err := srv.forwardRequest(raw, host, port, true); err != nil {
		t.Fatalf("forwardRequest: %v", err)
	}
	if _, ok := srv.config.altSvc.h3Endpoint(host, port, time.Now()); !ok {
		t.Fatal("a forwarded Alt-Svc response taught the table nothing")
	}
}

// The kill switch off means the feature is inert: the same response teaches nothing.
func TestTheKillSwitchOffLearnsNothing(t *testing.T) {
	cert := selfSignedCert(t, "altsvc.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":8443"; ma=3600`)
		_, _ = w.Write([]byte("ok"))
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	host, port := splitHostPort(t, origin.URL)

	srv := NewServer(NewProxyConfig(nil).WithScope(testScope()).WithUpstreamTLS(NewTLSPolicy().WithVerify(false)))
	srv.config.network.SetHTTP3AltSvc(false)
	raw := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host))
	if _, err := srv.forwardRequest(raw, host, port, true); err != nil {
		t.Fatalf("forwardRequest: %v", err)
	}
	if _, ok := srv.config.altSvc.h3Endpoint(host, port, time.Now()); ok {
		t.Fatal("the table learned an advertisement with the kill switch off")
	}
}

// The switch defaults ON: a proxy configured the way every existing caller configures it learns.
func TestHTTP3AltSvcDefaultsOn(t *testing.T) {
	if !NewNetworkSettings().HTTP3AltSvcEnabled() {
		t.Fatal("NewNetworkSettings has the h3 Alt-Svc switch off - ruling C says default ON")
	}
	cfg := NewProxyConfig(nil)
	if !cfg.network.HTTP3AltSvcEnabled() {
		t.Fatal("NewProxyConfig has the h3 Alt-Svc switch off - ruling C says default ON")
	}
}

func splitHostPort(t *testing.T, rawURL string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "https://"))
	if err != nil {
		t.Fatalf("splitting the test origin address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("reading the test origin port: %v", err)
	}
	return host, port
}
