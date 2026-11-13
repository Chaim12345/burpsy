package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const triageSecKey = "sk-test-SYNTHETIC-engine-fixture-0000"

func triageSecFinding() *Finding {
	return &Finding{Name: "SQL injection", Severity: "high", Confidence: "certain"}
}

// The endpoint policy itself: https anywhere, loopback http, nothing else - and refusals
// never echo the credential-bearing parts of the rejected URL.
func TestCheckTriageEndpointURL(t *testing.T) {
	ok := []string{
		"https://llm.example/v1",
		"https://127.0.0.1:8443/v1",
		"http://127.0.0.1:18107/v1",
		"http://127.1.2.3/v1",
		"http://[::1]:18107/v1",
		"http://localhost:18107/v1",
	}
	for _, raw := range ok {
		if err := CheckTriageEndpointURL(raw); err != nil {
			t.Errorf("%q refused: %v", raw, err)
		}
	}
	bad := []struct {
		raw    string
		secret string
	}{
		{"http://llm.example/v1", ""},
		{"http://10.0.0.5/v1", ""},
		{"http://127.0.0.1.evil.example/v1", ""}, // look-alike hostname is NOT loopback
		{"http://localhost.evil.example/v1", ""},
		{"ftp://llm.example/v1", ""},
		{"llm.example/v1", ""},
		{"https://", ""},
		{"https://user:p4ssw0rd-eng@llm.example/v1", "p4ssw0rd-eng"},
		{"https://llm.example/v1?key=qu3ry-eng", "qu3ry-eng"},
		{"https://llm.example/v1#fr4g-eng", "fr4g-eng"},
	}
	for _, tc := range bad {
		err := CheckTriageEndpointURL(tc.raw)
		if err == nil {
			t.Errorf("%q accepted", tc.raw)
			continue
		}
		if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
			t.Errorf("refusal for %q echoed the secret part: %v", tc.raw, err)
		}
	}
}

// Dispatch-time revalidation: a remote http base URL never reaches the network, even when the
// config arrived pre-checked (legacy store, or a caller that skipped validation).
func TestTriageFindingRevalidatesAtDispatch(t *testing.T) {
	var dialed int32
	cfg := TriageEndpointConfig{
		BaseURL: "http://169.254.1.1/v1", // remote, non-loopback
		Model:   "m",
		APIKey:  triageSecKey,
		HTTPClient: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			atomic.AddInt32(&dialed, 1)
			return nil, fmt.Errorf("should never dial")
		}}},
	}
	_, err := TriageFinding(context.Background(), triageSecFinding(), cfg)
	if err == nil || !strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("remote http not refused at dispatch: %v", err)
	}
	if atomic.LoadInt32(&dialed) != 0 {
		t.Errorf("a request was attempted despite the refusal")
	}
	if strings.Contains(err.Error(), triageSecKey) {
		t.Errorf("refusal echoed the key")
	}
}

// The redirect guard: an https->http downgrade (same hostname, changed scheme+port) refuses
// BEFORE the request is sent - the plain server must see nothing.
func TestTriageRedirectGuardRefusesDowngrade(t *testing.T) {
	var hits int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/chat/completions", http.StatusFound)
	}))
	defer tlsSrv.Close()
	cfg := TriageEndpointConfig{BaseURL: tlsSrv.URL, Model: "m", APIKey: triageSecKey, HTTPClient: tlsSrv.Client()}
	_, err := TriageFinding(context.Background(), triageSecFinding(), cfg)
	if err == nil || !strings.Contains(err.Error(), "changed origin") {
		t.Fatalf("downgrade redirect not refused: %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("the refused redirect was followed anyway")
	}
}

// Same-origin redirect (scheme, host AND port unchanged) still works and still carries the key.
func TestTriageRedirectGuardAllowsSameOrigin(t *testing.T) {
	var sawKey bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chat/completions" {
			http.Redirect(w, r, "/v1/chat/completions", http.StatusFound)
			return
		}
		sawKey = r.Header.Get("Authorization") == "Bearer "+triageSecKey
		http.Error(w, "stop here", http.StatusTeapot)
	}))
	defer srv.Close()
	// BaseURL has no path, so the engine posts to /chat/completions and gets redirected.
	cfg := TriageEndpointConfig{BaseURL: srv.URL, Model: "m", APIKey: triageSecKey, HTTPClient: srv.Client()}
	_, err := TriageFinding(context.Background(), triageSecFinding(), cfg)
	if err == nil || !strings.Contains(err.Error(), "418") {
		t.Fatalf("same-origin redirect did not complete: %v", err)
	}
	if !sawKey {
		t.Errorf("same-origin redirect lost the Authorization header")
	}
}

// The injection seam is not a security bypass: a caller-supplied client with its OWN
// CheckRedirect gets the credential rule composed on top - the caller's policy still runs,
// and the downgrade is still refused.
func TestTriageRedirectGuardComposesInjectedPolicy(t *testing.T) {
	var callerPolicyRan int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/chat/completions", http.StatusFound)
	}))
	defer tlsSrv.Close()
	injected := tlsSrv.Client()
	injected.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		atomic.AddInt32(&callerPolicyRan, 1)
		return nil
	}
	cfg := TriageEndpointConfig{BaseURL: tlsSrv.URL, Model: "m", APIKey: triageSecKey, HTTPClient: injected}
	_, err := TriageFinding(context.Background(), triageSecFinding(), cfg)
	if err == nil || !strings.Contains(err.Error(), "changed origin") {
		t.Fatalf("injected client bypassed the credential guard: %v", err)
	}
	if atomic.LoadInt32(&callerPolicyRan) == 0 {
		t.Errorf("the caller's CheckRedirect was not composed - it never ran")
	}
}

// The 10-redirect cap the default policy had is kept when the caller supplied none.
func TestTriageRedirectGuardKeepsTenRedirectCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/chat/completions", http.StatusFound)
	}))
	defer srv.Close()
	cfg := TriageEndpointConfig{BaseURL: srv.URL, Model: "m", APIKey: triageSecKey, HTTPClient: &http.Client{Timeout: 10 * time.Second}}
	_, err := TriageFinding(context.Background(), triageSecFinding(), cfg)
	if err == nil || !strings.Contains(err.Error(), "10 redirects") {
		t.Fatalf("redirect loop not stopped at 10: %v", err)
	}
}
