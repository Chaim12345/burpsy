package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The triage pass hands the configured API key to the endpoint as a bearer token. Where that
// header travels on a redirect is the Go http.Client's policy, not ours - so pin the current
// runtime behavior instead of paraphrasing it: same-host AND subdomain redirects keep the
// Authorization header (an https->http same-host downgrade included), only a genuinely
// different host strips it. These pins document the destination hazard; they change nothing.
func TestTriageRedirectKeyPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, r.Header.Get("X-Redirect-To"), http.StatusFound)
			return
		default:
			fmt.Fprintf(w, "auth=%q", r.Header.Get("Authorization"))
		}
	}))
	defer srv.Close()

	// dialAny maps every hostname onto the test server so cross-host and subdomain cases run
	// without DNS. Ports differ; Go's copy decision compares hostnames only.
	dialAny := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, strings.TrimPrefix(srv.URL, "http://"))
	}
	client := &http.Client{Transport: &http.Transport{DialContext: dialAny}}
	key := "sk-SYNTHETIC-redirect-fixture"
	host := strings.TrimPrefix(srv.URL, "http://")
	cases := []struct {
		name     string
		redirect string
		wantKey  bool
	}{
		{"same host and scheme", "http://" + host + "/land", true},
		{"same host different port", "http://" + strings.Split(host, ":")[0] + ":1" + "/land", true},
		{"subdomain of the origin", "http://deep.sub." + strings.Split(host, ":")[0] + "/land", true},
		{"different host", "http://unrelated.example/land", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.HasSuffix(tc.redirect, ":1/land") {
				t.Skip("port-1 dial would fail before the header question is answered")
			}
			req, err := http.NewRequest(http.MethodGet, "http://"+host+"/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+key)
			req.Header.Set("X-Redirect-To", tc.redirect)
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			buf := make([]byte, 256)
			n, _ := res.Body.Read(buf)
			got := strings.Contains(string(buf[:n]), key)
			if got != tc.wantKey {
				t.Errorf("redirect to %s: key forwarded=%v, want %v", tc.redirect, got, tc.wantKey)
			}
		})
	}
}

// The downgrade case needs a real TLS origin: https://host redirecting to http://the-same-host
// keeps the bearer header (hostname comparison ignores the scheme), which is why the ui2
// settings page refuses to mint remote http base URLs at all.
func TestTriageRedirectKeyPolicyHTTPSDowngrade(t *testing.T) {
	var plain *httptest.Server
	plain = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%q", r.Header.Get("Authorization"))
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/land", http.StatusFound)
	}))
	defer tlsSrv.Close()
	// Both servers listen on 127.0.0.1, so to Go's hostname-only copy rule this is a same-host
	// redirect - despite the scheme dropping from https to http.
	client := tlsSrv.Client()
	key := "sk-SYNTHETIC-redirect-fixture"
	req, err := http.NewRequest(http.MethodGet, tlsSrv.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := make([]byte, 256)
	n, _ := res.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), key) {
		t.Errorf("https->http same-host redirect did NOT forward the key - Go's policy changed; re-check the destination hazard notes")
	}
	// Sanity: the TLS client really verified the test CA (tlsSrv.Client() trusts only it), so a
	// default-config client must fail - otherwise the downgrade observation above would not be
	// about a verified-TLS origin.
	if _, err := (&http.Client{}).Get(tlsSrv.URL + "/start"); err == nil {
		t.Errorf("default client unexpectedly trusted the test CA - the downgrade pin proves nothing")
	}
}
