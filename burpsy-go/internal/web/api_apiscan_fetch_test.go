package web

// Upload from URL with Add auth (burpsy-react-ui-fu4l), against a local definition server that
// demands authentication. What is pinned:
//   - without the credential the fetch reports the 401; with Basic, Bearer or an OAuth2
//     client-credentials token it returns the document and recognises it;
//   - an out-of-scope definition URL — or token URL — is refused before anything is contacted;
//   - the credential never reaches history, the tool log, or the reply;
//   - the size and time bounds hold, redirects are not followed, and WSDL/HTML are named, not scanned.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fetchTestSpec = `{"openapi":"3.0.3","info":{"title":"Pets","version":"1"},"servers":[{"url":"https://api.example.test"}],` +
	`"paths":{"/pets":{"get":{"responses":{"200":{"description":"ok"}}}}}}`

// definitionServer serves the spec at /spec only to Basic alice:s3cret or Bearer <token>, issues
// that token at /token for client app:appsecret, and counts every request.
func definitionServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	const token = "tok-9f8e7d"
	mux := http.NewServeMux()
	mux.HandleFunc("/spec", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		user, pass, basic := r.BasicAuth()
		if !(basic && user == "alice" && pass == "s3cret") && r.Header.Get("Authorization") != "Bearer "+token {
			w.Header().Set("WWW-Authenticate", `Basic realm="api"`)
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fetchTestSpec))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		id, secret, ok := r.BasicAuth()
		if r.Method != http.MethodPost || !ok || id != "app" || secret != "appsecret" {
			http.Error(w, "bad client", http.StatusUnauthorized)
			return
		}
		r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("scope") != "read:spec" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"` + token + `","token_type":"Bearer","expires_in":60}`))
	})
	mux.HandleFunc("/service.wsdl", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`<?xml version="1.0"?><wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"></wsdl:definitions>`))
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/spec", http.StatusFound)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(2 * time.Second)
	})
	mux.HandleFunc("/huge", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(strings.Repeat("a", apiScanFetchMaxBytes+1)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func fetchServer(t *testing.T, srv *httptest.Server) *Server {
	t.Helper()
	s := newTestServer()
	u, _ := url.Parse(srv.URL)
	s.scope.AddInclude(u.Hostname())
	return s
}

func TestFetchingAnAuthenticatedDefinitionNeedsTheCredentialAndReturnsTheDocument(t *testing.T) {
	srv, _ := definitionServer(t)
	s := fetchServer(t, srv)

	rec := postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/spec"})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "401") {
		t.Fatalf("without auth: %d %s, want the 401 reported", rec.Code, rec.Body.String())
	}

	for name, auth := range map[string]map[string]any{
		"basic":  {"type": "basic", "username": "alice", "password": "s3cret"},
		"oauth2": {"type": "oauth2_client_credentials", "token_url": srv.URL + "/token", "client_id": "app", "client_secret": "appsecret", "scope": "read:spec"},
		"bearer": {"type": "bearer", "token": "tok-9f8e7d"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/spec", "auth": auth})
			if rec.Code != http.StatusOK {
				t.Fatalf("with %s: %d %s", name, rec.Code, rec.Body.String())
			}
			var resp apiScanFetchResp
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Definition != fetchTestSpec || resp.Format != "openapi-3" || !resp.Scannable || resp.Status != 200 {
				t.Errorf("reply = format %q scannable %v status %d, definition %d bytes", resp.Format, resp.Scannable, resp.Status, len(resp.Definition))
			}
			if name == "oauth2" && !resp.TokenFetched {
				t.Error("token_fetched is false for an OAuth2 fetch")
			}
			if strings.Contains(rec.Body.String(), "tok-9f8e7d") && name == "oauth2" {
				t.Error("the issued access token was echoed in the reply")
			}
		})
	}

	// The fetched document is accepted by the scan's own dry run, unchanged.
	if rec := postJSON(t, s, "/api/apiscan", map[string]any{"definition": fetchTestSpec, "base_url": srv.URL, "dry_run": true}); rec.Code != http.StatusOK {
		t.Errorf("dry run of the fetched definition: %d %s", rec.Code, rec.Body.String())
	}

	// Credentials are neither persisted nor logged: nothing in history, nothing in the tool log.
	if _, exchanges := s.store.Count(); exchanges != 0 {
		t.Errorf("the fetch recorded %d exchange(s) in history; its request carries the credential", exchanges)
	}
	logged := get200(t, s, "/api/tools/log")
	for _, secret := range []string{"s3cret", "appsecret", "tok-9f8e7d", base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))} {
		if strings.Contains(logged, secret) {
			t.Errorf("the tool log contains a credential (%q): %s", secret, logged)
		}
	}
	if !strings.Contains(logged, "/spec") {
		t.Errorf("the fetch is missing from the tool log: %s", logged)
	}
}

func TestAnOutOfScopeDefinitionOrTokenURLIsRefusedBeforeAnythingIsSent(t *testing.T) {
	srv, hits := definitionServer(t)
	s := newTestServer()
	s.scope.AddInclude("in-scope.example")

	rec := postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/spec",
		"auth": map[string]any{"type": "basic", "username": "alice", "password": "s3cret"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope definition URL: %d %s, want 403", rec.Code, rec.Body.String())
	}

	// Definition host in scope, token host not (localhost names the same server, a different host).
	u, _ := url.Parse(srv.URL)
	s.scope.AddInclude(u.Hostname())
	rec = postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/spec", "auth": map[string]any{
		"type": "oauth2_client_credentials", "token_url": "http://localhost:" + u.Port() + "/token", "client_id": "app", "client_secret": "appsecret"}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "token URL") {
		t.Fatalf("out-of-scope token URL: %d %s, want 403 naming the token URL", rec.Code, rec.Body.String())
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the definition server was contacted %d time(s) by refused fetches", n)
	}
}

func TestAFetchedDefinitionIsBoundedAndNamedForWhatItIs(t *testing.T) {
	srv, _ := definitionServer(t)
	s := fetchServer(t, srv)

	rec := postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/service.wsdl"})
	var resp apiScanFetchResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || resp.Format != "wsdl" || resp.Scannable || !strings.Contains(resp.Note, "WSDL") {
		t.Errorf("WSDL: %d format %q scannable %v note %q", rec.Code, resp.Format, resp.Scannable, resp.Note)
	}

	if rec := postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/moved"}); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "not followed") {
		t.Errorf("redirect: %d %s, want it reported and not followed", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/huge"}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("oversized definition: %d %s, want 422", rec.Code, rec.Body.String()[:min(200, rec.Body.Len())])
	}
	old := apiScanFetchTimeout
	apiScanFetchTimeout = 300 * time.Millisecond
	t.Cleanup(func() { apiScanFetchTimeout = old })
	started := time.Now()
	rec = postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/slow"})
	if rec.Code == http.StatusOK || time.Since(started) > 1500*time.Millisecond {
		t.Errorf("slow server: %d after %s, want a failure within the bound", rec.Code, time.Since(started))
	}

	u, _ := url.Parse(srv.URL)
	withUser := "http://alice:s3cret@" + u.Host + "/spec"
	rec = postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": withUser})
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "s3cret") {
		t.Errorf("credentials in the URL: %d %s, want 400 that does not repeat them", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/spec",
		"auth": map[string]any{"type": "bearer", "token": "x\r\nX-Injected: 1"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("header injection through the token: %d, want 400", rec.Code)
	}
}

// Review fixes (burpsy-react-ui-fu4l): the query string — where an API key in a URL lives — never
// reaches the tool log; a query with a space still produces a well-formed request; a malformed URL is
// not echoed; and a compressed body over the limit is reported as too large, not as corrupt.
func TestTheFetchKeepsTheQueryOutOfTheLogAndSendsAWellFormedRequestLine(t *testing.T) {
	var gotURI atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI.Store(r.RequestURI)
		w.Write([]byte(fetchTestSpec))
	}))
	t.Cleanup(srv.Close)
	s := fetchServer(t, srv)

	rec := postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/spec?api_key=k3y-sekret&q=a b"})
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch with a query: %d %s", rec.Code, rec.Body.String())
	}
	if uri, _ := gotURI.Load().(string); uri != "/spec?api_key=k3y-sekret&q=a%20b" {
		t.Errorf("the server received request-target %q, want the query sent with its space encoded", uri)
	}
	logged := get200(t, s, "/api/tools/log")
	if strings.Contains(logged, "k3y-sekret") || strings.Contains(logged, "api_key") {
		t.Errorf("the tool log carries the query string: %s", logged)
	}
	if !strings.Contains(logged, "/spec") {
		t.Errorf("the fetch is missing from the tool log: %s", logged)
	}

	rec = postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": "http:/alice:pw-in-url@h/x"})
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "pw-in-url") {
		t.Errorf("a host-less URL holding a password: %d %s, want 400 that does not repeat it", rec.Code, rec.Body.String())
	}
}

func TestAnOversizedCompressedDefinitionIsRefusedAsTooLargeNotCorrupt(t *testing.T) {
	gzipOf := func(b []byte) []byte {
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		zw.Write(b)
		zw.Close()
		return gz.Bytes()
	}
	// Two shapes of too large: one that compresses well (small on the wire, too big decoded), and one
	// that does not (already past the limit compressed, so the read cuts the gzip stream short —
	// which used to be reported as "could not be decoded").
	noise := make([]byte, apiScanFetchMaxBytes+1)
	mrand.New(mrand.NewSource(1)).Read(noise)
	bodies := map[string][]byte{
		"compressible":   gzipOf(bytes.Repeat([]byte("a"), apiScanFetchMaxBytes+1)),
		"incompressible": gzipOf(noise),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				w.Write(body)
			}))
			t.Cleanup(srv.Close)
			s := fetchServer(t, srv)

			rec := postJSON(t, s, "/api/apiscan/fetch", map[string]any{"url": srv.URL + "/spec"})
			if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "larger than") {
				t.Fatalf("oversized gzip definition: %d %s, want 422 naming the size limit", rec.Code, rec.Body.String())
			}
			if logged := get200(t, s, "/api/tools/log"); !strings.Contains(logged, "/spec") {
				t.Errorf("a fetch refused for size is missing from the tool log, though it was sent: %s", logged)
			}
		})
	}
}
