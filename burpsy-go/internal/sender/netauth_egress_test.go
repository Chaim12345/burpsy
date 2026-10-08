package sender

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/netauth"
)

// The tests in this file answer one question and nothing else: does a credential the
// operator configured actually leave the machine?
//
// That is worth its own file because it is the question a unit test of netauth cannot
// answer. netauth's tests prove a correct Authorization header can be *built*; these prove
// one is attached to a request that a real server receives. The gap between those two is
// where the whole feature would have silently not worked — a rule stored, a panel showing
// it, and every request going out unauthenticated.

func mustCredentials(t *testing.T, host string, scheme netauth.Scheme, user, password, realm string) *netauth.Credentials {
	t.Helper()
	rule, err := netauth.NewCredential(netauth.CredentialSpec{
		Host: host, Scheme: scheme, Username: user, Password: password, Realm: realm,
	})
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	store := netauth.NewCredentials()
	store.Add(rule)
	return store
}

// requestFor builds a typed request aimed at an httptest server's own address, so the host
// pattern under test is the host the server is actually listening on.
func requestFor(t *testing.T, method, rawURL string) *Request {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing %q: %v", rawURL, err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("no port in %q: %v", rawURL, err)
	}
	return &Request{
		Method: method,
		URL:    rawURL,
		Host:   parsed.Hostname(),
		Path:   parsed.Path,
		Port:   uint16(port),
		TLS:    parsed.Scheme == "https",
	}
}

// ---- Basic --------------------------------------------------------------------------

// The end-to-end claim for Basic: configure a rule, send one request, and the server sees
// the credentials on the first attempt with no 401 in between.
func Test_a_configured_basic_credential_reaches_the_server(t *testing.T) {
	var seen []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		user, password, ok := r.BasicAuth()
		if !ok || user != "operator" || password != "s3cret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="corp"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultSenderConfig()
	config.PlatformAuth = mustCredentials(t, "127.0.0.1", netauth.SchemeBasic, "operator", "s3cret", "")
	sender := NewSender(config)

	response, err := sender.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/protected"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the server answered %d, so the credential did not reach it. Authorization headers "+
			"observed: %q", response.StatusCode, seen)
	}
	mu.Lock()
	attempts := len(seen)
	mu.Unlock()
	if attempts != 1 {
		t.Errorf("Basic took %d attempts; it is preemptive and must authenticate on the first request "+
			"— an extra 401 per send is an extra unauthenticated request in the target's logs", attempts)
	}
}

// A host no rule covers must be sent to unauthenticated. The failure this guards is the
// worst one available here: the operator's credentials leaking to a target they were never
// configured for.
func Test_an_unmatched_host_is_sent_no_credential(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultSenderConfig()
	// A pattern that deliberately does not cover 127.0.0.1.
	config.PlatformAuth = mustCredentials(t, "intranet.example.com", netauth.SchemeBasic, "operator", "s3cret", "")
	sender := NewSender(config)

	if _, err := sender.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if authorization != "" {
		t.Errorf("a host outside every rule received %q; credentials configured for one target must "+
			"never reach another", authorization)
	}
}

// A credential the caller set itself wins. An operator editing a request in Repeater and
// typing a credential into it means that credential, and a per-host rule silently replacing
// it would make the request they are looking at not the request that goes out.
func Test_a_callers_own_authorization_header_is_not_replaced(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultSenderConfig()
	config.PlatformAuth = mustCredentials(t, "127.0.0.1", netauth.SchemeBasic, "rule", "rule-password", "")
	sender := NewSender(config)

	request := requestFor(t, http.MethodGet, server.URL+"/")
	request.Headers = map[string]string{"Authorization": "Bearer typed-by-the-operator"}
	if _, err := sender.Send(context.Background(), request); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if authorization != "Bearer typed-by-the-operator" {
		t.Errorf("the operator's own Authorization header became %q", authorization)
	}
}

// ---- Digest -------------------------------------------------------------------------

// Digest's two legs, end to end: the first request has nothing to hash, the 401 carries the
// nonce, and the retry authenticates. The server here checks the response hash rather than
// just the header's presence, so a wrong computation fails the test instead of passing it.
func Test_a_configured_digest_credential_authenticates_after_one_challenge(t *testing.T) {
	const (
		realm    = "corp"
		nonce    = "1f2e3d4c5b6a"
		username = "operator"
		password = "s3cret"
	)
	var attempts int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()

		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Digest ") {
			w.Header().Set("WWW-Authenticate",
				`Digest realm="`+realm+`", qop="auth", nonce="`+nonce+`", algorithm=MD5`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		params := digestParams(header)
		if params["nonce"] != nonce || params["username"] != username || params["qop"] != "auth" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		want := expectedDigestResponse(username, realm, password, r.Method, params["uri"],
			nonce, params["nc"], params["cnonce"])
		if params["response"] != want {
			t.Errorf("the Digest response hash is %q, want %q — the header was present but wrong, "+
				"which a presence check would have called a pass", params["response"], want)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DefaultSenderConfig()
	config.PlatformAuth = mustCredentials(t, "127.0.0.1", netauth.SchemeDigest, username, password, realm)
	sender := NewSender(config)

	response, err := sender.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/dir/index.html"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the server answered %d after the challenge; the Digest retry did not authenticate",
			response.StatusCode)
	}
	mu.Lock()
	got := attempts
	mu.Unlock()
	if got != 2 {
		t.Errorf("Digest took %d requests; it must be exactly two — one to be challenged and one to "+
			"answer. More would mean the retry is looping the operator's credentials at the target", got)
	}
}

// A rejected credential must be answered with the 401, not with a retry loop. A loop
// bounded by an attempt count would keep sending the operator's credentials at a host that
// keeps refusing them, which on an engagement is how an account gets locked out.
func Test_a_rejected_digest_credential_is_not_retried_forever(t *testing.T) {
	var attempts int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		// The same nonce every time: the credential is wrong, not the nonce stale.
		w.Header().Set("WWW-Authenticate", `Digest realm="corp", qop="auth", nonce="fixed", algorithm=MD5`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	config := DefaultSenderConfig()
	config.PlatformAuth = mustCredentials(t, "127.0.0.1", netauth.SchemeDigest, "operator", "wrong", "corp")
	sender := NewSender(config)

	response, err := sender.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected the 401 to come back as the answer it is, got %d", response.StatusCode)
	}
	mu.Lock()
	got := attempts
	mu.Unlock()
	if got > 2 {
		t.Errorf("a rejected credential produced %d requests; the retry is bounded at exactly one and "+
			"a repeated nonce must stop it", got)
	}
}

// ---- client certificates ------------------------------------------------------------

// The end-to-end claim for client TLS authentication on the sender's egress leg: a bound
// identity is presented on the handshake and the server sees the leaf it expected.
//
// A server with ClientAuth: RequireAnyClientCert is the assertion. It fails the handshake
// when no certificate arrives, so a Send that succeeds is itself proof one did — and the
// handler then checks it is the right one rather than merely some certificate.
func Test_a_bound_client_certificate_is_presented_on_the_handshake(t *testing.T) {
	identity, leafDER := generateClientIdentity(t)

	var presented [][]byte
	var mu sync.Mutex
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		for _, cert := range r.TLS.PeerCertificates {
			presented = append(presented, cert.Raw)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	certs := netauth.NewClientCerts()
	certs.Add(identity)

	config := DefaultSenderConfig()
	config.ClientCerts = certs
	// The httptest server's leaf is signed by its own throwaway CA, so verification is off
	// here for the same reason the proxy's upstream leg has it off: this test is about what we
	// present, not about what we trust.
	config.TLSVerify = false
	sender := NewSender(config)

	response, err := sender.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil {
		t.Fatalf("Send over TLS requiring a client certificate failed, so none was presented: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the server answered %d", response.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(presented) == 0 {
		t.Fatal("the handshake carried no client certificate")
	}
	if string(presented[0]) != string(leafDER) {
		t.Error("the server received a different certificate than the one bound to this host")
	}
}

// The raw-bytes path is a separate dial (Sender.dialTLS, not http.Transport), and it is the
// one the desync and smuggling probes use. A certificate that works for the typed path and
// not for this one would mean half the tool can reach a client-authenticated app.
func Test_a_bound_client_certificate_is_presented_on_the_raw_bytes_path(t *testing.T) {
	identity, _ := generateClientIdentity(t)

	listener := tlsListenerRequiringClientCert(t)
	defer listener.Close()

	certs := netauth.NewClientCerts()
	certs.Add(identity)

	config := DefaultSenderConfig()
	config.ClientCerts = certs
	config.TLSVerify = false
	sender := NewSender(config)

	host, portText, err := splitAddr(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)

	// ProtocolFor does one handshake and nothing else, which is exactly the observation this
	// test wants: it goes through dialTLS, and the listener refuses a handshake with no client
	// certificate. A success is the presentation.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := sender.ProtocolFor(ctx, host, uint16(port), true); err != nil {
		t.Fatalf("the raw-bytes TLS dial did not present a client certificate: %v", err)
	}
}

// A host with no binding must still be able to handshake with a server that merely
// *requests* a certificate. A server may ask every client and accept those that send none,
// so failing here would break targets that work today.
func Test_an_unbound_host_still_completes_a_handshake_that_requested_a_certificate(t *testing.T) {
	identity, _ := generateClientIdentity(t)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("a certificate was presented to a host with no binding")
		}
		w.WriteHeader(http.StatusOK)
	}))
	// RequestClientCert, not Require: the server asks and accepts a client that declines.
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()

	certs := netauth.NewClientCerts()
	// Bound to a host this request does not go to.
	identity.Host = "intranet.example.com"
	certs.Add(identity)

	config := DefaultSenderConfig()
	config.ClientCerts = certs
	config.TLSVerify = false
	sender := NewSender(config)

	response, err := sender.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil {
		t.Fatalf("a handshake that requested a certificate we do not have should still complete: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("the server answered %d", response.StatusCode)
	}
}

// ---- what the panel is told -----------------------------------------------------------

// The introspection the API reports through presented_on_egress. A sender built without the
// stores must say so, because a rule stored but never presented is the partial result this
// codebase treats as a bug.
func Test_a_sender_reports_whether_it_carries_network_authentication(t *testing.T) {
	bare := NewSender(DefaultSenderConfig())
	if bare.CarriesPlatformAuth() || bare.CarriesClientCerts() {
		t.Error("a sender built from DefaultSenderConfig claims to carry credentials it was never given")
	}

	config := DefaultSenderConfig()
	config.PlatformAuth = netauth.NewCredentials()
	config.ClientCerts = netauth.NewClientCerts()
	wired := NewSender(config)
	if !wired.CarriesPlatformAuth() || !wired.CarriesClientCerts() {
		t.Error("a sender built with both stores reports it has neither, so the panel would tell the " +
			"operator their rules are not presented when they are")
	}
}
