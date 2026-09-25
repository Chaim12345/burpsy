package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
	"software.sslmate.com/src/go-pkcs12"
)

// The literals every leak assertion searches for. Distinctive so that a hit in a response
// body is unambiguously the secret and not an artefact of base64 or JSON escaping.
const (
	apiPassword   = "web-api-password-DO-NOT-LEAK"
	apiPassphrase = "web-api-passphrase-DO-NOT-LEAK"
)

func networkServer() *Server {
	return NewServer(core.NewTrafficStore(), core.NewScope())
}

// call sends one request through the server's own mux, so the route registration is part of
// what is under test rather than the handler being called directly.
func call(t *testing.T, server *Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	recorder := httptest.NewRecorder()
	server.mux.ServeHTTP(recorder, request)
	return recorder
}

// ---- platform authentication --------------------------------------------------------

// The empty case, which honest counting requires be distinguishable from a failure: an
// empty array alone cannot say which, so the body says so.
func Test_platform_auth_reports_empty_as_empty_and_not_as_nothing(t *testing.T) {
	recorder := call(t, networkServer(), http.MethodGet, "/api/network/auth", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET answered %d: %s", recorder.Code, recorder.Body)
	}
	var response platformAuthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if !response.Empty {
		t.Error("a server with no rules did not report empty, so the panel cannot tell no-rules from a failed load")
	}
	if response.Rules == nil {
		t.Error("rules is null rather than an empty array, so the browser has to special-case it before counting")
	}
	// The panel reads both lists from here rather than hard-coding them, so a scheme cannot
	// appear in a selector without being implemented, and the unsupported ones are named out
	// loud rather than left as an absence for the operator to interpret.
	if len(response.Schemes) == 0 {
		t.Error("no schemes were advertised, so the panel's selector would be empty")
	}
	if len(response.Unsupported) == 0 {
		t.Error("the unsupported schemes were not named; an operator looking for NTLM needs to be told " +
			"it is not implemented rather than find nothing")
	}
}

// The core secret rule, at the API boundary: a password goes in and never comes back out.
// Asserted against the POST's own reply as well as the GET, because the reply is the place a
// careless echo of the request body would land.
func Test_no_response_from_the_network_api_carries_a_password(t *testing.T) {
	server := networkServer()

	post := call(t, server, http.MethodPost, "/api/network/auth",
		`{"host":"*.example.com","scheme":"basic","username":"operator","password":"`+apiPassword+`","realm":"corp"}`)
	if post.Code != http.StatusOK {
		t.Fatalf("POST answered %d: %s", post.Code, post.Body)
	}
	if strings.Contains(post.Body.String(), apiPassword) {
		t.Errorf("the POST reply echoed the password back: %s", post.Body)
	}

	get := call(t, server, http.MethodGet, "/api/network/auth", "")
	if strings.Contains(get.Body.String(), apiPassword) {
		t.Errorf("GET disclosed the password: %s", get.Body)
	}

	var response platformAuthResponse
	if err := json.Unmarshal(get.Body.Bytes(), &response); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(response.Rules) != 1 {
		t.Fatalf("expected the stored rule to be listed, got %d", len(response.Rules))
	}
	rule := response.Rules[0]
	// What it must say instead of the secret: that there is one. A blank field would read as
	// "no credential configured" for a rule that is live.
	if !rule.HasPassword {
		t.Error("has_password is false for a rule that has one, so the panel reads as unconfigured")
	}
	if rule.Host != "*.example.com" || rule.Username != "operator" || rule.Scheme != "basic" || rule.Realm != "corp" {
		t.Errorf("the stored rule came back wrong: %+v", rule)
	}
}

// Re-posting the same (host, scheme) replaces rather than appending, and says which
// happened — an operator fixing a typo in a password wants "updated", not a second row.
func Test_reposting_a_rule_replaces_it_and_says_so(t *testing.T) {
	server := networkServer()
	body := `{"host":"example.com","scheme":"basic","username":"a","password":"` + apiPassword + `"}`

	first := call(t, server, http.MethodPost, "/api/network/auth", body)
	if strings.Contains(first.Body.String(), `"replaced":true`) {
		t.Error("the first POST reported a replacement")
	}
	second := call(t, server, http.MethodPost, "/api/network/auth",
		`{"host":"example.com","scheme":"basic","username":"b","password":"`+apiPassword+`"}`)
	if !strings.Contains(second.Body.String(), `"replaced":true`) {
		t.Errorf("re-posting the same host and scheme did not report a replacement: %s", second.Body)
	}

	var response platformAuthResponse
	get := call(t, server, http.MethodGet, "/api/network/auth", "")
	json.Unmarshal(get.Body.Bytes(), &response)
	if len(response.Rules) != 1 || response.Rules[0].Username != "b" {
		t.Errorf("expected one rule updated to username b, got %+v", response.Rules)
	}
}

// The exact-match removal contract: 404 for an absent pattern. A DELETE that quietly
// succeeded would make a double-click look like two rules had existed.
func Test_deleting_an_absent_rule_answers_404(t *testing.T) {
	server := networkServer()
	call(t, server, http.MethodPost, "/api/network/auth",
		`{"host":"example.com","scheme":"basic","username":"a","password":"`+apiPassword+`"}`)

	cases := []struct {
		name   string
		target string
		want   int
	}{
		{"a host that is not in the list", "/api/network/auth?host=absent.example.com&scheme=basic", http.StatusNotFound},
		{"the right host, the wrong scheme", "/api/network/auth?host=example.com&scheme=digest", http.StatusNotFound},
		// A host the pattern would *match* is not the pattern. Removal keys on the pattern text
		// so the operator can tell which row they deleted.
		{"a host the pattern covers", "/api/network/auth?host=api.example.com&scheme=basic", http.StatusNotFound},
		{"no host at all", "/api/network/auth?scheme=basic", http.StatusBadRequest},
		// An unsupported scheme must be explained, not answered 404 — "no such rule" would send
		// the operator looking for a rule when the real answer is that NTLM is not implemented.
		{"an unsupported scheme", "/api/network/auth?host=example.com&scheme=ntlm", http.StatusBadRequest},
		{"the rule itself", "/api/network/auth?host=example.com&scheme=basic", http.StatusOK},
		{"the rule a second time", "/api/network/auth?host=example.com&scheme=basic", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := call(t, server, http.MethodDelete, tc.target, "")
			if recorder.Code != tc.want {
				t.Errorf("DELETE %s answered %d, want %d: %s", tc.target, recorder.Code, tc.want, recorder.Body)
			}
		})
	}
}

// Refuse-by-default at the boundary. Each of these is a rule that could never authenticate
// anything, and storing one would put a row on the panel that only ever fails.
func Test_the_network_api_refuses_unusable_rules(t *testing.T) {
	server := networkServer()
	cases := map[string]string{
		"no scheme":          `{"host":"example.com","username":"a","password":"b"}`,
		"unsupported scheme": `{"host":"example.com","scheme":"ntlmv2","username":"a","password":"b"}`,
		"unknown scheme":     `{"host":"example.com","scheme":"bearer","username":"a","password":"b"}`,
		"no host":            `{"host":"  ","scheme":"basic","username":"a","password":"b"}`,
		"no username":        `{"host":"example.com","scheme":"basic","username":"","password":"b"}`,
		"not json":           `{`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := call(t, server, http.MethodPost, "/api/network/auth", body)
			if recorder.Code != http.StatusBadRequest {
				t.Errorf("POST %s answered %d, want 400: %s", name, recorder.Code, recorder.Body)
			}
		})
	}
	// And nothing was stored by any of them.
	var response platformAuthResponse
	get := call(t, server, http.MethodGet, "/api/network/auth", "")
	json.Unmarshal(get.Body.Bytes(), &response)
	if len(response.Rules) != 0 {
		t.Errorf("a refused rule was stored anyway: %+v", response.Rules)
	}
}

// An empty password is a legal configuration — some appliances use one — and has_password
// must report it as absent rather than the row being refused or looking protected.
func Test_a_rule_with_an_empty_password_is_stored_and_reported_honestly(t *testing.T) {
	server := networkServer()
	recorder := call(t, server, http.MethodPost, "/api/network/auth",
		`{"host":"appliance.example.com","scheme":"basic","username":"admin","password":""}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("an empty password was refused: %d %s", recorder.Code, recorder.Body)
	}
	var response platformAuthResponse
	get := call(t, server, http.MethodGet, "/api/network/auth", "")
	json.Unmarshal(get.Body.Bytes(), &response)
	if len(response.Rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(response.Rules))
	}
	if response.Rules[0].HasPassword {
		t.Error("has_password is true for an empty password, which claims a secret that is not there")
	}
}

// The panel is told whether the credentials it edits actually reach the wire. A rule stored
// but never presented is the partial result this codebase treats as a bug, so it is reported
// rather than left to inference.
func Test_the_api_says_whether_the_attached_sender_presents_the_credentials(t *testing.T) {
	bare := networkServer()
	var response platformAuthResponse
	json.Unmarshal(call(t, bare, http.MethodGet, "/api/network/auth", "").Body.Bytes(), &response)
	if response.PresentedOnEgress {
		t.Error("a server whose sender has no credential store claims the rules are presented")
	}

	config := sender.DefaultSenderConfig()
	credentials := netauth.NewCredentials()
	certs := netauth.NewClientCerts()
	config.PlatformAuth = credentials
	config.ClientCerts = certs
	wired := networkServer().WithSender(sender.NewSender(config)).WithNetAuth(credentials, certs)

	json.Unmarshal(call(t, wired, http.MethodGet, "/api/network/auth", "").Body.Bytes(), &response)
	if !response.PresentedOnEgress {
		t.Error("a server whose sender holds the same store reports the rules are not presented")
	}

	var certResponse clientCertsResponse
	json.Unmarshal(call(t, wired, http.MethodGet, "/api/network/client-certs", "").Body.Bytes(), &certResponse)
	if !certResponse.PresentedOnEgress {
		t.Error("the client-certificate surface reports it is not presented despite being wired")
	}
}

// ---- client TLS certificates --------------------------------------------------------

// writeTestP12 generates a client identity and writes it as PKCS#12 under t.TempDir().
// Nothing key-bearing is committed: .gitignore excludes *.pem and *.key, and a checked-in
// PKCS#12 would be key material in the repository whatever directory it sat in.
func writeTestP12(t *testing.T, passphrase string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "burpsy web api test client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	raw, err := pkcs12.Modern2023.Encode(key, leaf, nil, passphrase)
	if err != nil {
		t.Fatalf("encoding PKCS#12: %v", err)
	}
	path := filepath.Join(t.TempDir(), "client.p12")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	return path
}

func Test_no_response_from_the_client_cert_api_carries_a_passphrase(t *testing.T) {
	server := networkServer()
	path := writeTestP12(t, apiPassphrase)

	post := call(t, server, http.MethodPost, "/api/network/client-certs",
		`{"host":"*.example.com","path":`+jsonString(path)+`,"passphrase":"`+apiPassphrase+`"}`)
	if post.Code != http.StatusOK {
		t.Fatalf("POST answered %d: %s", post.Code, post.Body)
	}
	if strings.Contains(post.Body.String(), apiPassphrase) {
		t.Errorf("the POST reply echoed the passphrase back: %s", post.Body)
	}

	get := call(t, server, http.MethodGet, "/api/network/client-certs", "")
	if strings.Contains(get.Body.String(), apiPassphrase) {
		t.Errorf("GET disclosed the passphrase: %s", get.Body)
	}

	var response clientCertsResponse
	if err := json.Unmarshal(get.Body.Bytes(), &response); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(response.Bindings) != 1 {
		t.Fatalf("expected one binding, got %d", len(response.Bindings))
	}
	binding := response.Bindings[0]
	// The metadata the panel needs to answer "which identity is this, and is it still valid",
	// read off the leaf at load time so the API never touches key material to produce it.
	if binding.Subject == "" || binding.Fingerprint == "" || binding.NotAfter == "" {
		t.Errorf("the binding is missing the metadata the panel shows: %+v", binding)
	}
	if !binding.HasPassphrase {
		t.Error("has_passphrase is false for a file that needed one, which reads as unprotected")
	}
	if binding.Path != path {
		t.Errorf("path is %q, want %q — it is the first thing to check when a handshake is rejected", binding.Path, path)
	}
	// PKCS#11 is declared out of scope rather than omitted, so the panel can say so instead of
	// leaving the operator to wonder whether they are looking in the wrong place.
	if response.PKCS11Supported {
		t.Error("the API claims PKCS#11 support, which this build does not implement")
	}
}

// A bad passphrase must be reported at the moment the operator can still fix it, with an
// error that names which of four things to change — and without echoing the secret back.
func Test_an_unloadable_pkcs12_is_refused_with_a_reason(t *testing.T) {
	server := networkServer()
	good := writeTestP12(t, apiPassphrase)

	cases := map[string]struct {
		body   string
		wantIn string
	}{
		"wrong passphrase": {`{"host":"example.com","path":` + jsonString(good) + `,"passphrase":"wrong"}`, "passphrase"},
		"missing file":     {`{"host":"example.com","path":"/nonexistent/absent.p12","passphrase":"x"}`, "no PKCS#12 file at"},
		"no host":          {`{"host":"","path":` + jsonString(good) + `,"passphrase":"x"}`, "host pattern"},
		"no path":          {`{"host":"example.com","path":"","passphrase":"x"}`, "PKCS#12 file"},
		"not json":         {`{`, "Invalid request body"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := call(t, server, http.MethodPost, "/api/network/client-certs", tc.body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("answered %d, want 400: %s", recorder.Code, recorder.Body)
			}
			if !strings.Contains(recorder.Body.String(), tc.wantIn) {
				t.Errorf("the error does not name what to fix.\ngot:  %s\nwant it to contain: %q",
					recorder.Body, tc.wantIn)
			}
			if strings.Contains(recorder.Body.String(), apiPassphrase) {
				t.Errorf("the error body carries the passphrase: %s", recorder.Body)
			}
		})
	}

	var response clientCertsResponse
	json.Unmarshal(call(t, server, http.MethodGet, "/api/network/client-certs", "").Body.Bytes(), &response)
	if len(response.Bindings) != 0 {
		t.Errorf("a binding that failed to load was stored anyway: %+v", response.Bindings)
	}
	if !response.Empty {
		t.Error("the empty binding list did not report itself empty")
	}
}

func Test_deleting_an_absent_client_cert_binding_answers_404(t *testing.T) {
	server := networkServer()
	path := writeTestP12(t, apiPassphrase)
	call(t, server, http.MethodPost, "/api/network/client-certs",
		`{"host":"*.example.com","path":`+jsonString(path)+`,"passphrase":"`+apiPassphrase+`"}`)

	if code := call(t, server, http.MethodDelete, "/api/network/client-certs?host=other.test", "").Code; code != http.StatusNotFound {
		t.Errorf("deleting an absent binding answered %d, want 404", code)
	}
	// The pattern text, not a host it covers.
	if code := call(t, server, http.MethodDelete, "/api/network/client-certs?host=api.example.com", "").Code; code != http.StatusNotFound {
		t.Errorf("deleting by a covered host answered %d, want 404 — removal is exact on the pattern", code)
	}
	if code := call(t, server, http.MethodDelete, "/api/network/client-certs", "").Code; code != http.StatusBadRequest {
		t.Errorf("deleting with no host answered %d, want 400", code)
	}
	if code := call(t, server, http.MethodDelete, "/api/network/client-certs?host=*.example.com", "").Code; code != http.StatusOK {
		t.Errorf("deleting the binding itself answered %d, want 200", code)
	}
	if code := call(t, server, http.MethodDelete, "/api/network/client-certs?host=*.example.com", "").Code; code != http.StatusNotFound {
		t.Errorf("deleting it twice answered %d the second time, want 404", code)
	}
}

// ---- persistence --------------------------------------------------------------------

// The round trip that matters: the secret reaches the database, comes back on restore, and
// still never appears in any response. Both halves are needed — a store that redacted by
// forgetting the password would pass a leak test and break the feature.
func Test_secrets_survive_persistence_and_are_still_never_echoed_back(t *testing.T) {
	store, err := persist.Open(filepath.Join(t.TempDir(), "netauth.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	defer store.Close()

	path := writeTestP12(t, apiPassphrase)

	// Session one: configure both surfaces through the API, so what lands in the database is
	// what a handler wrote rather than what a test constructed.
	first := networkServer().WithNetAuth(netauth.NewCredentials(), netauth.NewClientCerts()).WithPersist(store)
	if code := call(t, first, http.MethodPost, "/api/network/auth",
		`{"host":"*.example.com","scheme":"digest","username":"operator","password":"`+apiPassword+`","realm":"corp"}`).Code; code != http.StatusOK {
		t.Fatalf("POST auth answered %d", code)
	}
	if code := call(t, first, http.MethodPost, "/api/network/client-certs",
		`{"host":"*.example.com","path":`+jsonString(path)+`,"passphrase":"`+apiPassphrase+`"}`).Code; code != http.StatusOK {
		t.Fatalf("POST client-certs answered %d", code)
	}

	// Session two: a fresh restore, as a restart would do it.
	authRows, err := store.LoadPlatformAuth()
	if err != nil {
		t.Fatalf("LoadPlatformAuth: %v", err)
	}
	certRows, err := store.LoadClientCerts()
	if err != nil {
		t.Fatalf("LoadClientCerts: %v", err)
	}
	credentials, authFailures := netauth.RestoreCredentials(authRows)
	certs, certFailures := netauth.RestoreClientCerts(certRows)
	if len(authFailures) != 0 || len(certFailures) != 0 {
		t.Fatalf("restoring what this build just wrote failed: %v %v", authFailures, certFailures)
	}

	// The secret survived: a Digest rule that can compute a response has its password, and a
	// binding that produces a signer has its passphrase. Neither is observable any other way,
	// which is the point of checking it this way.
	if usable, err := credentials.Learn("api.example.com", `Digest realm="corp", nonce="n", qop="auth"`); !usable {
		t.Fatalf("the restored Digest rule could not learn a challenge: %v", err)
	}
	if _, ok := credentials.Authorization("api.example.com", http.MethodGet, "/"); !ok {
		t.Error("the restored Digest rule produced no header, so the password did not survive the round trip")
	}
	if certs.For("api.example.com") == nil {
		t.Error("the restored binding produced no certificate, so the passphrase did not survive the round trip")
	}

	// And the restored server still discloses nothing.
	second := networkServer().WithNetAuth(credentials, certs)
	for _, target := range []string{"/api/network/auth", "/api/network/client-certs"} {
		body := call(t, second, http.MethodGet, target, "").Body.String()
		for _, secret := range []string{apiPassword, apiPassphrase} {
			if strings.Contains(body, secret) {
				t.Errorf("GET %s disclosed a secret after a restore: %s", target, body)
			}
		}
	}

	// A DELETE must reach the database too, or the rule comes back on the next restart and the
	// operator's removal was cosmetic.
	if code := call(t, first, http.MethodDelete, "/api/network/auth?host=*.example.com&scheme=digest", "").Code; code != http.StatusOK {
		t.Fatal("DELETE did not remove the rule")
	}
	remaining, err := store.LoadPlatformAuth()
	if err != nil {
		t.Fatalf("LoadPlatformAuth after delete: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("the deleted rule is still in the database and would come back on restart: %+v", remaining)
	}
}

// A binding that could not be rebuilt at startup is reported on the panel, not dropped. It
// was on the operator's panel yesterday, and a panel that lists nothing where an identity
// used to be says the wrong thing about why a handshake now fails.
func Test_a_binding_that_could_not_be_restored_is_reported(t *testing.T) {
	server := networkServer().WithNetAuthRestoreNotes([]string{
		"client certificate for stale.example.com: no PKCS#12 file at /gone/identity.p12",
	})
	var response clientCertsResponse
	json.Unmarshal(call(t, server, http.MethodGet, "/api/network/client-certs", "").Body.Bytes(), &response)
	if len(response.RestoreFailures) != 1 {
		t.Fatalf("expected the restore failure to be reported, got %+v", response.RestoreFailures)
	}
	if !strings.Contains(response.RestoreFailures[0], "stale.example.com") {
		t.Errorf("the reported failure does not name the binding: %q", response.RestoreFailures[0])
	}
	// And with no failures it is an empty array rather than null, so the browser can count it.
	var clean clientCertsResponse
	json.Unmarshal(call(t, networkServer(), http.MethodGet, "/api/network/client-certs", "").Body.Bytes(), &clean)
	if clean.RestoreFailures == nil {
		t.Error("restore_failures is null rather than an empty array")
	}
}

// jsonString quotes a path for embedding in a request body literal. Paths from t.TempDir()
// contain no characters needing escapes today, but going through the encoder means a
// temp-directory name that does cannot silently turn these tests into malformed-JSON tests
// that pass for the wrong reason.
func jsonString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// senderWithAuth is a sender carrying the credential store, which is the state the panel calls
// "configured on egress".
func senderWithAuth(creds *netauth.Credentials) *sender.SenderConfig {
	c := sender.DefaultSenderConfig()
	c.PlatformAuth = creds
	return c
}

// The panel's "these rules are configured" claim covers the proxy leg as well as the sender, and the
// two are separate answers because a Server can be assembled with one and not the other. Before
// burpsy-react-ui-trcy the proxy never carried the store at all, so an operator's rules were stored,
// the panel said so, and their browser's traffic went out unauthenticated.
func TestThePanelReportsWhetherTheProxyLegCarriesTheCredentials(t *testing.T) {
	store := core.NewTrafficStore()
	creds := netauth.NewCredentials()
	rule, err := netauth.NewCredential("intranet.example.com", netauth.SchemeBasic, "operator", "pw", "")
	if err != nil {
		t.Fatal(err)
	}
	creds.Add(rule)

	// Both legs wired: the honest "configured" state.
	both := networkServer().
		WithNetAuth(creds, netauth.NewClientCerts()).
		WithSender(sender.NewSender(senderWithAuth(creds))).
		WithProxyServer(proxy.NewServer(proxy.NewProxyConfig(store).WithPlatformAuth(creds)))
	rec := call(t, both, http.MethodGet, "/api/network/auth", "")
	var view struct {
		Rules             []netauth.CredentialView `json:"rules"`
		PresentedOnEgress bool                     `json:"presented_on_egress"`
		PresentedOnProxy  bool                     `json:"presented_on_proxy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Rules) != 1 {
		t.Fatalf("rules = %d, want 1: the panel would show an empty list while the store holds one", len(view.Rules))
	}
	if !view.PresentedOnEgress {
		t.Error("presented_on_egress is false while the sender carries the store")
	}
	if !view.PresentedOnProxy {
		t.Error("presented_on_proxy is false while the proxy carries the store: the panel would claim the rules are not presented for browser traffic when they are (burpsy-react-ui-trcy)")
	}

	// The pre-fix shape: a store with rules, and a proxy that never received it. This is the state
	// the bead found, and the flag has to say so rather than reporting the sender's truth for both.
	proxyOnly := networkServer().
		WithNetAuth(creds, netauth.NewClientCerts()).
		WithSender(sender.NewSender(senderWithAuth(creds))).
		WithProxyServer(proxy.NewServer(proxy.NewProxyConfig(store)))
	rec = call(t, proxyOnly, http.MethodGet, "/api/network/auth", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.PresentedOnEgress {
		t.Error("presented_on_egress is false; the sender does carry the store")
	}
	if view.PresentedOnProxy {
		t.Error("presented_on_proxy is true for a proxy that was never given the store: a flag that reports the sender's state for the proxy's is exactly the overclaim trcy records")
	}
}
