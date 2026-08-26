// Platform authentication and client TLS certificates: the /api/network/auth and
// /api/network/client-certs surfaces.
//
// Split from api_network.go rather than appended to it. Both files landed as api_network.go in
// parallel branches, and merging them into one would have put the settings patcher and the
// credential store in a file whose name announces neither. This package is one api_*.go per feature
// area; secrets handling in particular deserves a file a reader can find by name.

package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/netauth"
)

// Settings → Network: platform authentication and client TLS certificates.
//
// # The one rule this file exists to keep
//
// No secret comes back out. Not in a GET, not in the reply to the POST that set it, not
// in a log line, not in an error message. The rule is enforced structurally rather than
// by care at each call site: netauth.Credential and netauth.ClientCert keep their
// secrets in unexported fields, so `encoding/json` cannot reach them, and the wire
// shapes these handlers serialise (netauth.CredentialView, netauth.ClientCertView) have
// no secret field for one to land in. A handler added later to this file inherits the
// guarantee without knowing about it.
//
// What the views do carry is whether a secret is *set* — has_password, has_passphrase.
// That is the honest-counting requirement, not a leak: a panel that showed a blank
// password field would read as "no credential configured" for a rule that is in fact
// live, and an operator would go looking for the wrong problem. Presence is reported;
// length never is, because a length is a brute-force hint.
//
// # Configuration export
//
// The brief for this work asked that these never appear in GET /api/config/export.
// **This build has no such route** — grep the tree: there is no /api/config/export and
// no bundle handler for scope, intercept and session rules to be exported as one. So
// there is nothing to exclude them from, and nothing was added to pretend otherwise.
// The decision that matters for whoever builds that route later is recorded here: an
// export bundle must be assembled from the redacted views above, never from
// Credentials.Secrets()/ClientCerts.Secrets(), which exist for internal/persist alone.
// Building it from the views makes the export structurally incapable of carrying a
// password, which is the same guarantee this file relies on rather than a second rule
// to remember.

// ---- wire shapes --------------------------------------------------------------------

// platformAuthResponse is GET /api/network/auth.
type platformAuthResponse struct {
	// Rules are in match order, which is semantic: netauth.Credentials is
	// first-match-wins, so the order the panel shows is the order that decides.
	Rules []netauth.CredentialView `json:"rules"`
	// Empty distinguishes "no rules configured" from "the request failed" for a caller
	// that only sees a JSON body. An empty array alone cannot say which.
	Empty bool `json:"empty"`
	// Schemes is what a selector may offer, read from the engine rather than hard-coded
	// in the browser, so a scheme cannot appear in the panel without being implemented.
	Schemes []string `json:"schemes"`
	// Unsupported names the schemes Burp has and this build does not, so the panel can
	// say so out loud. An operator told "NTLM is not supported" has an answer; one who
	// finds no NTLM option does not know whether they are looking in the wrong place.
	Unsupported []string `json:"unsupported"`
	// PresentedOnEgress reports whether the sender these rules are supposed to reach was
	// actually built with the credential store attached. See sender.CarriesPlatformAuth:
	// this can be false in a Server assembled without it, and a rule that is stored but
	// never presented must not look configured.
	PresentedOnEgress bool `json:"presented_on_egress"`
}

// clientCertsResponse is GET /api/network/client-certs.
type clientCertsResponse struct {
	Bindings []netauth.ClientCertView `json:"bindings"`
	Empty    bool                     `json:"empty"`
	// RestoreFailures is one line per persisted binding that could not be rebuilt at
	// startup — a PKCS#12 file deleted between sessions, a passphrase that no longer
	// opens it. Reported rather than dropped: the binding was on the operator's panel
	// yesterday, and silently losing it would make the panel claim an identity is bound
	// when no handshake will carry it.
	RestoreFailures []string `json:"restore_failures"`
	// PKCS11Supported is always false and is stated rather than omitted. Burp offers a
	// hardware-token source; this build does not implement one, and a panel that simply
	// lacks the option leaves the operator guessing. See netauth/clientcert.go for why
	// it is out of scope rather than stubbed.
	PKCS11Supported bool `json:"pkcs11_supported"`
	// PresentedOnEgress mirrors platformAuthResponse's field for the certificate source.
	// The proxy's upstream leg is wired separately (proxy.ProxyConfig.WithClientCerts)
	// and is not observable from here, so this speaks only for the sender.
	PresentedOnEgress bool `json:"presented_on_egress"`
}

// ---- platform authentication --------------------------------------------------------

// handleNetworkAuth serves the platform-authentication rule list.
//
// GET lists the rules, redacted. POST adds or replaces one. DELETE removes the rule with
// exactly the host pattern and scheme named in the query, and answers 404 when there is
// none — the same exact-match removal the scope list uses, and for the same reason: a
// pattern that is not there must be reported as absent, or a double-click on remove
// looks like two rules had existed.
func (s *Server) handleNetworkAuth(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getNetworkAuth(w, r)
	case http.MethodPost:
		s.postNetworkAuth(w, r)
	case http.MethodDelete:
		s.deleteNetworkAuth(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getNetworkAuth(w http.ResponseWriter, _ *http.Request) {
	rules := s.platformAuthStore().View()
	schemes := make([]string, 0, len(netauth.SupportedSchemes()))
	for _, scheme := range netauth.SupportedSchemes() {
		schemes = append(schemes, string(scheme))
	}
	writeJSON(w, http.StatusOK, platformAuthResponse{
		Rules:             rules,
		Empty:             len(rules) == 0,
		Schemes:           schemes,
		Unsupported:       netauth.UnsupportedSchemes(),
		PresentedOnEgress: s.sender != nil && s.sender.CarriesPlatformAuth(),
	})
}

func (s *Server) postNetworkAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host     string `json:"host"`
		Scheme   string `json:"scheme"`
		Username string `json:"username"`
		Password string `json:"password"`
		Realm    string `json:"realm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Refuse-by-default on the scheme, and the engine's error text is passed through
	// verbatim: it names NTLM and Negotiate as unsupported-by-this-build rather than as
	// typos, which is the difference between an answer and a dead end. An unrecognised
	// scheme is never coerced to Basic — that would put the operator's password in a
	// header the target never asked for, which is a disclosure and not a mere
	// misconfiguration.
	scheme, err := netauth.ParseScheme(req.Scheme)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rule, err := netauth.NewCredential(req.Host, scheme, req.Username, req.Password, req.Realm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	replaced := s.platformAuthStore().Add(rule)
	s.persistPlatformAuth()
	// The reply is the redacted view of what was stored — deliberately a round trip
	// rather than an echo of the request, so the response cannot carry back the password
	// the request brought in, and so the operator sees the rule as the engine actually
	// holds it (host trimmed, scheme canonicalised).
	writeJSON(w, http.StatusOK, struct {
		Rule     netauth.CredentialView `json:"rule"`
		Replaced bool                   `json:"replaced"`
	}{Rule: s.credentialView(rule.Host, scheme), Replaced: replaced})
}

func (s *Server) deleteNetworkAuth(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		http.Error(w, "A host pattern is required", http.StatusBadRequest)
		return
	}
	// The scheme is part of the identity, not a filter: (host, scheme) is what
	// netauth.Credentials keys on, so removing basic@example.com must not take
	// digest@example.com with it. Parsed rather than compared as a string so that
	// ?scheme=NTLM answers with the unsupported-scheme explanation instead of a 404 that
	// would read as "no such rule".
	scheme, err := netauth.ParseScheme(r.URL.Query().Get("scheme"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.platformAuthStore().Remove(host, scheme) {
		http.Error(w, "No platform-authentication rule with that host pattern and scheme", http.StatusNotFound)
		return
	}
	s.persistPlatformAuth()
	w.WriteHeader(http.StatusOK)
}

// credentialView finds the stored rule's redacted view by its identity.
//
// The view is read back out of the store rather than built from the Credential the
// handler happens to hold, so the reply describes what is live. Falls back to the
// in-hand rule's key if the store no longer has it — a concurrent DELETE between the Add
// and this read — and reports has_password false in that case, because there is then no
// stored password to report on.
func (s *Server) credentialView(host string, scheme netauth.Scheme) netauth.CredentialView {
	for _, view := range s.platformAuthStore().View() {
		if view.Host == host && view.Scheme == string(scheme) {
			return view
		}
	}
	return netauth.CredentialView{Host: host, Scheme: string(scheme)}
}

// ---- client TLS certificates --------------------------------------------------------

// handleNetworkClientCerts serves the client-certificate binding list.
//
// POST loads the PKCS#12 file there and then, which is the point: a bad passphrase or an
// unreadable file is reported while the operator is still looking at the form they typed
// it into, rather than surfacing three tabs away as a handshake the server rejected.
func (s *Server) handleNetworkClientCerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getNetworkClientCerts(w, r)
	case http.MethodPost:
		s.postNetworkClientCerts(w, r)
	case http.MethodDelete:
		s.deleteNetworkClientCerts(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getNetworkClientCerts(w http.ResponseWriter, _ *http.Request) {
	bindings := s.clientCertStore().View()
	// A nil slice would marshal as `null`, which the browser then has to special-case
	// before it can count it. Every list this API serves is an array.
	failures := s.netAuthRestoreNotes
	if failures == nil {
		failures = []string{}
	}
	writeJSON(w, http.StatusOK, clientCertsResponse{
		Bindings:          bindings,
		Empty:             len(bindings) == 0,
		RestoreFailures:   failures,
		PKCS11Supported:   false,
		PresentedOnEgress: s.sender != nil && s.sender.CarriesClientCerts(),
	})
}

func (s *Server) postNetworkClientCerts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host       string `json:"host"`
		Path       string `json:"path"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	entry, err := netauth.LoadClientCert(req.Host, req.Path, req.Passphrase)
	if err != nil {
		// LoadClientCert's errors name which of four things to change — a missing file, a
		// rejected passphrase, a file that is not PKCS#12, a PKCS#12 with no key pair — and
		// none of them contains the passphrase itself. Passed through so the operator gets
		// the actionable one rather than "could not load certificate".
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	replaced := s.clientCertStore().Add(entry)
	s.persistClientCerts()
	writeJSON(w, http.StatusOK, struct {
		Binding  netauth.ClientCertView `json:"binding"`
		Replaced bool                   `json:"replaced"`
	}{Binding: s.clientCertViewFor(entry.Host), Replaced: replaced})
}

func (s *Server) deleteNetworkClientCerts(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		http.Error(w, "A host pattern is required", http.StatusBadRequest)
		return
	}
	if !s.clientCertStore().Remove(host) {
		http.Error(w, "No client-certificate binding with that host pattern", http.StatusNotFound)
		return
	}
	s.persistClientCerts()
	w.WriteHeader(http.StatusOK)
}

// clientCertViewFor reads one binding's redacted view back out of the store. See
// credentialView for why the reply is a read-back rather than an echo.
func (s *Server) clientCertViewFor(host string) netauth.ClientCertView {
	for _, view := range s.clientCertStore().View() {
		if view.Host == host {
			return view
		}
	}
	return netauth.ClientCertView{Host: host}
}
