// Platform authentication and client TLS certificates: the /api/network/auth and
// /api/network/client-certs surfaces.
//
// Split from api_network.go rather than appended to it. Both files landed as api_network.go in
// parallel branches, and merging them into one would have put the settings patcher and the
// credential store in a file whose name announces neither. This package is one api_*.go per feature
// area; secrets handling in particular deserves a file a reader can find by name.

package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
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
	//
	// It covers the sender alone, not the proxy leg. The proxy carries the same store
	// (burpsy-react-ui-trcy wired it), but a Server can be assembled with one and not the
	// other, and a flag that claimed to cover both would be reporting the sender's state for
	// the proxy's. PresentedOnProxy is that second answer; an operator reading "configured"
	// in the panel needs both to be true before the claim is honest.
	PresentedOnEgress bool `json:"presented_on_egress"`
	// PresentedOnProxy reports whether the proxy leg was built with the credential store
	// attached, so browser traffic through the listener presents these rules. See
	// proxy.ProxyConfig.CarriesPlatformAuth.
	PresentedOnProxy bool `json:"presented_on_proxy"`
	// PromptOnFailure is Burp's "Prompt for credentials on platform authentication failure"
	// (burpsy-react-ui-3xnt), under Burp's key name. Off by default, as in Burp.
	PromptOnFailure bool `json:"prompt_on_authentication_failure"`
	// Warnings are the weak-authentication handshakes performed — every NTLMv1 one, which a rule
	// opted into (burpsy-react-ui-sel6) — most recent first. Served here, where the rule is
	// configured, and with the failures, where platform-authentication trouble is surfaced.
	Warnings []netauth.AuthWarning `json:"warnings"`
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
	case http.MethodPut:
		s.putNetworkAuthPrompt(w, r)
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
		// A nil proxy is a Server assembled without one — a test harness, or an embedder that
		// only wants the web surface — and that is not a failure, so it reads false rather than
		// being reported as a misconfiguration.
		PresentedOnProxy: s.proxyServer != nil && s.proxyServer.CarriesPlatformAuth(),
		PromptOnFailure:  s.platformAuthStore().PromptOnFailure(),
		Warnings:         s.platformAuthStore().Warnings(),
	})
}

// putNetworkAuthPromptReq is the request body putNetworkAuthPrompt decodes (named for its published schema).
type putNetworkAuthPromptReq struct {
	PromptOnFailure *bool `json:"prompt_on_authentication_failure"`
}

// putNetworkAuthPrompt sets Burp's "Prompt for credentials on platform authentication failure".
// The body is that one key; anything else is refused by name.
func (s *Server) putNetworkAuthPrompt(w http.ResponseWriter, r *http.Request) {
	var req putNetworkAuthPromptReq
	// Strict for every caller, not only an agent: the body is one key, and a misspelled one would
	// otherwise decode to "no value" and be refused for the wrong reason.
	dec := requestJSON(w, r, nil)
	dec.dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.PromptOnFailure == nil {
		http.Error(w, "PUT takes {\"prompt_on_authentication_failure\": true|false}; rules are added with POST", http.StatusBadRequest)
		return
	}
	s.platformAuthStore().SetPromptOnFailure(*req.PromptOnFailure)
	if s.persist != nil {
		s.persist.SavePlatformAuthPrompt(*req.PromptOnFailure)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"prompt_on_authentication_failure": *req.PromptOnFailure})
}

// handleNetworkAuthFailures serves GET/DELETE /api/network/auth/failures: the platform-authentication
// failures recorded while the prompt is on, most recent first, and the dismissal of one by host.
func (s *Server) handleNetworkAuthFailures(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		store := s.platformAuthStore()
		writeJSON(w, http.StatusOK, struct {
			PromptOnFailure bool                  `json:"prompt_on_authentication_failure"`
			Failures        []netauth.AuthFailure `json:"failures"`
			// Warnings are recorded whatever the prompt setting: see netauth.AuthWarning.
			Warnings []netauth.AuthWarning `json:"warnings"`
		}{PromptOnFailure: store.PromptOnFailure(), Failures: store.Failures(), Warnings: store.Warnings()})
	case http.MethodDelete:
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "A host is required", http.StatusBadRequest)
			return
		}
		if !s.platformAuthStore().DismissFailure(host) {
			http.Error(w, "No platform-authentication failure is recorded for that host", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// postNetworkAuthReq is the request body postNetworkAuth decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type postNetworkAuthReq struct {
	Host     string `json:"host"`
	Scheme   string `json:"scheme"`
	Username string `json:"username"`
	Password string `json:"password"`
	Realm    string `json:"realm"`
}

func (s *Server) postNetworkAuth(w http.ResponseWriter, r *http.Request) {
	var req postNetworkAuthReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Refuse-by-default on the scheme, and the engine's error text is passed through
	// verbatim: it names Kerberos as unsupported-by-this-build, and says which rule answers
	// Negotiate, rather than reading as a typo — the difference between an answer and a dead end. An unrecognised
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
	failures := s.netAuthNotes()
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

// postNetworkClientCertsReq is the request body postNetworkClientCerts decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type postNetworkClientCertsReq struct {
	Host       string `json:"host"`
	Path       string `json:"path"`
	Passphrase string `json:"passphrase"`
}

func (s *Server) postNetworkClientCerts(w http.ResponseWriter, r *http.Request) {
	var req postNetworkClientCertsReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
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

// ---- project restore ----------------------------------------------------------------

// RestoreNetworkAuth rebuilds the Settings → Network stores from the durable mirror,
// returning them plus one note per row it could not rebuild.
//
// # Why a partial restore is the right answer, and why it must be reported
//
// Nothing here is fatal. A platform-authentication row written by a build that had a
// scheme this one does not is dropped rather than coerced — coercing it to Basic would
// send the operator's password to a host under a scheme they never chose — and a
// client-certificate binding whose PKCS#12 file was deleted between sessions cannot be
// rebuilt at all. Refusing to start over either would take the whole engagement down for
// one stale row.
//
// But dropping them silently is the failure this codebase treats as a bug: the binding
// was on the operator's panel yesterday, and a panel that lists it while no handshake
// carries it is a partial result looking complete. So each failure comes back as a line
// the panel shows, *and* goes to the log. Two sinks because the two readers are different
// people at different times: the log is for afterwards, the panel is for the person who
// can still fix it.
//
// A nil store — no -db — restores nothing and reports nothing, which is not a failure but
// an empty first run.
//
// Exported, and in this package rather than cmd/burpsy where it started, because it has two
// callers: startup, which builds the stores before the sender exists so the sender can be
// constructed carrying them, and an in-console project switch (restoreNetAuth), which rebuilds
// them from the incoming project's file. One function, so the two cannot disagree about what a
// project's network authentication is (burpsy-react-ui-oava).
func RestoreNetworkAuth(store *persist.Store, logger *zap.Logger) (*netauth.Credentials, *netauth.ClientCerts, []string) {
	credentials := netauth.NewCredentials()
	certs := netauth.NewClientCerts()
	if store == nil {
		return credentials, certs, nil
	}

	var notes []string
	record := func(err error) {
		notes = append(notes, err.Error())
		logger.Warn("network authentication row could not be restored", zap.Error(err))
	}

	if rows, err := store.LoadPlatformAuth(); err != nil {
		// A failed read of the whole table is one note, not none: the alternative is a panel
		// that shows an empty rule list for a database that has rules in it.
		record(fmt.Errorf("reading stored platform-authentication rules: %w", err))
	} else {
		restored, failures := netauth.RestoreCredentials(rows)
		credentials = restored
		for _, failure := range failures {
			record(failure)
		}
	}

	// Burp's "Prompt for credentials on platform authentication failure" (3xnt) survives a restart
	// whether or not the rules themselves could be read.
	credentials.SetPromptOnFailure(store.LoadPlatformAuthPrompt())

	if rows, err := store.LoadClientCerts(); err != nil {
		record(fmt.Errorf("reading stored client-certificate bindings: %w", err))
	} else {
		restored, failures := netauth.RestoreClientCerts(rows)
		certs = restored
		for _, failure := range failures {
			record(failure)
		}
	}
	return credentials, certs, notes
}

// restoreNetAuth REPLACES the platform-authentication rules and client-certificate bindings with
// the project's own, on an in-console project switch (burpsy-react-ui-oava).
//
// The recorded-login library has been replaced on a switch since xhtk; these two stores were not,
// so project A's passwords and client identity stayed on the panel, stayed on the wire — the sender
// and the proxy present them from the same pointers — and were written into project B's file by the
// next save, since persistPlatformAuth and persistClientCerts mirror the whole list. Replace, not
// merge, for the reason restoreRecordedLogins gives.
//
// Three things are reset, and each is a place the outgoing identity would otherwise survive:
//   - the stores' contents, in place (netauth's ReplaceWith), because the sender and the proxy hold
//     the pointers and a swapped-in store would reach the panel and nothing else;
//   - what the platform-auth store learned under the old rules — Digest nonces, NTLM handshake
//     state, recorded failures — which ReplaceWith drops with the rules;
//   - the connections kept open for reuse, which completed their TLS handshake presenting the old
//     client certificate and would carry the next send under it (Sender.DropKeptConnections, and
//     Repeater's HTTP/2 session pool).
//
// What is NOT reset: a connection already in flight, and a browser tunnel the proxy is relaying
// right now. Both finish on the handshake they made; the next dial presents the new bindings.
//
// Startup does not come through here: cmd/burpsy calls RestoreNetworkAuth before the sender is
// built, so the sender can be constructed carrying the stores, and WithNetAuth attaches them.
func (s *Server) restoreNetAuth(p *persist.Store) {
	credentials, certs, notes := RestoreNetworkAuth(p, s.logger)
	s.platformAuthStore().ReplaceWith(credentials)
	s.clientCertStore().ReplaceWith(certs)
	s.netAuthNotesMu.Lock()
	s.netAuthRestoreNotes = notes
	s.netAuthNotesMu.Unlock()
	s.sender.DropKeptConnections()
	s.repeaterH2Sessions().Close()
}

// netAuthNotes is the restore-failure list the client-certificate GET reports. Read under a lock
// because a project switch rewrites it while the panel may be reading it.
func (s *Server) netAuthNotes() []string {
	s.netAuthNotesMu.Lock()
	defer s.netAuthNotesMu.Unlock()
	return s.netAuthRestoreNotes
}
