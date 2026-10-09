// Package netauth holds the credentials burpsy presents when a target demands them:
// HTTP platform authentication (Burp's Settings → Network → Platform authentication)
// and TLS client certificates (Settings → Network → Client TLS certificates).
//
// # Why one package for two panels
//
// Burp keeps these on two panels, and they are genuinely different protocols — one
// is a request header, the other a handshake message. They live together here
// because they share the three properties that actually shape the code: both are
// keyed by a host pattern, both are matched first-rule-wins against an outbound
// authority, and both hold an operator secret that must never come back out over
// the API. That last property is the reason this package exists at all instead of
// the fields hanging off the sender: a secret is easiest to keep when exactly one
// package can read it.
//
// # The secret rule, and why it is structural
//
// Every secret here lives in an **unexported** field. `encoding/json` cannot reach
// an unexported field, so a handler that forgets to redact still cannot leak one:
// the guarantee is a property of the type rather than a convention someone has to
// remember at each of three call sites. The redacted wire shapes (CredentialView,
// ClientCertView) have no secret field at all, so there is nowhere for a leak to
// land even by accident. `secretsNeverSerialise_test.go` pins both halves by
// marshalling a populated store and asserting the plaintext is absent from the
// bytes — a test that fails if anyone adds an exported secret later.
//
// This is deliberately stronger than "the handler redacts". A redacting handler is
// correct until someone adds a second handler.
//
// # Host matching mirrors the passthrough list on purpose
//
// matchHost implements exactly the semantics of internal/proxy's matchPattern: `*`
// matches everything, `*.example.com` matches `example.com` and any subdomain, and
// anything else is an exact hostname. An operator who has learnt the TLS
// passthrough list's pattern language should not have to learn a second one for
// credentials, so the rule is copied rather than improved. It is copied rather
// than imported because proxy.matchPattern is unexported and internal/proxy sits
// above this package in the dependency spine — importing it would invert the
// direction. hostPatternsAgreeWithTheProxy_test.go pins the two against each other
// so the copy cannot drift.
package netauth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// matchHost reports whether host is covered by pattern.
//
// Mirrors internal/proxy.matchPattern exactly — see the package doc for why this is
// a copy and not a call.
func matchHost(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	return pattern == host
}

// Scheme is an HTTP authentication scheme burpsy can present a credential under.
//
// # What is here, and what is not
//
// Burp offers five schemes: Basic, Digest, NTLMv1, NTLMv2 and Negotiate. This type has three:
// Basic, Digest and NTLMv2. NTLMv1 and Negotiate are **not supported**, and the reason they are
// absent from the type rather than present-and-erroring is that a scheme selector containing an
// option that does nothing is worse than a selector without it: the operator configures the
// credential, the tool reports success, and the requests go out unauthenticated with nothing
// anywhere saying so. ParseScheme refuses both by name; ntlm.go's package comment gives the reasons
// (NTLMv1 is DES under the NT hash with no client entropy; Negotiate needs a Kerberos credential).
//
// # NTLM is connection-bound
//
// NTLM is a three-leg handshake (Negotiate → Challenge → Authenticate) whose state is bound to one
// TCP connection, and a verified connection stays authenticated for the requests that follow on it.
// The typed sender drives it as such (burpsy-react-ui-sel6): BeginConnectionAuth hands it an
// NTLMExchange, and internal/sender runs the legs on one dedicated HTTP/1.1 connection that it
// verifies and then discards (internal/sender/connauth.go). The host-keyed Authorization/Learn
// branch for NTLM below remains for the proxy leg only, which relays a browser's own connection and
// is not connection-bound — gaps.md records that.
type Scheme string

const (
	// SchemeBasic sends RFC 7617 credentials preemptively, on the first request.
	SchemeBasic Scheme = "basic"
	// SchemeDigest answers an RFC 7616 challenge; see digest.go.
	SchemeDigest Scheme = "digest"
	// SchemeNTLMv2 answers an NTLMSSP CHALLENGE_MESSAGE with the MS-NLMP response
	// algorithm (burpsy-react-ui-noz5). The codec is ntlm.go (buildNegotiate /
	// parseChallenge / buildAuthenticate).
	//
	// On the sender the three legs are one NTLMExchange on one connection (BeginConnectionAuth,
	// burpsy-react-ui-sel6). The proxy leg still uses the host-keyed Authorization/Learn
	// branch — NEGOTIATE preemptively, the CHALLENGE learned per host — which is only correct
	// for a server that does not bind its challenge to the connection; see gaps.md.
	SchemeNTLMv2 Scheme = "ntlmv2"
)

// SupportedSchemes is what a selector may offer, in display order. The UI reads this
// through the API rather than hard-coding a list, so a scheme cannot appear in the
// panel without existing here.
func SupportedSchemes() []Scheme { return []Scheme{SchemeBasic, SchemeDigest, SchemeNTLMv2} }

// UnsupportedSchemes names the schemes Burp has and this does not, so the panel can
// say so out loud instead of leaving an operator to infer it from an absence. Being
// told "NTLM is not supported" is a usable answer; finding no NTLM option and not
// knowing whether you are looking in the wrong place is not.
func UnsupportedSchemes() []string { return []string{"NTLMv1", "Negotiate"} }

// ParseScheme resolves a wire string, refusing anything it does not implement.
//
// Refuse-by-default: an unrecognised scheme is an error, never a silent fallback to
// Basic. Falling back would send the operator's password in a header the target
// never asked for, which is a credential disclosure rather than a mere
// misconfiguration. The error names the unsupported Burp schemes explicitly when one
// is asked for, because "ntlm is not a known scheme" reads like a typo while "NTLM
// is not supported by this build" is the actual answer.
func ParseScheme(raw string) (Scheme, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "basic":
		return SchemeBasic, nil
	case "digest":
		return SchemeDigest, nil
	case "ntlmv2":
		return SchemeNTLMv2, nil
	case "":
		return "", errors.New("a platform-authentication rule needs a scheme: basic, digest or ntlmv2")
	case "ntlm", "ntlmv1", "negotiate", "kerberos":
		return "", fmt.Errorf("%s is not supported by this build; only basic, digest and ntlmv2 are implemented "+
			"(NTLMv1 is DES-only, and Negotiate needs a Kerberos "+
			"credential rather than a password)", strings.TrimSpace(raw))
	default:
		return "", fmt.Errorf("unknown authentication scheme %q: this build implements basic, digest and ntlmv2", strings.TrimSpace(raw))
	}
}

// Credential is one platform-authentication rule: a host pattern, a scheme, and the
// secret to present under it.
//
// password is unexported, which is the whole design — see the package doc. The
// getters that read it are Basic/Digest header construction inside this package and
// nothing else; there is no exported accessor, so the web package physically cannot
// put it on the wire.
type Credential struct {
	// Host is a pattern in matchHost's language.
	Host   string
	Scheme Scheme
	// Username travels in the Authorization header in both supported schemes, so it
	// is not a secret and the redacted view shows it. An operator needs to see which
	// account a rule uses to know whether the rule is the one failing.
	Username string
	// Realm, when set, restricts a Digest rule to one realm. Empty means any realm the
	// host challenges with. Ignored for Basic, which has no challenge to read a realm
	// from when sent preemptively.
	Realm string

	password string
}

// NewCredential validates and builds a rule.
//
// A blank host or username is refused rather than stored: a rule matching no host,
// or naming no account, is not a working credential, and accepting it would put a
// row in the panel that can never authenticate anything. An empty password is
// allowed — some appliances genuinely use one, and refusing it would be this code
// inventing a policy the HTTP specs do not have.
func NewCredential(host string, scheme Scheme, username, password, realm string) (Credential, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return Credential{}, errors.New("a platform-authentication rule needs a host pattern, for example example.com or *.example.com")
	}
	if strings.TrimSpace(username) == "" {
		return Credential{}, errors.New("a platform-authentication rule needs a username")
	}
	if scheme != SchemeBasic && scheme != SchemeDigest && scheme != SchemeNTLMv2 {
		return Credential{}, fmt.Errorf("unsupported scheme %q", string(scheme))
	}
	return Credential{
		Host:     host,
		Scheme:   scheme,
		Username: strings.TrimSpace(username),
		Realm:    strings.TrimSpace(realm),
		password: password,
	}, nil
}

// CredentialView is the redacted wire shape. There is no password field, and that is
// the point: GET /api/network/auth cannot disclose a secret it has no room for.
type CredentialView struct {
	Host     string `json:"host"`
	Scheme   string `json:"scheme"`
	Username string `json:"username"`
	Realm    string `json:"realm,omitempty"`
	// HasPassword distinguishes "a password is stored" from "the password is empty",
	// which the honest-counting rule requires: a blank field on the panel would read
	// as "no credential configured" for a rule that is in fact live. It reports
	// whether one is set, never its length — a length is a brute-force hint.
	HasPassword bool `json:"has_password"`
}

// view renders one rule with the secret dropped.
func (c Credential) view() CredentialView {
	return CredentialView{
		Host:        c.Host,
		Scheme:      string(c.Scheme),
		Username:    c.Username,
		Realm:       c.Realm,
		HasPassword: c.password != "",
	}
}

// Credentials is the ordered platform-authentication rule list.
//
// # Order is first-match-wins, and the order is the operator's
//
// Rules are matched in insertion order and the first host match is used, matching
// Burp. Longest-pattern-wins would be a defensible alternative and is deliberately
// not what happens: with an explicit list, "the first rule that matches" is a rule
// the operator can read off the panel, whereas a specificity ranking is one they
// have to reconstruct. A `*` rule placed first therefore shadows everything after
// it, which is visible on the panel rather than surprising.
//
// # (host, scheme) is unique
//
// Add replaces any existing rule with the same host pattern and scheme rather than
// appending a second one. Two rules with the same key could never both be reached —
// first-match-wins means the second is dead — and allowing them would make DELETE
// ambiguous about which one it removed. Replacement keeps the list a set of
// reachable rules, which is what the panel claims to be showing.
type Credentials struct {
	mu    sync.RWMutex
	rules []Credential
	// challenges caches the last Digest challenge seen per host, so a second request
	// to an already-challenged host can authenticate on its first attempt instead of
	// spending another 401. Keyed by host, not by pattern: a challenge is a fact about
	// one server, while a pattern is a statement about many.
	challenges map[string]*digestState
	// ntlm caches one host's NTLMv2 handshake state, the same shape and the same keying
	// as the Digest cache: the NEGOTIATE message this build sent and the CHALLENGE_MESSAGE
	// the server answered, kept as raw bytes because the MIC covers exactly those two legs.
	// State lives here rather than in a socket, so a learned challenge reaches the next
	// request whatever connection carries it.
	ntlm map[string]*ntlmSession
	// prompt and failures are Burp's "Prompt for credentials on platform authentication failure"
	// (prompt.go): whether failures are recorded, and the recorded ones keyed by lower-cased host.
	prompt   bool
	failures map[string]*AuthFailure
}

// NewCredentials returns an empty rule list.
func NewCredentials() *Credentials {
	return &Credentials{challenges: map[string]*digestState{}, ntlm: map[string]*ntlmSession{}}
}

// Add appends a rule, or replaces the one with the same (host, scheme) key.
//
// Returns whether it replaced rather than appended, so the API can report which
// happened. An operator who re-adds a host to fix a typo in the password wants to
// see "updated", not a second identical row.
func (c *Credentials) Add(rule Credential) (replaced bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.rules {
		if c.rules[i].Host == rule.Host && c.rules[i].Scheme == rule.Scheme {
			c.rules[i] = rule
			// A changed password invalidates any cached challenge for hosts this rule
			// covers: replaying a stale nonce with a new secret fails, and the failure
			// would look like the new password being wrong.
			c.forgetMatching(rule.Host)
			c.clearFailuresMatchingLocked(rule.Host)
			return true
		}
	}
	c.rules = append(c.rules, rule)
	c.forgetMatching(rule.Host)
	c.clearFailuresMatchingLocked(rule.Host)
	return false
}

// Remove drops the rule with exactly this host pattern and scheme.
//
// Exact-match by design, like the passthrough list's removal: a pattern that is not
// in the list must be reported as absent rather than quietly succeeding, or a
// double-click on remove would look like two rules had existed. The API turns a
// false return into 404.
func (c *Credentials) Remove(host string, scheme Scheme) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.rules {
		if c.rules[i].Host == host && c.rules[i].Scheme == scheme {
			c.rules = append(c.rules[:i], c.rules[i+1:]...)
			c.forgetMatching(host)
			return true
		}
	}
	return false
}

// ReplaceWith makes c hold exactly src's rules and prompt setting, and forgets everything c
// learned under the rules it held before: the cached Digest challenges, the NTLMv2 handshake
// state, and the recorded authentication failures.
//
// In place, not a pointer swap, because the pointer is shared: cmd/burpsy hands the same
// *Credentials to the web API, the sender and the proxy, and the sender's half is fixed at
// construction (see sender.CarriesPlatformAuth). A project switch that built a fresh store and
// pointed the API at it would leave the sender and proxy presenting the outgoing project's
// passwords while the panel showed the incoming one's (burpsy-react-ui-oava).
//
// The learned state goes with the rules because it is the outgoing engagement's: a Digest
// nonce or an NTLM challenge answered under project A's password is not something project B's
// requests may ride, and a failure recorded against A's rule would prompt B's operator about a
// credential B never configured. src is only read; nil empties c.
func (c *Credentials) ReplaceWith(src *Credentials) {
	if src == c {
		return
	}
	var rules []Credential
	prompt := false
	if src != nil {
		src.mu.RLock()
		rules = append([]Credential(nil), src.rules...)
		prompt = src.prompt
		src.mu.RUnlock()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules = rules
	c.prompt = prompt
	c.challenges = map[string]*digestState{}
	c.ntlm = map[string]*ntlmSession{}
	c.failures = nil
}

// Match returns the first rule covering host.
//
// Host only, no port: Burp's platform-authentication entry is keyed by destination
// host, and HTTP authentication is scoped by realm within an origin rather than by
// port. Adding a port arm would be a divergence from both, for a distinction no
// operator has asked this panel to make.
func (c *Credentials) Match(host string) (Credential, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, rule := range c.rules {
		if matchHost(rule.Host, host) {
			return rule, true
		}
	}
	return Credential{}, false
}

// View renders every rule, redacted, in match order. Order is preserved because it
// is semantic here — see the type doc.
func (c *Credentials) View() []CredentialView {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]CredentialView, 0, len(c.rules))
	for _, rule := range c.rules {
		out = append(out, rule.view())
	}
	return out
}

// Len reports how many rules are configured, for callers that need the count without
// building the view.
func (c *Credentials) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.rules)
}

// CredentialRow is one platform-authentication rule with its secret exposed, as
// internal/persist stores it.
//
// A named type rather than the Credential itself, because Credential's whole point is
// that its password is unreachable. Widening Credential would defeat that for every
// caller in order to serve one; a separate row type keeps the hole exactly one type
// wide and makes every use of it greppable.
type CredentialRow struct {
	Host     string
	Scheme   string
	Username string
	Password string
	Realm    string
}

// Secrets exposes the rules with their passwords, for the one caller that must write
// them to durable storage.
//
// This is the single deliberate hole in the package's "no secret leaves here" rule.
// It returns plaintext because internal/persist has to store something it can hand
// back at startup; there is no key-management story in this tool to encrypt it under,
// and inventing a local obfuscation would buy nothing but the appearance of
// protection. The real consequence — the SQLite mirror is secret-bearing and should
// be treated as such — belongs in the operator's threat model, stated plainly, rather
// than hidden behind a reversible encoding that suggests otherwise.
func (c *Credentials) Secrets() []CredentialRow {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]CredentialRow, 0, len(c.rules))
	for _, rule := range c.rules {
		out = append(out, CredentialRow{
			Host:     rule.Host,
			Scheme:   string(rule.Scheme),
			Username: rule.Username,
			Password: rule.password,
			Realm:    rule.Realm,
		})
	}
	return out
}

// ClientCert is one PKCS#12 identity bound to a host pattern.
//
// The parsed tls.Certificate is held rather than the file bytes: a handshake needs a
// signer, and re-reading and re-decrypting the file per dial would put a passphrase
// derivation on the connection path. path and passphrase are kept only so the
// identity can be rebuilt after a restart, and both are unexported.
type ClientCert struct {
	// Host is a pattern in matchHost's language.
	Host string
	// Subject, Issuer, NotAfter and Fingerprint are read off the leaf at load time so
	// the panel can show which identity is bound without the API ever touching key
	// material. Fingerprint is the SHA-256 of the leaf DER — the value an operator can
	// compare against what the server's logs say it received.
	Subject     string
	Issuer      string
	NotAfter    string
	Fingerprint string
	// Path is the PKCS#12 file this was loaded from. Not a secret (it is a filename the
	// operator typed) and shown on the panel, because "which file is this rule using"
	// is the first question when a handshake is rejected.
	Path string

	cert       *tls.Certificate
	passphrase string
}

// ClientCertView is the redacted wire shape: metadata read off the certificate, and
// no key material or passphrase anywhere in it.
type ClientCertView struct {
	Host        string `json:"host"`
	Path        string `json:"path"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotAfter    string `json:"not_after"`
	Fingerprint string `json:"fingerprint"`
	// HasPassphrase reports whether the PKCS#12 needed one, never what it was. A
	// passwordless PKCS#12 is legal and worth distinguishing from one whose passphrase
	// is stored.
	HasPassphrase bool `json:"has_passphrase"`
}

func (c ClientCert) view() ClientCertView {
	return ClientCertView{
		Host:          c.Host,
		Path:          c.Path,
		Subject:       c.Subject,
		Issuer:        c.Issuer,
		NotAfter:      c.NotAfter,
		Fingerprint:   c.Fingerprint,
		HasPassphrase: c.passphrase != "",
	}
}

// ClientCerts is the ordered client-certificate binding list.
//
// Same first-match-wins ordering and same exact-match removal as Credentials, for
// the same reasons. Removal is keyed on the host pattern alone here: unlike a
// credential there is no second axis to disambiguate on, and binding two identities
// to one host pattern would mean the second could never be presented.
type ClientCerts struct {
	mu    sync.RWMutex
	certs []ClientCert
}

// NewClientCerts returns an empty binding list.
func NewClientCerts() *ClientCerts { return &ClientCerts{} }

// Add binds an identity, replacing any existing binding for the same host pattern.
func (c *ClientCerts) Add(entry ClientCert) (replaced bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.certs {
		if c.certs[i].Host == entry.Host {
			c.certs[i] = entry
			return true
		}
	}
	c.certs = append(c.certs, entry)
	return false
}

// Remove drops the binding with exactly this host pattern, reporting whether one was
// there. The API turns false into 404.
func (c *ClientCerts) Remove(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.certs {
		if c.certs[i].Host == host {
			c.certs = append(c.certs[:i], c.certs[i+1:]...)
			return true
		}
	}
	return false
}

// ReplaceWith makes c hold exactly src's bindings; nil empties it. In place for the reason
// Credentials.ReplaceWith is: the sender's dialer and the proxy's upstream leg hold this pointer,
// so a project switch that swapped in a new store would leave both presenting the outgoing
// project's identity (burpsy-react-ui-oava). src is only read.
func (c *ClientCerts) ReplaceWith(src *ClientCerts) {
	if src == c {
		return
	}
	var certs []ClientCert
	if src != nil {
		src.mu.RLock()
		certs = append([]ClientCert(nil), src.certs...)
		src.mu.RUnlock()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs = certs
}

// For returns the certificate to present to host, or nil when no binding covers it.
//
// nil is the overwhelmingly common answer and must stay cheap: this runs on every
// TLS dial the tool makes, including when no client certificate is configured at
// all. The read lock over a short slice is the whole cost.
func (c *ClientCerts) For(host string) *tls.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, entry := range c.certs {
		if matchHost(entry.Host, host) {
			return entry.cert
		}
	}
	return nil
}

// View renders every binding, redacted, in match order.
func (c *ClientCerts) View() []ClientCertView {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ClientCertView, 0, len(c.certs))
	for _, entry := range c.certs {
		out = append(out, entry.view())
	}
	return out
}

// Len reports how many bindings are configured.
func (c *ClientCerts) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.certs)
}

// ClientCertRow is one binding as internal/persist stores it: where the PKCS#12 came
// from and the passphrase to open it, never the decoded key.
//
// Storing the path and passphrase rather than the file's bytes is deliberate. The
// alternative — copying the PKCS#12 into the database — would duplicate key material
// into a second place with a second lifetime, so revoking the identity would mean
// remembering that burpsy kept a copy. A path means the operator's file stays the one
// authority, and deleting it takes the identity away everywhere.
type ClientCertRow struct {
	Host       string
	Path       string
	Passphrase string
}

// Secrets exposes each binding's source path and passphrase, for persistence only.
// The same single deliberate hole as Credentials.Secrets — see that doc.
func (c *ClientCerts) Secrets() []ClientCertRow {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ClientCertRow, 0, len(c.certs))
	for _, entry := range c.certs {
		out = append(out, ClientCertRow{Host: entry.Host, Path: entry.Path, Passphrase: entry.passphrase})
	}
	return out
}
