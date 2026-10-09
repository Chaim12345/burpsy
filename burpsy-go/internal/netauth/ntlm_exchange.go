package netauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// NTLM as a connection-bound handshake (burpsy-react-ui-sel6), in the NTLM or the Negotiate
// header, v2 by default and v1 only for a rule that opts into it.
//
// # Why this exists beside Authorization and Learn
//
// NTLM authenticates a TCP connection, not a request. A server keeps the CHALLENGE it issued
// in the state of the connection that carried the NEGOTIATE, verifies the AUTHENTICATE only on
// that same connection, and from then on treats the connection — not the request — as the
// authenticated party. Authorization/Learn model the opposite: state keyed by host, answerable
// on whatever connection the next request happens to ride. Against a server that binds the
// challenge to its connection (IIS, http.sys, every SSPI server) that authenticates only when
// the pool happens to hand back the same socket, which is the "flaky target" failure the Scheme
// doc warned of; and the host-keyed state outlives the handshake, so every later request to the
// host presented an AUTHENTICATE computed against a challenge some other connection received.
//
// NTLMExchange is one handshake for one exchange. The caller (internal/sender) owns the
// connection and promises the three legs ride it; this type owns the secret and the protocol:
// it emits the NEGOTIATE, answers the CHALLENGE from the 401 that carried it, and records a
// rejection. It holds the rule's password in an unexported field and hands back only wire
// bytes, by the package's secret rule.

// NTLMExchange is one connection-bound NTLM handshake. It is not safe for concurrent use: one
// exchange is one connection and one sequence of legs. Concurrent sends each begin their own.
//
// # The header it travels in
//
// The NTLMSSP messages travel in "Authorization: NTLM <b64>" or, for a server that offers only
// Negotiate, as raw NTLM in "Authorization: Negotiate <b64>" — what Windows sends when Kerberos
// is unavailable; no SPNEGO wrapping. An exchange starts in the NTLM header unless the host has
// already been seen to offer only Negotiate, and SwitchToNegotiate moves it there on the same
// connection when the first 401 says so.
type NTLMExchange struct {
	store *Credentials
	host  string
	rule  Credential
	// wire is the Authorization scheme the messages travel in: "NTLM" or "Negotiate".
	wire string
	// negotiate is the type-1 message as sent, kept because the MIC covers it verbatim.
	negotiate []byte
	// switched is set once the exchange has moved to the Negotiate header, so it moves at most once.
	switched bool
	// answered is set once Authenticate has produced a type-3 message, so a second call — a
	// caller looping on 401s — is refused rather than presenting the credential again.
	answered bool
}

const (
	wireNTLM      = "NTLM"
	wireNegotiate = "Negotiate"
)

// BeginConnectionAuth starts a connection-bound handshake for host when the first rule
// covering it uses a connection-bound scheme (ntlmv2 or the opt-in ntlmv1), and reports false
// otherwise — including when no rule covers the host, in which case nothing is presented at all.
//
// Only the first matching rule is consulted, as for every scheme: first-match-wins is the
// panel's contract, and skipping past a Basic rule to find an NTLM one would present a
// credential the operator ordered after another.
func (c *Credentials) BeginConnectionAuth(host string) (*NTLMExchange, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, candidate := range c.rules {
		if !matchHost(candidate.Host, host) {
			continue
		}
		if !candidate.Scheme.isNTLM() {
			return nil, false
		}
		wire := wireNTLM
		if c.negotiateHosts[strings.ToLower(host)] {
			wire = wireNegotiate
		}
		return &NTLMExchange{store: c, host: host, rule: candidate, wire: wire, negotiate: ntlmNegotiateMessage()}, true
	}
	return nil, false
}

// Wire is the Authorization scheme this exchange's messages travel in: "NTLM" or "Negotiate".
func (x *NTLMExchange) Wire() string { return x.wire }

// Negotiate returns the Authorization value for the first leg: the type-1 NEGOTIATE message.
// It carries flags only, no credential, which is why it may go out before any challenge.
func (x *NTLMExchange) Negotiate() string { return encodeNTLM(x.wire, x.negotiate) }

// SwitchToNegotiate moves the exchange into the Negotiate header when the 401 that answered its
// NTLM NEGOTIATE carries no NTLM challenge but offers Negotiate — a server that does not speak the
// NTLM header. It reports whether it switched; the caller then resends Negotiate() on the same
// connection. It moves at most once, and remembers the host so the next exchange starts there.
func (x *NTLMExchange) SwitchToNegotiate(challenges []string) bool {
	if x.switched || x.wire == wireNegotiate || x.answered {
		return false
	}
	if _, ok := tokenFor(challenges, wireNTLM); ok {
		return false // the server answered in the NTLM header; stay there
	}
	offered := false
	for _, c := range challenges {
		token, _, _ := strings.Cut(strings.TrimSpace(c), " ")
		if strings.EqualFold(token, wireNegotiate) {
			offered = true
		}
	}
	if !offered {
		return false
	}
	x.wire, x.switched = wireNegotiate, true
	x.store.mu.Lock()
	if x.store.negotiateHosts == nil {
		x.store.negotiateHosts = map[string]bool{}
	}
	x.store.negotiateHosts[strings.ToLower(x.host)] = true
	x.store.mu.Unlock()
	return true
}

// tokenFor returns the base64 token of the first challenge in the given scheme that carries one.
func tokenFor(challenges []string, wire string) (string, bool) {
	for _, challenge := range challenges {
		token, rest, _ := strings.Cut(strings.TrimSpace(challenge), " ")
		if strings.EqualFold(token, wire) && strings.TrimSpace(rest) != "" {
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

// ErrNoNTLMChallenge is returned by Authenticate when the 401 that answered the NEGOTIATE
// carries no CHALLENGE_MESSAGE in the exchange's header — a bare offer, or only other schemes. A
// bare offer in reply to a NEGOTIATE is the server refusing the handshake, not inviting one;
// answering it would mean starting over on a connection the server has already declined.
var ErrNoNTLMChallenge = errors.New("the server answered the NTLM NEGOTIATE without a CHALLENGE_MESSAGE; it is not accepting this NTLM handshake")

// ErrNegotiateNotNTLM is returned when the server's Negotiate token is not raw NTLM — a SPNEGO
// (GSS-API) token, i.e. Kerberos or SPNEGO-wrapped negotiation — which this build cannot answer.
var ErrNegotiateNotNTLM = errors.New("the server's Negotiate token is SPNEGO/Kerberos, not raw NTLM; this build answers Negotiate " +
	"only with NTLM inside it and does not implement Kerberos")

// Authenticate answers the CHALLENGE_MESSAGE among a 401's WWW-Authenticate values with the
// type-3 AUTHENTICATE message, as an Authorization value in the exchange's header.
//
// It answers at most once per exchange. NTLM has no "stale" case: a 401 after the AUTHENTICATE
// is the credential refused, and presenting it again is how an account gets locked out.
//
// An ntlmv1 rule answers with NTLMv1 (ESS when the challenge sets it) and records a
// weak-authentication warning for the host, every time, whatever the prompt setting. An ntlmv2
// rule answers with NTLMv2 only: a challenge that cannot carry v2 is an error, never a v1 answer.
func (x *NTLMExchange) Authenticate(challenges []string) (string, error) {
	if x.answered {
		return "", errors.New("this NTLM handshake has already presented its credential; a further 401 is a rejection, not a challenge")
	}
	token, ok := tokenFor(challenges, x.wire)
	if !ok {
		return "", ErrNoNTLMChallenge
	}
	blob, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("the %s challenge payload is not valid base64: %w", x.wire, err)
	}
	if len(blob) < len(ntlmSignature) || string(blob[:len(ntlmSignature)]) != ntlmSignature {
		if x.wire == wireNegotiate {
			return "", ErrNegotiateNotNTLM
		}
		return "", errors.New("NTLM challenge does not start with the NTLMSSP signature")
	}

	if x.rule.Scheme == SchemeNTLMv1 {
		msg, ess, err := ntlmv1Answer(x.rule, blob)
		if err != nil {
			return "", err
		}
		x.answered = true
		scheme := "NTLMv1"
		if ess {
			scheme = "NTLMv1 (ESS)"
		}
		x.store.mu.Lock()
		x.store.recordWarningLocked(x.host, scheme, x.wire, WeakSchemeWarning(SchemeNTLMv1))
		x.store.mu.Unlock()
		return encodeNTLM(x.wire, msg), nil
	}

	header, err := ntlmAnswer(x.rule, x.negotiate, blob)
	if err != nil {
		return "", err
	}
	x.answered = true
	// ntlmAnswer renders the NTLM header; re-render in this exchange's header when it differs.
	if x.wire != wireNTLM {
		header = x.wire + strings.TrimPrefix(header, wireNTLM)
	}
	return header, nil
}

// Rejected records that the handshake failed for this host — the AUTHENTICATE was refused, or
// the challenge could not be answered — so the console's prompt-on-failure can name it. The
// challenge recorded is the scheme the host spoke.
func (x *NTLMExchange) Rejected(challenges []string) {
	challenge := x.wire
	for _, c := range challenges {
		if scheme, ok := platformChallengeScheme(c); ok && strings.EqualFold(scheme, x.wire) {
			challenge = c
			break
		}
	}
	x.store.mu.Lock()
	defer x.store.mu.Unlock()
	x.store.recordFailureLocked(x.host, challenge, FailureRejected)
}

// splitNTLMUser splits a "DOMAIN\user" username into its domain and account, the form Windows
// logon names take and the form the console's hint asks for. A username with no backslash has
// no domain of its own; the caller then hashes against the domain the server named, which is
// what a domain-less account (or a UPN "user@realm", sent whole) authenticates under.
func splitNTLMUser(username string) (domain, user string, hasDomain bool) {
	if i := strings.IndexByte(username, '\\'); i >= 0 {
		return username[:i], username[i+1:], true
	}
	return "", username, false
}

// String never prints the credential: an exchange that reaches a log line or a %v prints the
// host and the account only.
func (x *NTLMExchange) String() string {
	return fmt.Sprintf("%s handshake (%s) for %s as %s", x.wire, x.rule.Scheme, x.host, x.rule.Username)
}
