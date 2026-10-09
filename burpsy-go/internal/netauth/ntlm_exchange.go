package netauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// NTLM as a connection-bound handshake (burpsy-react-ui-sel6).
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
type NTLMExchange struct {
	store *Credentials
	host  string
	rule  Credential
	// negotiate is the type-1 message as sent, kept because the MIC covers it verbatim.
	negotiate []byte
	// answered is set once Authenticate has produced a type-3 message, so a second call — a
	// caller looping on 401s — is refused rather than presenting the credential again.
	answered bool
}

// BeginConnectionAuth starts a connection-bound handshake for host when the first rule
// covering it uses a connection-bound scheme (NTLM), and reports false otherwise — including
// when no rule covers the host, in which case nothing is presented at all.
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
		if candidate.Scheme != SchemeNTLMv2 {
			return nil, false
		}
		return &NTLMExchange{store: c, host: host, rule: candidate, negotiate: ntlmNegotiateMessage()}, true
	}
	return nil, false
}

// Negotiate returns the Authorization value for the first leg: the type-1 NEGOTIATE message.
// It carries flags only, no credential, which is why it may go out before any challenge.
func (x *NTLMExchange) Negotiate() string {
	return "NTLM " + base64.StdEncoding.EncodeToString(x.negotiate)
}

// ErrNoNTLMChallenge is returned by Authenticate when the 401 that answered the NEGOTIATE
// carries no NTLM CHALLENGE_MESSAGE — a bare "NTLM" offer, or only other schemes. A bare offer
// in reply to a NEGOTIATE is the server refusing the handshake, not inviting one; answering it
// would mean starting over on a connection the server has already declined, so it is a failure.
var ErrNoNTLMChallenge = errors.New("the server answered the NTLM NEGOTIATE without a CHALLENGE_MESSAGE; it is not accepting this NTLM handshake")

// Authenticate answers the CHALLENGE_MESSAGE among a 401's WWW-Authenticate values with the
// type-3 AUTHENTICATE message, as an Authorization value.
//
// It answers at most once per exchange. NTLM has no "stale" case: a 401 after the AUTHENTICATE
// is the credential refused, and presenting it again is how an account gets locked out.
func (x *NTLMExchange) Authenticate(challenges []string) (string, error) {
	if x.answered {
		return "", errors.New("this NTLM handshake has already presented its credential; a further 401 is a rejection, not a challenge")
	}
	var blob []byte
	for _, challenge := range challenges {
		token, rest, _ := strings.Cut(strings.TrimSpace(challenge), " ")
		if !strings.EqualFold(token, "NTLM") || strings.TrimSpace(rest) == "" {
			continue
		}
		msg, err := ntlmChallengeBlob(challenge)
		if err != nil {
			return "", err
		}
		blob = msg
		break
	}
	if blob == nil {
		return "", ErrNoNTLMChallenge
	}
	header, err := ntlmAnswer(x.rule, x.negotiate, blob)
	if err != nil {
		return "", err
	}
	x.answered = true
	return header, nil
}

// Rejected records that the handshake failed for this host — the AUTHENTICATE was refused, or
// the challenge could not be answered — so the console's prompt-on-failure can name it. The
// challenge recorded is the scheme the host spoke; reason says what the sender saw, for the
// failure's record and for the caller's own report.
func (x *NTLMExchange) Rejected(challenges []string) {
	challenge := "NTLM"
	for _, c := range challenges {
		if scheme, ok := platformChallengeScheme(c); ok && scheme == "NTLM" {
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
	return fmt.Sprintf("NTLM handshake for %s as %s", x.host, x.rule.Username)
}
