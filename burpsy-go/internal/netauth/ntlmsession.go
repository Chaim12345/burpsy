// The NTLMv2 handshake as a state machine the sender drives, and the header encoding
// around it.
//
// # Why this shape
//
// NTLM is the only scheme here that the credential store cannot answer with a header.
// Basic computes one from the rule alone; Digest computes one from the rule plus a cached
// challenge, which Credentials owns. NTLM is a conversation with three turns bound to one
// TCP connection, and the party that owns the connection is internal/sender.
//
// So the sender drives, and this file hands it exactly two things: the bytes to send, and
// a place to put the bytes that come back. What it never hands over is the password or any
// key derived from it. NTLMSession has no exported field; its NT one-way function lives in
// an unexported []byte that encoding/json cannot reach, the same structural guarantee the
// rest of this package relies on rather than a rule someone has to remember.
//
// # What a caller can and cannot get wrong
//
// The legs are ordered by the type: Negotiate() must be called before Authenticate(), and
// Authenticate() consumes the challenge bytes. A session is single-use — Authenticate()
// marks it spent — because reusing one would mean computing a second response against a
// challenge the server has already retired, which fails in a way that looks like a wrong
// password.
package netauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// NTLMSession is one NTLMv2 handshake against one connection.
//
// Created by (*Credentials).StartNTLM, which is the only way to get one: a session must be
// bound to a rule that actually matched the host, and a constructor taking a password
// would be a second door into the secret this package exists to keep behind one.
type NTLMSession struct {
	// ntowf is NTOWFv2 for this rule — derived from the password, and as good as the
	// password for authenticating. Unexported, never returned, never logged.
	ntowf []byte

	user        string
	domain      string
	workstation string

	negotiateMsg []byte
	spent        bool

	// timestamp is the FILETIME that goes into `temp` when the server did not supply one,
	// injectable so a test can pin it.
	//
	// It is a [8]byte source rather than a func() time.Time because the value this needs is
	// the FILETIME, and the spec's own vector uses Time=0 — which is 1601-01-01, a instant
	// time.Time can hold but whose UnixNano() overflows int64. Injecting the clock would
	// have made the one case the spec publishes the one case the seam cannot express.
	timestamp func() [8]byte
	// clientChallenge is the entropy source, injectable for the same reason. Production
	// is newClientChallenge.
	clientChallenge func() ([8]byte, error)
}

// StartNTLM begins a handshake for the first rule covering host, if that rule is NTLMv2.
//
// Returns false when there is no rule, or the rule is Basic or Digest — the caller then
// takes the header path it already had. It is deliberately not an error: "this host uses
// Digest" is a normal answer to "should I run an NTLM handshake", not a failure.
func (c *Credentials) StartNTLM(host string) (*NTLMSession, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, rule := range c.rules {
		if !matchHost(rule.Host, host) {
			continue
		}
		if rule.Scheme != SchemeNTLMv2 {
			return nil, false
		}
		return &NTLMSession{
			ntowf:           ntowfv2(rule.Username, rule.Domain, rule.password),
			user:            rule.Username,
			domain:          rule.Domain,
			workstation:     rule.Workstation,
			timestamp:       func() [8]byte { return ntlmTimestamp(time.Now()) },
			clientChallenge: newClientChallenge,
		}, true
	}
	return nil, false
}

// Negotiate returns the `Authorization: NTLM <base64>` header value for the first leg.
//
// The NEGOTIATE message is retained on the session because the MIC on the third leg is an
// HMAC over all three messages concatenated (MS-NLMP 3.1.5.1.2). Rebuilding it at MIC time
// instead of keeping it would be a second assembly of the same bytes, which is how the
// hashed message ends up differing from the sent one.
func (s *NTLMSession) Negotiate() string {
	s.negotiateMsg = buildNegotiate()
	return "NTLM " + base64.StdEncoding.EncodeToString(s.negotiateMsg)
}

// Authenticate answers the server's CHALLENGE_MESSAGE with the AUTHENTICATE_MESSAGE,
// returning the third leg's `Authorization` header value.
//
// challengeHeader is the raw WWW-Authenticate value from the 401 — "NTLM <base64>" — not
// the decoded bytes. Parsing is done here so the caller never has to know the header's
// shape, and so a server that answers with a bare "NTLM" (no challenge at all) is refused
// by name rather than producing an empty decode that looks like a protocol error further
// down.
func (s *NTLMSession) Authenticate(challengeHeader string) (string, error) {
	if s.negotiateMsg == nil {
		return "", errors.New("NTLM: Authenticate was called before Negotiate, so there is no first leg for " +
			"the message integrity code to cover")
	}
	if s.spent {
		return "", errors.New("NTLM: this handshake has already answered a challenge; a second response would " +
			"be computed against a nonce the server has retired, which fails as though the password were wrong")
	}

	raw, err := decodeNTLMHeader(challengeHeader)
	if err != nil {
		return "", err
	}
	challenge, err := parseChallenge(raw)
	if err != nil {
		return "", err
	}

	clientChallenge, err := s.clientChallenge()
	if err != nil {
		return "", err
	}

	// MS-NLMP 3.1.5.1.2: when the server's target info carries MsvAvTimestamp, the client
	// uses **that** timestamp rather than its own clock and must supply a MIC. Using the
	// local clock in that case produces a response a server with any skew tolerance at all
	// still rejects, and omitting the MIC after a server asked for one is a hard failure on
	// modern AD. When there is no timestamp there is nothing to echo, the local clock is
	// the only source, and no MIC is expected.
	timestamp, serverTimestamped := challenge.timestamp()
	targetInfo := challenge.TargetInfo
	if serverTimestamped {
		targetInfo = withMICFlag(targetInfo)
	} else {
		timestamp = s.timestamp()
	}

	ntResponse, sessionBaseKey := ntlmv2Response(s.ntowf, challenge.ServerChallenge, clientChallenge, timestamp, targetInfo)
	lmResponse := lmv2Response(s.ntowf, challenge.ServerChallenge, clientChallenge)

	authenticate := buildAuthenticate(authenticateInput{
		domain:       s.domain,
		user:         s.user,
		workstation:  s.workstation,
		lmResponse:   lmResponse,
		ntResponse:   ntResponse,
		flags:        ntlmClientFlags,
		withMIC:      serverTimestamped,
		micKey:       sessionBaseKey,
		negotiateMsg: s.negotiateMsg,
		challengeMsg: raw,
	})

	s.spent = true
	return "NTLM " + base64.StdEncoding.EncodeToString(authenticate), nil
}

// decodeNTLMHeader pulls the base64 blob out of an `NTLM <base64>` challenge header.
//
// # Why it is this strict
//
// A 401 may carry several WWW-Authenticate values, and the caller passes whichever one
// started with NTLM. Everything after that point is attacker-chosen: the scheme token, the
// base64, the message inside it. Each failure gets its own message because they mean
// different things to an operator — "the server offered NTLM but sent no challenge" is a
// misconfigured server, while "the challenge is not valid base64" is a middlebox mangling
// the header, and a single "bad NTLM challenge" would send them to the same wrong place.
func decodeNTLMHeader(header string) ([]byte, error) {
	value := strings.TrimSpace(header)
	scheme, blob, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, "NTLM") {
		if strings.EqualFold(value, "NTLM") {
			return nil, errors.New("the server offered NTLM but its 401 carried no challenge message; " +
				"it answered the NEGOTIATE leg with a bare `WWW-Authenticate: NTLM`")
		}
		return nil, fmt.Errorf("expected an NTLM challenge header but got %q", truncateForError(value))
	}
	blob = strings.TrimSpace(blob)
	if blob == "" {
		return nil, errors.New("the server's NTLM challenge header has the scheme but no base64 payload")
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("the server's NTLM challenge is not valid base64: %w", err)
	}
	return raw, nil
}

// truncateForError bounds what a server-controlled string can put into an error message.
//
// The value is a header from the host under test, and errors from here reach the API and
// the operator's screen. An unbounded echo would let a target paste an arbitrary amount of
// text — including something dressed up as burpsy's own output — into burpsy's UI.
func truncateForError(value string) string {
	const max = 40
	if len(value) <= max {
		return value
	}
	return value[:max] + "…"
}

// NTLMChallengeHeader picks the NTLM challenge out of a 401's WWW-Authenticate values.
//
// Returns the value and whether there was one. A server commonly offers several schemes in
// several headers — `Negotiate`, `NTLM`, `Basic` — and the caller must answer the NTLM one
// specifically; taking the first header would answer Negotiate with an NTLM message.
//
// `Negotiate` is deliberately **not** treated as an NTLM offer even though SPNEGO can wrap
// NTLM. Answering a Negotiate challenge with a bare NTLMSSP message (rather than a
// GSS-API-wrapped one) works against some servers and not others, and this build does not
// implement SPNEGO's wrapping — see ParseScheme. Claiming the scheme and half-speaking it
// is the failure mode that makes an operator blame the target.
func NTLMChallengeHeader(values []string) (string, bool) {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if strings.EqualFold(trimmed, "NTLM") || strings.HasPrefix(strings.ToUpper(trimmed), "NTLM ") {
			return trimmed, true
		}
	}
	return "", false
}
