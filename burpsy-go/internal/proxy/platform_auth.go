package proxy

import (
	"strings"

	"github.com/burpsy-go/burpsy/internal/netauth"
)

// This file is the proxy leg's platform authentication: the per-host credentials an operator
// configures under Settings → Network → Platform authentication, applied to the traffic a browser
// sends through the proxy.
//
// # The gap this closes
//
// The sender has had this since the codecs landed. The proxy never did: ProxyConfig carried client
// certificates and the upstream policy but no credential source, so an operator who configured Basic
// or Digest got authenticated Repeater sends, authenticated scanner probes, and an UNAUTHENTICATED
// browser — which is where most of their traffic is. The panel said the rules were stored. The NTLMv2
// codec landed in 3fb2ce1 and was unreachable for the traffic that needed it most
// (burpsy-react-ui-trcy).
//
// # Why a header injection and not a request rebuild
//
// The proxy relays bytes. Rebuilding a request to attach a credential would mean parsing it,
// re-serialising it, and hoping the round trip is byte-identical for everything the parse did not
// model — a header the parse folded, a body the parse re-framed. On a tool whose whole thesis is that
// raw bytes are written once and never copied, that is the wrong shape twice over.
//
// So the only edit is: find the end of the request head, and insert one header line there. Every
// other byte is untouched, and the operator's own Authorization header is never replaced — see
// applyPlatformAuth.
//
// # What this does NOT do, on purpose
//
//   - It does not retry. A Digest credential needs the host's challenge before it can be computed,
//     and that means reading a 401 and sending a second request with the answer. The proxy relays a
//     browser's connection on a keep-alive socket the browser owns; re-sending a request the browser
//     did not ask to repeat, against a host that is refusing it, is how an account gets locked out —
//     which is why the sender bounds its own retry to exactly one attempt and why this does none.
//     A Digest rule therefore works here for a host that challenges on a PREVIOUS request (the nonce
//     is cached by Learn) and not for the first request of a session.
//   - It does not touch CONNECT-tunnelled TLS. That is the same raw-bytes contract as everything
//     else here, and a request whose body this function cannot see is not one it may edit.
//   - It does not replace a credential the browser already sent. The browser is the operator's own
//     client and its Authorization header is its own business; a per-host rule quietly overwriting
//     it would mean the request on screen is not the request that goes out.

// PlatformAuthSource is the per-host credential lookup the proxy consults before forwarding.
//
// An interface rather than a concrete *netauth.Credentials for the same reason sender.PlatformAuth
// is one: internal/netauth owns the rules, the schemes and the secrets, and this package only needs
// to ask for a header value.
type PlatformAuthSource interface {
	// Authorization returns the header value to present for one request, and whether there is one.
	// False is an ordinary answer: a Digest rule has nothing to send until the host has challenged.
	Authorization(host, method, uri string) (string, bool)
	// Learn records a challenge from a 401 so a later request can authenticate against it. The proxy
	// calls it while relaying a response so the NEXT request on the connection can answer, which is
	// what makes Digest reachable at all on this leg.
	Learn(host, wwwAuthenticate string) (bool, error)
}

// WithPlatformAuth attaches the credential lookup the proxy consults before forwarding a request.
//
// The same *netauth.Credentials instance must be handed to the sender, so one set of rules governs
// every leg. Two stores would let the panel describe credentials Repeater honours and the proxy does
// not — the split burpsy-react-ui-trcy records, and the reason this exists.
//
// Nil is a no-op rather than a clear, matching every other With* on this type: a caller that never
// opted in keeps the unauthenticated behaviour it had, and a caller that wants to detach passes an
// empty store rather than nil, so "no credentials configured" and "no credential source" stay
// distinguishable in CarriesPlatformAuth.
func (c *ProxyConfig) WithPlatformAuth(source PlatformAuthSource) *ProxyConfig {
	if source != nil {
		c.platformAuth = source
	}
	return c
}

// CarriesPlatformAuth reports whether this proxy was built with a credential lookup attached.
//
// Exported for the same reason sender.CarriesPlatformAuth is: an operator whose panel says the rules
// are stored needs to be able to ask whether the leg they are watching will use them, and the answer
// has to be a property of the object rather than a re-derivation from the settings document.
func (c *ProxyConfig) CarriesPlatformAuth() bool { return c.platformAuth != nil }

// PlatformAuth returns the attached credential lookup, or nil. Nil is a real answer here rather than
// a default to paper over: a proxy with no source is a proxy that forwards unauthenticated, and
// pretending otherwise would make the difference invisible at the call site that has to skip the
// lookup.
func (c *ProxyConfig) PlatformAuth() PlatformAuthSource { return c.platformAuth }

// CarriesPlatformAuth reports whether this proxy was built with a credential lookup attached.
//
// The Server-level twin of ProxyConfig.CarriesPlatformAuth, for the same reason Server.Streaming
// exists: the web layer holds a *Server and needs to ask this question without reaching into its
// config, and a method that reached through would be a second way for the answer to differ from the
// field it reports.
func (s *Server) CarriesPlatformAuth() bool {
	return s != nil && s.config != nil && s.config.platformAuth != nil
}

// applyPlatformAuth returns the request bytes to forward, with a platform credential attached when
// one applies and the request does not already carry an Authorization header.
//
// # The operator's own header always wins
//
// A browser that sent Authorization is the operator's client asserting an identity, and a per-host
// rule replacing it would mean the request they can see in Repeater is not the one that went out —
// the same rule sender.go states and tests for its own leg. There is also a security reading: a
// target that can induce a browser to send a header is not thereby entitled to have a stored
// credential substituted for it.
//
// # Only the head is touched
//
// The insert goes at the blank line that ends the head, before the body. Getting that boundary wrong
// would splice a header into a body, so the search is for CRLFCRLF (with a bare-LFLF fallback, since
// a client may send that and refusing to authenticate it would be a silent difference). A request
// with no terminator is returned untouched rather than guessed at: an unparseable request is already
// refused further up, and this function does not get to decide otherwise.
func applyPlatformAuth(source PlatformAuthSource, requestData []byte, host, method, uri string) []byte {
	if source == nil || len(requestData) == 0 {
		return requestData
	}
	insertAt := requestHeaderInsertPoint(requestData)
	if insertAt < 0 {
		return requestData
	}
	head := requestData[:insertAt]
	if hasAuthorizationHeader(head) {
		return requestData
	}
	value, ok := source.Authorization(host, method, uri)
	if !ok || value == "" {
		return requestData
	}
	// The insert is ONE header line and no blank line of its own: it goes immediately before the
	// blank line that already ends the head, and that existing blank line becomes the terminator for
	// this header too. Carrying a second one is what produced a head with two terminators; carrying
	// none is what produced a credential glued onto the last header's name.
	//
	// The line ending matches the head's own, so a bare-LF request stays bare-LF rather than
	// acquiring a CRLF in the middle of its header block.
	eol := "\r\n"
	if strings.Contains(string(head), "\n") && !strings.Contains(string(head), "\r\n") {
		eol = "\n"
	}
	insert := []byte(eol + "Authorization: " + value)

	out := make([]byte, 0, len(requestData)+len(insert))
	out = append(out, requestData[:insertAt]...)
	out = append(out, insert...)
	out = append(out, requestData[insertAt:]...)
	return out
}

// requestHeadEnd returns the index just past the blank line that ends a request head, or -1.
//
// That index is where the BODY starts. It is NOT where a header goes: a header belongs BEFORE the
// blank line, and inserting at this index puts it after — which reads to the origin as the first
// bytes of the body. The distinction is the whole reason this is two functions rather than one.
func requestHeadEnd(requestData []byte) int {
	if i := strings.Index(string(requestData), "\r\n\r\n"); i >= 0 {
		return i + 4
	}
	if i := strings.Index(string(requestData), "\n\n"); i >= 0 {
		return i + 2
	}
	return -1
}

// requestHeaderInsertPoint returns the index at which a header line may be inserted: just past the
// last header's line ending and just before the blank line that ends the head.
//
// Both are the same place for a well-formed head, and they are NOT the same as requestHeadEnd's
// return, which is past the blank line. An earlier version of this used requestHeadEnd and put every
// credential at the front of the body; the test below is what caught it, and it is why the two are
// separate functions with names that say which is which.
func requestHeaderInsertPoint(requestData []byte) int {
	if i := strings.Index(string(requestData), "\r\n\r\n"); i >= 0 {
		return i
	}
	if i := strings.Index(string(requestData), "\n\n"); i >= 0 {
		return i
	}
	return -1
}

// hasAuthorizationHeader reports whether the head already carries an Authorization header, in any
// case.
//
// The comparison is case-insensitive because HTTP header names are (RFC 9110 §5.1), and a
// case-sensitive test would let a browser's `authorization:` be silently replaced by a stored rule —
// the exact outcome the "operator's own header wins" rule exists to prevent.
func hasAuthorizationHeader(head []byte) bool {
	for _, line := range headerLines(head) {
		field, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(field), "Authorization") {
			return true
		}
	}
	return false
}

// headerLines returns the head's header lines, without the request line and without the terminating
// blank line.
func headerLines(head []byte) []string {
	text := string(head)
	// Drop the request line.
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[i+1:]
	}
	// Drop the terminating blank line, in either spelling.
	text = strings.TrimSuffix(text, "\r\n\r\n")
	text = strings.TrimSuffix(text, "\n\n")
	var out []string
	for _, line := range strings.Split(text, "\n") {
		out = append(out, strings.TrimSuffix(line, "\r"))
	}
	return out
}

// splitRequestLine returns the request line's method and request-target, and false when the bytes do
// not begin with one.
//
// It is a two-field split on spaces rather than a full request-line parse: the only two things the
// credential lookup needs are the method (Digest hashes it) and the URI (Digest hashes it too), and a
// parser that could disagree with core's about what a request line is would be a second definition of
// the same thing.
func splitRequestLine(head []byte) (method, uri string, ok bool) {
	text := string(head)
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	text = strings.TrimRight(text, "\r")
	parts := strings.Fields(text)
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// requestMethodAndURI returns the method and request-target of a raw request, for the credential
// lookup. An unparseable request line yields empty strings, which the lookup treats as "no rule
// applies" — the same answer as no credential, and never a panic on bytes the proxy has already
// decided are not a request.
func requestMethodAndURI(requestData []byte) (method, uri string) {
	end := requestHeadEnd(requestData)
	if end < 0 {
		end = len(requestData)
	}
	method, uri, ok := splitRequestLine(requestData[:end])
	if !ok {
		return "", ""
	}
	return method, uri
}

// learnFromChallenge records a 401's challenges against a host, so the next request on this
// connection can answer them.
//
// It is called with whatever challenges the response carried, and reports nothing: a challenge that
// cannot be learned is not an error the proxy can act on, and a Digest rule that cannot answer yet
// simply sends nothing on the next request, which is the documented behaviour rather than a failure.
// The counting that makes that visible is netauth's own.
func learnFromChallenge(source PlatformAuthSource, host string, challenges []string) {
	if source == nil || host == "" {
		return
	}
	for _, challenge := range challenges {
		if _, err := source.Learn(host, challenge); err != nil {
			// Deliberately swallowed. A challenge this build cannot answer is not a fault in the
			// proxy: the credential store owns that decision, and the next request simply goes out
			// unauthenticated, which is the same answer as having no rule at all.
			continue
		}
	}
}

// platformAuthChallenges pulls the WWW-Authenticate values out of a raw response head.
//
// It reads the head rather than the whole response because the head is what a challenge arrives in,
// and because the streaming path may not have a whole response yet. A 401 with no challenge carries
// nothing to learn from, and that is an ordinary answer.
func platformAuthChallenges(responseHead []byte) []string {
	var out []string
	for _, line := range headerLines(responseHead) {
		field, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(field), "WWW-Authenticate") {
			continue
		}
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// interface check: *netauth.Credentials is the production implementation, and this is the assertion
// that keeps it one. A change to either signature breaks here rather than at a call site three legs
// away.
var _ PlatformAuthSource = (*netauth.Credentials)(nil)

// withPlatformAuth returns the request bytes to forward, with a platform credential attached when
// one applies.
//
// It is the Server-level seam so the three forward sites each make one call rather than repeating
// the nil check, the head parse and the method/URI extraction — three copies of which is how one of
// them ends up skipping the "operator's own header wins" rule the other two honour.
//
// A nil source, a request with no head terminator, a request that already carries Authorization, and
// a host with no matching rule all return the input unchanged. Every one of those is an ordinary
// answer, not a failure: the proxy's job is to forward what the browser sent, and a credential is
// something it adds when it may.
// forForwarding is the single place a request's bytes are adapted before they go upstream: the
// operator's Expect-header policy, then the platform credential (burpsy-react-ui-o1eu).
//
// One function rather than the same two calls at each egress leg, because the legs have already
// drifted once — the platform credential was wired into one path and not another — and a caller that
// remembered only one of the two would be the same defect again. Each step is a splice that returns
// its input unchanged when it has nothing to do, so the common case costs a comparison and the bytes
// on the wire are the bytes the browser sent.
func (s *Server) forForwarding(requestData []byte, host, method, uri string) []byte {
	if s == nil {
		return requestData
	}
	if n := s.config.network; n != nil && n.Continue.RemoveExpect {
		requestData = withoutExpectHeader(requestData)
	}
	return s.withPlatformAuth(requestData, host, method, uri)
}

func (s *Server) withPlatformAuth(requestData []byte, host, method, uri string) []byte {
	if s == nil {
		return requestData
	}
	return applyPlatformAuth(s.config.platformAuth, requestData, host, method, uri)
}

// requestMethod returns a raw request's method, or "" when the request line cannot be read.
//
// The credential lookup needs the method because Digest hashes it, so a request whose method cannot
// be read cannot be authenticated — and an empty method is exactly what produces no header, which is
// the right answer rather than a guess.
func requestMethod(requestData []byte) string {
	method, _ := requestMethodAndURI(requestData)
	return method
}

// requestURI returns a raw request's request-target, or "" when it cannot be read. See requestMethod.
func requestURI(requestData []byte) string {
	_, uri := requestMethodAndURI(requestData)
	return uri
}

// withoutExpectHeader removes every `Expect` header line from a request's head
// (burpsy-react-ui-o1eu), returning the bytes unchanged when the header is not there.
//
// The operator asked for this under Settings → Network → "Strip Expect: 100-continue from outbound
// requests", and the reason is a peer that STALLS on the header rather than answering it: the client
// waits for a 100 that never comes, and the request goes nowhere. The sender honours the setting on
// its typed path (sender.go:770); this is the same setting applied to traffic a browser is driving,
// which is the leg where the stall is most visible.
//
// A splice, not a rebuild, for the same reason applyPlatformAuth is: every byte outside the removed
// line — the request line, the other headers, their order and spacing, the body — is the byte the
// browser sent, and this proxy's record is only trustworthy while that is true. The line ending is
// the head's own, so a bare-LF request stays bare-LF.
func withoutExpectHeader(requestData []byte) []byte {
	insertAt := requestHeaderInsertPoint(requestData)
	if insertAt < 0 {
		return requestData
	}
	head := string(requestData[:insertAt])
	crlf := strings.Contains(head, "\r\n")
	eol := "\n"
	if crlf {
		eol = "\r\n"
	}
	lines := strings.Split(head, eol)
	kept := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		field, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(field), "Expect") {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return requestData
	}
	out := []byte(strings.Join(kept, eol))
	out = append(out, requestData[insertAt:]...)
	return out
}
