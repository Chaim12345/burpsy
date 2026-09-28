package netauth

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// RFC 7616 Digest access authentication.
//
// # Why this is here rather than delegated to a library
//
// Digest is ~120 lines of hashing with an exactly specified input, and the failure
// mode of getting it wrong is loud (the server answers 401 again) rather than
// silent. What a library would actually be buying is the challenge parser, and a
// parser is the part that has to be strict here: an unreadable or unsupported
// challenge must be refused, not guessed at, because guessing means sending the
// operator's password hashed under the wrong parameters to a host that will log the
// attempt.
//
// # What is implemented, and what is refused
//
// Algorithms: MD5, MD5-sess, SHA-256 and SHA-256-sess. MD5 is the RFC 2617 default
// and is what almost every appliance still speaks; it is implemented because
// refusing it would mean refusing the entire installed base, and burpsy is a tool
// for reaching targets as they are, not as they should be. An algorithm outside
// those four is refused by name.
//
// qop: `auth` only. `auth-int` folds a hash of the request body into the response,
// and is refused rather than silently downgraded to `auth` — a server that asked for
// integrity protection and got a plain `auth` response would reject it anyway, so a
// downgrade would only obscure why. A challenge offering both picks `auth`. A
// challenge with no qop at all falls back to the RFC 2069 two-term response, which
// old appliances still emit.

// Challenge is one parsed `WWW-Authenticate: Digest ...` header.
type Challenge struct {
	Realm     string
	Nonce     string
	Opaque    string
	Algorithm string
	// QOP is the server's offered quality-of-protection list, lowercased. Empty means
	// the header carried none, which selects the RFC 2069 response shape.
	QOP []string
	// Stale marks a nonce the server says has merely expired. The distinction matters:
	// a stale challenge means "retry with the same credential", while a fresh 401 after
	// a successful-looking response means the credential itself is wrong. Conflating
	// them turns an expired nonce into a reported authentication failure.
	Stale bool
}

// digestState is the cached challenge for one host plus the nonce counter spent
// against it.
//
// nc must strictly increase for a given nonce or a server enforcing replay
// protection rejects the request — and rejects it with another 401, which reads
// exactly like a wrong password. It is per-nonce rather than global because the
// count is defined relative to the nonce it accompanies.
type digestState struct {
	challenge Challenge
	nc        uint32
}

// hasQOP reports whether the server offered a given quality of protection.
func (c Challenge) hasQOP(want string) bool {
	for _, q := range c.QOP {
		if q == want {
			return true
		}
	}
	return false
}

// newHash returns the digest constructor for an algorithm, and whether the algorithm
// is a `-sess` variant.
//
// The empty algorithm is MD5: RFC 7616 §3.3 makes MD5 the default when the parameter
// is absent, and a challenge without one is common. Anything unrecognised is an
// error rather than a default, because computing a response under the wrong hash and
// sending it is worse than not sending it — it is a failed authentication attempt
// against the operator's real account, logged at the target.
func newHash(algorithm string) (func() hash.Hash, bool, error) {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "", "MD5":
		return md5.New, false, nil
	case "MD5-SESS":
		return md5.New, true, nil
	case "SHA-256":
		return sha256.New, false, nil
	case "SHA-256-SESS":
		return sha256.New, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported digest algorithm %q: this build implements MD5, MD5-sess, SHA-256 and SHA-256-sess", algorithm)
	}
}

// ParseChallenge reads the value of one `WWW-Authenticate` header and returns the
// Digest challenge in it.
//
// # Refuse-by-default
//
// A header naming a scheme other than Digest, or a Digest challenge with no nonce,
// is an error. A nonce is the one parameter with no defensible default: without it
// there is nothing to hash against, and inventing one produces a response the server
// cannot possibly accept.
//
// A single header can carry several challenges (`Basic realm="x", Digest ...`). Only
// the Digest one is read here; a target offering both is answered with Digest,
// because a rule that says digest asked for digest.
func ParseChallenge(header string) (Challenge, error) {
	rest := header
	for {
		trimmed := strings.TrimLeft(rest, " \t,")
		if trimmed == "" {
			return Challenge{}, fmt.Errorf("no Digest challenge in %q", header)
		}
		space := strings.IndexAny(trimmed, " \t")
		if space < 0 {
			return Challenge{}, fmt.Errorf("no Digest challenge in %q", header)
		}
		scheme := trimmed[:space]
		params := trimmed[space+1:]
		if strings.EqualFold(scheme, "Digest") {
			return parseDigestParams(params)
		}
		// Not Digest: skip this scheme's parameters and look at the next challenge. A
		// scheme's parameter list ends at the token that is followed by a space rather
		// than an `=`, which is the next scheme name.
		next := nextChallenge(params)
		if next < 0 {
			return Challenge{}, fmt.Errorf("no Digest challenge in %q", header)
		}
		rest = params[next:]
	}
}

// startsAChallenge reports whether one comma-separated item begins a new auth-scheme
// rather than continuing the current scheme's parameter list.
//
// The grammar is genuinely ambiguous without this test: `Basic realm="x", Digest
// nonce="y"` separates two challenges with the same comma that separates two parameters.
// What distinguishes them is that an item beginning a challenge starts with a bare token —
// a scheme name, which has no `=` in it — where a parameter item starts with `name=value`.
//
// The subtlety, and the bug this replaced: it is not enough to ask whether the *item*
// contains an `=`. `Digest realm="corp"` is a single comma-separated item that carries both
// the scheme name and its first parameter, so an item-wide test for `=` finds one and
// concludes the challenge never started. `Basic realm="x", Digest realm="corp", nonce="n"`
// then parsed as "no Digest challenge here", and a target offering both schemes was
// answered with neither — an operator with a working Digest credential would have watched
// it never be presented, with the 401 as the only clue. Only the item's *first* token
// decides, which is what the grammar actually says.
func startsAChallenge(item string) bool {
	item = strings.TrimSpace(item)
	if item == "" {
		return false
	}
	first := item
	if space := strings.IndexAny(item, " \t"); space >= 0 {
		first = item[:space]
	}
	return !strings.Contains(first, "=")
}

// nextChallenge finds where the following auth-scheme starts in a parameter list, or
// -1 when the list runs to the end.
func nextChallenge(params string) int {
	inQuotes := false
	itemStart := 0
	for i := 0; i < len(params); i++ {
		switch params[i] {
		case '\\':
			if inQuotes {
				i++
			}
		case '"':
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				continue
			}
			if startsAChallenge(params[itemStart:i]) {
				return itemStart
			}
			itemStart = i + 1
		}
	}
	if startsAChallenge(params[itemStart:]) {
		return itemStart
	}
	return -1
}

// parseDigestParams reads a Digest challenge's comma-separated auth-params.
func parseDigestParams(params string) (Challenge, error) {
	out := Challenge{}
	seenNonce := false
	for _, pair := range splitParams(params) {
		// The Digest challenge ends where the next scheme begins, and it may not be the last
		// one in the header: `Digest nonce="n", Basic realm="x"` is legal. Stopping here rather
		// than reading on matters because a following scheme's parameters would otherwise be
		// folded into this challenge — `Basic realm="x"` would be read as a realm for Digest,
		// and the response would be hashed against a realm the Digest server never sent.
		if startsAChallenge(pair) {
			break
		}
		eq := strings.Index(pair, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(pair[:eq]))
		value := unquote(strings.TrimSpace(pair[eq+1:]))
		switch key {
		case "realm":
			out.Realm = value
		case "nonce":
			out.Nonce = value
			seenNonce = true
		case "opaque":
			out.Opaque = value
		case "algorithm":
			out.Algorithm = value
		case "qop":
			for _, q := range strings.Split(value, ",") {
				if q = strings.ToLower(strings.TrimSpace(q)); q != "" {
					out.QOP = append(out.QOP, q)
				}
			}
		case "stale":
			out.Stale = strings.EqualFold(value, "true")
		}
		// Unknown parameters are ignored rather than refused: RFC 7616 §3.3 permits
		// extension auth-params, and a server sending `userhash` or `charset` is
		// conformant. Ignoring one cannot produce a wrong response — only the named
		// parameters feed the hash.
	}
	if !seenNonce || out.Nonce == "" {
		return Challenge{}, fmt.Errorf("Digest challenge carries no nonce, so no response can be computed: %q", params)
	}
	if _, _, err := newHash(out.Algorithm); err != nil {
		return Challenge{}, err
	}
	if len(out.QOP) > 0 && !out.hasQOP("auth") {
		return Challenge{}, fmt.Errorf("Digest challenge offers qop=%s; this build implements qop=auth only "+
			"(auth-int hashes the request body and is refused rather than silently downgraded)", strings.Join(out.QOP, ","))
	}
	return out, nil
}

// splitParams splits a comma-separated auth-param list, respecting quoted strings.
// A nonce may legally contain a comma, so strings.Split is not usable here.
func splitParams(params string) []string {
	var out []string
	inQuotes := false
	start := 0
	for i := 0; i < len(params); i++ {
		switch params[i] {
		case '\\':
			if inQuotes {
				i++
			}
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				out = append(out, strings.TrimSpace(params[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(params[start:]))
	return out
}

// unquote strips surrounding quotes and unescapes a quoted-string.
func unquote(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	inner := value[1 : len(value)-1]
	if !strings.Contains(inner, `\`) {
		return inner
	}
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' && i+1 < len(inner) {
			i++
			b.WriteByte(inner[i])
			continue
		}
		b.WriteByte(inner[i])
	}
	return b.String()
}

// cnonce returns a fresh client nonce.
//
// From crypto/rand, not math/rand: the client nonce is what stops a server (or
// anyone who has recorded one exchange) from precomputing responses, so a
// predictable one silently removes the protection the parameter exists for.
func cnonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating a client nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// hexHash returns the lowercase hex digest of the joined parts, colon-separated —
// the "H(data)" of RFC 7616 with the ":" concatenation the spec always applies.
func hexHash(newH func() hash.Hash, parts ...string) string {
	h := newH()
	for i, part := range parts {
		if i > 0 {
			h.Write([]byte(":"))
		}
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// digestResponse builds the `Authorization: Digest ...` value for one request.
//
// nc is the count for this nonce, already incremented by the caller under the store
// lock so two concurrent requests cannot spend the same value.
func digestResponse(cred Credential, ch Challenge, method, uri string, nc uint32) (string, error) {
	newH, sess, err := newHash(ch.Algorithm)
	if err != nil {
		return "", err
	}
	client, err := cnonce()
	if err != nil {
		return "", err
	}

	ha1 := hexHash(newH, cred.Username, ch.Realm, cred.password)
	if sess {
		// The -sess variants rebind HA1 to this nonce pair, so a captured HA1 cannot be
		// replayed against a later nonce.
		ha1 = hexHash(newH, ha1, ch.Nonce, client)
	}
	ha2 := hexHash(newH, method, uri)

	useQOP := ch.hasQOP("auth")
	var response string
	if useQOP {
		response = hexHash(newH, ha1, ch.Nonce, fmt.Sprintf("%08x", nc), client, "auth", ha2)
	} else {
		// RFC 2069: no qop, no nc, no cnonce in the response hash — and none of them in
		// the header either, because a server implementing only 2069 rejects parameters
		// it does not know.
		response = hexHash(newH, ha1, ch.Nonce, ha2)
	}

	parts := []string{
		fmt.Sprintf("username=%s", quoted(cred.Username)),
		fmt.Sprintf("realm=%s", quoted(ch.Realm)),
		fmt.Sprintf("nonce=%s", quoted(ch.Nonce)),
		fmt.Sprintf("uri=%s", quoted(uri)),
		fmt.Sprintf("response=%s", quoted(response)),
	}
	if ch.Algorithm != "" {
		// Echoed unquoted: algorithm is a token, and quoting it breaks servers that
		// compare it literally.
		parts = append(parts, "algorithm="+ch.Algorithm)
	}
	if useQOP {
		parts = append(parts,
			"qop=auth",
			fmt.Sprintf("nc=%08x", nc),
			fmt.Sprintf("cnonce=%s", quoted(client)),
		)
	}
	if ch.Opaque != "" {
		parts = append(parts, fmt.Sprintf("opaque=%s", quoted(ch.Opaque)))
	}
	return "Digest " + strings.Join(parts, ", "), nil
}

// quoted renders a quoted-string, escaping the two characters the grammar reserves.
// A username or realm containing a quote would otherwise terminate the value early
// and produce a header the server parses as different parameters entirely.
func quoted(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// basicHeader renders RFC 7617 credentials.
func basicHeader(cred Credential) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.password))
}

// Authorization returns the `Authorization` header value to present for one request,
// and whether there is one to present.
//
// # Why Digest can answer "not yet"
//
// Basic is preemptive: the header is computable from the rule alone, so a matching
// rule always produces one. Digest cannot be — the response hashes a server-chosen
// nonce, so the first request to a host has nothing to hash and this returns false.
// The caller sends unauthenticated, gets a 401, calls Learn with the challenge, and
// asks again. From then on the cached challenge answers on the first attempt.
//
// That two-phase shape is why this is a lookup rather than a "make me a header":
// "there is no header yet" is a real and expected answer, and collapsing it into an
// error would make the normal first request look like a failure.
func (c *Credentials) Authorization(host, method, uri string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var rule Credential
	found := false
	for _, candidate := range c.rules {
		if matchHost(candidate.Host, host) {
			rule = candidate
			found = true
			break
		}
	}
	if !found {
		return "", false
	}

	switch rule.Scheme {
	case SchemeBasic:
		return basicHeader(rule), true
	case SchemeNTLMv2:
		// NTLMv2 sends NEGOTIATE preemptively, like Basic: the type-1 message carries no
		// credential, only the flags this build asks for, so there is nothing to wait for
		// before sending it. The 401's CHALLENGE_MESSAGE is what is learned from.
		state, ok := c.ntlm[host]
		if !ok {
			negotiate := ntlmNegotiateMessage()
			c.ntlm[host] = &ntlmSession{negotiate: negotiate}
			return "NTLM " + base64.StdEncoding.EncodeToString(negotiate), true
		}
		// A challenge already learned: answer it. The request carrying this header is the
		// bounded retry, so the authenticate leg goes out with the answer computed against
		// the challenge as it was received.
		header, err := ntlmAnswer(rule, state.negotiate, state.challenge)
		if err != nil {
			// A challenge that cannot be answered is reported as "no header", not as a
			// wrong one, matching the Digest branch: the request goes out unauthenticated
			// and the 401 is the caller's honest answer.
			return "", false
		}
		return header, true
	case SchemeDigest:
		state, ok := c.challenges[host]
		if !ok {
			return "", false
		}
		state.nc++
		header, err := digestResponse(rule, state.challenge, method, uri, state.nc)
		if err != nil {
			// A challenge that parsed but cannot be answered (a rand failure) is reported as
			// "no header", not as a wrong one. The request then goes out unauthenticated and
			// the 401 is the caller's honest answer.
			return "", false
		}
		return header, true
	default:
		return "", false
	}
}

// Learn records the Digest challenge from a 401 so the next request to this host can
// authenticate on its first attempt.
//
// Returns whether the challenge is usable — false means there is no Digest rule for
// this host, or the header carried nothing this build can answer. The error explains
// which, for a caller that wants to report why a credential did not apply; a caller
// that only wants to know whether to retry can read the bool.
//
// A realm mismatch against a rule that named one is refused: a rule scoped to a
// realm is an operator saying "these credentials are for that realm", and presenting
// them to a different one is exactly the credential-to-the-wrong-place mistake the
// field exists to prevent.
func (c *Credentials) Learn(host, wwwAuthenticate string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var rule Credential
	found := false
	for _, candidate := range c.rules {
		if matchHost(candidate.Host, host) {
			rule = candidate
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}
	if rule.Scheme == SchemeNTLMv2 {
		// The NTLM leg learns raw bytes, not a Digest header. The blob is decoded and
		// validated here, against the store's lock, so a hostile payload is refused
		// before it is ever hashed — and the error travels to the caller that reports why
		// a credential did not apply.
		msg, err := ntlmChallengeBlob(wwwAuthenticate)
		if err != nil {
			return false, err
		}
		if _, err := parseChallenge(msg); err != nil {
			return false, err
		}
		state, ok := c.ntlm[host]
		if !ok {
			// No NEGOTIATE has gone out yet, so there is no exchange to answer: the
			// challenge is kept and the next Authorization call sends the type-1 message,
			// after which the following one carries the authenticate leg. This is the
			// same "works for a host that challenged on a PREVIOUS request" shape the
			// Digest branch documents — a first-request 401 is learned, not answered.
			c.ntlm[host] = &ntlmSession{negotiate: ntlmNegotiateMessage(), challenge: msg}
			return true, nil
		}
		if state.challenge != nil && bytes.Equal(state.challenge, msg) {
			// The same challenge message came back: the credential was rejected rather
			// than the nonce having expired, so re-learning it would loop. Reported as
			// unusable for the same reason the Digest branch reports it.
			return false, nil
		}
		state.challenge = msg
		return true, nil
	}
	if rule.Scheme != SchemeDigest {
		return false, nil
	}
	challenge, err := ParseChallenge(wwwAuthenticate)
	if err != nil {
		return false, err
	}
	if rule.Realm != "" && challenge.Realm != rule.Realm {
		return false, fmt.Errorf("rule for %s is scoped to realm %q but %s challenged with realm %q; "+
			"credentials were not presented", rule.Host, rule.Realm, host, challenge.Realm)
	}
	if existing, ok := c.challenges[host]; ok && existing.challenge.Nonce == challenge.Nonce {
		// The same nonce came back: the credential was rejected rather than the nonce
		// having expired, so re-learning it would loop. Reported as unusable so the
		// caller stops retrying and surfaces the 401.
		return false, nil
	}
	c.challenges[host] = &digestState{challenge: challenge}
	return true, nil
}

// forgetMatching drops cached challenges for every host a changed pattern covers.
// Called with the lock held from Add and Remove.
func (c *Credentials) forgetMatching(pattern string) {
	for host := range c.challenges {
		if matchHost(pattern, host) {
			delete(c.challenges, host)
		}
	}
	// The NTLMv2 cache answers the same question and so dies the same death: a stale
	// challenge replayed under a changed rule fails, and the failure would look like the
	// new password being wrong.
	for host := range c.ntlm {
		if matchHost(pattern, host) {
			delete(c.ntlm, host)
		}
	}
}
