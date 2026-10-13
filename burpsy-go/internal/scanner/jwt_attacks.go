package scanner

// Active JWT verification checks, decided by a differential with two controls.
//
// # The evidence rule
//
// Every forged token here is judged against the SAME three responses, sent through one harness:
//
//   - the original token (the harness baseline): what "accepted" looks like;
//   - a garbage-signature control: the original header and payload with every signature byte
//     altered. A verifier that checks anything at all rejects it;
//   - a tokenless control: the token's bytes removed from the request.
//
// A forgery is "accepted" only when its response has the baseline's shape (status and body, with the
// token strings masked out of both) AND the garbage control did not. Then:
//
//   - the tokenless control answering like the baseline means the endpoint does not depend on the
//     token at all, so nothing about verification can be shown and no row is reported;
//   - a baseline that is itself an error (status >= 400) is not an authenticated response to compare
//     against, so nothing is reported;
//   - the garbage control answering like the baseline is "JWT signature not verified", reported ONCE
//     by that row. The none / jwk / jku / x5u rows stand down, because every one of their forgeries is
//     explained by the server not checking signatures, and reporting each would be one defect counted
//     five times.
//
// An accepted forgery is sent a second time and the original once more before anything is reported:
// a response that changed because the session expired or the endpoint is non-deterministic does not
// survive that re-check.
//
// # Techniques (jwt_tool's playbook, decided by the rule above)
//
//   - signature not verified: altered signature, stripped signature (original alg), and a token whose
//     three segments are all empty — a validator that splits on dots and treats "no parts" as valid;
//   - RS/ES -> HS algorithm confusion: its own row, "JWT algorithm confusion" (a burpsy-native row,
//     jwt_confusion.go), decided with an extra control — the same claims HS256-signed with a random
//     key must be refused — and keyed with public keys the target disclosed (token headers, captured
//     traffic, the host's JWKS);
//   - kid path traversal to /dev/null with an empty HMAC key, and kid SQL injection that selects a
//     random constant we then sign with. Again, acceptance proves our chosen key was used;
//   - alg none and its case variants ("JWT none algorithm supported");
//   - a self-signed embedded jwk ("JWT self-signed JWK header supported");
//   - a signature truncated at a NUL ("JWT signature truncated at null byte", a burpsy-native row,
//     jwt_exposure.go): "%00" plus random bytes appended to the valid signature is accepted while the
//     same bytes without the NUL are refused;
//   - expired tokens ("JWT expired token accepted", a burpsy-native row: Burp's catalogue has none).
//     Either the captured token's own exp is in the past and it is still accepted while the garbage
//     control is rejected, or — when the token's HMAC secret falls to the configured wordlist — a
//     re-signed token with exp in the past is accepted while the same re-signed token with its
//     original claims is accepted too (the positive control that our signing is right).
//
// Nothing here is destructive: every probe is a GET-shaped replay of the captured request with only
// the token's bytes changed, and the SQL kid probe selects a constant.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// jwtExpiredIssue is burpsy's own row (b5003420, BurpsyNativeRows) for a server that does not enforce
// exp. Burp's catalogue has no such issue; the native advisory carries its CWE-613.
const jwtExpiredIssue = "JWT expired token accepted"

// jwtForgeryEnabled admits the forgery rows. check_jwt_forgery is their own switch; the extended-
// active family switch still admits them, as it did before the switch existed.
func jwtForgeryEnabled(c *ScanConfig) bool {
	return c != nil && (c.CheckJwtForgery || c.CheckExtendedActive)
}

// jwtProbe is one audit's differential over the JWT in one request.
type jwtProbe struct {
	cc       *CheckContext
	h        *ProbeHarness
	raw      string
	original string
	token    JWTToken

	base     ResponseFingerprint
	baseCode int
	// garbageTok is the altered-signature control token and garbage its response.
	garbageTok      string
	garbage         ResponseFingerprint
	garbageAccepted bool
	// tokenless is true when the request without its token answers like the baseline.
	tokenless bool
	// strippedTok/strippedAccepted: the original header and payload with an empty signature.
	strippedTok      string
	strippedAccepted bool
	stripTested      bool
}

// newJWTProbe finds the request's JWT and sends the baseline and both controls. ok=false with a nil
// error means there is no JWT in the request: nothing to do.
func newJWTProbe(ctx context.Context, cc *CheckContext, row string) (*jwtProbe, bool, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, false, nil
	}
	original, token, ok := jwtFromExchange(cc)
	if !ok {
		return nil, false, nil
	}
	if err := cc.RequireEgress(); err != nil {
		return nil, false, fmt.Errorf("%s: %w", row, err)
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if !strings.Contains(raw, original) {
		return nil, false, fmt.Errorf("%s: the token was not found in the request bytes, so it could not be replaced", row)
	}
	h, err := NewProbeHarness(ctx, cc, []string{"header", "cookie"})
	if err != nil {
		return nil, false, fmt.Errorf("%s: forged-token probe not prepared: %w", row, err)
	}
	p := &jwtProbe{cc: cc, h: h, raw: raw, original: original, token: token}
	p.baseCode = h.Baseline().Status
	p.base = p.fingerprint(h.Baseline(), original)

	p.garbageTok = token.RawHeader + "." + token.RawPayload + "." + jwtAlteredSignature(token.RawSignature)
	g, err := p.send(ctx, p.garbageTok)
	if err != nil {
		return nil, false, fmt.Errorf("%s: garbage-signature control not sent: %w", row, err)
	}
	p.garbage = g
	p.garbageAccepted = p.base.SameShape(g)

	none, err := p.send(ctx, "")
	if err != nil {
		return nil, false, fmt.Errorf("%s: tokenless control not sent: %w", row, err)
	}
	p.tokenless = p.base.SameShape(none)
	return p, true, nil
}

// decidable reports whether the differential can show anything: the baseline is a success, and the
// endpoint actually depends on the token.
func (p *jwtProbe) decidable() bool {
	return p.baseCode > 0 && p.baseCode < 400 && !p.tokenless
}

// fingerprint masks every token string the exchange carried, so an endpoint that echoes the token
// it was sent does not make each forgery look like a different response.
func (p *jwtProbe) fingerprint(r ProbeResponse, sent string) ResponseFingerprint {
	body := r.Body
	for _, tok := range []string{sent, p.original} {
		if len(tok) >= 8 {
			body = strings.ReplaceAll(body, tok, "\x00jwt\x00")
		}
	}
	return NewResponseFingerprint(r.Status, body)
}

// send replays the request with the token replaced by tok.
func (p *jwtProbe) send(ctx context.Context, tok string) (ResponseFingerprint, error) {
	res, err := p.h.send(ctx, jwtReplaceToken(p.raw, p.original, tok))
	if err != nil {
		return ResponseFingerprint{}, err
	}
	return p.fingerprint(res, tok), nil
}

// accepted reports whether tok gets the original token's answer while the garbage control did not.
func (p *jwtProbe) accepted(ctx context.Context, tok string) (bool, error) {
	got, err := p.send(ctx, tok)
	if err != nil {
		return false, err
	}
	return p.base.SameShape(got) && !p.garbage.SameShape(got), nil
}

// confirm re-sends an accepted token and the original: both must still answer as the baseline did,
// and the garbage control must still be rejected. This is the second, independent observation a
// finding needs.
func (p *jwtProbe) confirm(ctx context.Context, tok string) (bool, error) {
	if tok != "" {
		ok, err := p.accepted(ctx, tok)
		if err != nil || !ok {
			return false, err
		}
	}
	again, err := p.send(ctx, p.original)
	if err != nil {
		return false, err
	}
	return p.base.SameShape(again), nil
}

// stripped tests the original header and payload with no signature at all, once per probe.
func (p *jwtProbe) stripped(ctx context.Context) (bool, error) {
	if p.stripTested {
		return p.strippedAccepted, nil
	}
	if p.token.RawSignature == "" {
		// The captured token is already unsigned; stripping it would replay the original.
		p.stripTested = true
		return false, nil
	}
	p.strippedTok = p.token.RawHeader + "." + p.token.RawPayload + "."
	ok, err := p.accepted(ctx, p.strippedTok)
	if err != nil {
		return false, err
	}
	p.stripTested, p.strippedAccepted = true, ok
	return ok, nil
}

// jwtReplaceToken swaps the first copy of original for tok. When the token sat in a body, the
// request is re-serialised so Content-Length matches the new body.
func jwtReplaceToken(raw, original, tok string) []byte {
	mutated := strings.Replace(raw, original, tok, 1)
	i := strings.Index(raw, original)
	head := strings.Index(raw, "\r\n\r\n")
	if head < 0 {
		head = strings.Index(raw, "\n\n")
	}
	if i >= 0 && head >= 0 && i > head {
		if e, err := core.ParseRequestEdit([]byte(mutated)); err == nil {
			return e.ToRaw()
		}
	}
	return []byte(mutated)
}

// jwtAlteredSignature changes every byte of a signature while keeping its length and encoding, so the
// control differs from the original in the signature alone. An empty signature becomes a non-empty
// one of HMAC-SHA256 length.
func jwtAlteredSignature(sig string) string {
	b, ok := b64urlDecode(sig)
	if !ok || len(b) == 0 {
		if sig == "" {
			return b64urlEncode(make([]byte, 32))
		}
		out := []byte(sig)
		for i := range out {
			if out[i] == 'A' {
				out[i] = 'B'
			} else {
				out[i] = 'A'
			}
		}
		return string(out)
	}
	for i := range b {
		b[i] ^= 0x5a
	}
	return b64urlEncode(b)
}

// jwtSignHS256 builds a token with the given header and raw payload segment, HMAC-SHA256 keyed by key.
func jwtSignHS256(header map[string]any, rawPayload string, key []byte) (string, error) {
	hj, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	input := b64urlEncode(hj) + "." + rawPayload
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return input + "." + b64urlEncode(mac.Sum(nil)), nil
}

func jwtAsymmetric(alg string) bool {
	a := strings.ToUpper(alg)
	return strings.HasPrefix(a, "RS") || strings.HasPrefix(a, "PS") || strings.HasPrefix(a, "ES")
}

// ---------------------------------------------------------------------------
// JWT signature not verified
// ---------------------------------------------------------------------------

// jwtSignatureCheck is the "JWT signature not verified" row and, beside it, the burpsy-native expired-
// token row.
func jwtSignatureCheck(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	const row = "JWT signature not verified"
	p, ok, err := newJWTProbe(ctx, cc, row)
	if err != nil || !ok {
		return nil, err
	}
	if !p.decidable() {
		return nil, nil
	}
	if p.garbageAccepted {
		// Second observation: the altered signature is still answered as the original, and so is
		// the original itself.
		again, err := p.send(ctx, p.garbageTok)
		if err != nil || !p.base.SameShape(again) {
			return nil, err
		}
		if ok, err := p.confirm(ctx, ""); err != nil || !ok {
			return nil, err
		}
		return []*Finding{buildHeaderFinding(cc, row, "high", "firm", p.garbageTok,
			fmt.Sprintf("a token whose signature bytes were all altered got the same response as the original (HTTP %d), "+
				"while the same request without a token did not: the signature is not checked", p.baseCode))}, nil
	}

	var out []*Finding
	// Algorithm confusion has its own row (jwt_confusion.go). It is decided only when the stripped
	// token was refused: an unsigned token accepted explains any forgery, and is reported below.
	stripped, err := p.stripped(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", row, err)
	}
	reported := false
	if !stripped {
		conf, err := jwtConfusionFindings(ctx, cc, p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", row, err)
		}
		for _, f := range conf {
			reported = reported || f.Name == row
		}
		out = append(out, conf...)
	}

	type attempt struct {
		tok, how, confidence string
	}
	var tries []attempt
	tries = append(tries, attempt{"", "stripped", "firm"})
	tries = append(tries, attempt{"..", "a token whose header, payload and signature are all empty was accepted", "firm"})
	for _, f := range jwtKidForgeries(p.token) {
		tries = append(tries, attempt{f.tok, f.how, "certain"})
	}
	if reported {
		// The random-key HS256 control already reported this row; it is one defect.
		tries = nil
	}

	for _, a := range tries {
		var accepted bool
		tok, how := a.tok, a.how
		if how == "stripped" {
			accepted, err = p.stripped(ctx)
			tok, how = p.strippedTok, fmt.Sprintf("the token with its signature removed (alg %q kept) was accepted", p.token.Header.Alg)
		} else {
			accepted, err = p.accepted(ctx, tok)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", row, err)
		}
		if !accepted {
			continue
		}
		if ok, err := p.confirm(ctx, tok); err != nil || !ok {
			return nil, err
		}
		out = append(out, buildHeaderFinding(cc, row, "high", a.confidence, tok,
			fmt.Sprintf("%s: it got the same response as the original token (HTTP %d), sent twice, while a token "+
				"with an altered signature and the request with no token were both answered differently", how, p.baseCode)))
		break
	}
	if f := jwtNullByteFinding(ctx, cc, p); f != nil {
		out = append(out, f)
	}
	if f := jwtExpiredFinding(ctx, cc, p); f != nil {
		out = append(out, f)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// JWT none algorithm supported / self-signed JWK header supported
// ---------------------------------------------------------------------------

// jwtForgeryRow decides one forgery row. It stands down when the garbage control or the stripped
// token is accepted: those are "signature not verified", reported once by that row.
func jwtForgeryRow(row string, forge func(JWTToken) ([]string, error)) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		p, ok, err := newJWTProbe(ctx, cc, row)
		if err != nil || !ok {
			return nil, err
		}
		if !p.decidable() || p.garbageAccepted {
			return nil, nil
		}
		if s, err := p.stripped(ctx); err != nil {
			return nil, fmt.Errorf("%s: %w", row, err)
		} else if s {
			return nil, nil
		}
		forged, err := forge(p.token)
		if err != nil {
			return nil, fmt.Errorf("%s: could not forge a token to test with: %w", row, err)
		}
		if len(forged) == 0 {
			return nil, fmt.Errorf("%s: no forged token was produced, so nothing was tested", row)
		}
		for _, f := range forged {
			accepted, err := p.accepted(ctx, f)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", row, err)
			}
			if !accepted {
				continue
			}
			if ok, err := p.confirm(ctx, f); err != nil || !ok {
				return nil, err
			}
			return []*Finding{buildHeaderFinding(cc, row, "high", "firm", f,
				fmt.Sprintf("the forged token got the same response as the original (HTTP %d), sent twice, while a token "+
					"with an altered signature, the token with its signature stripped, and the request with no token were "+
					"each answered differently", p.baseCode))}, nil
		}
		return nil, nil
	}
}

// ---------------------------------------------------------------------------
// kid traversal and injection
// ---------------------------------------------------------------------------

// jwtKidForgeries are HS256 tokens whose kid steers a key lookup to a value we know: /dev/null (an
// empty key) by relative and absolute path, and a SQL lookup that selects a random constant.
func jwtKidForgeries(t JWTToken) []jwtForgery {
	var out []jwtForgery
	for _, kid := range []string{strings.Repeat("../", 12) + "dev/null", "/dev/null"} {
		header := map[string]any{"alg": "HS256", "kid": kid}
		passthroughHeaderFields(header, t.Header, false)
		if tok, err := jwtSignHS256(header, t.RawPayload, nil); err == nil {
			out = append(out, jwtForgery{tok, fmt.Sprintf(
				"kid path traversal: a token with kid %q signed with an empty HMAC key was accepted", kid)})
		}
	}
	secret := "bsy" + strings.ToLower(newProbeCanary(""))
	kid := "bsy-missing-key' UNION SELECT '" + secret + "'-- -"
	header := map[string]any{"alg": "HS256", "kid": kid}
	passthroughHeaderFields(header, t.Header, false)
	if tok, err := jwtSignHS256(header, t.RawPayload, []byte(secret)); err == nil {
		out = append(out, jwtForgery{tok, fmt.Sprintf(
			"kid injection: a token whose kid selects the constant %q, signed with that constant as the HMAC key, was accepted", secret)})
	}
	return out
}

// ---------------------------------------------------------------------------
// Expired tokens
// ---------------------------------------------------------------------------

// jwtExpiredFinding reports a server that accepts a token past its exp. The caller has established
// that the original is accepted, the garbage control rejected and the endpoint token-dependent.
func jwtExpiredFinding(ctx context.Context, cc *CheckContext, p *jwtProbe) *Finding {
	now := time.Now()
	if exp, ok := jwtNumericClaim(p.token.Payload, "exp"); ok && exp < float64(now.Add(-time.Minute).Unix()) {
		if ok, err := p.confirm(ctx, ""); err != nil || !ok {
			return nil
		}
		return buildHeaderFinding(cc, jwtExpiredIssue, "medium", "firm", p.original,
			fmt.Sprintf("the captured token expired at %s (exp %d) and is still accepted (HTTP %d, twice), while the same token "+
				"with an altered signature is rejected: the signature is verified but the expiry is not enforced",
				time.Unix(int64(exp), 0).UTC().Format(time.RFC3339), int64(exp), p.baseCode))
	}
	secret, ok := jwtRecoverHS256Secret(cc, p.token)
	if !ok {
		return nil
	}
	header := map[string]any{"alg": "HS256"}
	passthroughHeaderFields(header, p.token.Header, true)
	// Positive control: the original claims re-signed by us must be accepted, or our signing is not
	// what the server verifies and an expired-token rejection would mean nothing.
	resigned, err := jwtSignHS256(header, p.token.RawPayload, []byte(secret))
	if err != nil {
		return nil
	}
	if ok, err := p.accepted(ctx, resigned); err != nil || !ok {
		return nil
	}
	claims := map[string]any{}
	for k, v := range p.token.Payload {
		claims[k] = v
	}
	past := now.Add(-24 * time.Hour).Unix()
	claims["exp"] = past
	if _, has := claims["iat"]; has {
		claims["iat"] = past - 3600
	}
	pj, err := json.Marshal(claims)
	if err != nil {
		return nil
	}
	expired, err := jwtSignHS256(header, b64urlEncode(pj), []byte(secret))
	if err != nil {
		return nil
	}
	if ok, err := p.accepted(ctx, expired); err != nil || !ok {
		return nil
	}
	if ok, err := p.confirm(ctx, expired); err != nil || !ok {
		return nil
	}
	return buildHeaderFinding(cc, jwtExpiredIssue, "medium", "certain", expired,
		fmt.Sprintf("the token's HMAC secret is a wordlist entry, so a copy was re-signed with exp set to %s; it was accepted "+
			"(HTTP %d, twice) just as the unmodified re-signed claims were, while an altered signature was rejected: the "+
			"expiry is not enforced", time.Unix(past, 0).UTC().Format(time.RFC3339), p.baseCode))
}

func jwtNumericClaim(claims map[string]any, name string) (float64, bool) {
	switch v := claims[name].(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

// jwtRecoverHS256Secret tries the scanner's JWT wordlist against an HS256 token's signature, within
// the weak-secret check's own per-response budget.
func jwtRecoverHS256Secret(cc *CheckContext, t JWTToken) (string, bool) {
	if t.Header.Alg != "HS256" || cc.Scanner == nil {
		return "", false
	}
	sig, ok := b64urlDecode(t.RawSignature)
	if !ok {
		return "", false
	}
	_, weak := cc.Scanner.nativeChecks()
	if weak == nil {
		return "", false
	}
	input := []byte(t.RawHeader + "." + t.RawPayload)
	budget := weak.maxAttempts
	for _, candidate := range weak.wordlist.entries {
		if budget == 0 {
			return "", false
		}
		budget--
		if hmacHS256.verifies([]byte(candidate), input, sig) {
			return candidate, true
		}
	}
	return "", false
}
