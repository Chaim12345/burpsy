package scanner

// JWT algorithm confusion (RS/PS/ES -> HS256), burpsy's own row "JWT algorithm confusion"
// (b5003430, BurpsyNativeRows), decided inside the "JWT signature not verified" differential.
//
// # The defect
//
// A verifier that takes the algorithm from the token's header and the key from its key store,
// without pinning which algorithm family that key may be used with, verifies an "HS256" token with
// HMAC keyed by the bytes it holds for the RSA or EC public key. Those bytes are public, so anyone
// can mint a token the server accepts.
//
// # Where the public key comes from
//
// Only keys the target has itself disclosed, in this order of preference:
//
//   - the token's own jwk or x5c header;
//   - the project's captured traffic for the same origin (scheme, host, port), newest first: a jwk
//     or x5c header of ANY JWT seen in a request or response (another endpoint's token, a cookie the
//     login set), a JWK Set or bare JWK served as a JSON response, and a PEM public key or
//     certificate in a response body (escaped JSON included);
//   - the host's published JWKS (/.well-known/jwks.json, /jwks.json, the OpenID configuration's
//     same-host jwks_uri), fetched once per origin.
//
// No key is derived from signatures. Every candidate is instead checked against the captured
// token's own signature (RS*, PS*, ES*): verification is cheap and deterministic, and when one or
// more candidates verify, only those are tried — a key that does not verify the token is not the
// key the server verifies it with. When none verifies (an algorithm this file does not verify, or
// a token whose key was never disclosed), up to jwtMaxCandidateKeys unverified candidates are
// tried, kid matches first, and the finding says the key was not matched to the token.
//
// HMAC is keyed by exact bytes, so each key is tried in each encoding a verifier plausibly holds:
// PEM SubjectPublicKeyInfo with and without the final newline, DER SubjectPublicKeyInfo (what
// Java's Key.getEncoded returns), PEM and DER PKCS#1 for RSA, and the compact JWK JSON.
//
// # The evidence rule
//
// The confused token is reported only when, on top of the probe's controls (an altered-signature
// token refused, a tokenless request answered differently, a stripped-signature token refused):
//
//   - the confused token gets the original token's answer;
//   - the SAME header and claims HS256-signed with a random 32-byte key are refused — so the server
//     is not accepting any HS256 token, and acceptance proves it ran HMAC with the public key;
//   - all of it is observed twice: the confused token, the original, the random-key control and the
//     altered-signature control are each sent again and answer the same way.
//
// A random-key HS256 token that IS accepted (twice) is "JWT signature not verified" — the server
// takes HS256 tokens without checking them — and no confusion is reported, because nothing about
// the public key is shown.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha512" // SHA-384 and SHA-512 for the RS/PS/ES 384 and 512 verifications
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/core"
)

// IssueJWTAlgorithmConfusion is burpsy's row for an RS/ES-to-HS256 algorithm confusion.
const IssueJWTAlgorithmConfusion = "JWT algorithm confusion"

type jwtForgery struct{ tok, how string }

// jwtConfusionForgery is one confused token: the key it was keyed with and the encoding.
type jwtConfusionForgery struct {
	tok string
	key jwtKey
	enc string
}

// jwtConfusionFindings decides the confusion row over a probe whose garbage and stripped controls
// were both refused. It returns at most one finding: the confusion row, or — when an HS256 token
// signed with a random key is accepted — "JWT signature not verified".
func jwtConfusionFindings(ctx context.Context, cc *CheckContext, p *jwtProbe) ([]*Finding, error) {
	t := p.token
	if !jwtAsymmetric(t.Header.Alg) {
		return nil, nil
	}
	header := map[string]any{"alg": "HS256"}
	passthroughHeaderFields(header, t.Header, true)
	randomKey := make([]byte, 32)
	if _, err := rand.Read(randomKey); err != nil {
		return nil, fmt.Errorf("random HMAC key for the confusion control: %w", err)
	}
	randomTok, err := jwtSignHS256(header, t.RawPayload, randomKey)
	if err != nil {
		return nil, err
	}
	randomAccepted, err := p.accepted(ctx, randomTok)
	if err != nil {
		return nil, err
	}
	if randomAccepted {
		if ok, err := p.confirm(ctx, randomTok); err != nil || !ok {
			return nil, err
		}
		return []*Finding{buildHeaderFinding(cc, "JWT signature not verified", "high", "firm", randomTok,
			fmt.Sprintf("the %s token's claims re-signed as HS256 with a random key were accepted like the original "+
				"(HTTP %d, twice), while the original with an altered signature and the request with no token were "+
				"answered differently: HS256 tokens are accepted without checking their signature", t.Header.Alg, p.baseCode))}, nil
	}

	keys := jwtCandidateKeys(ctx, cc, t)
	for _, f := range jwtConfusionTokens(t, keys) {
		ok, err := p.accepted(ctx, f.tok)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		// Second observation of everything the verdict rests on.
		if ok, err := p.confirm(ctx, f.tok); err != nil || !ok {
			return nil, err
		}
		for _, control := range []string{randomTok, p.garbageTok} {
			again, err := p.send(ctx, control)
			if err != nil {
				return nil, err
			}
			if p.base.SameShape(again) {
				return nil, nil
			}
		}
		matched := "the key verifies the captured token's own " + t.Header.Alg + " signature"
		if !f.key.verifies {
			matched = "the key was NOT matched to the captured token's signature (its algorithm could not be verified here)"
		}
		return []*Finding{buildHeaderFinding(cc, IssueJWTAlgorithmConfusion, "high", "certain", f.tok,
			fmt.Sprintf("the %s token re-signed as HS256 with the server's public key (%s, %s) as the HMAC secret was "+
				"accepted like the original (HTTP %d), sent twice; %s. The same claims HS256-signed with a random key "+
				"and the original with an altered signature were each refused twice, a token with its signature "+
				"stripped was refused, and the request with no token was answered differently: the server ran "+
				"HMAC keyed with its own public key", t.Header.Alg, f.key.source, f.enc, p.baseCode, matched))}, nil
	}
	return nil, nil
}

// jwtConfusionTokens signs the token as HS256 with each candidate key, in each encoding.
func jwtConfusionTokens(t JWTToken, keys []jwtKey) []jwtConfusionForgery {
	var out []jwtConfusionForgery
	for _, k := range keys {
		for _, enc := range jwtKeyEncodings(k.pub) {
			header := map[string]any{"alg": "HS256"}
			passthroughHeaderFields(header, t.Header, true)
			tok, err := jwtSignHS256(header, t.RawPayload, enc.bytes)
			if err != nil {
				continue
			}
			out = append(out, jwtConfusionForgery{tok: tok, key: k, enc: enc.name})
		}
	}
	return out
}

type jwtKey struct {
	pub    any
	source string
	kid    string
	// verifies is set when the key verifies the captured token's own signature.
	verifies bool
}

type jwtKeyEncoding struct {
	name  string
	bytes []byte
}

// jwtKeyEncodings renders a public key the ways a verifier plausibly stores it. HMAC is keyed by the
// exact bytes, so each representation is a separate guess.
func jwtKeyEncodings(pub any) []jwtKeyEncoding {
	var out []jwtKeyEncoding
	if spki, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
		out = append(out,
			jwtKeyEncoding{"PEM SubjectPublicKeyInfo", p},
			jwtKeyEncoding{"PEM SubjectPublicKeyInfo without the final newline", []byte(strings.TrimRight(string(p), "\n"))},
			jwtKeyEncoding{"DER SubjectPublicKeyInfo", spki})
	}
	if rsaPub, ok := pub.(*rsa.PublicKey); ok {
		der := x509.MarshalPKCS1PublicKey(rsaPub)
		out = append(out,
			jwtKeyEncoding{"PEM PKCS#1", pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})},
			jwtKeyEncoding{"DER PKCS#1", der})
	}
	if j := jwkJSONOf(pub); j != nil {
		out = append(out, jwtKeyEncoding{"JWK JSON", j})
	}
	return out
}

// jwkJSONOf is the public key as a compact JWK with its required members in lexicographic order
// (the RFC 7638 thumbprint form), or nil for a key type it does not render.
func jwkJSONOf(pub any) []byte {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return []byte(fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
			b64urlEncode(big.NewInt(int64(k.E)).Bytes()), b64urlEncode(k.N.Bytes())))
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		return []byte(fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			k.Curve.Params().Name, b64urlEncode(k.X.FillBytes(make([]byte, size))), b64urlEncode(k.Y.FillBytes(make([]byte, size)))))
	}
	return nil
}

// jwtMaxCandidateKeys bounds the unverified keys tried; each costs one probe per encoding.
const jwtMaxCandidateKeys = 3

// jwtCandidateKeys collects the public keys the server may verify with (see the file comment) and
// keeps the ones that verify the token's own signature, or failing that up to jwtMaxCandidateKeys.
func jwtCandidateKeys(ctx context.Context, cc *CheckContext, t JWTToken) []jwtKey {
	var all []jwtKey
	all = append(all, jwtKeysInHeader(t, "from the token's jwk header", "from the token's x5c certificate")...)
	all = append(all, jwtHistoryKeys(cc)...)
	all = append(all, jwtHostKeys(ctx, cc)...)
	return jwtRankKeys(t, all)
}

// jwtRankKeys de-duplicates keys and orders them: those that verify t's signature (and nothing else
// when there are any), then kid matches, then the rest in collection order, capped.
func jwtRankKeys(t JWTToken, all []jwtKey) []jwtKey {
	var uniq []jwtKey
	for _, k := range all {
		dup := false
		for _, u := range uniq {
			if jwtSameKey(u.pub, k.pub) {
				dup = true
				break
			}
		}
		if !dup {
			uniq = append(uniq, k)
		}
	}
	var verified, matched, rest []jwtKey
	for _, k := range uniq {
		switch {
		case jwtSignatureVerifiesWith(t, k.pub):
			k.verifies = true
			verified = append(verified, k)
		case t.Header.Kid != "" && k.kid == t.Header.Kid:
			matched = append(matched, k)
		default:
			rest = append(rest, k)
		}
	}
	if len(verified) > 0 {
		return verified
	}
	out := append(matched, rest...)
	if len(out) > jwtMaxCandidateKeys {
		out = out[:jwtMaxCandidateKeys]
	}
	return out
}

func jwtSameKey(a, b any) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}

// jwtSignatureVerifiesWith reports whether pub verifies t's signature under t's own RS*, PS* or ES*
// algorithm. Any other algorithm, or a key of the wrong type, is false.
func jwtSignatureVerifiesWith(t JWTToken, pub any) bool {
	alg := strings.ToUpper(t.Header.Alg)
	if len(alg) != 5 {
		return false
	}
	var h crypto.Hash
	switch alg[2:] {
	case "256":
		h = crypto.SHA256
	case "384":
		h = crypto.SHA384
	case "512":
		h = crypto.SHA512
	default:
		return false
	}
	sig, ok := b64urlDecode(t.RawSignature)
	if !ok || !h.Available() {
		return false
	}
	d := h.New()
	d.Write([]byte(t.RawHeader + "." + t.RawPayload))
	sum := d.Sum(nil)
	switch alg[:2] {
	case "RS":
		k, ok := pub.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(k, h, sum, sig) == nil
	case "PS":
		k, ok := pub.(*rsa.PublicKey)
		return ok && rsa.VerifyPSS(k, h, sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}) == nil
	case "ES":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig)%2 != 0 || len(sig) == 0 {
			return false
		}
		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])
		return ecdsa.Verify(k, sum, r, s)
	}
	return false
}

// jwtKeysInHeader turns a token's jwk and x5c headers into keys.
func jwtKeysInHeader(t JWTToken, jwkSource, x5cSource string) []jwtKey {
	var keys []jwtKey
	if t.Header.Jwk != nil {
		if pub := jwkPublicKey(t.Header.Jwk); pub != nil {
			keys = append(keys, jwtKey{pub: pub, source: jwkSource, kid: stringField(t.Header.Jwk, "kid")})
		}
	}
	if len(t.Header.X5c) > 0 {
		if der, err := base64.StdEncoding.DecodeString(t.Header.X5c[0]); err == nil {
			if cert, err := x509.ParseCertificate(der); err == nil {
				keys = append(keys, jwtKey{pub: cert.PublicKey, source: x5cSource})
			}
		}
	}
	return keys
}

// jwkPublicKey turns an RSA or EC public JWK into a key, or nil.
func jwkPublicKey(m map[string]any) any {
	switch stringField(m, "kty") {
	case "RSA":
		n, okN := jwkBigInt(m, "n")
		e, okE := jwkBigInt(m, "e")
		if !okN || !okE || !e.IsInt64() || n.Sign() <= 0 {
			return nil
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}
	case "EC":
		curve := ecCurveNamed(stringField(m, "crv"))
		x, okX := jwkBigInt(m, "x")
		y, okY := jwkBigInt(m, "y")
		if curve == nil || !okX || !okY || !curve.IsOnCurve(x, y) {
			return nil
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Keys disclosed in the captured traffic
// ---------------------------------------------------------------------------

const (
	// jwtMaxHistoryScan bounds the captured exchanges searched for disclosed keys, newest first.
	jwtMaxHistoryScan = 2000
	// jwtMaxHistoryKeys bounds the distinct keys collected from them.
	jwtMaxHistoryKeys = 16
	// jwtMaxScannedMessage bounds the bytes of one message searched.
	jwtMaxScannedMessage = 1 << 20
)

// jwtHistoryKeys collects the public keys the same origin disclosed in captured traffic.
func jwtHistoryKeys(cc *CheckContext) []jwtKey {
	if cc == nil || cc.Scanner == nil || cc.Scanner.store == nil || cc.Exchange == nil {
		return nil
	}
	ex := cc.Exchange
	all := cc.Scanner.store.Exchanges()
	var keys []jwtKey
	scanned := 0
	for i := len(all) - 1; i >= 0 && scanned < jwtMaxHistoryScan && len(keys) < jwtMaxHistoryKeys; i-- {
		e := all[i]
		if e == nil || e.TLS != ex.TLS || e.Port != ex.Port || !strings.EqualFold(e.Host, ex.Host) {
			continue
		}
		scanned++
		where := fmt.Sprintf("%s %s (exchange %d)", e.Method, e.Path, e.ID)
		keys = append(keys, jwtKeysInMessage(jwtCapped(requestRaw(cc.Scanner, e)), "request to "+where)...)
		keys = append(keys, jwtKeysInMessage(jwtCapped(responseRaw(cc.Scanner, e)), "response to "+where)...)
	}
	return keys
}

func jwtCapped(s string) string {
	if len(s) > jwtMaxScannedMessage {
		return s[:jwtMaxScannedMessage]
	}
	return s
}

// jwtKeysInMessage finds public keys in one raw HTTP message: the jwk/x5c headers of any JWT in it,
// a JSON body that is a JWK Set or a JWK, and PEM public keys or certificates in the body.
func jwtKeysInMessage(raw, where string) []jwtKey {
	if raw == "" {
		return nil
	}
	var keys []jwtKey
	for _, cand := range jwtCandidatesIn(raw) {
		t := ParseJWT(cand)
		if t.ParseError != "" {
			continue
		}
		keys = append(keys, jwtKeysInHeader(t, "the jwk header of a JWT in the "+where,
			"the x5c header of a JWT in the "+where)...)
	}
	_, body, ok := splitHeadAndBody([]byte(raw))
	if !ok || len(body) == 0 {
		return keys
	}
	var doc any
	if json.Unmarshal(body, &doc) == nil {
		for _, m := range jwkMembersOf(doc) {
			if pub := jwkPublicKey(m); pub != nil {
				keys = append(keys, jwtKey{pub: pub, source: "a JWK in the " + where, kid: stringField(m, "kid")})
			}
		}
	}
	return append(keys, jwtPEMKeysIn(string(body), "a PEM block in the "+where)...)
}

// jwtPEMKeysIn decodes every PEM public key, RSA public key and certificate in text, including one
// carried in a JSON string ("\n" and "\/" escapes).
func jwtPEMKeysIn(text, source string) []jwtKey {
	if !strings.Contains(text, "-----BEGIN ") {
		return nil
	}
	if strings.Contains(text, `\n`) {
		text = strings.NewReplacer(`\r\n`, "\n", `\n`, "\n", `\/`, "/").Replace(text)
	}
	// pem.Decode wants a block to begin a line; a key quoted in JSON or HTML does not.
	text = strings.ReplaceAll(text, "-----BEGIN ", "\n-----BEGIN ")
	var keys []jwtKey
	rest := []byte(text)
	for len(keys) < jwtMaxHistoryKeys {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		var pub any
		switch block.Type {
		case "PUBLIC KEY":
			pub, _ = x509.ParsePKIXPublicKey(block.Bytes)
		case "RSA PUBLIC KEY":
			pub, _ = x509.ParsePKCS1PublicKey(block.Bytes)
		case "CERTIFICATE":
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				pub = cert.PublicKey
			}
		}
		switch pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			keys = append(keys, jwtKey{pub: pub, source: source})
		}
	}
	return keys
}

// ---------------------------------------------------------------------------
// Keys the host publishes
// ---------------------------------------------------------------------------

// jwtHostKeyEntry is one origin's published keys, fetched once per scanner (ActiveScanner.jwtKeys).
type jwtHostKeyEntry struct {
	once sync.Once
	keys []jwtKey
}

// jwtHostKeys fetches the host's JWKS from the conventional locations, through the scope-enforcing
// sender. Only same-host jwks_uri values are followed.
func jwtHostKeys(ctx context.Context, cc *CheckContext) []jwtKey {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil
	}
	ex := cc.Exchange
	cacheKey := fmt.Sprintf("%v|%s|%d", ex.TLS, ex.Host, ex.Port)
	v, _ := cc.Scanner.jwtKeys.LoadOrStore(cacheKey, &jwtHostKeyEntry{})
	entry := v.(*jwtHostKeyEntry)
	entry.once.Do(func() { entry.keys = jwtFetchHostKeys(ctx, cc.Scanner, ex) })
	return entry.keys
}

func jwtFetchHostKeys(ctx context.Context, s *ActiveScanner, ex *core.Exchange) []jwtKey {
	get := func(path string) []byte {
		resp := s.sendTestRequestFull(ctx, ex, "GET", path, nil)
		if resp == nil || resp.StatusCode != 200 {
			return nil
		}
		decodeTypedResponse(resp)
		return resp.Body
	}
	paths := []string{"/.well-known/jwks.json", "/jwks.json"}
	if body := get("/.well-known/openid-configuration"); body != nil {
		var conf struct {
			JwksURI string `json:"jwks_uri"`
		}
		if json.Unmarshal(body, &conf) == nil && conf.JwksURI != "" {
			if u, err := url.Parse(conf.JwksURI); err == nil && strings.EqualFold(u.Hostname(), ex.Host) && u.Path != "" {
				paths = append([]string{u.RequestURI()}, paths...)
			}
		}
	}
	var keys []jwtKey
	for _, path := range paths {
		body := get(path)
		if body == nil {
			continue
		}
		var doc any
		if json.Unmarshal(body, &doc) != nil {
			continue
		}
		for _, m := range jwkMembersOf(doc) {
			if pub := jwkPublicKey(m); pub != nil {
				keys = append(keys, jwtKey{pub: pub, source: "published at " + path, kid: stringField(m, "kid")})
			}
		}
		if len(keys) > 0 {
			return keys
		}
	}
	return nil
}
