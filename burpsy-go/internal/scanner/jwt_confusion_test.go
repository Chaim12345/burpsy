package scanner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// The key for /jw/confusion/der is disclosed ONLY in /jw/keyring's sample token. Audited in a store
// holding just the target, nothing may be reported: no key, no proof. With /jw/keyring captured
// first, the confusion row is reported with the key's source named. Its safe twins stay quiet with
// the key in hand.
func TestJWTAlgorithmConfusionUsesAKeyDisclosedOnlyInCapturedTraffic(t *testing.T) {
	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}
	endpoint := map[string]vulnapp.Endpoint{}
	for _, e := range vulnapp.Vulnerabilities() {
		endpoint[e.Path] = e
	}
	client := &http.Client{Timeout: 10 * time.Second}

	audit := func(t *testing.T, seedKeyring bool, target string) map[string]*Finding {
		t.Helper()
		rt := &runtimeTarget{srv: srv, host: host, port: port, store: core.NewTrafficStore(),
			exchanges: map[string]core.ExchangeID{}}
		if seedKeyring {
			rt.capture(t, client, endpoint[vulnapp.JWTKeyringPath])
		}
		id := rt.capture(t, client, endpoint[target])
		scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).
			WithConfig(&ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckJwtForgery: true})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
		out := map[string]*Finding{}
		for _, f := range findings {
			if f != nil {
				out[f.Name] = f
			}
		}
		return out
	}

	without := audit(t, false, "/jw/confusion/der")
	for _, row := range jwtRows {
		if f := without[row]; f != nil {
			t.Errorf("without the disclosing exchange, %q was reported: %s", row, f.Description)
		}
	}
	with := audit(t, true, "/jw/confusion/der")
	f := with[IssueJWTAlgorithmConfusion]
	if f == nil {
		t.Fatalf("with /jw/keyring captured, %q was not reported; rows: %s", IssueJWTAlgorithmConfusion, joinRows(with))
	}
	for _, want := range []string{"the jwk header of a JWT in the response to GET " + vulnapp.JWTKeyringPath,
		"DER SubjectPublicKeyInfo", "verifies the captured token's own RS256 signature", "random key"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("finding does not say %q: %s", want, f.Description)
		}
	}
	if with["JWT signature not verified"] != nil {
		t.Errorf("confusion was also reported as the signature row: %s", with["JWT signature not verified"].Description)
	}
	for _, safe := range []string{"/jw/safe/confusion/pin", "/jw/safe/confusion/nohs"} {
		got := audit(t, true, safe)
		for _, row := range jwtRows {
			if f := got[row]; f != nil {
				t.Errorf("%s: %q reported against a verifier that refuses HS256: %s", safe, row, f.Description)
			}
		}
	}
}

func TestJWTKeysInMessageFindsEveryDisclosureShape(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := map[string]any{"kty": "RSA", "n": b64urlEncode(rsaKey.N.Bytes()), "e": b64urlEncode(big.NewInt(int64(rsaKey.E)).Bytes())}
	hj, _ := json.Marshal(map[string]any{"alg": "RS256", "jwk": jwk})
	tok := b64urlEncode(hj) + "." + b64urlEncode([]byte(`{"sub":"x"}`)) + ".c2lnbmF0dXJl"
	spki, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	escaped, _ := json.Marshal(map[string]string{"publicKey": pemText})
	jwks, _ := json.Marshal(map[string]any{"keys": []any{jwk}})

	cases := []struct {
		name, raw string
		want      any
	}{
		{"token in a response body", "HTTP/1.1 200 OK\r\n\r\n{\"t\":\"" + tok + "\"}", &rsaKey.PublicKey},
		{"token in a request cookie", "GET / HTTP/1.1\r\nCookie: s=" + tok + "\r\n\r\n", &rsaKey.PublicKey},
		{"JWK Set body", "HTTP/1.1 200 OK\r\n\r\n" + string(jwks), &rsaKey.PublicKey},
		{"PEM body", "HTTP/1.1 200 OK\r\n\r\n" + pemText, &ecKey.PublicKey},
		{"PEM escaped in JSON", "HTTP/1.1 200 OK\r\n\r\n" + string(escaped), &ecKey.PublicKey},
	}
	for _, c := range cases {
		keys := jwtKeysInMessage(c.raw, "x")
		if len(keys) == 0 || !jwtSameKey(keys[0].pub, c.want) {
			t.Errorf("%s: key not found (got %d keys)", c.name, len(keys))
		}
	}
	hsTok := b64urlEncode([]byte(`{"alg":"HS256"}`)) + "." + b64urlEncode([]byte(`{"sub":"x"}`)) + ".c2ln"
	for _, raw := range []string{"HTTP/1.1 200 OK\r\n\r\n" + hsTok, "HTTP/1.1 200 OK\r\n\r\n-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n", ""} {
		if keys := jwtKeysInMessage(raw, "x"); len(keys) != 0 {
			t.Errorf("keys found where none is disclosed: %q", raw)
		}
	}
}

func TestJWTRankKeysKeepsOnlyTheKeyThatVerifiesTheToken(t *testing.T) {
	signer, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	in := b64urlEncode([]byte(`{"alg":"RS256","kid":"k"}`)) + "." + b64urlEncode([]byte(`{"sub":"x"}`))
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, sum[:])
	tok := ParseJWT(in + "." + b64urlEncode(sig))

	got := jwtRankKeys(tok, []jwtKey{{pub: &other.PublicKey, kid: "k"}, {pub: &signer.PublicKey}, {pub: &signer.PublicKey}})
	if len(got) != 1 || !got[0].verifies || !jwtSameKey(got[0].pub, &signer.PublicKey) {
		t.Fatalf("want only the verifying key, once; got %d keys", len(got))
	}
	// No key verifies: the kid match comes first and the cap applies.
	many := []jwtKey{{pub: &other.PublicKey}}
	for i := 0; i < 4; i++ {
		k, _ := rsa.GenerateKey(rand.Reader, 1024)
		many = append(many, jwtKey{pub: &k.PublicKey})
	}
	many[3].kid = "k"
	got = jwtRankKeys(tok, many)
	if len(got) != jwtMaxCandidateKeys || got[0].kid != "k" || got[0].verifies {
		t.Errorf("unverified ranking: %d keys, first kid %q", len(got), got[0].kid)
	}
}

func TestJWTSignatureVerifiesWithES256AndRejectsTheWrongKey(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	in := b64urlEncode([]byte(`{"alg":"ES256"}`)) + "." + b64urlEncode([]byte(`{"sub":"x"}`))
	sum := sha256.Sum256([]byte(in))
	r, s, _ := ecdsa.Sign(rand.Reader, k, sum[:])
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	tok := ParseJWT(in + "." + b64urlEncode(sig))
	if !jwtSignatureVerifiesWith(tok, &k.PublicKey) {
		t.Error("ES256 signature not verified with its own key")
	}
	if jwtSignatureVerifiesWith(tok, &wrong.PublicKey) {
		t.Error("ES256 signature verified with the wrong key")
	}
	if enc := jwtKeyEncodings(&k.PublicKey); !strings.Contains(string(enc[len(enc)-1].bytes), `"kty":"EC"`) {
		t.Errorf("last encoding is not the JWK JSON: %s", enc[len(enc)-1].name)
	}
}
