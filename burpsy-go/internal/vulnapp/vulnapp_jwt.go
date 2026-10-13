package vulnapp

// JWT verification defects, one per endpoint, each beside a verifier that gets it right.
//
// Every vulnerable endpoint here DOES check signatures in general: a token with an altered signature
// is rejected by all of them. That is what separates these rows from /rm/jwt, which checks nothing,
// and it is what the scanner's garbage-signature control relies on — a server that accepts any
// signature is one defect ("JWT signature not verified"), not one per forgery.
//
// Nothing here touches the filesystem or a database: the kid "file" lookup resolves the path
// lexically and treats /dev/null as the empty key it would read, and the kid "SQL" lookup
// pattern-matches a UNION SELECT of a quoted constant. Real crypto (HMAC-SHA256, RS256) is used
// throughout, because the property under test is cryptographic.

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
)

// jwSecret is the HS256 key the HMAC endpoints use. Not in any wordlist.
var jwSecret = []byte("jw-fixture-hs256-9c1e0f27d4b84a3a8a6e")

// jwWeakSecret is a wordlist secret, used only by the expiry pair: the scanner can only re-sign an
// expired token when it can recover the key.
var jwWeakSecret = []byte("secret")

// jwRSA is the server's RS256 key; its public half is published at /.well-known/jwks.json.
var jwRSA = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("vulnapp: generating jw rsa key: " + err.Error())
	}
	return k
}()

const jwRSAKid = "jw-rs-1"

func jwB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwMintHS(key []byte, header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	in := jwB64(h) + "." + jwB64(c)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(in))
	return in + "." + jwB64(mac.Sum(nil))
}

func jwMintRS(header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	in := jwB64(h) + "." + jwB64(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, jwRSA, crypto.SHA256, sum[:])
	if err != nil {
		panic("vulnapp: signing jw token: " + err.Error())
	}
	return in + "." + jwB64(sig)
}

var (
	jwHSToken  = jwMintHS(jwSecret, map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "alice"})
	jwRSToken  = jwMintRS(map[string]any{"alg": "RS256", "typ": "JWT", "kid": jwRSAKid}, map[string]any{"sub": "alice"})
	jwKidToken = jwMintHS(jwSecret, map[string]any{"alg": "HS256", "typ": "JWT", "kid": "main"}, map[string]any{"sub": "alice"})
	// jwExpiredToken is properly signed and expired an hour before the fixture was built.
	jwExpiredToken = jwMintHS(jwSecret, map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "alice", "exp": time.Now().Add(-time.Hour).Unix()})
	// jwWeakToken is current (exp a day ahead) and signed with the wordlist secret.
	jwWeakToken = jwMintHS(jwWeakSecret, map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "alice", "exp": time.Now().Add(24 * time.Hour).Unix()})
)

// JWTExpiryEndpoints names the routes of the burpsy-native "JWT expired token accepted" row
// (b5003420). They are declared in the manifest too; the scanner's own test drives them by name:
// vulnerable paths first, then their safe twins.
func JWTExpiryEndpoints() (vulnerable, safe []string, bearer map[string]string) {
	return []string{"/jw/expired", "/jw/expiry"}, []string{"/jw/safe/expired", "/jw/safe/expiry"},
		map[string]string{
			"/jw/expired": jwExpiredToken, "/jw/safe/expired": jwExpiredToken,
			"/jw/expiry": jwWeakToken, "/jw/safe/expiry": jwWeakToken,
		}
}

func jwBearer(tok string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok}
}

func jwtEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/jw/none", RequestHeaders: jwBearer(jwHSToken), Row: "JWT none algorithm supported",
			Note: "verifies HS256, but takes alg none (any casing) with an empty signature as valid"},
		{Path: "/jw/safe/hs", RequestHeaders: jwBearer(jwHSToken), Row: "JWT none algorithm supported", Safe: true,
			Note: "pins HS256 and verifies the signature"},

		{Path: "/jw/jwk", RequestHeaders: jwBearer(jwRSToken), Row: "JWT self-signed JWK header supported",
			Note: "verifies RS256 with the token's own embedded jwk when one is present"},
		{Path: "/jw/safe/rs", RequestHeaders: jwBearer(jwRSToken), Row: "JWT self-signed JWK header supported", Safe: true,
			Note: "pins RS256 and its own key"},

		{Path: "/jw/confusion", RequestHeaders: jwBearer(jwRSToken), Row: "JWT signature not verified",
			Note: "picks the algorithm from the header; HS256 is verified with the PEM public key as the HMAC secret"},
		{Path: "/jw/safe/rs", RequestHeaders: jwBearer(jwRSToken), Row: "JWT signature not verified", Safe: true,
			Note: "pins RS256 and its own key"},

		{Path: "/jw/kid", RequestHeaders: jwBearer(jwKidToken), Row: "JWT signature not verified",
			Note: "reads the HMAC key from a file named by kid, so ../../dev/null is an empty key"},
		{Path: "/jw/kidsql", RequestHeaders: jwBearer(jwKidToken), Row: "JWT signature not verified",
			Note: "looks the HMAC key up with kid concatenated into SQL, so a UNION SELECT chooses the key"},
		{Path: "/jw/safe/kid", RequestHeaders: jwBearer(jwKidToken), Row: "JWT signature not verified", Safe: true,
			Note: "looks kid up in a fixed map"},

		{Path: "/jw/anysig", RequestHeaders: jwBearer(jwHSToken), Row: "JWT signature not verified",
			Note: "requires three segments and a non-empty signature, and never checks the signature"},
		{Path: "/jw/nosig", RequestHeaders: jwBearer(jwHSToken), Row: "JWT signature not verified",
			Note: "verifies a signature when there is one, and accepts a token with none whatever its alg"},
		{Path: "/jw/empty", RequestHeaders: jwBearer(jwHSToken), Row: "JWT signature not verified",
			Note: "splits the token dropping empty segments and treats a token with no segments as valid"},
		{Path: "/jw/safe/hs", RequestHeaders: jwBearer(jwHSToken), Row: "JWT signature not verified", Safe: true,
			Note: "pins HS256 and verifies the signature"},

		{Path: "/jw/url?t=" + jwHSToken, Row: "Session token in URL",
			Note: "a signed JWT in a query parameter whose name says nothing"},
		{Path: "/jw/safe/url?t=release-2.4.1-build.7", Row: "Session token in URL", Safe: true,
			Note: "a dotted value in the same parameter that is not a token"},

		// The expiry routes: see JWTExpiryEndpoints.
		{Path: "/jw/expired", RequestHeaders: jwBearer(jwExpiredToken), Row: "JWT expired token accepted",
			Note: "verifies HS256, ignores exp"},
		{Path: "/jw/safe/expired", RequestHeaders: jwBearer(jwExpiredToken), Row: "JWT expired token accepted", Safe: true,
			Note: "verifies HS256 and exp"},
		{Path: "/jw/expiry", RequestHeaders: jwBearer(jwWeakToken), Row: "JWT expired token accepted",
			Note: "weak HS256 key, ignores exp"},
		{Path: "/jw/safe/expiry", RequestHeaders: jwBearer(jwWeakToken), Row: "JWT expired token accepted", Safe: true,
			Note: "weak HS256 key, enforces exp"},
	}
}

func registerJWT(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": jwRSAKid, "use": "sig", "alg": "RS256",
			"n": jwB64(jwRSA.PublicKey.N.Bytes()), "e": jwB64(big.NewInt(int64(jwRSA.PublicKey.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/jw/none", jwHandler(func(h map[string]any, in, sig string) bool {
		if alg, _ := h["alg"].(string); strings.EqualFold(alg, "none") {
			return sig == ""
		}
		return jwHSOK(h, in, sig, jwSecret)
	}, false))
	mux.HandleFunc("/jw/safe/hs", jwHandler(func(h map[string]any, in, sig string) bool {
		return jwHSOK(h, in, sig, jwSecret)
	}, false))
	mux.HandleFunc("/jw/jwk", jwHandler(func(h map[string]any, in, sig string) bool {
		if alg, _ := h["alg"].(string); alg != "RS256" {
			return false
		}
		pub := &jwRSA.PublicKey
		if jwk, ok := h["jwk"].(map[string]any); ok {
			if k, ok := finalJWKPublicKey(jwk); ok {
				pub = k
			}
		}
		return finalVerifyRS256(pub, in, sig)
	}, false))
	mux.HandleFunc("/jw/safe/rs", jwHandler(func(h map[string]any, in, sig string) bool {
		alg, _ := h["alg"].(string)
		return alg == "RS256" && finalVerifyRS256(&jwRSA.PublicKey, in, sig)
	}, false))
	mux.HandleFunc("/jw/confusion", jwHandler(func(h map[string]any, in, sig string) bool {
		switch alg, _ := h["alg"].(string); alg {
		case "RS256":
			return finalVerifyRS256(&jwRSA.PublicKey, in, sig)
		case "HS256":
			return jwHSOK(h, in, sig, jwPublicPEM())
		}
		return false
	}, false))
	mux.HandleFunc("/jw/kid", jwHandler(func(h map[string]any, in, sig string) bool {
		kid, _ := h["kid"].(string)
		var key []byte
		switch path.Join("/srv/keys", kid) {
		case "/srv/keys/main":
			key = jwSecret
		case "/dev/null":
			key = []byte{}
		default:
			return false
		}
		return jwHSOK(h, in, sig, key)
	}, false))
	mux.HandleFunc("/jw/kidsql", jwHandler(func(h map[string]any, in, sig string) bool {
		kid, _ := h["kid"].(string)
		if kid == "main" {
			return jwHSOK(h, in, sig, jwSecret)
		}
		// SELECT key FROM keys WHERE kid = '<kid>': a UNION SELECT of a quoted constant returns it.
		if m := jwUnionSelect.FindStringSubmatch(kid); m != nil {
			return jwHSOK(h, in, sig, []byte(m[1]))
		}
		return false
	}, false))
	mux.HandleFunc("/jw/safe/kid", jwHandler(func(h map[string]any, in, sig string) bool {
		kid, _ := h["kid"].(string)
		key, ok := map[string][]byte{"main": jwSecret}[kid]
		return ok && jwHSOK(h, in, sig, key)
	}, false))
	mux.HandleFunc("/jw/anysig", jwHandler(func(h map[string]any, in, sig string) bool {
		return sig != ""
	}, false))
	mux.HandleFunc("/jw/nosig", jwHandler(func(h map[string]any, in, sig string) bool {
		return sig == "" || jwHSOK(h, in, sig, jwSecret)
	}, false))
	mux.HandleFunc("/jw/empty", func(w http.ResponseWriter, r *http.Request) {
		tok, _ := rmBearerToken(r)
		// Java's String.split drops trailing empty strings, so "..", "...", "." split to nothing.
		if tok != "" && strings.Trim(tok, ".") == "" {
			fmt.Fprint(w, "Welcome, alice")
			return
		}
		jwHandler(func(h map[string]any, in, sig string) bool { return jwHSOK(h, in, sig, jwSecret) }, false)(w, r)
	})
	mux.HandleFunc("/jw/url", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>report page</body></html>")
	})
	mux.HandleFunc("/jw/safe/url", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>report page</body></html>")
	})
	mux.HandleFunc("/jw/expired", jwHandler(func(h map[string]any, in, sig string) bool {
		return jwHSOK(h, in, sig, jwSecret)
	}, false))
	mux.HandleFunc("/jw/safe/expired", jwHandler(func(h map[string]any, in, sig string) bool {
		return jwHSOK(h, in, sig, jwSecret)
	}, true))
	mux.HandleFunc("/jw/expiry", jwHandler(func(h map[string]any, in, sig string) bool {
		return jwHSOK(h, in, sig, jwWeakSecret)
	}, false))
	mux.HandleFunc("/jw/safe/expiry", jwHandler(func(h map[string]any, in, sig string) bool {
		return jwHSOK(h, in, sig, jwWeakSecret)
	}, true))
}

var jwUnionSelect = regexp.MustCompile(`(?i)'\s*UNION\s+SELECT\s+'([^']*)'`)

// jwPublicPEM is the server public key as the PEM text a confused verifier would hold.
func jwPublicPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(&jwRSA.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func jwHSOK(h map[string]any, in, sig string, key []byte) bool {
	if alg, _ := h["alg"].(string); alg != "HS256" {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(in))
	return hmac.Equal(got, mac.Sum(nil))
}

// jwHandler runs verify over a bearer token and answers 200 with the subject, or 401. With
// enforceExp, a token whose exp is in the past is rejected after the signature checks out.
func jwHandler(verify func(header map[string]any, signingInput, sig string) bool, enforceExp bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := rmBearerToken(r)
		if !ok || tok == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			http.Error(w, "malformed token", http.StatusUnauthorized)
			return
		}
		var header map[string]any
		hj, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil || json.Unmarshal(hj, &header) != nil {
			http.Error(w, "malformed header", http.StatusUnauthorized)
			return
		}
		if !verify(header, parts[0]+"."+parts[1], parts[2]) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		var claims map[string]any
		if cj, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(cj, &claims)
		}
		if exp, ok := claims["exp"].(float64); enforceExp && (!ok || int64(exp) < time.Now().Unix()) {
			http.Error(w, "token expired", http.StatusUnauthorized)
			return
		}
		sub, _ := claims["sub"].(string)
		fmt.Fprintf(w, "Welcome, %s", htmlEscape(sub))
	}
}
