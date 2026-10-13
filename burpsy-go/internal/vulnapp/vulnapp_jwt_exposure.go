package vulnapp

// JWT credential exposure and null-byte signature truncation (scanner/jwt_exposure.go,
// burpsy-react-ui-0vzb.29), each beside a twin without the defect.
//
// Every verifying endpoint here checks a real HMAC-SHA256 signature with jwSecret, so a token with an
// altered signature is refused by all of them; what differs is where the token travels and how the
// signature segment is read.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// The exposure row's name and the null-byte row's name, as the scanner reports them.
const (
	rowJWTExposed  = "JWT credential insufficiently protected"
	rowJWTNullByte = "JWT signature truncated at null byte"
)

// jxCookie is the cookie the exposure endpoints read their token from.
const jxCookie = "session"

// The login pair's tokens: each is set by its own login route only, so the cookie that stored it can
// only be found in that earlier response.
var (
	jxIssuedToken     = jwMintHS(jwSecret, map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "bob"})
	jxSafeIssuedToken = jwMintHS(jwSecret, map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "carol"})
)

func jwtExposureEndpoints() []Endpoint {
	cookie := map[string]string{"Cookie": jxCookie + "=" + jwHSToken}
	return []Endpoint{
		{Path: "/jx/cookie", RequestHeaders: cookie, Row: rowJWTExposed,
			Note: "verifies the session JWT from a cookie it (re)sets without HttpOnly or Secure, over cleartext HTTP"},
		{Path: "/jx/url?access_token=" + jwHSToken, Row: rowJWTExposed, TLS: true,
			Note: "verifies a JWT carried in the query string, over HTTPS"},
		{Path: "/jx/safe/cookie", RequestHeaders: cookie, Row: rowJWTExposed, TLS: true, Safe: true,
			Note: "verifies the session JWT from a cookie it sets HttpOnly; Secure; SameSite=Strict, over HTTPS"},
		{Path: "/jx/safe/optional", RequestHeaders: cookie, Row: rowJWTExposed, Safe: true,
			Note: "verifies the JWT when sent, in a script-readable cookie over HTTP, but answers the same without one: it grants nothing"},
		{Path: "/jx/safe/unverified", RequestHeaders: cookie, Row: rowJWTExposed, Safe: true,
			Note: "sets the JWT-shaped value in a script-readable cookie over HTTP but never reads it: not a credential"},

		// The cookie is set by an earlier login response, not by the page that reads it: the scanner has
		// to find the Set-Cookie that stored the token in the captured history.
		{Path: "/jx/login", TLS: true, Note: "issues the session JWT in a Secure cookie without HttpOnly"},
		{Path: "/jx/session", RequestHeaders: map[string]string{"Cookie": jxCookie + "=" + jxIssuedToken}, Row: rowJWTExposed, TLS: true,
			Note: "verifies the session cookie /jx/login set without HttpOnly, over HTTPS; sets no cookie itself"},
		{Path: "/jx/safe/login", TLS: true, Note: "issues the session JWT in an HttpOnly, Secure cookie"},
		{Path: "/jx/safe/session", RequestHeaders: map[string]string{"Cookie": jxCookie + "=" + jxSafeIssuedToken}, Row: rowJWTExposed, TLS: true, Safe: true,
			Note: "verifies the session cookie /jx/safe/login set HttpOnly and Secure, over HTTPS"},

		{Path: "/jx/nullbyte", RequestHeaders: jwBearer(jwHSToken), Row: rowJWTNullByte,
			Note: "cuts the signature at an encoded %00, then verifies HS256 exactly"},
		{Path: "/jx/safe/nullbyte", RequestHeaders: jwBearer(jwHSToken), Row: rowJWTNullByte, Safe: true,
			Note: "verifies the whole signature segment"},
		{Path: "/jx/safe/trailing", RequestHeaders: jwBearer(jwHSToken), Row: rowJWTNullByte, Safe: true,
			Note: "reads only the first 43 signature characters, so ANY trailing bytes pass, NUL or not: not a NUL truncation"},
	}
}

// jxVerify reports whether tok is an HS256 token signed with jwSecret, after cut has rewritten its
// signature segment.
func jxVerify(tok string, cut func(sig string) string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	return jwHSOK(map[string]any{"alg": "HS256"}, parts[0]+"."+parts[1], cut(parts[2]), jwSecret) && jxAlgHS256(parts[0])
}

// jxAlgHS256 pins the header's alg, as the forgery fixtures do.
func jxAlgHS256(rawHeader string) bool {
	hj, err := base64.RawURLEncoding.DecodeString(rawHeader)
	if err != nil {
		return false
	}
	var h map[string]any
	if json.Unmarshal(hj, &h) != nil {
		return false
	}
	alg, _ := h["alg"].(string)
	return alg == "HS256"
}

func jxWelcome(w http.ResponseWriter, ok bool) {
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	fmt.Fprint(w, "Welcome, alice")
}

func registerJWTExposure(mux *http.ServeMux) {
	whole := func(sig string) string { return sig }
	cookieToken := func(r *http.Request) string {
		c, err := r.Cookie(jxCookie)
		if err != nil {
			return ""
		}
		return c.Value
	}
	mux.HandleFunc("/jx/cookie", func(w http.ResponseWriter, r *http.Request) {
		tok := cookieToken(r)
		ok := jxVerify(tok, whole)
		if ok {
			w.Header().Add("Set-Cookie", jxCookie+"="+tok+"; Path=/")
		}
		jxWelcome(w, ok)
	})
	mux.HandleFunc("/jx/url", func(w http.ResponseWriter, r *http.Request) {
		jxWelcome(w, jxVerify(r.URL.Query().Get("access_token"), whole))
	})
	mux.HandleFunc("/jx/safe/cookie", func(w http.ResponseWriter, r *http.Request) {
		tok := cookieToken(r)
		ok := jxVerify(tok, whole)
		if ok {
			w.Header().Add("Set-Cookie", jxCookie+"="+tok+"; Path=/; HttpOnly; Secure; SameSite=Strict")
		}
		jxWelcome(w, ok)
	})
	mux.HandleFunc("/jx/safe/optional", func(w http.ResponseWriter, r *http.Request) {
		tok := cookieToken(r)
		if tok != "" {
			w.Header().Add("Set-Cookie", jxCookie+"="+tok+"; Path=/")
		}
		jxWelcome(w, tok == "" || jxVerify(tok, whole))
	})
	mux.HandleFunc("/jx/safe/unverified", func(w http.ResponseWriter, r *http.Request) {
		if tok := cookieToken(r); tok != "" {
			w.Header().Add("Set-Cookie", jxCookie+"="+tok+"; Path=/")
		}
		fmt.Fprint(w, "<html><body>catalogue page</body></html>")
	})
	mux.HandleFunc("/jx/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", jxCookie+"="+jxIssuedToken+"; Path=/; Secure")
		fmt.Fprint(w, "signed in")
	})
	mux.HandleFunc("/jx/safe/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", jxCookie+"="+jxSafeIssuedToken+"; Path=/; Secure; HttpOnly")
		fmt.Fprint(w, "signed in")
	})
	session := func(w http.ResponseWriter, r *http.Request) { jxWelcome(w, jxVerify(cookieToken(r), whole)) }
	mux.HandleFunc("/jx/session", session)
	mux.HandleFunc("/jx/safe/session", session)
	bearer := func(cut func(string) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			tok, _ := rmBearerToken(r)
			jxWelcome(w, jxVerify(tok, cut))
		}
	}
	mux.HandleFunc("/jx/nullbyte", bearer(func(sig string) string {
		if i := strings.Index(sig, "%00"); i > 0 {
			return sig[:i]
		}
		return sig
	}))
	mux.HandleFunc("/jx/safe/nullbyte", bearer(whole))
	mux.HandleFunc("/jx/safe/trailing", bearer(func(sig string) string {
		if len(sig) > 43 {
			return sig[:43]
		}
		return sig
	}))
}
