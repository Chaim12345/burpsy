package vulnapp

// the final tranche: reflected context, access control, CSRF, JWT arbitrary jku/x5u, pipelining,
// HTTP/2, and the four provenance rows.
//
// One file per check family, holding that family's vulnerable endpoints, their safe counterparts and
// the routes serving both. The manifest entries returned here are appended to Vulnerabilities() by
// familyEndpoints in vulnapp.go; the routes are registered by familyRegistrars.
//
// The contract every entry has to meet:
//
//   - Row must match a catalog row name in internal/scanner exactly. The runtime test resolves every
//     Row against the shipped registry before auditing anything, so a typo fails loudly rather than
//     exempting the endpoint from its own assertion.
//   - A vulnerable endpoint needs a safe twin: same Row, Safe: true, reflecting or echoing the same
//     input WITHOUT the defect. That twin is what catches a detector firing on reflection alone.
//     Where no such thing can exist, say why in SafeTwinNotApplicable rather than omitting it.
//   - Handlers must be the real mechanism, not a payload matcher. An endpoint that pattern-matches
//     the payloads it expects grades the check against the fixture author's guesses and passes
//     whether or not the detector works.
//
// Corresponding scanner descriptors: FinalCheckDescriptors.
//
// # Five of the sixteen catalog rows this family owns are not declared here
//
// Declaring a row that structurally cannot fire (or that can only "fire" by exercising a broken
// check) would fail TestTheScannerDetectsWhatTheTargetDeclaresItIsVulnerableTo for every agent
// working in this package, so these are left out rather than wired to something that would give a
// false reading:
//
//   - Hidden HTTP 2: the check is now correct — it takes an ALPN baseline and then forces HTTP/2
//     onto a separate, non-pooled connection (see checks_final.go) — but the row still cannot be
//     declared here, and the reason is structural rather than a check defect. The verdict is
//     per-host: it depends only on the shared server's ALPN offer and on whether that listener reads
//     HTTP/2 frames, which is identical for every path on it. So no endpoint here can differ from
//     its quiet twin in the way this row measures. The fixture has to be its own TLS listener with a
//     hand-controlled ALPN offer, which is what internal/scanner/hidden_http2_test.go builds: a real
//     hidden-h2 origin plus the two negatives (advertises h2; speaks no h2 at all).
//   - HTTP request smuggling, Client-side desync: pipeliningCheck dials cc.Exchange.Host/Port
//     directly. Endpoint has no field to point an exchange at a different listener, and
//     runtime_coverage_test.go's seed() always sets Host/Port to one of the two shared httptest
//     servers. A raw net.Listener built in this file would never be the dial target - nothing
//     routes an audited exchange to it. Needs a host-override field on Endpoint plus a third
//     listener; both are outside this file.
//   - BCheck / Bambda / Extension / Manually generated issue: provenanceCheck reads an internal
//     ProvenanceLedger, never an HTTP exchange, so no endpoint could demonstrate it even in
//     principle. It is also moot here: WithProvenanceLedger is never called anywhere in
//     runtime_coverage_test.go, so all four always return "no provenance ledger configured".
//   - External service interaction (SMTP): oobCheck is gated by oobChecksEnabled, which requires
//     ScanConfig.CheckOutOfBand. runtimeScanConfig() never sets it, so the check's own dispatch
//     guard skips it before touching any endpoint; it also needs a real collaborator subprocess.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// finalEndpoints returns this family's manifest entries.
func finalEndpoints() []Endpoint {
	finalJWTSetup()
	return []Endpoint{
		// --- reflected-context rows: submit a canary, check it lands where the row says it does ---
		{Path: "/fn/reflect/mask?preview=quokka1234", Row: "Suspicious input transformation (reflected)",
			Note: "renders preview through a masked-preview feature that leaves the first 8 characters as-is and ROT13/digit-shifts the rest, so a submitted value comes back altered rather than verbatim"},
		{Path: "/fn/reflect/mask-safe?preview=quokka1234", Row: "Suspicious input transformation (reflected)", Safe: true,
			Note: "renders preview unchanged, so no submitted value is ever altered in transit"},

		{Path: "/fn/reflect/theme?accent=teal", Row: "CSS injection (reflected)",
			Note: "splices accent straight into a <style> block with no validation, so any value becomes part of the page's CSS"},
		{Path: "/fn/reflect/theme-safe?accent=teal", Row: "CSS injection (reflected)", Safe: true,
			Note: "resolves accent through a fixed name->colour table and falls back to a default for anything unrecognised, so an arbitrary value never reaches the stylesheet"},

		{Path: "/fn/reflect/widget?cb=metrics", Row: "Client-side HTTP parameter pollution (reflected)",
			Note: "splices cb straight into a <script src> query string with no validation, so extra & or = characters in cb add or override parameters the loaded script did not expect"},
		{Path: "/fn/reflect/widget-safe?cb=metrics", Row: "Client-side HTTP parameter pollution (reflected)", Safe: true,
			Note: "resolves cb through a fixed name->script table and falls back to a fixed URL with no query string for anything unrecognised, so an arbitrary value never reaches the src attribute"},

		{Path: "/fn/reflect/checkout?returnTo=/cart", Row: "Form action hijacking (reflected)",
			Note: "splices returnTo straight into a form's action attribute with no validation, so a submitted value can point the form's own submission at a foreign host"},
		{Path: "/fn/reflect/checkout-safe?returnTo=/cart", Row: "Form action hijacking (reflected)", Safe: true,
			Note: "accepts returnTo only when it is a same-origin relative path (mirrors vulnapp.go's safeRedirect rule) and falls back to a fixed path otherwise, so an arbitrary value never reaches the action attribute"},

		// --- JWT arbitrary jku / x5u: a real RS256 verifier, fooled only by the vulnerable half ---
		{Path: "/fn/jwt/jku", Row: "JWT arbitrary jku header supported",
			RequestHeaders: map[string]string{"Authorization": "Bearer " + finalJWTToken},
			Note:           "verifies the bearer token's signature against whatever JWK Set the token's own jku header names, fetched with no allowlist"},
		{Path: "/fn/jwt/jku-safe", Row: "JWT arbitrary jku header supported", Safe: true,
			RequestHeaders: map[string]string{"Authorization": "Bearer " + finalJWTToken},
			Note:           "ignores any jku header entirely and always verifies against the server's own fixed key"},

		{Path: "/fn/jwt/x5u", Row: "JWT arbitrary x5u header supported",
			RequestHeaders: map[string]string{"Authorization": "Bearer " + finalJWTToken},
			Note:           "verifies the bearer token's signature against whatever certificate the token's own x5u header names, fetched with no allowlist"},
		{Path: "/fn/jwt/x5u-safe", Row: "JWT arbitrary x5u header supported", Safe: true,
			RequestHeaders: map[string]string{"Authorization": "Bearer " + finalJWTToken},
			Note:           "ignores any x5u header entirely and always verifies against the server's own fixed key"},

		// --- session-differential rows: real cookie-gated handlers, not a payload match ---
		{Path: "/fn/access/admin", Row: "Broken access control",
			Note: "serves the admin panel to every request, with or without a session cookie - there is no access check to bypass"},
		{Path: "/fn/access/admin-safe", Row: "Broken access control", Safe: true,
			Note: "serves the same panel only when the session cookie is present, and 401s otherwise"},

		{Path: "/fn/csrf/transfer", Row: "Cross-site request forgery", Method: "POST",
			Body: "amount=100&to=carol", ContentType: "application/x-www-form-urlencoded",
			Note: "processes the transfer on any repeat, from any Referer, once a valid session cookie is attached - there is no anti-CSRF defence to bypass"},
		{Path: "/fn/csrf/transfer-safe", Row: "Cross-site request forgery", Safe: true, Method: "POST",
			Body: "amount=100&to=carol", ContentType: "application/x-www-form-urlencoded",
			Note: "processes a transfer at most once and always reissues its session cookie with SameSite=Strict, so a replayed or cross-origin resubmission is rejected"},
	}
}

// registerFinal serves this family's routes.
func registerFinal(mux *http.ServeMux) {
	mux.HandleFunc("/fn/reflect/mask", finalMaskedPreview)
	mux.HandleFunc("/fn/reflect/mask-safe", finalMaskedPreviewSafe)
	mux.HandleFunc("/fn/reflect/theme", finalThemeStyle)
	mux.HandleFunc("/fn/reflect/theme-safe", finalThemeStyleSafe)
	mux.HandleFunc("/fn/reflect/widget", finalWidgetLoader)
	mux.HandleFunc("/fn/reflect/widget-safe", finalWidgetLoaderSafe)
	mux.HandleFunc("/fn/reflect/checkout", finalCheckoutForm)
	mux.HandleFunc("/fn/reflect/checkout-safe", finalCheckoutFormSafe)

	mux.HandleFunc("/fn/jwt/jku", finalJWTHandler(finalTrustJku))
	mux.HandleFunc("/fn/jwt/jku-safe", finalJWTHandler(finalTrustNothing))
	mux.HandleFunc("/fn/jwt/x5u", finalJWTHandler(finalTrustX5u))
	mux.HandleFunc("/fn/jwt/x5u-safe", finalJWTHandler(finalTrustNothing))

	mux.HandleFunc("/fn/access/admin", finalAdminPanel)
	mux.HandleFunc("/fn/access/admin-safe", finalAdminPanelSafe)
	mux.HandleFunc("/fn/csrf/transfer", finalCSRFTransfer)
	mux.HandleFunc("/fn/csrf/transfer-safe", finalCSRFTransferSafe)
}

// ---------------------------------------------------------------------------
// reflected-context rows
// ---------------------------------------------------------------------------

// finalObfuscateTail leaves the first 8 bytes of s untouched and substitution-ciphers the rest
// (ROT13 on letters, +1 mod 10 on digits). It models a "masked preview" feature that shows a
// prefix as-is and obscures the remainder reversibly instead of truncating or hashing it - real
// input comes back altered rather than byte-for-byte, which is what this row is about.
func finalObfuscateTail(s string) string {
	if len(s) <= 8 {
		return s
	}
	b := []byte(s)
	for i := 8; i < len(b); i++ {
		switch {
		case b[i] >= 'a' && b[i] <= 'z':
			b[i] = 'a' + (b[i]-'a'+13)%26
		case b[i] >= 'A' && b[i] <= 'Z':
			b[i] = 'A' + (b[i]-'A'+13)%26
		case b[i] >= '0' && b[i] <= '9':
			b[i] = '0' + (b[i]-'0'+1)%10
		}
	}
	return string(b)
}

func finalMaskedPreview(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("preview")
	fmt.Fprintf(w, "<html><body><p>Masked preview: %s</p></body></html>", htmlEscape(finalObfuscateTail(value)))
}

func finalMaskedPreviewSafe(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("preview")
	fmt.Fprintf(w, "<html><body><p>Preview: %s</p></body></html>", htmlEscape(value))
}

// finalThemeColors is the fixed name->colour table finalThemeStyleSafe resolves through. An
// unrecognised name - which is what an injected value always is - falls back to "default" rather
// than reaching the stylesheet.
var finalThemeColors = map[string]string{
	"teal":    "#008080",
	"coral":   "#ff7f50",
	"slate":   "#708090",
	"default": "#333333",
}

func finalThemeStyle(w http.ResponseWriter, r *http.Request) {
	accent := r.URL.Query().Get("accent")
	fmt.Fprintf(w, "<html><head><style>\nbody { --accent: %s; }\n</style></head><body>themed</body></html>", accent)
}

func finalThemeStyleSafe(w http.ResponseWriter, r *http.Request) {
	accent := r.URL.Query().Get("accent")
	color, ok := finalThemeColors[strings.ToLower(accent)]
	if !ok {
		color = finalThemeColors["default"]
	}
	fmt.Fprintf(w, "<html><head><style>\nbody { --accent: %s; }\n</style></head><body>themed</body></html>", color)
}

// finalWidgetScripts is the fixed name->script table finalWidgetLoaderSafe resolves through, the
// same allowlist shape as finalThemeColors above.
var finalWidgetScripts = map[string]string{
	"metrics": "/static/metrics.js",
	"chat":    "/static/chat.js",
}

func finalWidgetLoader(w http.ResponseWriter, r *http.Request) {
	cb := r.URL.Query().Get("cb")
	fmt.Fprintf(w, "<html><body><script src=\"/static/widget.js?callback=%s\"></script></body></html>", cb)
}

func finalWidgetLoaderSafe(w http.ResponseWriter, r *http.Request) {
	cb := r.URL.Query().Get("cb")
	src, ok := finalWidgetScripts[cb]
	if !ok {
		src = "/static/widget.js"
	}
	fmt.Fprintf(w, "<html><body><script src=\"%s\"></script></body></html>", src)
}

// finalIsSafeRelativePath is vulnapp.go's safeRedirect rule, applied here to a form action
// instead of a redirect target: a single leading slash, never a protocol-relative "//" and never
// a backslash form a browser would normalise into one.
func finalIsSafeRelativePath(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.Contains(s, "\\") {
		return false
	}
	return true
}

func finalCheckoutForm(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("returnTo")
	fmt.Fprintf(w, "<html><body><form method=\"post\" action=\"/checkout/complete?next=%s\"><input type=\"submit\"></form></body></html>", returnTo)
}

func finalCheckoutFormSafe(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("returnTo")
	if !finalIsSafeRelativePath(returnTo) {
		returnTo = "/cart"
	}
	fmt.Fprintf(w, "<html><body><form method=\"post\" action=\"/checkout/complete?next=%s\"><input type=\"submit\"></form></body></html>", htmlEscape(returnTo))
}

// ---------------------------------------------------------------------------
// JWT arbitrary jku / x5u header
// ---------------------------------------------------------------------------

// finalJWTKeyOnce and friends mint one RSA keypair and one legitimately-signed token, shared by
// all four JWT endpoints below: the vulnerable and safe variants both have to recognise the SAME
// properly-issued token (no jku/x5u header at all) against the server's own key, and differ only
// in what they do when a caller's token names an external one.
var (
	finalJWTKeyOnce sync.Once
	finalJWTPriv    *rsa.PrivateKey
	finalJWTToken   string
)

const finalJWTKid = "fn-app-key-1"

func finalJWTSetup() {
	finalJWTKeyOnce.Do(func() {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("vulnapp: generating jwt signing key: " + err.Error())
		}
		finalJWTPriv = priv
		finalJWTToken = finalMintJWT(priv, finalJWTKid, map[string]any{"sub": "alice", "role": "user"})
	})
}

// finalMintJWT signs an ordinary RS256 token carrying no jku/x5u header - the properly-issued
// case both the vulnerable and safe endpoint must accept via the server's own key.
func finalMintJWT(priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	headerJSON, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		panic("vulnapp: marshaling jwt header: " + err.Error())
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		panic("vulnapp: marshaling jwt payload: " + err.Error())
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		panic("vulnapp: signing jwt: " + err.Error())
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// finalBearerToken extracts the compact token from an Authorization: Bearer header.
func finalBearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimPrefix(h, prefix), true
}

// finalVerifyRS256 reports whether sigB64 is a valid RS256 signature over signingInput under pub.
func finalVerifyRS256(pub *rsa.PublicKey, signingInput, sigB64 string) bool {
	if pub == nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	hashed := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig) == nil
}

// finalJWKPublicKey builds an RSA public key from a JWK member's base64url n/e fields.
func finalJWKPublicKey(jwk map[string]any) (*rsa.PublicKey, bool) {
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)
	nb, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil || len(nb) == 0 {
		return nil, false
	}
	eb, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil || len(eb) == 0 {
		return nil, false
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() {
		return nil, false
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, true
}

// finalResolveJku fetches the JWK Set at jkuURL and returns the key matching kid, or the set's
// only key when there is exactly one. This is the vulnerable step itself: jkuURL comes straight
// from the token the caller presented, and nothing here checks it against an allowlist.
func finalResolveJku(jkuURL, kid string) (*rsa.PublicKey, bool) {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(jkuURL)
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&doc); err != nil || len(doc.Keys) == 0 {
		return nil, false
	}
	for _, k := range doc.Keys {
		if kidVal, _ := k["kid"].(string); kidVal != "" && kidVal == kid {
			return finalJWKPublicKey(k)
		}
	}
	if len(doc.Keys) == 1 {
		return finalJWKPublicKey(doc.Keys[0])
	}
	return nil, false
}

// finalResolveX5u fetches the PEM certificate at x5uURL and returns its RSA public key. Same
// vulnerability shape as finalResolveJku: the URL is whatever the token claims, unchecked.
func finalResolveX5u(x5uURL string) (*rsa.PublicKey, bool) {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(x5uURL)
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, false
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	return pub, ok
}

// finalTrustJku resolves a caller-claimed jku header with no allowlist - the vulnerable behaviour.
func finalTrustJku(header map[string]any) (*rsa.PublicKey, bool) {
	jku, _ := header["jku"].(string)
	if jku == "" {
		return nil, false
	}
	kid, _ := header["kid"].(string)
	return finalResolveJku(jku, kid)
}

// finalTrustX5u resolves a caller-claimed x5u header with no allowlist - the vulnerable behaviour.
func finalTrustX5u(header map[string]any) (*rsa.PublicKey, bool) {
	x5u, _ := header["x5u"].(string)
	if x5u == "" {
		return nil, false
	}
	return finalResolveX5u(x5u)
}

// finalTrustNothing never consults the header at all - the safe behaviour both jku-safe and
// x5u-safe share.
func finalTrustNothing(map[string]any) (*rsa.PublicKey, bool) { return nil, false }

// finalJWTHandler is the real RS256 verifier all four JWT endpoints run. trustHint resolves a
// caller-claimed key hint into the key to verify with; when it declines (absent, unreachable, or
// the safe variant that never looks), verification falls back to the server's own fixed key, so a
// token with no trusted path to a key is never accepted just because a header was present.
func finalJWTHandler(trustHint func(header map[string]any) (*rsa.PublicKey, bool)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		finalJWTSetup()
		token, ok := finalBearerToken(r)
		if !ok {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			http.Error(w, "malformed token", http.StatusUnauthorized)
			return
		}
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		var header map[string]any
		if err != nil || json.Unmarshal(headerJSON, &header) != nil {
			http.Error(w, "malformed header", http.StatusUnauthorized)
			return
		}
		pub, ok := trustHint(header)
		if !ok {
			pub = &finalJWTPriv.PublicKey
		}
		if !finalVerifyRS256(pub, parts[0]+"."+parts[1], parts[2]) {
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		var payload map[string]any
		if payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(payloadJSON, &payload)
		}
		sub, _ := payload["sub"].(string)
		fmt.Fprintf(w, "welcome, %s", htmlEscape(sub))
	}
}

// ---------------------------------------------------------------------------
// session-differential rows: broken access control, CSRF
// ---------------------------------------------------------------------------

// finalHasSession reports whether r carries the session cookie the runtime harness's coordinator
// absorbs (see runtime_coverage_test.go's HandleResponse call). Contains rather than an exact
// match, so an unrelated cookie alongside it does not defeat the check.
func finalHasSession(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Cookie"), "session=bsy-runtime-session")
}

const finalAdminPanelBody = "Admin panel: user list = alice, bob, carol"

func finalAdminPanel(w http.ResponseWriter, r *http.Request) {
	// No check at all: the panel is served whether or not a session cookie is attached, which is
	// exactly what "broken access control" means - there is no gate to bypass because there is no
	// gate.
	fmt.Fprint(w, finalAdminPanelBody)
}

func finalAdminPanelSafe(w http.ResponseWriter, r *http.Request) {
	if !finalHasSession(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fmt.Fprint(w, finalAdminPanelBody)
}

func finalCSRFTransfer(w http.ResponseWriter, r *http.Request) {
	if !finalHasSession(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// No anti-CSRF token, no Referer/Origin check, no limit on repeats: any request carrying the
	// session cookie succeeds, from anywhere, as many times as it is sent.
	fmt.Fprintf(w, "transferred %s to %s", htmlEscape(r.FormValue("amount")), htmlEscape(r.FormValue("to")))
}

// finalCSRFTransferUsed makes the safe endpoint's action single-use: a forged or replayed
// resubmission - which is indistinguishable from a legitimate one at the HTTP layer, since both
// carry the same valid session cookie - has to be refused on some real, structural ground, and a
// one-time transaction token has that ground even without inspecting the body or the Referer.
var finalCSRFTransferUsed atomic.Bool

func finalCSRFTransferSafe(w http.ResponseWriter, r *http.Request) {
	// The session cookie is reissued with SameSite=Strict on every response, success or refusal,
	// because the audited exchange's OWN stored response - not some separate login flow - is what
	// the check inspects for that attribute.
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "bsy-runtime-session", Path: "/", SameSite: http.SameSiteStrictMode})
	if !finalHasSession(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !finalCSRFTransferUsed.CompareAndSwap(false, true) {
		http.Error(w, "this transfer has already been completed", http.StatusForbidden)
		return
	}
	fmt.Fprintf(w, "transferred %s to %s", htmlEscape(r.FormValue("amount")), htmlEscape(r.FormValue("to")))
}
