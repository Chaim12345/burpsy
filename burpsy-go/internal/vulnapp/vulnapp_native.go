package vulnapp

// The two native, dataset-driven checks: "JWT weak HMAC secret" (internal/scanner/jwt_weak.go,
// SCAN-02) and "Vulnerable JavaScript dependency" (internal/scanner/js_vulns.go, SCAN-01).
//
// Both were fully implemented and unit-tested long before anything here declared them, so their
// detection logic had never been exercised end to end against a served response. These fixtures are
// what turns "the brute force works on a hand-built token" and "the range arithmetic works on a
// hand-built detection" into "the scanner found it in traffic".
//
// The contract every entry has to meet:
//
//   - Row must match a catalog row name in internal/scanner exactly. The runtime test resolves every
//     Row against the shipped registry before auditing anything, so a typo fails loudly rather than
//     exempting the endpoint from its own assertion.
//   - A vulnerable endpoint needs a safe twin: same Row, Safe: true, presenting the SAME KIND of
//     artefact without the defect. That twin is what catches a detector firing on shape alone.
//   - Handlers must be the real mechanism, not a payload matcher. Neither endpoint here inspects the
//     request at all: both serve a fixed artefact, and the detectors either do their own arithmetic
//     on it or they do not.
//
// # Why both halves are real rather than suggestive
//
// The weak-secret pair mints two genuine HS256 tokens with crypto/hmac. The vulnerable one's key is
// "your-256-bit-secret" — jwt.io's own documented example secret, and entry 26 of
// bundledJwtSecrets — so SCAN-02's brute force really recomputes the signature and really matches
// it. The safe one's key is 32 bytes of randomness fixed at authoring time; SCAN-02 spends its whole
// wordlist against it and correctly finds nothing, which is the outcome that has to be reached by
// exhaustion rather than by the check never running. Verified by counters, not by silence: the
// coverage snapshot after a scan of the safe endpoint shows TokensExhausted, not TokensRefused or
// TokensOutOfScope.
//
// The dependency pair serves two real jQuery release banners at two real jQuery release filenames.
// 1.6.1 falls inside six of the twelve ranges the vendored retire.js corpus records for jQuery;
// 3.7.1 is above every one of them, the corpus's last jQuery range ending below 3.5.0. Both versions
// are therefore decided by the corpus's own range arithmetic rather than by a version this file
// picked and hoped about, and both are identified by two independent extractor kinds at once — the
// `filename` pattern `jquery-(§§version§§)(\.min)?\.js` and the `filecontent` pattern
// `\* jQuery JavaScript Library v(§§version§§)` — so neither result rests on one signature.
//
// Corresponding scanner descriptors: neither row is in a CheckDescriptor family. Both are native
// passive checks reached from ActiveScanner.Audit via scanner_checks.go, gated on
// ScanConfig.CheckJwtWeak and ScanConfig.CheckJSVulns.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

// nativeEndpoints returns this family's manifest entries.
func nativeEndpoints() []Endpoint {
	return []Endpoint{
		// --- JWT weak HMAC secret: two real HS256 tokens, one key in the wordlist and one not ---
		{Path: "/nt/session", Row: "JWT weak HMAC secret",
			Note: "the response body carries a genuine HS256 token signed with \"your-256-bit-secret\", " +
				"which is in the bundled wordlist, so recomputing the signature with that entry matches"},
		{Path: "/nt/safe/session", Row: "JWT weak HMAC secret", Safe: true,
			Note: "the same response shape carrying a genuine HS256 token signed with 32 bytes of " +
				"randomness, so the whole wordlist is spent against it and no entry reproduces the signature"},

		// --- Vulnerable JavaScript dependency: two real jQuery releases ---
		{Path: "/nt/static/jquery-1.6.1.js", Row: "Vulnerable JavaScript dependency",
			Note: "serves jQuery 1.6.1's real release banner at its real release filename; the vendored " +
				"retire.js corpus records six ranges covering 1.6.1, so the version comparison decides it"},
		{Path: "/nt/static/safe/jquery-3.7.1.js", Row: "Vulnerable JavaScript dependency", Safe: true,
			Note: "the same banner and filename shape at 3.7.1, which is above every jQuery range in the " +
				"corpus (the highest ends below 3.5.0), so the same comparison clears it"},
	}
}

// registerNative serves this family's routes.
func registerNative(mux *http.ServeMux) {
	mux.HandleFunc("/nt/session", ntSession)
	mux.HandleFunc("/nt/safe/session", ntSafeSession)
	mux.HandleFunc("/nt/static/jquery-1.6.1.js", ntVulnerableJQuery)
	mux.HandleFunc("/nt/static/safe/jquery-3.7.1.js", ntSafeJQuery)
}

// ---------------------------------------------------------------------------
// JWT weak HMAC secret
// ---------------------------------------------------------------------------

// ntWeakJWTSecret is the key the vulnerable endpoint signs with. It is jwt.io's documented example
// secret and appears verbatim in internal/scanner/jwt_weak.go's bundledJwtSecrets, which is itself a
// stated subset of Burp Suite's shipped jwt_secrets.txt. Nothing here tells the check which entry to
// try: the check runs the whole list and this one happens to be in it.
const ntWeakJWTSecret = "your-256-bit-secret"

// ntStrongJWTSecret is 32 bytes from crypto/rand, base64url-encoded, fixed at authoring time so the
// fixture is deterministic. It is not in the bundled wordlist and is not a documented default of
// anything, so the negative result on /nt/safe/session is a real exhaustion of the list rather than
// an endpoint the check declined to attack.
const ntStrongJWTSecret = "maqNcKKP-0IvTkzgpP4yyvPlLU1Qn2b800elAv5e7kQ="

// ntMintJWT builds a genuine HS256 token: real base64url segments over a real HMAC-SHA256 of
// `header.payload`. The same construction internal/scanner/jwt_weak.go verifies.
func ntMintJWT(secret string, claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + enc.EncodeToString(mac.Sum(nil))
}

// The two tokens, minted once. A fixed token rather than one per request because the captured
// exchange is what the check reads: the runtime harness seeds each path once and audits the stored
// response, so a token that changed per request would never be the token under test anyway.
var (
	ntWeakJWT   = ntMintJWT(ntWeakJWTSecret, map[string]any{"sub": "1234567890", "name": "Alice Example", "iat": 1516239022})
	ntStrongJWT = ntMintJWT(ntStrongJWTSecret, map[string]any{"sub": "1234567890", "name": "Alice Example", "iat": 1516239022})
)

// ntSession hands out the weakly-signed token. The defect is the key, not the handler: the token is
// correctly formed and correctly signed, which is exactly the case SCAN-02 exists for.
func ntSession(w http.ResponseWriter, r *http.Request) {
	ntWriteSession(w, ntWeakJWT)
}

// ntSafeSession hands out the same response with a strongly-signed token, so a detector keying on
// "a JWT was served" rather than on a reproduced signature fires here and is caught.
func ntSafeSession(w http.ResponseWriter, r *http.Request) {
	ntWriteSession(w, ntStrongJWT)
}

func ntWriteSession(w http.ResponseWriter, token string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token_type":"Bearer","expires_in":3600,"access_token":%q}`, token)
}

// ---------------------------------------------------------------------------
// Vulnerable JavaScript dependency
// ---------------------------------------------------------------------------

// ntJQueryBanner is jQuery's own uncompressed release banner, with the version left as a parameter.
// The shape is the one retire.js's corpus matches on
// (`\* jQuery JavaScript Library v(§§version§§)`), so a hit here is the upstream signature firing on
// upstream's own text rather than on a string invented to be recognised.
const ntJQueryBanner = `/*!
 * jQuery JavaScript Library v%s
 * https://jquery.com/
 *
 * Copyright OpenJS Foundation and other contributors
 * Released under the MIT license
 * https://jquery.org/license
 */
(function (global, factory) {
	"use strict";
	// The library body is not reproduced: SCAN-01 identifies a library from its banner or its
	// filename and then does version arithmetic. Shipping a megabyte of jQuery would change nothing
	// it reads, and vendoring a real library into a deliberately vulnerable fixture is a liability
	// this package does not need.
	factory(global);
})(typeof window !== "undefined" ? window : this, function (window) {
	"use strict";
	return {};
});
`

func ntVulnerableJQuery(w http.ResponseWriter, r *http.Request) {
	ntWriteScript(w, "1.6.1")
}

// ntSafeJQuery serves the identical artefact at a patched version. Everything the check reads is the
// same except the three digits it does arithmetic on, so silence here can only come from the
// comparison.
func ntSafeJQuery(w http.ResponseWriter, r *http.Request) {
	ntWriteScript(w, "3.7.1")
}

func ntWriteScript(w http.ResponseWriter, version string) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	fmt.Fprintf(w, ntJQueryBanner, version)
}
