package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwtToken builds a real HS256/384/512 token signed with secret, so a cracked finding is proof the
// check reproduced a signature rather than proof it recognised a string.
func jwtToken(alg, secret string) string {
	header := b64url([]byte(fmt.Sprintf(`{"alg":%q,"typ":"JWT"}`, alg)))
	payload := b64url([]byte(`{"sub":"1234567890","name":"burpsy"}`))
	signingInput := header + "." + payload
	var h hash.Hash
	switch alg {
	case "HS384":
		h = hmac.New(sha512.New384, []byte(secret))
	case "HS512":
		h = hmac.New(sha512.New, []byte(secret))
	default:
		h = hmac.New(sha256.New, []byte(secret))
	}
	h.Write([]byte(signingInput))
	return signingInput + "." + b64url(h.Sum(nil))
}

// nonHmacToken is an alg this check cannot attack, with a signature that is merely well-formed
// base64url.
func nonHmacToken(alg string) string {
	header := b64url([]byte(fmt.Sprintf(`{"alg":%q,"typ":"JWT"}`, alg)))
	payload := b64url([]byte(`{"sub":"1234567890"}`))
	sig := make([]byte, 32)
	for i := range sig {
		sig[i] = 7
	}
	return header + "." + payload + "." + b64url(sig)
}

func storedResponse(t *testing.T, body string) *core.StoredMessage {
	t.Helper()
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
	return storedMessage(t, raw, core.DirectionResponse)
}

func storedResponseWithHeader(t *testing.T, headerLine string) *core.StoredMessage {
	t.Helper()
	return storedMessage(t, "HTTP/1.1 200 OK\r\n"+headerLine+"\r\nContent-Length: 0\r\n\r\n", core.DirectionResponse)
}

func storedMessage(t *testing.T, raw string, dir core.Direction) *core.StoredMessage {
	t.Helper()
	store := core.NewTrafficStore()
	id, err := store.Put([]byte(raw), dir)
	if err != nil {
		t.Fatalf("store.Put: %v", err)
	}
	msg, err := store.Get(id)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	return msg
}

// scannerWithResponse seeds a store with one exchange whose response is rawResponse, and returns a
// scanner over it. Shared by the SCAN-01 and SCAN-02 adapter tests.
func scannerWithResponse(t *testing.T, path, rawResponse string) (*ActiveScanner, *core.Exchange) {
	t.Helper()
	store := core.NewTrafficStore()
	reqID, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte(rawResponse), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: "h.test", Port: 443, TLS: true, Method: "GET", Path: path}
	store.AddExchange(ex)
	s := NewActiveScanner(store, zap.NewNop())
	return s, ex
}

func TestATokenSignedWithAWordlistSecretIsFoundAndNamesTheSecret(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	body := fmt.Sprintf(`{"access_token":%q}`, jwtToken("HS256", "secret"))
	f := c.Scan(storedResponse(t, body), nil)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(f), renderFindings(f))
	}
	if f[0].Name != jwtIssue {
		t.Errorf("issue = %q, want %q", f[0].Name, jwtIssue)
	}
	if f[0].Severity != "high" || f[0].Confidence != "certain" {
		t.Errorf("severity/confidence = %q/%q, want high/certain", f[0].Severity, f[0].Confidence)
	}
	if !strings.Contains(f[0].Description, `"secret"`) {
		t.Errorf("detail must name the secret: %s", f[0].Description)
	}
	if !strings.Contains(f[0].Description, "the response body") {
		t.Errorf("detail must name where the token was: %s", f[0].Description)
	}
	cov := c.Coverage()
	if cov.TokensCracked != 1 || cov.TokensDistinct != 1 || cov.Truncated {
		t.Errorf("coverage cracked=%d distinct=%d truncated=%v", cov.TokensCracked, cov.TokensDistinct, cov.Truncated)
	}
	if cov.Accounted() != cov.TokensDistinct {
		t.Errorf("accounted %d != distinct %d", cov.Accounted(), cov.TokensDistinct)
	}
}

func TestHS384AndHS512AreAttackedWithTheirOwnDigest(t *testing.T) {
	for _, alg := range []string{"HS384", "HS512"} {
		c := BundledJwtWeakSecretCheck()
		body := fmt.Sprintf(`{"t":%q}`, jwtToken(alg, "changeme"))
		f := c.Scan(storedResponse(t, body), nil)
		if len(f) != 1 {
			t.Fatalf("%s: got %d findings, want 1: %s", alg, len(f), renderFindings(f))
		}
		if !strings.Contains(f[0].Description, `"changeme"`) {
			t.Errorf("%s: detail = %s", alg, f[0].Description)
		}
	}
}

func TestATokenSignedWithAStrongSecretProducesNoFindingAndIsCountedExhausted(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	body := fmt.Sprintf(`{"t":%q}`, jwtToken("HS256", "8f2c1e5b-4d7a-4c9e-b3f1-6a0d92e77c14/entropy"))
	if f := c.Scan(storedResponse(t, body), nil); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.TokensExhausted != 1 || cov.TokensAbandoned != 0 || cov.Truncated {
		t.Errorf("coverage exhausted=%d abandoned=%d truncated=%v",
			cov.TokensExhausted, cov.TokensAbandoned, cov.Truncated)
	}
	if cov.HmacAttempts != uint64(cov.Wordlist.Entries) {
		t.Errorf("attempts = %d, want one per wordlist entry (%d)", cov.HmacAttempts, cov.Wordlist.Entries)
	}
	// The negative result is real, but only relative to the list — which the report names.
	if !strings.Contains(cov.Summary(), "burpsy bundled JWT secrets") {
		t.Errorf("summary must name the wordlist: %s", cov.Summary())
	}
	if cov.Inconclusive() {
		t.Errorf("an exhausted wordlist against one HMAC token is a real negative: %s", cov.Summary())
	}
}

func TestANonHmacTokenIsCountedAsSkippedNotAsClean(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	body := fmt.Sprintf(`{"a":%q,"b":%q,"c":%q}`,
		nonHmacToken("RS256"), nonHmacToken("ES256"), nonHmacToken("none"))
	if f := c.Scan(storedResponse(t, body), nil); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.TokensOutOfScope != 3 || cov.TokensExhausted != 0 {
		t.Errorf("coverage out_of_scope=%d exhausted=%d, want 3/0", cov.TokensOutOfScope, cov.TokensExhausted)
	}
	if cov.HmacAttempts != 0 {
		t.Errorf("no HMAC work is possible on an asymmetric token, got %d attempts", cov.HmacAttempts)
	}
	want := []AlgCount{{"ES256", 1}, {"RS256", 1}, {"none", 1}}
	if len(cov.OutOfScopeAlgorithms) != len(want) {
		t.Fatalf("out of scope algorithms = %+v, want %+v", cov.OutOfScopeAlgorithms, want)
	}
	for i, w := range want {
		if cov.OutOfScopeAlgorithms[i] != w {
			t.Errorf("out of scope algorithm %d = %+v, want %+v", i, cov.OutOfScopeAlgorithms[i], w)
		}
	}
	if !cov.Inconclusive() {
		t.Error("three tokens were never attacked, so this is not a clean result for them")
	}
	if cov.Accounted() != cov.TokensDistinct {
		t.Errorf("accounted %d != distinct %d", cov.Accounted(), cov.TokensDistinct)
	}
}

func TestARunThatHitsTheHmacBudgetReportsTheTruncationInsteadOfACleanResult(t *testing.T) {
	// The real secret sits at the end of the list, and the budget stops three entries in.
	list := JwtWordlistFromEntries("tiny", "unit test", []string{"a", "b", "c", "d", "e", "keyboard cat"})
	c := NewJwtWeakSecretCheckWithBudget(list, 3)
	body := fmt.Sprintf(`{"t":%q}`, jwtToken("HS256", "keyboard cat"))
	if f := c.Scan(storedResponse(t, body), nil); len(f) != 0 {
		t.Fatalf("the secret was never reached, so there is no evidence to report: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.TokensAbandoned != 1 {
		t.Errorf("abandoned = %d, want 1", cov.TokensAbandoned)
	}
	if cov.TokensExhausted != 0 {
		t.Error("an abandoned token is never exhausted")
	}
	if cov.HmacAttempts != 3 {
		t.Errorf("attempts = %d, want exactly the budget (3)", cov.HmacAttempts)
	}
	if !cov.Truncated {
		t.Error("the bound must be visible, not silent")
	}
	if !cov.Inconclusive() {
		t.Error("a truncated brute force is not a clean result")
	}
	if !strings.Contains(cov.Summary(), "1 abandoned mid-wordlist") {
		t.Errorf("summary must say so: %s", cov.Summary())
	}
	if cov.Accounted() != cov.TokensDistinct {
		t.Errorf("accounted %d != distinct %d", cov.Accounted(), cov.TokensDistinct)
	}
}

func TestAZeroBudgetAbandonsEveryTokenRatherThanClearingIt(t *testing.T) {
	c := NewJwtWeakSecretCheckWithBudget(BundledJwtWordlist(), 0)
	body := fmt.Sprintf(`{"t":%q}`, jwtToken("HS256", "secret"))
	if f := c.Scan(storedResponse(t, body), nil); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.TokensAbandoned != 1 || cov.HmacAttempts != 0 || !cov.Truncated {
		t.Errorf("coverage abandoned=%d attempts=%d truncated=%v, want 1/0/true",
			cov.TokensAbandoned, cov.HmacAttempts, cov.Truncated)
	}
}

func TestTheSameTokenOnASecondResponseIsDeduplicatedBySigningInput(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	body := fmt.Sprintf(`{"t":%q}`, jwtToken("HS256", "secret"))
	if f := c.Scan(storedResponse(t, body), nil); len(f) != 1 {
		t.Fatalf("first scan: got %d findings, want 1", len(f))
	}
	if f := c.Scan(storedResponse(t, body), nil); len(f) != 0 {
		t.Fatalf("cracked once, not once per page: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.TokensSeen != 2 || cov.TokensDistinct != 1 || cov.TokensAlreadyCovered != 1 {
		t.Errorf("coverage seen=%d distinct=%d already_covered=%d, want 2/1/1",
			cov.TokensSeen, cov.TokensDistinct, cov.TokensAlreadyCovered)
	}
	if cov.HmacAttempts != 1 {
		t.Errorf("attempts = %d, want 1 — the wordlist runs once for one signing input", cov.HmacAttempts)
	}
}

func TestATokenInASetCookieHeaderIsFoundAndTheLocationNamed(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	msg := storedResponseWithHeader(t, "Set-Cookie: session="+jwtToken("HS256", "jwt")+"; Path=/; HttpOnly")
	f := c.Scan(msg, nil)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(f), renderFindings(f))
	}
	if !strings.Contains(f[0].Description, "response header Set-Cookie") {
		t.Errorf("detail must name the header: %s", f[0].Description)
	}
}

func TestATokenInARequestAuthorizationHeaderIsFoundWhenTheRequestIsSupplied(t *testing.T) {
	req := storedMessage(t,
		"GET /api HTTP/1.1\r\nHost: h.test\r\nAuthorization: Bearer "+jwtToken("HS256", "admin")+"\r\n\r\n",
		core.DirectionRequest)
	c := BundledJwtWeakSecretCheck()
	f := c.Scan(storedResponse(t, "{}"), req)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(f), renderFindings(f))
	}
	if !strings.Contains(f[0].Description, "request header Authorization") {
		t.Errorf("detail must name the header: %s", f[0].Description)
	}
	if cov := c.Coverage(); cov.RequestsUnavailable != 0 {
		t.Errorf("requests unavailable = %d, want 0", cov.RequestsUnavailable)
	}
}

func TestScanningWithoutARequestMessageRecordsThatTheRequestSideWasNotExamined(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	c.Scan(storedResponse(t, "{}"), nil)
	if cov := c.Coverage(); cov.RequestsUnavailable != 1 {
		t.Errorf("requests unavailable = %d, want 1", cov.RequestsUnavailable)
	}
}

func TestAFiveSegmentJweIsRefusedRatherThanTreatedAsAJws(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	header := b64url([]byte(`{"alg":"dir","enc":"A128GCM"}`))
	body := fmt.Sprintf(`{"t":"%s.aaaa.bbbb.cccc.dddd"}`, header)
	if f := c.Scan(storedResponse(t, body), nil); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.TokensSeen != 0 || cov.TokensDistinct != 0 {
		t.Errorf("a five-segment token is not JWS-shaped: seen=%d distinct=%d", cov.TokensSeen, cov.TokensDistinct)
	}
}

func TestATokenWhoseHeaderIsNotDecodableJsonIsRefusedNotGuessedAt(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	// `eyJ`-prefixed, three segments, but the header decodes to bytes that are not JSON.
	body := `{"t":"eyJxxxxxx.eyJzdWIiOiJhIn0.QUJDREVG"}`
	if f := c.Scan(storedResponse(t, body), nil); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.TokensSeen != 1 || cov.TokensRefused != 1 || cov.TokensExhausted != 0 {
		t.Errorf("coverage seen=%d refused=%d exhausted=%d, want 1/1/0",
			cov.TokensSeen, cov.TokensRefused, cov.TokensExhausted)
	}
	if !cov.Inconclusive() {
		t.Error("a refused token is not a clean one")
	}
	if cov.Accounted() != cov.TokensDistinct {
		t.Errorf("accounted %d != distinct %d", cov.Accounted(), cov.TokensDistinct)
	}
}

func TestAHeaderWithNoAlgClaimIsRefusedRatherThanAttackedWithADefault(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	header := b64url([]byte(`{"typ":"JWT"}`))
	body := fmt.Sprintf(`{"t":"%s.%s.QUJDREVG"}`, header, b64url([]byte(`{"sub":"a"}`)))
	if f := c.Scan(storedResponse(t, body), nil); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	if cov := c.Coverage(); cov.TokensRefused != 1 || cov.HmacAttempts != 0 {
		t.Errorf("coverage refused=%d attempts=%d, want 1/0", cov.TokensRefused, cov.HmacAttempts)
	}
}

// A multi-megabyte "token" is a denial of service against the scanner, not a credential: it is
// refused before any HMAC work, and counted.
func TestATokenLargerThanTheCapIsRefusedBeforeAnyHmacWork(t *testing.T) {
	c := BundledJwtWeakSecretCheck()
	header := b64url([]byte(`{"alg":"HS256","typ":"JWT"}`))
	huge := header + "." + strings.Repeat("A", MaxTokenBytes+16) + ".QUJDREVG"
	if f := c.Scan(storedResponse(t, fmt.Sprintf(`{"t":%q}`, huge)), nil); len(f) != 0 {
		t.Fatalf("want no findings, got: %s", renderFindings(f))
	}
	cov := c.Coverage()
	if cov.TokensRefused != 1 || cov.HmacAttempts != 0 {
		t.Errorf("coverage refused=%d attempts=%d, want 1/0", cov.TokensRefused, cov.HmacAttempts)
	}
	if cov.Accounted() != cov.TokensDistinct {
		t.Errorf("accounted %d != distinct %d", cov.Accounted(), cov.TokensDistinct)
	}
}

func TestBase64urlDecodingRefusesACharacterOutsideTheAlphabet(t *testing.T) {
	if _, ok := b64urlDecode("eyJhbGciOiJIUzI1NiJ9"); !ok {
		t.Error("a real header segment must decode")
	}
	if _, ok := b64urlDecode("ab+cd"); ok {
		t.Error("standard base64 '+' is not base64url")
	}
	if _, ok := b64urlDecode("ab/cd"); ok {
		t.Error("standard base64 '/' is not base64url")
	}
	if _, ok := b64urlDecode(""); ok {
		t.Error("an empty segment is a refusal, not an empty decode")
	}
	if _, ok := b64urlDecode("a"); ok {
		t.Error("one base64 character cannot encode a byte")
	}
	// Padding is tolerated, since deployments emit it despite the JWS spec.
	if got, ok := b64urlDecode("QQ=="); !ok || string(got) != "A" {
		t.Errorf("padded decode = %q ok=%v, want \"A\" true", got, ok)
	}
}

// A token that begins mid-run is not a token: `xeyJ…` is somebody else's base64.
func TestTokenScanningIgnoresAnEyJThatIsNotASegmentStart(t *testing.T) {
	var out []rawToken
	out = scanTextForTokens("xxeyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.QUJDREVG", tokenLocation{}, out)
	if len(out) != 0 {
		t.Fatalf("got %d tokens, want 0: %+v", len(out), out)
	}
	// The same run, this time preceded by `=` — the most common way a token really appears.
	out = scanTextForTokens("cookie=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.QUJDREVG", tokenLocation{}, out)
	if len(out) != 1 {
		t.Fatalf("got %d tokens, want 1: %+v", len(out), out)
	}
}

func TestTheBundledWordlistStatesItsSizeAndProvenance(t *testing.T) {
	w := BundledJwtWordlist()
	if w.Len() != 51 {
		t.Errorf("entries = %d, want 51", w.Len())
	}
	if w.ID().Entries != 51 {
		t.Errorf("id entries = %d, want 51", w.ID().Entries)
	}
	if !strings.Contains(w.ID().Source, "jwt_secrets.txt") {
		t.Errorf("source must name the corpus it is a subset of: %s", w.ID().Source)
	}
	seen := make(map[string]bool, w.Len())
	for _, e := range w.entries {
		if seen[e] {
			t.Errorf("duplicate bundled secret %q inflates the entry count behind every negative result", e)
		}
		seen[e] = true
	}
}

func TestAWordlistFileReportsDistinctEntriesRatherThanLineCount(t *testing.T) {
	p := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(p, []byte("secret\n\nsecret\r\nchangeme\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	w, err := LoadJwtWordlist(p)
	if err != nil {
		t.Fatalf("LoadJwtWordlist: %v", err)
	}
	if w.Len() != 2 {
		t.Errorf("entries = %d, want 2: the duplicate and the blank line are not entries", w.Len())
	}
	if w.ID().Name != "list.txt" {
		t.Errorf("name = %q, want list.txt", w.ID().Name)
	}
}

func TestAMissingOrEmptyWordlistFileIsAnErrorRatherThanAnEmptyAttack(t *testing.T) {
	if _, err := LoadJwtWordlist("/nonexistent/list.txt"); err == nil {
		t.Error("a missing wordlist must be an error, not an attack against nothing")
	}
	p := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(p, []byte("\n\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadJwtWordlist(p); err == nil {
		t.Error("a wordlist with no entries must be an error")
	}
}

// The adapter on ActiveScanner: the request side is scanned too, findings carry the exchange, and
// remediation comes from Burp's catalogue.
func TestTheActiveScannerAdapterAttributesAndEnrichesJwtFindings(t *testing.T) {
	token := jwtToken("HS256", "secret")
	s, ex := scannerWithResponse(t, "/api/session", fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(`{"t":""}`)+len(token), fmt.Sprintf(`{"t":%q}`, token)))
	s.config.CheckJwtWeak = true

	f := s.checkJWTWeak(nil, ex)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(f), renderFindings(f))
	}
	if f[0].URL != ex.Path || f[0].Method != ex.Method || f[0].ExchangeID != ex.ID {
		t.Errorf("finding not attributed to its exchange: %+v", f[0])
	}
	def, ok := ByName(jwtIssue)
	if !ok {
		t.Fatalf("%q is not in the shipped catalogue, so no remediation can be wired", jwtIssue)
	}
	if f[0].Solution != def.Remediation {
		t.Errorf("remediation is not the catalogue's text:\n got %q\nwant %q", f[0].Solution, def.Remediation)
	}
	cov := s.JwtWeakCoverage()
	if cov.TokensCracked != 1 {
		t.Errorf("scanner coverage cracked = %d, want 1", cov.TokensCracked)
	}
	if cov.RequestsUnavailable != 0 {
		t.Errorf("the adapter has the request in hand, so it must pass it: unavailable = %d", cov.RequestsUnavailable)
	}
}

func TestTheJwtCheckIsSkippedWhenItsConfigFlagIsOff(t *testing.T) {
	s, ex := scannerWithResponse(t, "/api", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	s.config.CheckJwtWeak = false
	if f := s.checkJWTWeak(nil, ex); len(f) != 0 {
		t.Fatalf("a disabled check must produce nothing: %s", renderFindings(f))
	}
}
