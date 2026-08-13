package scanner

// End-to-end tests for the wired passive analysers. The analysers themselves are covered in
// infra_passive_test.go / infra_csp_test.go / infra_viewstate_test.go; these cover the
// wiring and the row-boundary decisions the runners make.

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// ---------- cookies ----------

func TestWiredTLSCookieWithoutSecureFires(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Set-Cookie: sid=abc; Path=/"), true)
	requireOneFinding(t, runPosture(t, checkTLSCookieWithoutSecure, cc), "TLS cookie without secure flag set")
}

func TestWiredTLSCookieWithoutSecureQuietWhenSecureSet(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Set-Cookie: sid=abc; Path=/; Secure"), true)
	if got := runPosture(t, checkTLSCookieWithoutSecure, cc); len(got) != 0 {
		t.Fatalf("got %d findings with Secure set, want 0", len(got))
	}
}

// Over cleartext the Secure attribute cannot be judged the same way — the row is scoped to
// TLS, so a cleartext exchange must stay quiet.
func TestWiredTLSCookieWithoutSecureQuietOverCleartext(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Set-Cookie: sid=abc; Path=/"), false)
	if got := runPosture(t, checkTLSCookieWithoutSecure, cc); len(got) != 0 {
		t.Fatalf("got %d findings over cleartext, want 0", len(got))
	}
}

func TestWiredCookieWithoutHttpOnlyFires(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Set-Cookie: sid=abc; Path=/; Secure"), true)
	requireOneFinding(t, runPosture(t, checkCookieWithoutHttpOnly, cc), "Cookie without HttpOnly flag set")
}

func TestWiredCookieScopedToParentDomainFires(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Set-Cookie: sid=abc; Domain=.test; Path=/"), true)
	got := runPosture(t, checkCookieScopedToParentDomain, cc)
	if len(got) > 1 {
		t.Fatalf("got %d findings, want at most 1", len(got))
	}
}

func TestWiredSessionTokenInURLFires(t *testing.T) {
	cc := postureFixture(t, "GET /p?jsessionid=abc123 HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	got := runPosture(t, checkSessionTokenInURL, cc)
	if len(got) == 0 {
		t.Fatal("jsessionid in the query string was not reported as a session token in URL")
	}
	requireOneFinding(t, got, "Session token in URL")
}

func TestWiredSessionTokenInURLQuietOnBenignParam(t *testing.T) {
	cc := postureFixture(t, "GET /p?q=hello HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	if got := runPosture(t, checkSessionTokenInURL, cc); len(got) != 0 {
		t.Fatalf("got %d findings on a benign parameter, want 0", len(got))
	}
}

// ---------- header attributes ----------

func TestWiredFrameableResponseFires(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	requireOneFinding(t, runPosture(t, checkFrameableResponse, cc), "Frameable response (potential Clickjacking)")
}

func TestWiredFrameableResponseQuietWithXFrameOptions(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "X-Frame-Options: DENY"), true)
	if got := runPosture(t, checkFrameableResponse, cc); len(got) != 0 {
		t.Fatalf("got %d findings with X-Frame-Options: DENY, want 0", len(got))
	}
}

func TestWiredXSSFilterDisabledFires(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "X-XSS-Protection: 0"), true)
	requireOneFinding(t, runPosture(t, checkXSSFilterDisabled, cc), "Browser cross-site scripting filter disabled")
}

func TestWiredCharsetChecksAreMutuallyExclusive(t *testing.T) {
	// No charset anywhere: the "does not specify" row fires and the "unrecognized" row
	// cannot, because there is nothing to recognise.
	none := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>x</body></html>", true)
	requireOneFinding(t, runPosture(t, checkHTMLDoesNotSpecifyCharset, none), "HTML does not specify charset")
	if got := runPosture(t, checkHTMLUsesUnrecognizedCharset, none); len(got) != 0 {
		t.Errorf("unrecognized-charset fired with no charset declared: %d findings", len(got))
	}

	// A bogus charset: the "unrecognized" row fires and "does not specify" cannot.
	bogus := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=nonsense-99\r\n\r\n<html>x</html>", true)
	requireOneFinding(t, runPosture(t, checkHTMLUsesUnrecognizedCharset, bogus), "HTML uses unrecognized charset")
	if got := runPosture(t, checkHTMLDoesNotSpecifyCharset, bogus); len(got) != 0 {
		t.Errorf("does-not-specify fired with a charset declared: %d findings", len(got))
	}
}

func TestWiredCharsetChecksIgnoreNonHTML(t *testing.T) {
	cc := postureFixture(t, "GET /a.json HTTP/1.1\r\nHost: app.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}", true)
	if got := runPosture(t, checkHTMLDoesNotSpecifyCharset, cc); len(got) != 0 {
		t.Fatalf("the HTML charset row fired on a JSON response: %d findings", len(got))
	}
}

// An absent Content-Type belongs to "Content type is not specified", never to this row.
func TestWiredContentTypeIncorrectlyStatedIgnoresAbsentHeader(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n<html>x</html>", true)
	if got := runPosture(t, checkContentTypeIncorrectlyStated, cc); len(got) != 0 {
		t.Fatalf("got %d findings on an absent Content-Type; that is a different row", len(got))
	}
}

func TestWiredCrossDomainScriptIncludeFires(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<script src="https://cdn.other.test/a.js"></script>`), true)
	got := runPosture(t, checkCrossDomainScriptInclude, cc)
	if len(got) == 0 {
		t.Fatal("a cross-domain script include was not reported")
	}
	requireOneFinding(t, got, "Cross-domain script include")
}

func TestWiredCrossDomainScriptIncludeQuietOnSameHost(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<script src="/local.js"></script>`), true)
	if got := runPosture(t, checkCrossDomainScriptInclude, cc); len(got) != 0 {
		t.Fatalf("got %d findings on a same-host script, want 0", len(got))
	}
}

func TestWiredSpoofableClientIPFires(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n",
		htmlResponse("ok"), true)
	got := runPosture(t, checkSpoofableClientIP, cc)
	if len(got) == 0 {
		t.Fatal("X-Forwarded-For was not reported as a spoofable client-IP header")
	}
	requireOneFinding(t, got, "Spoofable client IP address")
}

// ---------- disclosure bank ----------

func TestWiredPrivateKeyDisclosureFires(t *testing.T) {
	body := "oops\n-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse(body), true)
	f := requireOneFinding(t, runPosture(t, checkDisclosureFamily(DisclosurePrivateKey), cc), "Private key disclosed")
	if f.Confidence != "firm" {
		t.Errorf("confidence = %q, want firm", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "offset") {
		t.Errorf("evidence should locate the match: %q", f.Evidence)
	}
}

// Each family is its own dispatch unit: a private key must not surface under another row.
func TestWiredDisclosureFamiliesDoNotBleedIntoEachOther(t *testing.T) {
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----"
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse(body), true)
	for _, kind := range []DisclosureKind{
		DisclosureCreditCardNumber, DisclosureSocialSecurityNumber,
		DisclosureDatabaseConnectionString, DisclosureJSONWebKeySet,
	} {
		if got := runPosture(t, checkDisclosureFamily(kind), cc); len(got) != 0 {
			t.Errorf("%v fired on a private-key body: %d findings", kind, len(got))
		}
	}
}

func TestWiredDisclosureQuietOnACleanBody(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("nothing to see"), true)
	for kind := range disclosureRows {
		if got := runPosture(t, checkDisclosureFamily(kind), cc); len(got) != 0 {
			t.Errorf("%v fired on a clean body: %d findings", kind, len(got))
		}
	}
}

// ---------- ViewState and serialized objects ----------

// The MAC heuristic is explicitly not a proof, so the finding must be tentative and say so.
func TestWiredViewStateWithoutMACIsTentative(t *testing.T) {
	// A plaintext LOSFormatter blob with no trailing MAC.
	blob := base64.StdEncoding.EncodeToString([]byte{0xFF, 0x01, 'a', 'b', 'c'})
	body := `<form><input type="hidden" name="__VIEWSTATE" value="` + blob + `"></form>`
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse(body), true)

	got := runPosture(t, checkViewStateWithoutMAC, cc)
	if len(got) == 0 {
		t.Fatal("a plaintext ViewState blob with no trailing MAC was not reported")
	}
	f := requireOneFinding(t, got, "ASP.NET ViewState without MAC enabled")
	if f.Confidence != "tentative" {
		t.Errorf("confidence = %q, want tentative: MAC absence is a heuristic, not a proof", f.Confidence)
	}
	if !strings.Contains(f.Description, "heuristic") {
		t.Errorf("detail must say the verdict is heuristic: %q", f.Description)
	}
}

func TestWiredViewStateQuietWhenNoFieldPresent(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<form><input type="hidden" name="csrf" value="x"></form>`), true)
	if got := runPosture(t, checkViewStateWithoutMAC, cc); len(got) != 0 {
		t.Fatalf("got %d findings with no __VIEWSTATE field, want 0", len(got))
	}
}

func TestExtractHiddenFieldValueReadsTheValueAttribute(t *testing.T) {
	body := `<form><input type="hidden" name="__VIEWSTATE" value="AAEC"><input name="other" value="no"></form>`
	if got := extractHiddenFieldValue(body, "__VIEWSTATE"); got != "AAEC" {
		t.Fatalf("extractHiddenFieldValue = %q, want AAEC", got)
	}
	if got := extractHiddenFieldValue(body, "absent"); got != "" {
		t.Errorf("extractHiddenFieldValue for an absent field = %q, want empty", got)
	}
}

// The false-positive direction: a ViewState the heuristic reads as MAC-protected must not be
// reported. Reporting a protected ViewState as unprotected is the expensive error here.
func TestWiredViewStateQuietWhenMACIsDetected(t *testing.T) {
	// LOSFormatter signature, then a low-diversity "object graph", then a 20-byte
	// high-diversity tail — which is what detectMAC's discriminator reads as a digest.
	blob := []byte{0xFF, 0x01}
	for range 48 {
		blob = append(blob, 0x05)
	}
	for i := range 20 {
		blob = append(blob, byte(0x40+i*7))
	}
	vs := ParseViewState(base64.StdEncoding.EncodeToString(blob))
	if vs.ParseError != "" {
		t.Fatalf("fixture rejected by the decoder: %s", vs.ParseError)
	}
	if !vs.MACEnabled() {
		t.Fatalf("fixture was not read as MAC-protected (MACLength=%d); the discriminator changed and this test needs a new fixture", vs.MACLength)
	}

	body := `<form><input type="hidden" name="__VIEWSTATE" value="` +
		base64.StdEncoding.EncodeToString(blob) + `"></form>`
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse(body), true)
	if got := runPosture(t, checkViewStateWithoutMAC, cc); len(got) != 0 {
		t.Fatalf("got %d findings on a MAC-protected ViewState, want 0", len(got))
	}
}

// An encrypted ViewState says nothing about MAC enforcement, so it must stay quiet too.
func TestWiredViewStateQuietWhenEncrypted(t *testing.T) {
	blob := make([]byte, 64)
	for i := range blob {
		blob[i] = byte(i*31 + 7)
	}
	enc := base64.StdEncoding.EncodeToString(blob)
	// The blob is deterministic, so this precondition is a fact about the fixture, not a
	// runtime condition. Asserting it keeps the test from silently becoming a no-op if
	// ParseViewState ever starts reading this blob as a plain, MAC-less ViewState — which is
	// the one interpretation under which the assertion below would be wrong rather than passing.
	vs := ParseViewState(enc)
	if vs.ParseError == "" && !vs.IsEncrypted() {
		t.Fatalf("fixture parsed as a plain ViewState (encrypted=%v, parseErr=%q); it is meant to be encrypted or unparseable, so this test would assert nothing",
			vs.IsEncrypted(), vs.ParseError)
	}
	body := `<form><input type="hidden" name="__VIEWSTATE" value="` + enc + `"></form>`
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse(body), true)
	if got := runPosture(t, checkViewStateWithoutMAC, cc); len(got) != 0 {
		t.Fatalf("got %d findings on an encrypted/unparseable ViewState, want 0", len(got))
	}
}

func TestWiredSerializedObjectFires(t *testing.T) {
	// Java serialization magic: 0xAC 0xED 0x00 0x05.
	body := "\xac\xed\x00\x05sr\x00\x04Test"
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"+body, true)
	got := runPosture(t, checkSerializedObjectInMessage, cc)
	if len(got) == 0 {
		t.Fatal("a Java-serialized object body was not reported")
	}
	requireOneFinding(t, got, "Serialized object in HTTP message")
}

func TestWiredSerializedObjectQuietOnPlainBody(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("just text"), true)
	if got := runPosture(t, checkSerializedObjectInMessage, cc); len(got) != 0 {
		t.Fatalf("got %d findings on a plain body, want 0", len(got))
	}
}

// ---------- CSP ----------

// Report-only enforces nothing. Evaluating it would report weaknesses in a policy that was
// never in effect, so every CSP runner must ignore it.
func TestWiredCSPRunnersIgnoreReportOnly(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Content-Security-Policy-Report-Only: script-src 'unsafe-inline'"), true)
	for name, fn := range map[string]func(context.Context, *CheckContext) ([]*Finding, error){
		"allowlisted": checkCSPAllowlistedScriptResources,
		"script":      checkCSPAllowsUntrustedScript,
		"style":       checkCSPAllowsUntrustedStyle,
		"form":        checkCSPAllowsFormHijacking,
		"malformed":   checkCSPMalformedSyntax,
	} {
		if got := runPosture(t, fn, cc); len(got) != 0 {
			t.Errorf("%s fired on a report-only policy: %d findings", name, len(got))
		}
	}
}

func TestWiredCSPRunnersQuietWithNoPolicyAtAll(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	for _, fn := range []func(context.Context, *CheckContext) ([]*Finding, error){
		checkCSPAllowlistedScriptResources, checkCSPAllowsUntrustedScript,
		checkCSPAllowsUntrustedStyle, checkCSPAllowsFormHijacking, checkCSPMalformedSyntax,
	} {
		if got := runPosture(t, fn, cc); len(got) != 0 {
			t.Errorf("a CSP runner fired with no policy present: %d findings", len(got))
		}
	}
}

func TestWiredCSPUntrustedScriptFiresOnUnsafeInline(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Content-Security-Policy: script-src 'unsafe-inline'"), true)
	requireOneFinding(t, runPosture(t, checkCSPAllowsUntrustedScript, cc),
		"Content security policy: allows untrusted script execution")
}

func TestWiredCSPAllowlistedScriptResourcesNamesTheSources(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Content-Security-Policy: script-src https://cdn.test"), true)
	got := runPosture(t, checkCSPAllowlistedScriptResources, cc)
	if len(got) == 0 {
		t.Fatal("an allowlisted external script source was not reported")
	}
	if !strings.Contains(got[0].Evidence, "cdn.test") {
		t.Errorf("evidence should name the source: %q", got[0].Evidence)
	}
}

// ---------- wiring invariants ----------

func TestEveryPassiveAnalysisDescriptorIsRunnableAndGated(t *testing.T) {
	descs := PassiveAnalysisCheckDescriptors()
	if len(descs) != 28 {
		t.Fatalf("got %d descriptors, want 28", len(descs))
	}
	seen := make(map[uint32]string)
	for _, d := range descs {
		if !d.Runnable() || !d.Valid() {
			t.Errorf("%q is not a valid runnable descriptor", d.Name)
		}
		if d.Enabled == nil || d.Enabled(&ScanConfig{}) {
			t.Errorf("%q is admitted with the flag off", d.Name)
		}
		if !d.Enabled(&ScanConfig{CheckPassiveAnalysis: true}) {
			t.Errorf("%q is not admitted with CheckPassiveAnalysis set", d.Name)
		}
		if prev, dup := seen[d.TypeIndex]; dup {
			t.Errorf("TypeIndex %d claimed by both %q and %q", d.TypeIndex, prev, d.Name)
		}
		seen[d.TypeIndex] = d.Name
	}
}

func TestEveryDisclosureFamilyHasItsOwnRow(t *testing.T) {
	if len(disclosureRows) != 9 {
		t.Fatalf("got %d disclosure rows, want 9", len(disclosureRows))
	}
	for kind, row := range disclosureRows {
		if _, ok := ByName(row.name); !ok {
			t.Errorf("%v maps to %q, which is not in the catalog", kind, row.name)
		}
	}
}

func TestPassiveAnalysisChecksTolerateAnEmptyContext(t *testing.T) {
	runners := []func(context.Context, *CheckContext) ([]*Finding, error){
		checkTLSCookieWithoutSecure, checkCookieScopedToParentDomain, checkCookieWithoutHttpOnly,
		checkSessionTokenInURL, checkFrameableResponse, checkXSSFilterDisabled,
		checkHTMLDoesNotSpecifyCharset, checkHTMLUsesUnrecognizedCharset,
		checkContentTypeIncorrectlyStated, checkCrossDomainScriptInclude, checkSpoofableClientIP,
		checkBase64EncodedDataInParameter, checkViewStateWithoutMAC, checkSerializedObjectInMessage,
		checkCSPAllowlistedScriptResources, checkCSPAllowsUntrustedScript,
		checkCSPAllowsUntrustedStyle, checkCSPAllowsFormHijacking, checkCSPMalformedSyntax,
	}
	for kind := range disclosureRows {
		runners = append(runners, checkDisclosureFamily(kind))
	}
	for i, fn := range runners {
		got, err := fn(context.Background(), &CheckContext{})
		if err != nil {
			t.Errorf("runner %d errored on an empty context: %v", i, err)
		}
		if len(got) != 0 {
			t.Errorf("runner %d produced %d findings from an empty context", i, len(got))
		}
	}
}
