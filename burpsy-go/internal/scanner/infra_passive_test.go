package scanner

import "testing"

// ---------------------------------------------------------------------------
// Group 1: cookie security analyser
// ---------------------------------------------------------------------------

func TestParseSetCookieParsesAllAttributesAndDefaultsWhenAbsent(t *testing.T) {
	full := ParseSetCookie("session=abc123; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Strict; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
	if full.Name != "session" || full.Value != "abc123" {
		t.Fatalf("name/value must come from the part before the first ';', got %+v", full)
	}
	if full.Domain != ".example.com" || full.Path != "/" || full.SameSite != "Strict" {
		t.Fatalf("string attributes not parsed correctly: %+v", full)
	}
	if !full.Secure || !full.HttpOnly {
		t.Fatalf("bare Secure/HttpOnly flags must be recorded true, got %+v", full)
	}

	bare := ParseSetCookie("id=42")
	if bare.Name != "id" || bare.Value != "42" {
		t.Fatalf("bare cookie name/value wrong: %+v", bare)
	}
	if bare.Secure || bare.HttpOnly || bare.Domain != "" {
		t.Fatalf("a cookie with no attributes must default every flag/string to its zero value, got %+v", bare)
	}
}

func TestMissingSecureOnTLS(t *testing.T) {
	if !(CookieAttrs{Secure: false}).MissingSecureOnTLS(true) {
		t.Fatal("a non-Secure cookie issued over TLS must be flagged")
	}
	if (CookieAttrs{Secure: true}).MissingSecureOnTLS(true) {
		t.Fatal("a Secure cookie must not be flagged")
	}
}

func TestScopedToParentDomainRejectsDomainEqualToIssuingHost(t *testing.T) {
	if !(CookieAttrs{Domain: ".example.com"}).ScopedToParentDomain("www.example.com") {
		t.Fatal("a leading-dot Domain that is a real ancestor of the request host must be flagged as parent-scoped")
	}
	if (CookieAttrs{Domain: "example.com"}).ScopedToParentDomain("example.com") {
		t.Fatal("Domain equal to the issuing host is the default, safe host-only scope and must NOT be reported as parent-scoped")
	}
}

func TestMissingHttpOnly(t *testing.T) {
	if !(CookieAttrs{}).MissingHttpOnly() {
		t.Fatal("a cookie with HttpOnly unset must be flagged as missing HttpOnly")
	}
	if (CookieAttrs{HttpOnly: true}).MissingHttpOnly() {
		t.Fatal("a cookie with HttpOnly set must not be flagged")
	}
}

func TestLooksLikeSessionToken(t *testing.T) {
	for _, name := range []string{"JSESSIONID", "jsessionid", "ASPSESSIONIDCSRRQSQC", "connect.sid"} {
		if !LooksLikeSessionToken(name) {
			t.Errorf("%q is a known session-token cookie family and must be recognised", name)
		}
	}
	if LooksLikeSessionToken("username") {
		t.Fatal("an ordinary cookie name must not be reported as a session token")
	}
}

// ---------------------------------------------------------------------------
// Group 2: response/header attribute analyser
// ---------------------------------------------------------------------------

func TestIsFrameable(t *testing.T) {
	if !IsFrameable("", "") {
		t.Fatal("no X-Frame-Options and no CSP must be reported frameable")
	}
	if IsFrameable("DENY", "") {
		t.Fatal("X-Frame-Options: DENY must not be reported frameable")
	}
	if IsFrameable("", "default-src 'self'; frame-ancestors 'none'") {
		t.Fatal("a CSP frame-ancestors directive must not be reported frameable")
	}
}

func TestXSSFilterDisabled(t *testing.T) {
	if !XSSFilterDisabled("0") {
		t.Fatal("X-XSS-Protection: 0 must be reported as disabled")
	}
	if !XSSFilterDisabled("0; mode=block") {
		t.Fatal("a leading 0 followed by directives is still disabled")
	}
	if XSSFilterDisabled("1; mode=block") {
		t.Fatal("X-XSS-Protection: 1 must not be reported as disabled")
	}
}

func TestDeclaredCharsetHeaderWinsOverMetaTag(t *testing.T) {
	charset, source := DeclaredCharset(`text/html; charset=UTF-8`, `<html><head><meta charset="ISO-8859-1"></head></html>`)
	if charset != "UTF-8" || source != "content-type header" {
		t.Fatalf("a Content-Type charset must win over a conflicting <meta charset>, got (%q, %q)", charset, source)
	}

	charset, source = DeclaredCharset("text/html", "<html><body>hi</body></html>")
	if charset != "" || source != "" {
		t.Fatalf("no charset declared anywhere must return empty charset and source, got (%q, %q)", charset, source)
	}
}

func TestCharsetIsRecognised(t *testing.T) {
	if !CharsetIsRecognised("UTF-8") {
		t.Fatal("UTF-8 must be recognised")
	}
	if CharsetIsRecognised("made-up-charset-xyz") {
		t.Fatal("a nonexistent charset name must not be recognised")
	}
}

func TestContentTypeMatchesBody(t *testing.T) {
	png := []byte("\x89PNG\x0D\x0A\x1A\x0A\x00\x00\x00\x0DIHDR")
	if !ContentTypeMatchesBody("image/png", png) {
		t.Fatal("declared image/png matching real PNG magic bytes must report a match")
	}
	if ContentTypeMatchesBody("image/png", []byte("<html><body>fake</body></html>")) {
		t.Fatal("declared image/png but body sniffs confidently as HTML must report a mismatch")
	}
	if !ContentTypeMatchesBody("application/json", []byte(`{"ok":true}`)) {
		t.Fatal("JSON has no dedicated sniff signature (it sniffs as the text/plain fallback); it must not be flagged as a mismatch")
	}
}

func TestCrossDomainScriptSrcs(t *testing.T) {
	got := CrossDomainScriptSrcs(`<script src="https://evil.example.com/x.js"></script>`, "example.com")
	if len(got) != 1 || got[0] != "https://evil.example.com/x.js" {
		t.Fatalf("an absolute script src on a different host must be reported, got %v", got)
	}
	if got := CrossDomainScriptSrcs(`<script src="/js/app.js"></script>`, "example.com"); len(got) != 0 {
		t.Fatalf("a relative script src must not be reported cross-domain, got %v", got)
	}
}

func TestLooksBase64RejectsOrdinaryEnglishWord(t *testing.T) {
	if !LooksBase64("bpuO2WiQjAqZSf3raV4oWks+T2jj6oA8y+7MdXj5d3o=") {
		t.Fatal("a real base64 encoding of random bytes (4 char classes, high entropy) must be flagged")
	}
	if LooksBase64("internationalization") {
		t.Fatal("an ordinary English word must not be flagged, even though it is a valid base64-alphabet string")
	}
}

func TestSpoofableClientIPHeaders(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 1.2.3.4\r\nCF-Connecting-IP: 5.6.7.8\r\n\r\n"
	got := SpoofableClientIPHeaders(raw)
	if len(got) != 2 || got[0] != "X-Forwarded-For" || got[1] != "CF-Connecting-IP" {
		t.Fatalf("expected exactly the two present headers in fixed order, got %v", got)
	}
	if got := SpoofableClientIPHeaders("GET / HTTP/1.1\r\nHost: h\r\n\r\n"); len(got) != 0 {
		t.Fatalf("a request with none of the spoofable headers must return no headers, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Group 3: information-disclosure pattern bank
// ---------------------------------------------------------------------------

func TestDisclosureKindString(t *testing.T) {
	if got := DisclosureCreditCardNumber.String(); got != "credit card number" {
		t.Fatalf("DisclosureCreditCardNumber.String() = %q", got)
	}
	if got := DisclosureKind(999).String(); got != "unknown disclosure" {
		t.Fatalf("an out-of-range DisclosureKind must render as \"unknown disclosure\", got %q", got)
	}
}

func containsDisclosureKind(disclosures []Disclosure, kind DisclosureKind) bool {
	for _, d := range disclosures {
		if d.Kind == kind {
			return true
		}
	}
	return false
}

func TestScanDisclosuresDetectsEachFamilyFromRealEvidence(t *testing.T) {
	body := `<html><head><title>Index of /backup/</title></head><body>
<h1>Index of /backup/</h1>
<a href="../">Parent Directory</a>
Contact admin@example.com for access. Internal host 192.168.1.50 responded.
SSN on file: 123-45-6789. Card ending in 4532 0151 1283 0366.
Server=db1.internal;Database=app;User Id=sa;Password=S3cr3t!;
<?php echo "leaked source"; ?>
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA
-----END RSA PRIVATE KEY-----
{"keys":[{"kty":"RSA","kid":"test-key-1","e":"AQAB","n":"abc"}]}
</body></html>`

	got := ScanDisclosures(body)
	for _, kind := range []DisclosureKind{
		DisclosureDatabaseConnectionString,
		DisclosureSourceCode,
		DisclosureDirectoryListing,
		DisclosureEmailAddress,
		DisclosurePrivateIPAddress,
		DisclosureSocialSecurityNumber,
		DisclosureCreditCardNumber,
		DisclosurePrivateKey,
		DisclosureJSONWebKeySet,
	} {
		if !containsDisclosureKind(got, kind) {
			t.Errorf("expected a %s disclosure to be found in the fixture body, found kinds: %v", kind, got)
		}
	}
}

func TestScanDisclosuresRejectsLuhnInvalidCreditCardAndOtherFalsePositives(t *testing.T) {
	body := "Reference number 4532015112830367 was not charged. " +
		"Preferences saved: theme=dark; lang=en; " +
		"Public resolver 8.8.8.8 replied."

	got := ScanDisclosures(body)
	if containsDisclosureKind(got, DisclosureCreditCardNumber) {
		t.Fatal("a Luhn-invalid 16-digit string must NOT be reported as a credit card number")
	}
	if containsDisclosureKind(got, DisclosureDatabaseConnectionString) {
		t.Fatal("ordinary key=value preference text with no location/credential keywords must not be reported as a connection string")
	}
	if containsDisclosureKind(got, DisclosurePrivateIPAddress) {
		t.Fatal("a public IP address must not be reported as a private IP disclosure")
	}
}

// TestACookieScopedToAPublicSuffixIsNotReportedAsParentDomainWidening defends the
// publicsuffix-backed boundary check. Domain=co.uk against host shop.co.uk IS a
// dot-boundary suffix, so a plain suffix test reports it as real parent-domain widening.
// No browser accepts a cookie scoped to a public suffix, so that attribute widens nothing
// and reporting it would be a false positive.
func TestACookieScopedToAPublicSuffixIsNotReportedAsParentDomainWidening(t *testing.T) {
	c := CookieAttrs{Name: "s", Value: "1", Domain: "co.uk"}
	if c.ScopedToParentDomain("shop.co.uk") {
		t.Error("Domain=co.uk is a public suffix; browsers reject the cookie outright, so it must not be reported as parent-domain widening")
	}
}

// TestACookieScopedToARegistrableParentIsStillReported is the positive counterpart: the
// public-suffix guard must not suppress the real finding it sits beside.
func TestACookieScopedToARegistrableParentIsStillReported(t *testing.T) {
	c := CookieAttrs{Name: "s", Value: "1", Domain: "example.co.uk"}
	if !c.ScopedToParentDomain("shop.example.co.uk") {
		t.Error("Domain=example.co.uk is the registrable domain and genuinely widens scope to every sibling subdomain; this must still be reported")
	}
}

// TestCharsetRecognitionUsesTheBrowserEncodingTableNotAHandList defends the htmlindex
// change: these are real WHATWG-registered labels a hand-maintained list plausibly omits,
// and treating them as unrecognised would be a false "HTML uses unrecognized charset".
func TestCharsetRecognitionUsesTheBrowserEncodingTableNotAHandList(t *testing.T) {
	for _, label := range []string{"shift_jis", "euc-kr", "windows-1252", "gbk", "big5", "koi8-r"} {
		if !CharsetIsRecognised(label) {
			t.Errorf("%q is a WHATWG-registered encoding label that browsers honour; reporting it as unrecognised is a false positive", label)
		}
	}
	if CharsetIsRecognised("definitely-not-a-charset-xyz") {
		t.Error("an invented label must still be reported as unrecognised, or the check reports nothing at all")
	}
}

// serve-index — the Node/Express ecosystem's standard directory-listing
// middleware — titles its pages "listing directory /path/", which none of the
// Apache/IIS markers recovered from the Burp corpus match. OWASP Juice Shop's
// /ftp/ route is the live exhibit; every Express app on serve-index shares it.
func TestScanDisclosuresDetectsServeIndexListing(t *testing.T) {
	body := `<!DOCTYPE html><html><head><title>listing directory /ftp/</title></head>` +
		`<body><div id="listing"><h1>listing directory /ftp/</h1><ul id="files"></ul></div></body></html>`
	got := ScanDisclosures(body)
	if !containsDisclosureKind(got, DisclosureDirectoryListing) {
		t.Errorf("a serve-index listing page was not flagged as a directory listing; found kinds: %v", got)
	}
}
