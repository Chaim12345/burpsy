package scanner

// Wired evaluators for the remaining network-free passive analysers: cookie security,
// response/header attributes, the information-disclosure bank, ASP.NET ViewState,
// serialized-object recognition, and CSP directive evaluation.
//
// Same shape as checks_passive_posture.go: read the captured exchange, call a pure analyser,
// build a finding. Nothing here sends a request.

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func passiveAnalysisEnabled(c *ScanConfig) bool { return c != nil && c.CheckPassiveAnalysis }

// ---------------------------------------------------------------------------
// cookies
// ---------------------------------------------------------------------------

// eachSetCookie walks the response's Set-Cookie headers as parsed attribute sets.
func eachSetCookie(cc *CheckContext, fn func(CookieAttrs, string) bool) {
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	for _, raw := range headerValues(respRaw, headerSetCookie) {
		if !fn(ParseSetCookie(raw), raw) {
			return
		}
	}
}

func checkTLSCookieWithoutSecure(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	var out []*Finding
	eachSetCookie(cc, func(c CookieAttrs, _ string) bool {
		if c.MissingSecureOnTLS(cc.Exchange.TLS) {
			out = append(out, buildHeaderFinding(cc, "TLS cookie without secure flag set",
				"medium", "certain", "Set-Cookie: "+c.Name,
				"a cookie set over TLS carries no Secure attribute, so it will also be sent over cleartext"))
			return false
		}
		return true
	})
	return out, nil
}

func checkCookieScopedToParentDomain(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	// A session cookie is preferred over any other parent-scoped cookie: it is the one whose scope is
	// a provable cookie-tossing exposure (0vzb.19), reported here rather than on a row of its own.
	var first, session *CookieAttrs
	eachSetCookie(cc, func(c CookieAttrs, _ string) bool {
		if !c.ScopedToParentDomain(cc.Exchange.Host) {
			return true
		}
		if first == nil {
			first = &c
		}
		if LooksLikeSessionCookie(c.Name, c.Value) {
			session = &c
			return false
		}
		return true
	})
	if first == nil {
		return nil, nil
	}
	c, detail := first, "the cookie is scoped to a parent domain, so every sibling host receives it"
	if session != nil {
		c = session
		detail = "the session cookie is scoped to a parent domain, so every sibling host receives it, and " +
			"any sibling host can set a cookie with the same name, Domain and Path that replaces it in the " +
			"browser (cookie tossing): a session fixation or login-CSRF vector from the least trusted subdomain"
	}
	return []*Finding{buildHeaderFinding(cc, "Cookie scoped to parent domain",
		"info", "certain", fmt.Sprintf("Set-Cookie: %s; Domain=%s", c.Name, c.Domain), detail)}, nil
}

func checkCookieWithoutHttpOnly(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	var out []*Finding
	eachSetCookie(cc, func(c CookieAttrs, _ string) bool {
		if c.MissingHttpOnly() {
			detail := "the cookie is readable from JavaScript"
			if isSignedJWT(c.Value) {
				// Same row, a sharper statement: the readable value is a bearer credential.
				detail = "the cookie holds a signed JWT, a bearer credential, and is readable from JavaScript"
			}
			out = append(out, buildHeaderFinding(cc, "Cookie without HttpOnly flag set",
				"low", "certain", "Set-Cookie: "+c.Name, detail))
			return false
		}
		return true
	})
	return out, nil
}

func checkSessionTokenInURL(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	u, err := url.Parse(exchangeURL(cc.Exchange))
	if err != nil {
		return nil, nil
	}
	for name, values := range u.Query() {
		named := LooksLikeSessionToken(name)
		for _, v := range values {
			if strings.TrimSpace(v) == "" {
				continue
			}
			if named {
				return []*Finding{buildHeaderFinding(cc, "Session token in URL",
					"medium", "certain", "query parameter "+name,
					"a session-token-like parameter appears in the URL, where it is logged and leaked via Referer")}, nil
			}
			// A signed JWT is a bearer credential whatever its parameter is called: the value
			// itself is the evidence, decoded rather than guessed from the name.
			if isSignedJWT(v) {
				return []*Finding{buildHeaderFinding(cc, "Session token in URL",
					"medium", "certain", "query parameter "+name+" carries a JWT",
					"a signed JSON Web Token (a bearer credential) is sent in the URL, where it is logged and leaked via Referer")}, nil
			}
		}
	}
	return nil, nil
}

// isSignedJWT reports whether v is a whole JWS compact token with a JSON header naming a signing
// algorithm and a non-empty signature: a credential, not merely a dotted string.
func isSignedJWT(v string) bool {
	t := ParseJWT(strings.TrimSpace(v))
	return t.ParseError == "" && t.Header.Alg != "" && !strings.EqualFold(t.Header.Alg, "none") && t.RawSignature != ""
}

// ---------------------------------------------------------------------------
// response and header attributes
// ---------------------------------------------------------------------------

func checkFrameableResponse(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	xfo := nonEmptyHeaderValues(headerValues(respRaw, headerXFrameOptions))
	csp := nonEmptyHeaderValues(headerValues(respRaw, headerContentSecurityPolicy))
	if !IsFrameableHeaders(xfo, csp) {
		return nil, nil
	}
	evidence := "no X-Frame-Options and no frame-ancestors directive"
	switch {
	case len(csp) > 0 && strings.Contains(strings.ToLower(strings.Join(csp, ";")), "frame-ancestors"):
		evidence = "Content-Security-Policy: " + strings.Join(csp, ", ") + " (frame-ancestors admits any origin)"
	case len(xfo) > 0:
		evidence = "X-Frame-Options: " + strings.Join(xfo, ", ") + " (not a value browsers enforce) and no frame-ancestors directive"
	}
	return []*Finding{buildHeaderFinding(cc, "Frameable response (potential Clickjacking)",
		"info", "certain", evidence,
		"the response can be framed by another origin")}, nil
}

func checkXSSFilterDisabled(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := headerValue(responseRaw(cc.Scanner, cc.Exchange), "x-xss-protection")
	if !XSSFilterDisabled(raw) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Browser cross-site scripting filter disabled",
		"info", "certain", "X-XSS-Protection: "+raw,
		"the response explicitly disables the browser's XSS filter")}, nil
}

func checkHTMLDoesNotSpecifyCharset(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	contentType := headerValue(respRaw, "content-type")
	if !strings.Contains(strings.ToLower(contentType), "html") {
		return nil, nil
	}
	charset, _ := DeclaredCharset(contentType, responseBody(respRaw))
	if charset != "" {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "HTML does not specify charset",
		"info", "certain", "Content-Type: "+contentType,
		"an HTML response declares no character set, leaving the browser to guess it")}, nil
}

func checkHTMLUsesUnrecognizedCharset(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	contentType := headerValue(respRaw, "content-type")
	charset, source := DeclaredCharset(contentType, responseBody(respRaw))
	if charset == "" || CharsetIsRecognised(charset) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "HTML uses unrecognized charset",
		"info", "certain", fmt.Sprintf("charset %q declared in %s", charset, source),
		"the declared character set is not one the browser will recognise")}, nil
}

func checkContentTypeIncorrectlyStated(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	contentType := headerValue(respRaw, "content-type")
	// An absent Content-Type is the "not specified" row, not this one;
	// ContentTypeMatchesBody returns true for absence, so gate on presence here.
	if strings.TrimSpace(contentType) == "" {
		return nil, nil
	}
	body := responseBody(respRaw)
	if body == "" || ContentTypeMatchesBody(contentType, []byte(body)) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Content type incorrectly stated",
		"info", "certain", "Content-Type: "+contentType,
		"the declared content type does not match the response body")}, nil
}

func checkCrossDomainScriptInclude(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	srcs := CrossDomainScriptSrcs(responseBody(respRaw), cc.Exchange.Host)
	if len(srcs) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Cross-domain script include",
		"info", "certain", strings.Join(srcs, ", "),
		"the page executes script loaded from another domain, which it therefore trusts completely")}, nil
}

func checkSpoofableClientIP(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	headers := SpoofableClientIPHeaders(requestRaw(cc.Scanner, cc.Exchange))
	if len(headers) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Spoofable client IP address",
		"info", "certain", strings.Join(headers, ", "),
		"the request carries a client-IP header the application may trust")}, nil
}

func checkBase64EncodedDataInParameter(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	u, err := url.Parse(exchangeURL(cc.Exchange))
	if err != nil {
		return nil, nil
	}
	for name, values := range u.Query() {
		for _, v := range values {
			if LooksBase64(v) {
				return []*Finding{buildHeaderFinding(cc, "Base64-encoded data in parameter",
					"info", "certain", fmt.Sprintf("parameter %s=%s", name, v),
					"a parameter carries base64-encoded data, which may hide structured input the application decodes")}, nil
			}
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// information disclosure
// ---------------------------------------------------------------------------

// disclosureRow maps a bank family to its catalog row and severity.
var disclosureRows = map[DisclosureKind]struct {
	name     string
	severity string
}{
	DisclosureDatabaseConnectionString: {"Database connection string disclosed", "high"},
	DisclosureSourceCode:               {"Source code disclosure", "medium"},
	DisclosureDirectoryListing:         {"Directory listing", "info"},
	DisclosureEmailAddress:             {"Email addresses disclosed", "info"},
	DisclosurePrivateIPAddress:         {"Private IP addresses disclosed", "info"},
	DisclosureSocialSecurityNumber:     {"Social security numbers disclosed", "high"},
	DisclosureCreditCardNumber:         {"Credit card numbers disclosed", "high"},
	DisclosurePrivateKey:               {"Private key disclosed", "high"},
	DisclosureJSONWebKeySet:            {"Json Web Key Set disclosed", "info"},
}

// checkDisclosureFamily builds a runner for one disclosure family. The bank is scanned once
// per call and filtered, rather than scanned once and shared, because each catalog row is a
// separate dispatch unit and must be independently reportable.
func checkDisclosureFamily(kind DisclosureKind) CheckRunner {
	row := disclosureRows[kind]
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc.Scanner == nil || cc.Exchange == nil {
			return nil, nil
		}
		body := responseBody(responseRaw(cc.Scanner, cc.Exchange))
		if body == "" {
			return nil, nil
		}
		for _, d := range ScanDisclosures(body) {
			if d.Kind != kind {
				continue
			}
			return []*Finding{buildHeaderFinding(cc, row.name, row.severity, "firm",
				fmt.Sprintf("%s at offset %d", d.Match, d.Offset),
				"the response body discloses "+kind.String())}, nil
		}
		return nil, nil
	}
}

// extractHiddenFieldValue pulls the value attribute of a named input from a response body.
// Form parsing does not carry values (FormField is about shape, not content), and ViewState
// analysis needs the actual blob, so this reads the attribute directly.
func extractHiddenFieldValue(body, fieldName string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return ""
	}
	var found string
	doc.Find("input[name]").EachWithBreak(func(_ int, s *goquery.Selection) bool {
		name, _ := s.Attr("name")
		if !strings.EqualFold(name, fieldName) {
			return true
		}
		found, _ = s.Attr("value")
		return false
	})
	return found
}

func checkViewStateWithoutMAC(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	body := responseBody(responseRaw(cc.Scanner, cc.Exchange))
	field := extractHiddenFieldValue(body, "__VIEWSTATE")
	if field == "" {
		return nil, nil
	}
	vs := ParseViewState(field)
	if vs.ParseError != "" || vs.IsEncrypted() || vs.MACEnabled() {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "ASP.NET ViewState without MAC enabled",
		"high", "tentative",
		fmt.Sprintf("__VIEWSTATE decoded to %d bytes with no trailing MAC", len(vs.Decoded)),
		"the ViewState appears not to be MAC-protected, so a client may tamper with it; MAC absence is a documented heuristic, not a proof")}, nil
}

func checkSerializedObjectInMessage(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	reqRaw := requestRaw(cc.Scanner, cc.Exchange)
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	for _, c := range serializedCarriers(reqRaw, respRaw) {
		if kind := DetectSerializedObject([]byte(c.value)); kind != SerializedNone {
			return []*Finding{buildHeaderFinding(cc, "Serialized object in HTTP message",
				"high", "firm", fmt.Sprintf("%s in the %s", kind, c.where),
				"a native serialized object crosses the trust boundary, which is the precondition for an insecure-deserialization attack")}, nil
		}
	}
	return nil, nil
}

// serializedCarrier is one place in an exchange a serialized object can travel.
type serializedCarrier struct{ where, value string }

// serializedCarriers lists, in a fixed order (request before response), the places a serialized
// object is carried: the request's query parameters, cookies and body, then the response's
// Set-Cookie values and body. A parameter or cookie is offered both as sent and percent-decoded,
// because a blob is commonly percent-encoded on the wire (PHP serialize() text always is in a query
// string). The bodies are scanned whole, as they were before cookies and parameters were added.
func serializedCarriers(reqRaw, respRaw string) []serializedCarrier {
	var out []serializedCarrier
	add := func(where, v string) {
		if v == "" {
			return
		}
		out = append(out, serializedCarrier{where, v})
		if d, err := url.QueryUnescape(v); err == nil && d != v {
			out = append(out, serializedCarrier{where, d})
		}
	}
	head := reqRaw
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		head = head[:i]
	}
	if line, _, _ := strings.Cut(head, "\r\n"); line != "" {
		if f := strings.Fields(line); len(f) >= 2 {
			if _, q, ok := strings.Cut(f[1], "?"); ok {
				for _, kv := range strings.Split(q, "&") {
					k, v, _ := strings.Cut(kv, "=")
					add(fmt.Sprintf("request parameter %q", k), v)
				}
			}
		}
	}
	for _, h := range headerValues(head, "Cookie") {
		for _, kv := range strings.Split(h, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
			add(fmt.Sprintf("request cookie %q", k), v)
		}
	}
	if b := responseBody(reqRaw); b != "" {
		out = append(out, serializedCarrier{"request body", b})
	}
	respHead := respRaw
	if i := strings.Index(respHead, "\r\n\r\n"); i >= 0 {
		respHead = respHead[:i]
	}
	for _, h := range headerValues(respHead, headerSetCookie) {
		first, _, _ := strings.Cut(h, ";")
		k, v, _ := strings.Cut(strings.TrimSpace(first), "=")
		add(fmt.Sprintf("response cookie %q", k), v)
	}
	if b := responseBody(respRaw); b != "" {
		out = append(out, serializedCarrier{"response body", b})
	}
	return out
}

// ---------------------------------------------------------------------------
// CSP directive evaluation
// ---------------------------------------------------------------------------

// enforcedCSP returns the parsed enforcing policy and whether one was present. The
// report-only header is deliberately ignored: it enforces nothing, so evaluating it would
// report weaknesses in a policy that was never in effect.
func enforcedCSP(cc *CheckContext) (CSPPolicy, string, bool) {
	raw := headerValue(responseRaw(cc.Scanner, cc.Exchange), headerContentSecurityPolicy)
	if strings.TrimSpace(raw) == "" {
		return CSPPolicy{}, "", false
	}
	return ParseCSP(raw), raw, true
}

func checkCSPAllowlistedScriptResources(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	policy, raw, ok := enforcedCSP(cc)
	if !ok {
		return nil, nil
	}
	srcs := policy.AllowlistedScriptSources()
	if len(srcs) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Content security policy: allowlisted script resources",
		"info", "certain", strings.Join(srcs, " "),
		"the policy allowlists external script sources: "+raw)}, nil
}

func checkCSPAllowsUntrustedScript(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	policy, raw, ok := enforcedCSP(cc)
	if !ok || !policy.AllowsUntrustedScript() {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Content security policy: allows untrusted script execution",
		"medium", "certain", raw,
		"the script-src policy permits untrusted script execution")}, nil
}

func checkCSPAllowsUntrustedStyle(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	policy, raw, ok := enforcedCSP(cc)
	if !ok || !policy.AllowsUntrustedStyle() {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Content security policy: allows untrusted style execution",
		"info", "certain", raw,
		"the style-src policy permits untrusted style execution")}, nil
}

func checkCSPAllowsFormHijacking(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	policy, raw, ok := enforcedCSP(cc)
	if !ok || !policy.AllowsFormHijacking() {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Content security policy: allows form hijacking",
		"low", "certain", raw,
		"the policy sets no form-action restriction, so injected markup may retarget a form")}, nil
}

func checkCSPMalformedSyntax(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	policy, _, ok := enforcedCSP(cc)
	if !ok || len(policy.MalformedReasons) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Content security policy: malformed syntax",
		"info", "certain", strings.Join(policy.MalformedReasons, "; "),
		"the policy contains syntax the browser will not apply as intended")}, nil
}

// PassiveAnalysisCheckDescriptors returns the twenty-eight network-free analyser checks.
func PassiveAnalysisCheckDescriptors() []CheckDescriptor {
	out := []CheckDescriptor{
		passiveDescriptor("TLS cookie without secure flag set", DispatchScopePerRequest, passiveAnalysisEnabled, checkTLSCookieWithoutSecure),
		// The two burpsy cookie rows (checks_cookie_attrs.go) ride this descriptor behind their own
		// switch: both read the same Set-Cookie headers, and the registry admits one descriptor per Burp type.
		passiveDescriptor("Cookie scoped to parent domain", DispatchScopePerRequest,
			func(c *ScanConfig) bool { return passiveAnalysisEnabled(c) || cookieAttributesEnabled(c) },
			cookieScopedOrAttributes(checkCookieScopedToParentDomain)),
		passiveDescriptor("Cookie without HttpOnly flag set", DispatchScopePerRequest, passiveAnalysisEnabled, checkCookieWithoutHttpOnly),
		passiveDescriptor("Session token in URL", DispatchScopePerUrl, passiveAnalysisEnabled, checkSessionTokenInURL),

		passiveDescriptor("Frameable response (potential Clickjacking)", DispatchScopePerUrl, passiveAnalysisEnabled, checkFrameableResponse),
		passiveDescriptor("Browser cross-site scripting filter disabled", DispatchScopePerUrl, passiveAnalysisEnabled, checkXSSFilterDisabled),
		passiveDescriptor("HTML does not specify charset", DispatchScopePerUrl, passiveAnalysisEnabled, checkHTMLDoesNotSpecifyCharset),
		passiveDescriptor("HTML uses unrecognized charset", DispatchScopePerUrl, passiveAnalysisEnabled, checkHTMLUsesUnrecognizedCharset),
		passiveDescriptor("Content type incorrectly stated", DispatchScopePerUrl, passiveAnalysisEnabled, checkContentTypeIncorrectlyStated),
		passiveDescriptor("Cross-domain script include", DispatchScopePerUrl, passiveAnalysisEnabled, checkCrossDomainScriptInclude),
		passiveDescriptor("Spoofable client IP address", DispatchScopePerRequest, passiveAnalysisEnabled, checkSpoofableClientIP),
		passiveDescriptor("Base64-encoded data in parameter", DispatchScopePerUrl, passiveAnalysisEnabled, checkBase64EncodedDataInParameter),

		passiveDescriptor("ASP.NET ViewState without MAC enabled", DispatchScopePerUrl, passiveAnalysisEnabled, checkViewStateWithoutMAC),
		passiveDescriptor("Serialized object in HTTP message", DispatchScopePerRequest, passiveAnalysisEnabled, checkSerializedObjectInMessage),

		passiveDescriptor("Content security policy: allowlisted script resources", DispatchScopePerUrl, passiveAnalysisEnabled, checkCSPAllowlistedScriptResources),
		passiveDescriptor("Content security policy: allows untrusted script execution", DispatchScopePerUrl, passiveAnalysisEnabled, checkCSPAllowsUntrustedScript),
		passiveDescriptor("Content security policy: allows untrusted style execution", DispatchScopePerUrl, passiveAnalysisEnabled, checkCSPAllowsUntrustedStyle),
		passiveDescriptor("Content security policy: allows form hijacking", DispatchScopePerUrl, passiveAnalysisEnabled, checkCSPAllowsFormHijacking),
		passiveDescriptor("Content security policy: malformed syntax", DispatchScopePerUrl, passiveAnalysisEnabled, checkCSPMalformedSyntax),
	}
	// The nine disclosure families share one runner shape and one bank.
	for _, kind := range []DisclosureKind{
		DisclosureDatabaseConnectionString, DisclosureSourceCode, DisclosureDirectoryListing,
		DisclosureEmailAddress, DisclosurePrivateIPAddress, DisclosureSocialSecurityNumber,
		DisclosureCreditCardNumber, DisclosurePrivateKey, DisclosureJSONWebKeySet,
	} {
		out = append(out, passiveDescriptor(disclosureRows[kind].name, DispatchScopePerUrl,
			passiveAnalysisEnabled, checkDisclosureFamily(kind)))
	}
	return out
}

// nonEmptyHeaderValues drops empty header values (a header line with no value enforces nothing).
func nonEmptyHeaderValues(vs []string) []string {
	var out []string
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}
