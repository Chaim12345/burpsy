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
	var out []*Finding
	eachSetCookie(cc, func(c CookieAttrs, _ string) bool {
		if c.ScopedToParentDomain(cc.Exchange.Host) {
			out = append(out, buildHeaderFinding(cc, "Cookie scoped to parent domain",
				"info", "certain", fmt.Sprintf("Set-Cookie: %s; Domain=%s", c.Name, c.Domain),
				"the cookie is scoped to a parent domain, so every sibling host receives it"))
			return false
		}
		return true
	})
	return out, nil
}

func checkCookieWithoutHttpOnly(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	var out []*Finding
	eachSetCookie(cc, func(c CookieAttrs, _ string) bool {
		if c.MissingHttpOnly() {
			out = append(out, buildHeaderFinding(cc, "Cookie without HttpOnly flag set",
				"low", "certain", "Set-Cookie: "+c.Name,
				"the cookie is readable from JavaScript"))
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
		if !LooksLikeSessionToken(name) {
			continue
		}
		for _, v := range values {
			if strings.TrimSpace(v) == "" {
				continue
			}
			return []*Finding{buildHeaderFinding(cc, "Session token in URL",
				"medium", "certain", "query parameter "+name,
				"a session-token-like parameter appears in the URL, where it is logged and leaked via Referer")}, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// response and header attributes
// ---------------------------------------------------------------------------

func checkFrameableResponse(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	if !IsFrameable(headerValue(respRaw, headerXFrameOptions), headerValue(respRaw, headerContentSecurityPolicy)) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Frameable response (potential Clickjacking)",
		"info", "certain", "no X-Frame-Options and no frame-ancestors directive",
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
	for label, raw := range map[string]string{
		"request":  requestRaw(cc.Scanner, cc.Exchange),
		"response": responseRaw(cc.Scanner, cc.Exchange),
	} {
		body := responseBody(raw)
		if body == "" {
			continue
		}
		if kind := DetectSerializedObject([]byte(body)); kind != SerializedNone {
			return []*Finding{buildHeaderFinding(cc, "Serialized object in HTTP message",
				"high", "firm", fmt.Sprintf("%s serialized object in the %s body", kind, label),
				"a native serialized object crosses the trust boundary, which is the precondition for an insecure-deserialization attack")}, nil
		}
	}
	return nil, nil
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
		passiveDescriptor("Cookie scoped to parent domain", DispatchScopePerRequest, passiveAnalysisEnabled, checkCookieScopedToParentDomain),
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
