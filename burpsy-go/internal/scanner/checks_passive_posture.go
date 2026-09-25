package scanner

// Wired evaluators for the network-free passive rows. Each one reads the captured exchange
// and calls a pure analyser from infra_forms.go, infra_response.go or infra_transport.go;
// none of them sends anything, so they are admissible in a passive-only scan.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func passivePostureEnabled(c *ScanConfig) bool { return c != nil && c.CheckPassivePosture }

// responseBody returns the body of a raw HTTP message, or "" when it has none.
func responseBody(raw string) string {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[i+4:]
	}
	// Tolerate bare-LF separators; a proxy-captured message should be CRLF, but a
	// malformed one must not silently read as an empty body.
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[i+2:]
	}
	return ""
}

// responseStatus parses the status code from a raw response, or 0 when unreadable.
func responseStatus(raw string) int {
	line := raw
	if i := strings.Index(raw, "\r\n"); i >= 0 {
		line = raw[:i]
	} else if i := strings.Index(raw, "\n"); i >= 0 {
		line = raw[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return code
}

// headerSet collects a raw message's headers into an http.Header so the analysers can use
// the standard accessors, including repeated-header semantics.
func headerSet(raw string) http.Header {
	h := http.Header{}
	body := strings.Index(raw, "\r\n\r\n")
	head := raw
	if body >= 0 {
		head = raw[:body]
	}
	lines := strings.Split(head, "\r\n")
	for i, line := range lines {
		if i == 0 {
			continue // status or request line
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		h.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return h
}

// ---------------------------------------------------------------------------
// password handling and cross-domain POST (infra_forms.go)
// ---------------------------------------------------------------------------

// parsedForms reads the response body and returns its forms, resolved against the page URL.
func parsedForms(cc *CheckContext) ([]Form, string) {
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	pageURL := exchangeURL(cc.Exchange)
	forms, err := ParseForms([]byte(responseBody(respRaw)), pageURL)
	if err != nil {
		return nil, pageURL
	}
	return forms, pageURL
}

func checkCleartextPasswordSubmission(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	forms, _ := parsedForms(cc)
	for _, f := range forms {
		if f.HasPasswordField() && f.SubmitsOverCleartext() {
			return []*Finding{buildHeaderFinding(cc, "Cleartext submission of password",
				"high", "certain",
				fmt.Sprintf("form action %q", f.Action),
				"a form containing a password field submits over cleartext HTTP")}, nil
		}
	}
	return nil, nil
}

func checkPasswordSubmittedUsingGET(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	forms, _ := parsedForms(cc)
	for _, f := range forms {
		if f.HasPasswordField() && f.UsesGET() {
			return []*Finding{buildHeaderFinding(cc, "Password submitted using GET method",
				"low", "certain",
				fmt.Sprintf("form action %q method %q", f.Action, f.Method),
				"a password field is submitted in the URL query string")}, nil
		}
	}
	return nil, nil
}

func checkPasswordAutocomplete(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	forms, _ := parsedForms(cc)
	for _, f := range forms {
		if f.PasswordAutocompleteEnabled() {
			return []*Finding{buildHeaderFinding(cc, "Password field with autocomplete enabled",
				"low", "certain",
				fmt.Sprintf("form action %q", f.Action),
				"a password field permits browser autocomplete")}, nil
		}
	}
	return nil, nil
}

func checkPasswordInURLQuery(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	hits := PasswordInURLQuery(exchangeURL(cc.Exchange))
	if len(hits) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Password returned in URL query string",
		"low", "certain",
		"query parameter "+strings.Join(hits, ", "),
		"a password-like parameter carries a value in the URL query string")}, nil
}

func checkPasswordInCookie(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	for _, sc := range headerValues(respRaw, headerSetCookie) {
		if PasswordInCookie(sc) {
			name, _, _ := strings.Cut(sc, "=")
			return []*Finding{buildHeaderFinding(cc, "Password value set in cookie",
				"medium", "certain",
				"Set-Cookie: "+strings.TrimSpace(name),
				"a cookie carries a password-like value")}, nil
		}
	}
	return nil, nil
}

func checkCrossDomainPOST(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	forms, pageURL := parsedForms(cc)
	page, err := url.Parse(pageURL)
	if err != nil {
		return nil, nil
	}
	for _, f := range forms {
		if !f.UsesGET() && f.PostsCrossDomain(page) {
			return []*Finding{buildHeaderFinding(cc, "Cross-domain POST",
				"info", "certain",
				fmt.Sprintf("form action %q", f.Action),
				"a POST form submits to a different domain")}, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// response shape (infra_response.go)
// ---------------------------------------------------------------------------

func checkRequestURLOverride(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	found := RequestURLOverrides(headerSet(requestRaw(cc.Scanner, cc.Exchange)))
	if len(found) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Request URL override",
		"info", "certain",
		strings.Join(found, ", "),
		"the request carries a URL-override header, which can bypass path-based access control")}, nil
}

func checkLongRedirectionResponse(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	status := responseStatus(respRaw)
	body := responseBody(respRaw)
	if !IsLongRedirectionResponse(status, len(body)) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Long redirection response",
		"info", "certain",
		fmt.Sprintf("status %d with a %d-byte body", status, len(body)),
		"a redirection response carries a body large enough to contain the content it redirects away from")}, nil
}

func checkMultipleContentTypes(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	h := headerSet(responseRaw(cc.Scanner, cc.Exchange))
	if DeclareContentType(h) != ContentTypeMultiple {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Multiple content types specified",
		"info", "certain",
		"Content-Type: "+strings.Join(h.Values("Content-Type"), " | "),
		"the response declares more than one content type")}, nil
}

func checkContentTypeNotSpecified(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	if !ContentTypeMissingOnBody(headerSet(respRaw), len(responseBody(respRaw))) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Content type is not specified",
		"info", "certain",
		"no Content-Type header",
		"a response body was returned with no declared content type, leaving the browser to sniff it")}, nil
}

func checkCrossDomainRefererLeakage(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	policy := headerValue(respRaw, "referrer-policy")
	leaks, err := CrossDomainRefererLeaks(exchangeURL(cc.Exchange), policy, []byte(responseBody(respRaw)))
	if err != nil || len(leaks) == 0 {
		return nil, nil
	}
	hosts := make([]string, 0, len(leaks))
	for _, l := range leaks {
		hosts = append(hosts, l.TargetHost)
	}
	return []*Finding{buildHeaderFinding(cc, "Cross-domain Referer leakage",
		"info", "certain",
		"off-site links to "+strings.Join(hosts, ", "),
		"the page URL carries a query string and links off-site, so the full URL reaches a third party in the Referer header")}, nil
}

// ---------------------------------------------------------------------------
// transport posture (infra_transport.go)
// ---------------------------------------------------------------------------

func checkUnencryptedCommunications(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	if !IsUnencryptedCommunication(exchangeURL(cc.Exchange)) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Unencrypted communications",
		"low", "certain",
		"http:// request",
		"the application is used over an unencrypted connection")}, nil
}

func checkStrictTransportSecurity(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	if !StrictTransportSecurityNotEnforced(cc.Exchange.TLS, headerSet(respRaw)) {
		return nil, nil
	}
	detail := "no Strict-Transport-Security header is present"
	if raw := headerValue(respRaw, "strict-transport-security"); raw != "" {
		detail = "Strict-Transport-Security does not commit the browser to HTTPS: " + raw
	}
	return []*Finding{buildHeaderFinding(cc, "Strict transport security not enforced",
		"low", "certain", headerValue(respRaw, "strict-transport-security"), detail)}, nil
}

func checkCacheableHTTPSResponse(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	if !CacheableHTTPSResponse(cc.Exchange.TLS, headerSet(respRaw)) {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Cacheable HTTPS response",
		"info", "certain",
		"Cache-Control: "+headerValue(respRaw, "cache-control"),
		"a TLS response carries no no-store directive, so the browser may write it to disk")}, nil
}

func checkMixedContent(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	refs, err := MixedContent(exchangeURL(cc.Exchange), cc.Exchange.TLS, []byte(responseBody(respRaw)))
	if err != nil || len(refs) == 0 {
		return nil, nil
	}
	kind := "passive"
	severity := "info"
	if HasActiveMixedContent(refs) {
		kind = "active"
		severity = "low"
	}
	urls := make([]string, 0, len(refs))
	for _, r := range refs {
		urls = append(urls, r.Tag+" "+r.URL)
	}
	return []*Finding{buildHeaderFinding(cc, "Mixed content",
		severity, "certain",
		strings.Join(urls, ", "),
		fmt.Sprintf("an HTTPS page loads %d cleartext subresource(s), including %s content", len(refs), kind))}, nil
}

// PassivePostureCheckDescriptors returns the fifteen network-free passive checks.
func PassivePostureCheckDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		passiveDescriptor("Cleartext submission of password", DispatchScopePerUrl, passivePostureEnabled, checkCleartextPasswordSubmission),
		passiveDescriptor("Password submitted using GET method", DispatchScopePerUrl, passivePostureEnabled, checkPasswordSubmittedUsingGET),
		passiveDescriptor("Password field with autocomplete enabled", DispatchScopePerUrl, passivePostureEnabled, checkPasswordAutocomplete),
		passiveDescriptor("Password returned in URL query string", DispatchScopePerUrl, passivePostureEnabled, checkPasswordInURLQuery),
		passiveDescriptor("Password value set in cookie", DispatchScopePerUrl, passivePostureEnabled, checkPasswordInCookie),
		passiveDescriptor("Cross-domain POST", DispatchScopePerUrl, passivePostureEnabled, checkCrossDomainPOST),
		passiveDescriptor("Request URL override", DispatchScopePerUrl, passivePostureEnabled, checkRequestURLOverride),
		passiveDescriptor("Long redirection response", DispatchScopePerUrl, passivePostureEnabled, checkLongRedirectionResponse),
		passiveDescriptor("Multiple content types specified", DispatchScopePerUrl, passivePostureEnabled, checkMultipleContentTypes),
		passiveDescriptor("Content type is not specified", DispatchScopePerUrl, passivePostureEnabled, checkContentTypeNotSpecified),
		passiveDescriptor("Cross-domain Referer leakage", DispatchScopePerUrl, passivePostureEnabled, checkCrossDomainRefererLeakage),
		passiveDescriptor("Unencrypted communications", DispatchScopePerHost, passivePostureEnabled, checkUnencryptedCommunications),
		passiveDescriptor("Strict transport security not enforced", DispatchScopePerHost, passivePostureEnabled, checkStrictTransportSecurity),
		passiveDescriptor("Cacheable HTTPS response", DispatchScopePerUrl, passivePostureEnabled, checkCacheableHTTPSResponse),
		passiveDescriptor("Mixed content", DispatchScopePerHost, passivePostureEnabled, checkMixedContent),
	}
}
