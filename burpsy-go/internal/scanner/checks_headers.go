package scanner

// Header checks ported from Burp's passive/active header auditors.
//
// The decision logic in each family is split into a pure, network-free
// classifier (analyze*Evidence) and a thin CheckRunner that reads the relevant
// headers off the captured exchange and calls it — mirroring the sqli.go shape.
// Keeping the classifier pure means the observable evidence classes are unit
// testable without a live sender or a stored traffic fixture.

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// header names (canonical-ish; matched case-insensitively by the readers below)
const (
	headerAccessControlAllowOrigin      = "access-control-allow-origin"
	headerAccessControlAllowCredentials = "access-control-allow-credentials"
	headerContentSecurityPolicy         = "content-security-policy"
	headerContentSecurityPolicyReport   = "content-security-policy-report-only"
	headerXFrameOptions                 = "x-frame-options"
	headerSetCookie                     = "set-cookie"
	headerOrigin                        = "origin"
)

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

// CORSEvidence is the bitmask of CORS misconfigurations detected from a response.
type CORSEvidence uint8

const (
	// CORSEvidenceArbitraryOrigin means the policy reflects an arbitrary,
	// attacker-controlled Origin, or sends `*` together with credentials — either
	// effectively disables the same-origin policy.
	CORSEvidenceArbitraryOrigin CORSEvidence = 1 << iota
	// CORSEvidenceUnencryptedOrigin means the policy allows an http:// origin to
	// be used from an https:// context.
	CORSEvidenceUnencryptedOrigin
	// CORSEvidenceAllSubdomains means the policy reflects a wildcard-subdomain
	// pattern (e.g. https://*.example.com) or otherwise trusts any subdomain of
	// the host, widening the attack surface to every subdomain.
	CORSEvidenceAllSubdomains
)

// corsProbe holds the inputs to the CORS classifier: the request Origin (as sent),
// the response ACAO and ACAC values, and the scheme/probe Origin used to test the
// all-subdomains behaviour. All values are taken from captured traffic or a probe
// response; none are parsed from raw sockets here.
type corsProbe struct {
	requestOrigin    string // the Origin header of the audited request, if any
	allowOrigin      string // response Access-Control-Allow-Origin value
	allowCredentials bool   // response Access-Control-Allow-Credentials: true
	// probeOrigin and probeAllowOrigin come from a crafted subdomain probe: the
	// Origin we sent (https://<sub>.<host>) and the ACAO the server echoed back.
	probeOrigin      string
	probeAllowOrigin string
}

// analyzeCORSEvidence classifies CORS configuration from observed headers, with no
// network or storage access, so the decision table is independently testable.
func analyzeCORSEvidence(p corsProbe) CORSEvidence {
	var evidence CORSEvidence

	allowOrigin := strings.TrimSpace(p.allowOrigin)

	// Arbitrary origin trusted:
	//  - ACAO reflects the request's Origin verbatim (a non-null, non-wildcard
	//    value identical to an attacker-supplied Origin).
	//  - ACAO is the literal "*" while credentials are allowed.
	if p.requestOrigin != "" && allowOrigin != "" && !strings.Contains(allowOrigin, "*") {
		if strings.EqualFold(allowOrigin, p.requestOrigin) {
			evidence |= CORSEvidenceArbitraryOrigin
		}
	}
	if allowOrigin == "*" && p.allowCredentials {
		evidence |= CORSEvidenceArbitraryOrigin
	}

	// Unencrypted origin trusted: an http:// origin is allowed from an https
	// context. We detect this when ACAO reflects an http:// request origin, or
	// when the probe ACAO echoes an http:// probe origin.
	if p.requestOrigin != "" && allowOrigin != "" && !strings.Contains(allowOrigin, "*") {
		if strings.EqualFold(allowOrigin, p.requestOrigin) && strings.HasPrefix(strings.ToLower(p.requestOrigin), "http://") {
			evidence |= CORSEvidenceUnencryptedOrigin
		}
	}
	if p.probeOrigin != "" && strings.HasPrefix(strings.ToLower(p.probeOrigin), "http://") &&
		strings.EqualFold(strings.TrimSpace(p.probeAllowOrigin), p.probeOrigin) {
		evidence |= CORSEvidenceUnencryptedOrigin
	}

	// All subdomains trusted: a wildcard-subdomain pattern is echoed back, or the
	// probe ACAO mirrors a crafted subdomain Origin (https://<sub>.<host>).
	if isWildcardSubdomain(allowOrigin) {
		evidence |= CORSEvidenceAllSubdomains
	}
	if p.probeOrigin != "" && isSubdomainOf(p.probeOrigin, hostOf(p.requestOrigin)) &&
		strings.EqualFold(strings.TrimSpace(p.probeAllowOrigin), p.probeOrigin) {
		evidence |= CORSEvidenceAllSubdomains
	}

	return evidence
}

// isWildcardSubdomain reports whether an ACAO value is a wildcard-subdomain
// pattern, e.g. https://*.example.com. A bare "*" is handled by the caller's
// arbitrary-origin logic and is not a subdomain pattern here.
func isWildcardSubdomain(acao string) bool {
	acao = strings.TrimSpace(acao)
	if !strings.Contains(acao, "*") {
		return false
	}
	if acao == "*" {
		return false
	}
	u, err := url.Parse(acao)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	// Only treat https/http origins whose host begins with "*." as subdomain
	// patterns. ACAO never carries a path, so Host must start with "*.".
	return strings.HasPrefix(u.Host, "*.")
}

// hostOf returns the host portion of an origin URL, or "" if it is not a parseable
// origin. Used to frame a subdomain probe against the real host.
func hostOf(origin string) string {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return ""
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// isSubdomainOf reports whether child is a subdomain of parent (e.g.
// evil.example.com is a subdomain of example.com). Exact matches are not
// subdomains.
func isSubdomainOf(child, parent string) bool {
	child = strings.ToLower(strings.TrimSpace(child))
	parent = strings.ToLower(strings.TrimSpace(parent))
	if parent == "" || child == parent {
		return false
	}
	return strings.HasSuffix(child, "."+parent)
}

func corsEvidenceText(evidence CORSEvidence) string {
	parts := make([]string, 0, 3)
	if evidence&CORSEvidenceArbitraryOrigin != 0 {
		parts = append(parts, "Access-Control-Allow-Origin reflects an arbitrary attacker-controlled origin, or is '*' with credentials allowed")
	}
	if evidence&CORSEvidenceUnencryptedOrigin != 0 {
		parts = append(parts, "Access-Control-Allow-Origin allows an unencrypted http:// origin from an https context")
	}
	if evidence&CORSEvidenceAllSubdomains != 0 {
		parts = append(parts, "Access-Control-Allow-Origin trusts all subdomains of the host")
	}
	return strings.Join(parts, "; ")
}

// cspEvidenceText renders the detected CSP evidence classes as prose.
func cspEvidenceText(evidence CSPEvidence) string {
	parts := make([]string, 0, 2)
	if evidence&CSPEvidenceNotEnforced != 0 {
		parts = append(parts, "no enforcing Content-Security-Policy header is present")
	}
	if evidence&CSPEvidenceAllowsClickjacking != 0 {
		parts = append(parts, "no frame-ancestors directive and no X-Frame-Options header")
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// CSP
// ---------------------------------------------------------------------------

// CSPEvidence is the bitmask of CSP problems detected from a response.
type CSPEvidence uint8

const (
	// CSPEvidenceNotEnforced means no enforcing Content-Security-Policy header is
	// present (only a Report-Only header, or none at all).
	CSPEvidenceNotEnforced CSPEvidence = 1 << iota
	// CSPEvidenceAllowsClickjacking means there is no frame-ancestors directive and
	// no X-Frame-Options header, so the page can be framed.
	CSPEvidenceAllowsClickjacking
)

// cspProbe holds the inputs to the CSP classifier: which headers were observed.
type cspProbe struct {
	hasEnforcingCSP   bool // Content-Security-Policy present
	hasReportOnlyCSP  bool // Content-Security-Policy-Report-Only present
	hasFrameAncestors bool // a CSP carries frame-ancestors
	hasXFrameOptions  bool // X-Frame-Options present
}

// analyzeCSPEvidence classifies CSP posture from observed headers, with no network
// or storage access.
func analyzeCSPEvidence(p cspProbe) CSPEvidence {
	var evidence CSPEvidence
	if !p.hasEnforcingCSP {
		evidence |= CSPEvidenceNotEnforced
	}
	if !p.hasFrameAncestors && !p.hasXFrameOptions {
		evidence |= CSPEvidenceAllowsClickjacking
	}
	return evidence
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Duplicate cookies
// ---------------------------------------------------------------------------

// DuplicateCookieEvidence is the bitmask for the duplicate-cookie family. A single
// bit: two or more Set-Cookie entries set the same name to different values.
type DuplicateCookieEvidence uint8

const (
	// DuplicateCookieEvidenceConflicting means the same cookie name is set to two
	// or more distinct values across the response's Set-Cookie headers.
	DuplicateCookieEvidenceConflicting DuplicateCookieEvidence = 1 << iota
)

// analyzeDuplicateCookieEvidence classifies a response's ordered Set-Cookie values
// without network or storage access.
func analyzeDuplicateCookieEvidence(setCookies []string) DuplicateCookieEvidence {
	seen := make(map[string]string, len(setCookies))
	for _, raw := range setCookies {
		name, value := splitCookie(raw)
		if name == "" {
			continue
		}
		if prev, ok := seen[name]; ok {
			if prev != value {
				return DuplicateCookieEvidenceConflicting
			}
			continue
		}
		seen[name] = value
	}
	return 0
}

// splitCookie returns the cookie name and value from a single Set-Cookie header
// value (the part before the first ';'). It mirrors how browsers identify the
// cookie a header sets.
func splitCookie(raw string) (name, value string) {
	semi := strings.Index(raw, ";")
	pair := raw
	if semi >= 0 {
		pair = raw[:semi]
	}
	pair = strings.TrimSpace(pair)
	if pair == "" {
		return "", ""
	}
	eq := strings.Index(pair, "=")
	if eq < 0 {
		// A valueless cookie (e.g. "flag") — name with empty value.
		return pair, ""
	}
	return pair[:eq], pair[eq+1:]
}

func duplicateCookieEvidenceText() string {
	return "two or more Set-Cookie headers set the same cookie name to different values"
}

// ---------------------------------------------------------------------------
// Exchange header readers (reuse the core message API; no new parsing layer)
// ---------------------------------------------------------------------------

// responseRaw returns the raw bytes of the exchange's response message, or "".
func responseRaw(s *ActiveScanner, exchange *core.Exchange) string {
	if s == nil || exchange == nil || exchange.Response == nil {
		return ""
	}
	msg, err := s.store.Get(*exchange.Response)
	if err != nil {
		return ""
	}
	return string(msg.Raw())
}

// requestRaw returns the raw bytes of the exchange's request message, or "".
func requestRaw(s *ActiveScanner, exchange *core.Exchange) string {
	if s == nil || exchange == nil {
		return ""
	}
	msg, err := s.store.Get(exchange.Request)
	if err != nil {
		return ""
	}
	return string(msg.Raw())
}

// headerValue returns the (first) value of a header from a raw HTTP message,
// matching case-insensitively. Folding is not handled; the corpus we audit does
// not fold these security headers. Returns "" when absent.
func headerValue(raw, name string) string {
	lower := strings.ToLower(name)
	for _, line := range strings.Split(raw, "\r\n") {
		if !strings.HasPrefix(strings.ToLower(line), lower+":") {
			continue
		}
		v := strings.TrimSpace(line[len(lower)+1:])
		if v != "" {
			return v
		}
	}
	return ""
}

// headerValues returns every value of a header from a raw HTTP message, in order.
func headerValues(raw, name string) []string {
	lower := strings.ToLower(name)
	var out []string
	for _, line := range strings.Split(raw, "\r\n") {
		if !strings.HasPrefix(strings.ToLower(line), lower+":") {
			continue
		}
		out = append(out, strings.TrimSpace(line[len(lower)+1:]))
	}
	return out
}

// exchangeURL rebuilds a display URL for a finding from the exchange fields.
func exchangeURL(exchange *core.Exchange) string {
	scheme := "http"
	if exchange.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, exchange.Host, exchange.Port, exchange.Path)
}

// ---------------------------------------------------------------------------
// Check runners
// ---------------------------------------------------------------------------

// checkCORSArbitraryOrigin audits for a CORS policy that trusts an arbitrary
// origin. With a sender it sends a probe with an attacker-controlled Origin and
// reads the reflected ACAO; without one it falls back to the captured request's
// Origin header. In both cases the pure classifier decides.
func checkCORSArbitraryOrigin(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	s, exchange := cc.Scanner, cc.Exchange
	if s == nil || exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(s, exchange)
	reqRaw := requestRaw(s, exchange)

	probe := corsProbe{
		requestOrigin:    headerValue(reqRaw, headerOrigin),
		allowOrigin:      headerValue(respRaw, headerAccessControlAllowOrigin),
		allowCredentials: strings.EqualFold(headerValue(respRaw, headerAccessControlAllowCredentials), "true"),
	}
	if s.sender != nil {
		// Probe with an attacker-controlled origin to see if it is reflected.
		if got := strings.TrimSpace(probeCORSOrigin(ctx, s, exchange, "https://evil.example.com")); got != "" {
			probe.requestOrigin = "https://evil.example.com"
			probe.allowOrigin = got
		}
	}
	evidence := analyzeCORSEvidence(probe) & CORSEvidenceArbitraryOrigin
	if evidence == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Cross-origin resource sharing: arbitrary origin trusted",
		"high", "certain", corsEvidenceText(evidence),
		fmt.Sprintf("Access-Control-Allow-Origin: %s", probe.allowOrigin))}, nil
}

// checkCORSUnencryptedOrigin audits for a CORS policy that allows an unencrypted
// http:// origin from an https context.
func checkCORSUnencryptedOrigin(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	s, exchange := cc.Scanner, cc.Exchange
	if s == nil || exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(s, exchange)
	reqRaw := requestRaw(s, exchange)

	probe := corsProbe{
		requestOrigin: headerValue(reqRaw, headerOrigin),
		allowOrigin:   headerValue(respRaw, headerAccessControlAllowOrigin),
	}
	if s.sender != nil {
		// Probe with an unencrypted origin to see if it is reflected.
		if got := strings.TrimSpace(probeCORSOrigin(ctx, s, exchange, "http://evil.example.com")); got != "" {
			probe.requestOrigin = "http://evil.example.com"
			probe.allowOrigin = got
		}
	}

	evidence := analyzeCORSEvidence(probe) & CORSEvidenceUnencryptedOrigin
	if evidence == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Cross-origin resource sharing: unencrypted origin trusted",
		"low", "certain", corsEvidenceText(evidence),
		fmt.Sprintf("Access-Control-Allow-Origin: %s", probe.allowOrigin))}, nil
}

// checkCORSAllSubdomains audits for a CORS policy that trusts all subdomains of
// the host. It sends a crafted subdomain Origin probe when a sender is available;
// otherwise it only detects a literal wildcard-subdomain ACAO in the captured
// response.
func checkCORSAllSubdomains(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	s, exchange := cc.Scanner, cc.Exchange
	if s == nil || exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(s, exchange)
	reqRaw := requestRaw(s, exchange)

	probe := corsProbe{
		requestOrigin: headerValue(reqRaw, headerOrigin),
		allowOrigin:   headerValue(respRaw, headerAccessControlAllowOrigin),
	}
	if s.sender != nil && exchange.Host != "" {
		subOrigin := fmt.Sprintf("https://evil.%s", exchange.Host)
		probe.probeOrigin = subOrigin
		probe.probeAllowOrigin = probeCORSOrigin(ctx, s, exchange, subOrigin)
	}

	evidence := analyzeCORSEvidence(probe) & CORSEvidenceAllSubdomains
	if evidence == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Cross-origin resource sharing: all subdomains trusted",
		"low", "certain", corsEvidenceText(evidence),
		fmt.Sprintf("Access-Control-Allow-Origin: %s", probe.allowOrigin))}, nil
}

// probeCORSOrigin sends a GET to the exchange's URL with the given Origin header
// and returns the reflected Access-Control-Allow-Origin value (or ""). It reuses
// the scanner's engagement-scoped gate so the probe is authorised like every
// other egress. A refused or failed probe yields "" and the caller falls back to
// the captured response.
func probeCORSOrigin(ctx context.Context, s *ActiveScanner, exchange *core.Exchange, origin string) string {
	if s == nil || s.sender == nil || exchange == nil {
		return ""
	}
	meter := meterFrom(ctx)
	if meter != nil {
		meter.attempt()
	}
	gate := s.probeGate(exchange)
	resp, err := gate.SendRequest(ctx, &sender.Request{
		Method:  "GET",
		Host:    exchange.Host,
		Path:    exchange.Path,
		TLS:     exchange.TLS,
		Port:    exchange.Port,
		Headers: map[string]string{headerOrigin: origin},
	})
	if gate.Refused() > 0 {
		if meter != nil {
			meter.refusal()
		}
		return ""
	}
	if err != nil || resp == nil {
		if meter != nil {
			meter.failure()
		}
		return ""
	}
	if meter != nil {
		meter.succeeded()
	}
	// Case-insensitively. The constants in this file are lowercase because the passive path reads
	// raw response bytes, but resp.Headers comes from net/http, which canonicalises keys - so a
	// direct lookup for "access-control-allow-origin" never matched "Access-Control-Allow-Origin"
	// and this probe silently returned empty for every target. The row it feeds could not fire.
	return headerLookupFold(resp.Headers, headerAccessControlAllowOrigin)
}

// headerLookupFold finds a header value regardless of key casing.
//
// Two sources of headers meet in this file: raw response bytes, parsed lowercase, and
// sender.Response.Headers, which net/http canonicalises. Any code path that mixes them needs this,
// and the one that did not had a check that could never fire.
func headerLookupFold(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// checkCSPNotEnforced audits for a missing enforcing Content-Security-Policy
// header on an HTML response.
func checkCSPNotEnforced(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	s, exchange := cc.Scanner, cc.Exchange
	if s == nil || exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(s, exchange)
	probe := cspProbe{
		hasEnforcingCSP:   headerValue(respRaw, headerContentSecurityPolicy) != "",
		hasReportOnlyCSP:  headerValue(respRaw, headerContentSecurityPolicyReport) != "",
		hasFrameAncestors: strings.Contains(strings.ToLower(headerValue(respRaw, headerContentSecurityPolicy)), "frame-ancestors"),
		hasXFrameOptions:  headerValue(respRaw, headerXFrameOptions) != "",
	}
	evidence := analyzeCSPEvidence(probe) & CSPEvidenceNotEnforced
	if evidence == 0 {
		return nil, nil
	}
	detail := "no Content-Security-Policy header is present"
	if probe.hasReportOnlyCSP {
		detail = "only Content-Security-Policy-Report-Only is present; no enforcing policy"
	}
	return []*Finding{buildHeaderFinding(cc, "Content security policy: not enforced",
		"info", "certain", cspEvidenceText(evidence), detail)}, nil
}

// checkCSPAllowsClickjacking audits for a CSP/page that can be framed: no
// frame-ancestors directive and no X-Frame-Options header.
func checkCSPAllowsClickjacking(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	s, exchange := cc.Scanner, cc.Exchange
	if s == nil || exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(s, exchange)
	probe := cspProbe{
		hasEnforcingCSP:   headerValue(respRaw, headerContentSecurityPolicy) != "",
		hasReportOnlyCSP:  headerValue(respRaw, headerContentSecurityPolicyReport) != "",
		hasFrameAncestors: strings.Contains(strings.ToLower(headerValue(respRaw, headerContentSecurityPolicy)), "frame-ancestors"),
		hasXFrameOptions:  headerValue(respRaw, headerXFrameOptions) != "",
	}
	evidence := analyzeCSPEvidence(probe) & CSPEvidenceAllowsClickjacking
	if evidence == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Content security policy: allows clickjacking",
		"info", "certain", cspEvidenceText(evidence),
		"no frame-ancestors directive and no X-Frame-Options header")}, nil
}

// checkDuplicateCookies audits for two or more Set-Cookie headers setting the same
// cookie name to different values.
func checkDuplicateCookies(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	s, exchange := cc.Scanner, cc.Exchange
	if s == nil || exchange == nil {
		return nil, nil
	}
	respRaw := responseRaw(s, exchange)
	setCookies := headerValues(respRaw, headerSetCookie)
	if analyzeDuplicateCookieEvidence(setCookies) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Duplicate cookies set",
		"info", "certain", duplicateCookieEvidenceText(),
		fmt.Sprintf("%d Set-Cookie headers observed", len(setCookies)))}, nil
}

// buildHeaderFinding assembles a Finding for a header issue, pulling severity and
// remediation from the catalog entry resolved by name.
func buildHeaderFinding(cc *CheckContext, name, severity, confidence, evidenceText, detail string) *Finding {
	exchange := cc.Exchange
	solution := ""
	if def, ok := ByName(name); ok {
		solution = def.Remediation
	}
	return &Finding{
		Name:        name,
		Severity:    severity,
		Confidence:  confidence,
		Description: detail,
		URL:         exchangeURL(exchange),
		Method:      exchange.Method,
		Evidence:    evidenceText,
		Solution:    solution,
		ExchangeID:  exchange.ID,
		Timestamp:   time.Now(),
	}
}

// headerChecksEnabled gates the CORS/CSP/duplicate-cookie checks behind
// ScanConfig.CheckHeaders, off by default like every other per-family switch.
func headerChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckHeaders }

// HeaderCheckDescriptors returns the native header checks registered by this file.
// The coordinating session aggregates this with the other per-family descriptor
// functions into NativeCheckRegistry.
func HeaderCheckDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		nativeDescriptor("Cross-origin resource sharing: arbitrary origin trusted", DispatchScopePerRequest, headerChecksEnabled, checkCORSArbitraryOrigin),
		nativeDescriptor("Cross-origin resource sharing: unencrypted origin trusted", DispatchScopePerRequest, headerChecksEnabled, checkCORSUnencryptedOrigin),
		nativeDescriptor("Cross-origin resource sharing: all subdomains trusted", DispatchScopePerRequest, headerChecksEnabled, checkCORSAllSubdomains),
		nativeDescriptor("Content security policy: not enforced", DispatchScopePerUrl, headerChecksEnabled, checkCSPNotEnforced),
		nativeDescriptor("Content security policy: allows clickjacking", DispatchScopePerUrl, headerChecksEnabled, checkCSPAllowsClickjacking),
		nativeDescriptor("Duplicate cookies set", DispatchScopePerRequest, headerChecksEnabled, checkDuplicateCookies),
	}
}
