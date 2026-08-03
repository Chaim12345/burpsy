package scanner

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// ActiveScanner performs active security scanning.
type ActiveScanner struct {
	store      *core.TrafficStore
	logger     *zap.Logger
	config     *ScanConfig
	sender     *sender.Sender
	findings   []*Finding
	findingsMu sync.RWMutex
}

// ScanConfig holds scanner configuration.
type ScanConfig struct {
	MaxConcurrency     int
	Timeout            time.Duration
	CheckSqli          bool
	CheckXss           bool
	CheckPathTraversal bool
	CheckSSRF          bool
	CheckXXE           bool
	CheckJwtWeak       bool
	CheckJSVulns       bool
	CustomPayloads     []string
}

// Finding represents a security finding.
type Finding struct {
	ID          uint64
	Name        string
	Severity    string // "info", "low", "medium", "high", "critical"
	Confidence  string // "certain", "firm", "tentative"
	Description string
	URL         string
	Method      string
	Param       string
	Evidence    string
	Solution    string
	ExchangeID  uint64
	Timestamp   time.Time
}

// NewActiveScanner creates a new active scanner.
func NewActiveScanner(store *core.TrafficStore, logger *zap.Logger) *ActiveScanner {
	return &ActiveScanner{
		store:  store,
		logger: logger,
		config: &ScanConfig{
			MaxConcurrency:     10,
			Timeout:            30 * time.Second,
			CheckSqli:          true,
			CheckXss:           true,
			CheckPathTraversal: true,
			CheckSSRF:          true,
			CheckXXE:           false,
		},
		findings: make([]*Finding, 0),
	}
}

// WithConfig sets the scan configuration.
func (s *ActiveScanner) WithConfig(config *ScanConfig) *ActiveScanner {
	s.config = config
	return s
}

// WithSender sets the HTTP sender used to dispatch test requests.
// Without a sender, checks fall back to inspecting the stored exchange response.
func (s *ActiveScanner) WithSender(snd *sender.Sender) *ActiveScanner {
	s.sender = snd
	return s
}

// Audit runs an active audit on an exchange.
func (s *ActiveScanner) Audit(ctx context.Context, exchangeID uint64) ([]*Finding, error) {
	exchange, err := s.store.GetExchange(exchangeID)
	if err != nil {
		return nil, err
	}

	var findings []*Finding

	// Run SQL injection checks
	if s.config.CheckSqli {
		sqliFindings := s.checkSQLi(ctx, exchange)
		findings = append(findings, sqliFindings...)
	}

	// Run XSS checks
	if s.config.CheckXss {
		xssFindings := s.checkXSS(ctx, exchange)
		findings = append(findings, xssFindings...)
	}

	// Run path traversal checks
	if s.config.CheckPathTraversal {
		ptFindings := s.checkPathTraversal(ctx, exchange)
		findings = append(findings, ptFindings...)
	}

	// Run JWT weak secret checks
	if s.config.CheckJwtWeak {
		jwtFindings := s.checkJWTWeak(ctx, exchange)
		findings = append(findings, jwtFindings...)
	}

	// Run JS vulnerability checks
	if s.config.CheckJSVulns {
		jsFindings := s.checkJSVulns(ctx, exchange)
		findings = append(findings, jsFindings...)
	}

	// Store findings
	s.findingsMu.Lock()
	s.findings = append(s.findings, findings...)
	s.findingsMu.Unlock()

	return findings, nil
}

// AuditMultiple runs audits on multiple exchanges concurrently.
func (s *ActiveScanner) AuditMultiple(ctx context.Context, exchangeIDs []uint64) ([]*Finding, error) {
	sem := make(chan struct{}, s.config.MaxConcurrency)
	var wg sync.WaitGroup
	allFindings := make([]*Finding, 0)
	findingsMu := sync.Mutex{}

	for _, id := range exchangeIDs {
		wg.Add(1)
		go func(exchangeID uint64) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			findings, err := s.Audit(ctx, exchangeID)
			if err != nil {
				s.logger.Warn("audit failed", zap.Uint64("exchange_id", exchangeID), zap.Error(err))
				return
			}

			findingsMu.Lock()
			allFindings = append(allFindings, findings...)
			findingsMu.Unlock()
		}(id)
	}

	wg.Wait()
	return allFindings, nil
}

// checkSQLi performs SQL injection testing.
func (s *ActiveScanner) checkSQLi(ctx context.Context, exchange *core.Exchange) []*Finding {
	var findings []*Finding

	// SQL injection payloads
	payloads := []string{
		"' OR '1'='1",
		"1; DROP TABLE users--",
		"' UNION SELECT NULL--",
		"1' AND '1'='1",
		"' OR 1=1--",
		"admin'--",
		"1' OR '1'='1'/*",
	}

	// Error patterns that indicate SQL injection vulnerabilities
	errorPatterns := []string{
		"(?i)syntax.*error",
		"(?i)unclosed.*quote",
		"(?i)SQL.*warning",
		"(?i)mysql.*fetch",
		"(?i)ORA-[0-9]+",
		"(?i)Microsoft.*ODBC",
		"(?i)PostgreSQL.*ERROR",
		"(?i)SQLite.*error",
	}

	for _, payload := range payloads {
		// Test in URL parameters
		testURL := appendQueryParam(exchange.Path, "test", payload)
		if s.testPayload(ctx, exchange, testURL, payload, errorPatterns, "SQL Injection", &findings) {
			break // Found vulnerability, stop testing
		}
	}

	return findings
}

// checkXSS performs XSS testing.
func (s *ActiveScanner) checkXSS(ctx context.Context, exchange *core.Exchange) []*Finding {
	var findings []*Finding

	// XSS payloads
	payloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"'><script>alert(document.cookie)</script>",
		"<svg onload=alert(1)>",
	}

	for _, payload := range payloads {
		// Test in URL parameters
		testURL := appendQueryParam(exchange.Path, "xss", payload)
		if s.testXSSPayload(ctx, exchange, testURL, payload, &findings) {
			break // Found vulnerability, stop testing
		}
	}

	return findings
}

// checkPathTraversal performs path traversal testing.
func (s *ActiveScanner) checkPathTraversal(ctx context.Context, exchange *core.Exchange) []*Finding {
	var findings []*Finding

	// Path traversal payloads
	payloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}

	// Sensitive file contents to look for
	sensitivePatterns := []string{
		"root:x:0:0:",
		"[boot loader]",
		"Windows PE",
	}

	for _, payload := range payloads {
		testURL := appendQueryParam(exchange.Path, "file", payload)
		if s.testPathTraversal(ctx, exchange, testURL, payload, sensitivePatterns, &findings) {
			break
		}
	}

	return findings
}

// testPayload tests a payload and checks for error patterns.
func (s *ActiveScanner) testPayload(ctx context.Context, exchange *core.Exchange, testURL, payload string, errorPatterns []string, vulnType string, findings *[]*Finding) bool {
	respBody := s.sendTestRequest(ctx, exchange, testURL)

	for _, pattern := range errorPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(respBody) {
			*findings = append(*findings, &Finding{
				Name:        vulnType,
				Severity:    "high",
				Confidence:  "tentative",
				Description: fmt.Sprintf("Potential %s detected with payload: %s", vulnType, payload),
				URL:         testURL,
				Method:      exchange.Method,
				Evidence:    payload,
				Solution:    "Use parameterized queries and input validation",
				Timestamp:   time.Now(),
			})
			return true
		}
	}
	return false
}

// testXSSPayload tests XSS payloads.
func (s *ActiveScanner) testXSSPayload(ctx context.Context, exchange *core.Exchange, testURL, payload string, findings *[]*Finding) bool {
	respBody := s.sendTestRequest(ctx, exchange, testURL)

	// Check if payload is reflected
	if strings.Contains(respBody, payload) || strings.Contains(respBody, html.EscapeString(payload)) {
		*findings = append(*findings, &Finding{
			Name:        "Cross-Site Scripting (XSS)",
			Severity:    "high",
			Confidence:  "firm",
			Description: fmt.Sprintf("Reflected XSS detected with payload: %s", payload),
			URL:         testURL,
			Method:      exchange.Method,
			Evidence:    payload,
			Solution:    "Encode output and validate input",
			Timestamp:   time.Now(),
		})
		return true
	}
	return false
}

// testPathTraversal tests path traversal payloads.
func (s *ActiveScanner) testPathTraversal(ctx context.Context, exchange *core.Exchange, testURL, payload string, sensitivePatterns []string, findings *[]*Finding) bool {
	respBody := s.sendTestRequest(ctx, exchange, testURL)

	for _, pattern := range sensitivePatterns {
		if strings.Contains(respBody, pattern) {
			*findings = append(*findings, &Finding{
				Name:        "Path Traversal",
				Severity:    "high",
				Confidence:  "firm",
				Description: fmt.Sprintf("Path traversal detected, sensitive file content exposed"),
				URL:         testURL,
				Method:      exchange.Method,
				Evidence:    pattern,
				Solution:    "Validate and sanitize file paths, use chroot or containers",
				Timestamp:   time.Now(),
			})
			return true
		}
	}
	return false
}

// sendTestRequest dispatches a crafted test request through the sender when
// available, otherwise falls back to the stored response body of the original
// exchange (offline audit).
func (s *ActiveScanner) sendTestRequest(ctx context.Context, exchange *core.Exchange, testURL string) string {
	if s.sender != nil {
		resp, err := s.sender.Send(ctx, &sender.Request{
			Method: exchange.Method,
			Host:   exchange.Host,
			Path:   testURL,
			TLS:    exchange.TLS,
			Port:   exchange.Port,
		})
		if err == nil && resp != nil {
			return string(resp.Body)
		}
		s.logger.Warn("test request failed, falling back to stored response",
			zap.String("host", exchange.Host), zap.String("url", testURL), zap.Error(err))
	}
	return s.getResponseBody(exchange)
}

// appendQueryParam adds a query parameter to a path, preserving any existing
// query string: /a?b=c -> /a?b=c&x=v.
func appendQueryParam(path, key, value string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + key + "=" + url.QueryEscape(value)
}

// getResponseBody retrieves the response body from the store.
func (s *ActiveScanner) getResponseBody(exchange *core.Exchange) string {
	if exchange.Response == nil {
		return ""
	}
	msg, err := s.store.Get(*exchange.Response)
	if err != nil {
		return ""
	}
	// Get body span
	bodySpan := msg.Shape.Body
	if bodySpan.IsEmpty() {
		return ""
	}
	return string(msg.Slice(bodySpan))
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetFindings returns all findings.
func (s *ActiveScanner) GetFindings() []*Finding {
	s.findingsMu.RLock()
	defer s.findingsMu.RUnlock()

	result := make([]*Finding, len(s.findings))
	copy(result, s.findings)
	return result
}

// ClearFindings clears all findings.
func (s *ActiveScanner) ClearFindings() {
	s.findingsMu.Lock()
	defer s.findingsMu.Unlock()
	s.findings = make([]*Finding, 0)
}

// PassiveScanner performs passive security scanning.
type PassiveScanner struct {
	store      *core.TrafficStore
	logger     *zap.Logger
	findings   []*Finding
	findingsMu sync.RWMutex
}

// NewPassiveScanner creates a new passive scanner.
func NewPassiveScanner(store *core.TrafficStore, logger *zap.Logger) *PassiveScanner {
	return &PassiveScanner{
		store:    store,
		logger:   logger,
		findings: make([]*Finding, 0),
	}
}

// Scan performs passive scanning on an exchange.
func (s *PassiveScanner) Scan(exchange *core.Exchange) []*Finding {
	var findings []*Finding

	// Check for missing security headers
	s.checkSecurityHeaders(exchange, &findings)

	// Check for information disclosure
	s.checkInfoDisclosure(exchange, &findings)

	// Check for cookie security issues
	s.checkCookieSecurity(exchange, &findings)

	// Store findings
	s.findingsMu.Lock()
	s.findings = append(s.findings, findings...)
	s.findingsMu.Unlock()

	return findings
}

func (s *PassiveScanner) checkSecurityHeaders(exchange *core.Exchange, findings *[]*Finding) {
	// Parse response headers from stored message
	respHeaders := s.getResponseHeaders(exchange)
	lines := strings.Split(respHeaders, "\r\n")

	hasXFrameOptions := false
	hasXContentTypeOptions := false
	hasCSP := false

	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "x-frame-options:") {
			hasXFrameOptions = true
		}
		if strings.HasPrefix(lower, "x-content-type-options:") {
			hasXContentTypeOptions = true
		}
		if strings.HasPrefix(lower, "content-security-policy:") {
			hasCSP = true
		}
	}

	if !hasXFrameOptions {
		*findings = append(*findings, &Finding{
			Name:        "Missing X-Frame-Options Header",
			Severity:    "low",
			Confidence:  "certain",
			Description: "The X-Frame-Options header is missing, making the site vulnerable to clickjacking",
			URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
			Method:      exchange.Method,
			Solution:    "Add X-Frame-Options: DENY or SAMEORIGIN header",
			Timestamp:   time.Now(),
		})
	}

	if !hasXContentTypeOptions {
		*findings = append(*findings, &Finding{
			Name:        "Missing X-Content-Type-Options Header",
			Severity:    "low",
			Confidence:  "certain",
			Description: "The X-Content-Type-Options header is missing, allowing MIME type sniffing",
			URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
			Method:      exchange.Method,
			Solution:    "Add X-Content-Type-Options: nosniff header",
			Timestamp:   time.Now(),
		})
	}

	if !hasCSP {
		*findings = append(*findings, &Finding{
			Name:        "Missing Content-Security-Policy Header",
			Severity:    "info",
			Confidence:  "certain",
			Description: "The Content-Security-Policy header is missing",
			URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
			Method:      exchange.Method,
			Solution:    "Implement a strict Content-Security-Policy",
			Timestamp:   time.Now(),
		})
	}
}

func (s *PassiveScanner) checkInfoDisclosure(exchange *core.Exchange, findings *[]*Finding) {
	respBody := s.getResponseBody(exchange)

	// Patterns for sensitive information
	patterns := map[string]string{
		`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`:               "Email Address",
		`(?i)\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`:    "Credit Card Number",
		`(?i)(?:api[_-]?key|apikey|api_secret)["\s:=]+["']?[A-Za-z0-9_-]+["']?`: "API Key",
		`(?i)(?:password|passwd|pwd)["\s:=]+["']?[^\s"']+"'?`:                   "Password in Response",
		`(?i)\b[A-Fa-f0-9]{32}\b`:                                               "Potential Hash (MD5)",
	}

	for pattern, infoType := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		matches := re.FindAllString(respBody, -1)
		if len(matches) > 0 {
			*findings = append(*findings, &Finding{
				Name:        fmt.Sprintf("Information Disclosure: %s", infoType),
				Severity:    "medium",
				Confidence:  "tentative",
				Description: fmt.Sprintf("Potential %s found in response", infoType),
				URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
				Method:      exchange.Method,
				Evidence:    matches[0],
				Solution:    "Review and sanitize sensitive data from responses",
				Timestamp:   time.Now(),
			})
		}
	}
}

func (s *PassiveScanner) checkCookieSecurity(exchange *core.Exchange, findings *[]*Finding) {
	respHeaders := s.getResponseHeaders(exchange)

	// Find Set-Cookie headers
	lines := strings.Split(respHeaders, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "set-cookie:") {
			cookie := strings.TrimSpace(line[11:])

			// Check for Secure flag
			if !strings.Contains(strings.ToLower(cookie), "; secure") && exchange.TLS {
				*findings = append(*findings, &Finding{
					Name:        "Cookie Missing Secure Flag",
					Severity:    "medium",
					Confidence:  "certain",
					Description: "Cookie is set without Secure flag over HTTPS",
					URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
					Method:      exchange.Method,
					Evidence:    cookie[:min(len(cookie), 50)],
					Solution:    "Add Secure flag to all cookies",
					Timestamp:   time.Now(),
				})
			}

			// Check for HttpOnly flag
			if !strings.Contains(strings.ToLower(cookie), "; httponly") {
				*findings = append(*findings, &Finding{
					Name:        "Cookie Missing HttpOnly Flag",
					Severity:    "low",
					Confidence:  "certain",
					Description: "Cookie is set without HttpOnly flag",
					URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
					Method:      exchange.Method,
					Evidence:    cookie[:min(len(cookie), 50)],
					Solution:    "Add HttpOnly flag to session cookies",
					Timestamp:   time.Now(),
				})
			}

			// Check for SameSite flag
			if !strings.Contains(strings.ToLower(cookie), "; samesite") {
				*findings = append(*findings, &Finding{
					Name:        "Cookie Missing SameSite Flag",
					Severity:    "low",
					Confidence:  "certain",
					Description: "Cookie is set without SameSite flag",
					URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
					Method:      exchange.Method,
					Evidence:    cookie[:min(len(cookie), 50)],
					Solution:    "Add SameSite=Strict or SameSite=Lax flag",
					Timestamp:   time.Now(),
				})
			}
		}
	}
}

// getResponseBody retrieves the response body from the store.
func (s *PassiveScanner) getResponseBody(exchange *core.Exchange) string {
	if exchange.Response == nil {
		return ""
	}
	msg, err := s.store.Get(*exchange.Response)
	if err != nil {
		return ""
	}
	bodySpan := msg.Shape.Body
	if bodySpan.IsEmpty() {
		return ""
	}
	return string(msg.Slice(bodySpan))
}

// getResponseHeaders retrieves the response headers from the store.
func (s *PassiveScanner) getResponseHeaders(exchange *core.Exchange) string {
	if exchange.Response == nil {
		return ""
	}
	msg, err := s.store.Get(*exchange.Response)
	if err != nil {
		return ""
	}
	// Return full raw message for header parsing
	return string(msg.Raw())
}

// GetFindings returns all passive findings.
func (s *PassiveScanner) GetFindings() []*Finding {
	s.findingsMu.RLock()
	defer s.findingsMu.RUnlock()

	result := make([]*Finding, len(s.findings))
	copy(result, s.findings)
	return result
}
