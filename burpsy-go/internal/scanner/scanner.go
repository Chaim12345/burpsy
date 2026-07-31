package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// ActiveScanner performs active security scanning.
type ActiveScanner struct {
	store      *core.TrafficStore
	logger     *zap.Logger
	config     *ScanConfig
	findings   []*Finding
	findingsMu sync.RWMutex
}

// ScanConfig holds scanner configuration.
type ScanConfig struct {
	MaxConcurrency  int
	Timeout         time.Duration
	CheckSqli       bool
	CheckXss        bool
	CheckPathTraversal bool
	CheckSSRF       bool
	CheckXXE        bool
	CustomPayloads  []string
}

// Finding represents a security finding.
type Finding struct {
	ID           uint64
	Name         string
	Severity     string // "info", "low", "medium", "high", "critical"
	Confidence   string // "certain", "firm", "tentative"
	Description  string
	URL          string
	Method       string
	Param        string
	Evidence     string
	Solution     string
	ExchangeID   uint64
	Timestamp    time.Time
}

// NewActiveScanner creates a new active scanner.
func NewActiveScanner(store *core.TrafficStore, logger *zap.Logger) *ActiveScanner {
	return &ActiveScanner{
		store:  store,
		logger: logger,
		config: &ScanConfig{
			MaxConcurrency: 10,
			Timeout:        30 * time.Second,
			CheckSqli:      true,
			CheckXss:       true,
			CheckPathTraversal: true,
			CheckSSRF:      true,
			CheckXXE:       false,
		},
		findings: make([]*Finding, 0),
	}
}

// WithConfig sets the scan configuration.
func (s *ActiveScanner) WithConfig(config *ScanConfig) *ActiveScanner {
	s.config = config
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
	}

	_ = payloads // Would send test requests in real implementation
	
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
	}

	_ = payloads // Would send test requests in real implementation
	
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
	}

	_ = payloads // Would send test requests in real implementation
	
	return findings
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
	store    *core.TrafficStore
	logger   *zap.Logger
	findings []*Finding
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
	// Would check response headers in real implementation
	// Missing: X-Frame-Options, X-Content-Type-Options, CSP, etc.
}

func (s *PassiveScanner) checkInfoDisclosure(exchange *core.Exchange, findings *[]*Finding) {
	// Would check for sensitive data in responses
	// Email addresses, credit cards, API keys, etc.
}

func (s *PassiveScanner) checkCookieSecurity(exchange *core.Exchange, findings *[]*Finding) {
	// Would check cookie attributes
	// Missing: HttpOnly, Secure, SameSite
}

// GetFindings returns all passive findings.
func (s *PassiveScanner) GetFindings() []*Finding {
	s.findingsMu.RLock()
	defer s.findingsMu.RUnlock()
	
	result := make([]*Finding, len(s.findings))
	copy(result, s.findings)
	return result
}
