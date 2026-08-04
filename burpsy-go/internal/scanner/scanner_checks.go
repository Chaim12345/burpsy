// Package scanner provides additional active check implementations.
//
// The two checks here are thin adapters, not implementations: SCAN-01 lives in js_vulns.go and
// SCAN-02 in jwt_weak.go, each with its own dataset, coverage counters and refusal accounting. What
// remains in this file is the part that is specific to being reached from ActiveScanner.Audit —
// pulling the stored request and response out of the traffic store, stamping the exchange's identity
// onto each finding, and enriching remediation from Burp's shipped catalogue.
//
// Both checks are passive by nature: they examine traffic that has already been captured and send
// nothing. They hang off ActiveScanner because that is where Audit's existing callers reach them,
// and moving them would break those callers for no gain.
package scanner

import (
	"context"

	"github.com/burpsy-go/burpsy/internal/core"
)

// nativeChecks lazily builds the two native checks, so a scanner that never audits never parses the
// 514 KB retire.js corpus.
//
// WithJsLibraryCheck and WithJwtWeakSecretCheck win if they were called first: the Once only fills a
// slot that is still empty. Both setters must therefore be called before the first Audit, which is
// the same contract WithConfig and WithSender already have.
func (s *ActiveScanner) nativeChecks() (*JsLibraryCheck, *JwtWeakSecretCheck) {
	s.nativeOnce.Do(func() {
		if s.jsLib == nil {
			s.jsLib = VendoredJsLibraryCheck()
		}
		if s.jwtWeak == nil {
			s.jwtWeak = BundledJwtWeakSecretCheck()
		}
	})
	return s.jsLib, s.jwtWeak
}

// WithJsLibraryCheck runs SCAN-01 against an operator-supplied corpus instead of the vendored one.
// Call before the first Audit.
func (s *ActiveScanner) WithJsLibraryCheck(c *JsLibraryCheck) *ActiveScanner {
	s.jsLib = c
	return s
}

// WithJwtWeakSecretCheck runs SCAN-02 against an operator-supplied wordlist or budget instead of the
// bundled one. Call before the first Audit.
func (s *ActiveScanner) WithJwtWeakSecretCheck(c *JwtWeakSecretCheck) *ActiveScanner {
	s.jwtWeak = c
	return s
}

// JsLibraryCoverage reports which corpus SCAN-01 evaluated and how much of it, so a caller can tell
// "no vulnerable libraries" from "nothing was identified". See JsCoverage.Inconclusive.
func (s *ActiveScanner) JsLibraryCoverage() JsCoverage {
	js, _ := s.nativeChecks()
	return js.Coverage()
}

// JwtWeakCoverage reports which wordlist SCAN-02 ran and every token it declined to attack. See
// JwtCoverage.Inconclusive.
func (s *ActiveScanner) JwtWeakCoverage() JwtCoverage {
	_, jwt := s.nativeChecks()
	return jwt.Coverage()
}

// checkJWTWeak runs SCAN-02 over one captured exchange: every JWS-shaped string in the response's
// headers and body, plus the request's headers, is attacked with the wordlist.
//
// An exchange with no stored response is not scanned at all rather than scanned as an empty one — a
// pending exchange has no evidence in it either way, and counting it as a response examined would
// pad the denominator behind every claim SCAN-02 makes.
func (s *ActiveScanner) checkJWTWeak(ctx context.Context, exchange *core.Exchange) []*Finding {
	if !s.config.CheckJwtWeak || exchange == nil || exchange.Response == nil {
		return nil
	}
	_, check := s.nativeChecks()
	resp, err := s.store.Get(*exchange.Response)
	if err != nil {
		return nil
	}
	req, err := s.store.Get(exchange.Request)
	if err != nil {
		// Scan counts this: the request side was never examined, so Authorization headers were not
		// looked at for this exchange.
		req = nil
	}
	return s.attribute(check.Scan(resp, req), exchange)
}

// checkJSVulns runs SCAN-01 over one captured exchange's response body, matching known-vulnerable
// library versions by range arithmetic against the vendored retire.js corpus.
func (s *ActiveScanner) checkJSVulns(ctx context.Context, exchange *core.Exchange) []*Finding {
	if !s.config.CheckJSVulns {
		return nil
	}
	path, contentType, body, ok := jsAssetOf(s.store, exchange)
	if !ok {
		return nil
	}
	check, _ := s.nativeChecks()
	return s.attribute(check.Scan(path, contentType, body), exchange)
}

// attribute stamps the exchange's identity onto findings the checks produced, then fills remediation
// from Burp's catalogue for the ones that left it empty.
//
// The checks deliberately do not write their own remediation text: inventing it would be inventing
// security advice presented to an operator as authoritative. A finding whose issue name is not in
// the catalogue keeps whatever the check set, which for the one such issue here
// (jsUndeterminedIssue) is an instruction to go and check by hand rather than a fix.
func (s *ActiveScanner) attribute(findings []*Finding, exchange *core.Exchange) []*Finding {
	for _, f := range findings {
		f.URL = exchange.Path
		f.Method = exchange.Method
		f.ExchangeID = exchange.ID
		EnrichFinding(f)
	}
	return findings
}
