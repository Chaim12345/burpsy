// Package scanner provides additional active check implementations.
package scanner

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"regexp"
	"strings"
	"time"
	"context"

	"github.com/burpsy-go/burpsy/internal/core"
)

// checkJWTWeak detects JWT tokens with weak or default secrets.
func (s *ActiveScanner) checkJWTWeak(ctx context.Context, exchange *core.Exchange) []*Finding {
	if !s.config.CheckJwtWeak {
		return nil
	}
	var findings []*Finding
	body := s.getResponseBody(exchange)
	if body == "" {
		return nil
	}

	// Look for JWT-like strings in response (base64url parts separated by dots)
	jwtRe := regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	matches := jwtRe.FindAllString(body, -1)
	if len(matches) == 0 {
		return nil
	}

	// Common weak secrets to test against
	weakSecrets := []string{
		"", "secret", "key", "password", "admin", "jwt", "token",
		"changeme", "123456", "secretkey", "mysecret", "supersecret",
		"private", "public", "shared", "test", "demo", "sample",
	}

	for _, jwt := range matches {
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			continue
		}
		// Try to decode header to check alg
		headerB64 := parts[0]
		// Add padding if needed
		for len(headerB64)%4 != 0 {
			headerB64 += "="
		}
		headerBytes, err := base64.URLEncoding.DecodeString(headerB64)
		if err != nil {
			continue
		}
		var header map[string]interface{}
		if err := json.Unmarshal(headerBytes, &header); err != nil {
			continue
		}
		alg, _ := header["alg"].(string)
		if alg == "none" || alg == "" {
			findings = append(findings, &Finding{
				Name:        "JWT Algorithm None",
				Severity:    "critical",
				Confidence:  "certain",
				Description: "JWT uses 'none' algorithm - tokens can be forged without signature verification",
				URL:         exchange.Path,
				Method:      exchange.Method,
				Evidence:    "alg: " + alg,
				Solution:    "Require RS256 or HS256 algorithm; reject 'none' and unsigned tokens",
				Timestamp:   time.Now(),
			})
			continue
		}

		// For HS* algorithms, test against weak secrets
		if strings.HasPrefix(alg, "HS") {
			for _, secret := range weakSecrets {
				var h hash.Hash
				switch {
				case strings.HasSuffix(alg, "256"):
					h = hmac.New(sha256.New, []byte(secret))
				case strings.HasSuffix(alg, "384"):
					h = hmac.New(sha512.New384, []byte(secret))
				case strings.HasSuffix(alg, "512"):
					h = hmac.New(sha512.New, []byte(secret))
				default:
					h = hmac.New(md5.New, []byte(secret))
				}
				h.Write([]byte(parts[0] + "." + parts[1]))
				sig := base64.URLEncoding.EncodeToString(h.Sum(nil))
				sig = strings.TrimRight(sig, "=")
				if sig == parts[2] {
					findings = append(findings, &Finding{
						Name:        "JWT Weak Secret",
						Severity:    "high",
						Confidence:  "certain",
						Description: "JWT signed with a weak/default secret - tokens can be forged",
						URL:         exchange.Path,
						Method:      exchange.Method,
						Evidence:    "algorithm: " + alg + ", secret: '" + secret + "'",
						Solution:    "Use strong random secrets (32+ bytes); rotate secrets regularly",
						Timestamp:   time.Now(),
					})
					break
				}
			}
		}
	}
	return findings
}

// checkJSVulns scans for known-vulnerable JavaScript libraries.
func (s *ActiveScanner) checkJSVulns(ctx context.Context, exchange *core.Exchange) []*Finding {
	if !s.config.CheckJSVulns {
		return nil
	}
	var findings []*Finding
	body := s.getResponseBody(exchange)
	if body == "" {
		return nil
	}

	// Known vulnerable JS library patterns (name -> version pattern -> CVE/description)
	// This is a small subset; real implementation would load from a CVE database
	vulnLibs := map[string]map[string]string{
		"jquery": {
			"1.12.4": "CVE-2020-11022/23 - XSS via jQuery.html()",
			"2.2.4":  "CVE-2020-11022/23 - XSS via jQuery.html()",
			"3.4.1":  "CVE-2020-11022 - Prototype pollution",
			"3.5.0":  "CVE-2020-11023 - XSS via jQuery.html()",
		},
		"lodash": {
			"4.17.15": "CVE-2020-28500 - Prototype pollution",
			"4.17.19": "CVE-2021-23337 - Command injection",
			"4.17.20": "CVE-2021-23337 - Command injection",
		},
		"moment": {
			"2.24.0":  "CVE-2019-13358 - ReDoS",
			"2.29.1":  "CVE-2022-21741 - Path traversal in moment.parseFormat",
		},
		"handlebars": {
			"4.5.3":  "CVE-2019-10744 - Prototype pollution",
			"4.7.6":  "CVE-2021-23383 - Prototype pollution",
		},
		"bootstrap": {
			"4.3.1": "CVE-2019-8331 - XSS in tooltip/popover",
			"5.0.0": "CVE-2021-21240 - XSS in sanitize",
		},
	}

	// Simple pattern: look for library + version in script tags or URLs
	for lib, vulns := range vulnLibs {
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(lib) + `[-.]?([0-9]+\.[0-9]+\.[0-9]+)`)
		matches := re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				ver := m[1]
				if desc, ok := vulns[ver]; ok {
					findings = append(findings, &Finding{
						Name:        "Vulnerable JavaScript Library: " + lib,
						Severity:    "medium",
						Confidence:  "firm",
						Description: "Detected " + lib + " version " + ver + " with known vulnerability: " + desc,
						URL:         exchange.Path,
						Method:      exchange.Method,
						Evidence:    lib + "@" + ver,
						Solution:    "Upgrade " + lib + " to latest non-vulnerable version",
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	// Also check for known vulnerable patterns in inline scripts
	vulnPatterns := map[string]string{
		`eval\s*\(`:          "Use of eval() - code injection risk",
		`new\s+Function\s*\(`: "Use of Function constructor - code injection risk",
		`document\.write\s*\(`: "document.write() - XSS risk",
		`innerHTML\s*=\s*`:   "Direct innerHTML assignment - XSS risk",
		`outerHTML\s*=\s*`:   "Direct outerHTML assignment - XSS risk",
	}

	for pattern, desc := range vulnPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(body) {
			findings = append(findings, &Finding{
				Name:        "Insecure JavaScript Pattern",
				Severity:    "medium",
				Confidence:  "tentative",
				Description: desc,
				URL:         exchange.Path,
				Method:      exchange.Method,
				Evidence:    pattern,
				Solution:    "Avoid " + pattern + "; use safe DOM APIs",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}