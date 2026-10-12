package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// Cache-related checks: web cache poisoning and web cache deception are
// implemented natively (they are observable through ordinary request/response
// pairs). HTTP request smuggling and client-side desync used to be declined here for
// want of a keep-alive/pipelining primitive; both are registered by FinalCheckDescriptors
// in checks_final.go, with their runners in checks_smuggling.go.
//
// The evidence classifiers below are pure: they take observed response bodies,
// statuses and headers and return a bitmask with no network or storage access,
// mirroring the SQLi port's analyzeSQLiEvidence shape so the decision tables are
// unit-testable in isolation.

const (
	cachePoisonIssue    = "Web cache poisoning"
	cacheDeceptionIssue = "Web cache deception"

	// cacheDeceptionStaticExt is the static-looking suffix Burp appends to a
	// dynamic path; caches commonly treat a .css URL as a cacheable static asset.
	cacheDeceptionStaticExt = ".css"
)

// cacheDeceptionEvidence is the observable result class for deception.
type cacheDeceptionEvidence uint8

const (
	// deceptionEvidenceCacheableStatus means the decorated URL returned a status
	// a cache would typically store.
	deceptionEvidenceCacheableStatus cacheDeceptionEvidence = 1 << iota
	// deceptionEvidenceDynamicContent means the decorated response still carried
	// the original dynamic/sensitive content.
	deceptionEvidenceDynamicContent
)

// analyzeCacheDeceptionEvidence classifies the decorated-URL response. A finding
// requires the dynamic-content bit; the cacheable-status bit is supporting.
func analyzeCacheDeceptionEvidence(originalBody, decoratedBody string, decoratedStatus int) cacheDeceptionEvidence {
	var ev cacheDeceptionEvidence
	switch decoratedStatus {
	case http.StatusOK, http.StatusNonAuthoritativeInfo, http.StatusPartialContent,
		http.StatusMultipleChoices, http.StatusMovedPermanently, http.StatusFound, http.StatusNotModified:
		ev |= deceptionEvidenceCacheableStatus
	}
	if originalBody != "" && decoratedBody != "" && strings.Contains(decoratedBody, originalBody) {
		ev |= deceptionEvidenceDynamicContent
	}
	return ev
}

func cacheDeceptionEvidenceText(ev cacheDeceptionEvidence) string {
	parts := make([]string, 0, 2)
	if ev&deceptionEvidenceCacheableStatus != 0 {
		parts = append(parts, "decorated URL returned a cacheable status")
	}
	if ev&deceptionEvidenceDynamicContent != 0 {
		parts = append(parts, "dynamic/sensitive content served under a static-looking key")
	}
	if len(parts) == 0 {
		return "no web cache deception evidence"
	}
	return strings.Join(parts, "; ")
}

// responseIsCacheable reports whether a response is a caching candidate. It is
// conservative: it only excludes responses explicitly marked uncacheable
// (no-store/private). The presence of any cache-signalling header flips it to
// true; absent those it still returns true so a poisoning opportunity is not
// missed (the dangerous reflected bit is what gates a finding, not this flag).
func responseIsCacheable(headers map[string]string) bool {
	cc := strings.ToLower(headers["Cache-Control"])
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}
	for _, h := range []string{"Age", "Expires", "Etag", "Last-Modified", "X-Cache", "Via"} {
		if _, ok := headers[h]; ok {
			return true
		}
	}
	return true
}

// appendCacheDeceptionSuffix appends a static-looking file to a dynamic path,
// preserving any query string, so the request looks like a static asset fetch.
func appendCacheDeceptionSuffix(path string) string {
	query := ""
	if idx := strings.Index(path, "?"); idx >= 0 {
		query = path[idx:]
		path = path[:idx]
	}
	if strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	return path + "/nonexistent" + cacheDeceptionStaticExt + query
}

// sendCacheProbe sends one request through the engagement-scope gate and returns
// the response. It returns ok=false on refusal, transport error, or a missing
// sender, so a check falls through cleanly rather than reporting a false result.
func sendCacheProbe(s *ActiveScanner, ctx context.Context, exchange *core.Exchange, testURL string, headers map[string]string) (*sender.Response, bool) {
	if s == nil || s.sender == nil || exchange == nil {
		return nil, false
	}
	gate := s.probeGate(ctx, exchange)
	resp, err := gate.SendRequest(ctx, &sender.Request{
		Method:  exchange.Method,
		Host:    exchange.Host,
		Path:    testURL,
		TLS:     exchange.TLS,
		Port:    exchange.Port,
		Headers: headers,
	})
	if gate.Refused() > 0 || err != nil || resp == nil {
		return nil, false
	}
	return resp, true
}

func remediationFor(name string) string {
	if def, ok := ByName(name); ok {
		return def.Remediation
	}
	return ""
}

// checkWebCacheDeception requests a dynamic path with a static-looking suffix and
// checks whether the response still carries the original dynamic content under a
// cacheable status — the signature of a cache that may store sensitive content
// under a static key.
func checkWebCacheDeception(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Exchange == nil || cc.Scanner == nil {
		return nil, nil
	}
	s := cc.Scanner
	exchange := cc.Exchange

	originalBody := s.getResponseBody(exchange)
	if originalBody == "" {
		return nil, nil
	}
	decoratedURL := appendCacheDeceptionSuffix(exchange.Path)
	resp, ok := sendCacheProbe(s, ctx, exchange, decoratedURL, nil)
	if !ok {
		return nil, nil
	}
	evidence := analyzeCacheDeceptionEvidence(originalBody, string(resp.Body), resp.StatusCode)
	if evidence&deceptionEvidenceDynamicContent == 0 {
		return nil, nil
	}
	return []*Finding{{
		Name:        cacheDeceptionIssue,
		Severity:    "medium",
		Confidence:  "firm",
		Description: "Web cache deception: a dynamic, sensitive response was served under a static-looking URL (" + decoratedURL + "), which a cache may store and serve to other users.",
		URL:         decoratedURL,
		Method:      exchange.Method,
		Evidence:    cacheDeceptionEvidenceText(evidence),
		Solution:    remediationFor(cacheDeceptionIssue),
		ExchangeID:  exchange.ID,
		Timestamp:   time.Now(),
	}}, nil
}

// cacheChecksEnabled gates the whole cache-issue family behind
// ScanConfig.CheckCachePoisoning, off by default like every other per-family
// switch. The two declined entries share the gate with their native siblings
// so enabling the family reports on all four consistently.
func cacheChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckCachePoisoning }

// CacheCheckDescriptors returns the four cache-issue descriptors this engine owns:
// two implemented natively and two declined because the sender cannot observe the
// transport-level differential they require.
func CacheCheckDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		mediumDescriptor(cachePoisonIssue, DispatchScopePerUrl, cacheChecksEnabled, checkWebCachePoisoning),
		mediumDescriptor(cacheDeceptionIssue, DispatchScopePerUrl, cacheChecksEnabled, checkWebCacheDeception),
	}
}
