package scanner

// Response-shape and request-header analysers for the passive rows that infra_passive.go
// left unwritten: request-URL override, content-type declaration, long redirect bodies and
// cross-domain Referer leakage.
//
// Evidence provenance: the URL-override header set is recovered verbatim from burp.Zw6n
// ("X-Original-URL", "X-Rewrite-URL") and the method-override set from burp.Zssf
// ("X-Method-Override", "X-HTTP-Method-Override", "_method"). The long-redirect byte
// threshold below is NOT recovered — Burp's own figure is ZKM ciphertext residue — so it is
// a documented choice, labelled as such at its declaration.

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// URLOverrideHeaderNames is recovered from burp.Zw6n, which carries exactly these two.
var URLOverrideHeaderNames = []string{"X-Original-URL", "X-Rewrite-URL"}

// MethodOverrideHeaderNames is recovered from burp.Zssf. "_method" is a body/query
// parameter there rather than a header, and is handled separately.
var MethodOverrideHeaderNames = []string{"X-Method-Override", "X-HTTP-Method-Override"}

// MethodOverrideParamName is the non-header override recovered from burp.Zssf.
const MethodOverrideParamName = "_method"

// RequestURLOverrides returns the override headers present, in the recovered order.
func RequestURLOverrides(headers http.Header) []string {
	var found []string
	for _, name := range URLOverrideHeaderNames {
		if headers.Get(name) != "" {
			found = append(found, name)
		}
	}
	return found
}

// MethodOverrides returns the method-override headers present.
func MethodOverrides(headers http.Header) []string {
	var found []string
	for _, name := range MethodOverrideHeaderNames {
		if headers.Get(name) != "" {
			found = append(found, name)
		}
	}
	return found
}

// ContentTypeDeclaration distinguishes the three states the two catalog rows need. A single
// Content-Type carrying a comma-separated list counts as multiple: the recipient cannot tell
// which applies either.
type ContentTypeDeclaration int

const (
	ContentTypeAbsent ContentTypeDeclaration = iota
	ContentTypeSingle
	ContentTypeMultiple
)

func (c ContentTypeDeclaration) String() string {
	switch c {
	case ContentTypeAbsent:
		return "no content type specified"
	case ContentTypeSingle:
		return "one content type specified"
	case ContentTypeMultiple:
		return "multiple content types specified"
	}
	return "unknown"
}

// DeclareContentType classifies how many content types a response declares.
func DeclareContentType(headers http.Header) ContentTypeDeclaration {
	values := headers.Values("Content-Type")
	var types []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if strings.TrimSpace(part) != "" {
				types = append(types, strings.TrimSpace(part))
			}
		}
	}
	switch {
	case len(types) == 0:
		return ContentTypeAbsent
	case len(types) > 1:
		return ContentTypeMultiple
	default:
		return ContentTypeSingle
	}
}

// ContentTypeMissingOnBody reports the "Content type is not specified" condition: a body
// was returned with no declaration, leaving the browser to sniff it.
func ContentTypeMissingOnBody(headers http.Header, bodyLen int) bool {
	return bodyLen > 0 && DeclareContentType(headers) == ContentTypeAbsent
}

// LongRedirectBodyBytes is a chosen threshold, not a recovered Burp constant. A redirect
// body is meant to be a courtesy stub; anything past this size suggests the response served
// the content it was supposed to redirect away from, which an attacker can read without
// following the redirect.
const LongRedirectBodyBytes = 1024

// IsLongRedirectionResponse reports a 3xx carrying a body larger than the threshold. A 304
// is excluded: it is defined to have no body, so a payload there is a different defect.
func IsLongRedirectionResponse(status int, bodyLen int) bool {
	if status < 300 || status > 399 || status == http.StatusNotModified {
		return false
	}
	return bodyLen > LongRedirectBodyBytes
}

// RefererPolicyWithholdsURL reports whether a Referrer-Policy value stops the full URL
// reaching a third party. Values that send only the origin still leak the host but not the
// query string, which is where the sensitive data sits, so they count as withholding.
func RefererPolicyWithholdsURL(policy string) bool {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "no-referrer", "same-origin", "strict-origin", "origin",
		"origin-when-cross-origin", "strict-origin-when-cross-origin":
		return true
	}
	return false
}

// RefererLeak is one off-site link that would carry the current URL in its Referer.
type RefererLeak struct {
	TargetHost string
	Href       string
}

// CrossDomainRefererLeaks reports off-site links on a page whose own URL carries a query
// string. Following such a link sends the full URL — query string included — to the third
// party in the Referer header.
//
// A page with no query string is not reported: there is nothing in the URL to leak. An
// effective Referrer-Policy suppresses the finding entirely, which is why the policy is a
// parameter rather than something the caller is trusted to have checked.
func CrossDomainRefererLeaks(pageURL string, referrerPolicy string, body []byte) ([]RefererLeak, error) {
	if RefererPolicyWithholdsURL(referrerPolicy) {
		return nil, nil
	}
	page, err := url.Parse(pageURL)
	if err != nil {
		return nil, err
	}
	if page.RawQuery == "" {
		return nil, nil
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var leaks []RefererLeak
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		target, err := page.Parse(href)
		if err != nil || target.Host == "" {
			return
		}
		if target.Scheme != "http" && target.Scheme != "https" {
			return
		}
		if strings.EqualFold(target.Hostname(), page.Hostname()) {
			return
		}
		if _, dup := seen[target.Hostname()]; dup {
			return
		}
		seen[target.Hostname()] = struct{}{}
		leaks = append(leaks, RefererLeak{TargetHost: target.Hostname(), Href: href})
	})
	return leaks, nil
}
