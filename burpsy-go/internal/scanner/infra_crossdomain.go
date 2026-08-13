package scanner

// Cross-domain policy file parsing (Flash crossdomain.xml, Silverlight
// clientaccesspolicy.xml).
//
// Recovered evidence: the fetch/verify helpers backing burp.Zm24
// (APH_FlashCrossdomainPolicy) and burp.Zbtu (APH_SilverlightCrossdomainPolicy)
// are burp.Zudv and burp.Zebv respectively. map_root.tsv confirms, verbatim,
// the request path burp.Zudv fetches ("/crossdomain.xml") and the element/
// attribute names its decompiled body actually tests ("allow-access-from",
// "domain"); and for Zebv the path ("/clientaccesspolicy.xml") plus the
// attribute/scheme literals its ZN() normaliser strips ("uri", "http://",
// "https://"). Both class bodies are read in full at
// out/clean/root/Zudv.java and out/clean/root/Zebv.java, and the wildcard
// rules below (Zh/ZL: exact "*" after scheme-stripping) are ported directly
// from their Zh/ZM and ZL/ZM methods. Everything else this file recovers is
// cited per-field below; where the decompiled body does not reach a
// construct (the allow-http-request-headers-from element for Flash, and the
// http-request-headers attribute for Silverlight, plus the secure attribute)
// this file falls back to the publicly documented Adobe/Microsoft policy
// schemas, which is noted explicitly rather than presented as recovered.

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// CrossdomainPolicy is the decision-relevant content of a parsed Flash
// crossdomain.xml or Silverlight clientaccesspolicy.xml file: which
// origins/headers it trusts, and whether any of the admitted constructs are
// the ones that grant an arbitrary origin (or arbitrary header set) access
// to the resource the policy file is meant to protect.
type CrossdomainPolicy struct {
	// AllowedDomains lists every domain/uri value declared by the policy,
	// verbatim and in document order (including a literal "*" entry when
	// present). Kept even when AllowsAnyDomain is already true so a caller
	// can cite the exact markup that produced the finding.
	AllowedDomains []string
	// AllowsAnyDomain is true when any entry in AllowedDomains resolves to
	// a wildcard that admits every origin: an exact "*" for a Flash
	// allow-access-from domain attribute, or "*"/"http://*"/"https://*"
	// for a Silverlight <domain uri="...">   (Silverlight strips the
	// scheme before comparing — see ParseSilverlightPolicy).
	AllowsAnyDomain bool
	// AllowsAnyHeader is true when the policy additionally grants an
	// admitted requester the ability to set arbitrary HTTP request
	// headers: Flash's allow-http-request-headers-from headers="*", or
	// Silverlight's allow-from http-request-headers="*". Combined with
	// AllowsAnyDomain this means a page on any origin can forge
	// authenticated, header-bearing requests and read the response —
	// worse than a bare wildcard domain grant alone.
	AllowsAnyHeader bool
	// SecureFalseFound is true when a Flash allow-access-from element
	// spells out secure="false". Per the Adobe crossdomain.xml spec,
	// secure="true" additionally requires the connecting SWF's own
	// origin to have been loaded over HTTPS before its domain is trusted;
	// an explicit secure="false" opts back out of that, so a policy
	// served only over HTTPS can still be satisfied by a page an
	// on-path attacker served over plain HTTP. This is a materially
	// different (weaker) grant than the domain list alone describes, so
	// it is tracked as its own field rather than folded into
	// AllowsAnyDomain.
	SecureFalseFound bool
	// AllowedHTTPRequestHeaders lists every headers/http-request-headers
	// value declared by the policy, verbatim and in document order.
	AllowedHTTPRequestHeaders []string
	// ParseError holds the XML decoder's error text when raw could not be
	// parsed as well-formed XML. A non-empty ParseError means every other
	// field is a zero value BY REFUSAL to guess, not because the policy
	// was inspected and found safe: TrustsArbitraryOrigin and RiskSummary
	// both treat a parse failure as "undetermined", never as "found
	// nothing" — see their doc comments.
	ParseError string
}

// --- Flash: crossdomain.xml -------------------------------------------------

// flashCrossdomainPolicy models the subset of the Adobe crossdomain.xml
// schema this parser needs. The <cross-domain-policy> root and
// allow-access-from/domain literals are the ones recovered from burp.Zudv;
// allow-http-request-headers-from (and its headers/secure attributes) is not
// reached by Zudv's decompiled body — that class only walks
// allow-access-from — so it is included here from the public spec, which
// Flash Player itself implements and which is the construct the equivalent
// header-forgery risk depends on.
type flashCrossdomainPolicy struct {
	XMLName xml.Name            `xml:"cross-domain-policy"`
	Allow   []flashAllowAccess  `xml:"allow-access-from"`
	Headers []flashAllowHeaders `xml:"allow-http-request-headers-from"`
}

type flashAllowAccess struct {
	Domain string `xml:"domain,attr"`
	Secure string `xml:"secure,attr"`
}

type flashAllowHeaders struct {
	Domain  string `xml:"domain,attr"`
	Headers string `xml:"headers,attr"`
}

// ParseFlashCrossdomainPolicy parses the body of a /crossdomain.xml response
// (the recovered literal request path from burp.Zudv) into a
// CrossdomainPolicy. Malformed XML sets ParseError and leaves every other
// field zero, rather than guessing at partial content — see
// CrossdomainPolicy.ParseError.
func ParseFlashCrossdomainPolicy(raw []byte) CrossdomainPolicy {
	var doc flashCrossdomainPolicy
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return CrossdomainPolicy{ParseError: err.Error()}
	}

	var out CrossdomainPolicy
	for _, a := range doc.Allow {
		domain := strings.TrimSpace(a.Domain)
		if domain == "" {
			continue
		}
		out.AllowedDomains = append(out.AllowedDomains, domain)
		// Ported directly from Zudv.Zh: the only wildcard test the
		// decompiled body performs is an exact match against "*", with
		// no scheme-stripping (Flash domain values are bare hostnames,
		// never scheme-prefixed).
		if domain == "*" {
			out.AllowsAnyDomain = true
		}
		if strings.EqualFold(strings.TrimSpace(a.Secure), "false") {
			out.SecureFalseFound = true
		}
	}
	for _, h := range doc.Headers {
		if headers := strings.TrimSpace(h.Headers); headers != "" {
			out.AllowedHTTPRequestHeaders = append(out.AllowedHTTPRequestHeaders, headers)
			if headers == "*" {
				out.AllowsAnyHeader = true
			}
		}
		if strings.TrimSpace(h.Domain) == "*" {
			out.AllowsAnyDomain = true
		}
	}
	return out
}

// --- Silverlight: clientaccesspolicy.xml ------------------------------------

// silverlightPolicy models the subset of the Microsoft clientaccesspolicy.xml
// schema this parser needs. The access-policy/cross-domain-access/policy/
// allow-from/domain nesting and its "uri" attribute are the literals
// recovered from burp.Zebv. http-request-headers on allow-from is not
// reached by Zebv's decompiled body (only <domain uri> is walked), so it is
// included here from the public Silverlight spec for the same reason as the
// Flash headers-from element above.
type silverlightPolicy struct {
	XMLName xml.Name                     `xml:"access-policy"`
	Cross   silverlightCrossDomainAccess `xml:"cross-domain-access"`
}

type silverlightCrossDomainAccess struct {
	Policies []silverlightPolicyEntry `xml:"policy"`
}

type silverlightPolicyEntry struct {
	AllowFrom []silverlightAllowFrom `xml:"allow-from"`
}

type silverlightAllowFrom struct {
	HTTPRequestHeaders string              `xml:"http-request-headers,attr"`
	Domains            []silverlightDomain `xml:"domain"`
}

type silverlightDomain struct {
	URI string `xml:"uri,attr"`
}

// ParseSilverlightPolicy parses the body of a /clientaccesspolicy.xml
// response (the recovered literal request path from burp.Zebv) into a
// CrossdomainPolicy. Malformed XML sets ParseError and leaves every other
// field zero — see CrossdomainPolicy.ParseError.
func ParseSilverlightPolicy(raw []byte) CrossdomainPolicy {
	var doc silverlightPolicy
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return CrossdomainPolicy{ParseError: err.Error()}
	}

	var out CrossdomainPolicy
	for _, policy := range doc.Cross.Policies {
		for _, allow := range policy.AllowFrom {
			if headers := strings.TrimSpace(allow.HTTPRequestHeaders); headers != "" {
				out.AllowedHTTPRequestHeaders = append(out.AllowedHTTPRequestHeaders, headers)
				if headers == "*" {
					out.AllowsAnyHeader = true
				}
			}
			for _, d := range allow.Domains {
				uri := strings.TrimSpace(d.URI)
				if uri == "" {
					continue
				}
				out.AllowedDomains = append(out.AllowedDomains, uri)
				if silverlightURIIsWildcard(uri) {
					out.AllowsAnyDomain = true
				}
			}
		}
	}
	return out
}

// silverlightURIIsWildcard reports whether a <domain uri="..."> value grants
// every origin. Ported from Zebv.ZN (strip a leading "http://" or "https://",
// case-insensitively — both scheme literals are confirmed in map_root.tsv for
// burp.Zebv) followed by Zebv.ZL's exact-"*" test, so "*", "http://*", and
// "https://*" are all treated identically: the scheme prefix carries no
// scoping information once the host is a bare wildcard.
func silverlightURIIsWildcard(uri string) bool {
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "https://"):
		lower = lower[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		lower = lower[len("http://"):]
	}
	return lower == "*"
}

// --- Shared risk projection --------------------------------------------------

// TrustsArbitraryOrigin reports whether this policy, on its own, lets a page
// hosted on any origin act against the resource it protects. A parse failure
// returns false rather than true or false-by-assumption: it is neither safe
// nor confirmed unsafe, and this method can only speak to what was actually
// parsed. Callers that need to distinguish "parsed, no risky construct
// found" from "could not parse" must check ParseError directly (or use
// RiskSummary, which describes the parse failure instead of staying silent).
func (p CrossdomainPolicy) TrustsArbitraryOrigin() bool {
	if p.ParseError != "" {
		return false
	}
	return p.AllowsAnyDomain
}

// RiskSummary names the concrete risky construct found in the policy, or ""
// when the policy parsed cleanly and contained none. A parse failure is
// reported as its own distinct sentence — never as "" — so a caller cannot
// mistake "we could not read this policy" for "we read this policy and it
// was fine": those are different findings with different remediation.
func (p CrossdomainPolicy) RiskSummary() string {
	if p.ParseError != "" {
		return fmt.Sprintf("policy file could not be parsed as XML (%s); safety is undetermined, not confirmed", p.ParseError)
	}
	switch {
	case p.AllowsAnyDomain && p.AllowsAnyHeader:
		return `policy grants any origin ("*") access and permits arbitrary HTTP request headers from it`
	case p.AllowsAnyDomain:
		return `policy grants any origin ("*") access to this resource`
	case p.AllowsAnyHeader:
		return `policy permits an allowed origin to send arbitrary HTTP request headers ("*")`
	case p.SecureFalseFound:
		return `policy sets secure="false" on an allow-access-from entry, admitting the trusted domain over plain HTTP as well as HTTPS`
	default:
		return ""
	}
}
