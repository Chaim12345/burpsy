package scanner

import (
	"strings"
	"testing"
)

func TestAWildcardFlashAllowAccessFromGrantsAnyOriginAccess(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*"/>
</cross-domain-policy>`)

	p := ParseFlashCrossdomainPolicy(raw)

	if p.ParseError != "" {
		t.Fatalf("well-formed policy reported ParseError %q", p.ParseError)
	}
	if !p.AllowsAnyDomain {
		t.Fatal("domain=\"*\" must set AllowsAnyDomain: it grants every origin access, which is exactly the arbitrary-origin risk this check exists to catch")
	}
	if !p.TrustsArbitraryOrigin() {
		t.Fatal("a policy that admits domain=\"*\" must report TrustsArbitraryOrigin true")
	}
	if p.RiskSummary() == "" {
		t.Fatal("a wildcard-domain policy must produce a non-empty RiskSummary naming the construct found")
	}
	if len(p.AllowedDomains) != 1 || p.AllowedDomains[0] != "*" {
		t.Fatalf("AllowedDomains must preserve the literal declared value for evidence display, got %v", p.AllowedDomains)
	}
}

func TestAFlashPolicyWithExplicitSafeDomainListReportsNothingRisky(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="partner.example.com"/>
  <allow-access-from domain="api.example.org"/>
</cross-domain-policy>`)

	p := ParseFlashCrossdomainPolicy(raw)

	if p.ParseError != "" {
		t.Fatalf("well-formed policy reported ParseError %q", p.ParseError)
	}
	if p.AllowsAnyDomain {
		t.Fatal("a policy naming only concrete domains must not be classified as trusting an arbitrary origin")
	}
	if p.AllowsAnyHeader {
		t.Fatal("a policy with no allow-http-request-headers-from element must not report AllowsAnyHeader")
	}
	if p.SecureFalseFound {
		t.Fatal("a policy with no secure attribute must not report SecureFalseFound")
	}
	if p.TrustsArbitraryOrigin() {
		t.Fatal("a policy scoped to named domains must not report TrustsArbitraryOrigin true")
	}
	if got := p.RiskSummary(); got != "" {
		t.Fatalf("a policy with no risky construct must produce an empty RiskSummary, got %q", got)
	}
	if len(p.AllowedDomains) != 2 {
		t.Fatalf("both declared domains must be captured in order, got %v", p.AllowedDomains)
	}
}

func TestFlashSecureFalseIsDetectedIndependentlyOfDomainWildcarding(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="partner.example.com" secure="false"/>
</cross-domain-policy>`)

	p := ParseFlashCrossdomainPolicy(raw)

	if p.AllowsAnyDomain {
		t.Fatal("a named, non-wildcard domain must not itself set AllowsAnyDomain")
	}
	if !p.SecureFalseFound {
		t.Fatal("secure=\"false\" on an allow-access-from entry must set SecureFalseFound: it downgrades the policy to also trust the domain over plain HTTP, weakening it below what the domain list alone implies")
	}
	if p.TrustsArbitraryOrigin() {
		t.Fatal("secure=\"false\" alone (no wildcard domain) must not make TrustsArbitraryOrigin true; it is a narrower, still-reportable weakness")
	}
	if !strings.Contains(p.RiskSummary(), "secure=\"false\"") {
		t.Fatalf("RiskSummary must name the secure=\"false\" construct that was found, got %q", p.RiskSummary())
	}
}

func TestFlashHeadersWildcardGrantsArbitraryRequestHeaders(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="partner.example.com"/>
  <allow-http-request-headers-from domain="partner.example.com" headers="*"/>
</cross-domain-policy>`)

	p := ParseFlashCrossdomainPolicy(raw)

	if !p.AllowsAnyHeader {
		t.Fatal("headers=\"*\" on allow-http-request-headers-from must set AllowsAnyHeader")
	}
	if p.AllowsAnyDomain {
		t.Fatal("a headers-from domain scoped to a named partner must not set AllowsAnyDomain")
	}
	if len(p.AllowedHTTPRequestHeaders) != 1 || p.AllowedHTTPRequestHeaders[0] != "*" {
		t.Fatalf("the declared headers value must be captured verbatim, got %v", p.AllowedHTTPRequestHeaders)
	}
}

func TestASilverlightWildcardDomainURIGrantsAnyOriginAccess(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="utf-8"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from>
        <domain uri="*"/>
      </allow-from>
      <grant-to>
        <resource path="/" include-subpaths="true"/>
      </grant-to>
    </policy>
  </cross-domain-access>
</access-policy>`)

	p := ParseSilverlightPolicy(raw)

	if p.ParseError != "" {
		t.Fatalf("well-formed policy reported ParseError %q", p.ParseError)
	}
	if !p.AllowsAnyDomain {
		t.Fatal("a bare uri=\"*\" domain must set AllowsAnyDomain")
	}
	if !p.TrustsArbitraryOrigin() {
		t.Fatal("a policy admitting uri=\"*\" must report TrustsArbitraryOrigin true")
	}
}

func TestASilverlightSchemePrefixedWildcardURIIsStillTreatedAsAnyOrigin(t *testing.T) {
	// Zebv.ZN strips a leading http:// or https:// before comparing against
	// "*", so a scheme-qualified wildcard is just as permissive as a bare
	// one — the scheme adds no scoping once the host is "*".
	for _, uri := range []string{"http://*", "https://*", "HTTP://*"} {
		p := ParseSilverlightPolicy([]byte(`<access-policy><cross-domain-access><policy>` +
			`<allow-from><domain uri="` + uri + `"/></allow-from>` +
			`<grant-to><resource path="/" include-subpaths="true"/></grant-to>` +
			`</policy></cross-domain-access></access-policy>`))

		if !p.AllowsAnyDomain {
			t.Fatalf("uri=%q must normalize to a wildcard and set AllowsAnyDomain", uri)
		}
	}
}

func TestASilverlightNamedDomainURIDoesNotGrantAnyOriginAccess(t *testing.T) {
	raw := []byte(`<access-policy><cross-domain-access><policy>` +
		`<allow-from><domain uri="http://partner.example.com"/></allow-from>` +
		`<grant-to><resource path="/" include-subpaths="true"/></grant-to>` +
		`</policy></cross-domain-access></access-policy>`)

	p := ParseSilverlightPolicy(raw)

	if p.AllowsAnyDomain {
		t.Fatal("a scheme-prefixed but named host must not be misclassified as a wildcard once the scheme is stripped")
	}
	if p.TrustsArbitraryOrigin() {
		t.Fatal("a policy scoped to one named domain must not report TrustsArbitraryOrigin true")
	}
}

func TestSilverlightHTTPRequestHeadersWildcardGrantsArbitraryHeaders(t *testing.T) {
	raw := []byte(`<access-policy><cross-domain-access><policy>` +
		`<allow-from http-request-headers="*"><domain uri="partner.example.com"/></allow-from>` +
		`<grant-to><resource path="/" include-subpaths="true"/></grant-to>` +
		`</policy></cross-domain-access></access-policy>`)

	p := ParseSilverlightPolicy(raw)

	if !p.AllowsAnyHeader {
		t.Fatal("http-request-headers=\"*\" on allow-from must set AllowsAnyHeader")
	}
	if p.AllowsAnyDomain {
		t.Fatal("a named domain must not itself set AllowsAnyDomain even when headers are wide open")
	}
	if len(p.AllowedHTTPRequestHeaders) != 1 || p.AllowedHTTPRequestHeaders[0] != "*" {
		t.Fatalf("the declared http-request-headers value must be captured verbatim, got %v", p.AllowedHTTPRequestHeaders)
	}
}

func TestMalformedFlashXMLSetsParseErrorAndTrustsArbitraryOriginReturnsFalse(t *testing.T) {
	raw := []byte(`<cross-domain-policy><allow-access-from domain="*"`) // truncated, unclosed tag

	p := ParseFlashCrossdomainPolicy(raw)

	if p.ParseError == "" {
		t.Fatal("truncated/malformed XML must set ParseError rather than silently parsing a partial document")
	}
	if p.TrustsArbitraryOrigin() {
		t.Fatal("TrustsArbitraryOrigin must return false on a parse failure: it can only speak to what was actually parsed, and a wildcard visible in the raw bytes is not a substitute for a confirmed parse")
	}
	if p.AllowsAnyDomain {
		t.Fatal("a parse failure must leave AllowsAnyDomain at its zero value, not infer it from unparsed bytes")
	}
	if p.RiskSummary() == "" {
		t.Fatal("RiskSummary must not be empty on a parse failure: empty is reserved for 'parsed cleanly, nothing risky found', and a caller must be able to tell those two situations apart")
	}
}

func TestMalformedSilverlightXMLSetsParseErrorAndTrustsArbitraryOriginReturnsFalse(t *testing.T) {
	raw := []byte(`this is not xml at all {{{`)

	p := ParseSilverlightPolicy(raw)

	if p.ParseError == "" {
		t.Fatal("non-XML input must set ParseError")
	}
	if p.TrustsArbitraryOrigin() {
		t.Fatal("TrustsArbitraryOrigin must return false on a parse failure")
	}
	if p.RiskSummary() == "" {
		t.Fatal("RiskSummary must describe the parse failure rather than returning the same empty string used for a clean, risk-free parse")
	}
}
