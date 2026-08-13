package scanner

import (
	"testing"
)

// ---------------------------------------------------------------------------
// CORS classifiers
// ---------------------------------------------------------------------------

func TestCORSEvidenceArbitraryOriginReflectsAttackerOrigin(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		requestOrigin: "https://evil.example.com",
		allowOrigin:   "https://evil.example.com",
	})
	if evidence&CORSEvidenceArbitraryOrigin == 0 {
		t.Fatal("reflecting an arbitrary attacker Origin must flag arbitrary origin trusted")
	}
}

func TestCORSEvidenceArbitraryOriginWildcardWithCredentials(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		allowOrigin:      "*",
		allowCredentials: true,
	})
	if evidence&CORSEvidenceArbitraryOrigin == 0 {
		t.Fatal("'*' with credentials allowed must flag arbitrary origin trusted")
	}
}

func TestCORSEvidenceArbitraryOriginBenignStaticAllowlist(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		requestOrigin: "https://evil.example.com",
		allowOrigin:   "https://trusted.example.com",
	})
	if evidence != 0 {
		t.Fatalf("a static allowlist that does not match the request Origin must produce no evidence, got %#x", evidence)
	}
}

func TestCORSEvidenceArbitraryOriginWildcardWithoutCredentials(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		allowOrigin:      "*",
		allowCredentials: false,
	})
	if evidence&CORSEvidenceArbitraryOrigin != 0 {
		t.Fatalf("bare '*' without credentials must not flag arbitrary origin trusted, got %#x", evidence)
	}
}

func TestCORSEvidenceUnencryptedOriginReflected(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		requestOrigin: "http://evil.example.com",
		allowOrigin:   "http://evil.example.com",
	})
	if evidence&CORSEvidenceUnencryptedOrigin == 0 {
		t.Fatal("reflecting an http:// origin must flag unencrypted origin trusted")
	}
}

func TestCORSEvidenceUnencryptedOriginBenignHttps(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		requestOrigin: "https://evil.example.com",
		allowOrigin:   "https://evil.example.com",
	})
	if evidence&CORSEvidenceUnencryptedOrigin != 0 {
		t.Fatalf("an https:// reflected origin must not flag unencrypted origin trusted, got %#x", evidence)
	}
}

func TestCORSEvidenceAllSubdomainsWildcardPattern(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		allowOrigin: "https://*.example.com",
	})
	if evidence&CORSEvidenceAllSubdomains == 0 {
		t.Fatal("a 'https://*.example.com' ACAO must flag all-subdomains trusted")
	}
}

func TestCORSEvidenceAllSubdomainsProbeReflected(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		requestOrigin:    "https://app.example.com",
		probeOrigin:      "https://evil.app.example.com",
		probeAllowOrigin: "https://evil.app.example.com",
	})
	if evidence&CORSEvidenceAllSubdomains == 0 {
		t.Fatal("reflecting a crafted subdomain Origin must flag all-subdomains trusted")
	}
}

func TestCORSEvidenceAllSubdomainsBenignStaticHost(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		allowOrigin: "https://example.com",
	})
	if evidence&CORSEvidenceAllSubdomains != 0 {
		t.Fatalf("a static single-host ACAO must not flag all-subdomains trusted, got %#x", evidence)
	}
}

func TestCORSEvidenceAllSubdomainsProbeNotReflected(t *testing.T) {
	evidence := analyzeCORSEvidence(corsProbe{
		requestOrigin:    "https://app.example.com",
		probeOrigin:      "https://evil.app.example.com",
		probeAllowOrigin: "https://app.example.com",
	})
	if evidence&CORSEvidenceAllSubdomains != 0 {
		t.Fatalf("a subdomain probe that is not reflected must not flag all-subdomains trusted, got %#x", evidence)
	}
}

// ---------------------------------------------------------------------------
// CSP classifiers
// ---------------------------------------------------------------------------

func TestCSPEvidenceNotEnforcedWhenAbsent(t *testing.T) {
	evidence := analyzeCSPEvidence(cspProbe{})
	if evidence&CSPEvidenceNotEnforced == 0 {
		t.Fatal("absent CSP must flag not enforced")
	}
}

func TestCSPEvidenceNotEnforcedReportOnlyOnly(t *testing.T) {
	evidence := analyzeCSPEvidence(cspProbe{hasReportOnlyCSP: true})
	if evidence&CSPEvidenceNotEnforced == 0 {
		t.Fatal("report-only-only must flag not enforced")
	}
}

func TestCSPEvidenceEnforcedSuppressesNotEnforced(t *testing.T) {
	evidence := analyzeCSPEvidence(cspProbe{hasEnforcingCSP: true})
	if evidence&CSPEvidenceNotEnforced != 0 {
		t.Fatalf("an enforcing CSP must not flag not enforced, got %#x", evidence)
	}
}

func TestCSPEvidenceAllowsClickjackingWhenFramable(t *testing.T) {
	evidence := analyzeCSPEvidence(cspProbe{hasEnforcingCSP: true})
	if evidence&CSPEvidenceAllowsClickjacking == 0 {
		t.Fatal("no frame-ancestors and no X-Frame-Options must flag allows clickjacking")
	}
}

func TestCSPEvidenceFrameAncestorsSuppressesClickjacking(t *testing.T) {
	evidence := analyzeCSPEvidence(cspProbe{hasEnforcingCSP: true, hasFrameAncestors: true})
	if evidence&CSPEvidenceAllowsClickjacking != 0 {
		t.Fatalf("a frame-ancestors directive must suppress allows clickjacking, got %#x", evidence)
	}
}

func TestCSPEvidenceXFrameOptionsSuppressesClickjacking(t *testing.T) {
	evidence := analyzeCSPEvidence(cspProbe{hasEnforcingCSP: true, hasXFrameOptions: true})
	if evidence&CSPEvidenceAllowsClickjacking != 0 {
		t.Fatalf("an X-Frame-Options header must suppress allows clickjacking, got %#x", evidence)
	}
}

// ---------------------------------------------------------------------------
// Duplicate cookie classifier
// ---------------------------------------------------------------------------

func TestDuplicateCookieEvidenceDetectsConflictingValues(t *testing.T) {
	evidence := analyzeDuplicateCookieEvidence([]string{
		"session=abc; Secure",
		"session=xyz; Secure",
	})
	if evidence&DuplicateCookieEvidenceConflicting == 0 {
		t.Fatal("same cookie name set to different values must flag duplicate cookies")
	}
}

func TestDuplicateCookieEvidenceSameValueIsBenign(t *testing.T) {
	evidence := analyzeDuplicateCookieEvidence([]string{
		"session=abc; Secure",
		"session=abc; HttpOnly",
	})
	if evidence != 0 {
		t.Fatalf("same name + same value must produce no evidence, got %#x", evidence)
	}
}

func TestDuplicateCookieEvidenceDistinctNamesAreBenign(t *testing.T) {
	evidence := analyzeDuplicateCookieEvidence([]string{
		"a=1",
		"b=2",
	})
	if evidence != 0 {
		t.Fatalf("distinct cookie names must produce no evidence, got %#x", evidence)
	}
}

func TestDuplicateCookieEvidenceSingleHeaderIsBenign(t *testing.T) {
	evidence := analyzeDuplicateCookieEvidence([]string{"a=1"})
	if evidence != 0 {
		t.Fatalf("a single Set-Cookie must produce no evidence, got %#x", evidence)
	}
}

// ---------------------------------------------------------------------------
// Descriptor registration
// ---------------------------------------------------------------------------

func TestHeaderCheckDescriptorsReturnsSixValidNativeDistinct(t *testing.T) {
	descs := HeaderCheckDescriptors()
	if len(descs) != 6 {
		t.Fatalf("HeaderCheckDescriptors returned %d descriptors, want 6", len(descs))
	}
	seenTypeIndex := make(map[uint32]bool)
	claimed := map[string]bool{
		"Cross-origin resource sharing: arbitrary origin trusted":   false,
		"Cross-origin resource sharing: unencrypted origin trusted": false,
		"Cross-origin resource sharing: all subdomains trusted":     false,
		"Content security policy: not enforced":                     false,
		"Content security policy: allows clickjacking":              false,
		"Duplicate cookies set":                                     false,
	}
	for _, d := range descs {
		if !d.Valid() {
			t.Errorf("descriptor %q is not Valid(): %+v", d.Name, d)
		}
		if d.Implementation != ImplementationNative {
			t.Errorf("descriptor %q has implementation %q, want native", d.Name, d.Implementation)
		}
		if seenTypeIndex[d.TypeIndex] {
			t.Errorf("duplicate TypeIndex %d across descriptors", d.TypeIndex)
		}
		seenTypeIndex[d.TypeIndex] = true
		if def, ok := ByName(d.Name); !ok || def.TypeIndex != d.TypeIndex {
			t.Errorf("descriptor %q TypeIndex %d does not match catalog", d.Name, d.TypeIndex)
		}
		if _, ok := claimed[d.Name]; !ok {
			t.Errorf("descriptor %q is not one of the 6 claimed names", d.Name)
		}
		claimed[d.Name] = true
	}
	for name, got := range claimed {
		if !got {
			t.Errorf("claimed name %q missing from HeaderCheckDescriptors", name)
		}
	}
}
