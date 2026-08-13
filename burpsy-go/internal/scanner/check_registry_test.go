package scanner

import (
	"context"
	"testing"
)

func TestNativeCheckRegistryHasOneDescriptorPerCatalogIssueAfterTheCompletenessSweep(t *testing.T) {
	registry := NativeCheckRegistry()
	if len(registry) != 183 {
		t.Fatalf("native registry has %d entries, want 183 (one per catalog TypeIndex)", len(registry))
	}
	if err := ValidateRegistry(registry); err != nil {
		t.Fatal(err)
	}
	runnable := 0
	for _, descriptor := range registry {
		if descriptor.Implementation == ImplementationNative {
			runnable++
		}
		if descriptor.Enabled == nil {
			t.Errorf("%q has no configuration gate", descriptor.Name)
		}
		if descriptor.Implementation == ImplementationDeclined && descriptor.DeclineReason == "" {
			t.Errorf("%q is declined without a reason", descriptor.Name)
		}
	}
	// 5 original (SQLi, XSS reflected, path traversal, JWT weak secret, vulnerable JS dep) +
	// 6 header/CORS/CSP + 2 cache (poisoning, deception) + 6 reflection-probe family (input
	// reflection, open redirection, link manipulation, header injection, code injection, SSI
	// injection) + 5 host-discovery family (OpenAPI/Swagger, robots.txt, GraphQL endpoint, HTTP
	// PUT enabled, HTTP TRACE enabled) + 5 response-dependence family (backup file,
	// User-Agent-dependent, Referer-dependent, ASP.NET debugging, ASP.NET tracing) = 29, plus
	// the 15 network-free passive-posture checks (password-handling family, cross-domain POST,
	// content-type declaration, long redirect, request-URL override, cross-domain Referer
	// leakage, cleartext, HSTS, cacheable HTTPS, mixed content) = 44 runnable; the remaining
	// 139 are explicitly declined, then the 28 network-free analyser checks (cookie security,
	// response/header attributes, nine disclosure families, ViewState, serialized objects, five
	// CSP rows), then the 12 active injection checks (OS command, LDAP, XPath, XML, file path
	// manipulation, server-side template, expression language, and the five interpreted-language
	// code-injection rows) = 84 runnable and 99 declined.
	if runnable != 183 {
		t.Fatalf("native registry has %d runnable checks, want 183", runnable)
	}
}

func TestRegistryByTypeIndexSortsWithoutMutatingInput(t *testing.T) {
	input := NativeCheckRegistry()
	input[0], input[1] = input[1], input[0]
	firstBefore := input[0].TypeIndex
	sorted, err := RegistryByTypeIndex(input)
	if err != nil {
		t.Fatal(err)
	}
	if sorted[0].TypeIndex > sorted[len(sorted)-1].TypeIndex {
		t.Fatal("registry is not sorted by TypeIndex")
	}
	if input[0].TypeIndex != firstBefore {
		t.Fatal("sorting mutated the caller's registry")
	}
}

func TestDescriptorDeclineRequiresReasonAndNoRunner(t *testing.T) {
	declined := CheckDescriptor{
		TypeIndex:      1,
		Name:           "declined",
		Implementation: ImplementationDeclined,
		DeclineReason:  "requires browser execution",
	}
	if !declined.Valid() {
		t.Fatal("explicitly declined descriptor should be valid")
	}
	declined.Run = func(_ context.Context, _ *CheckContext) ([]*Finding, error) { return nil, nil }
	if declined.Valid() {
		t.Fatal("declined descriptor with runner should be invalid")
	}
}
