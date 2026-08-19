package scanner

import "testing"

// The policy must be derivable from the registry without a live scanner, and must classify rows the
// way their dispatch scope says. Pinned with concrete rows on both sides so a scope change that
// silently moves a row between host and path granularity shows up here.
func TestDedupPolicyGranularityFollowsDispatchScope(t *testing.T) {
	p := DedupPolicy()

	for _, name := range []string{
		"Strict transport security not enforced",
		"Robots.txt file",
		"TLS certificate",
	} {
		if !p.HostScoped[name] {
			t.Errorf("%q is not host-scoped, but its check runs once per host", name)
		}
	}
	// Endpoint-level rows must stay path-scoped: merging reflected XSS across every path of a host
	// would report one issue for a whole site.
	for _, name := range []string{
		"Cross-site scripting (reflected)",
		"SQL injection",
		"Input returned in response (reflected)",
	} {
		if p.HostScoped[name] {
			t.Errorf("%q is host-scoped, which would merge it across every path on a host", name)
		}
	}
}

// The provenance rows label who filed a finding, not what it is, so merging by their name would
// collapse unrelated findings.
func TestDedupPolicyExemptsProvenanceRows(t *testing.T) {
	p := DedupPolicy()
	for _, name := range provenanceRows {
		if !p.Exempt[name] {
			t.Errorf("%q is not exempt from deduplication", name)
		}
		if p.HostScoped[name] {
			t.Errorf("%q is host-scoped as well as exempt; exemption wins, but the pair is confusing", name)
		}
	}
}

// Every name in the policy has to be a real catalog row, or the policy silently applies to nothing.
func TestDedupPolicyNamesResolveInCatalog(t *testing.T) {
	p := DedupPolicy()
	for name := range p.HostScoped {
		if _, ok := ByName(name); !ok {
			t.Errorf("host-scoped row %q is absent from the catalog", name)
		}
	}
	for name := range p.Exempt {
		if _, ok := ByName(name); !ok {
			t.Errorf("exempt row %q is absent from the catalog", name)
		}
	}
}
