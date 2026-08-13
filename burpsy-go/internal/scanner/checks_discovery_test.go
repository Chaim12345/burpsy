package scanner

import "testing"

func TestFirstDirectiveLineSkipsCommentsAndBlankLines(t *testing.T) {
	body := "# comment\n\n  \nUser-agent: *\nDisallow: /admin\n"
	if got := firstDirectiveLine(body); got != "User-agent: *" {
		t.Fatalf("got %q, want %q", got, "User-agent: *")
	}
}

func TestFirstDirectiveLineEmptyBody(t *testing.T) {
	if got := firstDirectiveLine("\n# only a comment\n"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestHostDiscoveryCheckDescriptorsAreValidAndNative(t *testing.T) {
	descs := HostDiscoveryCheckDescriptors()
	if len(descs) != 5 {
		t.Fatalf("got %d descriptors, want 5", len(descs))
	}
	seen := make(map[uint32]struct{})
	for _, d := range descs {
		if d.Implementation != ImplementationNative {
			t.Errorf("%q is Implementation %q, want ImplementationNative", d.Name, d.Implementation)
		}
		if d.Scope != DispatchScopePerHost {
			t.Errorf("%q has scope %v, want DispatchScopePerHost", d.Name, d.Scope)
		}
		if !d.Valid() || !d.Runnable() {
			t.Errorf("%q is not a valid, runnable descriptor", d.Name)
		}
		if _, dup := seen[d.TypeIndex]; dup {
			t.Errorf("duplicate TypeIndex %d in HostDiscoveryCheckDescriptors", d.TypeIndex)
		}
		seen[d.TypeIndex] = struct{}{}
	}
}

func TestOpenAPIDefinitionPathsAreUnique(t *testing.T) {
	seen := make(map[string]struct{}, len(openAPIDefinitionPaths))
	for _, p := range openAPIDefinitionPaths {
		if _, dup := seen[p]; dup {
			t.Errorf("duplicate OpenAPI candidate path %q", p)
		}
		seen[p] = struct{}{}
	}
	if len(openAPIDefinitionPaths) < 20 {
		t.Fatalf("got %d candidate paths, want at least 20 recovered from map_root.tsv", len(openAPIDefinitionPaths))
	}
}
