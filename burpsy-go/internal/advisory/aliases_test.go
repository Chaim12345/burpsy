package advisory

import "testing"

// Every alias must point at an index the catalogue actually carries. A typo here would present as
// "that check has no advisory", which is indistinguishable from an unmapped check — so it is caught
// mechanically rather than by someone noticing a blank panel.
func TestEveryAliasResolvesToARealDefinition(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for name, idx := range aliases {
		d, ok := c.ByIndex(idx)
		if !ok {
			t.Errorf("alias %q -> %08x, which is not in the catalogue", name, idx)
			continue
		}
		if got, _ := c.Resolve(name); got != d {
			t.Errorf("Resolve(%q) did not return the aliased definition", name)
		}
	}
}

// An alias key must already be normalised, or it can never match: Resolve normalises the incoming
// name and compares against these keys verbatim.
func TestAliasKeysAreNormalised(t *testing.T) {
	for name := range aliases {
		if n := NormaliseName(name); n != name {
			t.Errorf("alias key %q is not normalised (want %q)", name, n)
		}
	}
	for name := range unmapped() {
		if n := NormaliseName(name); n != name {
			t.Errorf("unmapped key %q is not normalised (want %q)", name, n)
		}
	}
}

// The three checks with no catalogue equivalent report why, rather than looking like a failed load.
func TestUnmappedChecksExplainThemselves(t *testing.T) {
	c, _ := Load()
	for _, name := range []string{
		"Missing Content-Security-Policy Header",
		"Cookie Missing SameSite Flag",
		"Information Disclosure: Password in Response",
	} {
		def, reason := c.Resolve(name)
		if def != nil {
			t.Errorf("%s resolved to %q; it has no catalogue equivalent", name, def.Name)
		}
		if reason == "" {
			t.Errorf("%s has no recorded reason for being unmapped", name)
		}
	}
	// A name nobody has considered resolves to nothing, with no invented explanation.
	if def, reason := c.Resolve("Some BCheck nobody mapped"); def != nil || reason != "" {
		t.Errorf("unknown check produced def=%v reason=%q, want both empty", def, reason)
	}
}

// The real burpsy check names resolve. This is the test that fails when a check is renamed.
func TestBurpsyCheckNamesResolve(t *testing.T) {
	c, _ := Load()
	for _, name := range []string{
		"Missing X-Frame-Options Header", "Missing X-Content-Type-Options Header",
		"Cookie Missing HttpOnly Flag", "Cookie Missing Secure Flag",
		"Cross-Site Scripting (XSS)", "Path Traversal",
		"JWT none algorithm supported", "JWT weak HMAC secret (SCAN-02)",
		"Vulnerable JavaScript dependency (SCAN-01)",
		"SQL injection", "OS command injection", // exact catalogue names, no alias needed
	} {
		if d, _ := c.Resolve(name); d == nil {
			t.Errorf("%q resolves to no definition", name)
		}
	}
}

// The guesser's three issue names resolve to Burp's extension-generated type, which is where Param
// Miner's "Secret input" issues land in Burp (burpsy-react-ui-wlz8). Spelled as the scanner files
// them, so a rename on either side fails here rather than blanking the advisory panel.
func TestSecretInputIssuesResolveToTheExtensionGeneratedType(t *testing.T) {
	c, _ := Load()
	for _, name := range []string{"Secret input: query parameter", "Secret input: cookie", "Secret input: header"} {
		def, _ := c.Resolve(name)
		if def == nil || def.Name != "Extension generated issue" {
			t.Errorf("Resolve(%q) = %v, want the Extension generated issue definition", name, def)
		}
	}
}
