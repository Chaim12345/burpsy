package main

import (
	"strings"
	"testing"
)

// The -plugins allowlist is the Extender's whole admission gate, so a malformed entry refuses to start
// rather than surfacing later as a plugin the Extensions tab lists and cannot load.
func TestParsePluginAllowlistRefusesMalformedEntries(t *testing.T) {
	for _, bad := range []string{"probe", "=path", "probe=", "probe=/a,probe=/b"} {
		if _, err := parseNamePathAllowlist("-plugins", bad); err == nil {
			t.Errorf("parseNamePathAllowlist(%q) succeeded, want an error", bad)
		}
	}
	got, err := parseNamePathAllowlist("-plugins", " probe=/opt/burpsy/probe , notes=/usr/local/bin/notes ")
	if err != nil {
		t.Fatalf("parseNamePathAllowlist: %v", err)
	}
	if got["probe"] != "/opt/burpsy/probe" || got["notes"] != "/usr/local/bin/notes" {
		t.Errorf("allowlist = %v, want both entries trimmed", got)
	}
	// The error names the flag the operator typed, not whichever one the shared parser was written for.
	if _, err := parseNamePathAllowlist("-plugins", "probe"); err == nil ||
		!strings.Contains(err.Error(), "-plugins") {
		t.Errorf("error = %v, want it to name -plugins", err)
	}
}

// A spec carries the path and nothing else: no args, no env. Splitting a flag value into an argv is a
// small shell, and the executable is run directly precisely so that an argument containing shell
// metacharacters is data.
func TestPluginSpecsCarryThePathAlone(t *testing.T) {
	if specs := pluginSpecs(nil); specs != nil {
		t.Errorf("an empty allowlist produced %v, want nil so the host reports zero allowlisted", specs)
	}
	specs := pluginSpecs(map[string]string{"probe": "/opt/burpsy/probe"})
	spec, ok := specs["probe"]
	if !ok {
		t.Fatalf("specs = %v, want an entry for probe", specs)
	}
	if spec.Path != "/opt/burpsy/probe" || len(spec.Args) != 0 || len(spec.Env) != 0 {
		t.Errorf("spec = %+v, want the path alone", spec)
	}
}
