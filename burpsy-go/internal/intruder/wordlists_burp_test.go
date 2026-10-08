package intruder

// Assertions specific to the Burp-sourced payload lists added under burpsy-react-ui-2ngd:
// every "burp-*" bundled list must exist, load, be non-empty, and honestly state that it
// came from Burp Suite's own shipped resources (not a third-party corpus).
import (
	"strings"
	"testing"
)

func TestBurpPayloadListsLoadAndAreNonEmpty(t *testing.T) {
	var burpNames []string
	for _, name := range BuiltinWordlistNames() {
		if strings.HasPrefix(name, "burp-") {
			burpNames = append(burpNames, name)
		}
	}
	if len(burpNames) == 0 {
		t.Fatal("no burp-* bundled wordlists found — the Burp payload import did not land")
	}
	if len(burpNames) < 40 {
		t.Errorf("only %d burp-* lists found, want 40+ (Burp ships 48 PayloadStrings files)", len(burpNames))
	}
	for _, name := range burpNames {
		lines, err := builtinWordlistLines(name)
		if err != nil {
			t.Fatalf("read %q: %v", name, err)
		}
		if len(lines) == 0 {
			t.Errorf("%q resolved with zero payloads", name)
		}
		if BuiltinWordlistCount(name) != len(lines) {
			t.Errorf("%q: BuiltinWordlistCount %d != resolved %d", name, BuiltinWordlistCount(name), len(lines))
		}
		for _, l := range lines {
			if strings.HasPrefix(l, "#") {
				t.Errorf("%q: a provenance header line %q survived as payload", name, l)
			}
		}
	}
}

func TestBurpPayloadListsStateTheyAreFromBurp(t *testing.T) {
	for _, name := range BuiltinWordlistNames() {
		if !strings.HasPrefix(name, "burp-") {
			continue
		}
		raw, err := wordlistFS.ReadFile("wordlists/" + name + ".txt")
		if err != nil {
			t.Fatalf("raw read %q: %v", name, err)
		}
		head := ""
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "#") {
				break
			}
			head += line + "\n"
		}
		if !strings.Contains(head, "Burp Suite") {
			t.Errorf("%q's header does not honestly name Burp Suite as the source", name)
		}
		if !strings.Contains(head, "Source:") {
			t.Errorf("%q's header does not state its source", name)
		}
	}
}

func TestBurpPayloadPlaceholdersArePreserved(t *testing.T) {
	// Several Burp lists use {base}, {domain}, {file} template placeholders; the reader
	// must not strip or alter them.
	lines, err := builtinWordlistLines("burp-sqli")
	if err != nil {
		t.Fatalf("read burp-sqli: %v", err)
	}
	found := false
	for _, l := range lines {
		if strings.Contains(l, "{base}") {
			found = true
			break
		}
	}
	if !found {
		t.Error("burp-sqli lost its {base} placeholders — Burp's template syntax must be preserved as-is")
	}
}
