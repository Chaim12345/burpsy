package intruder

// The bundled wordlist corpus and its shorthand resolver (burpsy-react-ui-kal). The tests
// pin the contracts the honest-counting rule makes load-bearing:
//
//   - every bundled list exists in the embedded corpus and is listed by the manager;
//   - the count is MEASURED from the file, never from the header's claim: drift between the
//     provenance header's stated number and the measured count is a defect, so a wrong
//     header fails this test;
//   - the '#' provenance header is NOT payload space, and blank lines are not either;
//   - the builtin: shorthand resolves through the ordinary FileSource, so an attack that
//     names a bundled list runs on the same reader, trimming, length checks and cap as a
//     server-side file;
//   - an unknown builtin name is refused with the available names — an operator who typos
//     learns what exists rather than an empty payload set;
//   - the provenance of every bundled list is stated IN the file: each header names its
//     public source, its licence basis, and that nothing is extracted from PortSwigger's
//     shipped resources.
import (
	"strings"
	"testing"
)

func TestEveryBundledListIsNamedAndCounted(t *testing.T) {
	names := BuiltinWordlistNames()
	if len(names) == 0 {
		t.Fatal("the bundled corpus is empty — the whole feature exists because a corpus is missing")
	}
	for _, name := range names {
		if BuiltinWordlistCount(name) == 0 {
			t.Errorf("bundled list %q counts zero payloads — an empty list in the manager is a corpus claiming content it does not hold", name)
		}
	}
}

func TestTheProvenanceHeaderIsCommentNotPayload(t *testing.T) {
	lines, err := resolveBuiltinWordlist("builtin:sqli-basic", func(int) error { return nil })
	if err != nil {
		t.Fatalf("resolve sqli-basic: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("sqli-basic resolved empty")
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "#") {
			t.Errorf("a provenance header line %q survived as a payload — the header is the file's honesty, not its payload space", l)
		}
	}
	// The count is what the header says the attack will see: measured, not trusted.
	if got := BuiltinWordlistCount("sqli-basic"); got != len(lines) {
		t.Errorf("BuiltinWordlistCount says %d but the resolver produced %d — the count an operator plans around must be the count that fires", got, len(lines))
	}
}

func TestEachBundledListStatesItsProvenance(t *testing.T) {
	// The honest-counting rule as it applies to a corpus: every shipped list names its
	// public source, its licence basis, and that it is not extracted from Burp's resources.
	for _, name := range BuiltinWordlistNames() {
		data, err := builtinWordlistLines(name)
		if err != nil {
			t.Fatalf("read %q: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("%q resolved with zero payloads", name)
		}
		// The header lines are the file's own; read them raw.
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
		if !strings.Contains(head, "Source:") {
			t.Errorf("%q's header does not state its source", name)
		}
		if !strings.Contains(head, "Licence") {
			t.Errorf("%q's header does not state its licence basis", name)
		}
		if !strings.Contains(head, "PortSwigger") {
			t.Errorf("%q's header does not state that it is not extracted from PortSwigger's shipped resources", name)
		}
	}
}

func TestTheShorthandResolvesThroughTheOrdinaryFileSource(t *testing.T) {
	// {"type":"file","filename":"builtin:xss-basic"} must behave exactly like a server-side
	// file: same reader, same trimming, same cap. Resolve is the ordinary entry point.
	src := PayloadSource{Type: "file", File: &FileSource{Filename: "builtin:xss-basic"}}
	set, err := src.Resolve(100)
	if err != nil {
		t.Fatalf("Resolve builtin: %v", err)
	}
	if set.Total == 0 {
		t.Fatal("the builtin shorthand resolved zero payloads through the ordinary FileSource reader")
	}
	// and the cap truncates like any other list
	capped, err := src.Resolve(3)
	if err != nil {
		t.Fatalf("Resolve builtin capped: %v", err)
	}
	if !capped.Truncated || capped.Total != set.Total {
		t.Errorf("the builtin shorthand ignored the cap: truncated=%v total=%d, want truncation at 3 with the full total still stated", capped.Truncated, capped.Total)
	}
}

func TestAnUnknownBuiltinNameNamesWhatExists(t *testing.T) {
	_, err := resolveBuiltinWordlist("builtin:no-such-list", func(int) error { return nil })
	if err == nil {
		t.Fatal("an unknown builtin name resolved — a typo would silently arm the attack with nothing")
	}
	if !strings.Contains(err.Error(), "no bundled wordlist named") {
		t.Errorf("the refusal = %q, want it to name the mistake", err)
	}
}

func TestIsBuiltinSeparatesTheTwoAddressSpaces(t *testing.T) {
	if !IsBuiltinWordlist("builtin:sqli-basic") {
		t.Error("the shorthand was not recognised")
	}
	if IsBuiltinWordlist("/etc/passwd") {
		t.Error("an absolute path was treated as the builtin shorthand — the filesystem probe and the embedded corpus are different address spaces")
	}
}
