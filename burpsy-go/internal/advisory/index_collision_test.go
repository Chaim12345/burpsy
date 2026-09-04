package advisory

import "testing"

// ---- the typeIndex collision, which is Burp's own -------------------------------------------
//
// Two of Burp's shipped definition files declare a neighbour's typeIndex:
//
//	00101200_ReactServerComponentsRemoteCodeExecutionReact2shell.json -> 1052160   (Perl's)
//	09008000_BambdaGeneratedIssue.json                                -> 150994944 (BCheck's)
//
// Verified against Burp's own resources/KnowledgeBase/Issues: 183 files, 181 distinct indices,
// the same two mismatches. So the data is faithful and is deliberately NOT corrected — these
// tests exist to keep it that way and to pin the *behaviour* around it, which is what was
// actually broken.
//
// Before the fix, loadFS assigned byIndex unconditionally, so the last file read won and
// ByIndex answered a wrong-named advisory. GET /api/advisories/{index} served it.

// The bug itself: asking for one advisory's index must not return a different advisory.
//
// This is the assertion that would have failed before the fix, and it is written over the whole
// catalogue rather than the two known pairs so that a future data change cannot reintroduce the
// class somewhere else and pass.
func TestByIndexNeverReturnsADifferentlyNamedAdvisory(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	shadowed := map[string]bool{}
	for _, d := range c.ShadowedByIndex() {
		shadowed[d.Name] = true
	}
	for _, d := range c.All() {
		if shadowed[d.Name] {
			// A shadowed definition does not own its index by design; that is the documented
			// outcome, reported through ShadowedByIndex rather than hidden.
			continue
		}
		got, ok := c.ByIndex(d.TypeIndex)
		if !ok {
			t.Errorf("%q (index %d) is not reachable by index at all", d.Name, d.TypeIndex)
			continue
		}
		if got.Name != d.Name {
			t.Errorf("ByIndex(%d): asked for %q, got %q — a caller reading this advisory would be shown the wrong description, severity and remediation",
				d.TypeIndex, d.Name, got.Name)
		}
	}
}

// The filename decides which of two colliding definitions owns the index, and it must be the
// one whose name agrees with its own field. Deterministic, and not a function of directory order.
func TestTheDefinitionWhoseFilenameAgreesOwnsTheIndex(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Perl's index is claimed by both Perl (correctly) and React2Shell (incorrectly).
	if got, ok := c.ByIndex(1052160); !ok {
		t.Error("index 1052160 is unreachable")
	} else if got.Name != "Perl code injection" {
		t.Errorf("ByIndex(1052160) = %q, want \"Perl code injection\" — the file whose name matches its field must win", got.Name)
	}
	// BCheck's index is claimed by both BCheck (correctly) and Bambda (incorrectly).
	if got, ok := c.ByIndex(150994944); !ok {
		t.Error("index 150994944 is unreachable")
	} else if got.Name != "BCheck generated issue" {
		t.Errorf("ByIndex(150994944) = %q, want \"BCheck generated issue\"", got.Name)
	}
}

// A shadowed definition is still a definition: present in All, reachable by name, readable in
// full. Losing an index must not cost the operator the advisory text.
func TestShadowedDefinitionsRemainReachableByName(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	shadow := c.ShadowedByIndex()
	if len(shadow) == 0 {
		t.Skip("no index collisions in this data set — nothing to assert about shadowed entries")
	}
	inAll := map[string]bool{}
	for _, d := range c.All() {
		inAll[d.Name] = true
	}
	for _, d := range shadow {
		if !inAll[d.Name] {
			t.Errorf("shadowed definition %q was dropped from All()", d.Name)
		}
		got, ok := c.ByName(d.Name)
		if !ok {
			t.Errorf("shadowed definition %q is not reachable by name either — it is now unreadable", d.Name)
			continue
		}
		if got.Name != d.Name {
			t.Errorf("ByName(%q) returned %q", d.Name, got.Name)
		}
		if got.Description == "" {
			t.Errorf("shadowed definition %q has no description", d.Name)
		}
	}
}

// The counts must be self-consistent and must not be conflated.
//
// Len is the definition count, IndexedLen the addressable-index count, and the difference is
// exactly the shadowed list. This is the honest-counting rule applied to the catalogue itself:
// reporting Len as though every entry were addressable would overstate the index by two, which
// is how "183 checks" gets repeated as though all 183 were reachable.
func TestCatalogueCountsAreSelfConsistent(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(c.All()), c.Len(); got != want {
		t.Errorf("len(All()) = %d but Len() = %d", got, want)
	}
	if diff, shadow := c.Len()-c.IndexedLen(), len(c.ShadowedByIndex()); diff != shadow {
		t.Errorf("Len()-IndexedLen() = %d but there are %d shadowed definitions; the residue must be named, not implied",
			diff, shadow)
	}
	if c.IndexedLen() > c.Len() {
		t.Errorf("IndexedLen() = %d exceeds Len() = %d", c.IndexedLen(), c.Len())
	}
	t.Logf("catalogue: %d definitions loaded, %d addressable by index, %d shadowed",
		c.Len(), c.IndexedLen(), len(c.ShadowedByIndex()))
}

// indexFromFilename tolerates a name that does not follow the convention rather than failing the
// load. A definition with an unconventional filename is still a definition, and taking the whole
// advisory surface down to enforce a naming rule would be the wrong trade.
func TestIndexFromFilenameRejectsWithoutFailing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		want  int
		wantK bool
	}{
		{"00100e00_PerlCodeInjection.json", 0x00100e00, true},
		{"09008000_BambdaGeneratedIssue.json", 0x09008000, true},
		{"nounderscore.json", 0, false},
		{"short_Name.json", 0, false},
		{"zzzzzzzz_NotHex.json", 0, false},
		{"", 0, false},
	} {
		got, ok := indexFromFilename(tc.name)
		if ok != tc.wantK {
			t.Errorf("indexFromFilename(%q) ok = %v, want %v", tc.name, ok, tc.wantK)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("indexFromFilename(%q) = %d, want %d", tc.name, got, tc.want)
		}
	}
}
