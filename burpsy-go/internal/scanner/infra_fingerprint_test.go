package scanner

import "testing"

func TestFingerprintIdentifiesATechnologyFromHeaders(t *testing.T) {
	techs, err := Fingerprint(map[string][]string{
		"Server":       {"nginx/1.18.0"},
		"X-Powered-By": {"PHP/7.4.3"},
	}, []byte(`<html><body>hello</body></html>`))
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if len(techs) == 0 {
		t.Fatal("no technologies identified from nginx + PHP headers")
	}
	if _, ok := FindTechnology(techs, "nginx"); !ok {
		t.Errorf("nginx not identified; got %v", techs)
	}
}

func TestFingerprintExtractsAVersionWhenTheSignatureCarriesOne(t *testing.T) {
	techs, err := Fingerprint(map[string][]string{"Server": {"nginx/1.18.0"}}, nil)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	nginx, ok := FindTechnology(techs, "nginx")
	if !ok {
		t.Fatalf("nginx not identified; got %v", techs)
	}
	if !nginx.HasVersion() || nginx.Version != "1.18.0" {
		t.Errorf("version = %q, want 1.18.0", nginx.Version)
	}
}

func TestFindTechnologyIsCaseInsensitive(t *testing.T) {
	techs := []Technology{{Name: "React", Version: "18.2.0"}}
	if _, ok := FindTechnology(techs, "react"); !ok {
		t.Error("case-insensitive lookup failed")
	}
	if _, ok := FindTechnology(techs, "Vue"); ok {
		t.Error("found a technology that is not present")
	}
}

func TestVersionInAffectedRange(t *testing.T) {
	if got := CheckVersionRange("18.2.0", ">=18.0.0 <18.3.1"); got != VersionInRange {
		t.Fatalf("got %v, want VersionInRange", got)
	}
}

func TestVersionOutsideAffectedRange(t *testing.T) {
	if got := CheckVersionRange("19.1.0", ">=18.0.0 <18.3.1"); got != VersionOutOfRange {
		t.Fatalf("got %v, want VersionOutOfRange", got)
	}
}

// An absent or unparseable version must not read as "not affected".
func TestUnknownVersionIsNotOutOfRange(t *testing.T) {
	for _, v := range []string{"", "   ", "not-a-version", "1.x-ish"} {
		if got := CheckVersionRange(v, ">=18.0.0 <18.3.1"); got != VersionUnknown {
			t.Errorf("version %q gave %v, want VersionUnknown", v, got)
		}
	}
}

func TestUnparseableConstraintIsUnknownNotAMatch(t *testing.T) {
	if got := CheckVersionRange("18.2.0", "this is not a constraint"); got != VersionUnknown {
		t.Fatalf("got %v, want VersionUnknown", got)
	}
}

func TestTechnologyInAffectedRangeReportsAbsenceSeparately(t *testing.T) {
	techs := []Technology{{Name: "React", Version: "18.2.0"}}

	verdict, found := TechnologyInAffectedRange(techs, "React", ">=18.0.0 <18.3.1")
	if !found || verdict != VersionInRange {
		t.Errorf("React: found=%v verdict=%v, want true/VersionInRange", found, verdict)
	}

	_, found = TechnologyInAffectedRange(techs, "Vue", ">=1.0.0")
	if found {
		t.Error("an absent technology was reported as found")
	}
}

func TestDetectedWithoutVersionIsUnknownRatherThanUnaffected(t *testing.T) {
	techs := []Technology{{Name: "React"}}
	verdict, found := TechnologyInAffectedRange(techs, "React", ">=18.0.0 <18.3.1")
	if !found {
		t.Fatal("React was detected but reported as absent")
	}
	if verdict != VersionUnknown {
		t.Fatalf("verdict = %v, want VersionUnknown for a versionless detection", verdict)
	}
}
