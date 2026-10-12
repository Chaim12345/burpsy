package scanner

import (
	"strings"
	"testing"
)

// TestTheTraversalBankNamesNoApplicationsOwnFiles pins that the traversal payloads and signatures are
// techniques and platform files, never one application's data files. A signature keyed to a single
// benchmark's planted JSON scores that benchmark and nothing else, and reports a detection rate the
// scanner would not earn on any other target.
func TestTheTraversalBankNamesNoApplicationsOwnFiles(t *testing.T) {
	banned := []string{"secret.json", "OwaspAppInfo", "UserInfo.json", "NirraIshq", "Project Leader",
		"exposing one Vulnerability", "VulnerableApp"}
	all := append(append([]string{}, PathTraversalPayloads...), TraversalFileSignatures...)
	all = append(all, TraversalPayloadsFor("")...)
	for _, s := range all {
		for _, b := range banned {
			if strings.Contains(s, b) {
				t.Errorf("bank entry %q names an application's own file (%q)", s, b)
			}
		}
	}
}

// TestTraversalPayloadsPreserveThePointsOwnSuffixAndPrefix pins the per-point derivation: the NUL
// form keeps the point's own value as the allowed suffix, and a value with a directory keeps that
// directory as the expected prefix. Without a base value no derived form is produced.
func TestTraversalPayloadsPreserveThePointsOwnSuffixAndPrefix(t *testing.T) {
	has := func(list []string, want string) bool {
		for _, s := range list {
			if s == want {
				return true
			}
		}
		return false
	}
	got := TraversalPayloadsFor("docs/report.pdf")
	for _, want := range []string{
		"../../application.properties%00docs/report.pdf",
		"../../../../../../../../etc/passwd%00docs/report.pdf",
		"docs/../../../../../../../../etc/passwd",
	} {
		if !has(got, want) {
			t.Errorf("missing derived payload %q", want)
		}
	}
	if n, m := len(TraversalPayloadsFor("")), len(PathTraversalPayloads); n != m {
		t.Errorf("an empty base produced %d payloads, want the static %d", n, m)
	}
	if n, m := len(TraversalPayloadsFor("a%00b")), len(PathTraversalPayloads); n != m {
		t.Errorf("a base already carrying a NUL produced derived forms (%d vs %d)", n, m)
	}
}
