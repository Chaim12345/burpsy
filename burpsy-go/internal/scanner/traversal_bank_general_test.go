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

// TestTraversalBankHasEncodedBackslashAndOverlongForms pins the 0vzb.4 remainder: an encoded
// backslash climb for a Windows filter that contains-checks a literal `..\` but decodes %5c, and
// overlong UTF-8 forms for a filter that validates the string before an overlong-tolerant decoder
// turns %c0%af back into a separator (the Tomcat/IIS CVE-2000-0884 class).
func TestTraversalBankHasEncodedBackslashAndOverlongForms(t *testing.T) {
	has := func(want string) bool {
		for _, s := range PathTraversalPayloads {
			if s == want {
				return true
			}
		}
		return false
	}
	for _, want := range []string{
		// Encoded backslash, same Windows target as the literal climb.
		`..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cboot.ini`,
		// Mixed encoded separators: a filter matching only one literal form.
		`..%5c..%2f..%5c..%2fetc%2fpasswd`,
		// Overlong UTF-8: slash only, and dots+slash.
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		"%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
		// Overlong backslash for the Windows case.
		`..%c1%9c..%c1%9cwindows%c1%9cwin.ini`,
	} {
		if !has(want) {
			t.Errorf("missing 0vzb.4 bank entry %q", want)
		}
	}
}
