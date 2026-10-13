package scanner

import (
	"strings"
	"testing"
)

// The two techniques of burpsy-react-ui-0vzb.33, against the vulnapp fixtures in
// internal/vulnapp/vulnapp_fileref.go: each vulnerable endpoint must be reported, and each safe twin
// - each one built to defeat exactly one of the evidence rule's guards - must not.

func TestPathEquivalenceReportsARawPathConfinedToItsDirectory(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/fr/documents?name=report.txt", false)
	f := got["File path manipulation"]
	if f == nil {
		t.Fatalf("File path manipulation not reported on /fr/documents; rows: %s", joinRows(got))
	}
	if f.Confidence != "tentative" {
		t.Errorf("confidence = %q, want tentative: the evidence shows a raw path, not an escape", f.Confidence)
	}
	if !strings.Contains(f.Description+f.Evidence, "./report.txt") {
		t.Errorf("finding does not name the equivalent spelling it rests on: %+v", f)
	}
}

func TestPathEquivalenceStaysQuietOnLookupsThatAreNotPaths(t *testing.T) {
	rt := startRuntimeTarget(t)
	for _, path := range []string{
		"/fr/safe/documents?name=report.txt", // guard: "./V" must equal V
		"/fr/safe/basename?name=report.txt",  // guard: "<missing>/V" must differ
		"/fr/safe/search?q=report.txt",       // guard: ".V" must differ
	} {
		t.Run(path, func(t *testing.T) {
			if f := rt.findingsFor(t, path, false)["File path manipulation"]; f != nil {
				t.Fatalf("reported on %s: %q / %q", path, f.Evidence, f.Description)
			}
		})
	}
}

func TestPathEquivalenceCandidates(t *testing.T) {
	for v, want := range map[string]bool{
		"report.txt":        true,
		"docs/report.txt":   true,
		"profile.json":      true,
		"seed":              false, // no extension: not a file name
		"42":                false,
		"../report.txt":     false,
		"/etc/passwd":       false, // absolute: the file-content technique's case
		"a b.txt":           false,
		"report.txt?x=1":    false,
		"http://h/x.json":   false,
		"report.toolongext": false,
	} {
		if got := pathEquivalenceCandidate(v); got != want {
			t.Errorf("pathEquivalenceCandidate(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestXXEParameterEntityReportsAParserWithOnlyGeneralEntitiesOff(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/fr/xml/import", false)
	f := got["XML external entity injection"]
	if f == nil {
		t.Fatalf("XXE not reported on /fr/xml/import; rows: %s", joinRows(got))
	}
	if !strings.Contains(f.Evidence, "parameter entity") {
		t.Errorf("reported by another technique than the parameter-entity one: %q", f.Evidence)
	}
	if got := rt.findingsFor(t, "/fr/safe/xml/import", false)["XML external entity injection"]; got != nil {
		t.Fatalf("reported on the safe twin: %q / %q", got.Evidence, got.Description)
	}
}

func TestXXEParameterEntityDocumentKeepsTheBaseShape(t *testing.T) {
	doc := xxeParameterEntityDocument("<book><title>seed</title><isbn>1</isbn></book>", "http://127.0.0.1:1/x.dtd", "bsyxpeq")
	for _, want := range []string{`<!DOCTYPE book [`, `<!ENTITY % bsydtd SYSTEM "http://127.0.0.1:1/x.dtd"> %bsydtd;`,
		`<book><title>&bsyxpeq;</title><isbn>1</isbn></book>`} {
		if !strings.Contains(doc, want) {
			t.Errorf("document %q lacks %q", doc, want)
		}
	}
	if strings.Contains(xxeDTDBody("e", "m"), "SYSTEM") {
		t.Error("the served DTD must declare a literal entity only")
	}
}
