package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// ---- the export bundle must state its own coverage, truthfully ---------------------------
//
// BURP_PARITY_GAP_ANALYSIS.md §2.2: `Export configuration` downloaded a file carrying scope,
// intercept and session rules and silently dropped every other configuration surface. The menu
// said nothing, the file recorded nothing, and the import result counted only the three
// sections it knew about. The audit called it the finding an operator would actually be burned
// by — not because anything misbehaves, but because the mistake is discovered later, during
// work, on another machine.
//
// These tests bind the manifest to the serialisation. A manifest that can drift from what the
// bundle actually writes would be a second, more confident version of the same lie.

func exportForCoverage(t *testing.T) (map[string]json.RawMessage, configBundle) {
	t.Helper()
	ts := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/config/export", nil)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/export = %d: %s", rec.Code, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("bundle is not an object: %v", err)
	}
	var typed configBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &typed); err != nil {
		t.Fatalf("bundle does not decode: %v", err)
	}
	return raw, typed
}

// The binding that matters: every data section the bundle actually emits must be declared
// included. This is what stops the manifest drifting from the serialisation.
func TestEverySectionTheBundleWritesIsDeclaredIncluded(t *testing.T) {
	raw, _ := exportForCoverage(t)

	// Structural keys are not configuration sections.
	structural := map[string]bool{"version": true, "coverage": true}

	for key := range raw {
		if structural[key] {
			continue
		}
		if !slices.Contains(configIncludedSections, key) {
			t.Errorf("the bundle writes section %q but configIncludedSections does not list it. "+
				"A bundle that carries a section it does not declare is the same class of "+
				"misreport as one that omits a section silently.", key)
		}
	}
}

// And the converse: a section declared included must actually be emitted, or the manifest
// promises something the file does not contain — which is worse than the original silence,
// because now there is a written claim to rely on.
func TestEveryDeclaredIncludedSectionIsActuallyWritten(t *testing.T) {
	raw, _ := exportForCoverage(t)
	for _, section := range configIncludedSections {
		if _, present := raw[section]; !present {
			t.Errorf("configIncludedSections declares %q but the exported bundle has no such key. "+
				"Note this can also fire because the field carries `omitempty` and the surface is "+
				"empty on a fresh server — if so the fix is to emit the key regardless, since "+
				"\"exported and empty\" and \"not exported\" are different facts.", section)
		}
	}
}

// The two lists must be disjoint. A section in both would let a reader conclude either thing
// depending on which list they checked first.
func TestIncludedAndOmittedDoNotOverlap(t *testing.T) {
	for _, in := range configIncludedSections {
		if slices.Contains(configOmittedSections, in) {
			t.Errorf("%q is declared both included and omitted", in)
		}
	}
	if len(configIncludedSections) == 0 {
		t.Error("configIncludedSections is empty; the bundle would declare it carries nothing")
	}
}

// Partial must be derived from the omitted list rather than declared, so it cannot claim
// completeness while sections are missing. This is the field a programmatic reader branches on.
func TestPartialIsDerivedAndTrueWhileAnythingIsOmitted(t *testing.T) {
	_, typed := exportForCoverage(t)
	if typed.Coverage == nil {
		t.Fatal("the bundle carries no coverage manifest")
	}
	if len(configOmittedSections) > 0 && !typed.Coverage.Partial {
		t.Errorf("coverage.partial is false while %d sections are omitted: %v",
			len(configOmittedSections), configOmittedSections)
	}
	if len(configOmittedSections) == 0 && typed.Coverage.Partial {
		t.Error("coverage.partial is true with nothing omitted")
	}
	if !strings.Contains(typed.Coverage.Note, "omitted") {
		t.Errorf("the note does not tell a human reader what omitted means: %q", typed.Coverage.Note)
	}
}

// Import must ignore the manifest. A bundle's account of itself is evidence about the file, not
// an instruction — and honouring it would let a hand-edited coverage block change what import
// does to the live configuration.
func TestImportIgnoresTheCoverageManifest(t *testing.T) {
	ts := newTestServer()
	// A bundle claiming to be complete, carrying one scope rule and nothing else.
	body := `{"version":1,
	          "coverage":{"partial":false,"included":["scope","proxy_options"],"omitted":[]},
	          "scope":{"rules":[{"Kind":"Include","Host":"example.test"}]}}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body.String())
	}
	// The scope rule landed; the false claim about proxy_options changed nothing and did not
	// cause the import to report having applied it.
	if got := len(ts.scope.Rules()); got != 1 {
		t.Errorf("scope has %d rules after import, want 1", got)
	}
	if strings.Contains(rec.Body.String(), "proxy_options") {
		t.Errorf("the import result echoes a section it cannot apply: %s", rec.Body.String())
	}
}

// A round trip must survive the new field. An older bundle with no coverage block must still
// import, and must not be treated as a bundle claiming to carry everything.
func TestABundleWithoutCoverageStillImports(t *testing.T) {
	ts := newTestServer()
	body := `{"version":1,"scope":{"rules":[{"Kind":"Exclude","Host":"blocked.test"}]}}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import of a pre-manifest bundle = %d: %s", rec.Code, rec.Body.String())
	}
	if got := len(ts.scope.Rules()); got != 1 {
		t.Errorf("scope has %d rules, want 1", got)
	}
}
