package web

// The user/project configuration split (burpsy-react-ui-wfiw).
//
// This bead was closed once describing configSectionLevel and a test named
// TestImportWithLevelDoesNotTouchTheOtherLevel, neither of which existed in any file. The tests
// below are the ones that make the claim checkable rather than asserted.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CRITERION 1's manifest rule: every section is declared at EXACTLY one level. A section at both
// would make ?level=user and ?level=project overlap, so an operator importing one after the other
// would silently get whichever ran last; a section at neither would vanish from both narrowed
// bundles while still appearing in the un-narrowed one. Both are failures here rather than
// judgements made at request time.
func TestEveryConfigSectionIsDeclaredAtExactlyOneLevel(t *testing.T) {
	for _, section := range allConfigSections() {
		levels := configLevelsOf(section)
		switch len(levels) {
		case 1:
		case 0:
			t.Errorf("section %q is declared at no level, so it is absent from both ?level=user and "+
				"?level=project while still appearing in the un-narrowed bundle — add it to "+
				"configSectionLevel", section)
		default:
			t.Errorf("section %q is declared at %d levels (%v); a section at two levels makes the "+
				"two halves overlap, and an operator importing both gets whichever ran last",
				section, len(levels), levels)
		}
	}
	// And the manifest declares nothing the bundle does not know, which is the other direction of
	// the same drift: a stale entry would report coverage for a section that no longer exists.
	known := map[string]bool{}
	for _, s := range allConfigSections() {
		known[s] = true
	}
	for section := range configSectionLevel {
		if !known[section] {
			t.Errorf("configSectionLevel declares %q, which is in neither the included nor the "+
				"omitted list; the manifest is describing a section the bundle does not have", section)
		}
	}
}

// CRITERION 2: coverage is reported PER LEVEL, so "project: 3 of 9" is a different claim from
// "4 of 15". A narrowed bundle that reported the flat coverage would overstate exactly the way the
// un-split bundle did.
func TestCoverageIsReportedPerLevel(t *testing.T) {
	flat := exportCoverage()
	project := exportCoverageAt(configLevelProject, true)
	user := exportCoverageAt(configLevelUser, true)

	if len(project.Included)+len(user.Included) != len(flat.Included) {
		t.Errorf("the two levels include %d + %d sections, but the flat bundle includes %d; every "+
			"included section must belong to exactly one level",
			len(project.Included), len(user.Included), len(flat.Included))
	}
	if len(project.Omitted)+len(user.Omitted) != len(flat.Omitted) {
		t.Errorf("the two levels omit %d + %d sections, but the flat bundle omits %d",
			len(project.Omitted), len(user.Omitted), len(flat.Omitted))
	}
	for _, s := range project.Included {
		if configSectionLevel[s] != configLevelProject {
			t.Errorf("project coverage claims %q, which is a %s section", s, configSectionLevel[s])
		}
	}
	for _, s := range user.Included {
		if configSectionLevel[s] != configLevelUser {
			t.Errorf("user coverage claims %q, which is a %s section", s, configSectionLevel[s])
		}
	}
	// The note names the level, because a bundle is most often read in an editor at the moment it
	// matters and "partial" alone does not say partial in which direction.
	if !strings.Contains(project.Note, "project") {
		t.Errorf("the project bundle's note does not say which level it carries: %q", project.Note)
	}
}

// A narrowed export carries ONLY its own level's sections. Asserted on the JSON actually written,
// because a section that is nil in Go and absent from the wire is the thing the importer reads as
// "do not touch this surface".
func TestANarrowedExportCarriesOnlyItsOwnLevelsSections(t *testing.T) {
	s := newTestServer()
	for _, tc := range []struct {
		level       string
		wantPresent []string
		wantAbsent  []string
	}{
		{
			level:       "project",
			wantPresent: []string{"scope", "session_rules"},
			wantAbsent:  []string{"intercept", "uninteresting_headers"},
		},
		{
			level:       "user",
			wantPresent: []string{"intercept", "uninteresting_headers"},
			wantAbsent:  []string{"scope", "session_rules"},
		},
	} {
		t.Run(tc.level, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.handleConfigExport(rec, httptest.NewRequest(http.MethodGet, "/api/config/export?level="+tc.level, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatalf("decoding the bundle: %v", err)
			}
			for _, key := range tc.wantPresent {
				if _, ok := raw[key]; !ok {
					t.Errorf("a %s-level bundle does not carry %q", tc.level, key)
				}
			}
			for _, key := range tc.wantAbsent {
				v, ok := raw[key]
				if !ok {
					continue
				}
				// session_rules deliberately carries no `omitempty` (see its field comment: an
				// absent key means "do not touch this surface", so a bundle that COVERS the section
				// must write it even when empty). A narrowed bundle therefore writes a null rather
				// than dropping the key, and null is what the importer already reads as untouched.
				// What must never appear is DATA from the other level.
				if string(v) != "null" {
					t.Errorf("a %s-level bundle carries %q = %s, which belongs to the other level; "+
						"handing this file to someone would overwrite settings they did not ask for",
						tc.level, key, string(v))
				}
			}
			// And the coverage block is where a reader learns the section is not covered at all,
			// which is the distinction a null on the wire cannot make on its own.
			var bundle struct {
				Coverage configCoverage `json:"coverage"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
				t.Fatalf("decoding coverage: %v", err)
			}
			for _, key := range tc.wantAbsent {
				for _, inc := range bundle.Coverage.Included {
					if inc == key {
						t.Errorf("a %s-level bundle's coverage claims to include %q, which is the "+
							"other level's", tc.level, key)
					}
				}
			}
		})
	}
}

// An un-narrowed export is unchanged — every existing caller sends no level and must get exactly
// the bundle it got before.
func TestAnExportWithNoLevelIsUnchanged(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.handleConfigExport(rec, httptest.NewRequest(http.MethodGet, "/api/config/export", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d", rec.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for _, key := range []string{"scope", "intercept", "session_rules", "uninteresting_headers"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("an un-narrowed bundle is missing %q; a caller that sends no level must get "+
				"the whole bundle it always got", key)
		}
	}
}

// CRITERION 3, and the test the false close claimed existed: importing one level leaves the other
// level's surfaces untouched.
func TestImportWithLevelDoesNotTouchTheOtherLevel(t *testing.T) {
	s := newTestServer()

	// A distinctive user-level setting to protect, and a project-level one the bundle will carry.
	s.uninteresting.set(false, []string{"x-keep-me"})

	bundle := `{
		"version": 1,
		"scope": {"rules": [{"Kind": "Include", "Host": "imported.test"}]},
		"uninteresting_headers": {"request": ["x-from-the-bundle"], "response": []}
	}`

	rec := httptest.NewRecorder()
	s.handleConfigImport(rec, httptest.NewRequest(http.MethodPost, "/api/config/import?level=project",
		strings.NewReader(bundle)))
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}

	// The project-level section WAS applied.
	var sawImported bool
	for _, rule := range s.scope.Rules() {
		if rule.Pattern == "imported.test" {
			sawImported = true
		}
	}
	if !sawImported {
		t.Error("a project-level import did not apply the bundle's scope; the level narrowed away " +
			"the section it was supposed to carry")
	}

	// The user-level section was NOT, even though the bundle carried it.
	got := s.uninteresting.headers(false)
	for _, h := range got {
		if strings.EqualFold(h, "x-from-the-bundle") {
			t.Errorf("a project-level import overwrote the user-level uninteresting headers (%v); "+
				"importing an engagement must not touch the operator's own preferences", got)
		}
	}
	var keptMine bool
	for _, h := range got {
		if strings.EqualFold(h, "x-keep-me") {
			keptMine = true
		}
	}
	if !keptMine {
		t.Errorf("the operator's own header list was lost by a project-level import: %v", got)
	}
}

// An unrecognised level is REFUSED rather than read as "both". A typo that silently exported the
// whole bundle would have an operator hand a colleague a file believing it carried no personal
// settings.
func TestAnUnknownLevelIsRefusedOnBothRoutes(t *testing.T) {
	s := newTestServer()

	rec := httptest.NewRecorder()
	s.handleConfigExport(rec, httptest.NewRequest(http.MethodGet, "/api/config/export?level=everything", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("export with an unknown level answered %d, want 400; reading it as \"both\" would "+
			"export settings the operator asked to leave out", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleConfigImport(rec, httptest.NewRequest(http.MethodPost, "/api/config/import?level=everything",
		strings.NewReader(`{"version": 1}`)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("import with an unknown level answered %d, want 400", rec.Code)
	}
}

// The mirror of TestImportWithLevelDoesNotTouchTheOtherLevel, and the half that was missing: a
// USER-level import must leave the engagement's scope alone. Without this, a test that only ever
// imports at project level passes just as happily against an import that ignores the level for
// scope entirely.
func TestAUserLevelImportDoesNotTouchTheProjectsScope(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("engagement.test")

	bundle := `{
		"version": 1,
		"scope": {"rules": [{"Kind": "Include", "Host": "from-the-bundle.test"}]},
		"uninteresting_headers": {"request": ["x-from-the-bundle"], "response": []}
	}`
	rec := httptest.NewRecorder()
	s.handleConfigImport(rec, httptest.NewRequest(http.MethodPost, "/api/config/import?level=user",
		strings.NewReader(bundle)))
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}

	// The user-level section WAS applied.
	var sawHeader bool
	for _, h := range s.uninteresting.headers(false) {
		if strings.EqualFold(h, "x-from-the-bundle") {
			sawHeader = true
		}
	}
	if !sawHeader {
		t.Error("a user-level import did not apply the bundle's uninteresting headers")
	}

	// The engagement's scope was NOT, even though the bundle carried a scope section.
	var kept, imported bool
	for _, rule := range s.scope.Rules() {
		switch rule.Pattern {
		case "engagement.test":
			kept = true
		case "from-the-bundle.test":
			imported = true
		}
	}
	if imported {
		t.Error("a user-level import replaced the engagement's scope; restoring your own " +
			"preferences on a new machine must not import someone else's scope")
	}
	if !kept {
		t.Error("a user-level import cleared the engagement's scope")
	}
}

// A section nobody declared must be excluded from every narrowed bundle rather than riding along.
// The manifest test above makes an undeclared section a failure, but the FILTER must be safe in the
// meantime: a surface added without a manifest entry must not silently appear in a bundle the
// operator believes is one half.
func TestAnUndeclaredSectionIsExcludedFromEveryNarrowedBundle(t *testing.T) {
	for _, level := range []configLevel{configLevelUser, configLevelProject} {
		if sectionInLevel("a_section_nobody_declared", level, true) {
			t.Errorf("an undeclared section is admitted to a %s-level bundle; a surface added "+
				"without a manifest entry would ride along in a bundle the operator believes "+
				"carries one half", level)
		}
	}
	// And an un-narrowed bundle still carries everything, declared or not — that is the path every
	// existing caller takes.
	if !sectionInLevel("a_section_nobody_declared", "", false) {
		t.Error("an un-narrowed bundle dropped a section; a caller that sends no level must get " +
			"the whole bundle")
	}
}
