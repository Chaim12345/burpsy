package scanner

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// burpsy-react-ui-saq3.1: Burp's per-issue selection, read the way Burp reads it.
//
// testdata/burp-configs holds the 29 configuration files Burp Suite 2026.7.1 (build 51467) ships in
// resources/BuiltInConfigs, byte-for-byte, so these tests run against Burp's own files rather than
// against a fixture written to agree with the parser.

const shippedConfigDir = "testdata/burp-configs"

// readShippedConfig loads one shipped file by its Burp name.
func readShippedConfig(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(shippedConfigDir, name+".json"))
	if err != nil {
		t.Fatalf("reading shipped configuration %q: %v", name, err)
	}
	return data
}

// The five issue types "all except time-based detection methods" switches off, and the four whose
// "Time delays" method it switches off. Five and four, not two and seven: the file has nine entries,
// and the five disabled ones are the interpreted-language code-injection types Burp detects only by
// timing (none of them defines a detection method in Zcot).
var (
	timeBasedDisabledTypes = []uint32{
		0x00100f10, // Python code injection
		0x00100f00, // Ruby code injection
		0x00100e00, // Perl code injection
		0x00100d00, // Server-side JavaScript code injection
		0x00101000, // Unidentified code injection
	}
	timeBasedTimeDelaysOff = []uint32{
		0x00100210, // SQL injection (second order)
		0x00100100, // OS command injection
		0x00100200, // SQL injection
		0x00100c00, // PHP code injection
	}
)

// everyFamilyScanner turns every family switch on and loads one active corpus check, so the only
// thing that can narrow its check set is the configuration under test — and a BCheck exists for
// "BChecks only" to select.
func everyFamilyScanner(t *testing.T) *ActiveScanner {
	t.Helper()
	cfg := &ScanConfig{
		MaxConcurrency: 1, Timeout: 5 * time.Second,
		CheckSqli: true, CheckXss: true, CheckPathTraversal: true, CheckSSRF: true,
		CheckXXE: true, CheckJwtWeak: true, CheckJSVulns: true, CheckCachePoisoning: true,
		CheckPassiveAnalysis: true, CheckPassivePosture: true, CheckHeaders: true,
		CheckHostDiscovery: true, CheckExtendedCoverage: true, CheckReflectionProbes: true,
		CheckResponseDependence: true, CheckActiveInjection: true, CheckDOM: true,
		CheckExtendedActive: true, CheckOutOfBand: true, CheckStored: true,
	}
	check, err := bcheck.Parse("metadata:\n  language: v2-beta\n  name: \"selection corpus check\"\n" +
		"given query insertion point then\n  send payload:\n    appending: \"VULN\"\n" +
		"  if \"VULN\" in {latest.response.body} then\n    report issue:\n      severity: high\n" +
		"      confidence: certain\n      detail: \"reflected\"\n  end if\n")
	if err != nil {
		t.Fatalf("corpus check: %v", err)
	}
	return NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithConfig(cfg).
		WithCorpusChecks([]*bcheck.Check{check})
}

// typesOf is the set of catalogue types a dispatched check set covers.
func typesOf(checks []activeCheck) map[uint32]int {
	out := map[uint32]int{}
	for _, c := range checks {
		out[c.typeIndex]++
	}
	return out
}

// Every key a shipped file names must come back applied or unapplied, never neither and never both.
// This is the defect saq3.1 is: a parsed selected_issues landed in neither list.
func TestEveryShippedConfigurationAccountsForEveryScannerKeyItNames(t *testing.T) {
	entries, err := os.ReadDir(shippedConfigDir)
	if err != nil {
		t.Fatalf("reading %s: %v", shippedConfigDir, err)
	}
	if len(entries) != BurpShippedConfigCount {
		t.Fatalf("%d shipped files in %s, want %d", len(entries), shippedConfigDir, BurpShippedConfigCount)
	}
	rowName := map[string]string{}
	for _, k := range builtInConfigKeys {
		rowName[strings.TrimPrefix(k.burpKey, "scanner/")] = k.name
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(shippedConfigDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseBurpConfig(data)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		_, rep := parsed.applyWithAccounting(DefaultAuditConfig())
		applied, unapplied := map[string]int{}, map[string]int{}
		for _, k := range rep.Applied {
			applied[k]++
		}
		for _, k := range rep.Unapplied {
			unapplied[k]++
		}
		for _, key := range parsed.ParsedKeys {
			name, ok := rowName[key]
			if !ok {
				name = key
			}
			a, u := applied[name], unapplied[name]
			switch {
			case a == 0 && u == 0:
				t.Errorf("%s: %s was parsed and is in neither the applied nor the unapplied answer", e.Name(), key)
			case a+u > 1:
				t.Errorf("%s: %s is accounted %d time(s) applied and %d unapplied; exactly one answer is true",
					e.Name(), key, a, u)
			}
		}
	}
}

// Each shipped selection configuration, imported, must do what its name says. One row per file that
// carries issues_reported; the claim is checked against the check set a real scanner dispatches.
func TestEveryShippedSelectionConfigurationBehavesAsItsNameSays(t *testing.T) {
	scan := everyFamilyScanner(t)
	full := typesOf(scan.enabledChecksUnder(AuditConfig{}))
	if full[BCheckGeneratedTypeIndex] < 2 {
		t.Fatalf("the full set carries %d check(s) of the BCheck type, want the corpus check AND the "+
			"provenance row; without the corpus check the BChecks-only row has nothing to prove", full[BCheckGeneratedTypeIndex])
	}

	cases := []struct {
		file  string
		check func(t *testing.T, cfg AuditConfig, got map[uint32]int)
	}{
		{"Audit checks - all except time-based detection methods", func(t *testing.T, cfg AuditConfig, got map[uint32]int) {
			if len(cfg.IssueTypes) != 0 {
				t.Fatalf("IssueTypes = %v: the list is per-issue overrides here (no scan_only_selected_issues), "+
					"and reading it as a whitelist narrows a full audit to nine checks", cfg.IssueTypes)
			}
			for _, ty := range timeBasedDisabledTypes {
				if got[ty] != 0 {
					t.Errorf("type %#08x is enabled:false in the file and is still dispatched", ty)
				}
			}
			// Everything else the full set carries still runs — that is what "all except" means.
			for ty, n := range full {
				if slices.Contains(timeBasedDisabledTypes, ty) {
					continue
				}
				if got[ty] != n {
					t.Errorf("type %#08x: %d check(s) dispatched, want the full set's %d", ty, got[ty], n)
				}
			}
			var off []uint32
			for _, m := range cfg.DisabledDetectionMethods {
				if m.Method != MethodTimeDelays {
					t.Errorf("method %q of %#08x is recorded disabled; the file disables only Time delays", m.Method, m.TypeIndex)
				}
				off = append(off, m.TypeIndex)
			}
			slices.Sort(off)
			want := slices.Clone(timeBasedTimeDelaysOff)
			slices.Sort(want)
			if !slices.Equal(off, want) {
				t.Errorf("Time delays disabled for %x, want %x", off, want)
			}
		}},
		{"Audit checks - critical issues only", func(t *testing.T, cfg AuditConfig, got map[uint32]int) {
			want := []uint32{0x00100210, 0x00100f10, 0x00100c00, 0x00100d00, 0x00100e00, 0x00100f00,
				0x00101000, 0x00101200, 0x00100100, 0x00100200, 0x00100f20, 0x00400900, 0x00200140}
			for ty := range got {
				if !slices.Contains(want, ty) {
					t.Errorf("type %#08x is dispatched; the file whitelists thirteen types and this is not one", ty)
				}
			}
			for _, ty := range want {
				if full[ty] > 0 && got[ty] != full[ty] {
					t.Errorf("whitelisted type %#08x: %d check(s) dispatched, want %d", ty, got[ty], full[ty])
				}
			}
		}},
		{"Audit checks - BChecks only", func(t *testing.T, cfg AuditConfig, got map[uint32]int) {
			if len(got) != 1 || got[BCheckGeneratedTypeIndex] != full[BCheckGeneratedTypeIndex] {
				t.Errorf("dispatched types = %v, want only the BCheck type with all %d of its checks — "+
					"the loaded corpus check included", got, full[BCheckGeneratedTypeIndex])
			}
		}},
		{"Audit checks - extensions only", func(t *testing.T, cfg AuditConfig, got map[uint32]int) {
			// burpsy has no extension mechanism, so the only check of this type is the provenance row
			// that labels extension-filed findings; it sends nothing. Nothing that probes runs.
			if len(got) != 1 || got[ExtensionGeneratedTypeIndex] != 1 {
				t.Errorf("dispatched types = %v, want only the extension provenance row", got)
			}
		}},
		{"Audit checks - light active", func(t *testing.T, cfg AuditConfig, got map[uint32]int) {
			scanTypeMode(t, cfg)
			if cfg.MediumActiveChecks.Value != 0 || cfg.IntrusiveActiveChecks.Value != 0 || cfg.LightActiveChecks.Value != 1 {
				t.Errorf("tiers = light %+v medium %+v intrusive %+v, want light only",
					cfg.LightActiveChecks, cfg.MediumActiveChecks, cfg.IntrusiveActiveChecks)
			}
		}},
		{"Audit checks - medium active", func(t *testing.T, cfg AuditConfig, got map[uint32]int) {
			scanTypeMode(t, cfg)
			if cfg.MediumActiveChecks.Value != 1 || cfg.IntrusiveActiveChecks.Value != 0 {
				t.Errorf("tiers = medium %+v intrusive %+v, want medium on and intrusive off",
					cfg.MediumActiveChecks, cfg.IntrusiveActiveChecks)
			}
		}},
		{"Audit checks - passive", func(t *testing.T, cfg AuditConfig, got map[uint32]int) {
			scanTypeMode(t, cfg)
			for _, c := range scan.enabledChecksUnder(cfg) {
				if !c.passive {
					t.Errorf("%s is active and dispatched under the passive-only configuration", c.name)
				}
			}
		}},
		{"Audit checks - all except JavaScript analysis", func(t *testing.T, cfg AuditConfig, got map[uint32]int) {
			scanTypeMode(t, cfg)
			if !cfg.JavaScriptAnalysis.Set || cfg.JavaScriptAnalysis.Value != 0 {
				t.Errorf("javascript analysis = %+v, want set off", cfg.JavaScriptAnalysis)
			}
			if got[0x00200310] != 0 {
				t.Error("DOM-based XSS is dispatched under the configuration that turns JavaScript analysis off")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			cfg, unapplied, err := ApplyBurpConfigFile(DefaultAuditConfig(), readShippedConfig(t, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			for _, k := range unapplied {
				if strings.Contains(k, "issue") {
					t.Errorf("%s is reported unapplied; every selection key in Burp's own file is honoured", k)
				}
			}
			tc.check(t, cfg, typesOf(scan.enabledChecksUnder(cfg)))
		})
	}
}

// scanTypeMode asserts a scan-type configuration carries no per-issue selection.
func scanTypeMode(t *testing.T, cfg AuditConfig) {
	t.Helper()
	if len(cfg.IssueTypes)+len(cfg.DisabledIssueTypes)+len(cfg.DisabledDetectionMethods) != 0 {
		t.Errorf("a scan-type configuration carries a per-issue selection: types %v, disabled %v, methods %v",
			cfg.IssueTypes, cfg.DisabledIssueTypes, cfg.DisabledDetectionMethods)
	}
}

// Without scan_only_selected_issues an unlisted type still runs; with it, it does not
// (Zwnn.java:13-25). The same list, two flags, two opposite readings of an absent type.
func TestScanOnlySelectedIssuesIsWhatMakesTheListAWhitelist(t *testing.T) {
	scan := everyFamilyScanner(t)
	const sqli, xss = uint32(0x00100200), uint32(0x00200300)
	file := func(scanOnly string) []byte {
		return []byte(`{"scanner":{"issues_reported":{"select_individual_issues":true,` + scanOnly +
			`"selected_issues":[{"type_index":"0x00100200","enabled":true,"detection_methods":[]}]}}}`)
	}
	overrides, _, err := ApplyBurpConfigFile(DefaultAuditConfig(), file(""))
	if err != nil {
		t.Fatal(err)
	}
	if got := typesOf(scan.enabledChecksUnder(overrides)); got[xss] == 0 || got[sqli] == 0 {
		t.Errorf("overrides mode dispatched sqli=%d xss=%d; an unlisted type must still run", got[sqli], got[xss])
	}
	whitelist, _, err := ApplyBurpConfigFile(DefaultAuditConfig(), file(`"scan_only_selected_issues":true,`))
	if err != nil {
		t.Fatal(err)
	}
	if got := typesOf(scan.enabledChecksUnder(whitelist)); got[xss] != 0 || got[sqli] == 0 {
		t.Errorf("whitelist mode dispatched sqli=%d xss=%d; only the listed type may run", got[sqli], got[xss])
	}
	// A whitelist whose only entry is disabled admits nothing — not "no restriction", which is what an
	// empty IssueTypes would have said.
	none := []byte(`{"scanner":{"issues_reported":{"scan_only_selected_issues":true,` +
		`"selected_issues":[{"type_index":"0x00100200","enabled":false,"detection_methods":[]}]}}}`)
	nothing, _, err := ApplyBurpConfigFile(DefaultAuditConfig(), none)
	if err != nil {
		t.Fatal(err)
	}
	if got := scan.enabledChecksUnder(nothing); len(got) != 0 {
		t.Errorf("a whitelist of one disabled type dispatched %d check(s); it selects nothing", len(got))
	}
}

// In scan-type mode Burp never consults the list (Zmzw.java:86). A non-empty list there did nothing,
// so it is reported; an empty one asks for nothing and is honoured.
func TestAListOutsidePerIssueModeIsReportedNotSilentlyIgnored(t *testing.T) {
	scan := everyFamilyScanner(t)
	data := []byte(`{"scanner":{"issues_reported":{"select_individual_issues":false,` +
		`"selected_issues":[{"type_index":"0x00100200","enabled":false,"detection_methods":[]}]}}}`)
	cfg, unapplied, err := ApplyBurpConfigFile(DefaultAuditConfig(), data)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(unapplied, "selected_issues") {
		t.Errorf("unapplied = %v; a list Burp ignores in scan-type mode must be reported", unapplied)
	}
	if typesOf(scan.enabledChecksUnder(cfg))[0x00100200] == 0 {
		t.Error("SQL injection was removed by a list Burp does not consult in scan-type mode")
	}
}

// Selection mode does not consult the scan-type flags, so a tier a selection-mode file turns off
// does not narrow the run (Zmzw.java:86).
func TestPerIssueModeDoesNotConsultTheScanTypeFlags(t *testing.T) {
	data := []byte(`{"scanner":{"issues_reported":{"select_individual_issues":true,` +
		`"scan_type_passive":false,"scan_type_intrusive_active":false,"selected_issues":[]}}}`)
	cfg, _, err := ApplyBurpConfigFile(DefaultAuditConfig(), data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PassiveChecks.Set || cfg.IntrusiveActiveChecks.Set {
		t.Errorf("passive %+v intrusive %+v survive in per-issue mode; Burp does not read them there",
			cfg.PassiveChecks, cfg.IntrusiveActiveChecks)
	}
}

// Loading replaces state (Zx9y.java:186-191): a base configuration's selection does not leak into a
// file that speaks about selection.
func TestImportingASelectionReplacesTheBaseSelection(t *testing.T) {
	base := DefaultAuditConfig()
	base.IssueTypes = []uint32{0x00200300}
	base.DisabledIssueTypes = []uint32{0x00100100}
	cfg, _, err := ApplyBurpConfigFile(base, readShippedConfig(t, "Audit checks - all except time-based detection methods"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IssueTypes) != 0 || slices.Contains(cfg.DisabledIssueTypes, 0x00100100) {
		t.Errorf("the base selection survived the import: types %v disabled %v", cfg.IssueTypes, cfg.DisabledIssueTypes)
	}
}

// A method name Burp does not define for the type, and a type the catalogue does not hold, are
// recorded with a reason rather than dropped.
func TestASelectionNamingWhatBurpDoesNotDefineIsDeclinedWithAReason(t *testing.T) {
	data := []byte(`{"scanner":{"issues_reported":{"select_individual_issues":true,"selected_issues":[` +
		`{"type_index":"0x00100200","enabled":true,"detection_methods":[{"name":"Back-end socket poisoning","enabled":false}]},` +
		`{"type_index":"0x7fffffff","enabled":false,"detection_methods":[]}]}}}`)
	cfg, _, err := ApplyBurpConfigFile(DefaultAuditConfig(), data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DisabledDetectionMethods) != 0 {
		t.Errorf("a method SQL injection does not define was recorded disabled: %v", cfg.DisabledDetectionMethods)
	}
	var reasons []string
	for _, d := range cfg.DeclinedDetectionMethods {
		reasons = append(reasons, d.Reason)
	}
	sort.Strings(reasons)
	if len(reasons) != 2 || !strings.Contains(strings.Join(reasons, "|"), "Zwx_.Zm") ||
		!strings.Contains(strings.Join(reasons, "|"), "catalogue") {
		t.Errorf("declines = %v, want one per undefined method and unknown type, each with its reason", reasons)
	}
}

// A malformed entry fails the file by name rather than selecting or dropping an issue nobody chose.
func TestAMalformedSelectedIssueFailsTheFile(t *testing.T) {
	for _, bad := range []string{
		`[{"type_index":"0x00100200","detection_methods":[]}]`,
		`[{"type_index":"sqli","enabled":true,"detection_methods":[]}]`,
		`[{"type_index":"0x00100200","enabled":true,"detection_methods":[{"name":"Time delays"}]}]`,
		`{"0x00100200":true}`,
	} {
		_, err := ParseBurpConfig([]byte(`{"scanner":{"issues_reported":{"selected_issues":` + bad + `}}}`))
		if err == nil {
			t.Errorf("%s parsed; a malformed selection must fail the file", bad)
		}
	}
}

// The ignored_insertion_points lists carry Burp's match-rule objects. An empty list is honoured; a
// non-empty one is reported, never read as names.
func TestAFileSkipListIsHonouredWhenEmptyAndReportedWhenItCarriesRules(t *testing.T) {
	cfg, err := ParseBurpConfig(readShippedConfig(t, "Audit coverage - maximum"))
	if err != nil {
		t.Fatal(err)
	}
	_, rep := cfg.applyWithAccounting(DefaultAuditConfig())
	if !slices.Contains(rep.Applied, "skip_all_tests_for_parameters") {
		t.Errorf("applied = %v; Burp's own empty skip list must be honoured", rep.Applied)
	}
	rules := []byte(`{"scanner":{"ignored_insertion_points":{"skip_all_tests_for_parameters":` +
		`[{"enabled":true,"parameter":"csrf","item":"name","match_type":"matches_regex","expression":"csrf.*"}]}}}`)
	ruled, err := ParseBurpConfig(rules)
	if err != nil {
		t.Fatal(err)
	}
	applied, rep := ruled.applyWithAccounting(DefaultAuditConfig())
	if !slices.Contains(rep.Unapplied, "skip_all_tests_for_parameters") {
		t.Errorf("unapplied = %v; a rule list this engine cannot match must be reported", rep.Unapplied)
	}
	if len(applied.SkipAllTestsForParameters) != 0 {
		t.Errorf("a rule object was read as parameter names: %v", applied.SkipAllTestsForParameters)
	}
}

// An unknown scanner key is reported as the file spelled it, not only recorded.
func TestAnUnknownScannerKeyReachesTheReport(t *testing.T) {
	_, unapplied, err := ApplyBurpConfigFile(DefaultAuditConfig(),
		[]byte(`{"scanner":{"issues_reported":{"made_up_key":true},"made_up_section":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"issues_reported/made_up_key", "made_up_section"} {
		if !slices.Contains(unapplied, want) {
			t.Errorf("unapplied = %v, want %q", unapplied, want)
		}
	}
}

// Every field-backed row must be reachable from a parsed file. Nine were not — the row had a reader,
// the parser had no field mapping, and a loaded value was validated and then dropped.
func TestEveryFieldBackedRowIsReachableFromAParsedFile(t *testing.T) {
	for _, k := range builtInConfigKeys {
		if k.read == nil {
			continue
		}
		var c BuiltInConfig
		setBurpConfigField(&c, k.name, SomeUint32(1))
		if !k.read(c).Set {
			t.Errorf("%s: the parser has no field for this row, so a file setting it parses and does nothing", k.name)
		}
	}
}

// The honoured-configuration count the CLI prints is derived from Burp's own files, not remembered.
func TestTheHonouredShippedConfigurationCountIsDerivedFromBurpsOwnFiles(t *testing.T) {
	entries, err := os.ReadDir(shippedConfigDir)
	if err != nil {
		t.Fatal(err)
	}
	honoured := 0
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(shippedConfigDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := ParseBurpConfig(data)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if _, rep := cfg.applyWithAccounting(DefaultAuditConfig()); len(rep.Applied) > 0 {
			honoured++
		}
	}
	if honoured != BurpShippedConfigsSettingAnHonouredKey {
		t.Errorf("%d shipped configurations apply at least one key; BurpShippedConfigsSettingAnHonouredKey says %d",
			honoured, BurpShippedConfigsSettingAnHonouredKey)
	}
}
