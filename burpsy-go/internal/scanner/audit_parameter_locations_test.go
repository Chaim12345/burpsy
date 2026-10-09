package scanner

import (
	"slices"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"strings"
)

// The six `scanner/modifying_parameter_locations/*` keys, as Burp's configuration JSON spells them,
// against the point class each must add. The expected value is taken from the enumerator's own
// exported kind constant rather than a string typed here, so a renamed kind fails this test instead
// of silently deselecting the probes the operator asked for.
//
// The defect this guards: a key named `body_to_url` that produced query-to-body probes would send a
// request the operator never described, under their own configuration's name.
func Test_each_relocation_key_adds_exactly_its_own_point_class(t *testing.T) {
	cases := []struct {
		burpKey string
		set     func(c *BuiltInConfig)
		want    string
	}{
		{"body_to_url", func(c *BuiltInConfig) { c.RelocateBodyToURL = SomeUint32(1) }, string(bcheck.IpRelocateBodyToQuery)},
		{"body_to_cookie", func(c *BuiltInConfig) { c.RelocateBodyToCookie = SomeUint32(1) }, string(bcheck.IpRelocateBodyToCookie)},
		{"url_to_body", func(c *BuiltInConfig) { c.RelocateURLToBody = SomeUint32(1) }, string(bcheck.IpRelocateQueryToBody)},
		{"url_to_cookie", func(c *BuiltInConfig) { c.RelocateURLToCookie = SomeUint32(1) }, string(bcheck.IpRelocateQueryToCookie)},
		{"cookie_to_body", func(c *BuiltInConfig) { c.RelocateCookieToBody = SomeUint32(1) }, string(bcheck.IpRelocateCookieToBody)},
		{"cookie_to_url", func(c *BuiltInConfig) { c.RelocateCookieToURL = SomeUint32(1) }, string(bcheck.IpRelocateCookieToQuery)},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		var c BuiltInConfig
		tc.set(&c)
		applied := c.Apply(DefaultAuditConfig())
		if !slices.Contains(applied.InsertionKinds, tc.want) {
			t.Errorf("%s: point classes = %v, want them to include %q — the key names one relocation and must select that one",
				tc.burpKey, applied.InsertionKinds, tc.want)
		}
		// A relocation is an addition to the run's points, never a replacement: a preset that names
		// only a relocation key would otherwise probe one exotic location and nothing else.
		for _, k := range DefaultProbeInsertionKinds {
			if !slices.Contains(applied.InsertionKinds, k) {
				t.Errorf("%s dropped the engine's default %q point; the relocation must be added on top of it, not instead of it",
					tc.burpKey, k)
			}
		}
		if seen[tc.want] {
			t.Errorf("two relocation keys select %q, so one of them is misnamed", tc.want)
		}
		seen[tc.want] = true
	}
	if len(seen) != len(cases) {
		t.Errorf("%d relocation key(s) select %d distinct point class(es); each key has its own",
			len(cases), len(seen))
	}
}

// Zero removes the relocation instead of adding it: the same key is how an operator turns one off.
func Test_a_relocation_key_set_to_zero_removes_that_point_class(t *testing.T) {
	both := BuiltInConfig{RelocateBodyToURL: SomeUint32(1), RelocateCookieToBody: SomeUint32(1)}
	applied := both.Apply(DefaultAuditConfig())
	if !slices.Contains(applied.InsertionKinds, string(bcheck.IpRelocateCookieToBody)) {
		t.Fatalf("setup: point classes = %v, want the cookie relocation present", applied.InsertionKinds)
	}

	both.RelocateCookieToBody = SomeUint32(0)
	applied = both.Apply(DefaultAuditConfig())
	if slices.Contains(applied.InsertionKinds, string(bcheck.IpRelocateCookieToBody)) {
		t.Errorf("point classes = %v, want the cookie relocation gone after its key was set to 0", applied.InsertionKinds)
	}
	if !slices.Contains(applied.InsertionKinds, string(bcheck.IpRelocateBodyToQuery)) {
		t.Errorf("point classes = %v, want the other relocation still selected", applied.InsertionKinds)
	}
}

// The two point-selection sections compose: a preset that names insertion_point_types *and* a
// relocation gets both, rather than the second section silently replacing the first's materialised
// set (or being overwritten by it).
func Test_insertion_types_and_relocations_compose(t *testing.T) {
	c := BuiltInConfig{
		InsertURLParams:       SomeUint32(1),
		InsertCookies:         SomeUint32(0),
		InsertBodyParams:      SomeUint32(0),
		InsertEntireBody:      SomeUint32(0),
		InsertHTTPHeaders:     SomeUint32(0),
		InsertParamName:       SomeUint32(0),
		InsertURLPathFilename: SomeUint32(0),
		InsertURLPathFolders:  SomeUint32(0),
		RelocateURLToCookie:   SomeUint32(1),
	}
	applied := c.Apply(DefaultAuditConfig())
	if !slices.Equal(applied.InsertionKinds, []string{"query", "relocate_query_to_cookie"}) {
		t.Errorf("point classes = %v, want [query relocate_query_to_cookie]: the explicit selection decides the standard classes and the relocation is added to them",
			applied.InsertionKinds)
	}
}

// Every relocation key this engine honours must also be reported by Keys() as applying, so a chooser
// cannot show a key as inert while the overlay acts on it.
func Test_relocation_keys_report_that_they_apply(t *testing.T) {
	var c BuiltInConfig
	c.RelocateBodyToURL = SomeUint32(1)
	c.RelocateBodyToCookie = SomeUint32(1)
	c.RelocateURLToBody = SomeUint32(1)
	c.RelocateURLToCookie = SomeUint32(1)
	c.RelocateCookieToBody = SomeUint32(1)
	c.RelocateCookieToURL = SomeUint32(1)

	relocationRows := 0
	for _, k := range c.Keys() {
		if !slices.Contains([]string{
			"modifying_parameter_locations/body_to_url",
			"modifying_parameter_locations/body_to_cookie",
			"modifying_parameter_locations/url_to_body",
			"modifying_parameter_locations/url_to_cookie",
			"modifying_parameter_locations/cookie_to_body",
			"modifying_parameter_locations/cookie_to_url",
		}, "modifying_parameter_locations/"+lastPathSegment(k.BurpKey)) {
			continue
		}
		relocationRows++
		if !k.Set {
			t.Errorf("%s reports unset although this config sets its field", k.Name)
		}
		if !k.Applies {
			t.Errorf("%s reports Applies false although the overlay acts on it", k.Name)
		}
		if k.What == "" {
			t.Errorf("%s carries no description, so a chooser cannot say what it changes", k.Name)
		}
	}
	if relocationRows != 6 {
		t.Errorf("found %d relocation row(s) in the listing, want all 6", relocationRows)
	}
}

// The keys must survive the route an operator actually takes — loading one of Burp's own
// configuration files. A parsed relocation that landed in UnrepresentableKeys would be reported as
// inert while the JSON plainly names it.
func Test_a_parsed_burp_config_can_select_a_relocation(t *testing.T) {
	data := []byte(`{"scanner": {"modifying_parameter_locations": {"body_to_url": true, "cookie_to_body": true}}}`)
	cfg, err := ParseBurpConfig(data)
	if err != nil {
		t.Fatalf("ParseBurpConfig: %v", err)
	}
	applied, unapplied := cfg.ApplyWithReport(DefaultAuditConfig())
	if len(unapplied) != 0 {
		t.Errorf("unapplied = %v, want none: both keys have a field to land in now", unapplied)
	}
	for _, want := range []string{string(bcheck.IpRelocateBodyToQuery), string(bcheck.IpRelocateCookieToBody)} {
		if !slices.Contains(applied.InsertionKinds, want) {
			t.Errorf("point classes = %v, want %q selected by the parsed config", applied.InsertionKinds, want)
		}
	}
}

// A loaded file's unapplied keys must reach the report an operator reads, not just the field they
// were recorded in. The parser records a key under its section-qualified name while the listing
// looks rows up by their bare name, and a mismatch between the two spellings drops the key from the
// report silently — leaving a configuration that says "scan only these issues" looking fully
// honoured.
func Test_a_parsed_unapplied_key_reaches_the_report(t *testing.T) {
	// The KEY here was scan_only_selected_issues when this test was written, because the per-issue
	// selection keys were the obvious example of a key the parser records and the report drops. They
	// are HONOURED now (burpsy-react-ui-kvmx), so the example can no longer show the hazard this test
	// exists for. What it is actually about is the SPELLING: the parser records a key under its
	// section-qualified name (`issues_reported/selected_issues`) while the listing looks rows up by
	// their bare name, and a mismatch between the two drops the key from the report silently.
	//
	// So it now finds its own example rather than pinning one: whatever key this engine genuinely
	// cannot express, a file naming it must have that key reported. If none is reported the parser's
	// record and the listing's lookup have drifted apart, which is the failure, and the test says so
	// without needing to know which key it is.
	// Under javascript_analysis, which is the section that key actually lives in: a fixture that
	// puts it in issues_reported parses to a document that names no known key at all, and the test
	// would then be asserting on a file that was never a Burp configuration.
	// request_missing_dependencies, not use_static_analysis: the latter is applied since
	// burpsy-react-ui-9mti, and a test of the unapplied path needs a key the engine still cannot express.
	data := []byte(`{"scanner": {"javascript_analysis": {"request_missing_dependencies": true}}}`)
	cfg, err := ParseBurpConfig(data)
	if err != nil {
		t.Fatalf("ParseBurpConfig: %v", err)
	}
	_, unapplied := cfg.ApplyWithReport(DefaultAuditConfig())

	// A key this engine reports as unapplied must appear under EITHER spelling: the section-qualified
	// name the parser writes, or the bare row name a caller may set by hand. Matching only one of them
	// is the silent drop this test was written for.
	// The suffix test rather than a hard-coded pair of spellings: the parser may record the key under
	// its section (`javascript_analysis/...`) and the listing looks it up by its bare name, so a
	// suffix match accepts either without this test having to know which section the key lives in —
	// and a key MOVING sections cannot make it pass for the wrong reason.
	reported := false
	for _, name := range unapplied {
		if strings.HasSuffix(name, "javascript_request_missing_dependencies") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("unapplied = %v, want javascript_request_missing_dependencies under its bare or section-qualified "+
			"name; the operator has to be told which of their file's keys did nothing, and a key the engine "+
			"does not express is exactly such a key", unapplied)
	}

	// And a key this engine DOES honour must not appear at all, under either spelling — the mirror
	// of the same hazard, and the one burpsy-react-ui-86le and kvmx are about.
	honoured := []byte(`{"scanner": {"issues_reported": {"selected_issues": []}}}`)
	hcfg, err := ParseBurpConfig(honoured)
	if err != nil {
		t.Fatalf("ParseBurpConfig: %v", err)
	}
	_, honUnapplied := hcfg.ApplyWithReport(DefaultAuditConfig())
	for _, name := range honUnapplied {
		if strings.HasSuffix(name, "selected_issues") {
			t.Errorf("selected_issues is reported unapplied (%v); the control is honoured as a partial, and "+
				"saying otherwise is a false statement in a table an operator reads", honUnapplied)
		}
	}
}

// lastPathSegment returns the final component of a Burp key path.
func lastPathSegment(key string) string {
	if i := len(key) - 1; i > 0 {
		for j := i; j >= 0; j-- {
			if key[j] == '/' {
				return key[j+1:]
			}
		}
	}
	return key
}
