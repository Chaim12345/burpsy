package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

// burpsy-react-ui-02qi: the eight quick_scan_* keys now apply, and what they resolve to has to reach
// a console. A key that changes engine behaviour but leaves the wire silent is applied only in the
// sense that nothing contradicts it, and an operator watching a light audit has no way to tell which
// kinds it covers.
//
// The field is a DENY LIST and that has to be legible, because the opposite reading is a plausible
// mistake in the other direction: a consumer that treats the list as "these kinds get the light
// pass" would show a run with cookies excluded as covering nothing, and hide the light tier from a
// request whose whole body is cookies.

// The derived set reaches the wire, and it names what was taken OUT.
func TestTheLightAuditExclusionsReachTheWire(t *testing.T) {
	// Through the exported path a real caller has -- a preset applied over the default. The
	// derivation itself is unexported, which is correct (a console must not hand-build a set), and it
	// is also why this test cannot set the fields directly.
	cfg := scanner.BuiltInConfig{
		Name:                "no light audit for bodies or cookies",
		QuickScanBodyParams: scanner.SomeUint32(0),
		QuickScanCookies:    scanner.SomeUint32(0),
	}.Apply(scanner.DefaultAuditConfig())

	v := newAuditConfigView(cfg)
	if len(v.LightAuditKindsExcluded) != 2 {
		t.Fatalf("light_audit_kinds_excluded = %v, want the two kinds that were ticked off",
			v.LightAuditKindsExcluded)
	}
	want := map[string]bool{"body": false, "cookie": false}
	for _, kind := range v.LightAuditKindsExcluded {
		if _, ok := want[kind]; !ok {
			t.Errorf("excluded kind %q is not one of the two the keys removed", kind)
			continue
		}
		want[kind] = true
	}
	for kind, found := range want {
		if !found {
			t.Errorf("kind %q was taken out of the light pass and is not named on the wire; a console "+
				"reading this cannot show which kinds its light audit covers", kind)
		}
	}
}

// A run that excludes nothing says nothing on the wire, rather than naming every kind.
//
// The distinction matters because the field's zero value is ambiguous between "no kind is in the
// light pass" and "every kind is", and the wrong reading inverts the tier: a console that took the
// empty list as an allow-list would show an ordinary audit as covering no kinds at all.
func TestAnUnconfiguredLightAuditIsAbsentRatherThanEmptyButPresent(t *testing.T) {
	v := newAuditConfigView(scanner.DefaultAuditConfig())
	if v.LightAuditKindsExcluded != nil {
		t.Errorf("light_audit_kinds_excluded = %v for a configuration that excludes nothing; an empty "+
			"but present list reads as an allow-list of zero kinds, which is the opposite of the truth",
			v.LightAuditKindsExcluded)
	}
}

// The JSON key is the one a console reads, and the deny-list polarity survives the marshalling.
func TestTheExclusionsMarshalUnderTheNameAConsoleReads(t *testing.T) {
	cfg := scanner.BuiltInConfig{
		Name:                     "no light audit for path filenames",
		QuickScanURLPathFilename: scanner.SomeUint32(0),
	}.Apply(scanner.DefaultAuditConfig())

	raw, err := json.Marshal(newAuditConfigView(cfg))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{"light_audit_kinds_excluded", "url_path_filename"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the wire JSON is %s, want it to carry %q", raw, want)
		}
	}
}
