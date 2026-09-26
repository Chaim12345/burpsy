package scanner

import (
	"strings"
	"testing"
)

// burpsy-react-ui-86le: the config-key table reported skip_all_tests_for_parameters as
// `applies: false` — "not applied" — while the engine HONOURED the control, under a Go-API field
// name the key table could not see. The table is the operator-facing settings surface, so a row
// saying "not applied" tells an operator their skip list is unsupported while it silently works.
//
// This is the honest-counting defect class the project treats as worse than a missing feature: a
// settings page that denies a capability the engine has.

// The row must not claim the control is unsupported, and must name what IS missing.
func TestTheSkipListKeyIsNotReportedAsUnsupported(t *testing.T) {
	var row *struct {
		name string
		what string
	}
	_ = row
	for _, k := range BuiltInConfigKeys() {
		if k.Name != "skip_all_tests_for_parameters" {
			continue
		}
		if strings.HasPrefix(k.What, "not applied: ") {
			t.Errorf("the row still says the control is not applied (%q) while the engine honours it "+
				"through AuditConfig.SkipAllTestsForParameters", k.What)
		}
		if !strings.HasPrefix(k.What, "partly applied: ") {
			t.Errorf("the row is not marked partly applied: %q; an operator reading it cannot tell what "+
				"works from what does not", k.What)
		}
		// The honest part must still be said: Burp's VALUE is a list of match rules, and this
		// engine has no matcher for it. A row that only said "applied" would be claiming support for
		// a value shape that cannot be read, which is the mirror-image lie.
		if !strings.Contains(k.What, "match_type") {
			t.Errorf("the row does not say what is missing: %q; a rule matching by expression or item "+
				"arrives here as a name that matches nothing, and the operator has to be told", k.What)
		}
		if !k.Partial {
			t.Error("Partial is false on the row; a consumer filtering on Partial to find the " +
				"reduced-support controls will not find this one")
		}
		return
	}
	t.Fatal("no row for skip_all_tests_for_parameters at all; the key is absent from the disclosure " +
		"rather than misdescribed, which is the same defect wearing a different hat")
}

// A preset whose SOURCE FILE named a partial key must not have that key reported as unapplied.
//
// The unapplied list is built from two sources: the rows whose read is nil, and whatever the
// parser could not deliver. A row that names a partial key and then falls through to the generic
// "read == nil" arm lands in the list and the operator is told the control is unsupported — which
// is the pre-fix defect reached by a different route, and which the first partial test could not
// catch because that preset set no keys at all.
func TestAPartialKeyStaysOutOfTheUnappliedListEvenWhenAPresetNamesIt(t *testing.T) {
	preset := BuiltInConfig{
		Name:                "a shipped configuration that names the skip list",
		UnrepresentableKeys: []string{"skip_all_tests_for_parameters"},
	}
	_, unapplied := preset.ApplyWithReport(AuditConfig{})
	for _, name := range unapplied {
		if name == "skip_all_tests_for_parameters" {
			t.Errorf("a preset naming the skip list got it reported as unapplied (%v); the control IS "+
				"honoured, through a different value shape, and a console reading this list would say "+
				"otherwise", unapplied)
		}
	}
}

// And the row's own name and the name a preset would use are the same string, so the check above is
// testing the key the operator sees rather than a near-miss spelling.
func TestThePartialRowAndTheUnappliedListShareOneSpelling(t *testing.T) {
	for _, k := range BuiltInConfigKeys() {
		if !k.Partial {
			continue
		}
		preset := BuiltInConfig{Name: "naming it", UnrepresentableKeys: []string{k.Name}}
		_, unapplied := preset.ApplyWithReport(AuditConfig{})
		for _, got := range unapplied {
			if got == k.Name {
				t.Errorf("%q is both a partial row and a member of the unapplied list, so the two "+
					"answers are true at once", k.Name)
			}
		}
		return
	}
	t.Fatal("no partial row exists, so nothing can be said about the three-state contract")
}

// The unapplied list is what a console shows as "not supported". A partial key must not be in it.
func TestAPartialKeyIsNotInTheUnappliedList(t *testing.T) {
	preset := BuiltInConfig{
		Name: "with a skip list",
		// The key is honoured through a list-valued path, so a preset cannot carry it in
		// BuiltInConfig's scalar fields — the operator sets it on the RUN. This is why the row is
		// partial rather than applied: the preset loader cannot deliver the value, only the runtime
		// configuration can.
	}
	base, unapplied := preset.ApplyWithReport(AuditConfig{})
	for _, name := range unapplied {
		if name == "skip_all_tests_for_parameters" {
			t.Errorf("the skip-list key is in the unapplied list (%v); that list is what an operator "+
				"reads as \"this control is unsupported\"", unapplied)
		}
	}
	_ = base
}

// And the engine really does honour it, which is the half that was true all along and is what
// makes the row's claim a lie rather than a stale note.
func TestTheControlTheRowUsedToDenyIsHonouredByTheEngine(t *testing.T) {
	opts := AuditConfig{SkipAllTestsForParameters: []string{"user"}}.enumerateOptions()
	if len(opts.SkipAllTestsForParameters) != 1 || opts.SkipAllTestsForParameters[0] != "user" {
		t.Fatalf("enumerateOptions carried %v; the row claims the control is not applied, and if that "+
			"became true the settings page would be right and this would be a different bug",
			opts.SkipAllTestsForParameters)
	}
}

// The row and the engine must not be able to drift apart again. This asserts the specific control
// the row names is the one the enumerator consults — a rename that left the row pointing at a
// field nothing reads would restore the exact defect.
func TestTheRowsPartialKeyIsTheFieldTheEnumeratorConsults(t *testing.T) {
	// The name in the row is the Go-API spelling; the field it names must exist and reach the
	// enumerator, or the row is describing a control that is not there.
	cfg := AuditConfig{SkipAllTestsForParameters: []string{"token"}}
	opts := cfg.enumerateOptions()
	if opts.SkipAllTestsForParameters[0] != "token" {
		t.Error("the field the row names does not reach the enumerator's options")
	}
	// And it must be reported on the wire, because the console reads the row and needs the third
	// state to exist there at all.
	var sawPartial bool
	for _, k := range BuiltInConfigKeys() {
		if k.Partial {
			sawPartial = true
		}
	}
	if !sawPartial {
		t.Error("no row reports Partial, so the wire cannot express the third state and a console " +
			"reading it sees the same two answers as before")
	}
}
