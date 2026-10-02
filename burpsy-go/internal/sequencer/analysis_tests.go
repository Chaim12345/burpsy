package sequencer

// The named-test vocabulary shared by the two batteries (burpsy-react-ui-nm81).
//
// # Why one table
//
// Burp's panel switches nine tests across two batteries — four FIPS (Zsiz.java:180-183) and four
// extended (184-186) plus the descriptive count (178). A per-battery switch list would let the two
// disagree, and the disagreement would be invisible: an operator who turned "spectral" off in one
// place and not the other gets a report that ran it either way.
//
// So every test both batteries know is named here, ONCE, with the Burp key it corresponds to. A test
// a caller cannot name cannot be switched off by accident, and adding a test is one line rather than
// a decision about which of two lists it belongs in.
//
// # The names are the tests' own IDs
//
// FipsTest.ID ("monobit", "poker", "runs", "long_runs") and AdvancedTest.ID ("transition",
// "spectral", "correlation", "compression") are already on the wire. Burp's keys are carried beside
// them rather than replacing them: the ID is what a report names, the Burp key is what a migrated
// configuration says, and a report reader who has never seen a Burp configuration still reads an ID
// it can act on.

import (
	"sort"
	"strings"
)

// AnalysisTest names one statistical test an operator can switch off.
type AnalysisTest struct {
	// ID is the test's own identifier as it appears in a report.
	ID string
	// Name is its human name, so a settings surface does not have to render an id.
	Name string
	// BurpKey is the configuration key Burp spells this test with (Zsiz.java:178-186), for an
	// imported configuration to land on the right switch.
	BurpKey string
	// Battery is "fips" or "extended" — the two reports the test appears in, which is what makes it
	// knowable: a test nobody can place is a test nobody can display a switch for.
	Battery string
}

// The batteries, named as the report they appear in.
const (
	BatteryFips     = "fips"
	BatteryExtended = "extended"
)

// AnalysisTests is every test this build knows how to switch, sorted by ID.
//
// Sorted because it is rendered as a list of switches and read as a configuration surface: a list
// that reordered itself between two visits makes an operator hunt for a control they had just used.
var AnalysisTests = sortedAnalysisTests([]AnalysisTest{
	{ID: "monobit", Name: "Monobit Test", BurpKey: "fips_monobit", Battery: BatteryFips},
	{ID: "poker", Name: "Poker Test", BurpKey: "fips_poker", Battery: BatteryFips},
	{ID: "runs", Name: "Runs Test", BurpKey: "fips_runs", Battery: BatteryFips},
	{ID: "long_runs", Name: "Long Runs Test", BurpKey: "fips_long_run", Battery: BatteryFips},
	{ID: "transition", Name: "Character transition analysis", BurpKey: "transitions", Battery: BatteryExtended},
	{ID: "spectral", Name: "Spectral test", BurpKey: "spectral", Battery: BatteryExtended},
	{ID: "correlation", Name: "Correlation test", BurpKey: "correlation", Battery: BatteryExtended},
	{ID: "compression", Name: "Compression test", BurpKey: "compression", Battery: BatteryExtended},
})

// sortedAnalysisTests returns the table in ID order.
func sortedAnalysisTests(in []AnalysisTest) []AnalysisTest {
	out := make([]AnalysisTest, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// KnownAnalysisTest reports whether an id names a test this build can switch off.
func KnownAnalysisTest(id string) bool {
	for _, t := range AnalysisTests {
		if t.ID == id {
			return true
		}
	}
	return false
}

// AnalysisTestByBurpKey resolves a Burp configuration key to this build's id for it.
//
// Empty for a key this build has no switch for, which is the answer for the descriptive count
// (sequencer.token_analysis.count) and for any key a future Burp adds: the caller's switch is left
// where it is and the key is reported unrepresentable, rather than guessed at.
func AnalysisTestByBurpKey(key string) (string, bool) {
	for _, t := range AnalysisTests {
		if t.BurpKey == key {
			return t.ID, true
		}
	}
	return "", false
}

// firstDisableList collapses a variadic switch argument to the one list that matters.
//
// Variadic rather than a plain parameter so that a caller with no switch to apply — which is most of
// them, and every caller that predates the feature — keeps calling with the signature it had. A
// signature change would ripple through the tree for a feature most call sites do not use, and a
// required argument a call site cannot supply is a compile error rather than a default.
//
// Several lists are UNIONED rather than the first winning, because a variadic that silently dropped
// all but its first argument would be a way to lose a setting without an error.
func firstDisableList(lists [][]string) []string {
	if len(lists) == 0 {
		return nil
	}
	if len(lists) == 1 {
		return lists[0]
	}
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// DisabledSet turns a disable list into a lookup, ignoring ids this build does not know.
//
// Ignoring rather than refusing: the list comes from a stored configuration that a different burpsy
// build may have written, and a stale id must not fail an analysis outright. What it must not do is
// silently disable something the operator did not name, which is why only ids in AnalysisTests are
// ever honoured.
func DisabledSet(disabled []string) map[string]bool {
	out := make(map[string]bool, len(disabled))
	for _, id := range disabled {
		if id = strings.TrimSpace(id); id != "" && KnownAnalysisTest(id) {
			out[id] = true
		}
	}
	return out
}
