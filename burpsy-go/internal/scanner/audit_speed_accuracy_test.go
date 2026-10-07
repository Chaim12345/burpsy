package scanner

// Tests for the scan_speed and scan_accuracy axes (burpsy-react-ui-ev7y).
//
// Both keys were reported "not applied" on readings of Burp that were wrong about the mechanism:
// neither is run-level pacing. scan_speed is a per-check mutation-set selector (Zsv7.java:7-62,
// predicate speed >= required) and scan_accuracy is a mutation-token COUNT (Zs_2.java:8,
// Map.of(MINIMIZE_FALSE_NEGATIVES, 4, NORMAL, 8, MINIMIZE_FALSE_POSITIVES, 10)).
//
// The JSON in these tests is copied from Burp's own shipped presets rather than invented, so a
// change to how burpsy reads them fails here against the bytes an operator actually loads.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// The exact audit_optimization blocks Burp ships. Minimize false positives.json and
// Audit coverage - maximum.json differ on BOTH axes, which is what makes them the pair the bead
// names for the behavioural comparison.
const (
	burpMinimiseFalsePositives = `{"scanner": {"audit_optimization": {
		"consolidate_passive_issues": true, "follow_redirections": true, "maintain_session": true,
		"scan_accuracy": "minimise_false_positives", "scan_speed": "normal",
		"skip_ineffective_checks": true}}}`
	burpAuditCoverageMaximum = `{"scanner": {"audit_optimization": {
		"consolidate_passive_issues": false, "follow_redirections": true, "maintain_session": true,
		"scan_accuracy": "minimise_false_negatives", "scan_speed": "thorough",
		"skip_ineffective_checks": false}}}`
)

// CRITERION 5, and the only test here that asserts behaviour rather than configuration: the two
// shipped presets must produce DIFFERENT numbers of probe payloads. The config row moving out of
// the unapplied bucket proves nothing on its own — that is exactly the state this bead was filed
// against, where both presets loaded as silent no-ops.
func TestTheTwoShippedAccuracyPresetsSendDifferentNumbersOfPayloads(t *testing.T) {
	positives, err := ParseBurpConfig([]byte(burpMinimiseFalsePositives))
	if err != nil {
		t.Fatalf("Minimize false positives.json: %v", err)
	}
	maximum, err := ParseBurpConfig([]byte(burpAuditCoverageMaximum))
	if err != nil {
		t.Fatalf("Audit coverage - maximum.json: %v", err)
	}

	posCfg, _ := positives.ApplyWithReport(DefaultAuditConfig())
	maxCfg, _ := maximum.ApplyWithReport(DefaultAuditConfig())

	if !posCfg.ScanAccuracy.Set || !maxCfg.ScanAccuracy.Set {
		t.Fatal("a shipped preset's scan_accuracy did not reach the audit configuration at all")
	}

	// Twelve payloads is longer than every bound, so each run truncates to its own.
	payloads := make([]string, 12)
	for i := range payloads {
		payloads[i] = strings.Repeat("x", i+1)
	}
	posSent := (&ProbeHarness{accuracy: CheckAccuracy(posCfg.ScanAccuracy.Value).Attempts()}).boundPayloads(payloads)
	maxSent := (&ProbeHarness{accuracy: CheckAccuracy(maxCfg.ScanAccuracy.Value).Attempts()}).boundPayloads(payloads)

	if len(posSent) == len(maxSent) {
		t.Fatalf("both presets send %d payloads; the two shipped accuracy presets are still silent "+
			"no-ops, which is the defect this bead was filed for", len(posSent))
	}
	// Burp's own numbers, and the direction that surprises people: minimising FALSE POSITIVES
	// spends MORE attempts per candidate, because an attempt is a confirmation.
	if len(posSent) != 10 {
		t.Errorf("minimise_false_positives sent %d payloads, want 10 (Zs_2.java:8)", len(posSent))
	}
	if len(maxSent) != 4 {
		t.Errorf("minimise_false_negatives sent %d payloads, want 4 (Zs_2.java:8)", len(maxSent))
	}
}

// Both rows must leave the unapplied bucket — criterion 4.
func TestTheSpeedAndAccuracyRowsNoLongerReportThemselvesUnapplied(t *testing.T) {
	cfg, err := ParseBurpConfig([]byte(burpAuditCoverageMaximum))
	if err != nil {
		t.Fatalf("ParseBurpConfig: %v", err)
	}
	_, unapplied := cfg.ApplyWithReport(DefaultAuditConfig())
	for _, u := range unapplied {
		if strings.Contains(u, "scan_speed") || strings.Contains(u, "scan_accuracy") {
			t.Errorf("%q is still reported unapplied after the key was honoured", u)
		}
	}
}

// Burp's three speed spellings load by name — criterion 2. A preset exported from Burp carries the
// uiName, never a number, so a parser that only took integers would reject every real file.
func TestEveryBurpSpeedSpellingLoadsByName(t *testing.T) {
	for name, want := range map[string]CheckSpeed{
		"fast":     SpeedFast,
		"normal":   SpeedNormal,
		"thorough": SpeedThorough,
	} {
		cfg, err := ParseBurpConfig([]byte(`{"scanner": {"audit_optimization": {"scan_speed": "` + name + `"}}}`))
		if err != nil {
			t.Fatalf("scan_speed %q: %v", name, err)
		}
		if !cfg.ScanSpeed.Set || CheckSpeed(cfg.ScanSpeed.Value) != want {
			t.Errorf("scan_speed %q loaded as %v, want %v", name, cfg.ScanSpeed, want)
		}
	}
}

// And both accuracy spellings, British (what Burp ships) and American (what an operator may type)
// — criterion 3.
func TestEveryAccuracySpellingLoadsByNameIncludingTheBritishOne(t *testing.T) {
	for name, want := range map[string]CheckAccuracy{
		"minimise_false_negatives": AccuracyMinimiseFalseNegatives,
		"minimize_false_negatives": AccuracyMinimiseFalseNegatives,
		"normal":                   AccuracyNormal,
		"minimise_false_positives": AccuracyMinimiseFalsePositives,
		"minimize_false_positives": AccuracyMinimiseFalsePositives,
	} {
		cfg, err := ParseBurpConfig([]byte(`{"scanner": {"audit_optimization": {"scan_accuracy": "` + name + `"}}}`))
		if err != nil {
			t.Fatalf("scan_accuracy %q: %v", name, err)
		}
		if !cfg.ScanAccuracy.Set || CheckAccuracy(cfg.ScanAccuracy.Value) != want {
			t.Errorf("scan_accuracy %q loaded as %v, want %v", name, cfg.ScanAccuracy, want)
		}
	}
}

// A value this engine does not know must REFUSE the file rather than read as the default. A typo
// that silently narrowed a scan is the quiet wrong answer this package is written against.
func TestAnUnknownSpeedOrAccuracyRefusesTheFile(t *testing.T) {
	for _, body := range []string{
		`{"scanner": {"audit_optimization": {"scan_speed": "turbo"}}}`,
		`{"scanner": {"audit_optimization": {"scan_accuracy": "perfect"}}}`,
		`{"scanner": {"audit_optimization": {"scan_speed": 3}}}`,
	} {
		if _, err := ParseBurpConfig([]byte(body)); err == nil {
			t.Errorf("%s loaded without error; an unrecognised selector must be refused, not read "+
				"as the default", body)
		}
	}
}

// The speed predicate is Burp's: a run admits every check ranked at or below it — criterion 1.
func TestACheckRunsOnlyAtOrAboveItsOwnSpeedRank(t *testing.T) {
	for _, tc := range []struct {
		check, run CheckSpeed
		want       bool
	}{
		{SpeedFast, SpeedFast, true},
		{SpeedFast, SpeedNormal, true},
		{SpeedFast, SpeedThorough, true},
		{SpeedNormal, SpeedFast, false},
		{SpeedNormal, SpeedNormal, true},
		{SpeedNormal, SpeedThorough, true},
		{SpeedThorough, SpeedFast, false},
		{SpeedThorough, SpeedNormal, false},
		{SpeedThorough, SpeedThorough, true},
	} {
		if got := tc.check.RunsAt(tc.run); got != tc.want {
			t.Errorf("a %s check on a %s run: RunsAt = %v, want %v", tc.check, tc.run, got, tc.want)
		}
	}
}

// The zero value is every run, so a check added without a declared speed is never silently dropped
// — the same safe-by-default rule CheckInvasiveness follows.
func TestAnUndeclaredSpeedRunsEverywhere(t *testing.T) {
	var undeclared CheckSpeed
	for _, run := range []CheckSpeed{SpeedFast, SpeedNormal, SpeedThorough} {
		if !undeclared.RunsAt(run) {
			t.Errorf("a check with no declared speed was excluded from a %s run; an unranked check "+
				"must be admitted everywhere, or adding one silently narrows existing scans", run)
		}
	}
}

// An unset accuracy leaves a check's payload list exactly as written: every run that never named an
// accuracy must send what it sent before this key was honoured.
func TestAnUnsetAccuracyLeavesThePayloadListAlone(t *testing.T) {
	payloads := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"}
	got := (&ProbeHarness{}).boundPayloads(payloads)
	if len(got) != len(payloads) {
		t.Errorf("an unset accuracy truncated %d payloads to %d; a configuration that never named "+
			"accuracy must be unchanged", len(payloads), len(got))
	}
}

// Truncation keeps the ORDER, which is load-bearing: orderPayloads puts the payloads most likely to
// work first using what the guide learned, so taking the first N keeps that knowledge and sampling
// would throw it away.

// The run's accuracy must reach a harness built the way production builds one. Everything above
// exercises boundPayloads directly, which cannot see the wiring — and the wiring is exactly what was
// missing when this bead was closed the first time: the key reached the config and stopped there.
func TestARunsAccuracyReachesAHarnessBuiltTheWayProductionBuildsOne(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}, "/search?q=hello")
	cc.ScanAccuracy = SomeUint32(uint32(AccuracyMinimiseFalsePositives))

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	if h.accuracy != 10 {
		t.Errorf("the harness bounds payloads at %d with the run set to minimise_false_positives, "+
			"want 10; the configuration reached the run and not the probes, which is the exact "+
			"shape of this bead's original false close", h.accuracy)
	}

	// And the bound is the one the probes actually obey.
	long := make([]string, 25)
	for i := range long {
		long[i] = "p"
	}
	if got := len(h.boundPayloads(long)); got != 10 {
		t.Errorf("a 25-payload check sent %d payloads under minimise_false_positives, want 10", got)
	}
}

// A harness built for a run that named no accuracy keeps every payload — the behaviour every
// existing check had before this key was honoured.
func TestAHarnessForARunWithNoAccuracyIsUnbounded(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}, "/search?q=hello")

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	if h.accuracy != 0 {
		t.Errorf("a run that named no accuracy produced a bound of %d; an unnamed key must leave "+
			"every check's payload list alone", h.accuracy)
	}
}

// The dispatched path carries it too: a check run under a named configuration must probe to THAT
// configuration's accuracy, not the server-wide default's.
func TestADispatchedCheckSeesTheRunsAccuracyNotTheScannersDefault(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}, "/search?q=hello")

	runCfg := DefaultAuditConfig()
	runCfg.ScanAccuracy = SomeUint32(uint32(AccuracyMinimiseFalseNegatives))
	ctx := withRunConfig(context.Background(), runCfg)

	dispatched := newCheckContextForRun(ctx, cc.Scanner, cc.Exchange, nil)
	if !dispatched.ScanAccuracy.Set || CheckAccuracy(dispatched.ScanAccuracy.Value) != AccuracyMinimiseFalseNegatives {
		t.Errorf("a dispatched check sees accuracy %v, want the run's minimise_false_negatives; "+
			"without this a named configuration is a label on a run that ignored it",
			dispatched.ScanAccuracy)
	}
}

func TestTheAccuracyBoundKeepsTheMostPromisingPayloadsFirst(t *testing.T) {
	payloads := []string{"best", "second", "third", "fourth", "fifth", "sixth"}
	got := (&ProbeHarness{accuracy: 4}).boundPayloads(payloads)
	if len(got) != 4 {
		t.Fatalf("bound 4 produced %d payloads", len(got))
	}
	for i, want := range payloads[:4] {
		if got[i] != want {
			t.Errorf("payload %d is %q, want %q: the bound must truncate the ordered list, not "+
				"reorder or sample it", i, got[i], want)
		}
	}
}

// A list shorter than the bound is untouched — the bound is a ceiling, not a quota to fill.
func TestAShortPayloadListIsNotPaddedToTheAccuracyBound(t *testing.T) {
	got := (&ProbeHarness{accuracy: 10}).boundPayloads([]string{"a", "b"})
	if len(got) != 2 {
		t.Errorf("a 2-payload list under a bound of 10 became %d; the bound is a ceiling", len(got))
	}
}
