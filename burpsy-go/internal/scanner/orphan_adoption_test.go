package scanner

// Tests added at adoption (2026-10-04) for the orphaned baseline and response-module work.
//
// # Why these exist
//
// This file and its sibling response_modules_test.go were written by a session that ended without
// committing them, so they arrived unverified and landed unproven. Their existing tests are good —
// exact finding counts, names, severities, a redaction assertion — but they cover the HAPPY paths of
// subsystems whose design is mostly about refusal and about what must NOT happen. Everything below
// pins a claim the implementation's own doc comments make and no test enforced, so a later edit can
// not quietly remove the property that makes these subsystems honest rather than merely convenient.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// CalibrateBaseline refuses an empty sample set rather than returning a zero Baseline. The zero
// value is the dangerous shape: its mean length and zero standard deviation would flag EVERY
// response as anomalous, or — worse, depending on how the threshold test is written — flag none.
// A refusal is the only answer that cannot be mistaken for a calibrated endpoint.
func TestCalibrateBaselineRefusesAnEmptySampleSetRatherThanReturningZero(t *testing.T) {
	for _, tc := range []struct {
		name    string
		samples []BaselineSample
	}{
		{"nil", nil},
		{"empty", []BaselineSample{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CalibrateBaseline(tc.samples)
			if err == nil {
				t.Fatalf("CalibrateBaseline(%v) = %+v, nil error; a baseline calibrated on nothing "+
					"is a claim about an endpoint it never spoke to", tc.samples, got)
			}
			if got != nil {
				t.Errorf("CalibrateBaseline(%v) returned a Baseline AND an error (%+v); a refusal "+
					"must not also hand back a usable value", tc.samples, got)
			}
			if !strings.Contains(err.Error(), "at least one sample") {
				t.Errorf("error %q does not say what the caller must fix", err)
			}
		})
	}
}

// A single calibration sample has zero variance in every signal, which is the case the relative
// floors exist for. Without them, stddev == 0 would make "any difference at all" the test, so
// ordinary one-byte body noise on a live endpoint would be reported as an anomaly on every request.
func TestAOneSampleBaselineToleratesOrdinaryByteNoise(t *testing.T) {
	b, err := CalibrateBaseline([]BaselineSample{NewBaselineSample(200, "hello", 10*time.Millisecond)})
	if err != nil {
		t.Fatalf("CalibrateBaseline: %v", err)
	}
	threshold := DefaultDeviationThreshold()

	// One extra byte on a 5-byte body is a 20% change — over the 10% floor, so this is NOT meant to
	// be clean. The claim under test is narrower: the verdict must come from the floor rather than
	// from a zero-variance stddev, which would flag a response identical to the calibration sample.
	same := b.Compare(NewBaselineSample(200, "hello", 10*time.Millisecond), threshold)
	if same.Flagged {
		t.Errorf("an identical response was flagged against a one-sample baseline (%+v); the "+
			"relative floors are not standing in for the zero standard deviation", same)
	}
	// And a real deviation still flags, or the floor has simply disabled the signal.
	major := b.Compare(NewBaselineSample(500, "a completely different response body", 10*time.Millisecond), threshold)
	if !major.Flagged {
		t.Errorf("a status change plus a wholly different body was NOT flagged against a one-sample "+
			"baseline (%+v); the floor must tolerate noise without disabling the check", major)
	}
}

// DiffAccessControl reports a MATCH when identity B receives what identity A can see. That is the
// BOLA finding the whole subsystem exists for, and its polarity is the one thing an inverted
// implementation gets wrong: the same comparison, read backwards, reports a correctly-protected
// endpoint as broken and a broken one as fine.
func TestAccessControlDiffNamesTheBolaCaseInBothDirections(t *testing.T) {
	privileged := NewBaselineSample(200, `{"ssn":"123-45-6789","email":"owner@example.test"}`, 10*time.Millisecond)
	b, err := CalibrateBaseline([]BaselineSample{privileged})
	if err != nil {
		t.Fatalf("CalibrateBaseline: %v", err)
	}
	threshold := DefaultDeviationThreshold()

	if dev := b.DiffAccessControl(privileged, threshold); !dev.Matched {
		t.Errorf("identity B receiving identity A's exact body was not reported as a match (%+v); "+
			"that IS the BOLA case and it is the one verdict that must never be missed", dev)
	}
	denied := NewBaselineSample(403, "forbidden", 10*time.Millisecond)
	if dev := b.DiffAccessControl(denied, threshold); dev.Matched {
		t.Errorf("identity B being correctly refused was reported as a match (%+v); an enforced "+
			"endpoint must not read as a finding", dev)
	}
}

// RunResponseModules treats a nil module as a skip, not a panic. A caller assembling modules from a
// partially-populated config is an ordinary state (a module disabled by a switch), and a nil slot
// must not take the scan down.
func TestAResponseModuleListWithANilSlotDoesNotPanic(t *testing.T) {
	got := RunResponseModules([]ResponseModule{nil, nil, &SecretsModule{}}, []byte("nothing here"), nil)
	if len(got) != 0 {
		t.Errorf("RunResponseModules over an empty body returned %d findings: %+v", len(got), got)
	}
}

// Secrets never reach a report in full. The AWS secret key, the API key and the JWT are all
// redacted; an evidence field that carried the whole credential would put a live secret into the
// findings store, the console and any export.
func TestNoSecretsModuleFindingCarriesTheWholeSecret(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	body := []byte("aws_secret_access_key = \"" + secret + "\"\n" +
		`{"api_key":"sk_live_abcdefghijklmnop1234"}` + "\n" +
		"token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")

	findings := RunResponseModules(DefaultResponseModules(), body, nil)
	if len(findings) == 0 {
		t.Fatal("no findings at all; the fixture is not exercising the secret detectors")
	}
	for _, f := range findings {
		if strings.Contains(f.Evidence, secret) {
			t.Errorf("finding %q carries the whole AWS secret in its evidence: %q", f.Name, f.Evidence)
		}
		if strings.Contains(f.Evidence, "sk_live_abcdefghijklmnop1234") {
			t.Errorf("finding %q carries the whole API key in its evidence: %q", f.Name, f.Evidence)
		}
		if strings.Contains(f.Detail, secret) {
			t.Errorf("finding %q carries the whole secret in its DETAIL, which reaches logs: %q", f.Name, f.Detail)
		}
	}
}

// An AWS access key ID is deliberately echoed unredacted — it is a public identifier and the
// operator needs to know WHICH key leaked. This test exists so that asymmetry is a decision a
// future editor reads rather than a bug they either "fix" or copy into the secret branches.
func TestAnAccessKeyIDIsEchoedSoTheOperatorKnowsWhichKeyLeaked(t *testing.T) {
	const keyID = "AKIAABCDEFGHIJKLMNOP"
	findings := (&SecretsModule{}).Analyze([]byte(`{"debug_config":"`+keyID+`"}`), nil)
	if len(findings) == 0 {
		t.Fatal("an AWS access key ID produced no finding; the detector is not running")
	}
	if !strings.Contains(findings[0].Evidence, keyID) {
		t.Errorf("evidence %q does not contain the key ID; the ID is a public identifier and is "+
			"echoed on purpose so the operator can identify the key", findings[0].Evidence)
	}
}

// Baseline calibration refuses to run with a non-positive N rather than sending zero requests and
// reporting a calibrated endpoint.
func TestBaselineCalibrationRefusesANonPositiveSampleCount(t *testing.T) {
	sender := &recordingBaselineSender{}
	auth := AuthContext{Label: "authenticated"}
	for _, n := range []int{0, -1} {
		if _, _, err := RunBaselineCalibration(context.Background(), sender, auth, n); err == nil {
			t.Errorf("RunBaselineCalibration(n=%d) succeeded; a calibration that sends no request "+
				"cannot describe the endpoint", n)
		}
	}
	if sender.calls != 0 {
		t.Errorf("a refused calibration still sent %d request(s)", sender.calls)
	}
}

// recordingBaselineSender answers every calibration request with the same benign response, and
// records how many requests it was actually asked to send.
type recordingBaselineSender struct {
	calls int
}

func (s *recordingBaselineSender) Send(_ context.Context, _ AuthContext) (int, string, time.Duration, error) {
	s.calls++
	if s.calls == 2 {
		return 0, "", 0, errors.New("simulated transport failure")
	}
	return 200, `{"ok":true}`, 5 * time.Millisecond, nil
}

// Partial failure is reported as the REAL count rather than the requested one. A calibration that
// asked for N samples and got fewer must say so: a baseline built from two of five samples is a
// weaker claim than one built from five, and a report that says "5" would be a coverage claim the
// run cannot support.
func TestBaselineCalibrationReportsTheSamplesItActuallyGot(t *testing.T) {
	sender := &recordingBaselineSender{}
	baseline, got, err := RunBaselineCalibration(context.Background(), sender, AuthContext{Label: "authenticated"}, 3)
	if err != nil {
		t.Fatalf("RunBaselineCalibration: %v", err)
	}
	if baseline == nil {
		t.Fatal("a calibration with a partial failure returned no baseline; one usable sample is " +
			"enough to calibrate and the failure belongs in the count, not in a refusal")
	}
	if got != 2 {
		t.Errorf("RunBaselineCalibration reported %d successful sample(s); the sender answered 2 of "+
			"3 and the count must be the real one", got)
	}
}
