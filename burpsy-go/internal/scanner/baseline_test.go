package scanner

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// CalibrateBaseline
// ---------------------------------------------------------------------------

// TestCalibrateBaselineRefusesEmptySampleSet asserts the honest-counting guard: no calibration
// data must be a refusal, never a zero-value Baseline that would silently accept everything.
func TestCalibrateBaselineRefusesEmptySampleSet(t *testing.T) {
	got, err := CalibrateBaseline(nil)
	if err == nil {
		t.Fatalf("CalibrateBaseline(nil) = %+v, nil error; want an error", got)
	}
	if got != nil {
		t.Fatalf("CalibrateBaseline(nil) returned a non-nil Baseline alongside an error: %+v", got)
	}
}

// TestCalibrateBaselineRecordsModalStatusAvgLengthAndDuration asserts that calibration over
// several benign samples records the response characteristics the task requires: status, body
// length, and response time.
func TestCalibrateBaselineRecordsModalStatusAvgLengthAndDuration(t *testing.T) {
	samples := []BaselineSample{
		NewBaselineSample(200, "0123456789", 10*time.Millisecond),  // len 10
		NewBaselineSample(200, "01234567890", 20*time.Millisecond), // len 11
		NewBaselineSample(200, "012345678", 12*time.Millisecond),   // len 9
	}

	b, err := CalibrateBaseline(samples)
	if err != nil {
		t.Fatalf("CalibrateBaseline: %v", err)
	}
	if b.ModalStatus() != 200 {
		t.Fatalf("ModalStatus() = %d, want 200", b.ModalStatus())
	}
	if got, want := b.AvgBodyLen(), 10.0; got != want {
		t.Fatalf("AvgBodyLen() = %v, want %v", got, want)
	}
	if len(b.Samples) != 3 {
		t.Fatalf("Samples has %d entries, want 3 (calibration must keep the raw samples for reporting)", len(b.Samples))
	}
}

// TestCalibrateBaselineModalStatusIsTheMostFrequentAndTieBreaksToFirstSeen asserts the modal
// status picks the majority status, and that a tie resolves deterministically (first seen in
// calibration order) rather than depending on Go's randomised map iteration.
func TestCalibrateBaselineModalStatusIsTheMostFrequentAndTieBreaksToFirstSeen(t *testing.T) {
	samples := []BaselineSample{
		NewBaselineSample(200, "a", time.Millisecond),
		NewBaselineSample(200, "a", time.Millisecond),
		NewBaselineSample(500, "b", time.Millisecond),
	}
	b, err := CalibrateBaseline(samples)
	if err != nil {
		t.Fatalf("CalibrateBaseline: %v", err)
	}
	if b.ModalStatus() != 200 {
		t.Fatalf("ModalStatus() = %d, want 200 (2 of 3 samples)", b.ModalStatus())
	}
}

// ---------------------------------------------------------------------------
// Baseline.Compare — deviation detection
// ---------------------------------------------------------------------------

// calibratedBaseline builds a Baseline from n identical-shaped benign samples, for tests that
// need a stable reference point with real (non-zero) length/timing variance.
func calibratedBaseline(t *testing.T) *Baseline {
	t.Helper()
	samples := []BaselineSample{
		NewBaselineSample(200, "<html>account page: normal</html>", 50*time.Millisecond),
		NewBaselineSample(200, "<html>account page: normal2</html>", 55*time.Millisecond),
		NewBaselineSample(200, "<html>account page: norml</html>", 48*time.Millisecond),
		NewBaselineSample(200, "<html>account page: normalx</html>", 52*time.Millisecond),
		NewBaselineSample(200, "<html>account page: normaly</html>", 51*time.Millisecond),
	}
	b, err := CalibrateBaseline(samples)
	if err != nil {
		t.Fatalf("CalibrateBaseline: %v", err)
	}
	return b
}

// TestCompareDoesNotFlagAResponseWithinBaselineVariance asserts the false-positive-avoidance
// half of deviation detection: a response shaped like the calibration samples (same status,
// length within the observed range, no new content) must not be flagged.
func TestCompareDoesNotFlagAResponseWithinBaselineVariance(t *testing.T) {
	b := calibratedBaseline(t)
	// Reuses one of the exact calibration bodies (same hash, same length family, same
	// timing family) so only status/length/timing/hash signals genuinely within range are
	// exercised — a body never seen during calibration would trip NewBodyHash regardless of
	// how close its length and timing are, which is a different signal this test is not
	// about.
	sample := NewBaselineSample(200, "<html>account page: normal</html>", 53*time.Millisecond)

	dev := b.Compare(sample, DefaultDeviationThreshold())

	if dev.Flagged {
		t.Fatalf("Compare flagged an in-baseline-range response: %+v", dev)
	}
}

// TestCompareFlagsAStatusChange asserts the strongest signal: a response whose status code
// differs from the baseline's modal status is flagged, and StatusChanged is set explicitly so a
// caller can distinguish it from a length/timing/hash anomaly.
func TestCompareFlagsAStatusChange(t *testing.T) {
	b := calibratedBaseline(t)
	sample := NewBaselineSample(500, "<html>error</html>", 50*time.Millisecond)

	dev := b.Compare(sample, DefaultDeviationThreshold())

	if !dev.Flagged {
		t.Fatalf("Compare did not flag a status-code change: %+v", dev)
	}
	if !dev.StatusChanged {
		t.Fatalf("Compare flagged the response but StatusChanged = false: %+v", dev)
	}
}

// TestCompareFlagsALengthAnomalyBeyondThreshold asserts a body far longer than anything
// calibration saw is flagged, and that LengthAnomalous/LengthSigma report it explicitly.
func TestCompareFlagsALengthAnomalyBeyondThreshold(t *testing.T) {
	b := calibratedBaseline(t)
	// The calibration bodies are ~34 bytes; this one is roughly 30x longer, which must clear
	// any plausible standard-deviation threshold.
	hugeBody := make([]byte, 1000)
	for i := range hugeBody {
		hugeBody[i] = 'x'
	}
	sample := NewBaselineSample(200, string(hugeBody), 50*time.Millisecond)

	dev := b.Compare(sample, DefaultDeviationThreshold())

	if !dev.Flagged {
		t.Fatalf("Compare did not flag a grossly oversized body: %+v", dev)
	}
	if !dev.LengthAnomalous {
		t.Fatalf("Compare flagged the response but LengthAnomalous = false: %+v", dev)
	}
	if dev.LengthSigma <= DefaultDeviationThreshold().LengthSigma {
		t.Fatalf("LengthSigma = %v, want > the %v threshold that was cleared", dev.LengthSigma, DefaultDeviationThreshold().LengthSigma)
	}
}

// TestCompareFlagsANewBodyHashEvenWhenLengthAndStatusMatch asserts the hash signal catches a
// same-length, same-status content substitution that length alone would miss.
func TestCompareFlagsANewBodyHashEvenWhenLengthAndStatusMatch(t *testing.T) {
	b := calibratedBaseline(t)
	// Exactly the same length as "normalz" style samples but different content entirely.
	sample := NewBaselineSample(200, "<html>account page: HIJACKD</html>", 50*time.Millisecond)

	dev := b.Compare(sample, DefaultDeviationThreshold())

	if !dev.NewBodyHash {
		t.Fatalf("Compare did not flag an unseen body hash: %+v", dev)
	}
}

// TestCompareWithZeroVarianceBaselineUsesRelativeFloorNotAnyDifference asserts that a baseline
// calibrated with a single sample (stddev == 0) does not flag trivial one-byte noise as
// anomalous — the relative-floor fallback deviates documents.
func TestCompareWithZeroVarianceBaselineUsesRelativeFloorNotAnyDifference(t *testing.T) {
	single, err := CalibrateBaseline([]BaselineSample{
		NewBaselineSample(200, "0123456789", 10*time.Millisecond), // len 10
	})
	if err != nil {
		t.Fatalf("CalibrateBaseline: %v", err)
	}

	// One byte longer: well within the 10% relative floor.
	tiny := NewBaselineSample(200, "01234567891", 10*time.Millisecond)
	dev := single.Compare(tiny, DefaultDeviationThreshold())
	if dev.LengthAnomalous {
		t.Fatalf("Compare flagged a 1-byte change against a zero-variance baseline as a length anomaly: %+v", dev)
	}

	// Doubled in length: well beyond the 10% relative floor.
	big := NewBaselineSample(200, "0123456789012345678901234567890123456789", 10*time.Millisecond)
	dev = single.Compare(big, DefaultDeviationThreshold())
	if !dev.LengthAnomalous {
		t.Fatalf("Compare did not flag a quadrupled body length against a zero-variance baseline: %+v", dev)
	}
}

// TestCompareWithRequireStatusChangeIgnoresLengthAndHashSignalsForTheVerdict asserts that
// RequireStatusChange narrows the Flagged verdict to status alone, while still populating the
// other signal fields (honest counting: a threshold that ignores a signal must not hide it).
func TestCompareWithRequireStatusChangeIgnoresLengthAndHashSignalsForTheVerdict(t *testing.T) {
	b := calibratedBaseline(t)
	hugeBody := make([]byte, 1000)
	sample := NewBaselineSample(200, string(hugeBody), 50*time.Millisecond)

	dev := b.Compare(sample, DeviationThreshold{RequireStatusChange: true})

	if dev.Flagged {
		t.Fatalf("Compare flagged under RequireStatusChange despite no status change: %+v", dev)
	}
	if !dev.LengthAnomalous {
		t.Fatalf("Compare suppressed LengthAnomalous under RequireStatusChange; it must still be reported: %+v", dev)
	}
}

// ---------------------------------------------------------------------------
// RunBaselineCalibration
// ---------------------------------------------------------------------------

// fakeBaselineSender is a network-free BaselineSender, keyed by identity label like
// fakeDifferentialSender in infra_authdiff_test.go, plus an optional per-label failure
// countdown so tests can exercise partial and total calibration failure.
type fakeBaselineSender struct {
	byLabel map[string]struct {
		status   int
		body     string
		duration time.Duration
	}
	// failFirstN, if set for a label, makes that many calls fail before succeeding.
	failFirstN map[string]int
	calls      map[string]int
}

func (f *fakeBaselineSender) Send(_ context.Context, auth AuthContext) (int, string, time.Duration, error) {
	f.calls[auth.Label]++
	if remaining := f.failFirstN[auth.Label]; remaining > 0 {
		f.failFirstN[auth.Label] = remaining - 1
		return 0, "", 0, errors.New("simulated send failure")
	}
	resp, ok := f.byLabel[auth.Label]
	if !ok {
		return 0, "", 0, errors.New("fakeBaselineSender: no response configured for label " + auth.Label)
	}
	return resp.status, resp.body, resp.duration, nil
}

// TestRunBaselineCalibrationRecordsNResponses asserts calibration sends n requests and builds a
// Baseline reflecting what came back, reporting the full success count.
func TestRunBaselineCalibrationRecordsNResponses(t *testing.T) {
	sender := &fakeBaselineSender{
		byLabel: map[string]struct {
			status   int
			body     string
			duration time.Duration
		}{
			"benign": {status: 200, body: "<html>ok</html>", duration: 20 * time.Millisecond},
		},
		calls: map[string]int{},
	}

	b, n, err := RunBaselineCalibration(context.Background(), sender, AuthContext{Label: "benign"}, 5)
	if err != nil {
		t.Fatalf("RunBaselineCalibration: %v", err)
	}
	if n != 5 {
		t.Fatalf("RunBaselineCalibration succeeded count = %d, want 5", n)
	}
	if sender.calls["benign"] != 5 {
		t.Fatalf("sender received %d calls, want 5", sender.calls["benign"])
	}
	if len(b.Samples) != 5 {
		t.Fatalf("Baseline has %d samples, want 5", len(b.Samples))
	}
	if b.ModalStatus() != 200 {
		t.Fatalf("ModalStatus() = %d, want 200", b.ModalStatus())
	}
}

// TestRunBaselineCalibrationSucceedsOnPartialFailureAndReportsTheRealCount asserts the honest
// partial-success path: some sends failing does not refuse the whole calibration, but the
// returned count must say exactly how many actually succeeded, not silently claim n.
func TestRunBaselineCalibrationSucceedsOnPartialFailureAndReportsTheRealCount(t *testing.T) {
	sender := &fakeBaselineSender{
		byLabel: map[string]struct {
			status   int
			body     string
			duration time.Duration
		}{
			"benign": {status: 200, body: "<html>ok</html>", duration: 20 * time.Millisecond},
		},
		failFirstN: map[string]int{"benign": 2},
		calls:      map[string]int{},
	}

	b, n, err := RunBaselineCalibration(context.Background(), sender, AuthContext{Label: "benign"}, 5)
	if err != nil {
		t.Fatalf("RunBaselineCalibration: %v", err)
	}
	if n != 3 {
		t.Fatalf("RunBaselineCalibration succeeded count = %d, want 3 (5 attempted, 2 failed)", n)
	}
	if len(b.Samples) != 3 {
		t.Fatalf("Baseline has %d samples, want 3", len(b.Samples))
	}
}

// TestRunBaselineCalibrationRefusesWhenEveryRequestFails asserts the hard-refusal case: zero
// successful calibration requests must return an error and no Baseline, never a Baseline built
// from nothing.
func TestRunBaselineCalibrationRefusesWhenEveryRequestFails(t *testing.T) {
	sender := &fakeBaselineSender{
		byLabel: map[string]struct {
			status   int
			body     string
			duration time.Duration
		}{},
		failFirstN: map[string]int{"benign": 5},
		calls:      map[string]int{},
	}

	b, n, err := RunBaselineCalibration(context.Background(), sender, AuthContext{Label: "benign"}, 5)
	if err == nil {
		t.Fatalf("RunBaselineCalibration with every send failing returned no error; b=%+v n=%d", b, n)
	}
	if b != nil {
		t.Fatalf("RunBaselineCalibration returned a non-nil Baseline alongside a total-failure error: %+v", b)
	}
}

// TestRunBaselineCalibrationRefusesZeroOrNegativeN asserts the input-validation guard: asking
// for zero or fewer calibration requests is refused rather than silently producing an empty
// (and therefore useless) attempt.
func TestRunBaselineCalibrationRefusesZeroOrNegativeN(t *testing.T) {
	sender := &fakeBaselineSender{byLabel: map[string]struct {
		status   int
		body     string
		duration time.Duration
	}{}, calls: map[string]int{}}

	for _, n := range []int{0, -1} {
		if _, _, err := RunBaselineCalibration(context.Background(), sender, AuthContext{Label: "benign"}, n); err == nil {
			t.Fatalf("RunBaselineCalibration(n=%d) returned no error, want a refusal", n)
		}
	}
}

// ---------------------------------------------------------------------------
// Access-control diffing atop a calibrated baseline
// ---------------------------------------------------------------------------

// TestDiffAccessControlFlagsAMatchWhenIdentityBGetsIdentityAsResourceBack asserts the IDOR/BOLA
// signature this primitive exists to catch: identity B's response has the same shape as
// identity A's calibrated baseline, so Matched must be true.
func TestDiffAccessControlFlagsAMatchWhenIdentityBGetsIdentityAsResourceBack(t *testing.T) {
	baseline, err := CalibrateBaseline([]BaselineSample{
		NewBaselineSample(200, "<html>user 42's private profile</html>", 30*time.Millisecond),
		NewBaselineSample(200, "<html>user 42's private profile</html>", 32*time.Millisecond),
		NewBaselineSample(200, "<html>user 42's private profile</html>", 29*time.Millisecond),
	})
	if err != nil {
		t.Fatalf("CalibrateBaseline: %v", err)
	}

	// Identity B (a different user, or unauthenticated) requested /users/42 and got the exact
	// same body back that identity A (user 42, authenticated) normally gets.
	idorSample := NewBaselineSample(200, "<html>user 42's private profile</html>", 31*time.Millisecond)

	got := baseline.DiffAccessControl(idorSample, DefaultDeviationThreshold())
	if !got.Matched {
		t.Fatalf("DiffAccessControl did not flag a byte-identical cross-identity response as a match: %+v", got)
	}
	if got.Comparison.Flagged {
		t.Fatalf("DiffAccessControl's underlying Deviation was Flagged for an in-baseline response: %+v", got.Comparison)
	}
}

// TestDiffAccessControlDoesNotFlagAMatchWhenIdentityBIsCorrectlyDenied asserts the negative
// case: a 403 response for identity B is materially different from identity A's baseline, so
// Matched must be false — access control worked, there is no IDOR here.
func TestDiffAccessControlDoesNotFlagAMatchWhenIdentityBIsCorrectlyDenied(t *testing.T) {
	baseline, err := CalibrateBaseline([]BaselineSample{
		NewBaselineSample(200, "<html>user 42's private profile</html>", 30*time.Millisecond),
		NewBaselineSample(200, "<html>user 42's private profile</html>", 32*time.Millisecond),
	})
	if err != nil {
		t.Fatalf("CalibrateBaseline: %v", err)
	}

	deniedSample := NewBaselineSample(403, "<html>forbidden</html>", 15*time.Millisecond)

	got := baseline.DiffAccessControl(deniedSample, DefaultDeviationThreshold())
	if got.Matched {
		t.Fatalf("DiffAccessControl flagged a 403 denial as matching the baseline: %+v", got)
	}
	if !got.Comparison.StatusChanged {
		t.Fatalf("DiffAccessControl's underlying Deviation did not report the status change: %+v", got.Comparison)
	}
}

// TestRunAccessControlBaselineDiffDrivesTheFullPipelineEndToEnd asserts the whole seam wires
// together: RunBaselineCalibration builds identity A's baseline over several requests, one
// request is sent as identity B, and DiffAccessControl reaches the correct IDOR verdict — the
// generalisation of infra_authdiff_test.go's
// TestFakeDifferentialSenderDrivesClassifyAccessControlEndToEnd to an N-sample baseline.
func TestRunAccessControlBaselineDiffDrivesTheFullPipelineEndToEnd(t *testing.T) {
	sender := &fakeBaselineSender{
		byLabel: map[string]struct {
			status   int
			body     string
			duration time.Duration
		}{
			"authenticated":   {status: 200, body: "<html>account page</html>", duration: 25 * time.Millisecond},
			"unauthenticated": {status: 200, body: "<html>account page</html>", duration: 25 * time.Millisecond},
		},
		calls: map[string]int{},
	}

	baseline, got, err := RunAccessControlBaselineDiff(
		context.Background(), sender,
		AuthContext{Label: "authenticated"}, AuthContext{Label: "unauthenticated"},
		5, DefaultDeviationThreshold())
	if err != nil {
		t.Fatalf("RunAccessControlBaselineDiff: %v", err)
	}
	if sender.calls["authenticated"] != 5 {
		t.Fatalf("calibration sent %d authenticated requests, want 5", sender.calls["authenticated"])
	}
	if sender.calls["unauthenticated"] != 1 {
		t.Fatalf("diff sent %d unauthenticated requests, want exactly 1", sender.calls["unauthenticated"])
	}
	if len(baseline.Samples) != 5 {
		t.Fatalf("returned baseline has %d samples, want 5", len(baseline.Samples))
	}
	if !got.Matched {
		t.Fatalf("RunAccessControlBaselineDiff did not detect the IDOR match: %+v", got)
	}
}

// TestRunAccessControlBaselineDiffFailsWhenCalibrationFails asserts that a calibration failure
// (identity A's requests all erroring) surfaces as an error from the pipeline, never a
// misleading zero-value verdict.
func TestRunAccessControlBaselineDiffFailsWhenCalibrationFails(t *testing.T) {
	sender := &fakeBaselineSender{
		byLabel: map[string]struct {
			status   int
			body     string
			duration time.Duration
		}{},
		failFirstN: map[string]int{"authenticated": 5},
		calls:      map[string]int{},
	}

	_, _, err := RunAccessControlBaselineDiff(
		context.Background(), sender,
		AuthContext{Label: "authenticated"}, AuthContext{Label: "unauthenticated"},
		5, DefaultDeviationThreshold())
	if err == nil {
		t.Fatalf("RunAccessControlBaselineDiff with a fully-failing calibration returned no error")
	}
}
