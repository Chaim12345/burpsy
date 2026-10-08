package scanner

// Baseline diffing: calibrate "normal" from N benign requests, then flag responses that
// deviate from it — the pattern JLFuxx and most modern fuzzers use in place of (or alongside)
// signature matching, and the primitive that turns infra_authdiff.go's two-request access
// control comparison into an N-sample-calibrated one.
//
// # Why calibration, not a single baseline request
//
// ProbeHarness's baseline (probe_harness.go) is one request, which is right for injection
// evidence: the comparison there is "did THIS payload change THIS response", and a single
// reference is enough to tell payload-shaped noise from baseline shaped noise. Anomaly
// detection and access-control diffing ask a different question — "does this response look
// like the kind of response this endpoint normally gives" — and a single sample cannot answer
// that: an endpoint that varies its own body length by a few bytes on every legitimate request
// (a timestamp, a nonce, a request-scoped CSRF token) would make every single-sample comparison
// a false positive. Calibrating over N benign requests first is what lets Compare tell real
// variance apart from a genuine deviation.
//
// # Why status/length/hash/time, and nothing cleverer
//
// The same four signals ResponseFingerprint already uses for injection evidence, widened with
// duration and a real hash instead of a raw body compare: status is the strongest signal and
// checked first, body length and a normalised-body hash catch content-shape changes cheaply
// without keeping every calibration body in memory, and duration catches the class of endpoint
// (an authorization check that short-circuits, a slow query BOLA triggers) neither of the other
// three would. Nothing more clever is attempted, for the same reason responsesDiffer in sqli.go
// stayed simple: this package has exactly one differencing philosophy, applied consistently
// rather than reinvented per caller.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/burpsy-go/burpsy/internal/tools"
)

// lengthRelativeFloor and timingRelativeFloor are the deviation thresholds used when a
// baseline's calibration samples showed zero variance (most commonly: calibration ran with
// n == 1). A stddev of exactly zero must not be read as "any difference at all is anomalous" —
// that would flag ordinary one-byte noise from a single calibration sample — so a relative
// floor stands in for the standard-deviation test in that case.
const (
	lengthRelativeFloor = 0.10 // 10% body-length change
	timingRelativeFloor = 0.50 // 50% duration change; timing is noisier than length
)

// BaselineSample is one response's observable characteristics: what a benign calibration
// request records, and what a later (possibly fuzzed, possibly differently-authenticated)
// response is compared against.
type BaselineSample struct {
	Status   int
	BodyLen  int
	BodyHash string
	Duration time.Duration
}

// NewBaselineSample builds a sample from an observed status/body/duration triple, hashing the
// body with the package's one hash helper (internal/tools.Hasher) so every caller — calibration
// and comparison alike — hashes identically. SHA-256 rather than a shorter digest because a
// baseline's hash set is the thing collision would silently corrupt: two different bodies
// hashing alike would read as "this body was already seen during calibration" and suppress a
// real deviation.
func NewBaselineSample(status int, body string, duration time.Duration) BaselineSample {
	return BaselineSample{
		Status:   status,
		BodyLen:  len(body),
		BodyHash: tools.NewHasher().SHA256(body),
		Duration: duration,
	}
}

// Baseline is calibrated "normal" for one endpoint/identity, built from N benign responses.
// Only the summary statistics are kept beyond the raw samples — a scan calibrating hundreds of
// baselines must not keep every response body it saw in order to compare against it later.
type Baseline struct {
	// Samples is the raw calibration set, kept for reporting (how many requests, what they
	// looked like) — Compare itself only reads the derived fields below.
	Samples []BaselineSample

	modalStatus int
	avgLen      float64
	lenStdDev   float64
	avgDuration float64 // seconds; float64 so meanStdDev can be shared with length
	durStdDev   float64
	hashes      map[string]int
}

// CalibrateBaseline computes a Baseline's summary statistics from already-observed calibration
// samples. It performs no network I/O of its own — see RunBaselineCalibration for the seam that
// sends the N benign requests — the same "pure decision, separate sender seam" split
// infra_authdiff.go uses for ClassifyAccessControl vs DifferentialSender, and for the same
// reason: a decision function that could fail because of a network error is untestable without
// a network.
//
// It refuses an empty sample set outright rather than returning a zero-value Baseline that
// would silently accept everything as normal (an empty hash set, avgLen == 0): "no calibration
// data" must read as a refusal, not as a baseline that happens to flag nothing.
func CalibrateBaseline(samples []BaselineSample) (*Baseline, error) {
	if len(samples) == 0 {
		return nil, errors.New("baseline: calibration requires at least one sample")
	}

	statusCounts := make(map[int]int, len(samples))
	lens := make([]float64, len(samples))
	durs := make([]float64, len(samples))
	hashes := make(map[string]int, len(samples))
	for i, s := range samples {
		statusCounts[s.Status]++
		lens[i] = float64(s.BodyLen)
		durs[i] = s.Duration.Seconds()
		hashes[s.BodyHash]++
	}

	modal, best := 0, -1
	// Iterate samples (not the map) so the modal status is deterministic when two statuses tie:
	// the one seen first in calibration order wins, rather than depending on Go's randomised
	// map iteration order.
	seen := make(map[int]bool, len(statusCounts))
	for _, s := range samples {
		if seen[s.Status] {
			continue
		}
		seen[s.Status] = true
		if statusCounts[s.Status] > best {
			best = statusCounts[s.Status]
			modal = s.Status
		}
	}

	avgLen, lenStdDev := meanStdDev(lens)
	avgDur, durStdDev := meanStdDev(durs)

	return &Baseline{
		Samples:     append([]BaselineSample(nil), samples...),
		modalStatus: modal,
		avgLen:      avgLen,
		lenStdDev:   lenStdDev,
		avgDuration: avgDur,
		durStdDev:   durStdDev,
		hashes:      hashes,
	}, nil
}

// meanStdDev returns the sample mean and sample standard deviation (Bessel's correction, n-1)
// of xs. A single-element slice returns stddev == 0 rather than NaN or a division by zero —
// zero variance is exactly the honest answer when calibration ran with n == 1, and Compare's
// relative-floor fallback exists precisely to handle that case correctly.
func meanStdDev(xs []float64) (mean, stddev float64) {
	n := len(xs)
	if n == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(n)
	if n < 2 {
		return mean, 0
	}
	var sq float64
	for _, x := range xs {
		d := x - mean
		sq += d * d
	}
	return mean, math.Sqrt(sq / float64(n-1))
}

// ModalStatus, AvgBodyLen and AvgDuration expose the calibrated summary for reporting (a
// finding's detail text, a coverage line) without exposing the derived stddev fields, which are
// an internal implementation detail of Compare's thresholding.
func (b *Baseline) ModalStatus() int    { return b.modalStatus }
func (b *Baseline) AvgBodyLen() float64 { return b.avgLen }
func (b *Baseline) AvgDuration() time.Duration {
	return time.Duration(b.avgDuration * float64(time.Second))
}

// DeviationThreshold configures how sensitive Compare is. The zero value is deliberately not
// "flag nothing" or "flag everything": DefaultDeviationThreshold is the documented starting
// point, and a caller that wants the zero value's behaviour (RequireStatusChange only) must ask
// for it explicitly.
type DeviationThreshold struct {
	// LengthSigma is how many standard deviations a body length may move from the baseline
	// average before Compare flags it. Ignored (see lengthRelativeFloor) when the baseline
	// showed zero length variance.
	LengthSigma float64
	// TimingSigma is the same test applied to response duration.
	TimingSigma float64
	// RequireStatusChange narrows Compare to status-code deviation only, ignoring length,
	// hash and timing signals entirely. Exists for callers that want the cheapest, lowest
	// false-positive signal — a fuzzing campaign triaging thousands of responses where length
	// and timing noise would drown a human reviewer, for instance — without losing the
	// ability to ask "but was anything unusual by any measure" from the returned Deviation's
	// other fields, which Compare still populates even when this is set.
	RequireStatusChange bool
}

// DefaultDeviationThreshold is a conservative starting point: three standard deviations on
// both length and timing is the common "this is not noise" convention, wide enough that an
// endpoint with genuinely variable but benign responses (a counter, a timestamp) does not
// flood a scan with false positives.
func DefaultDeviationThreshold() DeviationThreshold {
	return DeviationThreshold{LengthSigma: 3, TimingSigma: 3}
}

// Deviation is what one comparison against a Baseline found. Every signal is reported
// independently — a caller filtering on Flagged alone gets the threshold's verdict, but a
// caller building a finding's detail text can say exactly which signal(s) tripped it, which
// none of Flagged alone. StatusChanged/LengthAnomalous/TimingAnomalous/NewBodyHash are computed
// unconditionally, even under RequireStatusChange, honest-counting the same way ProbeCoverage
// keeps declined and untested distinct: a threshold that ignores a signal for the verdict must
// not also hide that the signal fired.
type Deviation struct {
	StatusChanged   bool
	LengthAnomalous bool
	LengthSigma     float64 // standard deviations from baseline average; 0 when the baseline had zero length variance
	TimingAnomalous bool
	TimingSigma     float64
	NewBodyHash     bool
	Flagged         bool
	Reasons         []string
}

// Compare classifies one observed sample against the baseline, using threshold to decide which
// signals are anomalous enough to flag.
func (b *Baseline) Compare(sample BaselineSample, threshold DeviationThreshold) Deviation {
	dev := Deviation{}

	if sample.Status != b.modalStatus {
		dev.StatusChanged = true
		dev.Reasons = append(dev.Reasons, fmt.Sprintf(
			"status changed: baseline %d, observed %d", b.modalStatus, sample.Status))
	}

	dev.LengthSigma, dev.LengthAnomalous = deviates(
		float64(sample.BodyLen), b.avgLen, b.lenStdDev, threshold.LengthSigma, lengthRelativeFloor)
	if dev.LengthAnomalous {
		dev.Reasons = append(dev.Reasons, fmt.Sprintf(
			"body length deviates from baseline (baseline avg %.1f, observed %d)", b.avgLen, sample.BodyLen))
	}

	dev.TimingSigma, dev.TimingAnomalous = deviates(
		sample.Duration.Seconds(), b.avgDuration, b.durStdDev, threshold.TimingSigma, timingRelativeFloor)
	if dev.TimingAnomalous {
		dev.Reasons = append(dev.Reasons, fmt.Sprintf(
			"response time deviates from baseline (baseline avg %s, observed %s)",
			time.Duration(b.avgDuration*float64(time.Second)), sample.Duration))
	}

	if _, seen := b.hashes[sample.BodyHash]; !seen {
		dev.NewBodyHash = true
		dev.Reasons = append(dev.Reasons, "body hash was not observed during baseline calibration")
	}

	if threshold.RequireStatusChange {
		dev.Flagged = dev.StatusChanged
	} else {
		dev.Flagged = dev.StatusChanged || dev.LengthAnomalous || dev.TimingAnomalous || dev.NewBodyHash
	}
	return dev
}

// deviates is the shared standard-deviation-with-relative-floor test both length and timing use:
// a sigma test when the baseline showed real variance (stddev > 0), a relative-change floor
// otherwise. See lengthRelativeFloor/timingRelativeFloor's doc comment for why the floor exists
// rather than treating any change from a zero-variance baseline as anomalous.
func deviates(observed, mean, stddev, sigmaThreshold, relativeFloor float64) (sigma float64, anomalous bool) {
	diff := math.Abs(observed - mean)
	if stddev > 0 {
		sigma = diff / stddev
		return sigma, sigma > sigmaThreshold
	}
	if mean == 0 {
		return 0, diff > 0
	}
	return 0, diff/mean > relativeFloor
}

// ---------------------------------------------------------------------------
// Calibration over a live sender
// ---------------------------------------------------------------------------

// BaselineSender is the seam RunBaselineCalibration and RunAccessControlBaselineDiff use to
// avoid a direct dependency on a live network sender — the same seam DifferentialSender
// provides for the two-request access-control comparison in infra_authdiff.go, reused rather
// than duplicated: a CheckRunner wires a real, engagement-authorised sender behind it, and a
// unit test wires a fake that returns canned triples. auth carries the identity the request
// should be sent as, matching DifferentialSender.SendWithAuth's shape so one CheckRunner can
// share both seams against the same session.Coordinator-derived AuthContext pair.
type BaselineSender interface {
	Send(ctx context.Context, auth AuthContext) (status int, body string, duration time.Duration, err error)
}

// RunBaselineCalibration sends n benign requests as auth through sender and calibrates a
// Baseline from whichever succeeded. It reports the count that actually succeeded alongside the
// baseline — a caller asked for 20 and got 20 has a different confidence than one who asked for
// 20 and got 3, and collapsing that into a single opaque Baseline would lose it, the same
// honest-counting reason ProbeCoverage reports PointsCapped and PointsSkippedRepetitive instead
// of silently proceeding on whatever it managed to send.
//
// It refuses (returns an error, no Baseline) only when EVERY request failed: a baseline built
// from partial data is still useful and still honestly countable via the returned n; a baseline
// built from zero data is not a baseline, it is a refusal wearing one.
func RunBaselineCalibration(ctx context.Context, sender BaselineSender, auth AuthContext, n int) (*Baseline, int, error) {
	if sender == nil {
		return nil, 0, errors.New("baseline: no sender; calibration cannot be sent")
	}
	if n <= 0 {
		return nil, 0, errors.New("baseline: calibration requires at least one request")
	}

	samples := make([]BaselineSample, 0, n)
	var lastErr error
	for i := 0; i < n; i++ {
		status, body, duration, err := sender.Send(ctx, auth)
		if err != nil {
			lastErr = err
			continue
		}
		samples = append(samples, NewBaselineSample(status, body, duration))
	}
	if len(samples) == 0 {
		return nil, 0, fmt.Errorf("baseline: all %d calibration request(s) failed, last error: %w", n, lastErr)
	}

	baseline, err := CalibrateBaseline(samples)
	if err != nil {
		// Unreachable given the len(samples) == 0 guard above, but returned rather than
		// panicked so a future change to CalibrateBaseline's error conditions fails loudly
		// here instead of silently, per this package's own rule about refusals.
		return nil, len(samples), err
	}
	return baseline, len(samples), nil
}

// ---------------------------------------------------------------------------
// Access-control diffing atop a calibrated baseline
// ---------------------------------------------------------------------------

// AccessControlDeviation is the verdict for one access-control diff: does a second identity's
// response look like it received the SAME resource the baseline identity did? This deliberately
// inverts Deviation's polarity — for anomaly detection, "differs from baseline" is the finding;
// for access control / IDOR, "matches baseline" is the finding, because the question being
// asked is "did identity B, which should have been denied or shown a different resource, get
// identity A's resource back instead".
type AccessControlDeviation struct {
	// Matched is true when identity B's response was NOT flagged as different from identity
	// A's baseline — i.e. B received materially the same response A did. This is the
	// IDOR/BOLA signature: two different identities getting the same answer for a
	// resource-scoped request.
	Matched bool
	// Comparison is the underlying Deviation the match/no-match verdict was derived from, so
	// a caller building a finding can cite exactly which signals matched (or didn't).
	Comparison Deviation
}

// DiffAccessControl compares a single sample — captured under a different identity than the
// one the baseline was calibrated under — against the baseline, and reports whether that
// identity appears to have received the same resource. threshold has the same meaning as in
// Compare: a wider threshold accepts more incidental variance as "still the same resource"
// before concluding the two identities diverged.
func (b *Baseline) DiffAccessControl(other BaselineSample, threshold DeviationThreshold) AccessControlDeviation {
	dev := b.Compare(other, threshold)
	return AccessControlDeviation{Matched: !dev.Flagged, Comparison: dev}
}

// RunAccessControlBaselineDiff is the full pipeline the task this file exists for describes:
// calibrate a baseline under identityA with n benign requests, capture one observation under
// identityB against (implicitly, via sender) the same resource, and diff B against A's
// calibrated baseline.
//
// It generalises infra_authdiff.go's ClassifyAccessControl — a single authenticated vs.
// unauthenticated request pair — to an N-sample calibration: one authenticated/unauthenticated
// pair can coincidentally agree or disagree due to response noise the endpoint itself
// introduces (a per-request nonce, a counter), and a calibrated baseline is what lets the
// threshold in DiffAccessControl tell that noise apart from a genuine access-control failure.
// The two are not competing implementations — ClassifyAccessControl is still the right tool for
// a single cheap two-request check; this is for a caller that wants that check's answer backed
// by N samples of "what does authenticated identity A normally get back".
func RunAccessControlBaselineDiff(ctx context.Context, sender BaselineSender, identityA, identityB AuthContext, n int, threshold DeviationThreshold) (*Baseline, AccessControlDeviation, error) {
	baseline, _, err := RunBaselineCalibration(ctx, sender, identityA, n)
	if err != nil {
		return nil, AccessControlDeviation{}, fmt.Errorf("access-control baseline diff: calibrating identity %q: %w", identityA.Label, err)
	}

	status, body, duration, err := sender.Send(ctx, identityB)
	if err != nil {
		return baseline, AccessControlDeviation{}, fmt.Errorf("access-control baseline diff: sending as identity %q: %w", identityB.Label, err)
	}

	return baseline, baseline.DiffAccessControl(NewBaselineSample(status, body, duration), threshold), nil
}
