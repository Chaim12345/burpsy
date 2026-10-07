package scanner

// The active-probe harness: the I/O half the injection evaluators need.
//
// Everything under it already existed — bcheck.Enumerate finds insertion points,
// InsertionPoint.Apply splices a payload into the base request, and probeGate returns the
// AuthorisedSender that is the one way a probe leaves this process. What was missing was the
// thing that holds them together: capture a baseline, walk the points, send, and hand the
// pair to a classifier.
//
// # Why the baseline is captured once, up front
//
// Every classifier in infra_injection_evidence.go takes the baseline as a mandatory
// argument, so a harness that could not produce one would make all of them unusable. It is
// captured once per harness rather than per payload because re-fetching it between payloads
// would let an application's own state changes look like injection.
//
// # What "could not look" means here
//
// Three distinct failures are kept apart from "no evidence", because collapsing them is how
// a scanner reports coverage it does not have:
//
//   - No baseline: NewProbeHarness fails. A caller cannot proceed to report anything.
//   - Points that could not be enumerated: DeclinedPoints, straight from bcheck.
//   - A send that was refused or errored: the probe carries InjectionEvidenceInconclusive
//     and a Detail naming the reason, never InjectionEvidenceNone.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
)

// DefaultProbeInsertionKinds is the point set an injection evaluator walks when it does not
// name its own: the places a value the application parses can be placed.
var DefaultProbeInsertionKinds = []string{"query", "body", "cookie", "header"}

// ProbeResponse is one probe's observable outcome.
type ProbeResponse struct {
	Raw      []byte
	Body     string
	Status   int
	Duration time.Duration
}

// ProbeHarness holds one exchange's baseline and insertion points for a run of payloads.
type ProbeHarness struct {
	scanner  *ActiveScanner
	exchange *core.Exchange
	reqBytes []byte

	baseline ProbeResponse
	points   []bcheck.InsertionPoint
	declined []bcheck.Declined
	// accuracy is the run-level ScanAccuracy bound (ev7y): the maximum number of
	// payloads any single check may send. Zero means unset — no bound. A check
	// whose payload list is longer is truncated to accuracy entries, so a
	// minimise_false_positives run (accuracy=10) probes fewer candidates per
	// place than a minimise_false_negatives run (accuracy=4), which is the whole
	// point of the trade-off.
	accuracy int
}

// NewProbeHarness captures the baseline and enumerates insertion points.
//
// It fails when there is no sender, no request to mutate, or no baseline response: each of
// those makes every downstream comparison meaningless, and returning a usable harness anyway
// would let a caller report "no evidence" for work that never happened.
func NewProbeHarness(ctx context.Context, cc *CheckContext, kinds []string) (*ProbeHarness, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, errors.New("probe harness: no scanner or exchange")
	}
	s, exchange := cc.Scanner, cc.Exchange
	if s.sender == nil {
		return nil, errors.New("probe harness: no sender; an active probe cannot be sent")
	}
	raw := []byte(requestRaw(s, exchange))
	if len(raw) == 0 {
		return nil, errors.New("probe harness: the exchange carries no request bytes")
	}
	if len(kinds) == 0 {
		kinds = DefaultProbeInsertionKinds
	}

	h := &ProbeHarness{scanner: s, exchange: exchange, reqBytes: raw}
	// The run's accuracy becomes this harness's per-check payload bound (burpsy-react-ui-ev7y).
	// Unset leaves it zero, which boundPayloads reads as "no bound" — the behaviour every run had
	// before the key was honoured.
	if cc.ScanAccuracy.Set {
		h.accuracy = CheckAccuracy(cc.ScanAccuracy.Value).Attempts()
	}
	h.points, h.declined = bcheck.EnumerateWith(raw, kinds, cc.ProbeEnumerateOptions())

	baseline, err := h.send(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("probe harness: no baseline response: %w", err)
	}
	h.baseline = baseline
	// The baseline is a path of the target too — the response to the unmodified
	// request — so it is recorded like any other probe's response.
	h.recordCoverage(nil, "", baseline)
	return h, nil
}

// Baseline is the unmodified request's response, for every differential comparison.
func (h *ProbeHarness) Baseline() ProbeResponse { return h.baseline }

// Points are the insertion points a payload can be placed in.
func (h *ProbeHarness) Points() []bcheck.InsertionPoint { return h.points }

// DeclinedPoints are the places bcheck could not build a point for. They are part of the
// scan's coverage story: a check that tested five of nine parameters has not tested the
// endpoint, and a report saying otherwise is wrong.
func (h *ProbeHarness) DeclinedPoints() []bcheck.Declined { return h.declined }

// send is the single egress path: it always goes through probeGate, so a harness cannot
// become a way around the scope chokepoint. A scope refusal is metered as a refusal, not a
// generic failure, so the audit's refusal ledger stays accurate.
func (h *ProbeHarness) send(ctx context.Context, raw []byte) (ProbeResponse, error) {
	gate := h.scanner.probeGate(h.exchange)
	if gate == nil {
		return ProbeResponse{}, errors.New("no authorised sender")
	}
	meter := meterFrom(ctx)
	meter.attempt()
	refusedBefore := gate.Refused()
	res, err := gate.Send(ctx, raw)
	if gate.Refused() > refusedBefore {
		meter.refusal()
		return ProbeResponse{}, fmt.Errorf("refused: outside the engagement scope: %w", err)
	}
	if err != nil {
		meter.failure()
		return ProbeResponse{}, err
	}
	meter.succeeded()

	// Readable, like the base response it is compared with (burpsy-react-ui-s68u): the harness
	// replays the captured browser request, Accept-Encoding and all, so the wire answer is usually
	// gzip and often chunked — and a reflection check searching compressed bytes finds nothing.
	readable, _ := readableResponse(res.Raw)
	out := ProbeResponse{Raw: readable, Duration: res.Duration}
	if res.Status != nil {
		out.Status = *res.Status
	}
	out.Body = responseBody(string(readable))
	if out.Status == 0 {
		out.Status = responseStatus(string(readable))
	}
	// Auto-backoff (fkl8): the same 429/503 observation sendTestRequestFull holds. The
	// injection families send through THIS path, not that one, so the rule lives in both —
	// one observation per send path, no third place a rate limit could slip past.
	if out.Status == 429 || out.Status == 503 {
		meter.rateLimited(out.Status)
	}
	return out, nil
}

// Send places payload at point and dispatches the resulting request.
func (h *ProbeHarness) Send(ctx context.Context, point bcheck.InsertionPoint, payload string) (ProbeResponse, error) {
	return h.guidedSend(&point, payload, ctx)
}

// guidedSend applies the payload, sends, and folds the response into the coverage
// ledger — the one place a probe's response is recorded, so no probe path (direct Send,
// probe, or the baseline) can skip it.
func (h *ProbeHarness) guidedSend(point *bcheck.InsertionPoint, payload string, ctx context.Context) (ProbeResponse, error) {
	mutated, err := point.Apply(h.reqBytes, payload, false)
	if err != nil {
		return ProbeResponse{}, fmt.Errorf("applying payload to %s %q: %w", point.Kind, point.Name, err)
	}
	resp, err := h.send(ctx, mutated)
	if err != nil {
		return resp, err
	}
	h.recordCoverage(point, payload, resp)
	return resp, nil
}

// recordCoverage folds one probe's response into the scanner's coverage ledger and
// payload guide (burpsy-react-ui-6c90): the response cell (status × body-length
// bucket) is recorded per exchange, and when the cell is new the payload's novelty
// score at this place rises — the signal the guide orders future payload lists by.
//
// A nil point is the baseline: its response is a path of the target too and is
// recorded, but there is no place to score a payload against. A scanner without
// the ledgers (a zero ActiveScanner) is a no-op, not an error — the harness is
// usable offline without the guidance machinery.
func (h *ProbeHarness) recordCoverage(point *bcheck.InsertionPoint, payload string, resp ProbeResponse) {
	if h.scanner == nil || h.scanner.pathCov == nil {
		return
	}
	novel := h.scanner.pathCov.Record(fmt.Sprintf("%d", h.exchange.ID), resp.Status, len(resp.Body))
	if point != nil {
		h.scanner.guide.RecordOutcome(pointPlace(h.exchange.Host, *point), payload, novel)
	}
}

// orderPayloads applies the coverage guide to a place's payload list: the payloads
// that have opened new response cells at this place go first (burpsy-react-ui-6c90).
// A place with no history gets the list back exactly as written — see
// payloadGuide.Order for why an untouched list is never reshuffled.
func (h *ProbeHarness) orderPayloads(point bcheck.InsertionPoint, payloads []string) []string {
	// h.exchange is guarded alongside the guide, not after it. The guide is the thing whose absence
	// is a supported state (no coverage tracking configured), but h.exchange is dereferenced on the
	// line below to build the place key, so a harness built without one nil-panics the moment a guide
	// happens to be present. A harness with no exchange has no place to score a payload against, so
	// the list goes back unshuffled for the same reason the guide's absence does.
	if h.scanner == nil || h.scanner.guide == nil || h.exchange == nil {
		return payloads
	}
	return h.scanner.guide.Order(pointPlace(h.exchange.Host, point), payloads)
}

// probe runs one payload and hands the baseline/injected pair to classify. A send failure
// becomes an inconclusive probe rather than a clean one.
func (h *ProbeHarness) probe(ctx context.Context, point bcheck.InsertionPoint, payload string,
	classify func(baseline, injected ProbeResponse) (InjectionEvidence, string)) InjectionProbe {

	out := InjectionProbe{Payload: payload}
	injected, err := h.guidedSend(&point, payload, ctx)
	if err != nil {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s %q: probe not sent: %v", point.Kind, point.Name, err)
		return out
	}
	ev, detail := classify(h.baseline, injected)
	out.Evidence = ev
	out.Detail = fmt.Sprintf("%s %q: %s", point.Kind, point.Name, detail)
	return out
}

// ProbeErrorSignatures sends each payload and looks for signatures the baseline did not have.
//
// The list is coverage-guided (burpsy-react-ui-6c90): payloads that have opened new
// response cells at this place on earlier exchanges are sent first — gofuzz's
// "mutate what discovered new blocks", restated for a place that has not answered
// yet. A place with no history gets the list exactly as written.
func (h *ProbeHarness) ProbeErrorSignatures(ctx context.Context, point bcheck.InsertionPoint,
	payloads []string, signatures []string) []InjectionProbe {

	payloads = h.boundPayloads(payloads)
	out := make([]InjectionProbe, 0, len(payloads))
	payloads = h.orderPayloads(point, payloads)
	for _, payload := range payloads {
		out = append(out, h.probe(ctx, point, payload,
			func(baseline, injected ProbeResponse) (InjectionEvidence, string) {
				ev := ClassifyErrorEvidence(baseline.Body, injected.Body, signatures)
				switch ev.Evidence {
				case InjectionEvidenceErrorSignature:
					return ev.Evidence, "introduced " + ev.Matched[0]
				case InjectionEvidenceInconclusive:
					return ev.Evidence, "signature " + ev.Preexisting[0] + " was already in the baseline"
				}
				return ev.Evidence, "no signature introduced"
			}))
	}
	return out
}

// ProbeEvaluation sends payload and reports whether expected appeared without being echoed.
func (h *ProbeHarness) ProbeEvaluation(ctx context.Context, point bcheck.InsertionPoint,
	payload, expected string) InjectionProbe {

	return h.probe(ctx, point, payload,
		func(baseline, injected ProbeResponse) (InjectionEvidence, string) {
			ev := ClassifyEvaluation(baseline.Body, injected.Body, payload, expected)
			return ev, fmt.Sprintf("looking for %q: %s", expected, ev)
		})
}

// ProbeTiming sends payload and reports whether the delay it requested was observed. The
// baseline duration is the reference, so a uniformly slow endpoint does not read as
// injectable.
func (h *ProbeHarness) ProbeTiming(ctx context.Context, point bcheck.InsertionPoint,
	payload string, delay time.Duration) InjectionProbe {

	return h.probe(ctx, point, payload,
		func(baseline, injected ProbeResponse) (InjectionEvidence, string) {
			ev := ClassifyTimingEvidence(baseline.Duration, injected.Duration, delay)
			return ev, fmt.Sprintf("baseline %s, injected %s, requested %s: %s",
				baseline.Duration, injected.Duration, delay, ev)
		})
}

// ProbeBoolean sends an always-true and an always-false payload and compares both against
// the baseline. Both halves are required; see ClassifyBooleanDifferential.
func (h *ProbeHarness) ProbeBoolean(ctx context.Context, point bcheck.InsertionPoint,
	truePayload, falsePayload string) InjectionProbe {

	out := InjectionProbe{Payload: truePayload + " / " + falsePayload}
	whenTrue, err := h.Send(ctx, point, truePayload)
	if err != nil {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s %q: true-condition probe not sent: %v", point.Kind, point.Name, err)
		return out
	}
	whenFalse, err := h.Send(ctx, point, falsePayload)
	if err != nil {
		out.Evidence = InjectionEvidenceInconclusive
		out.Detail = fmt.Sprintf("%s %q: false-condition probe not sent: %v", point.Kind, point.Name, err)
		return out
	}
	ev := ClassifyBooleanDifferential(
		NewResponseFingerprint(h.baseline.Status, h.baseline.Body),
		NewResponseFingerprint(whenTrue.Status, whenTrue.Body),
		NewResponseFingerprint(whenFalse.Status, whenFalse.Body),
	)
	out.Evidence = ev
	out.Detail = fmt.Sprintf("%s %q: %s", point.Kind, point.Name, ev)
	return out
}

// ProbeCoverage is what a check reports alongside its findings: how much of the endpoint it
// actually reached. Points that could not be enumerated are named, not dropped.
type ProbeCoverage struct {
	PointsTested   int
	PointsDeclined int
	PayloadsSent   int
	// Inconclusive counts probes whose comparison could not be made.
	Inconclusive int
	// PointsCapped counts enumerated points the check did not probe because it hit
	// MaxInjectionPointsPerCheck. Without it the finding reads "Probed 8 insertion points" for a
	// request that had 20, which is a coverage claim the check did not earn. The cap is a bound on
	// requests, not a statement that the extra points were tested and clean.
	PointsCapped int
	// PointsSkippedRepetitive counts points the light-audit tier skipped because the same
	// (kind, host) had produced enough clean points this run (burpsy-react-ui-7bkj) — Burp's
	// "Skipped due to repetitive behavior". Reported beside PointsCapped because it is the
	// same honesty at a different scope: skipped points are NOT tested and must never read
	// as clean.
	PointsSkippedRepetitive int
	// PointsJudgedIneffective counts probes spent on points that answered nothing
	// (burpsy-react-ui-y4om). Not a skip count — those points WERE probed, which is the
	// difference the two tiers draw: the light tier declines a point on the behaviour of its
	// type, this one records the point's own evidence. Reported so a run whose point count
	// fell is legible: without it, points the gate later drops read as points that were never
	// enumerated.
	PointsJudgedIneffective int
}

// Coverage summarises a probe set for reporting.
func (h *ProbeHarness) Coverage(probes []InjectionProbe, pointsTested int) ProbeCoverage {
	cov := ProbeCoverage{
		PointsTested:   pointsTested,
		PointsDeclined: len(h.declined),
		PayloadsSent:   len(probes),
	}
	for _, p := range probes {
		if p.Evidence == InjectionEvidenceInconclusive {
			cov.Inconclusive++
		}
	}
	return cov
}

// boundPayloads truncates a check's payload list to the run's accuracy bound (burpsy-react-ui-ev7y,
// Burp's Zs_2.java:8 token counts: 4 / 8 / 10).
//
// Truncation rather than sampling, because the order is already meaningful: orderPayloads puts the
// payloads most likely to work first, using what the guide learned about this place. Taking the
// first N keeps that ordering's value; taking a random N would throw away the one piece of
// knowledge the run has accumulated.
//
// A zero or negative bound means unset and returns the list untouched, which is every run that
// never named an accuracy.
func (h *ProbeHarness) boundPayloads(payloads []string) []string {
	if h == nil || h.accuracy <= 0 || len(payloads) <= h.accuracy {
		return payloads
	}
	return payloads[:h.accuracy]
}
