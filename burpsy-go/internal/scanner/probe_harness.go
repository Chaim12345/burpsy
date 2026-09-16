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
	h.points, h.declined = bcheck.EnumerateWith(raw, kinds, cc.ProbeEnumerateOptions())

	baseline, err := h.send(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("probe harness: no baseline response: %w", err)
	}
	h.baseline = baseline
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

	out := ProbeResponse{Raw: res.Raw, Duration: res.Duration}
	if res.Status != nil {
		out.Status = *res.Status
	}
	out.Body = responseBody(string(res.Raw))
	if out.Status == 0 {
		out.Status = responseStatus(string(res.Raw))
	}
	return out, nil
}

// Send places payload at point and dispatches the resulting request.
func (h *ProbeHarness) Send(ctx context.Context, point bcheck.InsertionPoint, payload string) (ProbeResponse, error) {
	mutated, err := point.Apply(h.reqBytes, payload, false)
	if err != nil {
		return ProbeResponse{}, fmt.Errorf("applying payload to %s %q: %w", point.Kind, point.Name, err)
	}
	return h.send(ctx, mutated)
}

// probe runs one payload and hands the baseline/injected pair to classify. A send failure
// becomes an inconclusive probe rather than a clean one.
func (h *ProbeHarness) probe(ctx context.Context, point bcheck.InsertionPoint, payload string,
	classify func(baseline, injected ProbeResponse) (InjectionEvidence, string)) InjectionProbe {

	out := InjectionProbe{Payload: payload}
	injected, err := h.Send(ctx, point, payload)
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
func (h *ProbeHarness) ProbeErrorSignatures(ctx context.Context, point bcheck.InsertionPoint,
	payloads []string, signatures []string) []InjectionProbe {

	out := make([]InjectionProbe, 0, len(payloads))
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
