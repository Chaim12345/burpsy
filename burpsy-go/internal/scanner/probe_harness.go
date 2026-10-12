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
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
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
	// Followed is the page a redirect chain landed on, when this probe was sent with SendFollowing,
	// the run follows redirects (follow_redirections, burpsy-react-ui-o2p3) and the response was a
	// redirect the policy let it follow at least one hop of. Nil otherwise — including when the chain
	// was refused or filtered at its first hop, where the 30x above is all there is.
	Followed *ProbeResponse
	// FollowedTo is the absolute URL Followed came from. Empty when Followed is nil.
	FollowedTo string
}

// landing is the response a browser would render for this probe: the end of a followed redirect
// chain when there is one, the response itself otherwise. A browser following a 30x never renders
// the 30x's own body, so a check that asks "would this execute" asks it of the landing page.
func (r ProbeResponse) landing() ProbeResponse {
	if r.Followed != nil {
		return *r.Followed
	}
	return r
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

	// The detection-method selection this check runs under (burpsy-react-ui-2hze): its catalogue
	// row, the methods the run disabled for that row, and where a withheld probe is counted.
	typeIndex uint32
	issue     string
	disabled  map[string]bool
	declines  *MethodDeclineLedger

	// shapes records each probe's response shape in send order (burpsy-react-ui-vjjs), so the light
	// tier can ask whether a point's input changed anything before it counts the point as repetitive.
	shapesMu sync.Mutex
	shapes   []probeShape
}

// probeShape is what the repetitive-behaviour rule compares a probe's response on: its shape, not its
// content. An application that echoes every value back behaves the same way for every point of the
// type, which is repetition, so reflection alone does not break it.
type probeShape struct {
	status  int
	bodyLen int
}

// shapeMark is the position a caller reads probe shapes from.
func (h *ProbeHarness) shapeMark() int {
	h.shapesMu.Lock()
	defer h.shapesMu.Unlock()
	return len(h.shapes)
}

// inertSince reports whether every probe response since mark was indistinguishable from the baseline:
// the same status and a body length within inertLengthTolerance. That is the response-shape half of
// Burp's "Skipped due to repetitive behavior". A point whose input changed what
// the application answered is not repetitive behaviour, whatever the evidence rules concluded. A point
// with no recorded probe is not inert either, because nothing was compared.
func (h *ProbeHarness) inertSince(mark int) bool {
	h.shapesMu.Lock()
	defer h.shapesMu.Unlock()
	if mark >= len(h.shapes) {
		return false
	}
	base := len(h.baseline.Body)
	tol := inertLengthTolerance(base)
	for _, sh := range h.shapes[mark:] {
		d := sh.bodyLen - base
		if d < 0 {
			d = -d
		}
		if sh.status != h.baseline.Status || d > tol {
			return false
		}
	}
	return true
}

// inertLengthTolerance is how far a body length may move and still read as the same page: 2% of the
// baseline or 32 bytes, whichever is larger. That is room for a timestamp or a CSRF token, not for an
// error message or a different template.
func inertLengthTolerance(baseLen int) int {
	return max(32, baseLen/50)
}

// NewProbeHarness captures the baseline and enumerates insertion points.
//
// It fails when there is no sender, no request to mutate, or no baseline response: each of
// those makes every downstream comparison meaningless, and returning a usable harness anyway
// would let a caller report "no evidence" for work that never happened.
func NewProbeHarness(ctx context.Context, cc *CheckContext, kinds []string) (*ProbeHarness, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, fmt.Errorf("probe harness: no scanner or exchange: %w", errCapabilityMissing)
	}
	s, exchange := cc.Scanner, cc.Exchange
	if s.sender == nil {
		return nil, fmt.Errorf("probe harness: no sender; an active probe cannot be sent: %w", errCapabilityMissing)
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
	h.typeIndex, h.issue, h.disabled, h.declines = cc.CheckTypeIndex, cc.CheckIssue, cc.DisabledMethods, cc.MethodDeclines
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
	gate := h.scanner.probeGate(ctx, h.exchange)
	if gate == nil {
		return ProbeResponse{}, errors.New("no authorised sender")
	}
	resp, _, err := h.sendVia(ctx, gate, raw)
	return resp, err
}

// sendVia is send through a gate the caller holds, returning the wire bytes as well as the readable
// response — a redirect follower needs the bytes as they arrived and the same gate the probe left
// through, so its hops are refused and counted on the counters the probe's own refusal would be.
func (h *ProbeHarness) sendVia(ctx context.Context, gate *sender.AuthorisedSender, raw []byte) (ProbeResponse, []byte, error) {
	// The per-probe clock, the same rule bcheck_runner.go applies through sendProbe. Without it a
	// native probe that never gets an answer rides the audit item's deadline — the WHOLE budget —
	// because gate.Send takes the dispatch context straight through. A target that accepts the
	// request and then blocks (an `&echo …` command-injection payload whose shell is left waiting
	// on a stdout that never closes is the live example) hung every audit of that exchange for the
	// full 120 s with no way to observe progress, which is the "a probe has no clock of its own"
	// gap ProbeTimeout documents itself as closing. Cancellation still propagates both ways: the
	// derived context is cancelled when the probe returns (defer), and a cancelled parent cancels
	// the probe.
	sendCtx := ctx
	if budget := probeBudgetFor(h.scanner); budget > 0 {
		var cancel context.CancelFunc
		sendCtx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}
	meter := meterFrom(ctx)
	meter.attempt()
	refusedBefore := gate.Refused()
	res, err := gate.Send(sendCtx, raw)
	if gate.Refused() > refusedBefore {
		meter.refusal()
		return ProbeResponse{}, nil, fmt.Errorf("refused: outside the engagement scope: %w", err)
	}
	if err != nil {
		meter.failure()
		return ProbeResponse{}, nil, err
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
	return out, res.Raw, nil
}

// SendFollowing is Send for a check that needs the page a redirect lands on (burpsy-react-ui-o2p3):
// when the run follows redirects and the probe's response is one, the chain is followed and its
// landing page rides the result as Followed. The 30x stays the response, so nothing the check reads
// from it changes; a run that does not follow returns exactly what Send would.
//
// Every hop is a request the run sent, so it is treated like one: authorised on its own rendered
// bytes by a fresh AuthorisedSender sharing the probe's scope handle and resource pool
// (sender.FollowRedirectsAfterPolicy), metered as an attempt with its outcome, and counted against the
// run's request budget. A hop the scope refused is a refusal on the probe's own gate.
func (h *ProbeHarness) SendFollowing(ctx context.Context, point bcheck.InsertionPoint, payload string) (ProbeResponse, error) {
	return h.SendFollowingOpts(ctx, point, payload, bcheck.ApplyOptions{})
}

// SendFollowingOpts is SendFollowing with the apply options (burpsy-react-ui-79ld): the decoding
// variants send payload bytes that must reach the wire verbatim — a percent-escape the
// application is meant to decode, an overlong or invalid UTF-8 sequence — so their probes pass
// ApplyOptions.Raw and every other behaviour of SendFollowing is unchanged.
func (h *ProbeHarness) SendFollowingOpts(ctx context.Context, point bcheck.InsertionPoint, payload string,
	opts bcheck.ApplyOptions) (ProbeResponse, error) {
	mutated, err := point.ApplyOpts(h.reqBytes, payload, false, opts)
	if err != nil {
		return ProbeResponse{}, fmt.Errorf("applying payload to %s %q: %w", point.Kind, point.Name, err)
	}
	gate := h.scanner.probeGate(ctx, h.exchange)
	if gate == nil {
		return ProbeResponse{}, errors.New("no authorised sender")
	}
	resp, wire, err := h.sendVia(ctx, gate, mutated)
	if err != nil {
		return resp, err
	}
	h.recordCoverage(&point, payload, resp)
	policy, follow := h.scanner.redirectPolicy(ctx)
	if !follow || resp.Status < 300 || resp.Status >= 400 {
		return resp, nil
	}
	h.follow(ctx, gate, mutated, wire, policy, &resp)
	return resp, nil
}

// follow walks the redirect chain that starts at a probe's response and attaches the landing page.
// A chain that cannot be followed is not an error: the 30x is the response, which is the truthful
// result, and the reason sits on the hop the follower recorded.
func (h *ProbeHarness) follow(ctx context.Context, gate *sender.AuthorisedSender, raw, wire []byte,
	policy sender.RedirectSettings, resp *ProbeResponse) {

	meter := meterFrom(ctx)
	refusedBefore := gate.Refused()
	result, err := gate.FollowRedirectsAfterPolicy(ctx, raw, wire, policy)
	for i := gate.Refused() - refusedBefore; i > 0; i-- {
		meter.attempt()
		meter.refusal()
	}
	if err != nil || result == nil {
		return
	}
	// The landing page is the LAST followed hop's own bytes, read off the hop rather than off
	// result.Final: a hop whose answer could not be parsed is still followed and keeps its bytes, but
	// Final stays the response before it, and attaching that would present a 30x as the landing page.
	var landedOn string
	var landedRaw []byte
	for _, hop := range result.Hops {
		switch {
		case hop.Followed:
			meter.attempt()
			meter.succeeded()
			landedOn, landedRaw = hop.To, hop.ResponseRaw
		case strings.HasPrefix(hop.Reason, "the hop was authorised but could not be sent"):
			meter.attempt()
			meter.failure()
		}
	}
	if landedOn == "" || len(landedRaw) == 0 {
		return
	}
	readable, _ := readableResponse(landedRaw)
	landing := ProbeResponse{Raw: readable, Body: responseBody(string(readable)), Status: responseStatus(string(readable))}
	resp.Followed = &landing
	resp.FollowedTo = landedOn
}

// Send places payload at point and dispatches the resulting request.
func (h *ProbeHarness) Send(ctx context.Context, point bcheck.InsertionPoint, payload string) (ProbeResponse, error) {
	return h.guidedSend(&point, payload, ctx)
}

// SendHTMLUpload re-sends a multipart file part as an HTML document — filename newName,
// Content-Type text/html, content the payload — Burp's file-upload HTML variant (kzt7).
func (h *ProbeHarness) SendHTMLUpload(ctx context.Context, point bcheck.InsertionPoint, payload, newName string) (ProbeResponse, error) {
	mutated, err := point.ApplyHTMLUpload(h.reqBytes, payload, newName)
	if err != nil {
		return ProbeResponse{}, fmt.Errorf("applying payload to %s %q: %w", point.Kind, point.Name, err)
	}
	resp, err := h.send(ctx, mutated)
	if err != nil {
		return resp, err
	}
	h.recordCoverage(&point, payload, resp)
	return resp, nil
}

// SendAppending is Send with the payload appended to the point's original value rather than
// replacing it — the blind SQL probes' placement: a condition or a sleep only parses in the
// statement when it follows the value the application put there (`5 and 1=1`, `seed' and '1'='1`).
// An empty payload re-sends the original request, the baseline re-fetch a confirmation needs.
func (h *ProbeHarness) SendAppending(ctx context.Context, point bcheck.InsertionPoint, payload string) (ProbeResponse, error) {
	mutated, err := point.Apply(h.reqBytes, payload, true)
	if err != nil {
		return ProbeResponse{}, fmt.Errorf("applying payload to %s %q: %w", point.Kind, point.Name, err)
	}
	resp, err := h.send(ctx, mutated)
	if err != nil {
		return resp, err
	}
	h.recordCoverage(&point, payload, resp)
	return resp, nil
}

// guidedSend applies the payload, sends, and folds the response into the coverage
// ledger — the one place a probe's response is recorded, so no probe path (direct Send,
// probe, or the baseline) can skip it.
func (h *ProbeHarness) guidedSend(point *bcheck.InsertionPoint, payload string, ctx context.Context) (ProbeResponse, error) {
	return h.guidedSendOpts(point, payload, bcheck.ApplyOptions{}, ctx)
}

// guidedSendOpts is guidedSend with an escape policy. The coverage ledger records the payload as
// written, not as escaped, so the guide orders by what the check asked for.
func (h *ProbeHarness) guidedSendOpts(point *bcheck.InsertionPoint, payload string, opts bcheck.ApplyOptions, ctx context.Context) (ProbeResponse, error) {
	mutated, err := point.ApplyOpts(h.reqBytes, payload, false, opts)
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
	if point != nil {
		h.shapesMu.Lock()
		h.shapes = append(h.shapes, probeShape{status: resp.Status, bodyLen: len(resp.Body)})
		h.shapesMu.Unlock()
	}
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
	return h.probeOpts(ctx, point, payload, bcheck.ApplyOptions{}, classify)
}

// probeOpts is probe with an escape policy: the apply options decide how the payload is spelled for
// its container, so a probe whose payload IS the escape (a traversal `..%2f`) can send it raw.
func (h *ProbeHarness) probeOpts(ctx context.Context, point bcheck.InsertionPoint, payload string,
	opts bcheck.ApplyOptions,
	classify func(baseline, injected ProbeResponse) (InjectionEvidence, string)) InjectionProbe {

	out := InjectionProbe{Payload: payload}
	injected, err := h.guidedSendOpts(&point, payload, opts, ctx)
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

// withhold is the detection-method gate every probe kind passes through (burpsy-react-ui-2hze). It
// answers whether a probe of this method may be sent for this check's issue type, and when it may
// not, it records the decline with the number of requests withheld — so a run under "all except
// time-based detection methods" can show that its timing probes were withheld, not that they ran
// clean.
//
// Keyed by the check's type because Burp resolves a method name inside its type (Zwx_.java:43-61):
// "Time delays" disabled for request smuggling says nothing about SQL injection.
func (h *ProbeHarness) withhold(method string, probes int) bool {
	if h == nil || !h.disabled[method] {
		return false
	}
	h.declines.Record(MethodDecline{TypeIndex: h.typeIndex, Issue: h.issue, Method: method,
		Reason: methodDisabledReason, ProbesWithheld: probes})
	return true
}

// withheldProbe is the marker a gated probe returns in place of a sent one.
func withheldProbe(point bcheck.InsertionPoint, payload, method string) InjectionProbe {
	return InjectionProbe{Payload: payload, Withheld: true, Evidence: InjectionEvidenceNone,
		Detail: fmt.Sprintf("%s %q: not sent — %s is disabled for this issue type", point.Kind, point.Name, method)}
}

// ProbeErrorSignatures sends each payload and looks for signatures the baseline did not have.
//
// The list is coverage-guided (burpsy-react-ui-6c90): payloads that have opened new
// response cells at this place on earlier exchanges are sent first — gofuzz's
// "mutate what discovered new blocks", restated for a place that has not answered
// yet. A place with no history gets the list exactly as written.
//
// The escape-then-probe form: the payload is escaped for its container (percent-escape for a `k=v`
// pair), so a payload carrying a literal `../` arrives decoded by the target's own parameter parser.
func (h *ProbeHarness) ProbeErrorSignatures(ctx context.Context, point bcheck.InsertionPoint,
	payloads []string, signatures []string) []InjectionProbe {
	return h.probeErrorSignatures(ctx, point, payloads, signatures, false)
}

// ProbeErrorSignaturesRaw is ProbeErrorSignatures with the Raw escape policy (burpsy-react-ui-79ld;
// j1mk.35): the payload's own bytes reach the wire verbatim. A traversal payload is the probe — a
// `..%2f` separator spelled for a filter that does a literal `..` contains-check, or a `%00`
// terminator the filesystem API honours and a string filter does not — and percent-escaping the `%`
// turns `..%2f` into `..%252f`, which the target decodes once to the literal two characters the
// application never decodes again. The default policy's own escape is what a traversal probe exists
// to get past, so this bank is sent raw.
func (h *ProbeHarness) ProbeErrorSignaturesRaw(ctx context.Context, point bcheck.InsertionPoint,
	payloads []string, signatures []string) []InjectionProbe {
	return h.probeErrorSignatures(ctx, point, payloads, signatures, true)
}

func (h *ProbeHarness) probeErrorSignatures(ctx context.Context, point bcheck.InsertionPoint,
	payloads []string, signatures []string, raw bool) []InjectionProbe {

	payloads = h.boundPayloads(payloads)
	out := make([]InjectionProbe, 0, len(payloads))
	if h.withhold(MethodErrorMessages, len(payloads)) {
		for _, payload := range payloads {
			out = append(out, withheldProbe(point, payload, MethodErrorMessages))
		}
		return out
	}
	payloads = h.orderPayloads(point, payloads)
	for _, payload := range payloads {
		out = append(out, h.probeOpts(ctx, point, payload, bcheck.ApplyOptions{Raw: raw},
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

	if h.withhold(MethodStringEcho, 1) {
		return withheldProbe(point, payload, MethodStringEcho)
	}
	return h.probe(ctx, point, payload,
		func(baseline, injected ProbeResponse) (InjectionEvidence, string) {
			ev := ClassifyEvaluation(baseline.Body, injected.Body, payload, expected)
			return ev, fmt.Sprintf("looking for %q: %s", expected, ev)
		})
}

// ProbeEvaluationConfirmed is the evaluation probe for a payload whose proof is computed
// (burpsy-react-ui-j1mk.34). render is called once per send and must return a payload carrying a
// FRESH challenge each time, plus the value only evaluation of that payload can produce.
//
// Two controls, both required for a verdict of Evaluated:
//
//   - the expected value must not be spelled anywhere in the payload. A proof the payload carries
//     is a proof any reflection carries, and subtracting the echo only works when the reflection
//     is byte-faithful — a JSON `\n`, a doubled quote or a half-escaped value defeats it. A render
//     that breaks this is refused as Inconclusive rather than trusted.
//   - the first hit is re-asked with a second, independent challenge, and only a second hit
//     confirms. A response that contained the first product by chance (a token, a timestamp, an
//     error code) will not contain an unrelated second one; an interpreter will.
//
// A hit that does not reproduce is Inconclusive, not None: something produced the value once, and
// the honest report is "undecided", never "clean".
func (h *ProbeHarness) ProbeEvaluationConfirmed(ctx context.Context, point bcheck.InsertionPoint,
	render func() (payload, expected string)) InjectionProbe {

	payload, expected := render()
	if h.withhold(MethodStringEcho, 1) {
		return withheldProbe(point, payload, MethodStringEcho)
	}
	classify := func(payload, expected string) func(baseline, injected ProbeResponse) (InjectionEvidence, string) {
		return func(baseline, injected ProbeResponse) (InjectionEvidence, string) {
			if expected == "" || strings.Contains(payload, expected) {
				return InjectionEvidenceInconclusive, fmt.Sprintf("looking for %q: the payload itself spells it, so a reflection cannot be told from evaluation", expected)
			}
			ev := ClassifyEvaluation(baseline.Body, injected.Body, payload, expected)
			return ev, fmt.Sprintf("looking for %q: %s", expected, ev)
		}
	}
	first := h.probe(ctx, point, payload, classify(payload, expected))
	if first.Evidence != InjectionEvidenceEvaluated {
		return first
	}
	payload2, expected2 := render()
	if payload2 == payload || expected2 == expected {
		first.Evidence = InjectionEvidenceInconclusive
		first.Detail += "; not confirmed: the render gave no independent second challenge"
		return first
	}
	second := h.probe(ctx, point, payload2, classify(payload2, expected2))
	if second.Evidence != InjectionEvidenceEvaluated {
		first.Evidence = InjectionEvidenceInconclusive
		first.Detail += fmt.Sprintf("; did not reproduce with a second challenge (%s)", second.Detail)
		return first
	}
	first.Detail += fmt.Sprintf("; reproduced with an independent second challenge, %q evaluated to %q", payload2, expected2)
	return first
}

// ProbeTiming sends payload and reports whether the delay it requested was observed. The
// baseline duration is the reference, so a uniformly slow endpoint does not read as
// injectable.
func (h *ProbeHarness) ProbeTiming(ctx context.Context, point bcheck.InsertionPoint,
	payload string, delay time.Duration) InjectionProbe {

	if h.withhold(MethodTimeDelays, 1) {
		return withheldProbe(point, payload, MethodTimeDelays)
	}
	return h.probe(ctx, point, payload,
		func(baseline, injected ProbeResponse) (InjectionEvidence, string) {
			ev := ClassifyTimingEvidence(baseline.Duration, injected.Duration, delay)
			return ev, fmt.Sprintf("baseline %s, injected %s, requested %s: %s",
				baseline.Duration, injected.Duration, delay, ev)
		})
}

// ProbeTimingUnder sends a time-based probe gated by every method that governs it — the
// generic Time delays switch plus the dialect-specific one when the payload is dialect-only
// (burpsy-react-ui-saq3.2.1). A PostgreSQL pg_sleep probe is withheld when either PostgreSQL
// specific or Time delays is disabled, because Burp's UI offers both switches over the same
// request; withholding on the first disabled method found keeps the decline legible (one
// reason, not a list) while the count still says how many requests did not leave.
func (h *ProbeHarness) ProbeTimingUnder(ctx context.Context, point bcheck.InsertionPoint,
	payload string, delay time.Duration, methods []string) InjectionProbe {

	for _, method := range methods {
		if h.withhold(method, 1) {
			return withheldProbe(point, payload, method)
		}
	}
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
	if h.withhold(MethodBooleanConditions, 2) {
		return withheldProbe(point, out.Payload, MethodBooleanConditions)
	}
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
	// PayloadsWithheld counts probes not sent because their detection method is disabled for this
	// issue type (burpsy-react-ui-2hze). They are not in PayloadsSent: a withheld probe asked nothing.
	PayloadsWithheld int
}

// Coverage summarises a probe set for reporting.
func (h *ProbeHarness) Coverage(probes []InjectionProbe, pointsTested int) ProbeCoverage {
	cov := ProbeCoverage{
		PointsTested:   pointsTested,
		PointsDeclined: len(h.declined),
	}
	for _, p := range probes {
		if p.Withheld {
			cov.PayloadsWithheld++
			continue
		}
		cov.PayloadsSent++
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
