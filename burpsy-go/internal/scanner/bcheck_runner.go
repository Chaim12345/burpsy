// The scanner's half of the active bcheck pipeline: turning a loaded corpus
// check into an audit-engine check, and adapting the evaluator's Sink to this
// scanner's meter and egress chokepoint.
//
// # The chokepoint holds for corpus probes too
//
// The evaluator asks for raw request bytes to go to a named target. Those bytes
// are the check's to choose; the connection is not. Every send here goes through
// sender.AuthorisedSender bound to the scanned exchange's own authority, so a
// raw `send request` whose text names another Host is refused — the same gate
// every other constructed request in the process passes, and the same one the
// no_alternate_egress discipline exists to keep singular.
//
// # Metering
//
// The probe meter rides on the audit item's context (see meterKey), so a corpus
// check's sends count toward the request budget exactly like the built-in
// checks' do, and the engine can tell "ran, saw a probe response" from "tried
// to send and could not".
package scanner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// errCheckUnsupported is the runner's refusal: the evaluator cannot run this
// check at all, so it proves nothing. auditItem maps it to
// DispositionUnsupported (Skipped) rather than counting a clean miss.
var errCheckUnsupported = errors.New("bcheck: check cannot be evaluated")

// errCheckInconclusive: the check ran but could not decide. Counted as Unmeasurable, not clean.
var errCheckInconclusive = errors.New("scanner: check ran but its evidence was inconclusive")

// bcheckSink adapts the evaluator's Sink to this scanner: every send is metered
// and passes through the AuthorisedSender bound to the scanned exchange.
type bcheckSink struct {
	sc          *ActiveScanner
	ctx         context.Context
	ex          *core.Exchange
	meter       *probeMeter
	probeBudget time.Duration
	// check names the corpus check this sink serves. A corpus check chooses its own
	// payloads, so the coverage ledger cannot attribute novelty to a payload the way
	// ProbeHarness's guide can — but every probe still reaches a path, and the cell
	// it lands in is recorded per check name so the coverage report can say which
	// corpus checks opened new ground.
	check string
}

// Send writes raw request bytes to the bound target through the same gate every
// other constructed request in the process passes.
func (k *bcheckSink) Send(target *bcheck.Target, raw []byte) ([]byte, error) {
	if k.sc.sender == nil {
		// No sender means the caller built the scanner without egress — the same
		// offline posture sendTestRequest supports. A probe that cannot leave
		// abandons the check rather than judging from a stored response a
		// payload never produced.
		k.meter.attempt()
		k.meter.failure()
		return nil, errors.New("no sender configured for active bcheck probes")
	}
	k.meter.attempt()
	gate := k.sc.probeGate(k.ex)
	resp, err := sendProbe(k.ctx, gate, raw, k.probeBudget)
	if gate.Refused() > 0 {
		// A refusal counts as a failure too: nothing left the process, so the
		// check saw no probe response either way. (probeMeter.refusal already
		// also increments the failure count.)
		k.meter.refusal()
		return nil, errors.New("probe refused: outside the engagement scope")
	}
	if err != nil {
		k.meter.failure()
		return nil, err
	}
	k.meter.succeeded()
	// Coverage guidance (burpsy-react-ui-6c90): a corpus check's probe reached a
	// path of the target, and the cell it landed in is recorded per exchange and
	// check name. The guide cannot score these probes by payload — the check
	// script chooses its own — but the coverage half of the loop is the same one
	// the built-in checks feed.
	if k.sc.pathCov != nil {
		raw := string(resp)
		k.sc.pathCov.Record(fmt.Sprintf("%d", k.ex.ID), responseStatus(raw), len(responseBody(raw)))
	}
	return resp, nil
}

// corpusActiveChecks builds one audit-engine check per loaded corpus check the
// engine can dispatch, scoped by the check's own `given` clause.
//
// A check whose `given` has no active dispatch scope — a `given response` check
// with outbound sends — is left out rather than guessed at: PassiveScanner's
// ActiveChecks already excludes the passive set, and this guard covers the
// remainder rather than dispatching them under an invented scope.
// corpusActiveChecks builds the dispatch set for the loaded corpus's active checks from a corpus
// slice the caller already read under the config lock. toolRunner is read directly: it is
// installed once at construction and never mutated afterwards.
func (s *ActiveScanner) corpusActiveChecks(corpus []*bcheck.Check) []activeCheck {
	out := make([]activeCheck, 0, len(corpus))
	for _, c := range corpus {
		scope, ok := DispatchScopeForGiven(c.Given)
		if !ok {
			continue
		}
		// A check carrying `send payload` can only run where there is an insertion point to
		// place it: `given … insertion point`. M2Runnable is false for exactly those checks, so
		// a non-insertion-point scope with a non-M2 check is one whose payload has nowhere to
		// go — dispatch would fail it as ActiveNeedsPoint on every run. Left out rather than
		// dispatched, and still counted as NeedsInsertionPoint by the load report, which is the
		// honest place for a check the engine structurally cannot verdict.
		if scope != DispatchScopePerInsertionPoint && !c.M2Runnable() {
			continue
		}
		// A check that needs an external tool cannot run without the allowlist
		// runner. Left out of the dispatch set — and counted as LoadReport.Tools
		// at load time — rather than admitted and failed as ActiveUnsupported on
		// every exchange, which would log the same refusal per item.
		if c.NeedsTool() && s.toolRunner == nil {
			continue
		}
		cc := c
		out = append(out, activeCheck{
			name:  cc.Name,
			scope: scope,
			enabled: func(cfg *ScanConfig) bool {
				return cfg != nil && cfg.CheckCorpus
			},
			run: func(sc *ActiveScanner, ctx context.Context, ex *core.Exchange) ([]*Finding, error) {
				return sc.runBCheckCorpus(ctx, ex, cc)
			},
		})
	}
	return out
}

// runBCheckCorpus evaluates one loaded corpus check against one exchange,
// sending its probes through the meter and the chokepoint.
func (s *ActiveScanner) runBCheckCorpus(ctx context.Context, ex *core.Exchange, check *bcheck.Check) ([]*Finding, error) {
	if ex == nil || ex.Response == nil {
		return nil, errCheckUnsupported
	}
	resp, err := s.store.Get(*ex.Response)
	if err != nil {
		return nil, errCheckUnsupported
	}
	bctx := bcheck.NewContext()
	// Readable, like the probe responses sendProbe hands the check (s68u).
	bctx.Response, _ = readableResponse(resp.Raw())
	bctx.Host = ex.Host
	bctx.Port = ex.Port
	bctx.TLS = ex.TLS
	bctx.Path = ex.Path
	// The request is optional: a host-given check can run on the response
	// alone, but an insertion-point or `send request` check needs the bytes and
	// will refuse (SendFailed) rather than guess.
	if req, err := s.store.Get(core.MsgOrZero(ex.Request)); err == nil {
		bctx.Request = req.Raw()
	}
	sink := &bcheckSink{sc: s, ctx: ctx, ex: ex, meter: meterFrom(ctx), probeBudget: probeBudgetFor(s), check: check.Name}
	// The tool runner rides the context like the sink: the evaluator asks for a
	// named tool, this scanner resolves it through the allowlist. Nil keeps the
	// pre-tool behaviour — a check that somehow reaches `run tool` without one
	// is refused by the evaluator, never skipped.
	bctx.SetToolRunner(s.toolRunner)
	findings, rerr := bcheck.RunActive(check, bctx, sink, &bcheck.Target{
		Host: ex.Host,
		Port: ex.Port,
		TLS:  ex.TLS,
	})
	if rerr != nil {
		var ae *bcheck.ActiveError
		if errors.As(rerr, &ae) && ae.Kind == bcheck.ActiveUnsupported {
			if s.logger != nil {
				s.logger.Warn("active bcheck unsupported",
					zap.String("check", check.Name),
					zap.Uint64("exchange_id", uint64(ex.ID)),
					zap.String("reason", ae.Error()))
			}
			return nil, errCheckUnsupported
		}
		if s.logger != nil {
			s.logger.Warn("active bcheck failed",
				zap.String("check", check.Name),
				zap.Uint64("exchange_id", uint64(ex.ID)),
				zap.Error(rerr))
		}
		return nil, rerr
	}
	if decl := bctx.Declined(); len(decl) > 0 && s.logger != nil {
		s.logger.Warn("active bcheck declined insertion places",
			zap.String("check", check.Name),
			zap.Uint64("exchange_id", uint64(ex.ID)),
			zap.Strings("declined", decl))
	}
	if un := bctx.Unresolved(); len(un) > 0 && s.logger != nil {
		s.logger.Warn("active bcheck referenced paths it could not supply",
			zap.String("check", check.Name),
			zap.Uint64("exchange_id", uint64(ex.ID)),
			zap.Strings("unresolved", un))
	}
	out := make([]*Finding, 0, len(findings))
	for _, f := range findings {
		// The same conversion and catalogue enrichment the passive set uses, so
		// a corpus check's finding means the same thing whichever scanner
		// produced it.
		converted := bcheckFindingToScannerFinding(f, ex)
		EnrichFinding(converted)
		out = append(out, converted)
	}
	return out, nil
}
