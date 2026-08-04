package web

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// ---- Live active audit ------------------------------------------------------------------------
//
// Mirrors crates/web/src/routes/liveaudit.rs: a switch plus two counters, owned by the web
// server (which holds the scanner) and flipped by the UI. The sweep itself is a background
// loop, bounded the way the Rust one is: walk newly-completed in-scope exchanges in id order
// (append-only store, so position is the id), hand a batch to the active scanner, and record
// what happened. An exchange whose response has not landed simply waits for a later tick.

// LiveAuditState is the operator-visible state of the live sweep: whether it is enabled and
// how many exchanges/findings the sweep has accumulated so far.
type LiveAuditState struct {
	enabled  atomic.Bool
	swept    atomic.Uint64
	findings atomic.Uint64
}

// NewLiveAuditState creates a disabled live audit state.
func NewLiveAuditState() *LiveAuditState {
	return &LiveAuditState{}
}

// IsEnabled reports whether the sweep loop should run.
func (la *LiveAuditState) IsEnabled() bool { return la.enabled.Load() }

// SetEnabled flips the switch.
func (la *LiveAuditState) SetEnabled(on bool) { la.enabled.Store(on) }

// Record accumulates the outcome of one sweep tick.
func (la *LiveAuditState) Record(swept, findings uint64) {
	la.swept.Add(swept)
	la.findings.Add(findings)
}

// Swept returns the total exchanges handed to the scanner.
func (la *LiveAuditState) Swept() uint64 { return la.swept.Load() }

// FindingCount returns the total findings the sweep produced.
func (la *LiveAuditState) FindingCount() uint64 { return la.findings.Load() }

// liveAuditView mirrors dashboard.ts's LiveAuditResp.
type liveAuditView struct {
	Wired    bool   `json:"wired"`
	Enabled  bool   `json:"enabled"`
	Hint     string `json:"hint,omitempty"`
	Swept    uint64 `json:"swept,omitempty"`
	Findings uint64 `json:"findings,omitempty"`
}

// liveAuditUnwired reports a 200 with wired:false rather than a 404, matching the other
// feature surfaces so an unwired process does not look like a typo in the route.
func liveAuditUnwired() liveAuditView {
	return liveAuditView{
		Wired:   false,
		Enabled: false,
		Hint:    "live active audit needs a loaded check set; start with --bchecks",
	}
}

func (s *Server) liveAuditStatus() liveAuditView {
	if s.liveAudit == nil {
		return liveAuditUnwired()
	}
	return liveAuditView{
		Wired:    true,
		Enabled:  s.liveAudit.IsEnabled(),
		Swept:    s.liveAudit.Swept(),
		Findings: s.liveAudit.FindingCount(),
	}
}

// StartLiveAuditSweep launches the background sweep loop. It walks newly-completed
// in-scope exchanges in id order and hands batches to the active scanner while enabled.
// The caller owns the context; when it is cancelled the loop stops at the next tick.
func (s *Server) StartLiveAuditSweep(ctx context.Context) {
	if s.liveAudit == nil {
		s.liveAudit = NewLiveAuditState()
	}
	go s.liveAuditLoop(ctx)
}

func (s *Server) liveAuditLoop(ctx context.Context) {
	var highWater uint64
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.liveAudit.IsEnabled() {
				continue
			}
			s.liveAuditTick(ctx, &highWater)
		}
	}
}

// liveAuditTick collects one bounded batch of newly-completed in-scope exchanges and hands
// them to the scanner, recording the outcome. Sequential and bounded rather than
// exhaustive: an exchange whose response has not landed waits for a later tick, and
// everything after it waits with it.
func (s *Server) liveAuditTick(ctx context.Context, highWater *uint64) {
	_, total := s.store.Count()
	ids := make([]uint64, 0, 200)
	next := *highWater
	for next < uint64(total) && len(ids) < 200 {
		ex, err := s.store.GetExchange(next)
		if err != nil {
			break
		}
		if ex.Response == nil {
			break
		}
		if s.scope.Contains(ex.Host, ex.Port, ex.Path, ex.TLS) {
			ids = append(ids, next)
		}
		next++
	}
	if next == *highWater {
		return
	}
	*highWater = next
	if len(ids) == 0 {
		return
	}

	if s.scanner == nil {
		s.logger.Warn("live audit enabled but no active scanner wired")
		return
	}
	start := time.Now()
	// AuditSession rather than AuditMultiple: this is the highest-volume audit path in the process, so
	// it is where the engine's bounding pays for itself — a sweep over 200 captures of one host
	// dispatches each per-URL check once and refuses the rest as already covered. The session outcome
	// is the only place that saving is visible, and a sweep that reported "200 exchanges, 3 findings"
	// while quietly admitting a fraction of the work would be the exact claim the engine exists to
	// prevent.
	outcome, findings := s.scanner.AuditSession(ctx, ids, s.scanner.AuditConfig())
	for _, f := range findings {
		s.findings.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
		})
	}
	if ex, err := s.store.GetExchange(ids[0]); err == nil {
		s.toolLog.Record(toollog.ToolScanner, ex.Host, ex.Port, ex.TLS, "LIVE", "/audit", 0, uint64(time.Since(start).Milliseconds()), "")
	}
	s.liveAudit.Record(uint64(len(ids)), uint64(len(findings)))
	s.logger.Debug("live audit sweep",
		zap.Int("exchanges", len(ids)),
		zap.Int("findings", len(findings)),
		zap.String("engine", outcome.Summary()),
		zap.Duration("took", time.Since(start)))
	// A sweep the failure breaker stopped is not a sweep that found nothing, and it is worth more than
	// a debug line: the next tick will start again against a target that has already stopped answering.
	if outcome.Paused || outcome.TimedOut {
		s.logger.Warn("live audit sweep was bounded before it finished",
			zap.Int("exchanges", len(ids)),
			zap.Int("checks_not_admitted", outcome.NotAdmitted()),
			zap.Bool("paused", outcome.Paused),
			zap.Bool("timed_out", outcome.TimedOut))
	}
}
