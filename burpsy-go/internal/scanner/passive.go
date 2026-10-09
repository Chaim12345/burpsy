package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// LoadReport is the load-time classification of a BCheck corpus. It is distinct
// from runtime coverage: this records what was parsed and bucketed at startup,
// not which checks ran on live traffic.
type LoadReport struct {
	Files               int
	Passive             int
	Active              int
	Collaborator        int
	NeedsInsertionPoint int
	// Tools counts checks that invoke an external tool via `run tool`. Such
	// checks are never passive and are only dispatchable when the caller
	// attached a tool runner; without one they are counted here and refused,
	// exactly like the Collaborator bucket.
	Tools  int
	Errors []LoadError
}

// LoadError names one file the parser refused.
type LoadError struct {
	File string
	Err  string
}

// Summary formats the report the way the Rust CLI logs at startup.
func (r LoadReport) Summary() string {
	return fmt.Sprintf(
		"%d files: %d passive, %d active, %d collaborator, %d need insertion point, %d need tools, %d parse errors",
		r.Files, r.Passive, r.Active, r.Collaborator, r.NeedsInsertionPoint, r.Tools, len(r.Errors),
	)
}

// LoadDir reads every `.bcheck` under dir, classifies them, and returns a
// PassiveScanner ready to run the passive set on captured responses.
func LoadDir(dir string, store *core.TrafficStore, scope *core.Scope, logger *zap.Logger) (*PassiveScanner, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".bcheck") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	report := LoadReport{Files: len(files)}
	var checks []*bcheck.Check
	var entries []checkEntry
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			report.Errors = append(report.Errors, LoadError{File: path, Err: err.Error()})
			continue
		}
		c, err := bcheck.Parse(string(src))
		if err != nil {
			report.Errors = append(report.Errors, LoadError{File: path, Err: err.Error()})
			continue
		}
		checks = append(checks, c)
		entries = append(entries, checkEntry{check: c, source: string(src), origin: path})
	}
	ps := buildPassiveScanner(store, scope, logger, checks, report)
	ps.entries, ps.dir, ps.fromDir = entries, dir, true
	ps.dirErrs, ps.dirFiles = report.Errors, report.Files
	return ps, nil
}

// buildPassiveScanner splits an already-parsed corpus into passive and active
// buckets, mirroring crates/scanner/src/lib.rs PassiveScanner::build.
func buildPassiveScanner(store *core.TrafficStore, scope *core.Scope, logger *zap.Logger, checks []*bcheck.Check, report LoadReport) *PassiveScanner {
	passive, active, insertion, tools, report := classifyChecks(checks, report)
	return &PassiveScanner{
		store:     store,
		logger:    logger,
		scope:     scope,
		passive:   passive,
		active:    active,
		insertion: insertion,
		tools:     tools,
		report:    report,
		coverage:  newCoverageTracker(passive),
	}
}

// classifyChecks splits a parsed corpus into the passive, active, insertion-point and tool buckets
// and counts each into the report — shared by the startup load and every console change (kbu1).
func classifyChecks(checks []*bcheck.Check, report LoadReport) (passive, active, insertion, tools []*bcheck.Check, _ LoadReport) {
	passive = make([]*bcheck.Check, 0, len(checks))
	active = make([]*bcheck.Check, 0)
	insertion = make([]*bcheck.Check, 0)
	tools = make([]*bcheck.Check, 0)
	for _, c := range checks {
		switch {
		case c.NeedsCollaborator():
			report.Collaborator++
		case c.NeedsTool():
			// Never passive — it executes an external process — and active only
			// when a caller attaches a tool runner. Counted here regardless, and
			// kept for ActiveChecks so the active engine can dispatch it under
			// the runner's allowlist. The scanner's corpusActiveChecks applies
			// the nil-runner gate; this bucket is the honest load-time count.
			report.Tools++
			tools = append(tools, c)
		case c.IsPassive():
			report.Passive++
			passive = append(passive, c)
		case c.M2Runnable():
			report.Active++
			active = append(active, c)
		default:
			// Active but not M2-runnable: `given insertion point`, or any check
			// carrying `send payload`. Counted as before, and now also kept for
			// the active engine — see ActiveChecks.
			report.NeedsInsertionPoint++
			insertion = append(insertion, c)
		}
	}
	return passive, active, insertion, tools, report
}

// Loaded returns how many passive BCheck files will run on each response.
func (s *PassiveScanner) Loaded() int {
	s.setsMu.RLock()
	defer s.setsMu.RUnlock()
	return len(s.passive)
}

// ActiveLoaded returns how many active checks were classified at load time.
func (s *PassiveScanner) ActiveLoaded() int {
	s.setsMu.RLock()
	defer s.setsMu.RUnlock()
	return len(s.active)
}

// ActiveChecks returns the corpus checks the active audit engine can dispatch,
// in load order: the M2-runnable set (`given host` / `path` / `request`) plus
// the insertion-point set (`given insertion point`, or any check carrying
// `send payload`), plus the tool set (`run tool`, which the ActiveScanner
// gates on its configured runner). Passive and collaborator checks are
// excluded here — the passive set is this scanner's own, and a collaborator
// check cannot run without an interaction server.
//
// A fresh slice each call: the caller (the ActiveScanner) must be free to hold
// it without this scanner's later loads mutating it under it.
func (s *PassiveScanner) ActiveChecks() []*bcheck.Check {
	s.setsMu.RLock()
	defer s.setsMu.RUnlock()
	out := make([]*bcheck.Check, 0, len(s.active)+len(s.insertion)+len(s.tools))
	out = append(out, s.active...)
	out = append(out, s.insertion...)
	out = append(out, s.tools...)
	return out
}

// Report returns the startup classification for this scanner.
func (s *PassiveScanner) Report() LoadReport {
	s.setsMu.RLock()
	defer s.setsMu.RUnlock()
	return s.report
}

// Coverage returns a point-in-time snapshot of passive check runtime coverage.
func (s *PassiveScanner) Coverage() CoverageReport {
	s.setsMu.RLock()
	cov := s.coverage
	s.setsMu.RUnlock()
	if cov == nil {
		return CoverageReport{}
	}
	return cov.Snapshot()
}

// scanBChecks runs the loaded passive set against one exchange.
func (s *PassiveScanner) scanBChecks(exchange *core.Exchange) []*Finding {
	// One generation of the check set: the passive list and the coverage table it is index-aligned
	// with are read together, so a console import mid-scan cannot misalign the deltas.
	s.setsMu.RLock()
	passive, coverage := s.passive, s.coverage
	s.setsMu.RUnlock()
	if len(passive) == 0 {
		if coverage != nil {
			coverage.RecordSkip(ScanSkipNoChecksLoaded)
		}
		return nil
	}
	if exchange == nil {
		if coverage != nil {
			coverage.RecordSkip(ScanSkipExchangeNotFound)
		}
		return nil
	}
	if s.scope != nil && !s.scope.Contains(exchange.Host, exchange.Port, exchange.Path, exchange.TLS) {
		if coverage != nil {
			coverage.RecordSkip(ScanSkipOutOfScope)
		}
		return nil
	}
	if exchange.Response == nil {
		if coverage != nil {
			coverage.RecordSkip(ScanSkipResponseNotFound)
		}
		return nil
	}
	resp, err := s.store.Get(*exchange.Response)
	if err != nil {
		if coverage != nil {
			coverage.RecordSkip(ScanSkipResponseNotFound)
		}
		return nil
	}
	ctx, undecoded := s.passiveContext(exchange, resp.Raw())
	if undecoded && coverage != nil {
		coverage.RecordUndecoded()
	}

	deltas := make([]ScanDelta, len(passive))
	var out []*Finding
	for i, check := range passive {
		found, err := bcheck.RunPassive(check, ctx)
		if err != nil {
			deltas[i] = ScanDelta{Err: err.Error()}
			if s.logger != nil {
				s.logger.Warn("passive bcheck errored",
					zap.String("check", check.Name),
					zap.Error(err))
			}
			continue
		}
		deltas[i] = ScanDelta{Findings: uint64(len(found))}
		for _, f := range found {
			finding := bcheckFindingToScannerFinding(f, exchange)
			EnrichFinding(finding)
			out = append(out, finding)
		}
	}
	if coverage != nil {
		coverage.RecordScan(deltas)
	}
	return out
}

func bcheckFindingToScannerFinding(f bcheck.Finding, exchange *core.Exchange) *Finding {
	name := f.IssueName
	if name == "" {
		name = f.CheckName
	}
	if name == "" {
		name = "BCheck finding"
	}
	return &Finding{
		Name:        name,
		Severity:    mapBCheckSeverity(f.Severity),
		Confidence:  mapBCheckConfidence(f.Confidence),
		Description: f.Description,
		Solution:    f.Remediation,
		Param:       f.Param,
		ExchangeID:  exchange.ID,
		Timestamp:   time.Now(),
	}
}

func mapBCheckSeverity(s bcheck.Severity) string {
	switch s {
	case bcheck.SeverityHigh:
		return "high"
	case bcheck.SeverityMedium:
		return "medium"
	case bcheck.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func mapBCheckConfidence(c bcheck.Confidence) string {
	switch c {
	case bcheck.ConfidenceCertain:
		return "certain"
	case bcheck.ConfidenceFirm:
		return "firm"
	default:
		return "tentative"
	}
}

// passiveContext is the evaluation context a passive check sees for one exchange: the response as
// the application sent it — dechunked and decompressed (jgnf), so a check matching a body reads text,
// not gzip — and the request, when it was stored.
func (s *PassiveScanner) passiveContext(exchange *core.Exchange, rawResponse []byte) (*bcheck.Context, bool) {
	ctx := bcheck.NewContext()
	readable, undecoded := readableResponse(rawResponse)
	ctx.Response = readable
	ctx.Host = exchange.Host
	ctx.Port = exchange.Port
	ctx.Path = exchange.Path
	ctx.TLS = exchange.TLS
	if req, err := s.store.Get(core.MsgOrZero(exchange.Request)); err == nil {
		ctx.Request = req.Raw()
	}
	return ctx, undecoded
}

// TrialPassiveCheck runs one passive check against one captured exchange exactly as the passive
// scanner would, for a console test run (kbu1). Nothing is sent, and the result is not recorded as
// coverage — a test of a draft is not a scan.
func (s *PassiveScanner) TrialPassiveCheck(exchange *core.Exchange, check *bcheck.Check) CheckTrial {
	if exchange == nil || exchange.Response == nil {
		return CheckTrial{err: errCheckUnsupported, Unsupported: "the exchange has no stored response"}
	}
	resp, err := s.store.Get(*exchange.Response)
	if err != nil {
		return CheckTrial{err: errCheckUnsupported, Unsupported: "the exchange's response could not be read"}
	}
	ctx, _ := s.passiveContext(exchange, resp.Raw())
	found, err := bcheck.RunPassive(check, ctx)
	trial := CheckTrial{Unresolved: ctx.Unresolved(), Declined: ctx.Declined()}
	if err != nil {
		trial.err = err
		return trial
	}
	for _, f := range found {
		finding := bcheckFindingToScannerFinding(f, exchange)
		EnrichFinding(finding)
		trial.Findings = append(trial.Findings, finding)
	}
	return trial
}
