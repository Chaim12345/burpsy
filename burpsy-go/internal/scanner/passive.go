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
	Errors              []LoadError
}

// LoadError names one file the parser refused.
type LoadError struct {
	File string
	Err  string
}

// Summary formats the report the way the Rust CLI logs at startup.
func (r LoadReport) Summary() string {
	return fmt.Sprintf(
		"%d files: %d passive, %d active, %d collaborator, %d need insertion point, %d parse errors",
		r.Files, r.Passive, r.Active, r.Collaborator, r.NeedsInsertionPoint, len(r.Errors),
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
	}
	return buildPassiveScanner(store, scope, logger, checks, report), nil
}

// buildPassiveScanner splits an already-parsed corpus into passive and active
// buckets, mirroring crates/scanner/src/lib.rs PassiveScanner::build.
func buildPassiveScanner(store *core.TrafficStore, scope *core.Scope, logger *zap.Logger, checks []*bcheck.Check, report LoadReport) *PassiveScanner {
	passive := make([]*bcheck.Check, 0, len(checks))
	active := make([]*bcheck.Check, 0)
	for _, c := range checks {
		switch {
		case c.NeedsCollaborator():
			report.Collaborator++
		case c.IsPassive():
			report.Passive++
			passive = append(passive, c)
		case c.M2Runnable():
			report.Active++
			active = append(active, c)
		default:
			report.NeedsInsertionPoint++
		}
	}
	return &PassiveScanner{
		store:    store,
		logger:   logger,
		scope:    scope,
		passive:  passive,
		active:   active,
		report:   report,
		coverage: newCoverageTracker(passive),
	}
}

// Loaded returns how many passive BCheck files will run on each response.
func (s *PassiveScanner) Loaded() int {
	return len(s.passive)
}

// ActiveLoaded returns how many active checks were classified at load time.
func (s *PassiveScanner) ActiveLoaded() int {
	return len(s.active)
}

// Report returns the startup classification for this scanner.
func (s *PassiveScanner) Report() LoadReport {
	return s.report
}

// Coverage returns a point-in-time snapshot of passive check runtime coverage.
func (s *PassiveScanner) Coverage() CoverageReport {
	if s.coverage == nil {
		return CoverageReport{}
	}
	return s.coverage.Snapshot()
}

// scanBChecks runs the loaded passive set against one exchange.
func (s *PassiveScanner) scanBChecks(exchange *core.Exchange) []*Finding {
	if len(s.passive) == 0 {
		if s.coverage != nil {
			s.coverage.RecordSkip(ScanSkipNoChecksLoaded)
		}
		return nil
	}
	if exchange == nil {
		if s.coverage != nil {
			s.coverage.RecordSkip(ScanSkipExchangeNotFound)
		}
		return nil
	}
	if s.scope != nil && !s.scope.Contains(exchange.Host, exchange.Port, exchange.Path, exchange.TLS) {
		if s.coverage != nil {
			s.coverage.RecordSkip(ScanSkipOutOfScope)
		}
		return nil
	}
	if exchange.Response == nil {
		if s.coverage != nil {
			s.coverage.RecordSkip(ScanSkipResponseNotFound)
		}
		return nil
	}
	resp, err := s.store.Get(*exchange.Response)
	if err != nil {
		if s.coverage != nil {
			s.coverage.RecordSkip(ScanSkipResponseNotFound)
		}
		return nil
	}
	ctx := bcheck.NewContext()
	ctx.Response = resp.Raw()
	ctx.Host = exchange.Host
	ctx.Port = exchange.Port
	ctx.Path = exchange.Path
	ctx.TLS = exchange.TLS
	if req, err := s.store.Get(exchange.Request); err == nil {
		ctx.Request = req.Raw()
	}

	deltas := make([]ScanDelta, len(s.passive))
	var out []*Finding
	for i, check := range s.passive {
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
	if s.coverage != nil {
		s.coverage.RecordScan(deltas)
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
