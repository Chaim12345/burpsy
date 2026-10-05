package web

import (
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// restoreProjectScanState loads the PROJECT-level scan state from p: the scan-configuration overrides
// (config_level.go declares scanner_config project-level) and the live sweep's seen ledger
// (burpsy-react-ui-z4ml).
//
// Called from WithPersist, so it runs at startup and again on every in-console project switch. Before
// this both were loaded once, in main.go, so after a switch the console kept the OUTGOING project's
// scan overrides and audit history — and the next save of either wrote the outgoing project's values
// into the incoming project's file. User-level settings (the network path, upstream proxy, proxy
// options) are deliberately not reloaded here: they belong to the operator, not the engagement.
//
// A project that saved no overrides gets the LAUNCH defaults, not whatever the previous project set:
// the baseline is captured the first time this runs, before any project's overrides are applied.
func (s *Server) restoreProjectScanState(p *persist.Store) {
	if s.scanner != nil {
		if s.scanBaseline == nil {
			base := cloneScanConfig(s.scanner.UpdateScanConfig(func(*scanner.ScanConfig) {}))
			s.scanBaseline = &base
		}
		next := cloneScanConfig(*s.scanBaseline)
		if saved, err := p.LoadScanConfig(); err != nil {
			s.logger.Warn("failed to load the project's scan configuration; using launch defaults", zap.Error(err))
		} else if saved != nil {
			next = cloneScanConfig(*saved)
		}
		s.scanner.UpdateScanConfig(func(c *scanner.ScanConfig) { *c = next })
	}

	// An empty ledger resets the sweep's memory: the incoming project's traffic has never been audited
	// by this process, and carrying the outgoing project's "already seen" set would skip it.
	blob, err := p.LoadLiveSeenLedger()
	if err != nil {
		s.logger.Warn("could not restore the live sweep's seen ledger", zap.Error(err))
		blob = nil
	}
	s.LoadLiveSeenLedger(blob)
}

// cloneScanConfig copies a ScanConfig without sharing its slices, so the baseline cannot be edited
// through the live configuration.
func cloneScanConfig(c scanner.ScanConfig) scanner.ScanConfig {
	c.CustomPayloads = append([]string(nil), c.CustomPayloads...)
	c.IssueTypes = append([]uint32(nil), c.IssueTypes...)
	return c
}
