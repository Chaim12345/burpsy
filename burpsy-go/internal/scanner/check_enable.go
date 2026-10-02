package scanner

import "github.com/burpsy-go/burpsy/internal/bcheck"

// Per-check enable/disable for the loaded BCheck corpus (burpsy-react-ui-kdqj, criterion 1).
//
// # Why the disabled set lives here and not in the web layer
//
// The audit engine reads its dispatch set from ActiveScanner.corpus under s.mu (enabledChecks, and
// enabledChecksInTiers for the audit-level overlay). A disabled set held anywhere else — a map on
// the Server, a field on a route handler — would be a second list the engine never consulted, and
// an operator flipping a row off would watch the audit run it anyway. That is the exact
// decorative-switch defect this repository refuses to ship: a control that changes nothing.
//
// # Name-based, not index-based
//
// The disabled set is keyed by check NAME because a name is what an operator reads and what the
// corpus loader carries; a check's position in the corpus slice is an index into a slice that a
// later WithCorpusChecks can replace under them. A disabled index would survive a corpus reload and
// silently disable a different check — the same identity hazard the ledger's bit-stability rule
// exists to prevent.
//
// # The whole check, or the corpus switch?
//
// ScanConfig.CheckCorpus is the all-or-nothing switch and it already exists; this is the per-row
// refinement beneath it. Both are read at the same snapshot point (enabledChecks takes
// ConfigSnapshot once per run), so a run can never see one without the other.

// DisableCheck marks one corpus check off by name. The named check is skipped by every later run's
// dispatch set; a name that is not in the corpus is recorded anyway, so a disable that arrives
// before the corpus is loaded still takes effect when it loads — the same ordering tolerance
// WithCorpusChecks itself has.
//
// The set is nil until the first disable: a process where nothing was ever disabled holds no map,
// which is the zero cost the happy path pays.
func (s *ActiveScanner) DisableCheck(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disabledChecks == nil {
		s.disabledChecks = make(map[string]bool)
	}
	s.disabledChecks[name] = true
}

// EnableCheck clears one corpus check's disable. Clearing a name that was never disabled is a no-op
// — the set's own absence is the enabled state, and an enabled check has no entry to remove.
func (s *ActiveScanner) EnableCheck(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.disabledChecks, name)
}

// CheckDisabled reports whether one corpus check is currently disabled.
func (s *ActiveScanner) CheckDisabled(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.disabledChecks[name]
}

// DisabledChecks returns a copy of the disabled set, for the route that renders the corpus: a
// reader that took the live map would race a concurrent disable.
func (s *ActiveScanner) DisabledChecks() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]bool, len(s.disabledChecks))
	for name := range s.disabledChecks {
		out[name] = true
	}
	return out
}

// CorpusChecks returns a copy of the loaded corpus's active checks, in load order — the set
// WithCorpusChecks was given, which is the same LoadDir that built the passive scanner. The route
// that renders the corpus leaf reads THIS (criterion 3: both count their rows from the corpus
// loader rather than a second list), so the leaf and the audit engine cannot disagree about which
// corpus is loaded.
//
// Nil when no corpus was loaded — a process without --bchecks audits the built-ins only, and the
// leaf reports that rather than an empty list nothing could ever have loaded.
func (s *ActiveScanner) CorpusChecks() []*bcheck.Check {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*bcheck.Check, len(s.corpus))
	copy(out, s.corpus)
	return out
}

// corpusChecksEnabled filters the corpus to the checks an operator has not disabled.
//
// Read at the same two sites enabledChecks already reads s.corpus, so the disabled set cannot be
// consulted by one run shape and missed by another. Filtering here rather than in the web layer is
// the whole point: this is the set the audit engine dispatches, and a control the engine does not
// read is not a control.
func (s *ActiveScanner) corpusChecksEnabled(corpus []*bcheck.Check) []*bcheck.Check {
	s.mu.RLock()
	disabled := s.disabledChecks
	s.mu.RUnlock()
	if len(disabled) == 0 {
		return corpus
	}
	out := make([]*bcheck.Check, 0, len(corpus))
	for _, c := range corpus {
		if disabled[c.Name] {
			continue
		}
		out = append(out, c)
	}
	return out
}
