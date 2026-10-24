package scanner

// wiring.go is the one construction recipe for a fully capable ActiveScanner.
//
// # Why this exists
//
// The capability handles an audit can need - the stored and provenance ledgers
// the 10 stored/second-order checks refuse without, the session coordinator
// access-control and CSRF refuse without, the JS-library and JWT checks, the
// OOB provider, the tool runner, the bundled corpus, the audit config - grew
// up wired by exactly one call site (cmd/burpsy/main.go). The desktop binary
// and the web server's lazy fallback built their scanners without them, and
// every capability-gated check in those binaries filed Skipped under
// CapabilityMissing: same product, two audit engines, and the difference was
// invisible until a check's disposition was read.
//
// One builder, three call sites. A handle this process cannot provide stays
// nil here - an explicit, named opt-out at the call site, not a handle someone
// forgot. A binary that wires no CapabilityWiring at all is the bug this file
// exists to delete.
//
// The audit-budget question (which config source wins when several set a
// budget) is deliberately NOT decided here: WithAuditConfig is applied only
// when the caller supplies one, so this builder cannot change any binary's
// budget resolution. That fork is tracked separately.
//
// See cmd/burpsy/main.go, cmd/desktop/main.go and
// internal/web/api_scanner_audit.go (Server.activeScanner) for the three
// call sites.

import (
	"fmt"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/bcheck/bundled"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// CapabilityWiring carries every capability handle an ActiveScanner can be
// wired with. WithCapabilities wires each one; a nil handle is that binary's
// explicit opt-out and the corresponding checks keep reporting the missing
// capability by name.
type CapabilityWiring struct {
	// SessionCoordinator is the process's one session rule set. The web
	// console, the proxy's session gate and the scanner's access-control and
	// CSRF comparisons must all hold this same handle: two coordinators would
	// let the Session page describe rules the scanner stopped honouring.
	SessionCoordinator *session.Coordinator
	// ToolRunner is the allowlist runner `run tool` bcheck statements
	// dispatch through. Nil means no external tools are allowlisted; corpus
	// checks that need one are counted at load and excluded by name.
	ToolRunner bcheck.ToolRunner
	// OOBProvider backs the out-of-band (blind SSRF/XXE/RCE) checks. Nil
	// means no Collaborator-style server is configured; the checks report
	// the missing capability rather than guessing a callback channel.
	OOBProvider OOBProvider
	// CorpusChecks are the loaded BCheck corpus's active checks
	// (PassiveScanner.ActiveChecks). Attaching them switches
	// ScanConfig.CheckCorpus on, per WithCorpusChecks.
	CorpusChecks []*bcheck.Check
	// BundledCorpus is the corpus compiled into the binary, usually from
	// BundledCorpus. Attaching it switches check_corpus on — the shipped
	// corpus is part of the default audit set; see WithBundledCorpus.
	BundledCorpus []*bcheck.Check
	// AuditConfig is the audit budget/limit set the binary resolved from its
	// own flags or configuration. Nil leaves the engine's own resolution
	// untouched - see the budget note at the top of this file.
	AuditConfig *AuditConfig
	// BrowserProvider backs the DOM-based checks. Nil means the binary has
	// no DOM engine configured; those checks report the missing capability
	// and no browser ever starts.
	BrowserProvider BrowserProvider

	// NoStoredLedger, NoProvenanceLedger, NoJsLibraryCheck and
	// NoJwtWeakSecretCheck opt out of the handles the builder constructs
	// itself. They exist so a test or a memory-constrained embedding can
	// decline a handle by name; the default in every shipped binary is to
	// wire all four - they are in-memory and bounded, the JS corpus is
	// vendored and parsed once per process, and the JWT wordlist is compiled
	// in, so constructing them unconditionally costs nothing an audit that
	// never needs them would notice.
	NoStoredLedger       bool
	NoProvenanceLedger   bool
	NoJsLibraryCheck     bool
	NoJwtWeakSecretCheck bool
}

// WithCapabilities wires every handle in w onto s, in the order
// cmd/burpsy/main.go established: corpus availability before the handles the
// checks themselves need. It returns s so call sites can keep the builder
// chain shape.
func (s *ActiveScanner) WithCapabilities(w CapabilityWiring) *ActiveScanner {
	if len(w.CorpusChecks) > 0 {
		s.WithCorpusChecks(w.CorpusChecks)
	}
	if len(w.BundledCorpus) > 0 {
		s.WithBundledCorpus(w.BundledCorpus)
	}
	if w.ToolRunner != nil {
		s.WithToolRunner(w.ToolRunner)
	}
	if w.OOBProvider != nil {
		s.WithOOBProvider(w.OOBProvider)
	}
	if !w.NoStoredLedger {
		s.WithStoredLedger(NewStoredLedger())
	}
	if !w.NoProvenanceLedger {
		s.WithProvenanceLedger(NewProvenanceLedger())
	}
	if w.SessionCoordinator != nil {
		s.WithSessionCoordinator(w.SessionCoordinator)
	}
	if !w.NoJsLibraryCheck {
		s.WithJsLibraryCheck(NewJsLibraryCheck(VendoredJsVulnDb()))
	}
	if !w.NoJwtWeakSecretCheck {
		s.WithJwtWeakSecretCheck(NewJwtWeakSecretCheck(BundledJwtWordlist()))
	}
	if w.AuditConfig != nil {
		s.WithAuditConfig(*w.AuditConfig)
	}
	if w.BrowserProvider != nil {
		s.WithBrowserProvider(w.BrowserProvider)
	}
	return s
}

// BundledCorpus returns the BCheck corpus compiled into the binary
// (internal/bcheck/bundled), for CapabilityWiring.BundledCorpus. An operator's
// -bchecks directory ADDS to this set, it never replaces it: that is Burp's
// own treatment of custom BChecks, and an operator extending the shipped
// corpus should not silently lose the hundred-plus checks the binary carries.
// A loaded check that shares a bundled check's name replaces it at dispatch
// (the dedup WithBundledCorpus documents), so overriding one shipped check
// stays possible without forking the set.
//
// Attaching the result switches check_corpus on, exactly as a loaded
// directory does (WithBundledCorpus): the corpus the binary ships is part of
// the default audit set, and the operator's off switch is check_corpus.
//
// Shared by cmd/burpsy and cmd/desktop so the CLI and the desktop binary can
// never disagree about which corpus the binary carries. An embedded corpus
// that will not load is a build defect, not an operator error, so it is
// returned as an error and the caller refuses to start rather than run
// without a set it shipped.
func BundledCorpus(logger *zap.Logger) ([]*bcheck.Check, error) {
	m, err := bundled.LoadManifest()
	if err != nil {
		return nil, err
	}
	checks, err := m.EnabledChecks()
	if err != nil {
		return nil, fmt.Errorf("bundled bcheck corpus: %w", err)
	}
	if logger != nil {
		c := m.Counts()
		logger.Info("bundled bcheck corpus enabled by default (check_corpus off to opt out)",
			zap.String("source", m.Source.Repository+"@"+m.Source.Commit),
			zap.Int("upstream", c.Upstream), zap.Int("imported", c.Imported),
			zap.Int("enabled", c.Enabled), zap.Any("excluded", c.ByCategory))
	}
	return checks, nil
}
