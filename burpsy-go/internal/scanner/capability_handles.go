package scanner

// The two remaining capability handles a check needs: a browser, and the stored-input ledger.
//
// Both are lazily created and both report unavailability as an error rather than as an empty
// result. That is the whole design constraint: a DOM check that silently got no browser would
// report "no DOM vulnerability", and a stored check that silently got no ledger would report
// "nothing stored". Neither is true, and both are the failure mode this project exists to
// avoid.

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/session"
)

// BrowserProvider hands out a shared headless browser. It is an interface so a check's tests
// can supply a stub without launching Chrome, and so the scanner does not depend on chromedp
// at the point of use.
type BrowserProvider interface {
	// Browser returns the shared browser, or an error naming why there is none.
	Browser(ctx context.Context) (*domexec.Browser, error)
	// Close releases the browser if one was ever started.
	Close() error
}

// lazyBrowser starts Chrome at most once, on first use, and remembers a failure so a scan
// against a machine with no Chrome does not pay the launch cost per check.
type lazyBrowser struct {
	opts domexec.Options

	mu      sync.Mutex
	started bool
	browser *domexec.Browser
	err     error
}

// NewLazyBrowserProvider builds a provider that launches Chrome on first request.
func NewLazyBrowserProvider(opts domexec.Options) BrowserProvider {
	return &lazyBrowser{opts: opts}
}

func (l *lazyBrowser) Browser(ctx context.Context) (*domexec.Browser, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.started {
		if l.err != nil {
			return nil, l.err
		}
		// A browser whose process died is not reusable, and returning it would produce
		// zero observations that look like a clean result.
		if l.browser != nil && !l.browser.Available() {
			l.err = errors.New("browser: the headless browser is no longer available")
			return nil, l.err
		}
		return l.browser, nil
	}
	l.started = true
	// Deliberately not ctx: the browser outlives the check that first asked for it, and
	// binding it to one check's context would kill it when that check returned.
	b, err := domexec.NewBrowser(context.Background(), l.opts)
	if err != nil {
		l.err = fmt.Errorf("browser: no DOM execution capability: %w", err)
		return nil, l.err
	}
	l.browser = b
	return b, nil
}

func (l *lazyBrowser) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.browser == nil {
		return nil
	}
	err := l.browser.Close()
	// Idempotent: the test binary closes this provider through two doors (a scanner's
	// CloseCapabilities and TestMain's own teardown), and a second Close must be a
	// no-op rather than an error a caller has to interpret.
	l.browser = nil
	return err
}

// WithBrowserProvider installs the browser handle. Without it, DOM checks report a missing
// capability instead of an empty observation set.
//
// Attaching an engine also switches the DOM families on (ScanConfig.CheckDOM), the same way
// WithCorpusChecks switches CheckCorpus on for a loaded corpus, and WithConfig can turn it back
// off again. The two knobs are load-bearing in opposite directions and half-opening either one is
// a defect with no error message: an engine with the families still gated is a browser launched
// for checks that cannot dispatch, and reads as a clean scan of a page nobody looked at. A nil
// provider leaves the switch alone, so a process with no engine does not turn a knob that gates
// nothing.
func (s *ActiveScanner) WithBrowserProvider(p BrowserProvider) *ActiveScanner {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.browsers = p
	if p != nil && s.config != nil {
		s.config.CheckDOM = true
	}
	return s
}

// DOMCapabilityConfigured reports whether an engine was named for this scan. It answers from
// configuration alone and never starts anything: the provider is lazy on purpose, so "an engine
// is configured" and "an engine works" are separate questions with separate answers — the second
// is what Browser() reports, per check, naming the failure.
//
// It exists because a caller that wires the engine (cmd/burpsy) cannot otherwise see whether it
// succeeded, and a silently unwired binary reports every DOM check as capability-less while
// looking correctly configured from the outside.
// A nil receiver answers false, like enabledChecks: a server with no scanner attached has no DOM
// capability, and making the caller check twice invites the check being forgotten once.
// BrowserForRender hands out the configured browser for rendering outside a check — the
// crawler's rendered-DOM discovery pass (burpsy-react-ui-nx7b). An error rather than a nil
// browser, for the same reason Browser() below the interface is: a caller that silently got
// no browser would read a render failure as "the page has no such links", which is the
// failure mode this project exists to avoid.
func (s *ActiveScanner) BrowserForRender(ctx context.Context) (*domexec.Browser, error) {
	if s == nil || s.browsers == nil {
		return nil, fmt.Errorf("no DOM execution capability is configured")
	}
	return s.browsers.Browser(ctx)
}

func (s *ActiveScanner) DOMCapabilityConfigured() bool {
	return s != nil && s.browsers != nil
}

// WithStoredLedger installs a stored-input ledger shared across the scan. Without it, stored
// checks report a missing capability.
func (s *ActiveScanner) WithStoredLedger(l *StoredLedger) *ActiveScanner {
	s.stored = l
	return s
}

// StoredLedgerHandle returns the scan's ledger, or nil when none was installed.
func (s *ActiveScanner) StoredLedgerHandle() *StoredLedger {
	if s == nil {
		return nil
	}
	return s.stored
}

// The four accessors below mirror StoredLedgerHandle: nil-safe reads of the capability
// handles, so a surface (Settings' capability report, a test) can state what the shipped
// binary actually wired instead of inferring it from flags. Nil is a supported state and
// the checks' own error paths already say "no X configured for this scan" — these exist
// so the wiring question has a direct answer.

// ProvenanceLedgerHandle returns the provenance ledger, or nil when none was installed.
func (s *ActiveScanner) ProvenanceLedgerHandle() *ProvenanceLedger {
	if s == nil {
		return nil
	}
	return s.provenance
}

// SessionCoordinatorHandle returns the session coordinator, or nil when none was installed.
func (s *ActiveScanner) SessionCoordinatorHandle() *session.Coordinator {
	if s == nil {
		return nil
	}
	return s.sessions
}

// JsLibraryCheckHandle returns the JS-library vulnerability check, or nil when none was installed.
func (s *ActiveScanner) JsLibraryCheckHandle() *JsLibraryCheck {
	if s == nil {
		return nil
	}
	return s.jsLib
}

// JwtWeakSecretCheckHandle returns the JWT weak-secret check, or nil when none was installed.
func (s *ActiveScanner) JwtWeakSecretCheckHandle() *JwtWeakSecretCheck {
	if s == nil {
		return nil
	}
	return s.jwtWeak
}

// CloseCapabilities releases every scan-scoped external handle: the browser and the collaborator
// channel. Callers that built a scanner with either provider must call this when the scan ends.
//
// Both are closed even if the first fails, because leaking a Chrome process or an interactsh
// subprocess is worse than losing one error string.
func (s *ActiveScanner) CloseCapabilities() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.browsers != nil {
		firstErr = s.browsers.Close()
	}
	if err := s.closeOOB(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Browser returns the shared browser for a check, or an error naming why there is none.
//
// The error is the point. A check that cannot get a browser must report that it could not
// look, and this is the only way it learns the difference between "the page had no tainted
// flow" and "nothing ever loaded the page".
//
// A missing capability wraps errCheckUnsupported, so the audit engine counts it Skipped rather
// than SendFailed. The distinction is not cosmetic: the failure breaker abandons the rest of a
// dispatch unit after two send failures, and this scan has not sent anything the target could
// have failed — counting "no browser is configured" as a target failure abandoned every check
// that happened to be dispatched after a DOM one (burpsy-react-ui-<see gaps>).
func (cc *CheckContext) Browser(ctx context.Context) (*domexec.Browser, error) {
	if cc == nil || cc.Scanner == nil || cc.Scanner.browsers == nil {
		return nil, fmt.Errorf("browser: no DOM execution capability is configured for this scan: %w", errCapabilityMissing)
	}
	return cc.Scanner.browsers.Browser(ctx)
}

// StoredLedger returns the scan's stored-input ledger, or an error when none is configured.
//
// The absence wraps errCheckUnsupported for the same reason Browser's does: no ledger is a
// capability this scan does not have, not a failure of the target to answer a probe.
func (cc *CheckContext) StoredLedger() (*StoredLedger, error) {
	if cc == nil || cc.Scanner == nil || cc.Scanner.stored == nil {
		return nil, fmt.Errorf("stored ledger: no stored-input tracking is configured for this scan: %w", errCapabilityMissing)
	}
	return cc.Scanner.stored, nil
}

// RequireEgress reports an error when this context cannot send a probe.
//
// It exists because the absence of a sender is otherwise indistinguishable from a negative
// result. Several helpers on this path report failure in-band — sendTestRequest returns a bare
// string, so "" means any of "no sender", "refused", "failed" and "the file really is empty" —
// and a check that treats that uniformly reports a clean bill of health for a probe it never
// sent. Calling this first turns the one case that is not a verdict into an error, which is
// what CheckRunner's contract requires: "a nil finding slice is a clean result, not an
// implicit unsupported result."
//
// Every failure here is a precondition — no sender is configured, or the exchange is not
// authorised — and never a transport outcome. It therefore wraps errCheckUnsupported so the
// engine counts the check Skipped rather than SendFailed: a scan with no egress is a
// capability this scan does not have, and counting it as a target failure tripped the
// consecutive-failure breaker and abandoned the rest of the dispatch unit, silently starving
// every check ordered after it.
//
// Passive checks must NOT call this. They answer from the exchange already captured, so for
// them a missing sender is irrelevant and an error here would be a false refusal.
func (cc *CheckContext) RequireEgress() error {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return fmt.Errorf("egress: no scanner or exchange on this check context: %w", errCapabilityMissing)
	}
	if cc.Scanner.sender == nil {
		return fmt.Errorf("egress: no sender is configured for this scan, so an active probe cannot be sent and this check cannot report a verdict: %w", errCapabilityMissing)
	}
	if cc.Scanner.probeGate(context.Background(), cc.Exchange) == nil {
		return fmt.Errorf("egress: no authorised sender for this exchange, so an active probe cannot be sent: %w", errCapabilityMissing)
	}
	return nil
}

// ObserveStoredCanaries feeds one captured exchange's response to the ledger, returning the
// canaries that surfaced in an exchange other than the one that planted them.
//
// This is the driver the second-order rows need: planting happens during active probing, but
// a canary only becomes a finding when it is seen somewhere else, which means every response
// the scan sees afterwards has to be checked. Wiring it here rather than inside one check
// keeps a single place responsible for the observation half.
func (s *ActiveScanner) ObserveStoredCanaries(exchange *core.Exchange) []StoredObservation {
	if s == nil || s.stored == nil || exchange == nil {
		return nil
	}
	body := responseBody(responseRaw(s, exchange))
	if body == "" {
		return nil
	}
	return s.stored.Observe(exchange.ID, exchange.Path, []byte(body))
}
