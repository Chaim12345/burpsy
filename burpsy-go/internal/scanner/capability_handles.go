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
func (s *ActiveScanner) WithBrowserProvider(p BrowserProvider) *ActiveScanner {
	s.browsers = p
	return s
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
func (cc *CheckContext) Browser(ctx context.Context) (*domexec.Browser, error) {
	if cc == nil || cc.Scanner == nil || cc.Scanner.browsers == nil {
		return nil, errors.New("browser: no DOM execution capability is configured for this scan")
	}
	return cc.Scanner.browsers.Browser(ctx)
}

// StoredLedger returns the scan's stored-input ledger, or an error when none is configured.
func (cc *CheckContext) StoredLedger() (*StoredLedger, error) {
	if cc == nil || cc.Scanner == nil || cc.Scanner.stored == nil {
		return nil, errors.New("stored ledger: no stored-input tracking is configured for this scan")
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
// Passive checks must NOT call this. They answer from the exchange already captured, so for
// them a missing sender is irrelevant and an error here would be a false refusal.
func (cc *CheckContext) RequireEgress() error {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return errors.New("egress: no scanner or exchange on this check context")
	}
	if cc.Scanner.sender == nil {
		return errors.New("egress: no sender is configured for this scan, so an active probe cannot be sent and this check cannot report a verdict")
	}
	if cc.Scanner.probeGate(cc.Exchange) == nil {
		return errors.New("egress: no authorised sender for this exchange, so an active probe cannot be sent")
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
