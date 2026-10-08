package scanner

// The out-of-band channel, held for the life of a scan rather than the life of a check.
//
// Two problems with acquiring it per check, and the second is a correctness bug rather than a cost.
//
// The cost: registering a collaborator domain spawns interactsh-client and waits for a public DNS
// registration. Doing that once per row per endpoint meant four rows times every audited URL, each
// paying the registration again, to ask a question one channel answers for all of them. The client's
// own documentation says markers exist to "tell two concurrent checks' callbacks apart", so sharing
// was always the intended shape.
//
// The bug: a check that opens the channel also closes it on return. It slept five seconds, polled
// once, then closed - so a callback arriving in the sixth second was not merely missed, it was
// unrecoverable, and the row reported nothing, which reads as clean. A target that queues outbound
// work, or one behind a slow resolver, is exactly the target this row exists to catch.
//
// So the channel now outlives every check, and the waiting is handed to the pending registry, which
// polls until its deadline and reports anything still unanswered as outstanding.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/oob"
)

// OOBProvider hands out the scan's collaborator channel.
//
// An interface rather than a concrete client so a test can supply a channel whose callbacks it
// controls. Everything about this row's honesty is in the timing, and timing is not testable
// against a real public collaborator.
type OOBProvider interface {
	// Channel returns the shared channel, or an error explaining why there is none.
	Channel(ctx context.Context) (OOBChannel, error)
	// Registration reports what this provider has already done, without doing any of it.
	//
	// On the interface rather than behind a type assertion because an operator-facing surface has
	// to be able to render the channel's state, and the one thing it must never do is call
	// Channel() to find out: Channel registers a public collaborator domain on first use and blocks
	// for up to Options.Timeout doing it. A status read that mints is a status read that changes
	// the thing it reports, and — for the Collaborator tab, which polls — it would spawn
	// interactsh-client the moment someone opened the tool.
	//
	// A provider that could not answer this would leave that surface guessing, so it is a required
	// method: guessing here means showing an address nothing polls, or reporting a channel as
	// absent while a scan holds one open.
	Registration() OOBRegistration
	Close() error
}

// OOBRegistration is a provider's own account of its channel, obtainable without opening one.
//
// Attempted and Open are separate booleans because three states have to be told apart and two of
// them are both "not open": never asked for (nothing has needed a callback yet), asked for and
// failed (the binary is missing, or registration timed out), and open. Collapsing the first two
// loses the distinction between "no evidence has been sought" and "evidence could not be sought",
// which is the same distinction the whole out-of-band path exists to preserve.
type OOBRegistration struct {
	// Attempted is true once registration has been tried, successfully or not.
	Attempted bool
	// Open is true when a channel exists and Domain names its payload domain.
	Open bool
	// Domain is the registered payload domain. Empty unless Open.
	Domain string
	// Err is why the attempt failed, when one was made and did not succeed.
	Err error
	// Server is the interaction server the operator configured. Empty means the client's own
	// default public pool (oast.pro / oast.live / oast.fun / oast.me / oast.online) — reported as
	// empty rather than filled in with a guess, because which of those a registration lands on is
	// the client's choice and is not knowable until Domain exists.
	Server string
}

// OOBChannel is the part of the collaborator a check actually uses.
type OOBChannel interface {
	// Domain is the registered collaborator domain payloads are built against.
	Domain() string
	// InteractionsFor returns the interactions whose hostname carries marker.
	InteractionsFor(marker string) ([]oob.Interaction, error)
}

// lazyOOB registers the collaborator on first request and keeps it for the scan.
type lazyOOB struct {
	opts oob.Options

	mu      sync.Mutex
	started bool
	client  *oob.Client
	err     error
}

// NewLazyOOBProvider builds a provider that registers a collaborator domain on first use, so a
// scan with the out-of-band rows disabled never spawns the binary at all.
func NewLazyOOBProvider(opts oob.Options) OOBProvider {
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	return &lazyOOB{opts: opts}
}

func (l *lazyOOB) Channel(ctx context.Context) (OOBChannel, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.started {
		if l.err != nil {
			return nil, l.err
		}
		return l.client, nil
	}
	l.started = true
	// Deliberately not ctx. The channel has to outlive the check that first asked for it - that is
	// the entire point - and binding it to one check's context would close it on return, which is
	// the bug this file exists to remove.
	c, err := oob.NewClient(context.Background(), l.opts)
	if err != nil {
		l.err = fmt.Errorf("out-of-band channel unavailable: %w", err)
		return nil, l.err
	}
	l.client = c
	return c, nil
}

// Registration reports the channel this provider has already opened, and never opens one.
//
// It reads the same three fields Channel() writes under the same mutex, so a status read
// concurrent with a first registration sees either the before or the after state, never a
// half-populated one.
func (l *lazyOOB) Registration() OOBRegistration {
	l.mu.Lock()
	defer l.mu.Unlock()
	reg := OOBRegistration{Attempted: l.started, Err: l.err, Server: l.opts.ServerURL}
	if l.client != nil {
		reg.Open = true
		reg.Domain = l.client.Domain()
	}
	return reg
}

func (l *lazyOOB) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client == nil {
		return nil
	}
	return l.client.Close()
}

// WithOOBProvider installs the collaborator handle.
//
// Without it the out-of-band rows report a missing capability. They must never report zero
// interactions, because a channel that was never opened cannot distinguish a target that did not
// call back from one nobody was listening for.
func (s *ActiveScanner) WithOOBProvider(p OOBProvider) *ActiveScanner {
	if s == nil {
		return s
	}
	s.oobMu.Lock()
	s.oob = p
	s.oobMu.Unlock()
	return s
}

// OOBChannel returns the scan's collaborator channel, or an error naming what is missing.
func (s *ActiveScanner) OOBChannel(ctx context.Context) (OOBChannel, error) {
	if s == nil {
		return nil, errors.New("out-of-band: no scanner")
	}
	s.oobMu.Lock()
	p := s.oob
	s.oobMu.Unlock()
	if p == nil {
		return nil, errors.New("out-of-band: no collaborator channel is configured for this scan, " +
			"so a callback cannot be observed and this check cannot report a verdict")
	}
	return p.Channel(ctx)
}

// OOBRegistration reports the scan channel's state, and whether one is configured at all, without
// opening a channel.
//
// The bool is the distinction the operator-facing surface turns on: no provider is "the Collaborator
// tool is not configured", which is a sentence about this installation, whereas a provider whose
// registration failed is "configured and broken", which is a sentence about this run. They call for
// different copy and different remedies, so they are not folded into one zero value.
func (s *ActiveScanner) OOBRegistration() (OOBRegistration, bool) {
	if s == nil {
		return OOBRegistration{}, false
	}
	s.oobMu.Lock()
	p := s.oob
	s.oobMu.Unlock()
	if p == nil {
		return OOBRegistration{}, false
	}
	return p.Registration(), true
}

// ClearOOBProvider removes the collaborator handle and closes its channel: Burp's "Don't use Burp
// Collaborator" (burpsy-react-ui-8e3n). Afterwards the out-of-band rows report a missing capability, as
// they do on an installation that never configured one, never zero interactions. It returns what
// Registration reported just before the removal, so a caller can say which domain was given up.
func (s *ActiveScanner) ClearOOBProvider() (OOBRegistration, bool, error) {
	if s == nil {
		return OOBRegistration{}, false, nil
	}
	s.oobMu.Lock()
	p := s.oob
	s.oob = nil
	s.oobMu.Unlock()
	if p == nil {
		return OOBRegistration{}, false, nil
	}
	reg := p.Registration()
	return reg, true, p.Close()
}

// closeOOB releases the channel at the end of a scan.
func (s *ActiveScanner) closeOOB() error {
	if s == nil {
		return nil
	}
	s.oobMu.Lock()
	p := s.oob
	s.oobMu.Unlock()
	if p == nil {
		return nil
	}
	return p.Close()
}
