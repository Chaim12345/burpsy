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
	Close() error
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
