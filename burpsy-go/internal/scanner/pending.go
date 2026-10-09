package scanner

// Deferred evidence: claims that cannot be settled while the check that made them is still running.
//
// Two families need this and neither could ever produce a finding without it. The stored rows plant
// a canary during an audit, so every response already captured predates the planting; the
// out-of-band rows plant a callback domain, and a target that fetches it does so on its own
// schedule. Both were written as though the answer would be available before the check returned:
// the stored checks looked for a sighting that could not exist yet, and the collaborator checks
// slept five seconds, polled once, then closed the channel - so a callback arriving in the sixth
// second was not merely missed, it was unrecoverable.
//
// This is the shape all three reference scanners settle on, and none of them is event-driven for
// it. Burp re-checks on a ~1000ms timer (burp.Zrm7's doSingleCheck), ZAP's OAST add-on schedules a
// Poller at a fixed rate, Nuclei runs a background interactsh poller. The difference worth copying
// is Nuclei's alone: its cache survives the end of the main scan, so a late callback is still
// correlated. Burp and ZAP drop those.
//
// The property that matters more than any of that: an item still outstanding when the deadline
// passes is reported as outstanding. It is not a finding, and it is emphatically not a clean
// result - nobody looked at the answer, because the answer had not arrived.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// PendingResolver asks whether the evidence has arrived yet.
//
// It returns (finding, true, nil) once settled affirmatively, (nil, true, nil) once settled
// negatively - the target was asked and demonstrably did not do the thing - and (nil, false, nil)
// while the answer is still unknown. The three-way return is the whole point: "not yet" and "no"
// are different answers and a bool cannot carry both.
type PendingResolver func(context.Context) (*Finding, bool, error)

// PendingBatchResolver is PendingResolver for a claim that can produce several findings, and can
// produce some before it is settled: a BCheck run whose `report issue and continue` fired for one
// collaborator address while another condition still has no answer (burpsy-react-ui-ar8v). It
// returns the findings that are new since the last poll; settled is true once nothing about the
// claim is still unknown. A claim that produced findings and then hit its deadline unsettled is
// still outstanding — part of it was never answered.
type PendingBatchResolver func(context.Context) (found []*Finding, settled bool, err error)

// PendingItem is one claim awaiting evidence from outside this process.
type PendingItem struct {
	// Row is the catalog row that will be reported if the evidence arrives.
	Row string
	// Exchange is where the payload was planted, so an outstanding item names a place.
	Exchange core.ExchangeID
	// What describes the plant in a sentence a reader can act on.
	What string
	// Deadline bounds the wait. Past it the item is outstanding, never clean.
	Deadline time.Time

	resolve PendingResolver
	batch   PendingBatchResolver
	found   int
	polls   int
	err     error
}

// PendingRegistry holds deferred claims for the life of a scan.
type PendingRegistry struct {
	mu       sync.Mutex
	items    []*PendingItem
	settled  []*Finding
	retired  []*PendingItem
	rejected []*PendingItem
}

// NewPendingRegistry returns an empty registry.
func NewPendingRegistry() *PendingRegistry { return &PendingRegistry{} }

// Register records a claim to be polled later. What and Row are required: an item that cannot say
// what it is waiting for cannot be reported honestly when it never resolves.
func (r *PendingRegistry) Register(item PendingItem, resolve PendingResolver) error {
	if r == nil {
		return fmt.Errorf("pending registry: nil registry, so this claim would be dropped silently")
	}
	if resolve == nil {
		return fmt.Errorf("pending registry: %q registered with no resolver", item.Row)
	}
	if item.Row == "" || item.What == "" {
		return fmt.Errorf("pending registry: an item must name its row and what it planted")
	}
	item.resolve = resolve
	return r.add(item)
}

// RegisterBatch records a claim whose resolver may report several findings, some before it
// settles. The same requirements as Register apply.
func (r *PendingRegistry) RegisterBatch(item PendingItem, resolve PendingBatchResolver) error {
	if r == nil {
		return fmt.Errorf("pending registry: nil registry, so this claim would be dropped silently")
	}
	if resolve == nil {
		return fmt.Errorf("pending registry: %q registered with no resolver", item.Row)
	}
	if item.Row == "" || item.What == "" {
		return fmt.Errorf("pending registry: an item must name its row and what it planted")
	}
	item.batch = resolve
	return r.add(item)
}

func (r *PendingRegistry) add(item PendingItem) error {
	if item.Deadline.IsZero() {
		item.Deadline = nowUTC().Add(DefaultPendingDeadline)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, &item)
	return nil
}

// DefaultPendingDeadline is how long a claim is carried when its registrant names no deadline.
// Long enough for a target that queues work rather than acting inline; short enough that a scan
// ends.
const DefaultPendingDeadline = 30 * time.Second

// PendingPollInterval is the gap between polls, matching the ~1000ms Burp uses for its own
// deferred re-checks rather than inventing a cadence.
const PendingPollInterval = time.Second

// Poll runs one round over every unsettled item.
//
// Errors do not discard an item: a channel that was unreachable this second may answer the next,
// and dropping the claim on a transport failure is how a scanner converts "could not ask" into
// "asked and got nothing".
func (r *PendingRegistry) Poll(ctx context.Context) (findings []*Finding, outstanding int) {
	r.mu.Lock()
	items := make([]*PendingItem, len(r.items))
	copy(items, r.items)
	r.mu.Unlock()

	var keep []*PendingItem
	var settled []*Finding
	var rejected, retired []*PendingItem

	for _, it := range items {
		if ctx.Err() != nil {
			keep = append(keep, it)
			continue
		}
		var found []*Finding
		var done bool
		var err error
		if it.batch != nil {
			found, done, err = it.batch(ctx)
		} else {
			var f *Finding
			f, done, err = it.resolve(ctx)
			if f != nil {
				found = []*Finding{f}
			}
		}
		it.polls++
		if err != nil {
			it.err = err
		}
		settled = append(settled, found...)
		it.found += len(found)
		switch {
		case done && it.found > 0:
			// Settled affirmatively; its findings are already in settled.
		case done:
			rejected = append(rejected, it)
		case nowUTC().After(it.Deadline):
			retired = append(retired, it)
		default:
			keep = append(keep, it)
		}
	}

	r.mu.Lock()
	r.items = keep
	r.settled = append(r.settled, settled...)
	r.rejected = append(r.rejected, rejected...)
	r.retired = append(r.retired, retired...)
	out := len(keep)
	r.mu.Unlock()
	return settled, out
}

// Await polls until every item settles or its deadline passes, whichever comes first.
func (r *PendingRegistry) Await(ctx context.Context) []*Finding {
	if r == nil {
		return nil
	}
	var all []*Finding
	for {
		found, outstanding := r.Poll(ctx)
		all = append(all, found...)
		if outstanding == 0 || ctx.Err() != nil {
			return all
		}
		select {
		case <-ctx.Done():
			return all
		case <-time.After(PendingPollInterval):
		}
	}
}

// Outstanding returns the items that never settled: registered, polled, and still unanswered when
// their deadline passed. These are the rows a report must not describe as clean.
func (r *PendingRegistry) Outstanding() []*PendingItem {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*PendingItem, 0, len(r.retired)+len(r.items))
	out = append(out, r.retired...)
	out = append(out, r.items...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Row < out[j].Row })
	return out
}

// Summarise reports the registry's own accounting, in the vocabulary the audit outcome uses.
//
// The outstanding count is the load-bearing number. A scan that planted forty canaries and
// confirmed none of them has not shown the target is clean; it has shown that forty answers never
// came, and a report that omits the distinction is claiming coverage this registry did not supply.
func (r *PendingRegistry) Summarise() string {
	if r == nil {
		return "no deferred evidence was tracked"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "%d confirmed", len(r.settled))
	fmt.Fprintf(&b, ", %d answered negatively", len(r.rejected))
	if n := len(r.retired) + len(r.items); n > 0 {
		fmt.Fprintf(&b, ", %d still outstanding (not clean - no answer arrived)", n)
	}
	return b.String()
}

// PendingCount reports how many claims are still unsettled.
func (r *PendingRegistry) PendingCount() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.items)
}
