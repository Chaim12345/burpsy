package scanner

// Closing the stored lifecycle.
//
// A stored finding needs two events in order: a canary is planted, then it is seen somewhere it
// was not planted. In a batch audit those two can never both happen, because every response the
// scan has was captured before the scan started - the planting always comes last. The stored rows
// were therefore structurally unable to report anything, while still counting as runnable
// coverage, which is the worst combination this project allows.
//
// The fix is the one Burp reaches for: after probing, go and look again. Re-fetching a page the
// scan already knows about produces a response that postdates the planting, and that response is
// the only place a stored canary can legitimately surface.
//
// Deliberately not a crawl. This re-visits URLs the scan was already given and nothing else: a
// scanner that discovers new URLs during its own audit phase would be sending traffic the operator
// never authorised, and scope is checked per request regardless.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// PendingCount reports how many deferred claims are unsettled, without creating the registry on
// first use the way Pending does. That distinction is the guard the web audit paths need: an audit
// that registered nothing must skip FinishScan entirely (the re-fetch pass is real traffic), and
// calling Pending() to count would itself register a registry where there was none — making the
// guard read one where zero claims exist.
func (s *ActiveScanner) PendingCount() int {
	if s == nil {
		return 0
	}
	s.pendingMu.Lock()
	r := s.pending
	s.pendingMu.Unlock()
	return r.PendingCount()
}

// Pending returns the scan's deferred-evidence registry, creating it on first use.
func (s *ActiveScanner) Pending() *PendingRegistry {
	if s == nil {
		return nil
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pending == nil {
		s.pending = NewPendingRegistry()
	}
	return s.pending
}

// ScanCompletion is what the deferred half of a scan managed to settle.
type ScanCompletion struct {
	// Refetch is the second look's own accounting.
	Refetch StoredRefetchOutcome
	// RefetchError is why no second look happened, when none did.
	RefetchError string
	// Render is the browser second look's own accounting: the flows only a rendered page shows.
	Render StoredDOMRenderOutcome
	// RenderError is why no page was rendered, when the scan asked for DOM checks and none was.
	RenderError string
	// Outstanding are claims that never got an answer. Not findings, and not clean either.
	Outstanding []*PendingItem
	// Pending is the registry's summary line.
	Pending string
}

// FinishScan settles the deferred half of a scan: look again, then ask every claim once more.
//
// This has to be a separate phase because the ordering is the point. Claims are registered while
// checks run, the re-fetch produces responses that postdate them, and only then can a claim be
// answered. Calling this before the audit finishes would ask every question too early - which is
// precisely the bug it exists to fix.
func (s *ActiveScanner) FinishScan(ctx context.Context) ([]*Finding, ScanCompletion) {
	var c ScanCompletion
	if s == nil {
		return nil, c
	}
	if out, err := s.RefetchStoredTargets(ctx); err != nil {
		// A missing capability is reported, never swallowed: without the second look the stored
		// claims below are outstanding for a reason the reader needs to know.
		c.RefetchError = err.Error()
	} else {
		c.Refetch = out
	}
	// The browser pass runs after the HTTP one and never instead of it: a canary the raw response
	// already carried is cheaper to find there, and this pass exists only for the flows that pass
	// cannot see at all.
	if out, err := s.RenderStoredTargets(ctx); err != nil {
		c.RenderError = err.Error()
	} else {
		c.Render = out
	}
	findings := s.Pending().Await(ctx)
	c.Outstanding = s.Pending().Outstanding()
	c.Pending = s.Pending().Summarise()
	return findings, c
}

// StoredRefetchOutcome reports what the second look actually managed to do.
//
// Refetched and Observed are separate numbers on purpose. Zero sightings after twenty successful
// re-fetches is a real negative result; zero sightings after zero re-fetches is not a result at
// all, and a caller that cannot tell them apart will report the second as though it were the first.
type StoredRefetchOutcome struct {
	// Candidates is how many distinct GET targets the scan knew about.
	Candidates int
	// Refetched is how many were successfully fetched again.
	Refetched int
	// Refused is how many the scope check declined.
	Refused int
	// Failed is how many could not be fetched.
	Failed int
	// Observed is how many canaries surfaced in an exchange other than the one that planted them.
	Observed int
	// Outstanding is how many planted canaries have still never been seen anywhere.
	Outstanding int
}

// Summary renders the outcome in the vocabulary a report can print.
func (o StoredRefetchOutcome) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d known GET targets re-fetched", o.Refetched, o.Candidates)
	if o.Refused > 0 {
		fmt.Fprintf(&b, ", %d refused by scope", o.Refused)
	}
	if o.Failed > 0 {
		fmt.Fprintf(&b, ", %d failed", o.Failed)
	}
	fmt.Fprintf(&b, "; %d canary sighting(s)", o.Observed)
	if o.Outstanding > 0 {
		fmt.Fprintf(&b, ", %d planted canary(ies) never surfaced anywhere (not clean - the pages "+
			"that would render them may not have been re-fetched)", o.Outstanding)
	}
	return b.String()
}

// RefetchStoredTargets re-requests every GET target the scan already knows about and feeds each
// response to the stored ledger.
//
// It records the re-fetches as real exchanges, because that is what they are: traffic this tool
// sent, which belongs in the store like any other. A sighting attributed to an exchange that does
// not exist could not be reproduced by whoever reads the finding.
func (s *ActiveScanner) RefetchStoredTargets(ctx context.Context) (StoredRefetchOutcome, error) {
	var out StoredRefetchOutcome
	if s == nil || s.store == nil {
		return out, fmt.Errorf("stored re-fetch: no traffic store")
	}
	if s.stored == nil {
		// No ledger means nothing was planted, so a second look would prove nothing. Saying so
		// beats reporting a clean sweep of zero targets.
		return out, fmt.Errorf("stored re-fetch: no stored-input ledger, so nothing was planted to look for")
	}
	if s.sender == nil {
		return out, fmt.Errorf("stored re-fetch: no sender, so the pages that would render a canary cannot be requested")
	}

	for _, t := range s.storedRefetchTargets() {
		out.Candidates++
		gate := s.probeGate(ctx, t.exchange)
		if gate == nil {
			out.Refused++
			continue
		}
		resp, err := gate.SendRequest(ctx, &sender.Request{
			Method: "GET",
			Host:   t.exchange.Host,
			Path:   t.path,
			TLS:    t.exchange.TLS,
			Port:   t.exchange.Port,
		})
		if err != nil || resp == nil {
			out.Failed++
			continue
		}
		out.Refetched++

		ex, err := s.recordRefetch(t, string(resp.Body))
		if err != nil {
			out.Failed++
			continue
		}
		out.Observed += len(s.ObserveStoredCanaries(ex))
	}

	out.Outstanding = len(s.stored.Outstanding())
	return out, nil
}

type refetchTarget struct {
	exchange *core.Exchange
	path     string
}

// storedRefetchTargets is the deduplicated GET surface of the scan, in a fixed order.
//
// Deduplication is by method, host, port and path: the same page captured forty times does not
// need forty re-fetches, and an unbounded second pass over a large history would be a request
// amplifier rather than a check.
func (s *ActiveScanner) storedRefetchTargets() []refetchTarget {
	seen := map[string]bool{}
	var out []refetchTarget
	for _, ex := range s.store.Exchanges() {
		if ex == nil || !strings.EqualFold(ex.Method, "GET") {
			continue
		}
		key := strings.ToLower(ex.Host) + "|" + fmt.Sprint(ex.Port) + "|" + ex.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, refetchTarget{exchange: ex, path: ex.Path})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// recordRefetch stores the second look as its own exchange so a sighting can be cited.
func (s *ActiveScanner) recordRefetch(t refetchTarget, body string) (*core.Exchange, error) {
	raw := "GET " + t.path + " HTTP/1.1\r\nHost: " + t.exchange.Host + "\r\n\r\n"
	reqID, err := s.store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		return nil, err
	}
	respRaw := "HTTP/1.1 200 OK\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
	respID, err := s.store.Put([]byte(respRaw), core.DirectionResponse)
	if err != nil {
		return nil, err
	}
	ex := &core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID,
		Host: t.exchange.Host, Port: t.exchange.Port, TLS: t.exchange.TLS,
		Method: "GET", Path: t.path,
		// Read from the bytes actually stored above, which name no Content-Type — so this is "" and the
		// History row will say the response declared no type. That is the truth about these bytes and it
		// is left alone: the re-fetch wraps a body it holds as a string with a minimal synthetic head,
		// and inventing a Content-Type here would put a type on the row that no server ever sent and
		// that the stored response a reader can open does not contain.
		Mime: core.MimeEssence([]byte(respRaw)),
	}
	s.store.AddExchange(ex)
	return ex, nil
}
