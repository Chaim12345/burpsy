package scanner

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/oob"
)

// fakeChannel is a collaborator whose callback timing the test controls.
//
// A real public collaborator cannot be used here: the whole property under test is what happens to
// an interaction that arrives after the check returned, and that is a statement about timing rather
// than about interactsh. Driving a real channel would test the network.
type fakeChannel struct {
	mu       sync.Mutex
	domain   string
	arrived  []oob.Interaction
	readErr  error
	reads    int
	failNext int
}

func (f *fakeChannel) Domain() string { return f.domain }

func (f *fakeChannel) InteractionsFor(marker string) ([]oob.Interaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.failNext > 0 {
		f.failNext--
		return nil, f.readErr
	}
	var out []oob.Interaction
	for _, i := range f.arrived {
		if strings.Contains(strings.ToLower(i.FullID), strings.ToLower(marker)) || marker == "" {
			out = append(out, i)
		}
	}
	return out, nil
}

// callback makes an interaction visible, as a target contacting the collaborator would.
func (f *fakeChannel) callback(protocol, from string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.arrived = append(f.arrived, oob.Interaction{Protocol: protocol, RemoteAddress: from})
}

type fakeOOBProvider struct{ ch *fakeChannel }

func (p *fakeOOBProvider) Channel(context.Context) (OOBChannel, error) { return p.ch, nil }
func (p *fakeOOBProvider) Close() error                                { return nil }

// The defect: the old check slept five seconds, polled once and closed the channel, so a callback
// in the sixth second was unrecoverable. The registry has to still find it.
func TestACallbackArrivingAfterTheCheckReturnedIsStillReported(t *testing.T) {
	ch := &fakeChannel{domain: "collab.test"}
	r := NewPendingRegistry()

	// Register the claim the way oobCheck now does, then let the callback arrive afterwards.
	if err := r.Register(PendingItem{
		Row:      "Out-of-band resource load (HTTP)",
		What:     "3 probes carrying x.collab.test planted in /fetch, awaiting an http callback",
		Deadline: nowUTC().Add(10 * time.Second),
	}, func(context.Context) (*Finding, bool, error) {
		got, err := ch.InteractionsFor("")
		if err != nil {
			return nil, false, err
		}
		for _, i := range oob.Deduplicate(got) {
			if strings.EqualFold(i.Protocol, "http") {
				return &Finding{Name: "Out-of-band resource load (HTTP)",
					Evidence: "http interaction from " + i.RemoteAddress}, true, nil
			}
		}
		return nil, false, nil
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// The window the old implementation had already closed.
	if found, outstanding := r.Poll(context.Background()); len(found) != 0 || outstanding != 1 {
		t.Fatalf("poll before the callback returned %d findings / %d outstanding, want 0 / 1",
			len(found), outstanding)
	}
	ch.callback("http", "203.0.113.9")

	found := r.Await(context.Background())
	if len(found) != 1 {
		t.Fatalf("got %d findings after a late callback, want 1: an interaction arriving after the "+
			"check returned is the case this registry exists for", len(found))
	}
	if !strings.Contains(found[0].Evidence, "203.0.113.9") {
		t.Errorf("evidence = %q, want the calling address so the finding can be corroborated",
			found[0].Evidence)
	}
}

// No callback is not evidence of no vulnerability. The claim must stay outstanding.
func TestNoCallbackIsReportedOutstandingRatherThanClean(t *testing.T) {
	ch := &fakeChannel{domain: "collab.test"}
	r := NewPendingRegistry()
	if err := r.Register(PendingItem{
		Row:      "External service interaction (DNS)",
		What:     "probes planted in /fetch, awaiting a dns callback",
		Deadline: nowUTC().Add(50 * time.Millisecond),
	}, func(context.Context) (*Finding, bool, error) {
		if _, err := ch.InteractionsFor(""); err != nil {
			return nil, false, err
		}
		// Never settles negatively, by design.
		return nil, false, nil
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if found := r.Await(context.Background()); len(found) != 0 {
		t.Fatalf("got %d findings with no callback, want 0", len(found))
	}
	out := r.Outstanding()
	if len(out) != 1 {
		t.Fatalf("Outstanding() = %d, want 1: silence from a collaborator is the absence of "+
			"evidence, not evidence of absence, and a report that omits it claims coverage", len(out))
	}
	if ch.reads == 0 {
		t.Error("the channel was never read, so the outstanding claim proves nothing about polling")
	}
}

// The channel must be shared across checks, not reopened per check: registration is expensive and
// per-check clients were closed before a callback could land.
func TestTheChannelIsRegisteredOnceAndSharedAcrossChecks(t *testing.T) {
	opened := 0
	p := &countingProvider{onOpen: func() { opened++ }, ch: &fakeChannel{domain: "collab.test"}}
	scan := NewActiveScanner(nil, nil).WithOOBProvider(p)

	for range 5 {
		if _, err := scan.OOBChannel(context.Background()); err != nil {
			t.Fatalf("OOBChannel: %v", err)
		}
	}
	if opened != 1 {
		t.Errorf("channel opened %d times for five requests, want 1: each registration spawns a "+
			"process and waits on public DNS, and a per-check client is closed before a callback "+
			"can arrive", opened)
	}
}

type countingProvider struct {
	onOpen func()
	ch     *fakeChannel
	once   sync.Once
}

func (p *countingProvider) Channel(context.Context) (OOBChannel, error) {
	p.once.Do(p.onOpen)
	return p.ch, nil
}
func (p *countingProvider) Close() error { return nil }

// With no provider the rows must refuse. Zero interactions from a channel nobody opened cannot be
// distinguished from a target that did not call back.
func TestNoProviderIsARefusalNotZeroInteractions(t *testing.T) {
	scan := NewActiveScanner(nil, nil)
	_, err := scan.OOBChannel(context.Background())
	if err == nil {
		t.Fatal("OOBChannel returned a channel with no provider installed")
	}
	if !strings.Contains(err.Error(), "cannot report a verdict") {
		t.Errorf("err = %q, want it to say a verdict is impossible rather than implying nothing "+
			"was found", err)
	}
}
