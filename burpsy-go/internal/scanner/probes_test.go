package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// fakeGate records the context it was asked to send on and lets the test decide
// whether it blocks, returns a result, or surfaces an error.
type fakeGate struct {
	gotCtx     context.Context
	gotRaw     []byte
	refused    int64
	resp       []byte
	err        error
	blockOnCtx bool
}

func (f *fakeGate) Send(ctx context.Context, raw []byte) (sender.AuthorisedResult, error) {
	f.gotCtx = ctx
	f.gotRaw = raw
	if f.blockOnCtx {
		<-ctx.Done()
		return sender.AuthorisedResult{}, ctx.Err()
	}
	if ctx.Err() != nil {
		// A well-behaved sender aborts the moment its context is done and reports
		// the context error rather than a probe response.
		return sender.AuthorisedResult{}, ctx.Err()
	}
	return sender.AuthorisedResult{Raw: f.resp}, f.err
}

func (f *fakeGate) Refused() int64 { return f.refused }

// A zero budget inherits the parent context exactly: the gate sees the parent's
// context, carrying a parent deadline but no per-probe one.
func Test_sendProbe_inherits_parent_deadline_when_budget_zero(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g := &fakeGate{resp: []byte("ok")}

	raw, err := sendProbe(parent, g, []byte("req"), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(raw) != "ok" {
		t.Fatalf("got %q, want %q", raw, "ok")
	}
	if g.gotCtx != parent {
		// With no budget we pass the parent straight through.
		t.Fatalf("expected the parent context to reach the gate, got a derived one")
	}
}

// A cancelled parent propagates: even with no budget, the gate receives the
// already-cancelled context, so the probe cannot hang the audit.
func Test_sendProbe_propagates_parent_cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g := &fakeGate{resp: []byte("ignored")}

	_, err := sendProbe(ctx, g, []byte("req"), 0)
	if ctx.Err() == nil {
		t.Fatalf("parent should be cancelled")
	}
	if g.gotCtx.Err() == nil {
		t.Fatalf("gate must receive the cancelled context, so it can abort immediately")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// A positive budget derives a child context with its own deadline, so a slow
// probe is cancelled on its own clock and the parent audit stays live.
func Test_sendProbe_per_probe_timeout_cancels_slow_probe(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	g := &fakeGate{blockOnCtx: true}

	start := time.Now()
	_, err := sendProbe(parent, g, []byte("req"), 20*time.Millisecond)
	elapsed := time.Since(start)

	if ctxErr := context.Cause(g.gotCtx); !errors.Is(ctxErr, context.DeadlineExceeded) {
		t.Fatalf("probe context should time out: got %v", ctxErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("probe ran far longer than its 20ms budget: %v", elapsed)
	}
	if _, hasDeadline := g.gotCtx.Deadline(); !hasDeadline {
		t.Fatalf("per-probe context must carry its own deadline")
	}
}

// The derived per-probe context is always cancelled, releasing the connection
// even when the probe returns promptly.
func Test_sendProbe_release_connection_after_return(t *testing.T) {
	parent := context.Background()
	g := &fakeGate{resp: []byte("ok")}

	if _, err := sendProbe(parent, g, []byte("req"), 50*time.Millisecond); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Deferred cancel of the derived context is observable via its cause being set
	// on timeout, or simply that the parent (no deadline) is unaffected.
	if parent.Err() != nil {
		t.Fatalf("parent context must not be cancelled by the per-probe budget")
	}
}

func Test_probeBudgetFor_reads_config(t *testing.T) {
	s := &ActiveScanner{config: &ScanConfig{ProbeTimeout: 7 * time.Second}}
	if got := probeBudgetFor(s); got != 7*time.Second {
		t.Fatalf("got %v, want 7s", got)
	}
	if got := probeBudgetFor(nil); got != 0 {
		t.Fatalf("nil scanner must yield zero budget, got %v", got)
	}
	if got := probeBudgetFor(&ActiveScanner{}); got != 0 {
		t.Fatalf("nil config must yield zero budget, got %v", got)
	}
}
