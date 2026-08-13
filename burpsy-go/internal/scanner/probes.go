package scanner

import (
	"context"
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// probeGate is the egress chokepoint a probe is sent through. The live type is
// *sender.AuthorisedSender; the interface exists so sendProbe can be unit-tested
// with a fake that records the context it received.
type probeGate interface {
	Send(ctx context.Context, raw []byte) (sender.AuthorisedResult, error)
	Refused() int64
}

// sendProbe sends raw through gate, capping the request at budget. A non-positive
// budget inherits the parent context's deadline (the audit item's), so the probe
// rides the audit's cancellation without its own clock. A positive budget derives a
// child context with its own timeout, so a single slow probe is cancelled on its own
// deadline rather than hanging the whole audit; the derived context is always
// cancelled (defer) so the underlying connection is released the moment the probe
// returns or times out. Cancellation therefore propagates both ways: a cancelled
// parent cancels the probe, and the per-probe timeout cancels a probe whose parent
// is still live. The returned bytes are the gate's raw response.
func sendProbe(ctx context.Context, gate probeGate, raw []byte, budget time.Duration) ([]byte, error) {
	send := func(c context.Context) ([]byte, error) {
		resp, err := gate.Send(c, raw)
		return resp.Raw, err
	}
	if budget <= 0 {
		return send(ctx)
	}
	pctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return send(pctx)
}

// probeBudgetFor reads the per-probe timeout from the scanner's config, returning
// zero (inherit the audit deadline) when config is unset.
func probeBudgetFor(s *ActiveScanner) time.Duration {
	if s == nil || s.config == nil {
		return 0
	}
	return s.config.ProbeTimeout
}
