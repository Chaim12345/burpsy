package proxy

import (
	"context"
	"sync/atomic"
)

// traffic_hook.go is the proxy-listener half of the extension wiring
// (burpsy-react-ui-wiwh): a registered plugin's proxy handler sees every
// request and response this listener relays, before the bytes move on, and
// answers with replacement bytes, a drop, or a forced intercept decision.
// The sender half (sender.HTTPHook) covers the tools; this seam covers the
// browser's traffic through the listener, which never crosses the sender.
//
// Placement, stated once and mirrored at each call site:
//
//   - request: after Match & Replace, before the intercept hold. Extensions
//     see the effective message the operator configured (Burp's behaviour),
//     and their forced Intercept/DoNotIntercept decision feeds the hold that
//     runs next, which is the only slot where forcing interception can mean
//     anything.
//   - response: straight off the origin, before Match & Replace — the mirror
//     image of the request side, so the operator's static rules apply to what
//     the extension produced, same as they apply to what the client sent.
//
// A replacement cannot move the destination: the dial target is decided by
// the pipeline's own authority and retarget logic, not by the bytes, so an
// extension cannot widen a request past the engagement scope by rewriting it.
// The HTTP handler kind is invoked for this same traffic by the composition
// root's adapter, ahead of the proxy kind (Burp's documented order for
// proxied traffic); this package only knows about the combined seam below.

// TrafficHookResult is what a proxy traffic hook answered for one message.
// Raw always carries the bytes to continue with — the originals unless the
// hook replaced them.
type TrafficHookResult struct {
	Raw     []byte
	Changed bool
	// Dropped asks the listener to drop the message. Request drops mirror the
	// operator's own intercept-drop on each path; response drops suppress the
	// origin's bytes the same way the operator's response drop does.
	Dropped bool
	// Intercept is the hook's forced hold decision for a request: true forces
	// a hold, false forbids one, nil leaves the operator's rules in charge.
	// Meaningless on responses and ignored there.
	Intercept *bool
	// Applied names the plugins that answered validly; Failures counts those
	// that did not. Diagnostics only — the bytes are what matter.
	Applied  []string
	Failures int
}

// TrafficHook is the seam the composition root wires to the extension host.
// A nil hook — the default — leaves the relay byte-for-byte what it was, and
// a hook that errors is fail-open: the traffic continues on its original
// bytes and the failure is counted, matching the sender half's rule that a
// broken plugin must never wedge the operator's traffic.
type TrafficHook interface {
	HookTraffic(ctx context.Context, phase string, raw []byte) TrafficHookResult
}

// TrafficHookCounts is the running tally exposed for the extension UI row:
// how many messages crossed the seam, how many the hook changed or dropped,
// and how often it failed open.
type TrafficHookCounts struct {
	Calls    uint64 `json:"calls"`
	Changed  uint64 `json:"changed"`
	Dropped  uint64 `json:"dropped"`
	Failures uint64 `json:"failures"`
}

// trafficHook is the listener's hook, nil by default; the counters live
// beside it on ProxyConfig because the relay goroutines read them, and the
// same "set before NewServer" rule as toolLog applies — see WithTrafficHook.
type trafficHookState struct {
	hook     TrafficHook
	calls    atomic.Uint64
	changed  atomic.Uint64
	dropped  atomic.Uint64
	failures atomic.Uint64
}

// WithTrafficHook attaches the extension traffic hook. Nil — the default —
// leaves every relay byte-for-byte unwired. Set before NewServer: the field
// is read by every relay goroutine, so a later write would be a data race,
// not a late binding.
func (c *ProxyConfig) WithTrafficHook(h TrafficHook) *ProxyConfig {
	c.trafficHook.hook = h
	return c
}

// TrafficHookCounts returns the seam's running tallies.
func (c *ProxyConfig) TrafficHookCounts() TrafficHookCounts {
	return TrafficHookCounts{
		Calls:    c.trafficHook.calls.Load(),
		Changed:  c.trafficHook.changed.Load(),
		Dropped:  c.trafficHook.dropped.Load(),
		Failures: c.trafficHook.failures.Load(),
	}
}

// applyTrafficHook runs the wired hook over one message. Unwired it returns
// the input untouched; a hook panic is contained here as a failure so a
// plugin crash cannot take a relay goroutine — and the connection it serves —
// down with it.
func (s *Server) applyTrafficHook(ctx context.Context, phase string, raw []byte) (res TrafficHookResult) {
	st := &s.config.trafficHook
	if st.hook == nil {
		return TrafficHookResult{Raw: raw}
	}
	st.calls.Add(1)
	defer func() {
		if r := recover(); r != nil {
			st.failures.Add(1)
			res = TrafficHookResult{Raw: raw, Failures: 1}
		}
	}()
	res = st.hook.HookTraffic(ctx, phase, raw)
	if res.Raw == nil {
		res.Raw = raw
	}
	if res.Changed {
		st.changed.Add(1)
	}
	if res.Dropped {
		st.dropped.Add(1)
	}
	if res.Failures > 0 {
		st.failures.Add(uint64(res.Failures))
	}
	return res
}
