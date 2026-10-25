package sender

import "context"

// HTTPHook is the sender's seam for extension traffic handlers (burpsy-react-ui-wiwh wiring).
// One implementation lives at the composition root (an adapter over extension.Host); the sender
// knows nothing about plugins. The contract mirrors the host's: HookHTTP never blocks past the
// host's per-plugin timeout and never returns an error - a plugin that fails is reported in
// Failures and the original bytes carry on. Availability first, always.
type HTTPHook interface {
	// HookHTTP offers one message (phase is "request" or "response") and returns what to carry.
	HookHTTP(ctx context.Context, phase string, raw []byte) HTTPHookResult
}

// HTTPHookResult is the hook's answer for one message. Raw is always set: the offered bytes
// unless a granted plugin replaced them.
type HTTPHookResult struct {
	Raw     []byte
	Changed bool
	// Applied names the plugins that answered validly; Failures counts the ones that did not.
	Applied  []string
	Failures int
}

// HTTPHookFunc adapts a closure to HTTPHook, so the composition root can wire an
// extension.Host without the sender importing the extension package.
type HTTPHookFunc func(ctx context.Context, phase string, raw []byte) HTTPHookResult

// HookHTTP implements HTTPHook.
func (f HTTPHookFunc) HookHTTP(ctx context.Context, phase string, raw []byte) HTTPHookResult {
	return f(ctx, phase, raw)
}

// WithHTTPHook sets the traffic hook every send through an AuthorisedSender built on this Sender
// consults. Like the other With* mutators it is a boot-time call: it takes mu, so it is safe
// against concurrent sends, but it is meant for the wiring in main, not for runtime flipping.
//
// nil is the supported default and the zero-change state: with no hook, the send path is one
// nil check exactly as before this existed.
func (s *Sender) WithHTTPHook(h HTTPHook) *Sender {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.httpHook = h
	return s
}

// hook returns the configured hook, or nil.
func (s *Sender) hook() HTTPHook {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.httpHook
}

// HTTPHookCounters are the running totals the tool log surface reads (wiring for that surface
// is a later slice; the counters are the seam).
type HTTPHookCounters struct {
	RequestsChanged  int64
	ResponsesChanged int64
	Failures         int64
}

// HTTPHookCounts returns a copy of the running totals.
func (s *Sender) HTTPHookCounts() HTTPHookCounters {
	return HTTPHookCounters{
		RequestsChanged:  s.httpHookRequestsChanged.Load(),
		ResponsesChanged: s.httpHookResponsesChanged.Load(),
		Failures:         s.httpHookFailures.Load(),
	}
}

// hookRequest offers an outbound request to the hook. A replacement is scope-checked against the
// same authority before it may leave: the hook can narrow a request's ambition, never widen it,
// and never move it to another host. A refused replacement refuses the send like any scope refusal.
// A refusal returns the scope error, exactly as if the replaced bytes had arrived from the caller.
func (a *AuthorisedSender) hookRequest(ctx context.Context, raw []byte) ([]byte, error) {
	h := a.net.hook()
	if h == nil {
		return raw, nil
	}
	res := h.HookHTTP(ctx, "request", raw)
	a.net.httpHookFailures.Add(int64(res.Failures))
	if !res.Changed {
		return raw, nil
	}
	if err := a.scope.AuthoriseRaw(a.host, a.port, a.tls, res.Raw); err != nil {
		a.refused.Add(1)
		return nil, err
	}
	a.net.httpHookRequestsChanged.Add(1)
	return res.Raw, nil
}

// hookResponse offers an inbound response to the hook. Responses carry no destination authority,
// so there is nothing to re-scope: what the hook returns is what the caller sees.
func (a *AuthorisedSender) hookResponse(ctx context.Context, resp []byte) []byte {
	h := a.net.hook()
	if h == nil {
		return resp
	}
	res := h.HookHTTP(ctx, "response", resp)
	a.net.httpHookFailures.Add(int64(res.Failures))
	if res.Changed {
		a.net.httpHookResponsesChanged.Add(1)
		return res.Raw
	}
	return resp
}

