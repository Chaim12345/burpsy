package web

import (
	"context"
	"sync/atomic"
)

// ws_hook.go is the WebSocket half of the extension wiring
// (burpsy-react-ui-wiwh, slice 3): a registered plugin's websocket handler
// sees the Repeater's ws sends. "created" carries the authorised handshake
// bytes before the dial, "message" the frame payload before it goes out; a
// plugin answers replacement bytes or a drop (the kind's only two actions).
//
// The anti-widening rule is the sender seam's, ported: a "created" replacement
// must re-pass the same raw-bytes scope gate the plan already passed against
// the same authority, and the dial target still comes from the plan, never
// from the bytes. A replacement that cannot re-pass is refused closed — the
// send does not happen — because sending it would mean the bytes on the wire
// are not the bytes the scope authorised.

// WsHookResult is what a websocket hook answered for one phase. Raw always
// carries the bytes to continue with — the originals unless replaced.
type WsHookResult struct {
	Raw     []byte
	Changed bool
	// Dropped asks the send to be abandoned. The operator is told, and the
	// attempt is written to the tool log like any send that left nothing on
	// the wire.
	Dropped  bool
	Applied  []string
	Failures int
}

// WsHook is the seam the composition root wires to the extension host. Nil —
// the default — leaves the send byte-for-byte what it was; a panicking hook
// fails open and is counted, matching the proxy and sender halves' rule that
// a broken plugin must never wedge the operator's traffic.
type WsHook interface {
	HookWs(ctx context.Context, phase string, raw []byte) WsHookResult
}

// WsHookCounts is the running tally exposed for the extension UI row.
type WsHookCounts struct {
	Calls    uint64 `json:"calls"`
	Changed  uint64 `json:"changed"`
	Dropped  uint64 `json:"dropped"`
	Failures uint64 `json:"failures"`
}

type wsHookState struct {
	hook     WsHook
	calls    atomic.Uint64
	changed  atomic.Uint64
	dropped  atomic.Uint64
	failures atomic.Uint64
}

// WithWsHook attaches the extension websocket hook. Nil leaves every send
// byte-for-byte unwired. Set before serving: the field is read by request
// goroutines, so a later write would be a data race, not a late binding.
func (s *Server) WithWsHook(h WsHook) *Server {
	s.wsHook.hook = h
	return s
}

// WsHookCounts returns the seam's running tallies.
func (s *Server) WsHookCounts() WsHookCounts {
	return WsHookCounts{
		Calls:    s.wsHook.calls.Load(),
		Changed:  s.wsHook.changed.Load(),
		Dropped:  s.wsHook.dropped.Load(),
		Failures: s.wsHook.failures.Load(),
	}
}

// applyWsHook runs the wired hook over one phase. Unwired it returns the
// input untouched; a hook panic is contained here as a failure so a plugin
// crash cannot take the request goroutine down with it.
func (s *Server) applyWsHook(ctx context.Context, phase string, raw []byte) (res WsHookResult) {
	st := &s.wsHook
	if st.hook == nil {
		return WsHookResult{Raw: raw}
	}
	st.calls.Add(1)
	defer func() {
		if r := recover(); r != nil {
			st.failures.Add(1)
			res = WsHookResult{Raw: raw, Failures: 1}
		}
	}()
	res = st.hook.HookWs(ctx, phase, raw)
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
