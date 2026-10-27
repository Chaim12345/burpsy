package extension

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

// Traffic hooks (burpsy-react-ui-tvv5). The proxy, the sender and the WebSocket layer call
// Host.Hook with a message; every loaded, granted plugin that registered a hook of that kind is
// asked in name order, each seeing the previous one's output.
//
// The contract, in the order a caller depends on it:
//
//  1. Hook never blocks past HookTimeout per plugin and never returns an error. A plugin that errors,
//     answers something this host cannot interpret, answers too slowly or has died leaves the message as
//     the previous step left it, and the failure is in HookResult.Failures, on the plugin's error console
//     and in its hook_failures counter.
//  2. A message no plugin changed comes back as the caller's own byte slice. Nothing is parsed or
//     re-serialised here, so duplicate headers and header order survive by construction.
//  3. A plugin that fails HookFailureLimit times running is suspended for HookCooldown: its hooks are
//     skipped, not called, so one broken plugin costs a few timeouts and not every request.
//  4. Only plugins the operator granted "hook.traffic" are called.

// Defaults for the hook bounds.
const (
	DefaultHookTimeout      = 2 * time.Second
	DefaultHookFailureLimit = 3
	DefaultHookCooldown     = 30 * time.Second
)

// HookCall is one message offered to the hooks of one kind.
type HookCall struct {
	Kind Kind
	// Phase is "request" or "response" for the HTTP and proxy kinds, "created" or "message" for
	// WebSocket.
	Phase string
	Raw   []byte
}

// HookFailure is one hook that did not produce a usable answer.
type HookFailure struct {
	Plugin       string `json:"plugin"`
	Registration string `json:"registration"`
	Reason       string `json:"reason"`
}

// HookResult is what the caller applies. Raw is always set: the original bytes unless a plugin
// replaced them.
type HookResult struct {
	Raw     []byte
	Changed bool
	// Dropped means a plugin asked for the message to be dropped (proxy and WebSocket only).
	Dropped bool
	// Intercept is the proxy hook's forced decision, nil when no plugin forced one.
	Intercept *bool
	// Applied names the plugins that answered validly, Failures those that did not. Both are
	// non-nil.
	Applied  []string
	Failures []HookFailure
}

func hookPhaseOK(kind Kind, phase string) bool {
	switch kind {
	case KindHTTPHandler, KindProxyHandler:
		return phase == "request" || phase == "response"
	case KindWebSocketHandler:
		return phase == "created" || phase == "message"
	}
	return false
}

// hookAction validates an answer's action for the kind. "" means continue.
func hookAction(kind Kind, action string) (string, bool) {
	if action == "" {
		action = "continue"
	}
	switch kind {
	case KindHTTPHandler:
		return action, action == "continue"
	case KindProxyHandler:
		switch action {
		case "continue", "drop", "intercept", "do-not-intercept":
			return action, true
		}
	case KindWebSocketHandler:
		return action, action == "continue" || action == "drop"
	}
	return action, false
}

// Hook offers the message to every granted plugin's hooks of call.Kind.
func (h *Host) Hook(ctx context.Context, call HookCall) HookResult {
	res := HookResult{Raw: call.Raw, Applied: []string{}, Failures: []HookFailure{}}
	if ctx == nil {
		ctx = context.Background()
	}
	if !hookPhaseOK(call.Kind, call.Phase) {
		res.Failures = append(res.Failures, HookFailure{Reason: fmt.Sprintf("phase %q is not valid for %q", call.Phase, call.Kind)})
		return res
	}
	h.mu.Lock()
	names := append([]string(nil), h.ordered...)
	h.mu.Unlock()

	for _, name := range names {
		p, err := h.lookup(name)
		if err != nil {
			continue
		}
		var regs []string
		p.mu.Lock()
		if p.state == StateLoaded {
			for _, reg := range p.registrations {
				if reg.Kind == call.Kind {
					regs = append(regs, reg.ID)
				}
			}
		}
		p.mu.Unlock()
		if len(regs) == 0 || !contains(p.grants, "hook.traffic") {
			continue
		}
		for _, id := range regs {
			if h.hookOne(ctx, p, id, call, &res) {
				return res
			}
		}
	}
	return res
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// hookOne runs one registration and folds its answer into res. It returns true when the chain
// must stop (a drop or an intercept decision).
func (h *Host) hookOne(ctx context.Context, p *plugin, id string, call HookCall, res *HookResult) (stop bool) {
	fail := func(reason string) {
		res.Failures = append(res.Failures, HookFailure{Plugin: p.name, Registration: id, Reason: reason})
		p.hookFails.Add(1)
		if p.hookStreak.Add(1) >= int64(h.cfg.HookFailureLimit) {
			p.hookSuspendEnd.Store(time.Now().Add(h.cfg.HookCooldown).UnixNano())
			p.hookStreak.Store(0)
			p.console.append(StreamError, SourceHost, fmt.Sprintf("hooks suspended for %s after %d consecutive failures", h.cfg.HookCooldown, h.cfg.HookFailureLimit))
		}
		p.console.append(StreamError, SourceHost, fmt.Sprintf("hook %q (%s) failed, the message was passed on unchanged by it: %s", id, call.Phase, reason))
	}
	if end := p.hookSuspendEnd.Load(); end != 0 {
		if time.Now().UnixNano() < end {
			res.Failures = append(res.Failures, HookFailure{Plugin: p.name, Registration: id, Reason: "plugin hooks are suspended after repeated failures"})
			return false
		}
		p.hookSuspendEnd.Store(0)
	}
	p.hookCalls.Add(1)

	text, enc := encodePayload(res.Raw)
	hctx, cancel := context.WithTimeout(ctx, h.cfg.HookTimeout)
	defer cancel()
	out, err := h.Invoke(hctx, p.name, InvokeParams{Registration: id, Phase: call.Phase, Raw: text, Encoding: enc})
	if err != nil {
		fail(err.Error())
		return false
	}
	action, ok := hookAction(call.Kind, out.Action)
	if !ok {
		fail(fmt.Sprintf("action %q is not allowed for a %s", out.Action, call.Kind))
		return false
	}
	var replacement []byte
	if action == "continue" && out.HookRaw != nil {
		replacement, err = decodePayload(out.HookRaw, out.Encoding)
		if err != nil {
			fail("undecodable replacement: " + err.Error())
			return false
		}
		if len(replacement) > h.cfg.MaxMessageBytes {
			fail(fmt.Sprintf("replacement is %d bytes, over the %d-byte bound", len(replacement), h.cfg.MaxMessageBytes))
			return false
		}
	}
	p.hookStreak.Store(0)
	res.Applied = append(res.Applied, p.name)
	switch action {
	case "drop":
		res.Dropped = true
		return true
	case "intercept", "do-not-intercept":
		v := action == "intercept"
		res.Intercept = &v
		return true
	}
	if replacement != nil && !bytes.Equal(replacement, res.Raw) {
		res.Raw, res.Changed = replacement, true
	}
	return false
}
