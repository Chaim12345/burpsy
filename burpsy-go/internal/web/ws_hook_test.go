package web

// The extension websocket seam (burpsy-react-ui-wiwh, slice 3), end to end
// through /api/repeater/ws-send against the same echo target the send's own
// tests use. What is pinned: unwired is nothing, a "message" replacement
// reaches the target, a "created" rewrite that keeps its authority flows and
// moves the recorded path, a drop abandons the send and is told to the
// operator, an out-of-authority "created" rewrite is refused closed, and a
// panicking hook fails open.

import (
	"context"
	"encoding/json"

	"net/http"
	"strings"
	"testing"
)

type wsHookStub func(ctx context.Context, phase string, raw []byte) WsHookResult

func (f wsHookStub) HookWs(ctx context.Context, phase string, raw []byte) WsHookResult {
	return f(ctx, phase, raw)
}

func TestWsHookUnwiredLeavesBytesUntouched(t *testing.T) {
	s := newTestServer()
	raw := []byte("GET /chat HTTP/1.1\r\nHost: example\r\n\r\n")
	res := s.applyWsHook(context.Background(), "created", raw)
	if string(res.Raw) != string(raw) || res.Changed || res.Dropped {
		t.Fatalf("unwired hook altered the message: %+v", res)
	}
	if c := s.WsHookCounts(); c != (WsHookCounts{}) {
		t.Fatalf("unwired hook counted calls: %+v", c)
	}
}

func TestWsHookMessageReplacementReachesTheTarget(t *testing.T) {
	target := wsEchoTarget(t)
	host, _ := repeaterWsTargetOf(target)

	s := newTestServer()
	s.scope.AddInclude(host)
	s.WithWsHook(wsHookStub(func(_ context.Context, phase string, raw []byte) WsHookResult {
		if phase == "message" {
			return WsHookResult{Raw: []byte("hooked frame"), Changed: true, Applied: []string{"stub"}}
		}
		return WsHookResult{Raw: raw}
	}))

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"target":  target.URL[len("http://"):],
		"path":    "/",
		"opcode":  "text",
		"payload": "original frame",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var resp repeaterWsSendResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The echo target answers "echo: <what it received>", so the reply proves which
	// bytes left the machine.
	if len(resp.Messages) != 1 || resp.Messages[0].Payload != "echo: hooked frame" {
		t.Fatalf("reply = %+v, want the echo of the HOOKED frame", resp.Messages)
	}
	if c := s.WsHookCounts(); c.Calls != 2 || c.Changed != 1 {
		t.Fatalf("counts: %+v", c)
	}
}

func TestWsHookDropAbandonsTheSendAndSaysSo(t *testing.T) {
	target := wsEchoTarget(t)
	host, _ := repeaterWsTargetOf(target)

	s := newTestServer()
	s.scope.AddInclude(host)
	s.WithWsHook(wsHookStub(func(_ context.Context, phase string, raw []byte) WsHookResult {
		if phase == "message" {
			return WsHookResult{Raw: raw, Dropped: true, Applied: []string{"stub"}}
		}
		return WsHookResult{Raw: raw}
	}))

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"target":  target.URL[len("http://"):],
		"path":    "/",
		"opcode":  "text",
		"payload": "doomed frame",
	})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "dropped by extension") {
		t.Fatalf("status = %d (%s), want a named drop", rec.Code, rec.Body.String())
	}
	if c := s.WsHookCounts(); c.Dropped != 1 {
		t.Fatalf("counts: %+v", c)
	}
}

func TestWsHookCreatedRewriteKeepsAuthorityAndMovesThePath(t *testing.T) {
	target := wsEchoTarget(t)
	host, _ := repeaterWsTargetOf(target)

	s := newTestServer()
	s.scope.AddInclude(host)
	s.WithWsHook(wsHookStub(func(_ context.Context, phase string, raw []byte) WsHookResult {
		if phase == "created" {
			return WsHookResult{
				Raw:     []byte(strings.Replace(string(raw), "GET / ", "GET /hooked ", 1)),
				Changed: true, Applied: []string{"stub"},
			}
		}
		return WsHookResult{Raw: raw}
	}))

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"target":  target.URL[len("http://"):],
		"path":    "/",
		"opcode":  "text",
		"payload": "frame",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var resp repeaterWsSendResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	ex, err := s.store.GetExchange(resp.ExchangeID)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ex.Path != "/hooked" {
		t.Fatalf("recorded path = %q, want the hooked handshake's path", ex.Path)
	}
}

// A "created" replacement that breaks the plan's raw-bytes gate is refused
// closed. The rewrite here destroys the request line, which is the refusal
// AuthoriseRaw can state plainly. Swapping the Host header is deliberately NOT
// the attack pinned: the dial target comes from the plan, never the bytes, so
// a header-swap lands on the same authorised authority — confusing, but not a
// scope escape, and exactly what the operator's own Match & Replace can do.
func TestWsHookCreatedRewriteThatFailsTheRecheckIsRefusedClosed(t *testing.T) {
	target := wsEchoTarget(t)
	host, _ := repeaterWsTargetOf(target)

	s := newTestServer()
	s.scope.AddInclude(host)
	s.WithWsHook(wsHookStub(func(_ context.Context, phase string, raw []byte) WsHookResult {
		if phase == "created" {
			return WsHookResult{
				Raw:     []byte(strings.Replace(string(raw), "GET / ", "GARBAGE ", 1)),
				Changed: true, Applied: []string{"stub"},
			}
		}
		return WsHookResult{Raw: raw}
	}))

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"target":  target.URL[len("http://"):],
		"path":    "/",
		"opcode":  "text",
		"payload": "frame",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d (%s), want a closed refusal of the rewrite that fails the re-check", rec.Code, rec.Body.String())
	}
}

func TestWsHookPanicFailsOpen(t *testing.T) {
	target := wsEchoTarget(t)
	host, _ := repeaterWsTargetOf(target)

	s := newTestServer()
	s.scope.AddInclude(host)
	s.WithWsHook(wsHookStub(func(_ context.Context, phase string, raw []byte) WsHookResult {
		panic("plugin exploded")
	}))

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"target":  target.URL[len("http://"):],
		"path":    "/",
		"opcode":  "text",
		"payload": "frame",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("a panicking hook must not wedge the send: %d (%s)", rec.Code, rec.Body.String())
	}
	if c := s.WsHookCounts(); c.Failures == 0 {
		t.Fatalf("the panic was not counted: %+v", c)
	}
}
