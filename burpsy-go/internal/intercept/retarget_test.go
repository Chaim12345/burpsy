package intercept

import (
	"strings"
	"testing"
	"time"
)

// Burp's "Edit target" (burpsy-react-ui-akv) lets an operator send a held item to a different host,
// port or scheme. These are the cases the engine must refuse rather than pass on, and each refusal
// exists because the alternative is a request that goes somewhere the operator did not intend:

// TestEngine_ForwardRefusesARetargetWithoutAHost: an empty host reaches net.Dial as ":80", which is
// the local machine. A request silently sent to localhost because the operator cleared a field is the
// worst possible reading of an edit, so it is refused by name.
func TestEngine_ForwardRefusesARetargetWithoutAHost(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetRules(DirectionRequest, true, nil)
	h := e.Hold(reqMessage("a.test", "GET", "/"))
	if h == nil {
		t.Fatal("not held")
	}

	err := e.Forward(h.ID, nil, false, &Target{Host: "  ", Port: 8080})
	if err == nil {
		t.Fatal("Forward accepted a retarget with no host")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("error = %q, want it to name the missing host", err)
	}

	// And the hold is still there to correct. A refusal that resolved the hold would release the
	// request down the original path, which is the opposite of what the operator asked for.
	done := make(chan Action, 1)
	go func() {
		action, _, _ := h.Wait()
		done <- action
	}()
	select {
	case action := <-done:
		t.Fatalf("Wait returned %v after a refused retarget; the hold should have been left alone", action)
	case <-time.After(50 * time.Millisecond):
	}
	if err := e.Drop(h.ID, "test cleanup"); err != nil {
		t.Fatalf("Drop after a refused forward: %v", err)
	}
}

// TestEngine_ForwardRefusesARetargetWithoutAPort: port 0 is not "the default port", it is the
// wildcard, and a dial to host:0 is refused by the kernel. Refused up front so the operator is told
// which field is wrong instead of watching a request disappear.
func TestEngine_ForwardRefusesARetargetWithoutAPort(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetRules(DirectionRequest, true, nil)
	h := e.Hold(reqMessage("a.test", "GET", "/"))
	if h == nil {
		t.Fatal("not held")
	}
	err := e.Forward(h.ID, nil, false, &Target{Host: "b.test", Port: 0})
	if err == nil {
		t.Fatal("Forward accepted a retarget with port 0")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Errorf("error = %q, want it to name the port", err)
	}
}

// TestEngine_ForwardCarriesTheTargetToWait is the positive half: the destination the operator chose
// is what the proxy is handed alongside the bytes.
func TestEngine_ForwardCarriesTheTargetToWait(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetRules(DirectionRequest, true, nil)
	h := e.Hold(reqMessage("a.test", "GET", "/"))
	if h == nil {
		t.Fatal("not held")
	}
	target := &Target{Host: "b.test", Port: 8443, TLS: true}
	go func() {
		time.Sleep(20 * time.Millisecond)
		if err := e.Forward(h.ID, nil, false, target); err != nil {
			t.Errorf("Forward: %v", err)
		}
	}()
	action, _, got := h.Wait()
	if action != ActionForward {
		t.Fatalf("action = %v, want forward", action)
	}
	if got == nil {
		t.Fatal("the target did not reach Wait, so the proxy would send the request to the original host")
	}
	if *got != *target {
		t.Errorf("target = %+v, want %+v", *got, *target)
	}
}

// TestEngine_DropDropsTheTargetToo: a dropped message has no destination. Carrying one would let an
// exchange that never happened be recorded, or reported, against a host nothing was sent to.
func TestEngine_DropDropsTheTargetToo(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetRules(DirectionRequest, true, nil)
	h := e.Hold(reqMessage("a.test", "GET", "/"))
	if h == nil {
		t.Fatal("not held")
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		if err := e.Drop(h.ID, "no"); err != nil {
			t.Errorf("Drop: %v", err)
		}
	}()
	action, raw, target := h.Wait()
	if action != ActionDrop || raw != nil {
		t.Fatalf("action = %v raw = %q, want a drop with no bytes", action, raw)
	}
	if target != nil {
		t.Errorf("a dropped message came back with target %+v", *target)
	}
}

// TestEngine_ForwardRefusesARetargetOnAWebSocketFrame: a frame has no addressing of its own — it
// travels inside the connection its handshake established — so a destination on one is meaningless,
// and accepting it would silently discard the operator's instruction.
func TestEngine_ForwardRefusesARetargetOnAWebSocketFrame(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionWebSocketToServer, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	frame := &Message{
		Direction: DirectionWebSocketToServer,
		Host:      "a.test",
		Port:      443,
		TLS:       true,
		Opcode:    "text",
		Raw:       []byte("hello"),
	}
	h := e.Hold(frame)
	if h == nil {
		t.Fatal("the frame was not held")
	}
	err := e.Forward(h.ID, nil, false, &Target{Host: "b.test", Port: 443, TLS: true})
	if err == nil {
		t.Fatal("Forward accepted a retarget on a WebSocket frame")
	}
	if !strings.Contains(err.Error(), "WebSocket") {
		t.Errorf("error = %q, want it to name the reason", err)
	}
}
