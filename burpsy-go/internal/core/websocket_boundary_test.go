package core

import "testing"

// AtMessageBoundary (burpsy-react-ui-wuwf) is where Repeater's attach may splice a frame. Each of the
// three ways the stream can be mid-message is pinned on its own.
func TestAtMessageBoundaryKnowsEveryWayAStreamIsMidMessage(t *testing.T) {
	mask := [4]byte{1, 2, 3, 4}
	whole := EncodeWsFrame(WsOpcodeText, []byte("hello"), &mask)
	first := EncodeWsFrame(WsOpcodeText, []byte("hel"), &mask)
	first[0] &^= 0x80 // FIN clear: a fragmented message begins
	ping := EncodeWsFrame(WsOpcodePing, []byte("p"), &mask)
	last := EncodeWsFrame(WsOpcodeContinuation, []byte("lo"), &mask)

	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	if !r.AtMessageBoundary() {
		t.Fatal("a fresh stream is not at a boundary")
	}
	step := func(b []byte, want bool, what string) {
		t.Helper()
		if err := r.Feed(b); err != nil {
			t.Fatal(err)
		}
		if got := r.AtMessageBoundary(); got != want {
			t.Fatalf("%s: AtMessageBoundary = %v, want %v", what, got, want)
		}
	}
	step(whole[:1], false, "half a header")
	step(whole[1:4], false, "header done, payload not")
	step(whole[4:], true, "a whole frame")
	step(first, false, "a fragmented message's first frame")
	step(ping, false, "a control frame inside the fragmented message")
	step(last, true, "the final continuation")
}
