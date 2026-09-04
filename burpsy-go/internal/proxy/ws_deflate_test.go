package proxy

import (
	"bytes"
	"compress/flate"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// ---- what the operator is shown for a compressed message (issue 3ay) -----------------------
//
// core.InflateWsMessage is tested in its own package. What is tested here is the decision: which
// messages get inflated, and what the note says when one does not. That decision is the part with
// consequences — inflating a message whose compression window we do not have would show convincing
// but wrong plaintext, and this surface is read as evidence.

func deflateForTest(t *testing.T, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := fw.Write([]byte(payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := fw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{0x00, 0x00, 0xff, 0xff})
}

func inflateTestServer() *Server {
	return NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).WithLogger(zap.NewNop()))
}

// An uncompressed message passes through untouched, note included. The common case, and the one a
// bug here would break for every connection rather than only the compressed ones.
func TestAnUncompressedMessageIsRecordedUnchanged(t *testing.T) {
	srv := inflateTestServer()
	ev := &core.WsEvent{Opcode: core.WsOpcodeText, Payload: []byte("plain"), Note: "some note"}

	payload, note := srv.wsInflateForView(ev, core.WsDeflateParams{}, true)
	if string(payload) != "plain" {
		t.Errorf("payload = %q, want it unchanged", payload)
	}
	if note != "some note" {
		t.Errorf("note = %q, want the event's own note", note)
	}
}

// The case this work exists for: negotiated with no_context_takeover, so the message stands alone
// and the operator sees the message rather than a DEFLATE blob.
func TestACompressedMessageIsInflatedWhenItStandsAlone(t *testing.T) {
	srv := inflateTestServer()
	const original = `{"type":"chat","text":"hello there"}`
	ev := &core.WsEvent{
		Opcode:     core.WsOpcodeText,
		Payload:    deflateForTest(t, original),
		Compressed: true,
		Note:       "RSV1 is set: this payload is compressed",
	}
	params := core.WsDeflateParams{Negotiated: true, ClientNoContextTakeover: true}

	payload, note := srv.wsInflateForView(ev, params, true)
	if string(payload) != original {
		t.Errorf("payload = %q, want the inflated message %q", payload, original)
	}
	if !strings.Contains(note, "decoded from permessage-deflate") {
		t.Errorf("note = %q; a decoded message must say it was decoded, or the operator cannot tell "+
			"whether they are reading the message or the stream", note)
	}
}

// The refusal, and the note that has to explain it. Without no_context_takeover this message depends
// on a window we do not have.
func TestACompressedMessageIsKeptCompressedWhenContextCarriesOver(t *testing.T) {
	srv := inflateTestServer()
	compressed := deflateForTest(t, "would decode to nonsense without the window")
	ev := &core.WsEvent{
		Opcode: core.WsOpcodeText, Payload: compressed, Compressed: true,
		Note: "RSV1 is set:",
	}
	// Negotiated, but neither direction agreed no_context_takeover.
	params := core.WsDeflateParams{Negotiated: true}

	payload, note := srv.wsInflateForView(ev, params, true)
	if !bytes.Equal(payload, compressed) {
		t.Error("the payload was altered; an undecodable message must be recorded exactly as it arrived")
	}
	if !strings.Contains(note, "client_no_context_takeover") {
		t.Errorf("note = %q; it must name the parameter whose absence prevents decoding, so the "+
			"operator knows what to look for", note)
	}
	if !strings.Contains(note, "wrong plaintext") {
		t.Errorf("note = %q; it must say why burpsy declines rather than merely that it did", note)
	}
}

// Per direction: a server that agreed no_context_takeover for itself only must not have its client's
// messages decoded on the strength of that.
func TestTheDirectionsAreDecidedIndependently(t *testing.T) {
	srv := inflateTestServer()
	const original = "decodable"
	params := core.WsDeflateParams{Negotiated: true, ServerNoContextTakeover: true}

	newEvent := func() *core.WsEvent {
		return &core.WsEvent{
			Opcode: core.WsOpcodeText, Payload: deflateForTest(t, original),
			Compressed: true, Note: "RSV1 is set:",
		}
	}

	// server→client: agreed, so decoded.
	payload, _ := srv.wsInflateForView(newEvent(), params, false)
	if string(payload) != original {
		t.Errorf("server→client payload = %q, want it decoded", payload)
	}

	// client→server: not agreed, so kept compressed.
	ev := newEvent()
	kept, note := srv.wsInflateForView(ev, params, true)
	if string(kept) == original {
		t.Error("client→server was decoded on the strength of the SERVER's parameter")
	}
	if !strings.Contains(note, "client_no_context_takeover") {
		t.Errorf("note = %q, want it to name the client-side parameter", note)
	}
}

// A corrupt compressed payload must be recorded as it arrived, with the failure stated. Discarding
// it would lose the only evidence of what was on the wire.
func TestAnUndecodableCompressedMessageKeepsItsBytesAndSaysSo(t *testing.T) {
	srv := inflateTestServer()
	garbage := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb}
	ev := &core.WsEvent{Opcode: core.WsOpcodeText, Payload: garbage, Compressed: true, Note: "RSV1 is set:"}
	params := core.WsDeflateParams{Negotiated: true, ClientNoContextTakeover: true}

	payload, note := srv.wsInflateForView(ev, params, true)
	if !bytes.Equal(payload, garbage) {
		t.Error("a payload that failed to inflate was altered or dropped")
	}
	if !strings.Contains(note, "failed") {
		t.Errorf("note = %q; a failed decode must say so rather than leaving the operator to assume "+
			"the bytes are the message", note)
	}
}

// A decompression bomb is truncated at the cap, and what was decoded is kept — it is true as far as
// it goes — with the shortfall stated rather than the message discarded.
func TestABombIsTruncatedAtTheCapAndSaysSo(t *testing.T) {
	srv := inflateTestServer()
	bomb := deflateForTest(t, strings.Repeat("A", 4<<20))
	ev := &core.WsEvent{Opcode: core.WsOpcodeText, Payload: bomb, Compressed: true, Note: "RSV1 is set:"}
	params := core.WsDeflateParams{Negotiated: true, ClientNoContextTakeover: true}

	payload, note := srv.wsInflateForView(ev, params, true)
	if len(payload) != core.DefaultMaxWsMessageBytes {
		t.Errorf("payload is %d bytes, want exactly the %d cap", len(payload), core.DefaultMaxWsMessageBytes)
	}
	if !strings.Contains(note, "truncated") {
		t.Errorf("note = %q, want it to say the message was truncated at the cap", note)
	}
}
