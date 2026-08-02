package core

import (
	"strings"
	"testing"
)

// Build a frame the way a peer would, so the tests exercise the decoder rather
// than a helper that shares its assumptions.
func wsFrame(t *testing.T, fin bool, opcode byte, mask *[4]byte, payload []byte) []byte {
	t.Helper()
	out := []byte{opcode}
	if fin {
		out[0] |= 0x80
	}
	switch n := len(payload); {
	case n < 126:
		out = append(out, byte(n))
	case n <= 65535:
		out = append(out, 126, byte(n>>8), byte(n))
	default:
		out = append(out, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	if mask != nil {
		out[1] |= 0x80
		out = append(out, mask[:]...)
		at := len(out)
		out = append(out, payload...)
		WsUnmask(out[at:], *mask, 0)
	} else {
		out = append(out, payload...)
	}
	return out
}

func drainEvents(r *WsReassembler) []*WsEvent {
	var v []*WsEvent
	for {
		ev := r.Pop()
		if ev == nil {
			return v
		}
		v = append(v, ev)
	}
}

func TestWsWholeUnmaskedTextFrameYieldsOneMessage(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	if err := r.Feed(wsFrame(t, true, 0x1, nil, []byte("hello"))); err != nil {
		t.Fatalf("feed: %v", err)
	}
	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1 (one frame is one message)", len(ev))
	}
	if ev[0].Opcode != WsOpcodeText {
		t.Errorf("opcode = %v, want text", ev[0].Opcode)
	}
	if string(ev[0].Payload) != "hello" {
		t.Errorf("payload = %q, want hello", ev[0].Payload)
	}
	if ev[0].Fragments != 1 || ev[0].Dropped != 0 || ev[0].Note != "" {
		t.Errorf("unexpected event fields: %+v", ev[0])
	}
}

func TestWsMaskedFrameIsCapturedWithTheMaskRemoved(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	mask := [4]byte{0xde, 0xad, 0xbe, 0xef}
	wire := wsFrame(t, true, 0x1, &mask, []byte("secret payload"))
	if string(wire[len(wire)-14:]) == "secret payload" {
		t.Fatal("the fixture must actually be masked, or this test proves nothing")
	}
	if err := r.Feed(wire); err != nil {
		t.Fatalf("feed: %v", err)
	}
	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1", len(ev))
	}
	if string(ev[0].Payload) != "secret payload" {
		t.Errorf("payload = %q, want the unmasked bytes", ev[0].Payload)
	}
}

func TestWsDecoderAgreesAtEveryPossibleSplit(t *testing.T) {
	mask := [4]byte{1, 2, 3, 4}
	wire := append(append(append(
		wsFrame(t, true, 0x1, &mask, []byte("first message here")),
		wsFrame(t, true, 0x2, nil, bytesN(300, 0xff))...),
		wsFrame(t, true, 0x9, nil, []byte("ping"))...), []byte{}...)

	expect := func() []string {
		r := NewWsReassembler(DefaultMaxWsMessageBytes)
		if err := r.Feed(wire); err != nil {
			t.Fatalf("feed: %v", err)
		}
		var v []string
		for _, ev := range drainEvents(r) {
			v = append(v, string(ev.Payload))
		}
		return v
	}()
	if len(expect) != 3 {
		t.Fatalf("expect = %d, want 3", len(expect))
	}

	for split := 1; split < len(wire); split++ {
		r := NewWsReassembler(DefaultMaxWsMessageBytes)
		if err := r.Feed(wire[:split]); err != nil {
			t.Fatalf("feed first half at split %d: %v", split, err)
		}
		if err := r.Feed(wire[split:]); err != nil {
			t.Fatalf("feed second half at split %d: %v", split, err)
		}
		var got []string
		for _, ev := range drainEvents(r) {
			got = append(got, string(ev.Payload))
		}
		if strings.Join(got, "|") != strings.Join(expect, "|") {
			t.Fatalf("split at %d decoded differently from the unsplit stream — a header or mask offset does not survive that seam", split)
		}
	}
}

func bytesN(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestWsFragmentedMessageIsReassembledAndCountsFrames(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	if err := r.Feed(wsFrame(t, false, 0x1, nil, []byte("one "))); err != nil {
		t.Fatalf("feed: %v", err)
	}
	if err := r.Feed(wsFrame(t, false, 0x0, nil, []byte("two "))); err != nil {
		t.Fatalf("feed: %v", err)
	}
	if ev := r.Pop(); ev != nil {
		t.Fatal("an unterminated message must not be emitted early")
	}
	if err := r.Feed(wsFrame(t, true, 0x0, nil, []byte("three"))); err != nil {
		t.Fatalf("feed: %v", err)
	}
	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1", len(ev))
	}
	if string(ev[0].Payload) != "one two three" {
		t.Errorf("payload = %q", ev[0].Payload)
	}
	if ev[0].Opcode != WsOpcodeText {
		t.Errorf("opcode = %v, want text (the first frame names the type)", ev[0].Opcode)
	}
	if ev[0].Fragments != 3 {
		t.Errorf("fragments = %d, want 3", ev[0].Fragments)
	}
}

func TestWsControlFrameInterleavedWithFragmentsDoesNotJoinTheMessage(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	feed(t, r, wsFrame(t, false, 0x2, nil, []byte("AAAA")))
	feed(t, r, wsFrame(t, true, 0x9, nil, []byte("pp")))
	feed(t, r, wsFrame(t, true, 0x0, nil, []byte("BBBB")))
	ev := drainEvents(r)
	if len(ev) != 2 {
		t.Fatalf("events = %d, want 2 (the ping and the message are separate)", len(ev))
	}
	if ev[0].Opcode != WsOpcodePing || string(ev[0].Payload) != "pp" {
		t.Errorf("ev[0] = %+v, want the ping with its payload", ev[0])
	}
	if ev[1].Opcode != WsOpcodeBinary || string(ev[1].Payload) != "AAAABBBB" {
		t.Errorf("ev[1] = %+v, want the reassembled binary message without the ping's payload", ev[1])
	}
	if ev[1].Fragments != 2 {
		t.Errorf("fragments = %d, want 2", ev[1].Fragments)
	}
}

func feed(t *testing.T, r *WsReassembler, data []byte) {
	t.Helper()
	if err := r.Feed(data); err != nil {
		t.Fatalf("feed: %v", err)
	}
}

func TestWsOversizedMessageIsTruncatedAndCountsWhatItDidNotKeep(t *testing.T) {
	r := NewWsReassembler(8)
	feed(t, r, wsFrame(t, true, 0x2, nil, bytesN(20, 0x41)))
	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1", len(ev))
	}
	if len(ev[0].Payload) != 8 {
		t.Errorf("kept %d bytes, want exactly the cap (8)", len(ev[0].Payload))
	}
	if ev[0].Dropped != 12 {
		t.Errorf("dropped = %d, want 12 — the row must not lie about the message size", ev[0].Dropped)
	}
}

func TestWsCapAppliesToTheReassembledMessageNotToEachFragment(t *testing.T) {
	r := NewWsReassembler(6)
	feed(t, r, wsFrame(t, false, 0x1, nil, []byte("aaaa")))
	feed(t, r, wsFrame(t, true, 0x0, nil, []byte("bbbb")))
	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1", len(ev))
	}
	if string(ev[0].Payload) != "aaaabb" {
		t.Errorf("payload = %q, want aaaabb (the cap bounds the whole message, not each frame)", ev[0].Payload)
	}
	if ev[0].Dropped != 2 {
		t.Errorf("dropped = %d, want 2", ev[0].Dropped)
	}
}

func TestWsOversizedControlFrameIsRecordedRatherThanRefused(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	feed(t, r, wsFrame(t, true, 0x9, nil, bytesN(200, 0x42)))
	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1 (still captured)", len(ev))
	}
	if len(ev[0].Payload) != 200 {
		t.Errorf("payload = %d bytes, want 200", len(ev[0].Payload))
	}
	if !strings.Contains(ev[0].Note, "5.5") {
		t.Errorf("note = %q, want a citation of the rule broken (RFC 6455 §5.5)", ev[0].Note)
	}
}

func TestWsContinuationWithNothingInFlightIsNotedNotDropped(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	feed(t, r, wsFrame(t, true, 0x0, nil, []byte("orphan")))
	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1", len(ev))
	}
	if string(ev[0].Payload) != "orphan" {
		t.Errorf("payload = %q", ev[0].Payload)
	}
	if !strings.Contains(ev[0].Note, "no fragmented") {
		t.Errorf("note = %q, want the anomaly named", ev[0].Note)
	}
}

func TestWsLengthWithReservedHighBitSetStopsTheCaptureAndSaysWhy(t *testing.T) {
	wire := []byte{0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0}
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	err := r.Feed(wire)
	if err == nil {
		t.Fatal("feed must fail: nothing after this header can be located")
	}
	if !strings.Contains(err.Error(), "unknowable") {
		t.Errorf("error = %q, want the reason stated", err)
	}
}

func TestWsPartialHeaderAsksForMoreBytesRatherThanFailing(t *testing.T) {
	if hdr, more, err := ParseWsFrameHeader(nil); err != nil || !more || hdr != nil {
		t.Errorf("empty = (%v, %v, %v), want (nil, true, nil)", hdr, more, err)
	}
	if _, more, err := ParseWsFrameHeader([]byte{0x81}); err != nil || !more {
		t.Errorf("single byte = (%v, %v), want keep reading", more, err)
	}
	// 126 announces a 2-byte extended length that has not arrived.
	if _, more, err := ParseWsFrameHeader([]byte{0x81, 126, 0x01}); err != nil || !more {
		t.Errorf("partial extended length = (%v, %v), want keep reading", more, err)
	}
	// A mask bit whose key has not arrived.
	if _, more, err := ParseWsFrameHeader([]byte{0x81, 0x85, 0xde, 0xad}); err != nil || !more {
		t.Errorf("partial mask = (%v, %v), want keep reading", more, err)
	}
}

func TestWsExtendedLengthsAndMaskAreAccountedForInTheHeaderLength(t *testing.T) {
	hdr, more, err := ParseWsFrameHeader(wsFrame(t, true, 0x2, nil, bytesN(400, 0)))
	if err != nil || more {
		t.Fatalf("parse = (%v, %v)", more, err)
	}
	if hdr.PayloadLen != 400 || hdr.HeaderLen != 4 {
		t.Errorf("16-bit len = (%d, %d), want (400, 4)", hdr.PayloadLen, hdr.HeaderLen)
	}

	wire := []byte{0x82, 127, 0, 0, 0, 0, 0, 1, 0x11, 0x70}
	hdr, more, err = ParseWsFrameHeader(wire)
	if err != nil || more {
		t.Fatalf("parse = (%v, %v)", more, err)
	}
	if hdr.PayloadLen != 70000 || hdr.HeaderLen != 10 {
		t.Errorf("64-bit len = (%d, %d), want (70000, 10)", hdr.PayloadLen, hdr.HeaderLen)
	}

	mask := [4]byte{9, 9, 9, 9}
	hdr, more, err = ParseWsFrameHeader(wsFrame(t, true, 0x1, &mask, []byte("x")))
	if err != nil || more {
		t.Fatalf("parse = (%v, %v)", more, err)
	}
	if hdr.HeaderLen != 6 || hdr.Mask != mask {
		t.Errorf("masked header = (len %d, mask %v), want (6, %v)", hdr.HeaderLen, hdr.Mask, mask)
	}
}

func TestWsReservedOpcodeKeepsItsNumber(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	feed(t, r, wsFrame(t, true, 0xb, nil, []byte("?")))
	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("events = %d, want 1", len(ev))
	}
	if ev[0].Opcode != WsOpcode(0xb) {
		t.Errorf("opcode = %v, want 0xb — a probe wants to see what it sent", ev[0].Opcode)
	}
	if ev[0].Opcode.Name() != "reserved(0xb)" {
		t.Errorf("name = %q", ev[0].Opcode.Name())
	}
	if !ev[0].Opcode.IsControl() {
		t.Error("0xb is in the control range")
	}
}

func TestWsRSVBitsSurviveTheDecode(t *testing.T) {
	hdr, more, err := ParseWsFrameHeader([]byte{0xc1, 0x00})
	if err != nil || more {
		t.Fatalf("parse = (%v, %v)", more, err)
	}
	if hdr.RSV != 0b100 {
		t.Errorf("rsv = %b, want 100 (RSV1)", hdr.RSV)
	}
	if !hdr.FIN {
		t.Error("fin must be set")
	}
	if hdr.Opcode != WsOpcodeText {
		t.Errorf("opcode = %v, want text", hdr.Opcode)
	}
}

// ---- Compression honesty -----------------------------------------------------------------------

// rsv1 sets the wire bit permessage-deflate uses to mark a compressed payload.
// On the wire it is bit 0x40 of the first byte; the decoder reports it as
// RSV == 0x04, having shifted the nibble down.
func rsv1(frame []byte) []byte {
	frame[0] |= 0x40
	return frame
}

func TestWsCompressedFrameIsRecordedWithANoteRatherThanAsPlaintext(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	deflated := []byte{0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}
	feed(t, r, rsv1(wsFrame(t, true, 0x1, nil, deflated)))

	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("a compressed frame produced %d messages; it must still be recorded as one", len(ev))
	}
	if ev[0].Note == "" {
		t.Fatal("a permessage-deflate payload was recorded with no note, so history offers a DEFLATE block as though it were the message text")
	}
	if !strings.Contains(ev[0].Note, "RSV1") {
		t.Errorf("the note does not name RSV1, so an operator cannot tell why the payload is unreadable: %q", ev[0].Note)
	}
	if string(ev[0].Payload) != string(deflated) {
		t.Error("the payload was altered; an undecoded frame must be kept byte for byte as it arrived, or the note describes something other than what is shown")
	}
}

func TestWsUncompressedFrameCarriesNoNoteSoTheNoteMeansSomething(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	feed(t, r, wsFrame(t, true, 0x1, nil, []byte("plain")))

	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("got %d messages, want 1", len(ev))
	}
	if ev[0].Note != "" {
		t.Errorf("an ordinary frame was annotated %q; a note that appears on healthy traffic stops meaning anything", ev[0].Note)
	}
}

func TestWsCompressionNoteBelongsToItsOwnMessageOnly(t *testing.T) {
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	feed(t, r, rsv1(wsFrame(t, true, 0x1, nil, []byte("compressed"))))
	feed(t, r, wsFrame(t, true, 0x1, nil, []byte("clear")))

	ev := drainEvents(r)
	if len(ev) != 2 {
		t.Fatalf("got %d messages, want 2", len(ev))
	}
	if ev[0].Note == "" {
		t.Error("the compressed message lost its note")
	}
	if ev[1].Note != "" {
		t.Errorf("the following message inherited %q, which would mark a readable payload as unreadable", ev[1].Note)
	}
}

func TestWsCompressedFragmentsAreNotedOnceForTheWholeMessage(t *testing.T) {
	// RFC 7692 sets RSV1 on the first frame of a message only, so the note has
	// to survive reassembly rather than being attached per frame.
	r := NewWsReassembler(DefaultMaxWsMessageBytes)
	feed(t, r, rsv1(wsFrame(t, false, 0x1, nil, []byte("head"))))
	feed(t, r, wsFrame(t, true, 0x0, nil, []byte("tail")))

	ev := drainEvents(r)
	if len(ev) != 1 {
		t.Fatalf("got %d messages, want 1 reassembled message", len(ev))
	}
	if !strings.Contains(ev[0].Note, "RSV1") {
		t.Errorf("a fragmented compressed message was recorded without saying so: note = %q", ev[0].Note)
	}
	if ev[0].Fragments != 2 {
		t.Errorf("fragments = %d, want 2; the note must not cost the frame count", ev[0].Fragments)
	}
}

// ---- Handshake rewriting -----------------------------------------------------------------------

func wsHandshake(extensions string) []byte {
	req := "GET /chat HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: keep-alive, Upgrade\r\n"
	if extensions != "" {
		req += "Sec-WebSocket-Extensions: " + extensions + "\r\n"
	}
	return []byte(req + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
}

func TestWsStripExtensionsRemovesTheOfferAndNamesWhatItRemoved(t *testing.T) {
	out, removed, err := StripWsExtensionsHeader(wsHandshake("permessage-deflate; client_max_window_bits"))
	if err != nil {
		t.Fatalf("a well-formed handshake was refused: %v", err)
	}
	if strings.Contains(strings.ToLower(string(out)), WsExtensionsHeader) {
		t.Fatalf("the offer survived the strip, so the origin can still negotiate compression:\n%s", out)
	}
	if len(removed) != 1 || removed[0] != "permessage-deflate; client_max_window_bits" {
		t.Errorf("removed = %q; the caller cannot record what it took out unless the value comes back verbatim", removed)
	}
	if !IsWsUpgradeRequest(out) {
		t.Fatalf("the rewritten request is no longer a recognisable upgrade, so the strip broke the handshake it was cleaning:\n%s", out)
	}
	if !strings.HasSuffix(string(out), "\r\n\r\n") {
		t.Errorf("the header block no longer terminates, so the rest of the handshake would be read as a body:\n%s", out)
	}
	if !strings.Contains(string(out), "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==") {
		t.Errorf("a header after the removed line was lost:\n%s", out)
	}
}

func TestWsStripExtensionsRemovesEveryOfferNotJustTheFirst(t *testing.T) {
	raw := []byte("GET /chat HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate\r\n" +
		"Upgrade: websocket\r\n" +
		"sec-websocket-extensions: x-private-codec\r\n" +
		"Connection: Upgrade\r\n\r\n")

	out, removed, err := StripWsExtensionsHeader(raw)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if len(removed) != 2 {
		t.Fatalf("removed %d offers, want 2; a header list is repeatable and stopping at the first leaves compression negotiable", len(removed))
	}
	if strings.Contains(strings.ToLower(string(out)), WsExtensionsHeader) {
		t.Errorf("an offer survived:\n%s", out)
	}
	if !IsWsUpgradeRequest(out) {
		t.Errorf("removing two interleaved headers broke the request:\n%s", out)
	}
}

func TestWsStripExtensionsLeavesAHandshakeWithoutAnOfferByteForByte(t *testing.T) {
	raw := wsHandshake("")
	out, removed, err := StripWsExtensionsHeader(raw)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if removed != nil {
		t.Errorf("removed = %q for a handshake that offered nothing", removed)
	}
	if string(out) != string(raw) {
		t.Errorf("a request with nothing to strip was rewritten anyway:\n%s", out)
	}
}

func TestWsStripExtensionsRefusesToClaimARewriteItCouldNotParse(t *testing.T) {
	// A start line with no method/target/version split. The parser refuses it,
	// and so must the rewrite.
	raw := []byte("\x00\x01garbage\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
	out, removed, err := StripWsExtensionsHeader(raw)
	if err == nil {
		t.Fatal("unparseable bytes were accepted silently; a caller would then record 'extensions stripped' for a request it never rewrote")
	}
	if removed != nil {
		t.Errorf("removed = %q for bytes that were never parsed", removed)
	}
	if string(out) != string(raw) {
		t.Error("the refused request came back altered; a refusal must leave the bytes alone")
	}
}

// ---- Handshake detection -----------------------------------------------------------------------

func TestIsWsUpgradeRequestRecognisesTheBrowserHeaders(t *testing.T) {
	req := "GET /chat HTTP/1.1\r\n" +
		"Host: t.test\r\n" +
		"Connection: keep-alive, Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if !IsWsUpgradeRequest([]byte(req)) {
		t.Error("an upgrade request must be recognised")
	}
	if IsWsUpgradeRequest([]byte("GET / HTTP/1.1\r\nHost: t.test\r\n\r\n")) {
		t.Error("an ordinary request must not be an upgrade")
	}
	// Connection: Upgrade without the Upgrade header is not an upgrade offer.
	if IsWsUpgradeRequest([]byte("GET / HTTP/1.1\r\nHost: t.test\r\nConnection: Upgrade\r\n\r\n")) {
		t.Error("Connection: Upgrade alone is not a WebSocket offer")
	}
}

func TestIsWsUpgradeResponseRequires101AndTheUpgradeHeader(t *testing.T) {
	ok := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
	if !IsWsUpgradeResponse([]byte(ok)) {
		t.Error("a 101 with Upgrade: websocket must be recognised")
	}
	// A 4xx refusal may still echo the Upgrade header; the status alone decides.
	if IsWsUpgradeResponse([]byte("HTTP/1.1 400 Bad Request\r\nUpgrade: websocket\r\nContent-Length: 0\r\n\r\n")) {
		t.Error("a refusal that echoes the header is not an upgrade acceptance")
	}
	// A 101 naming a different protocol is not a WebSocket upgrade.
	if IsWsUpgradeResponse([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n")) {
		t.Error("101 to another protocol is not a WebSocket upgrade")
	}
}

// ---- Store integration -------------------------------------------------------------------------

func TestWsStoreHandsOutPositionsAsIds(t *testing.T) {
	ts := NewTrafficStore()
	id := ts.AddWsMessage(&WsMessage{Exchange: 7, FromClient: true, Opcode: WsOpcodeText, Len: 5, AtMs: 1}, []byte("hello"))
	if id != 0 {
		t.Errorf("id = %d, want 0 (position is the id)", id)
	}
	got, err := ts.WsMessage(id)
	if err != nil {
		t.Fatalf("WsMessage: %v", err)
	}
	if got.Exchange != 7 || got.Payload != 0 {
		t.Errorf("row = %+v, want exchange 7 and payload handle 0", got)
	}
	payload, err := ts.WsPayload(got.Payload)
	if err != nil {
		t.Fatalf("WsPayload: %v", err)
	}
	if string(payload) != "hello" {
		t.Errorf("payload = %q", payload)
	}
	if _, err := ts.WsMessage(5); err == nil {
		t.Error("an out-of-range id must error, not fabricate a row")
	}
}

func TestWsStoreListsNewestFirst(t *testing.T) {
	ts := NewTrafficStore()
	for i := 0; i < 4; i++ {
		ts.AddWsMessage(&WsMessage{Exchange: 1, AtMs: uint64(i)}, []byte{byte(i)})
	}
	rows := ts.WsMessages(0, 2)
	if len(rows) != 2 || uint64(rows[0].ID) != 3 || uint64(rows[1].ID) != 2 {
		t.Fatalf("newest-first page = %d rows starting at %d, want 2 starting at 3", len(rows), rows[0].ID)
	}
	rows = ts.WsMessages(2, 2)
	if len(rows) != 2 || uint64(rows[0].ID) != 1 || uint64(rows[1].ID) != 0 {
		t.Fatalf("second page = %d rows, want 2 starting at 1", len(rows))
	}
	if rows := ts.WsMessages(10, 2); rows != nil {
		t.Fatal("an offset past the end must be empty, not fabricated")
	}
}

func TestWsConnectionsFoldsTheIndexAndJoinsToTheHandshake(t *testing.T) {
	ts := NewTrafficStore()
	req, err := ts.Put([]byte("GET /chat HTTP/1.1\r\n\r\n"), DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	ts.AddExchange(&Exchange{Request: req, Host: "t.test", Port: 8443, TLS: true, Method: "GET", Path: "/chat"})
	ex := ts.Exchanges()[0]

	for i, m := range []struct {
		fromClient bool
	}{
		{true}, {false}, {false},
	} {
		ts.AddWsMessage(&WsMessage{Exchange: ex.ID, FromClient: m.fromClient, AtMs: uint64(1000 + i)}, []byte("x"))
	}

	conns := ts.WsConnections()
	if len(conns) != 1 {
		t.Fatalf("conns = %d, want 1", len(conns))
	}
	c := conns[0]
	if c.Host != "t.test" || c.Port != 8443 || !c.TLS || c.Path != "/chat" {
		t.Errorf("connection joined to its handshake = %+v", c)
	}
	if c.Messages != 3 || c.Sent != 1 || c.Received != 2 {
		t.Errorf("counts = (messages %d, sent %d, received %d), want (3, 1, 2)", c.Messages, c.Sent, c.Received)
	}
	if c.LastMs != 1002 {
		t.Errorf("last_ms = %d, want 1002", c.LastMs)
	}
}

func TestWsCloseStatusDecodesCodeAndReason(t *testing.T) {
	if code, reason, ok := WsCloseStatus([]byte{0x03, 0xe8, 'b', 'y', 'e'}); !ok || code != 1000 || reason != "bye" {
		t.Errorf("close = (%d, %q, %v), want (1000, bye, true)", code, reason, ok)
	}
	if _, _, ok := WsCloseStatus(nil); ok {
		t.Error("a bare close carries no code")
	}
	if _, _, ok := WsCloseStatus([]byte{0x03}); ok {
		t.Error("a truncated code is not a code")
	}
}
