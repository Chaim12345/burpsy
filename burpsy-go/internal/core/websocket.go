package core

import (
	"bytes"
	"fmt"
	"strings"
)

// This file owns WebSocket framing (RFC 6455) and the per-message index row the
// traffic store keeps for it. Framing lives here, not in the proxy, for the
// same reason the HTTP parser does: decoding a frame is a pure function over
// bytes, it is the part worth testing exhaustively, and it must be reachable
// from anywhere that inspects captured traffic — not only from the socket loop
// that first read it. The proxy owns the relay; this owns the parse.

// DefaultMaxWsMessageBytes is the payload cap for a captured message. One
// mebibyte, matching the order of magnitude of the proxy's own read caps.
// Deliberately not unbounded: a WebSocket connection is open-ended by design,
// so anything unbounded per message is unbounded overall.
const DefaultMaxWsMessageBytes = 1024 * 1024

// MaxWsFrameHeaderLen is the longest header a frame can have: 2 fixed + 8
// extended length + 4 mask.
const MaxWsFrameHeaderLen = 14

// MaxWsControlPayload is the most a control frame's payload may carry
// (RFC 6455 §5.5).
const MaxWsControlPayload = 125

// WsRsv1 is the reserved bit RFC 7692's permessage-deflate uses to mark a
// compressed payload. RSV is decoded as (b0 >> 4) & 0x07, so RSV1 — the most
// significant of the three — lands on 0x04 here, not on 0x01.
const WsRsv1 byte = 0x04

// WsOpcode represents a WebSocket frame opcode (RFC 6455 §5.2). Reserved
// values keep their wire number rather than collapsing, because a probe that
// sends opcode 11 wants to see 11 in history.
type WsOpcode int

const (
	WsOpcodeContinuation WsOpcode = 0
	WsOpcodeText         WsOpcode = 1
	WsOpcodeBinary       WsOpcode = 2
	WsOpcodeClose        WsOpcode = 8
	WsOpcodePing         WsOpcode = 9
	WsOpcodePong         WsOpcode = 10
)

// Name is the opcode's display name. A reserved opcode renders with its
// number, so the operator sees which one was sent.
func (o WsOpcode) Name() string {
	switch o {
	case WsOpcodeContinuation:
		return "continuation"
	case WsOpcodeText:
		return "text"
	case WsOpcodeBinary:
		return "binary"
	case WsOpcodeClose:
		return "close"
	case WsOpcodePing:
		return "ping"
	case WsOpcodePong:
		return "pong"
	default:
		return fmt.Sprintf("reserved(0x%x)", int(o))
	}
}

// IsControl reports whether the opcode is a control opcode (0x8..=0xf).
// Control frames are never fragmented and carry at most MaxWsControlPayload
// bytes.
func (o WsOpcode) IsControl() bool {
	return int(o)&0x08 != 0
}

// WsFrameHeader is a decoded frame header, with the number of header bytes it
// occupied. The payload starts at HeaderLen.
type WsFrameHeader struct {
	FIN        bool
	RSV        byte
	Opcode     WsOpcode
	Masked     bool
	PayloadLen uint64
	Mask       [4]byte
	HeaderLen  int
}

// WsError is the one thing that stops a capture: a frame header that cannot be
// located at all, so every later "message" this side decoded would be fiction.
// Protocol anomalies — an oversized control frame, a fragmented control frame,
// a continuation with nothing to continue — are recorded on the event and
// parsing carries on; only this stops the index.
type WsError struct {
	Message string
}

func (e *WsError) Error() string { return e.Message }

func wsErrorf(format string, args ...any) *WsError {
	return &WsError{Message: fmt.Sprintf(format, args...)}
}

// ParseWsFrameHeader decodes a frame header. It returns (nil, true, nil) when
// more bytes are needed — never "malformed" — and (nil, false, err) for the
// one unrecoverable header: a 64-bit length with the reserved MSB set, after
// which the start of the next frame is unknowable.
func ParseWsFrameHeader(buf []byte) (*WsFrameHeader, bool, error) {
	if len(buf) < 2 {
		return nil, true, nil
	}
	b0, b1 := buf[0], buf[1]
	hdr := &WsFrameHeader{
		FIN:    b0&0x80 != 0,
		RSV:    (b0 >> 4) & 0x07,
		Opcode: WsOpcode(b0 & 0x0f),
		Masked: b1&0x80 != 0,
	}
	i := 2
	switch b1 & 0x7f {
	case 126:
		if len(buf) < 4 {
			return nil, true, nil
		}
		hdr.PayloadLen = uint64(uint16(buf[2])<<8 | uint16(buf[3]))
		i = 4
	case 127:
		if len(buf) < 10 {
			return nil, true, nil
		}
		var v uint64
		for _, b := range buf[2:10] {
			v = v<<8 | uint64(b)
		}
		if v&(1<<63) != 0 {
			return nil, false, wsErrorf("frame declares 64-bit length %d with the reserved high bit set, so where the next frame starts is unknowable", v)
		}
		if v > uint64(^uint(0)>>1) {
			return nil, false, wsErrorf("frame declares length %d, larger than this platform can address", v)
		}
		hdr.PayloadLen = v
		i = 10
	default:
		hdr.PayloadLen = uint64(b1 & 0x7f)
	}
	if hdr.Masked {
		if len(buf) < i+4 {
			return nil, true, nil
		}
		copy(hdr.Mask[:], buf[i:i+4])
		i += 4
	}
	hdr.HeaderLen = i
	return hdr, false, nil
}

// WsUnmask XORs payload with mask, where offset is how many payload bytes of
// this frame already went by. The mask cycles over the frame's payload as a
// whole; restarting the key at every read would produce garbage for every
// fragment after the first.
func WsUnmask(payload []byte, mask [4]byte, offset uint64) {
	for i := range payload {
		payload[i] ^= mask[(offset+uint64(i))%4]
	}
}

// EncodeWsFrame builds a single unfragmented frame carrying payload. It is the
// inverse of ParseWsFrameHeader, and it exists for exactly one caller: the
// interception path, which must put an operator-edited payload back on the wire.
// Capture never encodes anything — it only ever reads — so until frames could be
// held there was nothing in this package that needed to write one.
//
// mask nil sends the frame unmasked; non-nil masks the payload with it. That is
// not a stylistic choice. RFC 6455 §5.1 requires every client-to-server frame to
// be masked and forbids masking server-to-client frames, and a peer that
// receives the wrong one is required to fail the connection. So the caller
// passes the mask when it is relaying toward the server and nil when it is
// relaying toward the client, and getting that backwards is a dropped
// connection rather than a subtle corruption — which is the better failure of
// the two, but it is still the caller's decision to make and not this
// function's to guess.
//
// The mask is applied to a copy. Masking in place would be faster and would also
// scribble over the operator's edited bytes, which the caller still holds and
// which are recorded as evidence of what they sent.
//
// FIN is always set. The interception path only ever holds whole unfragmented
// data frames — see wsHoldable in internal/proxy/ws.go for why fragmented and
// compressed frames are relayed untouched instead — so a continuation frame is
// never re-encoded and this function does not need to express one.
func EncodeWsFrame(opcode WsOpcode, payload []byte, mask *[4]byte) []byte {
	n := len(payload)
	// 2 header bytes, up to 8 more for an extended length, 4 more for a mask.
	out := make([]byte, 0, 2+8+4+n)

	out = append(out, 0x80|byte(opcode&0x0f)) // FIN, no RSV: never compressed.

	maskBit := byte(0)
	if mask != nil {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		out = append(out, maskBit|byte(n))
	case n <= 0xFFFF:
		out = append(out, maskBit|126, byte(n>>8), byte(n))
	default:
		out = append(out, maskBit|127)
		// 8-byte big-endian. The reserved high bit is necessarily clear: n came
		// from len() on an in-memory slice, so it cannot reach 1<<63.
		for shift := 56; shift >= 0; shift -= 8 {
			out = append(out, byte(uint64(n)>>uint(shift)))
		}
	}

	if mask == nil {
		return append(out, payload...)
	}
	out = append(out, mask[:]...)
	masked := make([]byte, n)
	copy(masked, payload)
	// Offset 0: this is a whole frame, so its mask starts at the key's first byte.
	WsUnmask(masked, *mask, 0)
	return append(out, masked...)
}

// WsEvent is one reassembled application message or control frame, ready to be
// recorded. The payload is unmasked and truncated to the cap; the shortfall is
// counted rather than hidden, because a 3 MiB message shown as 1 MiB with no
// further comment is a lie.
type WsEvent struct {
	// The opcode of the message's first frame — never Continuation, which is
	// framing rather than a message type.
	Opcode    WsOpcode
	Payload   []byte
	Fragments uint32
	Dropped   uint64
	Note      string
	// Compressed reports that the message's first frame had RSV1 set, i.e. this payload is a
	// permessage-deflate stream rather than the message.
	//
	// A field rather than something a caller infers from Note. The note is prose for an operator and
	// gets reworded; a consumer deciding whether to inflate needs a fact, and string-matching a
	// human-readable sentence for it is the kind of coupling that breaks silently on a copy edit.
	Compressed bool
	// UserEdited is Burp's "Edited" fact for a WebSocket message: the operator's own hold changed the
	// payload before it was relayed. It is stamped by the relay via MarkLastMessageUserEdited after it
	// feeds an edited frame, never inferred from the bytes — a message the operator forwarded untouched
	// is byte-identical whether a Match & Replace rule rewrote it or not, so "the recorded bytes differ
	// from what arrived" would flag the tool's own rewrites as the operator's (burpsy-react-ui-sd0d).
	// The same reasoning that put the fact on intercept.Held.Wait rather than a byte comparison keeps it
	// here on the event rather than recomputed downstream.
	UserEdited bool
}

// wsDest says where a frame's payload is going. A control frame interleaves
// with a fragmented data message (RFC 6455 §5.4), so the two never share a
// buffer or its truncation accounting.
type wsDest int

const (
	wsDestData wsDest = iota
	wsDestControl
)

type wsInFlight struct {
	hdr      WsFrameHeader
	consumed uint64
	dest     wsDest
}

// WsReassembler is a frame-stream state machine: bytes in, complete messages
// out. It is fed whatever bytes arrived and asked for whatever messages are
// now complete; it never waits for a whole frame to be resident, so a peer
// that declares a 4 GiB frame costs DefaultMaxWsMessageBytes, not 4 GiB. That
// bound is the whole reason this is a state machine rather than "buffer a
// frame, then parse it" — a proxy whose resident set is chosen by the peer is
// a proxy that gets killed by the peer.
type WsReassembler struct {
	maxMessageBytes int
	// Header bytes seen but not yet sufficient to decode. At most
	// MaxWsFrameHeaderLen.
	head []byte
	// Some while a frame's payload is still being consumed.
	inFlight *wsInFlight
	// The fragmented data message under construction.
	partial       []byte
	partialOpcode WsOpcode
	partialOpen   bool
	// partialCompressed is RSV1 from the message's FIRST frame. Per RFC 7692 §6.1 only that frame
	// carries the flag; continuations of a compressed message do not repeat it, so reading it from
	// any later frame would report false.
	partialCompressed bool
	fragments         uint32
	dropped           uint64
	noteMsg           string
	ctrl              []byte
	ctrlDropped       uint64
	ctrlNote          string
	ready             []*WsEvent
}

// NewWsReassembler creates a reassembler that keeps at most maxMessageBytes of
// any message and counts the shortfall.
func NewWsReassembler(maxMessageBytes int) *WsReassembler {
	return &WsReassembler{
		maxMessageBytes: maxMessageBytes,
		head:            make([]byte, 0, MaxWsFrameHeaderLen),
		ready:           make([]*WsEvent, 0),
	}
}

// Feed ingests newly arrived bytes, queueing complete messages for Pop. An
// error means the frame stream can no longer be located; the caller stops
// capturing this connection and keeps relaying it. A single read can carry
// several frames, and messages decoded before the bad header are already in
// the ready queue — discarding them would lose evidence the parser already
// has, which is the opposite of what stopping the capture is for.
func (r *WsReassembler) Feed(data []byte) error {
	for len(data) > 0 {
		if r.inFlight != nil {
			f := r.inFlight
			want := f.hdr.PayloadLen - f.consumed
			if uint64(len(data)) < want {
				want = uint64(len(data))
			}
			r.takePayload(data[:want])
			data = data[want:]
			if r.inFlight != nil && r.inFlight.consumed == r.inFlight.hdr.PayloadLen {
				r.finishFrame()
			}
		} else {
			// Take up to a maximal header rather than guessing how many bytes
			// this one needs: the width depends on bytes that may not have
			// arrived. Anything taken beyond the header is handed back below.
			take := MaxWsFrameHeaderLen - len(r.head)
			if take > len(data) {
				take = len(data)
			}
			if take == 0 {
				// Unreachable: a 14-byte prefix always decodes, since 2 + 8 + 4
				// is the widest header RFC 6455 defines. Guarded anyway,
				// because the alternative to a break here is a spin.
				break
			}
			r.head = append(r.head, data[:take]...)
			hdr, needMore, err := ParseWsFrameHeader(r.head)
			if err != nil {
				return err
			}
			if needMore {
				data = data[take:]
				continue
			}
			// Give back everything after this header — it belongs to the
			// payload.
			over := len(r.head) - hdr.HeaderLen
			data = data[take-over:]
			r.head = r.head[:0]
			r.beginFrame(hdr)
			// A frame with no payload completes here or never: the payload
			// loop is only reached when there are bytes left to consume.
			if hdr.PayloadLen == 0 {
				r.finishFrame()
			}
		}
	}
	return nil
}

// Pop returns the next complete message, if one is ready.
func (r *WsReassembler) Pop() *WsEvent {
	if len(r.ready) == 0 {
		return nil
	}
	ev := r.ready[0]
	r.ready = r.ready[1:]
	return ev
}

// MarkLastMessageUserEdited stamps the message that most recently completed as one the operator
// edited in the hold. The relay calls it immediately after feeding the frame an edit produced: that
// frame is a single EncodeWsFrame output, so it always parses and completes in one Feed, and the
// event it flushes is the last one queued — even when a stale in-flight partial was flushed ahead of
// it by the interrupt path (a fresh data frame arriving mid-message), because that partial is queued
// first and the edited message last. Stamping after the fact rather than setting a pending flag
// before the Feed is what makes this immune to which flush fires: the interrupt flush cannot claim
// the flag for the wrong message because there is no flag to claim.
//
// A no-op when nothing is queued, which cannot happen on the edited path but guards a future caller.
// Control-frame events never reach here: the relay only marks the data message an edit re-encoded.
func (r *WsReassembler) MarkLastMessageUserEdited() {
	if n := len(r.ready); n > 0 {
		r.ready[n-1].UserEdited = true
	}
}

func (r *WsReassembler) beginFrame(hdr *WsFrameHeader) {
	dest := wsDestData
	if hdr.Opcode.IsControl() {
		if hdr.PayloadLen > MaxWsControlPayload {
			r.ctrlNote = fmt.Sprintf("control frame carries %d bytes; RFC 6455 §5.5 allows at most %d", hdr.PayloadLen, MaxWsControlPayload)
		}
		if !hdr.FIN && r.ctrlNote == "" {
			r.ctrlNote = "control frame is fragmented; RFC 6455 §5.5 forbids it"
		}
		if hdr.RSV != 0 && r.ctrlNote == "" {
			r.ctrlNote = wsRsvNote(hdr.RSV)
		}
		r.ctrl = r.ctrl[:0]
		r.ctrlDropped = 0
		dest = wsDestControl
	} else {
		switch hdr.Opcode {
		case WsOpcodeContinuation:
			if !r.partialOpen {
				r.note("continuation frame with no fragmented message in flight")
			}
		default:
			if r.partialOpen {
				r.note(fmt.Sprintf("a new %s frame arrived while a fragmented message was still in flight; the incomplete one is recorded as it stood", hdr.Opcode.Name()))
				r.flushPartial(r.fragments)
			}
			r.partialOpcode = hdr.Opcode
			r.partialOpen = true
		}
		// Checked after the flush above, which clears the note belonging to the
		// message that just ended — otherwise a compressed message would inherit
		// its predecessor's anomaly and lose its own.
		if hdr.RSV != 0 {
			r.note(wsRsvNote(hdr.RSV))
		}
		// Only the first frame of a message carries RSV1 (RFC 7692 §6.1), which is why this is
		// guarded on fragments == 0 rather than set from whichever frame happens to be in hand.
		if r.fragments == 0 && hdr.RSV&WsRsv1 != 0 {
			r.partialCompressed = true
		}
		r.fragments++
	}
	r.inFlight = &wsInFlight{hdr: *hdr, dest: dest}
}

func (r *WsReassembler) takePayload(chunk []byte) {
	f := r.inFlight
	if f == nil {
		return
	}
	offset := f.consumed
	f.consumed += uint64(len(chunk))
	var mask *[4]byte
	if f.hdr.Masked {
		m := f.hdr.Mask
		mask = &m
	}
	limit := r.maxMessageBytes
	buf := &r.partial
	if f.dest == wsDestControl {
		buf = &r.ctrl
	}
	room := limit - len(*buf)
	if room < 0 {
		room = 0
	}
	keep := room
	if keep > len(chunk) {
		keep = len(chunk)
	}
	if keep > 0 {
		at := len(*buf)
		*buf = append(*buf, chunk[:keep]...)
		if mask != nil {
			WsUnmask((*buf)[at:], *mask, offset)
		}
	}
	over := len(chunk) - keep
	if over > 0 {
		if f.dest == wsDestControl {
			r.ctrlDropped += uint64(over)
		} else {
			r.dropped += uint64(over)
		}
	}
}

func (r *WsReassembler) finishFrame() {
	f := r.inFlight
	if f == nil {
		return
	}
	r.inFlight = nil
	switch f.dest {
	case wsDestControl:
		// Control frames never join a fragmented data message, even when they
		// interleave with one — RFC 6455 §5.4 permits it.
		r.ready = append(r.ready, &WsEvent{
			Opcode:    f.hdr.Opcode,
			Payload:   r.ctrl,
			Fragments: 1,
			Dropped:   r.ctrlDropped,
			Note:      r.ctrlNote,
		})
		r.ctrl = nil
		r.ctrlDropped = 0
		r.ctrlNote = ""
	case wsDestData:
		if f.hdr.FIN {
			r.flushPartial(r.fragments)
		}
	}
}

// flushPartial emits the fragmented message as it currently stands and resets
// for the next one.
func (r *WsReassembler) flushPartial(fragments uint32) {
	opcode := r.partialOpcode
	if !r.partialOpen {
		opcode = WsOpcodeContinuation
	}
	r.ready = append(r.ready, &WsEvent{
		Opcode:     opcode,
		Payload:    r.partial,
		Fragments:  fragments,
		Dropped:    r.dropped,
		Note:       r.noteMsg,
		Compressed: r.partialCompressed,
	})
	r.partial = nil
	r.partialCompressed = false
	r.partialOpcode = WsOpcodeContinuation
	r.partialOpen = false
	r.fragments = 0
	r.dropped = 0
	r.noteMsg = ""
}

// wsRsvNote describes a frame that arrived with reserved bits set.
//
// RSV1 is the one that matters in practice: RFC 7692's permessage-deflate sets
// it to mark a compressed payload, so the bytes recorded for such a message are
// a DEFLATE stream and not the message at all. Burp, once an operator turns its
// extension stripping off, records that block with nothing to distinguish it
// from a message that genuinely looked like that — a compressed blob presented
// as the plaintext, which is exactly the silent partial result this project
// refuses. Naming it costs one string per message and turns an unreadable row
// into an explained one.
//
// The frame is still recorded rather than dropped. An undecoded payload that
// says it is undecoded is evidence; discarding it would replace one wrong
// answer with a missing one.
func wsRsvNote(rsv byte) string {
	if rsv&WsRsv1 != 0 {
		return "RSV1 is set: this payload is compressed (RFC 7692 permessage-deflate) and is recorded exactly as it arrived, undecoded — the bytes below are the DEFLATE stream, not the message. Leave Sec-WebSocket-Extensions stripping enabled to capture this connection's messages in the clear."
	}
	return fmt.Sprintf("reserved frame bits RSV=0x%x are set; no extension this proxy negotiated defines them, so the payload is recorded exactly as it arrived", rsv)
}

// note records the first anomaly seen for the message in flight. First rather
// than last, and never concatenated: the initial deviation is the one that
// explains everything after it.
func (r *WsReassembler) note(msg string) {
	if r.noteMsg == "" {
		r.noteMsg = msg
	}
}

// ---- Handshake detection ------------------------------------------------------------------

// IsWsUpgradeRequest reports whether raw bytes are an HTTP request offering a
// WebSocket upgrade (RFC 6455 §4.1). Both headers are token lists — browsers
// send "Connection: keep-alive, Upgrade", so a substring test on the whole
// value would miss the common case. This deliberately does not check
// Sec-WebSocket-Key or Sec-WebSocket-Version: whether the handshake is valid
// is the origin's decision, announced by its response, and a proxy that
// second-guessed it would refuse to record exactly the malformed handshakes a
// tester is probing with.
func IsWsUpgradeRequest(raw []byte) bool {
	shape, err := Parse(raw, DirectionRequest)
	if err != nil {
		return false
	}
	return headerHasToken(raw, &shape, "connection", "upgrade") &&
		headerHasToken(raw, &shape, "upgrade", "websocket")
}

// IsWsUpgradeResponse reports whether raw bytes are an HTTP response accepting
// a WebSocket upgrade: status 101 plus Upgrade: websocket. The status alone is
// not enough — 101 is the generic protocol-switch code and could name any
// protocol in Upgrade — and the header alone is not enough either, because a
// 4xx refusal may still echo it. The conjunction is what means "everything
// after this is frames".
func IsWsUpgradeResponse(raw []byte) bool {
	shape, err := Parse(raw, DirectionResponse)
	if err != nil {
		return false
	}
	if second := sliceSpan(raw, shape.SecondToken); !bytes.Equal(second, []byte("101")) {
		return false
	}
	return headerHasToken(raw, &shape, "upgrade", "websocket")
}

// WsExtensionsHeader is the request header carrying the client's extension
// offer (RFC 6455 §4.1, §9.1). Lower-case because every comparison against it
// is case-insensitive.
const WsExtensionsHeader = "sec-websocket-extensions"

// StripWsExtensionsHeader removes every Sec-WebSocket-Extensions header from a
// client handshake, returning the rewritten request and the offers it removed.
//
// Why a capturing proxy should do this: that header is how a client offers
// permessage-deflate (RFC 7692). If the origin accepts, every later frame
// arrives DEFLATE-compressed with RSV1 set, and a capture that stored those
// bytes would be presenting an opaque compressed block as though it were the
// message. Burp strips by default for the same reason — config key
// proxy.miscellaneous.strip_sec_websocket_extensions_headers_in_incoming_requests.
// What Burp does not do is say so afterwards; the removed values are returned
// here precisely so the caller can record the rewrite rather than let a
// modified handshake look pristine in history.
//
// A request that will not parse is left alone and the refusal is returned as an
// error, never as a silent no-op: a caller must not be able to record "stripped"
// for bytes it did not rewrite. In practice this is unreachable from the proxy,
// which only calls this after IsWsUpgradeRequest already parsed the same bytes.
func StripWsExtensionsHeader(raw []byte) ([]byte, []string, error) {
	shape, err := Parse(raw, DirectionRequest)
	if err != nil {
		return raw, nil, fmt.Errorf("handshake did not parse, so its extension offer was left in place: %w", err)
	}

	type cut struct{ start, end int }
	var cuts []cut
	var removed []string
	for _, h := range shape.Headers {
		if !strings.EqualFold(strings.TrimSpace(string(sliceSpan(raw, h.Name))), WsExtensionsHeader) {
			continue
		}
		start := h.Name.Offset
		if start > len(raw) {
			continue
		}
		end := h.Value.End()
		if end < start {
			end = start
		}
		if end > len(raw) {
			end = len(raw)
		}
		// The line terminator goes with the line. Cutting the field but leaving
		// its CRLF behind would end the header block early and turn the rest of
		// the handshake into a body — a rewrite that broke the request it was
		// meant to clean up.
		for end < len(raw) && raw[end] != '\n' {
			end++
		}
		if end < len(raw) {
			end++
		}
		cuts = append(cuts, cut{start: start, end: end})
		removed = append(removed, strings.TrimSpace(string(sliceSpan(raw, h.Value))))
	}
	if len(cuts) == 0 {
		// Returned as the same slice, not a copy: a handshake that offered
		// nothing is forwarded byte for byte.
		return raw, nil, nil
	}

	// Headers arrive in wire order, so the cuts are ascending and disjoint and
	// the gaps between them can simply be concatenated.
	out := make([]byte, 0, len(raw))
	prev := 0
	for _, c := range cuts {
		if c.start > prev {
			out = append(out, raw[prev:c.start]...)
		}
		prev = c.end
	}
	out = append(out, raw[prev:]...)
	return out, removed, nil
}

// sliceSpan returns a span as bytes, bounds-checked against raw.
func sliceSpan(raw []byte, s Span) []byte {
	if s.Offset >= len(raw) {
		return nil
	}
	end := s.Offset + s.Len
	if end > len(raw) {
		end = len(raw)
	}
	return raw[s.Offset:end]
}

// headerHasToken reports whether the header name carries token in its
// comma-separated value list. Header names and the websocket token are both
// case-insensitive.
func headerHasToken(raw []byte, shape *MessageShape, name, token string) bool {
	for _, h := range shape.Headers {
		n := sliceSpan(raw, h.Name)
		if !strings.EqualFold(strings.TrimSpace(string(n)), name) {
			continue
		}
		v := sliceSpan(raw, h.Value)
		for _, t := range bytes.Split(v, []byte(",")) {
			if strings.EqualFold(strings.TrimSpace(string(t)), token) {
				return true
			}
		}
	}
	return false
}

// WsMessage is one captured WebSocket message: an index row that names its
// handshake exchange and its payload by handle, never a payload. Position is
// the id, exactly as for messages and exchanges, which is what makes lookups
// O(1) rather than a scan.
type WsMessage struct {
	ID MsgId
	// The exchange whose 101 response opened this connection. Every message
	// names its handshake, so history can join a row to a host and path.
	Exchange ExchangeID
	// The payload's handle in the ws-payload index, which stores the bytes
	// once and hands out handles — a socket that has carried a hundred
	// thousand messages therefore costs a hundred thousand fixed-size rows.
	Payload MsgId
	// FromClient is true for client→server, false for server→client. Spelled
	// as a bool here; the wire name comes from the serialisation layer.
	FromClient bool
	Opcode     WsOpcode
	// Payload bytes kept. Differs from the declared length exactly when
	// Dropped is non-zero.
	Len int
	// Declared payload bytes not kept. Non-zero means this row is a truncated
	// view, and the UI must say so rather than presenting Len as the message
	// size.
	Dropped   uint64
	Fragments uint32
	AtMs      uint64
	Note      string
	// UserEdited is Burp's "Edited" fact for this message: the operator's own hold changed the payload
	// before the relay sent it. Carried from the WsEvent the relay stamped (see WsEvent.UserEdited).
	//
	// It lives on the message row, not folded into the handshake exchange's flag, because a socket that
	// carries ten thousand frames and one edit would then flag the handshake with nothing to say which
	// frame — and the handshake's own flag already answers a different question, whether the upgrade
	// *request* was edited in its hold. These are two facts; one bit for both would lose which happened.
	UserEdited bool
}

// WsCloseStatus decodes a close frame's payload: two big-endian status bytes
// followed by an optional UTF-8 reason. Rendered as a number rather than as
// its two bytes as characters, which would show mojibake instead of 1000.
// Returns (0, "", false) for a close frame that carried no payload — RFC 6455
// permits one.
func WsCloseStatus(payload []byte) (code uint16, reason string, ok bool) {
	if len(payload) < 2 {
		return 0, "", false
	}
	code = uint16(payload[0])<<8 | uint16(payload[1])
	return code, string(payload[2:]), true
}
