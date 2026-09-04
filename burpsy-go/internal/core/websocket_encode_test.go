package core

import (
	"bytes"
	"strings"
	"testing"
)

// ---- EncodeWsFrame ------------------------------------------------------------------------
//
// The interception path puts an operator-edited payload back on the wire, so this is the one
// place in the codebase that *writes* a WebSocket frame. Every test here checks the encoder
// against ParseWsFrameHeader rather than against a hand-written byte string wherever it can:
// the parser was written first, independently, and is exercised by the whole capture suite, so
// agreement between them is worth more than agreement with my own idea of the format.
//
// Burp intercepts WebSocket messages, which is why this exists at all. The Rust reference does
// not, so there was nothing to port and no encoder in this package until now.

// Round trip across the length-encoding boundaries. 125/126 and 65535/65536 are where the
// format changes shape, and an off-by-one there produces a frame whose declared length
// disagrees with its payload — which desynchronises the peer's parser for the rest of the
// connection rather than failing locally.
func TestEncodeWsFrameRoundTripsAtLengthBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 125, 126, 127, 65535, 65536, 65537} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i % 251)
		}

		frame := EncodeWsFrame(WsOpcodeBinary, payload, nil)
		hdr, need, err := ParseWsFrameHeader(frame)
		if err != nil {
			t.Fatalf("n=%d: the parser rejected our own frame: %v", n, err)
		}
		if need {
			t.Fatalf("n=%d: the parser wants more bytes than we emitted (%d)", n, len(frame))
		}
		if !hdr.FIN {
			t.Errorf("n=%d: FIN not set; a held frame is always whole", n)
		}
		if hdr.RSV != 0 {
			t.Errorf("n=%d: RSV = %d, want 0 — an encoded frame is never compressed", n, hdr.RSV)
		}
		if hdr.Opcode != WsOpcodeBinary {
			t.Errorf("n=%d: opcode = %v, want binary", n, hdr.Opcode)
		}
		if hdr.Masked {
			t.Errorf("n=%d: mask bit set for a nil mask", n)
		}
		if hdr.PayloadLen != uint64(n) {
			t.Errorf("n=%d: declared length %d — the peer would desynchronise here",
				n, hdr.PayloadLen)
		}
		// The declared length and the actual remainder must agree, which is the property
		// that actually keeps the peer in step.
		if got := len(frame) - hdr.HeaderLen; got != n {
			t.Errorf("n=%d: %d payload bytes after a %d-byte header, declared %d",
				n, got, hdr.HeaderLen, hdr.PayloadLen)
		}
		if !bytes.Equal(frame[hdr.HeaderLen:], payload) {
			t.Errorf("n=%d: payload altered by an unmasked encode", n)
		}
	}
}

// A masked frame must round trip through the parser *and* the unmasker back to the original
// bytes. This is the client-bound-for-server case, which RFC 6455 §5.1 requires to be masked.
func TestEncodeWsFrameMasksReversibly(t *testing.T) {
	payload := []byte("GET /admin HTTP/1.1 — edited by the operator")
	mask := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}

	frame := EncodeWsFrame(WsOpcodeText, payload, &mask)
	hdr, need, err := ParseWsFrameHeader(frame)
	if err != nil || need {
		t.Fatalf("parsing our masked frame: err=%v need=%v", err, need)
	}
	if !hdr.Masked {
		t.Fatal("mask bit not set, so the server is required to fail the connection")
	}
	if hdr.Mask != mask {
		t.Errorf("mask travelled as %v, want %v", hdr.Mask, mask)
	}

	body := make([]byte, len(frame)-hdr.HeaderLen)
	copy(body, frame[hdr.HeaderLen:])
	// A masked frame must not be readable on the wire; if it is, we did not mask it.
	if bytes.Equal(body, payload) {
		t.Error("payload is identical to plaintext on the wire — the mask was not applied")
	}
	WsUnmask(body, hdr.Mask, 0)
	if !bytes.Equal(body, payload) {
		t.Errorf("unmasked to %q, want %q", body, payload)
	}
}

// The caller keeps the operator's edited bytes and records them as evidence of what was sent.
// Masking in place would corrupt that copy, so the encoder must not touch its input.
func TestEncodeWsFrameDoesNotMutateTheCallersPayload(t *testing.T) {
	payload := []byte("hold me")
	original := make([]byte, len(payload))
	copy(original, payload)
	mask := [4]byte{1, 2, 3, 4}

	EncodeWsFrame(WsOpcodeText, payload, &mask)

	if !bytes.Equal(payload, original) {
		t.Errorf("the encoder masked its input in place: %q became %q — the caller's record of "+
			"what the operator sent is now the masked bytes", original, payload)
	}
}

// A zero-length masked frame still carries its 4 mask bytes. Empty payloads are ordinary on a
// WebSocket and the length-0 path is the one most likely to skip the mask by accident.
func TestEncodeWsFrameEmptyMaskedFrameStillCarriesItsMask(t *testing.T) {
	mask := [4]byte{9, 9, 9, 9}
	frame := EncodeWsFrame(WsOpcodeText, nil, &mask)

	hdr, need, err := ParseWsFrameHeader(frame)
	if err != nil || need {
		t.Fatalf("parsing an empty masked frame: err=%v need=%v", err, need)
	}
	if !hdr.Masked || hdr.Mask != mask {
		t.Errorf("masked=%v mask=%v, want true and %v", hdr.Masked, hdr.Mask, mask)
	}
	if hdr.PayloadLen != 0 {
		t.Errorf("declared length %d, want 0", hdr.PayloadLen)
	}
	if len(frame) != hdr.HeaderLen {
		t.Errorf("%d bytes total but the header is %d; there is payload where there should be none",
			len(frame), hdr.HeaderLen)
	}
}

// Header bytes checked directly for the one case worth pinning by hand, because the parser
// and the encoder could in principle agree on a shared misreading of the spec. 126 selects the
// 2-byte extended length, so a 200-byte frame is the smallest case that exercises it.
func TestEncodeWsFrameHeaderBytesMatchTheSpec(t *testing.T) {
	frame := EncodeWsFrame(WsOpcodeText, make([]byte, 200), nil)
	// 0x81 = FIN + opcode 1. 126 = "read the next two bytes as the length". 200 = 0x00C8.
	want := []byte{0x81, 126, 0x00, 0xC8}
	if !bytes.HasPrefix(frame, want) {
		t.Errorf("header = % x, want prefix % x", frame[:min(len(frame), 4)], want)
	}
}

// Control frames are encodable even though the interception path does not hold them, because
// nothing in the encoder should depend on the caller's policy. If a later change decides to
// hold a close frame, the encoder should not be the thing that breaks.
func TestEncodeWsFrameEncodesControlOpcodes(t *testing.T) {
	for _, op := range []WsOpcode{WsOpcodeClose, WsOpcodePing, WsOpcodePong} {
		frame := EncodeWsFrame(op, []byte("x"), nil)
		hdr, need, err := ParseWsFrameHeader(frame)
		if err != nil || need {
			t.Fatalf("%v: err=%v need=%v", op, err, need)
		}
		if hdr.Opcode != op {
			t.Errorf("opcode round tripped as %v, want %v", hdr.Opcode, op)
		}
		if !hdr.Opcode.IsControl() {
			t.Errorf("%v should report as a control frame", op)
		}
		if !strings.Contains(strings.ToLower(hdr.Opcode.Name()), strings.ToLower(op.Name())) {
			t.Errorf("name %q does not match %q", hdr.Opcode.Name(), op.Name())
		}
	}
}
