package http2

import (
	"bytes"
	"testing"
)

// ibhs: native fuzz for the h2 frame and HPACK decoders burpsy owns. Crashers, if
// any, land in testdata via the go fuzzer; this file carries the seed corpus. Short
// local smoke runs; W5 schedules the nightly-length runs.

// FuzzDecodeFrameHeader: a decoded header re-encodes to the same nine octets, and
// decoding those octets reproduces the header — the decoder may never invent bits.
func FuzzDecodeFrameHeader(f *testing.F) {
	f.Add([]byte{0, 0, 4, 0x4, 0x0, 0, 0, 0, 1}) // HEADERS
	f.Add([]byte{0, 0, 0, 0x0, 0x0, 0, 0, 0, 0}) // empty DATA
	f.Add([]byte{0xff, 0xff, 0xff, 0x7, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, ok := DecodeFrameHeader(b)
		if !ok {
			return
		}
		enc := h.Encode()
		if !bytes.Equal(enc[:], b[:FrameHeaderLen]) {
			t.Fatalf("header re-encode differs: %q -> %+v -> %q", b[:FrameHeaderLen], h, enc)
		}
		h2, ok2 := DecodeFrameHeader(enc[:])
		if !ok2 || h2 != h {
			t.Fatalf("round-trip through Encode changed the header: %+v -> %+v", h, h2)
		}
	})
}

// FuzzReadFrames: frame reading never consumes past the input, never invents
// payload, and the complete frames plus the tail account for every octet.
func FuzzReadFrames(f *testing.F) {
	f.Add([]byte{0, 0, 4, 0x4, 0x0, 0, 0, 0, 1, 1, 2, 3, 4})
	f.Add([]byte{0, 0, 4, 0x4, 0x0, 0, 0, 0, 1, 1, 2}) // truncated payload
	f.Add([]byte{0, 0, 1, 0x7, 0x0, 0, 0, 0, 3, 0})    // GOAWAY
	f.Add([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))  // preface as frames
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		frames, tail := ReadFrames(b)
		consumed := 0
		for _, fr := range frames {
			if len(fr.Payload) != int(fr.Header.Len) {
				t.Fatalf("frame payload %d octets, header declared %d", len(fr.Payload), fr.Header.Len)
			}
			if fr.Offset != consumed {
				t.Fatalf("frame offset %d, expected %d", fr.Offset, consumed)
			}
			consumed += FrameHeaderLen + len(fr.Payload)
		}
		if consumed > len(b) {
			t.Fatalf("consumed %d of %d octets", consumed, len(b))
		}
		if tail.Kind == TailComplete && consumed != len(b) {
			t.Fatalf("complete tail with %d unconsumed octets", len(b)-consumed)
		}
		if tail.Kind == TailIncomplete && consumed == len(b) {
			t.Fatal("incomplete tail with nothing left")
		}
	})
}

// FuzzHpackDecode: arbitrary blocks against a fresh decoder, the same block twice
// on one decoder (the dynamic table changes the second read), and an
// encode-then-decode round-trip on fuzzer-shaped header fields.
func FuzzHpackDecode(f *testing.F) {
	f.Add([]byte{0x82, 0x86, 0x84}, ":path", "/")               // static-table indexed
	f.Add([]byte{0x40, 0x01, 0x61, 0x01, 0x62}, "a", "b")       // literal, incremental
	f.Add([]byte{0x3f, 0xff, 0xff, 0xff, 0xff, 0x7f}, "x", "y") // huge size update
	f.Add([]byte{0x80}, "", "")                                 // index 0 (invalid)
	f.Add([]byte{0xbe}, "n", "v")
	f.Fuzz(func(t *testing.T, block []byte, name, value string) {
		fresh := NewDecoder(4096)
		fields, err := fresh.Decode(block)
		if err != nil && fields != nil {
			t.Fatalf("errored decode returned fields: %v", fields)
		}
		// Same block again on one decoder: the dynamic table now answers
		// differently. It must never panic, whatever the first read left behind.
		twice := NewDecoder(4096)
		_, _ = twice.Decode(block)
		_, _ = twice.Decode(block)

		// Round-trip: what the encoder framed, the decoder reads back whole.
		if name != "" {
			want := []HeaderField{NewHeaderField(name, value)}
			enc := NewEncoder(4096).Encode(want)
			got, err := NewDecoder(4096).Decode(enc)
			if err != nil {
				t.Fatalf("encoder output refused: %v", err)
			}
			if !HeaderFieldsEqual(got, want) {
				t.Fatalf("round-trip changed the fields: %v -> %v", want, got)
			}
		}
	})
}
