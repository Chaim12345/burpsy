package core

import (
	"bytes"
	"compress/flate"
	"errors"
	"strings"
	"testing"
)

// ---- permessage-deflate (issue 3ay) --------------------------------------------------------
//
// Inflation exists so an operator who disabled extension stripping can read their traffic instead of
// seeing opaque DEFLATE blocks. It is deliberately read-only: the relayed bytes are untouched, which
// is what makes it safe — a bug here shows wrong plaintext, it cannot corrupt the connection.
//
// The tests that matter most are the refusals. Inflating a message that depends on an earlier
// compression window would produce plausible-looking wrong plaintext, which on a tool whose output
// is read as evidence is worse than showing nothing.

// deflateMessage compresses a payload the way a permessage-deflate sender does: raw deflate with a
// sync flush, then the trailing empty block removed.
func deflateMessage(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := fw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	out := buf.Bytes()
	// The sender strips the 4-byte tail; InflateWsMessage puts it back.
	return bytes.TrimSuffix(out, wsDeflateTail)
}

func TestInflateRoundTripsARealCompressedMessage(t *testing.T) {
	for _, payload := range []string{
		`{"type":"chat","text":"hello"}`,
		strings.Repeat("highly compressible ", 500),
		"a",
	} {
		compressed := deflateMessage(t, []byte(payload))
		got, err := InflateWsMessage(compressed, DefaultMaxWsMessageBytes)
		if err != nil {
			t.Fatalf("len %d: %v", len(payload), err)
		}
		if string(got) != payload {
			t.Errorf("inflated %d bytes, want the original %d", len(got), len(payload))
		}
	}
}

// An empty compressed payload is a legal empty message. flate reports an unexpected EOF for it,
// which would read to the caller as corruption and get the message recorded as unreadable.
func TestInflateAnEmptyPayloadIsAnEmptyMessageNotAnError(t *testing.T) {
	got, err := InflateWsMessage(nil, DefaultMaxWsMessageBytes)
	if err != nil {
		t.Errorf("empty payload: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes for an empty payload", len(got))
	}
}

// A decompression bomb must be bounded. A compressed message is one by construction — a few
// kilobytes can expand to gigabytes — and this runs on the proxy's own goroutine.
func TestInflateIsBoundedAgainstADecompressionBomb(t *testing.T) {
	// 4 MiB of zeroes compresses to a few kilobytes.
	bomb := deflateMessage(t, bytes.Repeat([]byte{0}, 4<<20))

	const cap = 64 << 10
	got, err := InflateWsMessage(bomb, cap)
	if !errors.Is(err, ErrWsDeflateTooLarge) {
		t.Fatalf("error = %v, want ErrWsDeflateTooLarge", err)
	}
	if len(got) != cap {
		t.Errorf("returned %d bytes, want exactly the cap %d — what was inflated up to the cap is "+
			"true and worth keeping", len(got), cap)
	}
}

// Corrupt input must error rather than return whatever came out first. DEFLATE output is only
// meaningful as far as the stream was valid, and the caller cannot tell where that was.
func TestInflateRefusesACorruptStream(t *testing.T) {
	if _, err := InflateWsMessage([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb}, DefaultMaxWsMessageBytes); err == nil {
		t.Error("a corrupt payload inflated without error")
	}
}

// ---- negotiation ---------------------------------------------------------------------------

func TestParseDeflateParamsReadsWhatTheServerAgreed(t *testing.T) {
	cases := []struct {
		name string
		head string
		want WsDeflateParams
	}{
		{
			"not negotiated",
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
			WsDeflateParams{},
		},
		{
			"negotiated, context takeover in force",
			"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
			WsDeflateParams{Negotiated: true},
		},
		{
			"both directions independent",
			"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: permessage-deflate; " +
				"client_no_context_takeover; server_no_context_takeover\r\n\r\n",
			WsDeflateParams{Negotiated: true, ClientNoContextTakeover: true, ServerNoContextTakeover: true},
		},
		{
			"server only",
			"HTTP/1.1 101\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n\r\n",
			WsDeflateParams{Negotiated: true, ServerNoContextTakeover: true},
		},
		{
			"case and spacing as a real server might send it",
			"HTTP/1.1 101\r\nSEC-WEBSOCKET-EXTENSIONS:   PerMessage-Deflate ;  Client_No_Context_Takeover \r\n\r\n",
			WsDeflateParams{Negotiated: true, ClientNoContextTakeover: true},
		},
		{
			"another extension alongside it",
			"HTTP/1.1 101\r\nSec-WebSocket-Extensions: x-something, permessage-deflate; client_no_context_takeover\r\n\r\n",
			WsDeflateParams{Negotiated: true, ClientNoContextTakeover: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseWsDeflateParams([]byte(tc.head))
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The refusal that keeps wrong plaintext off the screen. Without no_context_takeover a message
// depends on the window left by earlier ones, and burpsy does not keep that state.
func TestInflatableForRefusesWhenContextCarriesAcrossMessages(t *testing.T) {
	takeover := WsDeflateParams{Negotiated: true}
	if takeover.InflatableFor(true) || takeover.InflatableFor(false) {
		t.Error("a message is claimed inflatable while the compression window carries across " +
			"messages; inflating it with a fresh window yields plausible-looking wrong plaintext")
	}

	// Per-direction, because a server may agree to it for one side only.
	clientOnly := WsDeflateParams{Negotiated: true, ClientNoContextTakeover: true}
	if !clientOnly.InflatableFor(true) {
		t.Error("client→server should be inflatable with client_no_context_takeover")
	}
	if clientOnly.InflatableFor(false) {
		t.Error("server→client claimed inflatable on the strength of the CLIENT's parameter")
	}

	// And nothing is inflatable when the extension was never negotiated — those frames are not
	// compressed at all, so an inflate attempt would fail on ordinary plaintext.
	var none WsDeflateParams
	if none.InflatableFor(true) || none.InflatableFor(false) {
		t.Error("claimed inflatable with no extension negotiated")
	}
}
