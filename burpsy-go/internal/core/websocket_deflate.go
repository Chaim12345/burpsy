package core

// permessage-deflate (RFC 7692), enough of it to read compressed traffic.
//
// # What this does and, more importantly, what it does not
//
// burpsy strips the client's `Sec-WebSocket-Extensions` offer from every handshake by default
// (see stripWsHandshake), so the origin cannot negotiate compression and frames arrive in the
// clear. An operator who disables that stripping — because the origin requires the extension —
// used to get frames recorded as opaque DEFLATE blocks with a note saying so.
//
// This inflates them **for the operator's view only**. The bytes relayed between the peers are
// untouched, which is the property that makes this safe to do at all: a bug here shows the operator
// wrong plaintext, it cannot corrupt the connection.
//
// Editing a compressed message is a different problem and is still refused. RFC 7692 §7.1.1 lets
// the two ends carry the LZ77 window across messages unless `no_context_takeover` is negotiated, so
// a proxy that re-compressed only the messages an operator edited would produce a deflate stream
// whose history does not match what the peer actually received — corrupting every later message on
// that connection, not just the edited one. Doing that correctly means decompressing and
// recompressing *every* message in the direction, which changes the bytes on the wire even when the
// operator changed nothing, and turns any bug into a whole-connection failure. Not worth it while
// stripping the extension gives the same editability with none of the risk.
//
// So: inflation is offered where it is provably safe, and the harder half is declined out loud
// rather than half-implemented.

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"strings"
)

// wsDeflateTail is the four bytes RFC 7692 §7.2.1 says a receiver appends before inflating: the
// sender removed them, because every message ends with an empty uncompressed block.
var wsDeflateTail = []byte{0x00, 0x00, 0xff, 0xff}

// WsDeflateParams is what a handshake negotiated.
type WsDeflateParams struct {
	// Negotiated is false when the response offered no permessage-deflate, in which case nothing
	// else here means anything.
	Negotiated bool
	// ClientNoContextTakeover means the client compresses each message independently, so a
	// client→server message can be inflated on its own.
	ClientNoContextTakeover bool
	// ServerNoContextTakeover is the same for server→client.
	ServerNoContextTakeover bool
}

// InflatableFor reports whether a message in this direction can be inflated on its own.
//
// Without no_context_takeover the sender's compression window carries across messages, so message N
// cannot be inflated without having inflated 1..N-1 through the same stream. burpsy does not keep
// that state, and guessing would produce plausible-looking wrong plaintext — the worst outcome on a
// tool whose output is read as evidence. So the honest answer is "not inflatable", and the recorded
// note says which parameter would make it so.
func (p WsDeflateParams) InflatableFor(fromClient bool) bool {
	if !p.Negotiated {
		return false
	}
	if fromClient {
		return p.ClientNoContextTakeover
	}
	return p.ServerNoContextTakeover
}

// ParseWsDeflateParams reads the negotiated extension out of a 101 response head.
//
// The response is authoritative: the client offers, the server chooses. A parameter the server did
// not echo was not agreed, whatever the client asked for.
func ParseWsDeflateParams(responseHead []byte) WsDeflateParams {
	var p WsDeflateParams
	for _, line := range strings.Split(string(responseHead), "\n") {
		line = strings.TrimRight(line, "\r")
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(line[:colon]), "Sec-WebSocket-Extensions") {
			continue
		}
		value := strings.ToLower(line[colon+1:])
		// A header may list several extensions separated by commas; only the deflate one matters,
		// and its parameters are semicolon-separated within it.
		for _, ext := range strings.Split(value, ",") {
			ext = strings.TrimSpace(ext)
			if !strings.HasPrefix(ext, "permessage-deflate") {
				continue
			}
			p.Negotiated = true
			for _, param := range strings.Split(ext, ";")[1:] {
				switch strings.TrimSpace(param) {
				case "client_no_context_takeover":
					p.ClientNoContextTakeover = true
				case "server_no_context_takeover":
					p.ServerNoContextTakeover = true
				}
			}
		}
	}
	return p
}

// ErrWsDeflateTooLarge is returned when an inflated message exceeds the cap.
//
// Its own error because the caller has to treat it differently from a corrupt stream: the data is
// fine and there is simply too much of it, so what was inflated so far is still true and worth
// keeping, where a corrupt stream's output is not.
var ErrWsDeflateTooLarge = errors.New("inflated websocket message exceeds the cap")

// InflateWsMessage inflates one self-contained compressed message.
//
// Correct only when the sender used no_context_takeover for this direction — see
// WsDeflateParams.InflatableFor, which the caller must consult first. Given a message that depends
// on an earlier window this returns an error rather than the garbage a fresh window would produce.
//
// max bounds the output. A compressed message is a decompression bomb risk by construction: a few
// kilobytes can expand to gigabytes, and this runs on the proxy's own goroutine.
func InflateWsMessage(payload []byte, max int) ([]byte, error) {
	if len(payload) == 0 {
		// An empty compressed payload is a legal empty message; flate would report an unexpected
		// EOF for it, which would read as corruption.
		return nil, nil
	}
	// The sender dropped the trailing empty block; put it back.
	src := io.MultiReader(bytes.NewReader(payload), bytes.NewReader(wsDeflateTail))
	fr := flate.NewReader(src)
	defer fr.Close()

	// One byte over the cap, so hitting it is distinguishable from landing exactly on it.
	out, err := io.ReadAll(io.LimitReader(fr, int64(max)+1))
	if len(out) > max {
		return out[:max], ErrWsDeflateTooLarge
	}
	// io.ErrUnexpectedEOF is the NORMAL ending here, not a fault.
	//
	// A permessage-deflate message is a sync-flushed stream: it carries no final block, because the
	// sender may continue the same compression context into the next message. So the reader reaches
	// the end of the data without ever seeing an end-of-stream marker, which is exactly what
	// unexpected-EOF means. Rejecting it — as the first draft of this function did — rejected every
	// valid compressed message; the round-trip test caught that immediately.
	//
	// Genuine corruption reports flate.CorruptInputError or flate.InternalError instead, and those
	// still fail, so the distinction the caller needs survives. The residual case is a stream
	// truncated mid-message, which is indistinguishable from a normal ending and yields a short
	// message: acceptable, because the alternative is refusing all of them, and the caller records
	// the byte count so a truncated view is at least measurable.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("inflate websocket message: %w", err)
	}
	return out, nil
}
