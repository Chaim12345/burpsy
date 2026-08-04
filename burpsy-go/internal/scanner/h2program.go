package scanner

import (
	"bytes"
	"fmt"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// Capturing an HTTP/2 frame program through the one capture path (H2-03, CRAWL-02).
//
// # Why this is here rather than in internal/sender
//
// CRAWL-02's rule is that every surface's traffic reaches history through Capture.Record and not through
// a lookalike, because the first thing a second copy drifts on is the reporting. internal/sender cannot
// call Record — internal/scanner imports sender, so the arrow only goes one way — so the conversion from
// a frame-program result to a captured exchange lives on this side of that arrow. It is deliberately thin:
// it renders, it labels, and it hands the result to the same Record every other producer uses.
//
// # Why the stored bytes are wrapped rather than stored raw
//
// core.Parse needs a start line and a blank line to index a message, and a frame program is neither — it
// is a preface and a pile of frames. The store therefore holds an envelope whose body is the program's
// exact octets: the bytes that went on the wire are preserved byte for byte, and everything around them is
// burpsy's own labelling, named as such by the X-Burpsy- prefix and by the exchange's Notes.
//
// The method token is FrameProgramMethod, which is not an HTTP method and cannot be mistaken for one. The
// alternative was to record the program as though it were the GET its first header block contains, and
// that would be a lie in the most damaging place: an operator scanning history for what was sent to a
// host would see an ordinary request and never learn that what actually went out was fourteen frames with
// a lying length.
//
// # Why the reply is not rendered as an HTTP response
//
// It would need HPACK-decoding the peer's HEADERS frame, and real peers Huffman-code their header strings
// — which internal/http2's decoder deliberately does not implement (hpack.go's named seam). A partial
// decode would let a status line be invented from the fields that happened to decode, which is exactly
// the kind of confident-and-wrong output this codebase refuses. So the reply is stored as octets under a
// status line that says frame-program rather than a number, and Exchange.Status stays absent because
// there genuinely is no status.

// FrameProgramMethod is the method token a captured frame program carries.
//
// Not an HTTP method, on purpose: this row's request bytes are frames, and a reader must not be able to
// mistake it for a request the way an invented "GET" would invite.
const FrameProgramMethod = "H2-FRAME-PROGRAM"

// FrameProgramNoPath is the target token for a program that addresses no request at all — a SETTINGS
// flood, a bare preface. Not a path any URL can produce, so it cannot be read as one.
const FrameProgramNoPath = "*"

// RecordFrameProgram stores one frame program's send through the same pipeline proxied and crawled traffic
// take, and returns the indexed exchange.
//
// # A program that drew no reply is still recorded; one that was never sent is not
//
// Those two look alike and are not. A program the peer answered with silence is a result — a peer that
// takes fourteen malformed frames and says nothing has told you something — so it is indexed, with a reply
// envelope whose body is empty and whose X-Burpsy-Read-Ended says why the read stopped. Nothing is
// fabricated: the envelope states a zero-length reply rather than implying one arrived.
//
// A program that was refused by scope, or whose dial failed, has no request bytes at all. That one is not
// indexed and comes back as Record's ErrNoResponse, because a row with no response wedges the live-audit
// sweep for the life of the process (see Record's own note). It belongs in the caller's refusal ledger,
// which is where AuthorisedSender.Refused already counts it.
func (c Capture) RecordFrameProgram(res sender.FrameProgramResult) (*core.Exchange, error) {
	path := FrameProgramNoPath
	if len(res.Authorisation.Requests) > 0 {
		path = res.Authorisation.Requests[0].Path
	}
	notes := frameProgramNotes(res)
	return c.Record(CapturedExchange{
		Host:     res.Host,
		Port:     res.Port,
		TLS:      res.TLS,
		Method:   FrameProgramMethod,
		Path:     path,
		Request:  renderFrameProgramRequest(res, path),
		Response: renderFrameProgramReply(res),
		Started:  res.Started,
		Duration: res.Duration,
		Protocol: core.ProtocolHTTP2,
		// SourceRepeater rather than a source of its own. A frame program is an operator-driven send at one
		// named target, which is what the repeater source means, and every per-source report in the tool
		// enumerates the sources it knows explicitly — a new constant would appear in some of those reports
		// and be missing from others until each was updated, which is the drift core.Source's own doc warns
		// about. What distinguishes this row from a hand resend is carried by Notes and by
		// FrameProgramMethod, both of which are visible in the row itself.
		Source: core.SourceRepeater,
		Notes:  &notes,
	})
}

// frameProgramNotes says what this row's bytes are, since the bytes cannot say it themselves — which is
// exactly what CapturedExchange.Notes is for.
func frameProgramNotes(res sender.FrameProgramResult) string {
	return fmt.Sprintf("HTTP/2 frame program: %d frames sent, %d deliberate violations, %s; "+
		"the stored request body is the program's octets, not an HTTP/1 request. Reply: %d frames, %s",
		len(res.Program.Frames), len(res.Violations), res.Authorisation.Verdict,
		len(res.ReplyFrames), readNote(res))
}

// readNote names how the read window ended, or that nothing was read.
func readNote(res sender.FrameProgramResult) string {
	if res.ReadEnded == "" {
		return "nothing was read"
	}
	return res.ReadEnded
}

// renderFrameProgramRequest wraps the program's octets in the smallest envelope core.Parse can index,
// labelling every field it adds.
func renderFrameProgramRequest(res sender.FrameProgramResult, path string) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s %s HTTP/2\r\n", FrameProgramMethod, path)
	fmt.Fprintf(&out, "Host: %s\r\n", res.Host)
	fmt.Fprintf(&out, "X-Burpsy-Capture: frame-program\r\n")
	fmt.Fprintf(&out, "X-Burpsy-Frames: %d\r\n", len(res.Program.Frames))
	fmt.Fprintf(&out, "X-Burpsy-Requests-Authorised: %d\r\n", len(res.Authorisation.Requests))
	fmt.Fprintf(&out, "X-Burpsy-Violations: %d\r\n", len(res.Violations))
	if res.Negotiated != "" {
		fmt.Fprintf(&out, "X-Burpsy-Alpn: %s\r\n", res.Negotiated)
	} else {
		// Named rather than omitted: a cleartext prior-knowledge send negotiated nothing, and an absent
		// header would read as "not recorded" rather than "there was no negotiation".
		fmt.Fprintf(&out, "X-Burpsy-Alpn: none (cleartext prior knowledge)\r\n")
	}
	fmt.Fprintf(&out, "Content-Length: %d\r\n\r\n", len(res.Sent))
	out.Write(res.Sent)
	return out.Bytes()
}

// renderFrameProgramReply wraps the reply octets the same way.
//
// The status line carries "frame-program" where a code would go, so nothing downstream reads a status this
// exchange does not have — Capture.Record's storedStatus finds no number and leaves Exchange.Status
// absent, which is the truth.
func renderFrameProgramReply(res sender.FrameProgramResult) []byte {
	if len(res.Sent) == 0 {
		// Nothing was written, so there is no exchange: Record turns this into ErrNoResponse rather than an
		// indexed row. A program that *was* written and drew nothing gets the envelope below with an empty
		// body, which is a different fact and is recorded as one.
		return nil
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "HTTP/2 frame-program\r\n")
	fmt.Fprintf(&out, "X-Burpsy-Capture: frame-program-reply\r\n")
	fmt.Fprintf(&out, "X-Burpsy-Frames: %d\r\n", len(res.ReplyFrames))
	if res.ReplyTail.Kind == http2.TailIncomplete {
		fmt.Fprintf(&out, "X-Burpsy-Partial-Frame: %d octet(s) at offset %d\r\n",
			res.ReplyTail.Have, res.ReplyTail.Offset)
	}
	fmt.Fprintf(&out, "X-Burpsy-Read-Ended: %s\r\n", readNote(res))
	fmt.Fprintf(&out, "Content-Length: %d\r\n\r\n", len(res.Response))
	out.Write(res.Response)
	return out.Bytes()
}
