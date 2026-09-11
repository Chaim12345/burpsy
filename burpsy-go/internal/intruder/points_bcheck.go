package intruder

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
)

// Intruder used to keep its own body parser, and it only knew form-encoding:
// a JSON body yielded a single entire-body position, so no individual field of
// a JSON API request could be attacked (burpsy-react-ui-33t). The scanner's
// enumerator in internal/bcheck already models JSON string values and
// base64/XML nested containers, escapes payloads per container and refuses
// bodies it would corrupt. Rather than grow a second parser beside it — two
// parsers means two container models drifting apart — Intruder now consumes
// that enumerator for body containers the form walker cannot read.
//
// What is deliberately *not* taken from bcheck: form bodies (the native
// form walker already covers them, wire-faithful and unescaped), cookies,
// headers, query and path (same reason). Only positions the native discovery
// cannot express arrive here: body_json_value and body_nested_value.
//
// Top-level XML and multipart bodies stay absent on purpose: bcheck declines
// them today, and the single-parser policy says Intruder grows XML support the
// day the scanner does — those bodies keep the entire-body fallback meanwhile.

// appendJSONAndNestedPoints maps the scanner enumerator's body points onto
// intruder positions. bcheck's windows are body-relative; intruder's spans are
// absolute into the raw request, so every window is shifted by the body span.
// The enumerator's refusals are ignored by design: a declined body simply
// contributes no new positions, which is what the pre-33t behaviour was.
//
// Chunked bodies are the rrm6 seam. ParseRequestEdit dechunks before
// enumerating, so a window [start,end) is relative to the *decoded* stream
// while intruder's spans point into the *wire* bytes, which still carry chunk
// headers. When both endpoints of a window map into the same chunk the wire
// span is [chunkData+start', chunkData+end') and splicing it leaves every
// chunk size before the splice intact — the only thing rewriteBodyFraming has
// to fix afterwards is the last chunk's size. A window whose endpoints fall in
// different chunks has no wire span at all: refusing it keeps the guarantee
// that an attack request is never a half-spliced one, the same posture the
// multipart decline takes.
func appendJSONAndNestedPoints(raw []byte, msg *core.StoredMessage, body core.Span, rawBody []byte, out []InsertionPoint) []InsertionPoint {
	// A negative limit is uncapped: the scanner's per-request ceiling guards
	// audit cost, while an attack is bounded by its own max-payload and
	// position-count limits downstream.
	chunked := isChunkedBody(raw, msg)
	points, _ := bcheck.EnumerateWithLimit(raw, []string{string(bcheck.IpBody)}, -1)
	for i := range points {
		p := &points[i]
		if start, end, ok := p.BodyJSONWindow(); ok {
			off, ln, ok := wireWindow(rawBody, start, end, chunked)
			if !ok {
				continue
			}
			out = append(out, InsertionPoint{
				Kind:   PointBodyJSONValue,
				Span:   core.Span{Offset: body.Offset + off, Len: ln},
				Label:  p.Name,
				escape: escapeJSON,
			})
			continue
		}
		if start, end, ok := p.BodyNestedWindow(); ok {
			off, ln, ok := wireWindow(rawBody, start, end, chunked)
			if !ok {
				continue
			}
			out = append(out, InsertionPoint{
				Kind:   PointBodyNestedValue,
				Span:   core.Span{Offset: body.Offset + off, Len: ln},
				Label:  p.Name,
				escape: escapeNested,
				bc:     p,
			})
		}
	}
	return out
}

// wireWindow maps a decoded-frame window [start,end) onto the wire frame and
// reports whether a single contiguous wire span exists for it. The length is
// the decoded length — chunk framing sits outside value bytes, so the decoded
// bytes are identical to the wire bytes they map to. For an unchunked body the
// two frames are the same and the window passes through unchanged. For a
// chunked body both endpoints must land inside the same chunk's data;
// anything else (framing the parser cannot read, a window straddling a chunk
// boundary) yields ok=false and the point is omitted.
func wireWindow(rawBody []byte, start, end int, chunked bool) (off, ln int, ok bool) {
	if !chunked {
		return start, end - start, true
	}
	rawStart, ok := rawBodyOffset(rawBody, start, end)
	if !ok {
		return 0, 0, false
	}
	return rawStart, end - start, true
}

// rawBodyOffset resolves where the decoded offset begins in the raw wire body,
// refusing windows that would straddle a chunk boundary: both start and end
// must fall inside the same chunk's data. It walks dechunk's exact state
// machine (internal/core/edit.go:329) — a disagreement here would splice into
// framing instead of data — and reports ok=false for a malformed size line, a
// window past the decoded end, or a straddle (rrm6's destroy-the-request
// class: the splice would land in the next chunk header, and the stale size
// would make the server read the payload as framing).
func rawBodyOffset(rawBody []byte, start, end int) (rawStart int, ok bool) {
	if start < 0 || end < start {
		return 0, false
	}
	consumed := 0
	rawCursor := 0
	for {
		nl := bytes.IndexByte(rawBody[rawCursor:], '\n')
		if nl < 0 {
			return 0, false
		}
		line := strings.TrimSpace(string(rawBody[rawCursor : rawCursor+nl]))
		sizeHex := line
		if i := strings.IndexByte(line, ';'); i >= 0 {
			sizeHex = line[:i]
		}
		size, err := strconv.ParseUint(sizeHex, 16, 64)
		if err != nil {
			return 0, false
		}
		dataStart := rawCursor + nl + 1
		if size == 0 {
			// Terminal chunk: the decoded stream ends here, so a window with
			// start < end cannot begin at or past it.
			return 0, false
		}
		avail := len(rawBody) - dataStart
		if uint64(avail) < size {
			// Truncated stream: dechunk appends the whole tail, so a window
			// inside the tail is itself the raw tail — no framing to protect.
			if consumed <= start && end <= consumed+avail {
				return dataStart + (start - consumed), true
			}
			return 0, false
		}
		if consumed <= start && end <= consumed+int(size) {
			return dataStart + (start - consumed), true
		}
		if end <= consumed+int(size) {
			// end fits inside this chunk but start is in an earlier one.
			return 0, false
		}
		consumed += int(size)
		rawCursor = dataStart + int(size)
		for rawCursor < len(rawBody) && (rawBody[rawCursor] == '\r' || rawBody[rawCursor] == '\n') {
			rawCursor++
		}
	}
}

// isChunkedBody reports whether the message carries a chunked transfer
// encoding, which is the one case where the stored body span and the
// enumerator's decoded stream disagree: ParseRequestEdit dechunks before
// enumerating, so bcheck's windows are relative to the decoded bytes while
// msg.Shape.Body is a span into the raw wire bytes that still carry framing.
func isChunkedBody(raw []byte, msg *core.StoredMessage) bool {
	for _, h := range msg.Shape.Headers {
		if strings.EqualFold(string(raw[h.Name.Offset:h.Name.End()]), "transfer-encoding") &&
			strings.Contains(strings.ToLower(string(raw[h.Value.Offset:h.Value.End()])), "chunked") {
			return true
		}
	}
	return false
}

// escapePayload prepares one payload for splicing into its point, per the
// point's container. Native points pass the payload through byte-for-byte.
func escapePayload(p *InsertionPoint, payload []byte) ([]byte, bool) {
	switch p.escape {
	case escapeJSON:
		return []byte(bcheck.EscapeJSON(string(payload))), true
	case escapeNested:
		v, err := p.bc.WireValue(string(payload))
		if err != nil {
			return nil, false
		}
		return []byte(v), true
	default:
		return payload, true
	}
}
