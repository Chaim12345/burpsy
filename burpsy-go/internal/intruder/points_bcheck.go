package intruder

import (
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
func appendJSONAndNestedPoints(raw []byte, msg *core.StoredMessage, body core.Span, out []InsertionPoint) []InsertionPoint {
	// A negative limit is uncapped: the scanner's per-request ceiling guards
	// audit cost, while an attack is bounded by its own max-payload and
	// position-count limits downstream.
	points, _ := bcheck.EnumerateWithLimit(raw, []string{string(bcheck.IpBody)}, -1)
	for i := range points {
		p := &points[i]
		if start, end, ok := p.BodyJSONWindow(); ok {
			out = append(out, InsertionPoint{
				Kind:   PointBodyJSONValue,
				Span:   core.Span{Offset: body.Offset + start, Len: end - start},
				Label:  p.Name,
				escape: escapeJSON,
			})
			continue
		}
		if start, end, ok := p.BodyNestedWindow(); ok {
			out = append(out, InsertionPoint{
				Kind:   PointBodyNestedValue,
				Span:   core.Span{Offset: body.Offset + start, Len: end - start},
				Label:  p.Name,
				escape: escapeNested,
				bc:     p,
			})
		}
	}
	return out
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
