package intruder

// Insertion-point discovery and payload splicing, ported from burpsy-intruder::lib.
//
// Burp's insertion-point engine materialises every attack position as an object and threads it
// through every check-dispatch scope. Here an insertion point is a Span plus a kind — no
// allocation, pointing into bytes the store already owns. A payload is applied by splicing once
// at send time rather than by cloning the request per position per check.
//
// The taxonomy mirrors Burp's, recovered from its own method names
// (addUrlFilenameInsertionPoint, addUrlFoldersInsertionPoints, ...).

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
)

// PointKind is where in a request a payload can be placed. Mirrors Burp's 8 configurable
// families.
type PointKind int

const (
	PointURLParamValue PointKind = iota
	PointURLParamName
	PointURLPathFolder
	PointURLPathFilename
	PointBodyParamValue
	PointBodyParamName
	PointEntireBody
	PointCookieValue
	PointHeaderValue
	PointBodyJSONValue
	PointBodyNestedValue
	// PointBodyXMLValue is a text node or attribute value of an XML body.
	PointBodyXMLValue
	// PointBodyMultipartValue is one part's content in a multipart body.
	PointBodyMultipartValue
	// PointBodyMultipartAttr is a quoted parameter value on a multipart part's
	// Content-Disposition header — its `name` or `filename`.
	PointBodyMultipartAttr
	PointManual
)

func (k PointKind) String() string {
	switch k {
	case PointURLParamValue:
		return "url_param_value"
	case PointURLParamName:
		return "url_param_name"
	case PointURLPathFolder:
		return "url_path_folder"
	case PointURLPathFilename:
		return "url_path_filename"
	case PointBodyParamValue:
		return "body_param_value"
	case PointBodyParamName:
		return "body_param_name"
	case PointEntireBody:
		return "entire_body"
	case PointCookieValue:
		return "cookie_value"
	case PointHeaderValue:
		return "header_value"
	case PointBodyJSONValue:
		return "body_json_value"
	case PointBodyNestedValue:
		return "body_nested_value"
	case PointBodyXMLValue:
		return "body_xml_value"
	case PointBodyMultipartValue:
		return "body_multipart_value"
	case PointBodyMultipartAttr:
		return "body_multipart_attr"
	case PointManual:
		return "manual"
	default:
		return "unknown"
	}
}

// escapeKind decides what ApplyAll does to a payload before splicing it into a
// point's window. Native intruder points splice raw bytes — wire-faithful, the
// operator's payload crosses exactly as typed. Points adopted from the scanner
// enumerator (internal/bcheck, see points_bcheck.go) live inside a container
// whose framing must survive the splice, and the enumerator already knows the
// escape for each one: JSON string, XML text node or attribute value, MIME
// quoted-string, or a rebuilt JSON/base64/XML-nested wire value. escapeNone is
// the zero value so every point constructed before this existed behaves exactly
// as before.
type escapeKind uint8

const (
	escapeNone escapeKind = iota
	// escapeBcheck rebuilds the point's whole wire value through the enumerator
	// that produced it (bcheck.InsertionPoint.WireValue), which is the single
	// definition of how a payload is escaped for each container, shared with the
	// scanner. A payload the container cannot hold at all is refused there and
	// the splice is skipped, never rewritten into something the operator did not
	// type.
	escapeBcheck
)

// InsertionPoint is an attack position: a span into the request plus what it is.
type InsertionPoint struct {
	Kind  PointKind
	Span  core.Span
	Label string

	// escape and bc are zero/nil for every natively discovered point. bc points
	// at the scanner-side point for every position adopted from the enumerator
	// (JSON, XML, multipart, nested), whose wire value is rebuilt per payload.
	escape escapeKind
	bc     *bcheck.InsertionPoint
}

// PointConfig is which position families to generate. Maps 1:1 onto Burp's
// insertion_point_types.
type PointConfig struct {
	URLParams      bool
	ParamNames     bool
	URLPathFolders bool
	URLPathFile    bool
	BodyParams     bool
	EntireBody     bool
	Cookies        bool
	Headers        bool
}

// ManualSpan is an operator-marked payload position: a byte range of the base
// request, named the way Burp names it — the § pair around a selection. Spans
// are validated (in bounds, non-overlapping) before they become points, because
// two overlapping markers would splice two payloads into the same bytes and the
// result would depend on the splice order.
type ManualSpan struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// ManualPoints turns validated spans into insertion points. Every check that
// can fail is done here rather than at the splice, so the caller's error is
// about the operator's marking, not an engine-internal refusal.
func ManualPoints(base []byte, spans []ManualSpan) ([]InsertionPoint, error) {
	points := make([]InsertionPoint, 0, len(spans))
	for i, span := range spans {
		if span.Start < 0 || span.End > len(base) || span.Start >= span.End {
			return nil, fmt.Errorf("manual point %d: start %d, end %d is not a byte range of the %d-byte request", i+1, span.Start, span.End, len(base))
		}
		for j, other := range spans {
			if j >= i {
				break
			}
			if span.Start < other.End && other.Start < span.End {
				return nil, fmt.Errorf("manual points %d and %d overlap", j+1, i+1)
			}
		}
		points = append(points, InsertionPoint{
			Kind:  PointManual,
			Span:  core.Span{Offset: span.Start, Len: span.End - span.Start},
			Label: fmt.Sprintf("manual %d", i+1),
		})
	}
	return points, nil
}

// DefaultPointConfig is Burp's own defaults: parameter values on; names/paths/headers off, as
// they multiply cost.
func DefaultPointConfig() *PointConfig {
	return &PointConfig{
		URLParams:  true,
		BodyParams: true,
		Cookies:    true,
	}
}

// AllPointConfig turns every position family on.
func AllPointConfig() *PointConfig {
	return &PointConfig{
		URLParams:      true,
		ParamNames:     true,
		URLPathFolders: true,
		URLPathFile:    true,
		BodyParams:     true,
		EntireBody:     true,
		Cookies:        true,
		Headers:        true,
	}
}

// boringHeaders are headers not worth attacking by default — they mostly produce noise.
var boringHeaders = map[string]bool{
	"host":            true,
	"content-length":  true,
	"connection":      true,
	"accept-encoding": true,
	"cookie":          true,
}

// FindPoints computes every insertion point for a stored request.
//
// Allocation is limited to the returned slice and small labels; no request bytes are copied.
func FindPoints(msg *core.StoredMessage, cfg *PointConfig) []InsertionPoint {
	var out []InsertionPoint
	raw := msg.Raw()
	target := msg.Shape.SecondToken
	tend := min(target.End(), len(raw))
	if target.Offset >= tend {
		return out
	}
	tbytes := raw[target.Offset:tend]
	qpos := bytes.IndexByte(tbytes, '?')
	pathEnd := len(tbytes)
	if qpos >= 0 {
		pathEnd = qpos
	}
	pathSpan := core.Span{Offset: target.Offset, Len: pathEnd}

	if cfg.URLPathFolders || cfg.URLPathFile {
		var segs []core.Span
		for _, s := range splitSpans(raw, pathSpan, '/') {
			if !s.IsEmpty() {
				segs = append(segs, s)
			}
		}
		for i, s := range segs {
			last := i+1 == len(segs)
			if last && cfg.URLPathFile {
				out = append(out, InsertionPoint{
					Kind:  PointURLPathFilename,
					Span:  s,
					Label: text(raw, s),
				})
			} else if !last && cfg.URLPathFolders {
				out = append(out, InsertionPoint{
					Kind:  PointURLPathFolder,
					Span:  s,
					Label: text(raw, s),
				})
			}
		}
	}

	if qpos >= 0 && (cfg.URLParams || cfg.ParamNames) {
		qstart := target.Offset + qpos + 1
		qspan := core.Span{Offset: qstart, Len: saturatingSub(tend, qstart)}
		pushKVPoints(raw, qspan, cfg.URLParams, cfg.ParamNames,
			PointURLParamValue, PointURLParamName, &out)
	}

	if cfg.Cookies {
		for _, h := range msg.Shape.Headers {
			if !nameEq(raw, h.Name, "cookie") {
				continue
			}
			for _, pair := range splitSpans(raw, h.Value, ';') {
				t := trim(raw, pair)
				if t.IsEmpty() {
					continue
				}
				if name, value, ok := splitOnce(raw, t, '='); ok {
					out = append(out, InsertionPoint{
						Kind:  PointCookieValue,
						Span:  value,
						Label: text(raw, name),
					})
				}
			}
		}
	}

	if cfg.Headers {
		for _, h := range msg.Shape.Headers {
			n := text(raw, h.Name)
			if boringHeaders[lower(n)] {
				continue
			}
			out = append(out, InsertionPoint{
				Kind:  PointHeaderValue,
				Span:  h.Value,
				Label: lower(n),
			})
		}
	}

	body := msg.Shape.Body
	if !body.IsEmpty() {
		isForm := false
		if ct := msg.Header("content-type"); len(ct) >= len("application/x-www-form-urlencoded") &&
			bytes.Contains(bytes.ToLower(ct), []byte("application/x-www-form-urlencoded")) {
			isForm = true
		}
		if isForm && (cfg.BodyParams || cfg.ParamNames) {
			pushKVPoints(raw, body, cfg.BodyParams, cfg.ParamNames,
				PointBodyParamValue, PointBodyParamName, &out)
		}
		if cfg.BodyParams {
			// Every other body container — JSON fields, XML nodes and attributes,
			// multipart parts and their attributes, and base64/XML nested inside any
			// of them — comes from the scanner's enumerator; see points_bcheck.go for
			// why Intruder keeps exactly one body-container parser.
			out = appendContainerPoints(raw, msg, body, raw[body.Offset:body.End()], out)
		}
		if cfg.EntireBody {
			out = append(out, InsertionPoint{
				Kind:  PointEntireBody,
				Span:  body,
				Label: "body",
			})
		}
	}
	return out
}

func pushKVPoints(raw []byte, region core.Span, wantValues, wantNames bool,
	vkind, nkind PointKind, out *[]InsertionPoint) {
	for _, pair := range splitSpans(raw, region, '&') {
		if pair.IsEmpty() {
			continue
		}
		if name, value, ok := splitOnce(raw, pair, '='); ok {
			if wantValues {
				*out = append(*out, InsertionPoint{Kind: vkind, Span: value, Label: text(raw, name)})
			}
			if wantNames {
				*out = append(*out, InsertionPoint{Kind: nkind, Span: name, Label: text(raw, name)})
			}
		} else if wantNames {
			*out = append(*out, InsertionPoint{Kind: nkind, Span: pair, Label: text(raw, pair)})
		}
	}
}

// ApplyPlace is one splice for ApplyAll.
type ApplyPlace struct {
	Point   *InsertionPoint
	Payload []byte
}

// spliced is a resolved (clamped) splice, pre-sort.
type spliced struct {
	start, end int
	payload    []byte
}

// Apply splices payload into raw at point, producing the request to send.
//
// The only place a request is copied, and it happens once per attempt — not once per insertion
// point per check, which is where Burp's memory goes.
func Apply(raw []byte, point *InsertionPoint, payload []byte) []byte {
	return ApplyAll(raw, []ApplyPlace{{Point: point, Payload: payload}})
}

// ApplyAll splices several payloads into one request in a single pass.
//
// Pitchfork and cluster bomb fill every selected position in the same request, so the obvious
// "call Apply once per position" is wrong twice over: it copies the whole request N times, and
// every splice invalidates the spans of the positions to its right.
//
// Overlapping positions are real input, not a hypothetical: EntireBody contains every
// BodyParamValue, and a UrlParamName sits directly against its value. The rule is
// earliest-starting span wins, later overlapping spans are skipped, so the output is always a
// well-formed request and never a half-spliced one.
//
// ApplyAll is the byte-only view for callers that cannot act on a refusal (Apply, and the
// splice-shape tests): a payload the container cannot hold is dropped and the request is built
// from what remains. The attack driver uses applyAllChecked instead, so it can record the
// dropped attempt as skipped rather than sending it — see that function.
func ApplyAll(raw []byte, places []ApplyPlace) []byte {
	out, _ := applyAllChecked(raw, places)
	return out
}

// applyAllChecked is ApplyAll with the refusals surfaced. refusals holds one reason per place
// whose payload the container refused, in the enumerator's own words (escapePayload → bcheck's
// WireValue). Its emptiness is the contract the driver acts on: a non-empty refusals means this
// attempt could not be represented as the operator asked, so the driver records it as skipped
// and never sends the bytes — otherwise a single-position attack whose only payload was refused
// would go out as the unmodified base request and read in the report as a real send
// (burpsy-react-ui-194b). The returned bytes are still a well-formed request (the refused places
// simply do not appear in it), so a caller that only wants a request can ignore refusals.
func applyAllChecked(raw []byte, places []ApplyPlace) (out []byte, refusals []string) {
	sl := make([]spliced, 0, len(places))
	for _, pl := range places {
		payload, err := escapePayload(pl.Point, pl.Payload)
		if err != nil {
			// The payload cannot be written into its container at all: a multipart
			// part's content carrying that part's boundary delimiter, a line break
			// inside a quoted header attribute, a nested wire value that failed to
			// rebuild. Splicing it anyway would end the container and send a request
			// that is corrupt rather than mutated, so the position is dropped from the
			// spliced output and its reason is carried out for the driver to record.
			refusals = append(refusals, err.Error())
			continue
		}
		start := pl.Point.Span.Offset
		if start > len(raw) {
			start = len(raw)
		}
		end := pl.Point.Span.End()
		if end > len(raw) {
			end = len(raw)
		}
		if end < start {
			end = start
		}
		sl = append(sl, spliced{start: start, end: end, payload: payload})
	}
	sortSpans(sl)

	extra := 0
	for _, s := range sl {
		extra += len(s.payload)
	}
	built := make([]byte, 0, len(raw)+extra)
	cursor := 0
	for _, s := range sl {
		if s.start < cursor {
			continue
		}
		built = append(built, raw[cursor:s.start]...)
		built = append(built, s.payload...)
		cursor = s.end
	}
	built = append(built, raw[cursor:]...)

	// A chunked request's body is a sequence of size-prefixed chunks, and the
	// splices above changed the bytes inside one of them. Every size before the
	// spliced chunk still describes its data exactly; the spliced chunk's size
	// is the only one that can be stale, and rewriteChunkedBody restates each
	// size against the bytes it precedes — the same walk dechunk runs on the
	// way in (rrm6). It also drops a stale Content-Length: with
	// Transfer-Encoding: chunked the chunk stream frames the body, and a
	// Content-Length counting the pre-splice bytes is the framing disagreement
	// a smuggling probe is built to surface. Our own attack request is kept to
	// one honest framing rather than two contradictory ones.
	if shape, err := core.Parse(raw, core.DirectionRequest); err == nil {
		if te := headerSpan(raw, shape, "transfer-encoding"); te != nil &&
			bytes.Contains(bytes.ToLower(raw[te.Offset:te.End()]), []byte("chunked")) {
			return rewriteChunkedBody(raw, built), refusals
		}
	}
	return fixContentLength(built), refusals
}

// sortSpans orders by (start, end) ascending, matching the Rust sort_by_key.
func sortSpans(sl []spliced) {
	for i := 1; i < len(sl); i++ {
		for j := i; j > 0; j-- {
			if sl[j-1].start < sl[j].start || (sl[j-1].start == sl[j].start && sl[j-1].end <= sl[j].end) {
				break
			}
			sl[j-1], sl[j] = sl[j], sl[j-1]
		}
	}
}

// fixContentLength recomputes Content-Length after splicing, else servers reject or hang.
func fixContentLength(raw []byte) []byte {
	shape, err := core.Parse(raw, core.DirectionRequest)
	if err != nil {
		return append([]byte(nil), raw...)
	}
	bodyLen := shape.Body.Len
	var hdr *core.Span
	for _, h := range shape.Headers {
		if nameEq(raw, h.Name, "content-length") {
			vv := h.Value
			hdr = &vv
			break
		}
	}
	if hdr == nil {
		return append([]byte(nil), raw...)
	}
	newVal := itoa(bodyLen)
	var out []byte
	out = append(out, raw[:min(hdr.Offset, len(raw))]...)
	out = append(out, newVal...)
	out = append(out, raw[min(hdr.End(), len(raw)):]...)
	return out
}

// rewriteChunkedBody re-emits the spliced request's chunked body with honest
// chunk sizes, and drops a Content-Length that no longer describes the body.
//
// The size lines in `out` are stale: exactly one chunk — the one a splice
// landed in — has a size that no longer counts the bytes following it, so a
// walk that trusted those sizes would measure every later chunk from the wrong
// place. The walk is therefore anchored in `base`, the pre-splice request,
// whose sizes are all honest: each base chunk's data span is located from
// base's own size lines, then the same span is measured in `out` — identical
// bytes for untouched chunks (only absolute offsets moved by the earlier
// splices), one payload longer or shorter for the spliced chunk. The fresh
// size is computed from what `out` actually holds, which is the whole repair.
//
// Content-Length is dropped when present: with Transfer-Encoding: chunked the
// chunk stream frames the body, and a Content-Length counting the pre-splice
// bytes is precisely the framing disagreement a smuggling probe is built to
// surface. An attack request keeps one honest framing rather than two
// contradictory ones.
func rewriteChunkedBody(base, out []byte) []byte {
	shape, err := core.Parse(base, core.DirectionRequest)
	if err != nil {
		return out
	}
	bodyStart := shape.Body.Offset
	head := base[:bodyStart]

	// The head is byte-identical between base and out — every splice lands
	// inside the body — so out's body starts at the same offset. Rebuild the
	// head, minus Content-Length, and track how its length moved so the body
	// walk can translate offsets between the two frames.
	sb := make([]byte, 0, len(out)+16)
	sb = append(sb, head...)
	delta := 0
	if cl := headerSpan(base, shape, "content-length"); cl != nil {
		lineStart := cl.Offset
		for lineStart > 0 && head[lineStart-1] != '\n' {
			lineStart--
		}
		lineEnd := cl.End()
		for lineEnd < bodyStart && head[lineEnd] != '\n' {
			lineEnd++
		}
		if lineEnd < bodyStart {
			lineEnd++ // the '\n'
		}
		sb = sb[:lineStart]
		sb = append(sb, head[lineEnd:]...)
		delta = len(sb) - bodyStart
	}

	baseBody := base[bodyStart:]
	outBody := out[bodyStart:]
	bcur, ocur := 0, 0
	for {
		nl := bytes.IndexByte(baseBody[bcur:], '\n')
		if nl < 0 {
			// No more chunk headers: keep out's remaining bytes verbatim.
			sb = append(sb, outBody[ocur:]...)
			break
		}
		line := strings.TrimSpace(string(baseBody[bcur : bcur+nl]))
		sizeHex := line
		if i := strings.IndexByte(line, ';'); i >= 0 {
			sizeHex = line[:i]
		}
		size, err := strconv.ParseUint(sizeHex, 16, 64)
		if err != nil || size == 0 || uint64(len(baseBody)-(bcur+nl+1)) < size {
			// Terminal chunk, truncated stream, or not a chunk header at all.
			// No splice can live past this point — points are refused outside
			// chunk data — so the tail is byte-identical modulo the shift.
			sb = append(sb, outBody[ocur:]...)
			break
		}
		dataStart := bcur + nl + 1
		dataEnd := dataStart + int(size)
		oLineStart := bcur + delta
		oDataStart := dataStart + delta
		// The spliced chunk's data in out: base's data with every splice that
		// landed inside it already applied. Its length is whatever separates
		// out's data start from the first byte of out's copy of the NEXT
		// base line — but simpler and exact: out's body is base's body with
		// the splices applied, so the next chunk header in out begins at
		// (nextBaseHeader + deltaAfter), where deltaAfter accumulates each
		// chunk's size change. Track it as we go.
		nextNl := bytes.IndexByte(baseBody[dataEnd:], '\n')
		var oDataEnd int
		if nextNl < 0 {
			oDataEnd = len(outBody)
		} else {
			oDataEnd = dataEnd + delta + nextNl
			// oDataEnd currently points at out's next size line's newline;
			// walk back over the CR to the end of out's data.
			for oDataEnd > oDataStart && (outBody[oDataEnd-1] == '\n' || outBody[oDataEnd-1] == '\r') {
				oDataEnd--
			}
		}
		newSize := oDataEnd - oDataStart
		if newSize < 0 {
			sb = append(sb, outBody[ocur:]...)
			break
		}
		// Emit: out's bytes up to the size line (excluding the old size text),
		// then the fresh size, then the CRLF that ended base's size line, then
		// out's data, then the CRLF that follows it.
		sb = append(sb, outBody[ocur:oLineStart]...)
		sb = append(sb, strconv.FormatInt(int64(newSize), 16)...)
		sb = append(sb, baseBody[bcur+nl:dataStart]...) // the original "\r\n" of the size line
		sb = append(sb, outBody[oDataStart:oDataEnd]...)
		// chunk-terminating CRLF: in base it sits at dataEnd..(dataEnd+2 when CRLF).
		sepEnd := dataEnd
		for sepEnd < len(baseBody) && (baseBody[sepEnd] == '\r' || baseBody[sepEnd] == '\n') {
			sepEnd++
		}
		oSepEnd := sepEnd + delta
		sb = append(sb, outBody[oDataEnd:oSepEnd]...)
		bcur = sepEnd
		ocur = oSepEnd
		// Accumulate this chunk's size change into the running offset delta.
		delta += newSize - int(size)
	}
	return sb
}

// headerSpan returns the span of the first header named name, or nil.
func headerSpan(raw []byte, shape core.MessageShape, name string) *core.Span {
	for _, h := range shape.Headers {
		if nameEq(raw, h.Name, name) {
			vv := h.Value
			return &vv
		}
	}
	return nil
}

// ---- span helpers ------------------------------------------------------------------------

func splitSpans(raw []byte, region core.Span, sep byte) []core.Span {
	var out []core.Span
	end := min(region.End(), len(raw))
	start := min(region.Offset, end)
	for i := start; i < end; i++ {
		if raw[i] == sep {
			out = append(out, core.Span{Offset: start, Len: i - start})
			start = i + 1
		}
	}
	out = append(out, core.Span{Offset: start, Len: saturatingSub(end, start)})
	return out
}

func splitOnce(raw []byte, region core.Span, sep byte) (core.Span, core.Span, bool) {
	end := min(region.End(), len(raw))
	for i := region.Offset; i < end; i++ {
		if raw[i] == sep {
			return core.Span{Offset: region.Offset, Len: i - region.Offset},
				core.Span{Offset: i + 1, Len: saturatingSub(end, i+1)}, true
		}
	}
	return core.Span{}, core.Span{}, false
}

func trim(raw []byte, s core.Span) core.Span {
	end := min(s.End(), len(raw))
	a := min(s.Offset, end)
	b := end
	for a < b && (raw[a] == ' ' || raw[a] == '\t') {
		a++
	}
	for b > a && (raw[b-1] == ' ' || raw[b-1] == '\t') {
		b--
	}
	return core.Span{Offset: a, Len: b - a}
}

func nameEq(raw []byte, s core.Span, want string) bool {
	end := min(s.End(), len(raw))
	start := min(s.Offset, end)
	if end-start != len(want) {
		return false
	}
	return bytes.EqualFold(raw[start:end], []byte(want))
}

func text(raw []byte, s core.Span) string {
	end := min(s.End(), len(raw))
	return string(raw[min(s.Offset, end):end])
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func saturatingSub(a, b int) int {
	if a < b {
		return 0
	}
	return a - b
}

func itoa(n int) []byte {
	if n == 0 {
		return []byte{'0'}
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return buf[i:]
}
