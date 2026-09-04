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
	default:
		return "unknown"
	}
}

// escapeKind decides what ApplyAll does to a payload before splicing it into a
// point's window. Native intruder points splice raw bytes — wire-faithful, the
// operator's payload crosses exactly as typed. Points adopted from the scanner
// enumerator (internal/bcheck, see points_bcheck.go) live inside a container
// whose framing must survive the splice: a JSON string value needs its payload
// escaped, and a value nested inside base64/XML needs the whole outer wire
// value rebuilt. escapeNone is the zero value so every point constructed
// before this existed behaves exactly as before.
type escapeKind uint8

const (
	escapeNone escapeKind = iota
	escapeJSON
	escapeNested
)

// InsertionPoint is an attack position: a span into the request plus what it is.
type InsertionPoint struct {
	Kind  PointKind
	Span  core.Span
	Label string

	// escape and bc are zero/nil for every natively discovered point. bc points
	// at the scanner-side point for body_nested_value positions, whose wire
	// value must be rebuilt per payload (decode → splice → re-encode).
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
			// JSON fields (and base64/XML nested inside body values) come from the
			// scanner's enumerator — see points_bcheck.go for why Intruder keeps
			// exactly one body-container parser.
			out = appendJSONAndNestedPoints(raw, msg, body, out)
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
func ApplyAll(raw []byte, places []ApplyPlace) []byte {
	sl := make([]spliced, 0, len(places))
	for _, pl := range places {
		payload, ok := escapePayload(pl.Point, pl.Payload)
		if !ok {
			// A nested wire value failed to rebuild. Enumeration decoded the very
			// same bytes, so this is unreachable in practice; skipping the splice
			// keeps the guarantee below — the output is always a well-formed
			// request — rather than splicing a payload that corrupts the container.
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
	out := make([]byte, 0, len(raw)+extra)
	cursor := 0
	for _, s := range sl {
		if s.start < cursor {
			continue
		}
		out = append(out, raw[cursor:s.start]...)
		out = append(out, s.payload...)
		cursor = s.end
	}
	out = append(out, raw[cursor:]...)
	return fixContentLength(out)
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
