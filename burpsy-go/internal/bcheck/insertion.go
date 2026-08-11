// Insertion points — the places in a request where a payload can be placed.
//
// `given insertion point` runs a check once per point, and `send payload`
// mutates **exactly one** of them per send. That one-at-a-time rule is the whole
// value of the construct: it is what lets a finding say *which parameter* is
// injectable. A run that changed two parameters would report a vulnerability
// without saying where it is, which is not a finding, it is a rumour.
//
// # A point is an offset, not a copy
//
// Each point holds a byte range into one component of the base request — the
// query string, one header's value, or the body. Enumerating every point for a
// request therefore costs a few small labels, not a request clone per position.
// A payload is applied by splicing that one range, so everything else in the
// request is untouched, which is what makes a resulting finding attributable to
// the point's name.
//
// Because the ranges address the **base** request, Apply must always be handed
// the request the point was enumerated from. Applying twice, or applying to an
// already-mutated request, would splice at offsets that no longer mean what they
// meant.
//
// # Which families exist, and why the DSL names only four
//
// BCheck's `given … insertion point` grammar can name exactly four of them —
// `query`, `body`, `cookie`, `header`. Parameter *names*, the entire body, and
// URL path segments are attackable by Burp's scanner but unaddressable from the
// DSL, so a `given` line can never constrain a probe to them. The engine
// nonetheless enumerates them (`param-name`, `path-filename`, `path-folder`,
// `body-whole`) for consumers that audit beyond the DSL — the native engine,
// an operator-driven API audit — and a consumer must name them explicitly:
// `any` never expands to them, because a check that says `any` means any
// *named* location and silently adding positions the check author never named
// would change what it tested.
//
// **`any` includes headers.** The evidence is `other/tokens/jwt-none-algorithm
// .bcheck`, which is a bare `given insertion point` and carries the author's own
// comment: *"Authorization header is treat differently as the base value may be
// prefixed with 'Bearer'"*. A JWT check whose `any` skipped headers would never
// fire on the one place JWTs live.
//
// **Nested points are not enumerated.** Burp audits inside an already-decoded
// parameter and reports `"Skipped as nested insertion points not enabled"`
// when that is switched off. Not implementing it is a miss, never a false
// positive: fewer positions get probed, and every position that does get probed
// is still exactly one.
//
// # Encoding: escape the payload, never re-encode the base value
//
// A payload dropped raw into a query parameter can carry `&` or `=` and silently
// become *two* parameters. So the payload is percent-escaped for the byte set
// that decides how the container is parsed, and only that set.
//
// The base value is left byte-identical. The alternative — decode the base
// value, splice, re-encode the whole thing, which is what Burp's insertion
// points do — rewrites bytes the check never asked to change (`a+b` would go
// out as `a%20b`), and a probe that differs from the baseline in ways the check
// did not cause is a false positive waiting to happen.
package bcheck

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
)

// IpKind is an insertion-point family the DSL can name. `any` is a selector in
// the `given` line, not a location, so it never appears on an InsertionPoint.
type IpKind string

const (
	IpQuery  IpKind = "query"
	IpBody   IpKind = "body"
	IpCookie IpKind = "cookie"
	IpHeader IpKind = "header"

	// The non-DSL families. No `given … insertion point` grammar line can name
	// these (see the package doc); they exist for consumers that audit beyond
	// the DSL. `any` deliberately never expands to them.
	IpParamName IpKind = "param-name"
	IpPathFile  IpKind = "path-filename"
	IpPathDir   IpKind = "path-folder"
	IpBodyAll   IpKind = "body-whole"
)

// InsertionPoint is one place a payload can go, plus the value already there.
type InsertionPoint struct {
	// Kind is never IpAny — `any` is a selector in the `given` line, not a
	// location.
	Kind IpKind
	// Name is the parameter, header or cookie name. For JSON, the key (or
	// `key[i]` inside an array).
	Name string
	// BaseValue is the value as it appears on the wire, still encoded. What
	// `{insertion_point_base_value}` resolves to, and what `appending:` appends
	// to. Burp registers the same thing in the BCheck *variable* map rather
	// than the request map, guarded on both a v1-beta-or-later language and a
	// non-null insertion point — which is why the name is simply absent outside
	// an insertion-point check rather than empty inside one.
	BaseValue string

	loc    loc
	coding coding
}

// locKind enumerates which component of the base request a point addresses.
type locKind int

const (
	locQuery locKind = iota
	locHeader
	locCookie
	locBody
	// locPath addresses a byte range within the request path (slash-free
	// segments), for the path-folder / path-filename families.
	locPath
)

// loc is a byte range within one component of the base request: the query
// string, the value of header `index`, a range within that value, the body, or
// the path.
type loc struct {
	kind  locKind
	index int // header index for locHeader / locCookie
	start int
	end   int
}

// coding describes how a payload must be escaped so the surrounding container
// still parses.
type coding int

const (
	// codingRaw is a header value, multipart value or CDATA section: no
	// container to break, so the payload goes out verbatim.
	codingRaw coding = iota
	// codingForm is a `k=v` pair in a query string, a cookie header or a form
	// body.
	codingForm
	// codingJson is inside a JSON string literal.
	codingJson
	// codingXMLText is XML element text content: `&` and `<` decide how the
	// container is parsed and `>` is escaped too (a raw `>` is legal XML text
	// but `]]>` / `-->` sequences break out of CDATA / comments).
	codingXMLText
	// codingXMLAttr is an XML attribute value: the text escapes plus the quote
	// that ends the attribute.
	codingXMLAttr
	// codingPath is a URL path segment: `/`, `?` and `#` decide the route, `%`
	// changes how the segment itself decodes, and the request line is ASCII.
	codingPath
)

// Declined is a place the enumerator refused to build insertion points for, and
// why.
//
// The body case is the one that matters: splicing a payload into a container
// whose framing is not modelled (plain text, a non-UTF-8 body, a multipart body
// with no parseable boundary) produces a request the server rejects before the
// code under test ever sees it. Returning nothing in that case made the refusal
// indistinguishable from "this request genuinely has nowhere to inject" — so a
// `given body insertion point` check against such a body reported a clean bill
// of health while testing nothing. That is the silent false negative this type
// exists to prevent: a declined body is surfaced as skipped, never as tested.
// XML and multipart bodies used to be declined; both are modelled now, so their
// refusals no longer occur.
type Declined struct {
	// What was declined, named for the operator ("request body").
	What string
	// Why no points were built ("multipart body: framing not modelled").
	Reason string
}

// Describe returns one line naming both what was declined and why, for a report
// row or an Unsupported payload. Neither field alone is enough: Reason without
// What reads as an unattributed error, and a check with several `given …
// insertion point` clauses can decline more than one kind of place.
func (d Declined) Describe() string {
	return fmt.Sprintf("%s: %s", d.What, d.Reason)
}

// Enumerate returns every insertion point of the requested kinds, in a fixed
// order: query, headers, cookies, body, then the non-DSL families (param-name,
// path-folder, path-filename, body-whole) — plus the places that were
// *declined* rather than enumerated.
//
// The order is pinned because it is observable — a check reports one finding
// per point, and a scanner that reordered them between runs would reorder its
// own output.
//
// An empty point list with no declines is normal (a bare `GET /` with no
// interesting headers has nowhere to inject) and means the check simply has
// nothing to do here. An empty point list *with* declines is different: the
// request had somewhere to inject that this enumerator refuses to splice into,
// and the caller must report that as skipped rather than clean.
func Enumerate(req []byte, kinds []string) ([]InsertionPoint, []Declined) {
	e, err := core.ParseRequestEdit(req)
	if err != nil {
		// Go's raw-byte model lets an unparseable request reach the enumerator,
		// which the Rust type system prevents. It has nowhere to inject, and the
		// refusal is recorded so the check reads as skipped, not tested.
		return nil, []Declined{{What: "request", Reason: "unparseable request: " + err.Error()}}
	}
	want := func(k IpKind) bool {
		for _, kd := range kinds {
			if kd == "any" || IpKind(kd) == k {
				return true
			}
		}
		return false
	}
	// wantExact matches only the literal kind string — the non-DSL families a
	// consumer must name explicitly. `any` never expands to them (see the
	// package doc): a check that says `any` means any *named* location.
	wantExact := func(k IpKind) bool {
		for _, kd := range kinds {
			if IpKind(kd) == k {
				return true
			}
		}
		return false
	}

	var out []InsertionPoint
	var declined []Declined

	if want(IpQuery) {
		for _, kv := range kvPairs(e.Query, '&') {
			out = append(out, InsertionPoint{
				Kind:      IpQuery,
				Name:      e.Query[kv.name[0]:kv.name[1]],
				BaseValue: e.Query[kv.value[0]:kv.value[1]],
				loc:       loc{kind: locQuery, start: kv.value[0], end: kv.value[1]},
				coding:    codingForm,
			})
		}
	}

	if want(IpHeader) {
		for i, h := range e.Headers {
			if isReservedHeader(h[0]) {
				continue
			}
			out = append(out, InsertionPoint{
				Kind:      IpHeader,
				Name:      h[0],
				BaseValue: h[1],
				loc:       loc{kind: locHeader, index: i},
				coding:    codingRaw,
			})
		}
	}

	if want(IpCookie) {
		for i, h := range e.Headers {
			if !strings.EqualFold(h[0], "cookie") {
				continue
			}
			for _, kv := range kvPairs(h[1], ';') {
				out = append(out, InsertionPoint{
					Kind:      IpCookie,
					Name:      h[1][kv.name[0]:kv.name[1]],
					BaseValue: h[1][kv.value[0]:kv.value[1]],
					loc:       loc{kind: locCookie, index: i, start: kv.value[0], end: kv.value[1]},
					coding:    codingForm,
				})
			}
		}
	}

	if want(IpBody) {
		bodyPoints(e, &out, &declined)
	}

	// Non-DSL families, after the DSL four so the pinned order keeps existing
	// points stable. No `given` line names these; a consumer must ask for them
	// by kind.

	if wantExact(IpParamName) {
		// Query parameter names first, then form-body names, then JSON keys —
		// the order the values are enumerated in above.
		for _, kv := range kvPairs(e.Query, '&') {
			out = append(out, InsertionPoint{
				Kind:      IpParamName,
				Name:      e.Query[kv.name[0]:kv.name[1]],
				BaseValue: e.Query[kv.name[0]:kv.name[1]],
				loc:       loc{kind: locQuery, start: kv.name[0], end: kv.name[1]},
				coding:    codingForm,
			})
		}
		if isFormBody(e) {
			for _, kv := range kvPairs(string(e.Body), '&') {
				out = append(out, InsertionPoint{
					Kind:      IpParamName,
					Name:      string(e.Body[kv.name[0]:kv.name[1]]),
					BaseValue: string(e.Body[kv.name[0]:kv.name[1]]),
					loc:       loc{kind: locBody, start: kv.name[0], end: kv.name[1]},
					coding:    codingForm,
				})
			}
		}
		if isJSONBody(e) {
			for _, jk := range jsonStringKeys(string(e.Body)) {
				out = append(out, InsertionPoint{
					Kind:      IpParamName,
					Name:      jk.name,
					BaseValue: jk.name,
					loc:       loc{kind: locBody, start: jk.value[0], end: jk.value[1]},
					coding:    codingJson,
				})
			}
		}
	}

	segs, file := pathSegments(e.Path)
	if wantExact(IpPathDir) {
		for i := range segs {
			if i == file {
				continue
			}
			out = append(out, InsertionPoint{
				Kind:      IpPathDir,
				Name:      e.Path[segs[i][0]:segs[i][1]],
				BaseValue: e.Path[segs[i][0]:segs[i][1]],
				loc:       loc{kind: locPath, start: segs[i][0], end: segs[i][1]},
				coding:    codingPath,
			})
		}
	}
	if wantExact(IpPathFile) && file >= 0 {
		out = append(out, InsertionPoint{
			Kind:      IpPathFile,
			Name:      e.Path[segs[file][0]:segs[file][1]],
			BaseValue: e.Path[segs[file][0]:segs[file][1]],
			loc:       loc{kind: locPath, start: segs[file][0], end: segs[file][1]},
			coding:    codingPath,
		})
	}
	if wantExact(IpBodyAll) && len(e.Body) > 0 {
		if utf8.Valid(e.Body) {
			out = append(out, InsertionPoint{
				Kind:      IpBodyAll,
				Name:      "body",
				BaseValue: string(e.Body),
				loc:       loc{kind: locBody, start: 0, end: len(e.Body)},
				coding:    codingRaw,
			})
		} else {
			declined = append(declined, Declined{
				What:   "request body",
				Reason: "non-UTF-8 body: cannot splice without corrupting it",
			})
		}
	}

	return out, declined
}

// isReservedHeader reports whether a payload must not be placed in the named
// header.
//
// `Host` selects the virtual host, so a payload there tests a different
// application and the finding would be misattributed. `Content-Length` and
// `Transfer-Encoding` are rewritten on serialisation, so a payload in them is
// discarded before it reaches the wire — a silent no-op probe, which is worse
// than no probe. `Connection` is hop-by-hop. `Cookie` is enumerated as
// individual cookie points instead, because a payload appended to the whole
// cookie blob is not attributable to any one cookie.
func isReservedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection", "cookie":
		return true
	}
	return false
}

// bodyPoints appends body points, if the body is a container we can splice into
// without corrupting it — otherwise a Declined entry naming what was refused
// and why.
//
// The modelled containers are JSON (string values), `k=v` forms, XML (element
// text, CDATA and attribute values) and multipart/form-data (part values and
// uploaded file names). Everything else — plain text, a multipart body with no
// parseable boundary, a non-UTF-8 body — yields nothing plus a Declined entry:
// splicing into a container whose framing we do not model would produce a body
// the server rejects before the code under test ever sees the payload, and a
// check whose probe is rejected reports nothing while looking like it ran. The
// refusal is therefore recorded, not swallowed. XML and multipart used to be
// declined; both are modelled now (P0-2), so the checks that target `query or
// body` against them run instead of skipping.
func bodyPoints(e *core.RequestEdit, out *[]InsertionPoint, declined *[]Declined) {
	if len(e.Body) == 0 {
		return
	}
	if !utf8.Valid(e.Body) {
		*declined = append(*declined, Declined{
			What:   "request body",
			Reason: "non-UTF-8 body: cannot splice without corrupting it",
		})
		return
	}
	body := string(e.Body)
	ctype := strings.ToLower(e.Header("content-type"))
	trimmed := strings.TrimLeft(body, " \t\r\n")

	if isJSONBody(e) {
		for _, jv := range jsonStringValues(body) {
			*out = append(*out, InsertionPoint{
				Kind:      IpBody,
				Name:      jv.name,
				BaseValue: body[jv.value[0]:jv.value[1]],
				loc:       loc{kind: locBody, start: jv.value[0], end: jv.value[1]},
				coding:    codingJson,
			})
		}
		return
	}

	// XML before the form heuristic: an XML declaration carries `="` pairs and
	// a missing Content-Type body that starts with `<` is XML, not a form.
	if strings.Contains(ctype, "xml") || strings.HasPrefix(trimmed, "<") {
		for _, xv := range xmlPoints(body) {
			*out = append(*out, InsertionPoint{
				Kind:      IpBody,
				Name:      xv.name,
				BaseValue: body[xv.value[0]:xv.value[1]],
				loc:       loc{kind: locBody, start: xv.value[0], end: xv.value[1]},
				coding:    xv.coding,
			})
		}
		return
	}

	if strings.Contains(ctype, "multipart/form-data") {
		boundary := multipartBoundary(e.Header("content-type"))
		if boundary == "" {
			*declined = append(*declined, Declined{
				What:   "request body",
				Reason: "multipart body without a parseable boundary: framing unknowable",
			})
			return
		}
		for _, part := range multipartParts(body, boundary) {
			*out = append(*out, InsertionPoint{
				Kind:      IpBody,
				Name:      part.name,
				BaseValue: body[part.value[0]:part.value[1]],
				loc:       loc{kind: locBody, start: part.value[0], end: part.value[1]},
				coding:    codingRaw,
			})
			if part.hasFile && part.file[0] >= 0 {
				*out = append(*out, InsertionPoint{
					Kind:      IpBody,
					Name:      part.name + " filename",
					BaseValue: part.filename,
					// The filename lives inside the part's header block, not
					// the value region — spliced by its own range.
					loc:    loc{kind: locBody, start: part.file[0], end: part.file[1]},
					coding: codingRaw,
				})
			}
		}
		return
	}

	// A missing Content-Type on a `k=v&k=v` body is still a form as far as
	// every server is concerned; requiring the header would leave those bodies
	// untested.
	if isFormBody(e) {
		for _, kv := range kvPairs(body, '&') {
			*out = append(*out, InsertionPoint{
				Kind:      IpBody,
				Name:      body[kv.name[0]:kv.name[1]],
				BaseValue: body[kv.value[0]:kv.value[1]],
				loc:       loc{kind: locBody, start: kv.value[0], end: kv.value[1]},
				coding:    codingForm,
			})
		}
		return
	}

	*declined = append(*declined, Declined{
		What:   "request body",
		Reason: "body matches no modelled container (plain text): splicing would corrupt framing the server rejects before the code under test sees the payload",
	})
}

// Apply splices payload into this point of req, which must be the request the
// point was enumerated from. appending keeps the existing value and adds to it;
// otherwise it is overwritten. The new raw request is returned.
//
// Everything else in the request is untouched, which is what makes a resulting
// finding attributable to the point's name.
func (p *InsertionPoint) Apply(req []byte, payload string, appending bool) ([]byte, error) {
	e, err := core.ParseRequestEdit(req)
	if err != nil {
		return nil, err
	}

	var escaped string
	switch p.coding {
	case codingForm:
		escaped = percentEscape(payload)
	case codingJson:
		escaped = jsonEscape(payload)
	case codingXMLText:
		escaped = xmlEscape(payload, false)
	case codingXMLAttr:
		escaped = xmlEscape(payload, true)
	case codingPath:
		escaped = pathEscape(payload)
	default:
		escaped = payload
	}
	// The base value is already in wire form, so the escaped payload
	// concatenates onto it directly — no decode/re-encode round trip.
	newVal := escaped
	if appending {
		newVal = p.BaseValue + escaped
	}

	switch p.loc.kind {
	case locQuery:
		e.Query = spliceStr(e.Query, p.loc.start, p.loc.end, newVal)
	case locPath:
		e.Path = spliceStr(e.Path, p.loc.start, p.loc.end, newVal)
	case locHeader:
		if p.loc.index < len(e.Headers) {
			e.Headers[p.loc.index][1] = newVal
		}
	case locCookie:
		if p.loc.index < len(e.Headers) {
			h := &e.Headers[p.loc.index]
			h[1] = spliceStr(h[1], p.loc.start, p.loc.end, newVal)
		}
	case locBody:
		start := p.loc.start
		if start > len(e.Body) {
			start = len(e.Body)
		}
		end := p.loc.end
		if end > len(e.Body) {
			end = len(e.Body)
		}
		if end < start {
			end = start
		}
		b := make([]byte, 0, len(e.Body)+len(newVal))
		b = append(b, e.Body[:start]...)
		b = append(b, newVal...)
		b = append(b, e.Body[end:]...)
		e.Body = b
	}

	return e.ToRaw(), nil
}

// spliceStr replaces the byte range [start,end) of s with newVal, flooring
// either end to the nearest char boundary so a range that lands mid-codepoint
// splices at the nearest legal position instead of producing invalid UTF-8.
func spliceStr(s string, start, end int, newVal string) string {
	start = floorBoundary(s, start)
	end = floorBoundary(s, end)
	if end < start {
		end = start
	}
	var sb strings.Builder
	sb.Grow(len(s) + len(newVal))
	sb.WriteString(s[:start])
	sb.WriteString(newVal)
	sb.WriteString(s[end:])
	return sb.String()
}

// floorBoundary moves i down to the nearest UTF-8 character boundary.
//
// A byte is a char boundary when it is not a continuation byte (0x80..0xBF),
// so an index pointing at a continuation byte is inside a multi-byte sequence
// and is floored to the preceding boundary.
func floorBoundary(s string, i int) int {
	if i > len(s) {
		i = len(s)
	}
	for i > 0 && i < len(s) && s[i]&0xC0 == 0x80 {
		i--
	}
	return i
}

// kvPair holds the byte ranges of the name and value of one `k=v` clause.
type kvPair struct {
	name  [2]int
	value [2]int
}

// kvPairs returns the name and value ranges of each `k=v` clause in s, split on
// sep.
//
// A clause with no `=` is skipped. It has no value to append to, and turning
// `?debug` into `?debug=<payload>` invents a parameter the application was
// never sent — a different request, tested under the original's name.
func kvPairs(s string, sep byte) []kvPair {
	b := []byte(s)
	var out []kvPair
	start := 0
	i := 0
	for i <= len(b) {
		if i == len(b) || b[i] == sep {
			// Cookie clauses are `; `-separated, so leading space is part of
			// the delimiter.
			cs := start
			for cs < i && (b[cs] == ' ' || b[cs] == '\t') {
				cs++
			}
			eq := -1
			for k := cs; k < i; k++ {
				if b[k] == '=' {
					eq = k
					break
				}
			}
			if eq >= 0 && eq > cs {
				out = append(out, kvPair{
					name:  [2]int{cs, eq},
					value: [2]int{eq + 1, i},
				})
			}
			start = i + 1
		}
		i++
	}
	return out
}

// jsonValue is one JSON string value: the key that names it and its byte range.
type jsonValue struct {
	name  string
	value [2]int
}

// jsonString is one JSON string token: an object key or a value, the name that
// attributes it, and its byte range (the content inside the quotes).
type jsonString struct {
	name  string
	value [2]int
	isKey bool
}

// jsonStrings walks s once and returns every JSON **string** token, tagged
// key-or-value, with the byte range of each token's content.
//
// Only strings. Splicing into a number or a boolean (`{"n":1}` → `{"n":1'}`)
// yields JSON the server rejects at parse time, so the payload never reaches
// the code being tested and the check quietly finds nothing — the exact
// silent-negative this codebase refuses to ship.
//
// The scanner is deliberately structural rather than a full parser: it needs
// positions in the original text, which a value-tree parser throws away.
func jsonStrings(s string) []jsonString {
	type frame struct {
		object bool
		// label is the key this container was reached by, for naming values
		// nested inside it.
		label string
		key   string
		index int
		// In an object, whether the next string is a value rather than a key.
		expectValue bool
	}

	b := []byte(s)
	var stack []frame
	var out []jsonString
	i := 0

	for i < len(b) {
		switch b[i] {
		case '{', '[':
			label := ""
			if len(stack) > 0 {
				f := stack[len(stack)-1]
				if f.object {
					label = f.key
				} else {
					label = f.label + "[" + strconv.Itoa(f.index) + "]"
				}
			}
			stack = append(stack, frame{
				object:      b[i] == '{',
				label:       label,
				expectValue: b[i] == '[', // array elements are always values
			})
			i++
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i++
		case ':':
			if len(stack) > 0 {
				stack[len(stack)-1].expectValue = true
			}
			i++
		case ',':
			if len(stack) > 0 {
				f := &stack[len(stack)-1]
				if f.object {
					f.expectValue = false
				} else {
					f.index++
				}
			}
			i++
		case '"':
			start := i + 1
			j := start
		scan:
			for j < len(b) {
				switch b[j] {
				case '\\':
					j += 2
				case '"':
					break scan
				default:
					j++
				}
			}
			end := j
			if end > len(b) {
				end = len(b)
			}
			if len(stack) > 0 {
				f := &stack[len(stack)-1]
				if f.object && !f.expectValue {
					// An object key: its own name is itself.
					f.key = s[start:end]
					out = append(out, jsonString{
						name:  s[start:end],
						value: [2]int{start, end},
						isKey: true,
					})
				} else {
					name := ""
					if f.object {
						name = f.key
					} else {
						name = f.label + "[" + strconv.Itoa(f.index) + "]"
					}
					out = append(out, jsonString{name: name, value: [2]int{start, end}})
				}
			}
			// A bare top-level string is the whole body, not a parameter.
			i = end + 1
		default:
			i++
		}
	}
	return out
}

// jsonStringValues returns every JSON **string** value in s, with the key that
// names it.
func jsonStringValues(s string) []jsonValue {
	var out []jsonValue
	for _, js := range jsonStrings(s) {
		if !js.isKey {
			out = append(out, jsonValue{name: js.name, value: js.value})
		}
	}
	return out
}

// jsonStringKeys returns every JSON **object key** in s, with the key as its
// own name — the param-name family's view of a JSON body.
func jsonStringKeys(s string) []jsonValue {
	var out []jsonValue
	for _, js := range jsonStrings(s) {
		if js.isKey {
			out = append(out, jsonValue{name: js.name, value: js.value})
		}
	}
	return out
}

// percentEscape escapes the bytes that decide how a `k=v` container is read.
//
// `&`, `=` and `;` are the separators; `+` and `%` change how the value itself
// decodes, so leaving them raw would hand the application a payload other than
// the one the check wrote; `#` truncates a URL; and anything outside printable
// ASCII — space included — cannot appear in a request line at all. Everything
// else is passed through, so an injection payload arrives looking like itself.
func percentEscape(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '&' || c == '=' || c == '+' || c == ';' || c == '#' || c == '%' ||
			c <= 0x20 || c >= 0x7f {
			fmt.Fprintf(&sb, "%%%02X", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// jsonEscape escapes a payload for use inside a JSON string literal.
func jsonEscape(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	return sb.String()
}

// xmlEscape escapes a payload for an XML text node, and — when attr is set —
// for an attribute value, where the quotes that end the attribute must be
// escaped too. `&` is replaced first: it is the escape that makes the others
// parse as themselves.
func xmlEscape(s string, attr bool) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := range s {
		switch c := s[i]; c {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		case '"':
			if attr {
				sb.WriteString("&quot;")
			} else {
				sb.WriteByte(c)
			}
		case '\'':
			if attr {
				sb.WriteString("&apos;")
			} else {
				sb.WriteByte(c)
			}
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// pathEscape escapes the bytes that decide how a URL path segment is read:
// `/` and `?` split the route, `#` truncates the URL, `%` changes how the
// segment itself decodes, and the request line is printable ASCII. Everything
// else passes through, so an injection payload arrives looking like itself.
func pathEscape(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := range s {
		c := s[i]
		if c == '/' || c == '?' || c == '#' || c == '%' || c <= 0x20 || c >= 0x7f {
			fmt.Fprintf(&sb, "%%%02X", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// isJSONBody reports whether the request body is a JSON container: an explicit
// JSON Content-Type, or a body that starts with `{` or `[`.
func isJSONBody(e *core.RequestEdit) bool {
	body := string(e.Body)
	trimmed := strings.TrimLeft(body, " \t\r\n")
	ctype := strings.ToLower(e.Header("content-type"))
	return strings.Contains(ctype, "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

// isFormBody reports whether the request body is a `k=v&k=v` form: an explicit
// form Content-Type, or — the heuristic every server applies — a missing
// Content-Type on a body that contains `=`. Requiring the header would leave
// those bodies untested.
func isFormBody(e *core.RequestEdit) bool {
	body := string(e.Body)
	ctype := strings.ToLower(e.Header("content-type"))
	return strings.Contains(ctype, "x-www-form-urlencoded") ||
		(ctype == "" && strings.Contains(body, "="))
}

// xmlValue is one spliceable place in an XML body: element text content, a
// CDATA section, or an attribute value, named by element path.
type xmlValue struct {
	name   string
	value  [2]int
	coding coding
}

// isXMLNameByte reports whether b can appear in an XML name (ASCII slice: the
// corpus's XML is ASCII; anything else simply never starts a name here).
func isXMLNameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '_' || b == '-' || b == '.' || b == ':'
}

// allSpace reports whether s is entirely whitespace.
func allSpace(s string) bool {
	for i := range s {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		default:
			return false
		}
	}
	return true
}

// xmlPoints finds every element text node, CDATA section and attribute value
// in an XML body, named by element path (`config/user`, `config/user@id`).
//
// The walker is structural, like jsonStringValues: it needs byte positions in
// the original text, and splice positions are always inside quoted attribute
// values or between tags — safe regardless of how valid the XML is. Comments,
// DOCTYPE and processing-instruction regions are skipped entirely: they are
// inert to the code under test, so a probe placed there would find nothing
// with or without a vulnerability.
//
// CDATA content is a text point with raw coding: inside CDATA nothing is
// escaped, and escaping the payload would hand the application a different
// payload than the check wrote.
//
// Element text is escape-coded (codingXMLText); attribute values get the
// quote-aware variant (codingXMLAttr). Repeated paths — two `<item>` elements,
// or mixed content — are disambiguated with an ordinal suffix, like JSON array
// elements.
func xmlPoints(s string) []xmlValue {
	var out []xmlValue
	b := []byte(s)
	var path []string
	i := 0
	for i < len(b) {
		if b[i] != '<' {
			// Text node: everything up to the next '<'.
			var end int
			if j := strings.IndexByte(s[i:], '<'); j >= 0 {
				end = i + j
			} else {
				end = len(b)
			}
			if end > i && len(path) > 0 && !allSpace(s[i:end]) {
				out = append(out, xmlValue{
					name:   strings.Join(path, "/"),
					value:  [2]int{i, end},
					coding: codingXMLText,
				})
			}
			i = end
			continue
		}
		switch {
		case strings.HasPrefix(s[i:], "<!--"):
			if j := strings.Index(s[i+4:], "-->"); j >= 0 {
				i += 4 + j + 3
			} else {
				return out
			}
		case strings.HasPrefix(s[i:], "<![CDATA["):
			start := i + 9
			if j := strings.Index(s[start:], "]]>"); j >= 0 {
				end := start + j
				if end > start && len(path) > 0 {
					out = append(out, xmlValue{
						name:   strings.Join(path, "/"),
						value:  [2]int{start, end},
						coding: codingRaw,
					})
				}
				i = end + 3
			} else {
				return out
			}
		case strings.HasPrefix(s[i:], "<!"), strings.HasPrefix(s[i:], "<?"):
			// DOCTYPE or processing instruction: nothing spliceable inside.
			if j := strings.IndexByte(s[i:], '>'); j >= 0 {
				i += j + 1
			} else {
				return out
			}
		case i+1 < len(b) && b[i+1] == '/':
			// Closing tag: pop the element stack.
			if j := strings.IndexByte(s[i:], '>'); j >= 0 {
				if len(path) > 0 {
					path = path[:len(path)-1]
				}
				i += j + 1
			} else {
				return out
			}
		default:
			// Opening tag: the element name, then its attributes.
			start := i + 1
			k := start
			for k < len(b) && isXMLNameByte(b[k]) {
				k++
			}
			elem := s[start:k]
			selfClose := false
			for k < len(b) && b[k] != '>' {
				k0 := k
				for k < len(b) && (b[k] == ' ' || b[k] == '\t' || b[k] == '\r' || b[k] == '\n') {
					k++
				}
				if k+1 < len(b) && b[k] == '/' && b[k+1] == '>' {
					selfClose = true
					break
				}
				if k >= len(b) || b[k] == '>' {
					break
				}
				an := k
				for k < len(b) && isXMLNameByte(b[k]) {
					k++
				}
				attr := s[an:k]
				for k < len(b) && (b[k] == ' ' || b[k] == '\t' || b[k] == '\r' || b[k] == '\n') {
					k++
				}
				if k < len(b) && b[k] == '=' {
					k++
					for k < len(b) && (b[k] == ' ' || b[k] == '\t' || b[k] == '\r' || b[k] == '\n') {
						k++
					}
					var quote byte
					if k < len(b) && (b[k] == '"' || b[k] == '\'') {
						quote = b[k]
						k++
					}
					vs := k
					for k < len(b) {
						if quote != 0 {
							if b[k] == quote {
								break
							}
						} else if b[k] == '>' || b[k] == ' ' || b[k] == '\t' {
							break
						}
						k++
					}
					if quote != 0 && k < len(b) {
						k++
					}
					if k > vs && attr != "" && elem != "" {
						base := strings.Join(path, "/")
						if base != "" {
							base += "/"
						}
						out = append(out, xmlValue{
							name:   base + elem + "@" + attr,
							value:  [2]int{vs, k - 1},
							coding: codingXMLAttr,
						})
					}
				} else if k == k0 {
					// An unrecognised byte inside a tag (a stray `&`, say):
					// skip it rather than loop forever on the same position.
					k++
				}
			}
			if k < len(b) && b[k] == '>' {
				k++
			}
			if !selfClose && elem != "" {
				path = append(path, elem)
			}
			i = k
		}
	}

	// Repeated element paths get an ordinal suffix from the second occurrence
	// on, like JSON array elements. Mixed content yields two text nodes in one
	// element; both are real points and both need distinct names.
	counts := make(map[string]int, len(out))
	for _, v := range out {
		counts[v.name]++
	}
	seen := make(map[string]int, len(out))
	for i := range out {
		if counts[out[i].name] > 1 {
			n := seen[out[i].name]
			seen[out[i].name]++
			out[i].name = fmt.Sprintf("%s[%d]", out[i].name, n)
		}
	}
	return out
}

// mpPart is one multipart part: the disposition name, the uploaded filename
// (when the part is a file), the byte range of the filename inside the header
// block, and the byte range of the value.
type mpPart struct {
	name     string
	filename string
	hasFile  bool
	file     [2]int
	value    [2]int
}

// headerEnd returns the offset just past the blank line that ends a header
// block — after "\r\n\r\n" or "\n\n", whichever comes first — or -1.
func headerEnd(s string) int {
	if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
		return i + 4
	}
	if i := strings.Index(s, "\n\n"); i >= 0 {
		return i + 2
	}
	return -1
}

// parseDisposition pulls `name` and `filename` out of a part's
// Content-Disposition header block, tolerating quoted and bare values and
// bare-LF line endings.
func parseDisposition(s string) (name, filename string, hasFile bool) {
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(strings.TrimSuffix(l, "\r"))
		if !strings.HasPrefix(strings.ToLower(l), "content-disposition:") {
			continue
		}
		for _, param := range strings.Split(l[len("content-disposition:"):], ";") {
			eq := strings.IndexByte(param, '=')
			if eq < 0 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(param[:eq]))
			val := strings.TrimSpace(param[eq+1:])
			if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
				val = val[1 : len(val)-1]
			}
			switch key {
			case "name":
				name = val
			case "filename":
				filename = val
				hasFile = true
			}
		}
	}
	return name, filename, hasFile
}

// multipartBoundary extracts the boundary parameter of a Content-Type header,
// preserving case — boundaries are opaque, case-sensitive strings, so the
// detection may be case-insensitive while the value must not be re-cased.
func multipartBoundary(ctype string) string {
	for _, p := range strings.Split(ctype, ";") {
		p = strings.TrimSpace(p)
		if len(p) > len("boundary=") && strings.EqualFold(p[:len("boundary=")], "boundary=") {
			v := p[len("boundary="):]
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
				if q := strings.IndexByte(v[1:], v[0]); q >= 0 {
					v = v[1 : 1+q]
				} else {
					v = v[1:]
				}
			}
			return v
		}
	}
	return ""
}

// multipartParts walks a multipart/form-data body and returns its parts in
// wire order, each with the byte range of its value. Line endings may be bare
// LF, as the store parser tolerates.
//
// Value ranges are raw bytes (codingRaw): a multipart value is opaque octets
// and the only framing decider is the boundary string itself, which the splice
// cannot touch. A payload that corrupts framing is the probe being tested, not
// a mis-splice; Burp behaves the same way.
//
// A part whose disposition carries no name is skipped — it has no value an
// application reads by name. A delimiter with no following newline is treated
// as the body ending, as is the closing `--boundary--`.
func multipartParts(body, boundary string) []mpPart {
	var out []mpPart
	pos := strings.Index(body, "--"+boundary)
	for pos >= 0 {
		rest := body[pos+len("--"+boundary):]
		if strings.HasPrefix(rest, "--") {
			break // closing delimiter
		}
		var nl int
		if strings.HasPrefix(rest, "\r\n") {
			nl = 2
		} else if strings.HasPrefix(rest, "\n") {
			nl = 1
		} else {
			break // a delimiter not followed by a newline is not a boundary
		}
		hdrStart := pos + len("--"+boundary) + nl
		blank := headerEnd(body[hdrStart:])
		if blank < 0 {
			break // no header terminator: nothing after this is structured
		}
		valueStart := hdrStart + blank
		valueEnd := len(body)
		if next := strings.Index(body[valueStart:], "--"+boundary); next >= 0 {
			valueEnd = valueStart + next
			// The CRLF immediately before the delimiter belongs to the
			// delimiter line, not the value.
			for valueEnd > valueStart && (body[valueEnd-1] == '\r' || body[valueEnd-1] == '\n') {
				valueEnd--
			}
		}
		name, filename, hasFile := parseDisposition(body[hdrStart : hdrStart+blank])
		if name != "" {
			out = append(out, mpPart{
				name:     name,
				filename: filename,
				hasFile:  hasFile,
				file:     [2]int{-1, -1},
				value:    [2]int{valueStart, valueEnd},
			})
			if hasFile {
				// The filename sits inside the header block; locate its range
				// so Apply can splice it without touching the part value.
				if fr := filenameRange(body[hdrStart : hdrStart+blank]); fr[0] >= 0 {
					out[len(out)-1].file = [2]int{hdrStart + fr[0], hdrStart + fr[1]}
				}
			}
		}
		if next := strings.Index(body[valueStart:], "--"+boundary); next >= 0 {
			pos = valueStart + next
		} else {
			break
		}
	}
	return out
}

// filenameRange returns the byte range of the value following `filename=` in a
// header block, or {-1,-1} when there is none. The range covers the quoted
// value content: splicing inside the quotes keeps the header parseable.
func filenameRange(headers string) [2]int {
	low := strings.ToLower(headers)
	idx := strings.Index(low, "filename=")
	if idx < 0 {
		return [2]int{-1, -1}
	}
	start := idx + len("filename=")
	for start < len(headers) && (headers[start] == ' ' || headers[start] == '\t') {
		start++
	}
	if start < len(headers) && (headers[start] == '"' || headers[start] == '\'') {
		q := headers[start]
		start++
		if end := strings.IndexByte(headers[start:], q); end >= 0 {
			return [2]int{start, start + end}
		}
		return [2]int{start, len(headers)}
	}
	end := start
	for end < len(headers) && headers[end] != ';' && headers[end] != '\r' && headers[end] != '\n' {
		end++
	}
	return [2]int{start, end}
}

// pathSegments returns the byte ranges of each non-empty slash-free segment of
// path — which ParseRequestEdit guarantees starts with '/' — and the index of
// the final segment, the filename. A path of "/" has no segments (file = -1).
func pathSegments(path string) (segs [][2]int, file int) {
	b := []byte(path)
	start := 1 // skip the leading '/'
	for i := 1; i <= len(b); i++ {
		if i == len(b) || b[i] == '/' {
			if i > start {
				segs = append(segs, [2]int{start, i})
			}
			start = i + 1
		}
	}
	if len(segs) == 0 {
		return nil, -1
	}
	return segs, len(segs) - 1
}

// Relocations returns the sibling points holding the same parameter name in a
// different container — the same-named parameter of the query string, a form
// or JSON body, or the cookie header.
//
// Burp's scanner relocates payloads between containers (URL ↔ body ↔ cookie)
// to defeat per-parameter validation and WAFs; this is the position set such a
// pass would probe. It is deliberately **not** wired into BCheck dispatch: a
// `given query insertion point` check asked for the query, and putting its
// payload in the body or cookie would report findings at positions the check
// author never named. Consumers that want relocation — the native engine, an
// operator-driven audit — call this explicitly, one payload per relocated
// request, each still attributable to the parameter's name.
func (p InsertionPoint) Relocations(req []byte) []InsertionPoint {
	var out []InsertionPoint
	points, _ := Enumerate(req, []string{"query", "body", "cookie"})
	for _, q := range points {
		if q.Name == p.Name && q.loc.kind != p.loc.kind {
			out = append(out, q)
		}
	}
	return out
}
