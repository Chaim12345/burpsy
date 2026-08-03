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
// # Which families exist, and why only four
//
// BCheck's `given … insertion point` grammar can name exactly four of them —
// `query`, `body`, `cookie`, `header`. Parameter *names*, the entire body, and
// URL path segments are attackable by Burp's scanner but unaddressable from the
// DSL, so enumerating them here would send probes at positions no check asked
// for and no `given` line can constrain.
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
	"strings"
	"unicode/utf8"
)

// IpKind is an insertion-point family the DSL can name. `any` is a selector in
// the `given` line, not a location, so it never appears on an InsertionPoint.
type IpKind string

const (
	IpQuery  IpKind = "query"
	IpBody   IpKind = "body"
	IpCookie IpKind = "cookie"
	IpHeader IpKind = "header"
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
)

// loc is a byte range within one component of the base request: the query
// string, the value of header `index`, a range within that value, or the body.
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
	// codingRaw is a header value: no container to break, so the payload goes
	// out verbatim.
	codingRaw coding = iota
	// codingForm is a `k=v` pair in a query string, a cookie header or a form
	// body.
	codingForm
	// codingJson is inside a JSON string literal.
	codingJson
)

// Declined is a place the enumerator refused to build insertion points for, and
// why.
//
// The body case is the one that matters: splicing a payload into a container
// whose framing is not modelled (multipart, XML, a non-UTF-8 body) produces a
// request the server rejects before the code under test ever sees it. Returning
// nothing in that case made the refusal indistinguishable from "this request
// genuinely has nowhere to inject" — so a `given body insertion point` check
// against a multipart form reported a clean bill of health while testing
// nothing. That is the silent false negative this type exists to prevent: a
// declined body is surfaced as skipped, never as tested.
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
// order: query, headers, cookies, body — plus the places that were *declined*
// rather than enumerated.
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
	e, err := parseRequest(req)
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

	var out []InsertionPoint
	var declined []Declined

	if want(IpQuery) {
		for _, kv := range kvPairs(e.query, '&') {
			out = append(out, InsertionPoint{
				Kind:      IpQuery,
				Name:      e.query[kv.name[0]:kv.name[1]],
				BaseValue: e.query[kv.value[0]:kv.value[1]],
				loc:       loc{kind: locQuery, start: kv.value[0], end: kv.value[1]},
				coding:    codingForm,
			})
		}
	}

	if want(IpHeader) {
		for i, h := range e.headers {
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
		for i, h := range e.headers {
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
// Multipart, XML and plain-text bodies yield nothing. Splicing into a container
// whose framing we do not model would produce a body the server rejects before
// the code under test ever sees the payload, and a check whose probe is
// rejected reports nothing while looking like it ran. The refusal is therefore
// recorded, not swallowed.
func bodyPoints(e *requestEdit, out *[]InsertionPoint, declined *[]Declined) {
	if len(e.body) == 0 {
		return
	}
	if !utf8.Valid(e.body) {
		*declined = append(*declined, Declined{
			What:   "request body",
			Reason: "non-UTF-8 body: cannot splice without corrupting it",
		})
		return
	}
	body := string(e.body)
	ctype := strings.ToLower(e.header("content-type"))
	trimmed := strings.TrimLeft(body, " \t\r\n")

	if strings.Contains(ctype, "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
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

	// A missing Content-Type on a `k=v&k=v` body is still a form as far as
	// every server is concerned; requiring the header would leave those bodies
	// untested.
	isForm := strings.Contains(ctype, "x-www-form-urlencoded") ||
		(ctype == "" && strings.Contains(body, "="))
	if isForm {
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
		Reason: "body matches no modelled container (multipart, XML or plain text): splicing would corrupt framing the server rejects before the code under test sees the payload",
	})
}

// Apply splices payload into this point of req, which must be the request the
// point was enumerated from. appending keeps the existing value and adds to it;
// otherwise it is overwritten. The new raw request is returned.
//
// Everything else in the request is untouched, which is what makes a resulting
// finding attributable to the point's name.
func (p *InsertionPoint) Apply(req []byte, payload string, appending bool) ([]byte, error) {
	e, err := parseRequest(req)
	if err != nil {
		return nil, err
	}

	var escaped string
	switch p.coding {
	case codingForm:
		escaped = percentEscape(payload)
	case codingJson:
		escaped = jsonEscape(payload)
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
		e.query = spliceStr(e.query, p.loc.start, p.loc.end, newVal)
	case locHeader:
		if p.loc.index < len(e.headers) {
			e.headers[p.loc.index][1] = newVal
		}
	case locCookie:
		if p.loc.index < len(e.headers) {
			h := &e.headers[p.loc.index]
			h[1] = spliceStr(h[1], p.loc.start, p.loc.end, newVal)
		}
	case locBody:
		start := p.loc.start
		if start > len(e.body) {
			start = len(e.body)
		}
		end := p.loc.end
		if end > len(e.body) {
			end = len(e.body)
		}
		if end < start {
			end = start
		}
		b := make([]byte, 0, len(e.body)+len(newVal))
		b = append(b, e.body[:start]...)
		b = append(b, newVal...)
		b = append(b, e.body[end:]...)
		e.body = b
	}

	return e.toRaw(), nil
}

// requestEdit is the parsed view of a request that insertion points address.
// Splices mutate the components; toRaw rebuilds wire bytes with a correct
// Content-Length.
type requestEdit struct {
	method  string
	path    string
	query   string
	version string
	headers [][2]string
	body    []byte
}

// parseRequest splits raw request bytes into its components. It tolerates bare
// LF line endings, as the store's parser does.
func parseRequest(raw []byte) (*requestEdit, error) {
	s := string(raw)
	headEnd := strings.Index(s, "\r\n\r\n")
	sep := "\r\n"
	if headEnd < 0 {
		headEnd = strings.Index(s, "\n\n")
		sep = "\n"
	}
	if headEnd < 0 {
		headEnd = len(s)
	}
	head := s[:headEnd]
	// headEnd points at the start of the blank-line separator, which is the
	// whole "\r\n\r\n" (4 bytes) or "\n\n" (2 bytes). Skipping only one
	// "\r\n" leaves the second half of the blank line glued onto the body,
	// so `{base.request.body}` came back with a leading "\r\n".
	sepLen := 4
	if sep == "\n" {
		sepLen = 2
	}
	var body []byte
	if headEnd+sepLen <= len(s) {
		body = raw[headEnd+sepLen:]
	}

	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request")
	}
	parts := strings.Fields(strings.TrimSuffix(lines[0], "\r"))
	if len(parts) < 2 {
		return nil, fmt.Errorf("request line needs a method and a target")
	}
	e := &requestEdit{
		method:  parts[0],
		version: "HTTP/1.1",
		body:    body,
	}
	if len(parts) >= 3 {
		e.version = parts[2]
	}
	e.path = parts[1]
	if i := strings.IndexByte(e.path, '?'); i >= 0 {
		e.query = e.path[i+1:]
		e.path = e.path[:i]
	}

	for _, l := range lines[1:] {
		l = strings.TrimSuffix(l, "\r")
		if l == "" {
			continue
		}
		if idx := strings.IndexByte(l, ':'); idx > 0 {
			e.headers = append(e.headers, [2]string{
				strings.TrimSpace(l[:idx]),
				strings.TrimSpace(l[idx+1:]),
			})
		}
	}
	return e, nil
}

// header returns the first header value with the given name (case-insensitive),
// or "".
func (r *requestEdit) header(name string) string {
	for _, h := range r.headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// toRaw serialises the request to origin-form wire bytes with a correct
// Content-Length. Length and framing headers are rewritten, never echoed.
func (r *requestEdit) toRaw() []byte {
	var sb strings.Builder
	sb.Grow(256 + len(r.body))
	target := r.path
	if r.query != "" {
		target += "?" + r.query
	}
	sb.WriteString(r.method)
	sb.WriteByte(' ')
	sb.WriteString(target)
	sb.WriteByte(' ')
	sb.WriteString(r.version)
	sb.WriteString("\r\n")

	for _, h := range r.headers {
		switch strings.ToLower(h[0]) {
		case "content-length", "transfer-encoding":
			continue
		}
		sb.WriteString(h[0])
		sb.WriteString(": ")
		sb.WriteString(h[1])
		sb.WriteString("\r\n")
	}
	// A body always gets a length. An empty body gets one only for methods
	// where its absence would be ambiguous.
	if len(r.body) > 0 || r.method == "POST" || r.method == "PUT" || r.method == "PATCH" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(r.body))
	}
	sb.WriteString("\r\n")
	sb.Write(r.body)
	return []byte(sb.String())
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

// jsonStringValues returns every JSON **string** value in s, with the key that
// names it.
//
// Only strings. Splicing into a number or a boolean (`{"n":1}` → `{"n":1'}`)
// yields JSON the server rejects at parse time, so the payload never reaches
// the code being tested and the check quietly finds nothing — the exact
// silent-negative this codebase refuses to ship.
//
// The scanner is deliberately structural rather than a full parser: it needs
// positions in the original text, which a value-tree parser throws away.
func jsonStringValues(s string) []jsonValue {
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
	var out []jsonValue
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
					label = fmt.Sprintf("%s[%d]", f.label, f.index)
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
					f.key = s[start:end]
				} else {
					name := ""
					if f.object {
						name = f.key
					} else {
						name = fmt.Sprintf("%s[%d]", f.label, f.index)
					}
					out = append(out, jsonValue{name: name, value: [2]int{start, end}})
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
