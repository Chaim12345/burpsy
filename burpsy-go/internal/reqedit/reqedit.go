// Package reqedit applies structured edits to a raw HTTP/1.x request (burpsy-react-ui-vuxy).
//
// Burp's agent send_request takes a stored request plus an ordered list of edit operations —
// set_header, set_query_param, set_form_fields, raw_replace, … — so a model can tamper with a
// captured request without hand-authoring raw bytes. This is that, with burpsy's invariant held: the
// request is bytes, and an edit touches only the span it addresses.
//
//   - Nothing is parsed into a structure and re-serialised. Each op finds its span in the current bytes
//     and splices; every byte outside that span — header order and casing, duplicate headers, odd
//     whitespace, the line-ending style — comes through unchanged.
//   - The line ending a new header line uses is the one the request already uses (CRLF, or bare LF for
//     a hand-typed request), so an edit never mixes the two.
//   - Content-Length is rewritten only when a body op ran (set_body, set_form_fields, set_body_param,
//     delete_body_param, set_json_field), and only the header's value is touched. A raw op is raw:
//     it changes exactly what it names, framing included.
//   - A body op on a chunked request is refused rather than guessed at: the chunk framing would have
//     to be rebuilt, which is not "the addressed span". Delete Transfer-Encoding first, or use a raw op.
//   - Ops run in order, each on the previous one's output. An op that cannot apply — a header to delete
//     that is not there is fine, but a malformed op, a raw_replace whose text is absent, a JSON path
//     that does not exist under a non-object — is an error naming the op's index, and nothing is
//     returned: a half-applied edit list is a request nobody asked for.
package reqedit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Op is one edit. Which fields an op reads is listed per op in Ops.
type Op struct {
	Op     string            `json:"op" enum:"delete_body_param|delete_header|delete_query_param|delete_request_cookie|raw_insert_at|raw_replace|set_body|set_body_param|set_form_fields|set_header|set_json_field|set_method|set_path|set_query_param|set_query_string|set_request_cookie" desc:"the operation; set_* replace or add, delete_* remove, raw_* edit the raw bytes"`
	Name   string            `json:"name,omitempty" desc:"header, parameter or cookie name; the text to find for raw_replace; a dotted path (a.b.0.c) for set_json_field"`
	Value  *string           `json:"value,omitempty" desc:"the value to set; for set_json_field a JSON value text (\"x\", 1, true, {...}); for raw_insert_at the text to insert; for raw_replace the replacement"`
	Fields map[string]string `json:"fields,omitempty" desc:"set_form_fields: name to value"`
	Append bool              `json:"append,omitempty" desc:"set_form_fields: merge into the existing body params instead of replacing the body"`
	Offset *int              `json:"offset,omitempty" desc:"raw_insert_at: byte offset into the raw request, clamped to its length"`
}

// Ops is every operation, with the fields it requires.
var Ops = map[string]string{
	"set_method":            "value",
	"set_path":              "value (no '?'; the query string is left alone)",
	"set_query_string":      "value (raw, no leading '?'; \"\" clears it)",
	"set_query_param":       "name, value (inserted as written: URL-encode it yourself)",
	"delete_query_param":    "name",
	"set_header":            "name, value (replaces the first occurrence's value in place, or appends the header)",
	"delete_header":         "name (removes every occurrence)",
	"set_body_param":        "name, value (urlencoded body; inserted as written)",
	"delete_body_param":     "name",
	"set_request_cookie":    "name, value",
	"delete_request_cookie": "name",
	"set_body":              "value (the whole body, verbatim)",
	"set_form_fields":       "fields, append (sets Content-Type to application/x-www-form-urlencoded; values are URL-encoded)",
	"set_json_field":        "name (dotted path), value (JSON text): replaces that value's span, or inserts the key into its parent object",
	"raw_insert_at":         "offset, value",
	"raw_replace":           "name (literal text to find), value (replacement); every occurrence",
}

// OpNames is Ops' keys, sorted, for a schema enum.
func OpNames() []string {
	out := make([]string, 0, len(Ops))
	for k := range Ops {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Applied is what one op did, for the caller to show.
type Applied struct {
	Index  int    `json:"index"`
	Op     string `json:"op"`
	Effect string `json:"effect"`
}

// request is the working view of the bytes: where the head ends, which line ending it uses.
type request struct {
	raw []byte
	eol string
}

func (r *request) headEnd() (end int, sepLen int) {
	if i := bytes.Index(r.raw, []byte("\r\n\r\n")); i >= 0 {
		return i, 4
	}
	if i := bytes.Index(r.raw, []byte("\n\n")); i >= 0 {
		return i, 2
	}
	return len(r.raw), 0
}

func (r *request) body() []byte {
	end, sep := r.headEnd()
	if sep == 0 {
		return nil
	}
	return r.raw[end+sep:]
}

// lines returns the head's lines as [start,end) spans excluding their terminators.
func (r *request) lines() [][2]int {
	end, _ := r.headEnd()
	var out [][2]int
	start := 0
	for start <= end {
		i := bytes.IndexByte(r.raw[start:end], '\n')
		if i < 0 {
			out = append(out, [2]int{start, end})
			break
		}
		lineEnd := start + i
		contentEnd := lineEnd
		if contentEnd > start && r.raw[contentEnd-1] == '\r' {
			contentEnd--
		}
		out = append(out, [2]int{start, contentEnd})
		start = lineEnd + 1
	}
	return out
}

func (r *request) splice(start, end int, with []byte) {
	out := make([]byte, 0, len(r.raw)-(end-start)+len(with))
	out = append(out, r.raw[:start]...)
	out = append(out, with...)
	out = append(out, r.raw[end:]...)
	r.raw = out
}

// requestTarget returns the span of the request-target on the request line.
func (r *request) requestTarget() (int, int, error) {
	ls := r.lines()
	if len(ls) == 0 {
		return 0, 0, fmt.Errorf("the request has no request line")
	}
	line := r.raw[ls[0][0]:ls[0][1]]
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 < 0 {
		return 0, 0, fmt.Errorf("the request line %q has no request-target", line)
	}
	rest := line[sp1+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	if sp2 < 0 {
		sp2 = len(rest)
	}
	return ls[0][0] + sp1 + 1, ls[0][0] + sp1 + 1 + sp2, nil
}

// pathQuerySpans splits the request-target into the path span and the query span (after '?', may be
// empty with hasQuery false). An absolute-form target's path starts after its authority.
func (r *request) pathQuerySpans() (pathStart, pathEnd, qStart, qEnd int, hasQuery bool, err error) {
	ts, te, err := r.requestTarget()
	if err != nil {
		return
	}
	target := r.raw[ts:te]
	pathStart = ts
	for _, scheme := range []string{"http://", "https://"} {
		if len(target) >= len(scheme) && strings.EqualFold(string(target[:len(scheme)]), scheme) {
			rest := target[len(scheme):]
			slash := bytes.IndexAny(rest, "/?")
			if slash < 0 {
				pathStart = te
			} else {
				pathStart = ts + len(scheme) + slash
			}
		}
	}
	q := bytes.IndexByte(r.raw[pathStart:te], '?')
	if q < 0 {
		return pathStart, te, te, te, false, nil
	}
	return pathStart, pathStart + q, pathStart + q + 1, te, true, nil
}

// headerLines returns the indexes into lines() of headers named name (case-insensitive).
func (r *request) headerLines(name string) []int {
	var out []int
	for i, l := range r.lines() {
		if i == 0 {
			continue
		}
		line := r.raw[l[0]:l[1]]
		colon := bytes.IndexByte(line, ':')
		if colon > 0 && strings.EqualFold(strings.TrimSpace(string(line[:colon])), name) {
			out = append(out, i)
		}
	}
	return out
}

func (r *request) headerValue(name string) (string, bool) {
	idx := r.headerLines(name)
	if len(idx) == 0 {
		return "", false
	}
	l := r.lines()[idx[0]]
	line := r.raw[l[0]:l[1]]
	colon := bytes.IndexByte(line, ':')
	return strings.TrimSpace(string(line[colon+1:])), true
}

// setHeader replaces the first occurrence's value (keeping the name as written and a single space
// after the colon) or appends "Name: value" as the last header line.
func (r *request) setHeader(name, value string) string {
	idx := r.headerLines(name)
	if len(idx) > 0 {
		l := r.lines()[idx[0]]
		line := r.raw[l[0]:l[1]]
		colon := bytes.IndexByte(line, ':')
		vs := l[0] + colon + 1
		for vs < l[1] && (r.raw[vs] == ' ' || r.raw[vs] == '\t') {
			vs++
		}
		r.splice(vs, l[1], []byte(value))
		if len(idx) > 1 {
			return fmt.Sprintf("replaced the first %s header's value; %d later occurrence(s) left unchanged", name, len(idx)-1)
		}
		return "replaced the " + name + " header's value"
	}
	ls := r.lines()
	last := ls[len(ls)-1]
	r.splice(last[1], last[1], []byte(r.eol+name+": "+value))
	return "added a " + name + " header"
}

func (r *request) deleteHeader(name string) int {
	idx := r.headerLines(name)
	ls := r.lines()
	for i := len(idx) - 1; i >= 0; i-- {
		l := ls[idx[i]]
		// Remove the line together with the terminator that precedes it, so the line before keeps its own.
		start := l[0]
		prevEnd := start - 1
		if prevEnd >= 0 && r.raw[prevEnd] == '\n' {
			if prevEnd >= 1 && r.raw[prevEnd-1] == '\r' {
				prevEnd--
			}
			start = prevEnd
		}
		r.splice(start, l[1], nil)
	}
	return len(idx)
}

// params helpers over an & separated span. Names compare as written (case-sensitive), the way a
// server reads them.
func setParam(s, name, value string) (string, string) {
	parts := []string{}
	if s != "" {
		parts = strings.Split(s, "&")
	}
	for i, p := range parts {
		k, _, _ := strings.Cut(p, "=")
		if k == name {
			parts[i] = name + "=" + value
			return strings.Join(parts, "&"), "replaced " + name
		}
	}
	parts = append(parts, name+"="+value)
	return strings.Join(parts, "&"), "added " + name
}

func deleteParam(s, name string) (string, int) {
	if s == "" {
		return s, 0
	}
	parts := strings.Split(s, "&")
	kept := parts[:0]
	n := 0
	for _, p := range parts {
		k, _, _ := strings.Cut(p, "=")
		if k == name {
			n++
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, "&"), n
}

func (r *request) setBody(b []byte) {
	end, sep := r.headEnd()
	if sep == 0 {
		r.raw = append(append(r.raw[:end:end], []byte(r.eol+r.eol)...), b...)
		return
	}
	r.splice(end+sep, len(r.raw), b)
}

func (r *request) chunked() bool {
	v, ok := r.headerValue("Transfer-Encoding")
	return ok && strings.Contains(strings.ToLower(v), "chunked")
}

// Apply runs ops over raw in order and returns the edited bytes and what each op did.
func Apply(raw []byte, ops []Op) ([]byte, []Applied, error) {
	r := &request{raw: append([]byte(nil), raw...), eol: "\r\n"}
	if i := bytes.IndexByte(raw, '\n'); i >= 0 && (i == 0 || raw[i-1] != '\r') {
		r.eol = "\n"
	}
	applied := make([]Applied, 0, len(ops))
	bodyTouched := false
	for i, op := range ops {
		effect, body, err := r.apply(op)
		if err != nil {
			return nil, nil, fmt.Errorf("edit %d (%s): %w", i, op.Op, err)
		}
		bodyTouched = bodyTouched || body
		applied = append(applied, Applied{Index: i, Op: op.Op, Effect: effect})
	}
	if bodyTouched {
		n := strconv.Itoa(len(r.body()))
		if _, ok := r.headerValue("Content-Length"); ok || len(r.body()) > 0 {
			r.setHeader("Content-Length", n)
			applied = append(applied, Applied{Index: -1, Op: "content_length", Effect: "Content-Length set to " + n + " for the edited body"})
		}
	}
	return r.raw, applied, nil
}

func need(v *string, what string) (string, error) {
	if v == nil {
		return "", fmt.Errorf("%s is required", what)
	}
	return *v, nil
}

func (r *request) apply(op Op) (effect string, bodyOp bool, err error) {
	if _, known := Ops[op.Op]; !known {
		return "", false, fmt.Errorf("unknown op; the ops are %s", strings.Join(OpNames(), ", "))
	}
	needsName := map[string]bool{"set_query_param": true, "delete_query_param": true, "set_header": true, "delete_header": true,
		"set_body_param": true, "delete_body_param": true, "set_request_cookie": true, "delete_request_cookie": true,
		"set_json_field": true, "raw_replace": true}
	if needsName[op.Op] && op.Name == "" {
		return "", false, fmt.Errorf("name is required")
	}
	if strings.ContainsAny(op.Name, "\r\n") && op.Op != "raw_replace" {
		return "", false, fmt.Errorf("name must not contain a line break")
	}
	if op.Value != nil && strings.ContainsAny(*op.Value, "\r\n") {
		switch op.Op {
		case "set_body", "raw_insert_at", "raw_replace", "set_json_field", "set_body_param":
		default:
			// A line break in a header or request-line value is a header injection, which is a raw op's
			// job to do on purpose, not a structured op's to do by accident.
			return "", false, fmt.Errorf("value must not contain a line break; use raw_replace or raw_insert_at to write raw bytes")
		}
	}
	switch op.Op {
	case "set_method":
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		if v == "" || strings.ContainsAny(v, " \t") {
			return "", false, fmt.Errorf("a method is one token")
		}
		ls := r.lines()
		sp := bytes.IndexByte(r.raw[ls[0][0]:ls[0][1]], ' ')
		if sp < 0 {
			return "", false, fmt.Errorf("the request line has no method")
		}
		r.splice(ls[0][0], ls[0][0]+sp, []byte(v))
		return "method set to " + v, false, nil
	case "set_path":
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		if strings.Contains(v, "?") || strings.ContainsAny(v, " \t") {
			return "", false, fmt.Errorf("value must not contain '?' or whitespace; set the query with set_query_string")
		}
		ps, pe, _, _, _, err := r.pathQuerySpans()
		if err != nil {
			return "", false, err
		}
		r.splice(ps, pe, []byte(v))
		return "path set to " + v, false, nil
	case "set_query_string":
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		if strings.ContainsAny(v, " \t#") {
			return "", false, fmt.Errorf("a query string must not contain whitespace or '#'")
		}
		_, pe, qs, qe, has, err := r.pathQuerySpans()
		if err != nil {
			return "", false, err
		}
		switch {
		case v == "" && has:
			r.splice(pe, qe, nil)
			return "query string cleared", false, nil
		case v == "":
			return "query string already empty", false, nil
		case has:
			r.splice(qs, qe, []byte(v))
		default:
			r.splice(pe, pe, []byte("?"+v))
		}
		return "query string set", false, nil
	case "set_query_param", "delete_query_param":
		_, pe, qs, qe, has, err := r.pathQuerySpans()
		if err != nil {
			return "", false, err
		}
		q := ""
		if has {
			q = string(r.raw[qs:qe])
		}
		if op.Op == "delete_query_param" {
			nq, n := deleteParam(q, op.Name)
			if n == 0 {
				return "no query parameter " + op.Name + " to delete", false, nil
			}
			if nq == "" {
				r.splice(pe, qe, nil)
			} else {
				r.splice(qs, qe, []byte(nq))
			}
			return fmt.Sprintf("deleted %d %s query parameter(s)", n, op.Name), false, nil
		}
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		if strings.ContainsAny(v, " \t#&") {
			return "", false, fmt.Errorf("a query value must not contain whitespace, '#' or '&' unencoded")
		}
		nq, what := setParam(q, op.Name, v)
		if has {
			r.splice(qs, qe, []byte(nq))
		} else {
			r.splice(pe, pe, []byte("?"+nq))
		}
		return what + " in the query", false, nil
	case "set_header":
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		if strings.ContainsAny(op.Name, ": \t") {
			return "", false, fmt.Errorf("a header name must not contain ':' or whitespace")
		}
		return r.setHeader(op.Name, v), false, nil
	case "delete_header":
		n := r.deleteHeader(op.Name)
		return fmt.Sprintf("deleted %d %s header(s)", n, op.Name), false, nil
	case "set_body_param", "delete_body_param":
		if r.chunked() {
			return "", false, errChunked
		}
		b := string(r.body())
		if op.Op == "delete_body_param" {
			nb, n := deleteParam(b, op.Name)
			r.setBody([]byte(nb))
			return fmt.Sprintf("deleted %d %s body parameter(s)", n, op.Name), true, nil
		}
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		nb, what := setParam(b, op.Name, v)
		r.setBody([]byte(nb))
		return what + " in the body", true, nil
	case "set_request_cookie", "delete_request_cookie":
		if op.Op == "set_request_cookie" {
			if op.Value == nil {
				return "", false, fmt.Errorf("value is required")
			}
			if strings.ContainsAny(*op.Value, ";") {
				return "", false, fmt.Errorf("a cookie value must not contain ';'")
			}
		}
		cur, has := r.headerValue("Cookie")
		var pairs []string
		if has && cur != "" {
			pairs = strings.Split(cur, ";")
		}
		found := false
		kept := pairs[:0]
		for _, p := range pairs {
			k, _, _ := strings.Cut(strings.TrimSpace(p), "=")
			if k == op.Name {
				found = true
				if op.Op == "set_request_cookie" {
					kept = append(kept, " "+op.Name+"="+*op.Value)
				}
				continue
			}
			kept = append(kept, p)
		}
		if op.Op == "set_request_cookie" {
			if !found {
				kept = append(kept, " "+op.Name+"="+*op.Value)
			}
		} else if !found {
			return "no cookie " + op.Name + " to delete", false, nil
		}
		joined := strings.TrimSpace(strings.Join(kept, ";"))
		if joined == "" {
			r.deleteHeader("Cookie")
			return "deleted the last cookie and the Cookie header", false, nil
		}
		r.setHeader("Cookie", joined)
		if op.Op == "delete_request_cookie" {
			return "deleted cookie " + op.Name, false, nil
		}
		return "set cookie " + op.Name, false, nil
	case "set_body":
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		if r.chunked() {
			return "", false, errChunked
		}
		r.setBody([]byte(v))
		return fmt.Sprintf("body set (%d bytes)", len(v)), true, nil
	case "set_form_fields":
		if len(op.Fields) == 0 {
			return "", false, fmt.Errorf("fields is required")
		}
		if r.chunked() {
			return "", false, errChunked
		}
		names := make([]string, 0, len(op.Fields))
		for k := range op.Fields {
			names = append(names, k)
		}
		sort.Strings(names)
		b := ""
		if op.Append {
			b = string(r.body())
		}
		for _, k := range names {
			b, _ = setParam(b, url.QueryEscape(k), url.QueryEscape(op.Fields[k]))
		}
		r.setBody([]byte(b))
		r.setHeader("Content-Type", "application/x-www-form-urlencoded")
		return fmt.Sprintf("set %d form field(s)", len(names)), true, nil
	case "set_json_field":
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		if r.chunked() {
			return "", false, errChunked
		}
		nb, what, err := setJSONField(r.body(), op.Name, v)
		if err != nil {
			return "", false, err
		}
		r.setBody(nb)
		return what, true, nil
	case "raw_insert_at":
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		if op.Offset == nil {
			return "", false, fmt.Errorf("offset is required")
		}
		at := *op.Offset
		if at < 0 {
			at = 0
		}
		if at > len(r.raw) {
			at = len(r.raw)
		}
		r.splice(at, at, []byte(v))
		return fmt.Sprintf("inserted %d bytes at %d", len(v), at), false, nil
	case "raw_replace":
		v, err := need(op.Value, "value")
		if err != nil {
			return "", false, err
		}
		n := bytes.Count(r.raw, []byte(op.Name))
		if n == 0 {
			return "", false, fmt.Errorf("the text to replace is not in the request")
		}
		r.raw = bytes.ReplaceAll(r.raw, []byte(op.Name), []byte(v))
		return fmt.Sprintf("replaced %d occurrence(s)", n), false, nil
	}
	return "", false, fmt.Errorf("unhandled op")
}

var errChunked = fmt.Errorf("the body is chunked (Transfer-Encoding: chunked); a structured body edit would have to rebuild the chunk framing. delete_header Transfer-Encoding first, or use raw_replace")

// setJSONField replaces the value at a dotted path, or inserts the last key into its parent object.
// It finds spans with the JSON tokenizer, so only the value's own bytes (or the inserted member)
// change: formatting, key order and every other value are untouched.
func setJSONField(body []byte, path, value string) ([]byte, string, error) {
	if !json.Valid([]byte(value)) {
		return nil, "", fmt.Errorf("value %q is not a JSON value (quote a string: \"\\\"admin\\\"\")", value)
	}
	if !json.Valid(body) {
		return nil, "", fmt.Errorf("the body is not JSON")
	}
	segs := strings.Split(path, ".")
	start, end, ok := jsonSpan(body, segs)
	if ok {
		out := append(append(append([]byte{}, body[:start]...), value...), body[end:]...)
		return out, "replaced JSON " + path, nil
	}
	// Insert: the parent must exist and be an object.
	ps, pe, pok := 0, len(body), true
	if len(segs) > 1 {
		ps, pe, pok = jsonSpan(body, segs[:len(segs)-1])
	} else {
		ps, pe = trimSpan(body, 0, len(body))
	}
	if !pok || body[ps] != '{' {
		return nil, "", fmt.Errorf("JSON path %q does not exist, and its parent is not an object to add it to", path)
	}
	closing := pe - 1
	inner := bytes.TrimSpace(body[ps+1 : closing])
	key, _ := json.Marshal(segs[len(segs)-1])
	member := string(key) + ":" + value
	if len(inner) > 0 {
		member = "," + member
	}
	out := append(append(append([]byte{}, body[:closing]...), member...), body[closing:]...)
	return out, "added JSON " + path, nil
}

func trimSpan(b []byte, s, e int) (int, int) {
	for s < e && (b[s] == ' ' || b[s] == '\t' || b[s] == '\r' || b[s] == '\n') {
		s++
	}
	for e > s && (b[e-1] == ' ' || b[e-1] == '\t' || b[e-1] == '\r' || b[e-1] == '\n') {
		e--
	}
	return s, e
}

// jsonSpan finds the byte span of the value at path. Array elements are addressed by index.
func jsonSpan(body []byte, path []string) (int, int, bool) {
	s, e := trimSpan(body, 0, len(body))
	for _, seg := range path {
		ns, ne, ok := childSpan(body, s, e, seg)
		if !ok {
			return 0, 0, false
		}
		s, e = ns, ne
	}
	return s, e, true
}

// childSpan finds member seg (object key, or array index) of the value spanning [s,e).
func childSpan(body []byte, s, e int, seg string) (int, int, bool) {
	if s >= e || (body[s] != '{' && body[s] != '[') {
		return 0, 0, false
	}
	dec := json.NewDecoder(bytes.NewReader(body[s:e]))
	if _, err := dec.Token(); err != nil {
		return 0, 0, false
	}
	isObj := body[s] == '{'
	idx := 0
	want, _ := strconv.Atoi(seg)
	for dec.More() {
		if isObj {
			k, err := dec.Token()
			if err != nil {
				return 0, 0, false
			}
			key, _ := k.(string)
			var raw json.RawMessage
			before := dec.InputOffset()
			if err := dec.Decode(&raw); err != nil {
				return 0, 0, false
			}
			after := dec.InputOffset()
			if key == seg {
				vs, ve := trimSpan(body, s+int(before), s+int(after))
				// skip the ':' separator
				for vs < ve && (body[vs] == ':' || body[vs] == ' ' || body[vs] == '\t' || body[vs] == '\r' || body[vs] == '\n') {
					vs++
				}
				return vs, ve, true
			}
		} else {
			var raw json.RawMessage
			before := dec.InputOffset()
			if err := dec.Decode(&raw); err != nil {
				return 0, 0, false
			}
			after := dec.InputOffset()
			if idx == want && strconv.Itoa(want) == seg {
				vs, ve := trimSpan(body, s+int(before), s+int(after))
				for vs < ve && (body[vs] == ',' || body[vs] == ' ' || body[vs] == '\t' || body[vs] == '\r' || body[vs] == '\n') {
					vs++
				}
				return vs, ve, true
			}
			idx++
		}
	}
	return 0, 0, false
}
