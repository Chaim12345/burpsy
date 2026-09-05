package core

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Editable HTTP requests.
//
// The store keeps messages as immutable bytes plus spans, which is what makes
// capture cheap. But every attack tool — BCheck's `send request`, Intruder,
// Repeater, match-and-replace — needs to take a captured request apart, change
// one piece, and put it back together. That is this file.
//
// Three details decide whether the request you send is actually valid.
//
// Content-Length must be recomputed. A check that appends to the body and
// leaves a stale Content-Length either gets its body truncated by the server or
// hangs waiting for bytes that never come. Either way the check silently fails
// to test what it thinks it tests, so ToRaw always rewrites the length.
//
// Chunked bodies must be decoded on the way in. A proxied request can arrive
// with Transfer-Encoding: chunked, where the stored body bytes include the chunk
// framing. Emitting those bytes under a Content-Length would send the framing as
// literal content. So chunked bodies are decoded at parse time and re-emitted
// length-delimited.
//
// Proxied requests use absolute-form targets. `GET http://host/a HTTP/1.1` is
// what a client sends to a proxy; `GET /a HTTP/1.1` is what an origin expects.
// The authority is split off and kept separately so a rebuilt request is
// origin-form — correct for a scanner opening its own connection — while still
// being able to answer {base.request.url}.

// EditError is a fixed reason a request could not be taken apart. The values are
// comparable, so a caller can distinguish "no header terminator" from a
// malformed start line rather than matching on message text.
type EditError string

func (e EditError) Error() string { return string(e) }

const (
	// ErrNoHeaderTerminator means no CRLFCRLF, LFLF, or trailing LF was found.
	// This is deliberately stricter than the message parser's findHeaderEnd,
	// which treats a terminator-less buffer as all head and no body. That
	// leniency is right for recording whatever arrived on the wire; it is wrong
	// here, because a request that gets rebuilt from a head we merely guessed at
	// would be sent as an attack and its result believed.
	ErrNoHeaderTerminator EditError = "no header terminator"
	ErrNonUTF8Head        EditError = "non-UTF-8 request head"
	ErrEmptyRequest       EditError = "empty request"
	ErrNoMethod           EditError = "no method"
	ErrNoTarget           EditError = "no target"
)

// RequestEdit is a request taken apart for editing. Header order is preserved,
// because a check that reorders headers is a different request than the one that
// was captured.
type RequestEdit struct {
	Method string
	// Origin is the scheme and authority when the original target was
	// absolute-form ("http://host"). Empty means the target was origin-form.
	Origin string
	// Path never includes the query.
	Path string
	// Query is the query without the leading '?'. Empty means no query.
	Query   string
	Version string
	// Headers holds name/value pairs in wire order. Duplicates are kept: a
	// request with two Cookie headers is not the same request as one with a
	// single merged Cookie.
	Headers [][2]string
	Body    []byte
}

// isSchemeToken reports whether s is a URI scheme per RFC 3986: ALPHA *( ALPHA / DIGIT / "+" /
// "-" / "." ). Used to tell an absolute-form request target from an origin-form one whose query
// happens to contain a URL.
func isSchemeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// ParseRequestEdit takes a raw request apart. It tolerates bare LF line endings,
// as the store's parser does.
func ParseRequestEdit(raw []byte) (*RequestEdit, error) {
	headEnd, bodyStart, ok := strictHeaderEnd(raw)
	if !ok {
		return nil, ErrNoHeaderTerminator
	}
	if !utf8.Valid(raw[:headEnd]) {
		return nil, ErrNonUTF8Head
	}
	head := string(raw[:headEnd])

	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return nil, ErrEmptyRequest
	}
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}

	parts := strings.Fields(lines[0])
	if len(parts) < 1 {
		return nil, ErrNoMethod
	}
	if len(parts) < 2 {
		return nil, ErrNoTarget
	}
	e := &RequestEdit{Method: parts[0], Version: "HTTP/1.1"}
	if len(parts) >= 3 {
		e.Version = parts[2]
	}

	// Absolute-form: split scheme://authority from the path.
	//
	// Only when the target actually begins with a scheme. This used to search the whole target for
	// "://", so `GET /r?next=https://example.com/x` was read as absolute-form: Origin became
	// "/r?next=https://", Path became "/x", and the entire query string was discarded. Every probe
	// then went to the wrong path with no parameters, and because the query was gone rather than
	// refused, the insertion-point enumerator reported no points and no declines - a silent
	// omission on precisely the redirect, callback and webhook parameters worth testing.
	target := parts[1]
	rest := target
	if !strings.HasPrefix(target, "/") {
		if i := strings.Index(target, "://"); i >= 0 && isSchemeToken(target[:i]) {
			after := target[i+3:]
			if j := strings.IndexByte(after, '/'); j >= 0 {
				e.Origin = target[:i+3+j]
				rest = after[j:]
			} else {
				e.Origin = target
				rest = "/"
			}
		}
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		e.Path, e.Query = rest[:i], rest[i+1:]
	} else {
		e.Path = rest
	}

	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		if idx := strings.IndexByte(l, ':'); idx > 0 {
			e.Headers = append(e.Headers, [2]string{
				strings.TrimSpace(l[:idx]),
				strings.TrimSpace(l[idx+1:]),
			})
		}
	}

	rawBody := raw[bodyStart:]
	if e.isChunked() {
		e.Body = dechunk(rawBody)
	} else {
		e.Body = rawBody
	}
	return e, nil
}

func (e *RequestEdit) isChunked() bool {
	for _, h := range e.Headers {
		if strings.EqualFold(h[0], "transfer-encoding") &&
			strings.Contains(strings.ToLower(h[1]), "chunked") {
			return true
		}
	}
	return false
}

// Target is the request-line target in origin-form.
func (e *RequestEdit) Target() string {
	if e.Query == "" {
		return e.Path
	}
	return e.Path + "?" + e.Query
}

// URL is the full URL, for {base.request.url}.
func (e *RequestEdit) URL() string {
	host := e.Origin
	if host == "" {
		if h := e.Header("host"); h != "" {
			host = "http://" + h
		}
	}
	return host + e.Target()
}

// File is Java's URL.getFile(): path plus query. Corpus checks use it for
// extension tests.
func (e *RequestEdit) File() string { return e.Target() }

// Header returns the first value with this name (case-insensitive), or "".
func (e *RequestEdit) Header(name string) string {
	for _, h := range e.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// SetHeader replaces every header with this name, or appends if absent. Later
// duplicates are dropped so the replacement is unambiguous — leaving a second
// copy behind would mean the value that reaches the server depends on which one
// it happens to read.
func (e *RequestEdit) SetHeader(name, value string) {
	first := -1
	for i, h := range e.Headers {
		if strings.EqualFold(h[0], name) {
			first = i
			break
		}
	}
	if first < 0 {
		e.Headers = append(e.Headers, [2]string{name, value})
		return
	}
	e.Headers[first][1] = value
	kept := e.Headers[:0]
	seen := false
	for _, h := range e.Headers {
		if strings.EqualFold(h[0], name) {
			if seen {
				continue
			}
			seen = true
		}
		kept = append(kept, h)
	}
	e.Headers = kept
}

// AddHeader adds a header, keeping any existing ones of the same name.
func (e *RequestEdit) AddHeader(name, value string) {
	e.Headers = append(e.Headers, [2]string{name, value})
}

// AddQuery appends one `k=v` clause, choosing '?' or '&' by whether a query
// already exists.
func (e *RequestEdit) AddQuery(clause string) {
	clause = strings.TrimLeft(clause, "?&")
	if clause == "" {
		return
	}
	if e.Query == "" {
		e.Query = clause
		return
	}
	e.Query += "&" + clause
}

// ToRaw serialises to origin-form wire bytes with a correct Content-Length.
func (e *RequestEdit) ToRaw() []byte {
	var sb strings.Builder
	sb.Grow(256 + len(e.Body))
	sb.WriteString(e.Method)
	sb.WriteByte(' ')
	sb.WriteString(e.Target())
	sb.WriteByte(' ')
	sb.WriteString(e.Version)
	sb.WriteString("\r\n")

	for _, h := range e.Headers {
		// Length and framing are rewritten below; never echo the originals.
		if strings.EqualFold(h[0], "content-length") || strings.EqualFold(h[0], "transfer-encoding") {
			continue
		}
		sb.WriteString(h[0])
		sb.WriteString(": ")
		sb.WriteString(h[1])
		sb.WriteString("\r\n")
	}
	// A body always gets a length. An empty body gets one only for methods where
	// its absence would be ambiguous.
	if len(e.Body) > 0 || e.Method == "POST" || e.Method == "PUT" || e.Method == "PATCH" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(e.Body))
	}
	sb.WriteString("\r\n")
	sb.Write(e.Body)
	return []byte(sb.String())
}

// StrictHeaderEnd reports the end of the header block and the start of the body.
// Unlike the message parser's findHeaderEnd it refuses a buffer with no
// terminator at all rather than treating the whole thing as head; see
// ErrNoHeaderTerminator for why the difference is deliberate.
func StrictHeaderEnd(raw []byte) (headEnd, bodyStart int, ok bool) {
	return strictHeaderEnd(raw)
}

func strictHeaderEnd(raw []byte) (headEnd, bodyStart int, ok bool) {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\n' {
			continue
		}
		// CRLFCRLF
		if i+2 < len(raw) && raw[i+1] == '\r' && raw[i+2] == '\n' {
			return i, i + 3, true
		}
		// Bare LFLF
		if i+1 < len(raw) && raw[i+1] == '\n' {
			return i, i + 2, true
		}
		// Terminator at the very end of the buffer.
		if i+1 == len(raw) {
			return i, len(raw), true
		}
	}
	return 0, 0, false
}

// dechunk decodes a chunked body. A malformed stream yields whatever decoded
// cleanly, which is the same tolerance the message parser applies.
func dechunk(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for {
		nl := bytes.IndexByte(b, '\n')
		if nl < 0 {
			return out
		}
		line := strings.TrimSpace(string(b[:nl]))
		// Ignore any chunk extension after ';'.
		sizeHex := line
		if i := strings.IndexByte(line, ';'); i >= 0 {
			sizeHex = line[:i]
		}
		size, err := strconv.ParseUint(sizeHex, 16, 64)
		if err != nil {
			return out
		}
		b = b[nl+1:]
		if size == 0 {
			return out
		}
		if uint64(len(b)) < size {
			return append(out, b...)
		}
		out = append(out, b[:size]...)
		b = b[size:]
		// Skip the CRLF that follows the chunk data.
		for len(b) > 0 && (b[0] == '\r' || b[0] == '\n') {
			b = b[1:]
		}
	}
}
