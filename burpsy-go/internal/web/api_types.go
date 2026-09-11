package web

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
)

// ExchangeView is the wire shape every exchange-facing endpoint serves. It mirrors the
// `Exchange` interface in the UI's types.ts: ids into the message store rather than payloads,
// `null` (never `0`) for an absent response or status, and a protocol token the UI switches on.
//
// # duration_ms is deliberately unchanged, and what that costs
//
// core.Exchange stopped holding a millisecond count (see core.ExchangeDuration) and this field did not
// change with it: it is still a number, derived from the finer internal representation, so every existing
// consumer reads exactly what it read before and no UI change is needed.
//
// The cost is real and is stated rather than left to be discovered. duration_ms cannot express the
// distinction the internal type exists for — a measured sub-millisecond exchange and an exchange nobody
// timed both render as 0 — so a row showing "0 ms" means "under a millisecond, or never measured". The
// distinction is available everywhere else: in the store, in the database (exchanges.duration_us, NULL
// when unmeasured), and to any Go caller through core.Exchange.Duration.Measured.
//
// Closing it on the wire is one additive field: `DurationUs *uint64` with `json:"duration_us"`, nil when
// unmeasured, plus `duration_us: number | null` on the UI's Exchange interface and a render that shows
// "<1 ms" for a measured zero and an em dash for null. Deliberately not done here — internal/web/ui/ is
// owned elsewhere, and a JSON field no consumer reads is a shape change bought for nothing.
type ExchangeView struct {
	ID          core.ExchangeID `json:"id"`
	Request     uint64          `json:"request"`
	Response    *uint64         `json:"response"`
	Host        string          `json:"host"`
	Port        uint16          `json:"port"`
	TLS         bool            `json:"tls"`
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Status      *uint16         `json:"status"`
	ResponseLen int             `json:"response_len"`
	// Mime is the response's media type, parameters stripped and lowercased ("text/html"), or "" when
	// the response declared none — or when there is no response, which `response: null` is what
	// distinguishes. The UI's History MIME column and type filter are the consumers, and they had both
	// been shipping against this field before it existed on the wire at all.
	//
	// Carried on the index row rather than resolved per row, and that is not an optimisation detail:
	// exchangeView is handed only a *core.Exchange and has no store access precisely so that listing
	// 100k exchanges cannot start reading response bodies. See core.Exchange.Mime.
	Mime       string  `json:"mime"`
	StartedMs  uint64  `json:"started_ms"`
	DurationMs uint64  `json:"duration_ms"`
	Notes      *string `json:"notes"`
	// Highlight is the operator's colour tag, "" when unset. See core.ValidHighlights for the
	// vocabulary; PATCH /api/exchange/{id} is the only writer.
	Highlight string `json:"highlight"`
	Related   []any  `json:"related"`
	Protocol  string `json:"protocol"`
	// TaskID is the run that produced this exchange, omitted for traffic no task owns.
	TaskID uint64 `json:"task_id,omitempty"`
	// ParentID is the exchange this one was derived from — a Repeater resend's original, an Intruder
	// payload's base request. Omitted when there is no antecedent.
	ParentID *core.ExchangeID `json:"parent_id,omitempty"`
	// Cookies names the cookies the response set, in first-seen order. Empty when none were
	// set; `response: null` is what separates that from "no response yet". See core.Exchange.
	Cookies []string `json:"cookies"`
	// Title is the response's HTML <title> text, "" when it has none. See core.Exchange.
	Title string `json:"title"`
}

// MessageView is the wire shape for a stored message: id, byte length, and a lossy UTF-8 text
// rendering. The UI's comparer and history viewer slice by byte offsets into this text, so `len`
// is the raw byte count, not the string rune count.
type MessageView struct {
	ID   uint64 `json:"id"`
	Len  int    `json:"len"`
	Text string `json:"text"`
	// ContentEncoding is the message's own Content-Encoding, empty when it has none. Carried so the
	// viewer knows why `text` is unreadable without having to re-parse the head it was just handed.
	ContentEncoding string `json:"content_encoding,omitempty"`
	// Decoded is the body with its Content-Encoding undone, and the head as it was, for a message
	// this build can decompress. Nil when there was nothing to decode or when the decode failed —
	// DecodeError says which.
	//
	// A separate field rather than a substitution in Text, and that is the whole design: burpsy's
	// stated invariant is that captured bytes are the bytes on the wire, so `text` stays the exact
	// capture. A viewer that replaced it would make history disagree with a packet capture for a
	// reason the operator could not see. This is the readable rendering beside the record, not
	// instead of it.
	Decoded *string `json:"decoded,omitempty"`
	// DecodeError names why a compressed message could not be decoded: an encoding this build has no
	// decoder for (br, zstd), a corrupt stream, or a body over the cap. Present rather than silent,
	// because "burpsy cannot read this" and "there was nothing to read" are the two states an
	// unreadable pane must never merge.
	DecodeError string `json:"decode_error,omitempty"`
	// Body64 is the body after the head, base64-encoded — the exact octets, which `text` cannot
	// carry for a non-UTF-8 body (JSON strings are UTF-8, so an invalid byte arrives as U+FFFD and
	// the bytes are gone). Populated only when the body exists and is not valid UTF-8: for text
	// bodies `text` already is the body, and encoding every body would triple the size of the
	// common response for no reader. First consumer is the Render view's image data URL
	// (burpsy-react-ui-n7n); a QR code that differs by one pixel from what the server sent is a
	// different QR code.
	Body64 string `json:"body_base64,omitempty"`
}

// StatsView mirrors the UI's Stats interface.
type StatsView struct {
	Exchanges       int    `json:"exchanges"`
	Messages        int    `json:"messages"`
	StoredBytes     int64  `json:"stored_bytes"`
	ProxyBind       string `json:"proxy_bind"`
	WebBind         string `json:"web_bind"`
	TLSInterception bool   `json:"tls_interception"`
	// DOMEngine is the -dom value as the operator wrote it ("chrome", a browser path, a ws://
	// endpoint), or "off". DOMChecks is whether the audit engine can actually dispatch the DOM
	// families. Two fields because they can disagree — an engine named for a process whose
	// scanner is absent is a capability nobody has — and because a console that reports neither
	// lets a scan of a JavaScript application look complete when no script ever ran.
	DOMEngine string `json:"dom_engine"`
	DOMChecks bool   `json:"dom_checks"`
}

// FindingView is the legacy /api/findings wire shape.
type FindingView struct {
	ID          uint64 `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Description string `json:"description"`
	// Param is the parameter this finding was observed at, empty for resource findings.
	Param string `json:"param,omitempty"`
}

func protocolToken(p core.Protocol) string {
	if p == core.ProtocolHTTP2 {
		return "Http2"
	}
	return "Http1"
}

func exchangeView(ex *core.Exchange) *ExchangeView {
	var resp *uint64
	if ex.Response != nil {
		id := uint64(*ex.Response)
		resp = &id
	}
	return &ExchangeView{
		ID:          ex.ID,
		Request:     uint64(ex.Request),
		Response:    resp,
		Host:        ex.Host,
		Port:        ex.Port,
		TLS:         ex.TLS,
		Method:      ex.Method,
		Path:        ex.Path,
		Status:      ex.Status,
		ResponseLen: ex.ResponseLen,
		Mime:        ex.Mime,
		StartedMs:   ex.StartedMs,
		// Millis, not the raw microseconds: this field's JSON shape predates core.ExchangeDuration and
		// stays exactly as it was. See the note under ExchangeView for what that cannot express.
		DurationMs: ex.Duration.Millis(),
		Notes:      ex.Notes,
		Highlight:  ex.Highlight,
		Related:    []any{},
		Protocol:   protocolToken(ex.Protocol),
		TaskID:     ex.TaskID,
		ParentID:   ex.ParentID,
		Cookies:    ex.Cookies,
		Title:      ex.Title,
	}
}

// messageView projects one stored message, with a decoded rendering beside the raw bytes when the
// message is compressed.
//
// This is the "unreadable in history" half of the gzip/deflate gap. A gzipped response rendered as
// `text` is a screenful of binary, and burpsy had no decompressor on any HTTP path at all — the only
// inflate in the tree was WebSocket-only. The raw bytes stay exactly as captured; see
// MessageView.Decoded for why the decode is added alongside rather than swapped in.
func messageView(msg *core.StoredMessage) *MessageView {
	raw := msg.Raw()
	view := &MessageView{
		ID:   uint64(msg.ID),
		Len:  msg.Len(),
		Text: string(raw),
	}
	head, body := splitHeadBody(raw)
	if len(body) == 0 {
		// No terminator, or a head with nothing after it. There is no body to decode, and a truncated
		// head's Content-Encoding describes bytes that are not here.
		return view
	}

	// plain tracks the body through each layer of wire framing as it comes off, and Body64 is always
	// taken from wherever plain ends up (see the deferred assignment below) — never from `body` as
	// captured. That used to be the bug (burpsy-react-ui-r0go): Body64 was populated from the still-
	// chunked, still-compressed bytes before either transform ran, so a chunked or gzipped image handed
	// the render tab's <img> decoder chunk-size digits or a gzip header instead of pixels. `text` keeps
	// carrying the untouched wire bytes throughout, per the invariant on MessageView.Decoded.
	plain := body
	defer func() {
		if !isUTF8(plain) {
			// text cannot carry these bytes (JSON/UTF-8 mangles them), so the exact octets ride along
			// base64-encoded for the views that need the real thing. Deferred so every return path below
			// — decode success, decode failure, unsupported encoding, bad chunk framing — encodes
			// whatever unwrapping was actually achieved rather than skipping this on the early returns.
			view.Body64 = base64.StdEncoding.EncodeToString(plain)
		}
	}()

	// compressed is read once so the chunk-framing step below can tell "nothing to decode" apart from
	// "the decode failed" — DecodeError's own doc promises it names why a *compressed* message could
	// not be decoded, and a plain chunked capture with bad framing has nothing compressed to blame.
	encoding := firstHeaderValue(head, "Content-Encoding")
	compressed := encoding != "" && !strings.EqualFold(encoding, "identity")
	if compressed {
		view.ContentEncoding = encoding
		if !httputil.Unpackable(encoding) {
			view.DecodeError = "no decoder for Content-Encoding " + strconv.Quote(encoding) +
				" in this build; gzip and deflate are supported"
			return view
		}
	}

	// Chunk framing wraps whatever is beneath it (compressed or not), so it has to come off before
	// decompression is even attempted — feeding `size CRLF data` to gzip decodes the size prefix as
	// payload. Unconditional on Content-Encoding being present, unlike the decode step below: a plain
	// chunked image needs unwrapping for Body64 exactly as much as a compressed one, which is what this
	// fix (burpsy-react-ui-r0go) added — the old code dechunked only when there was also a supported
	// Content-Encoding to decode, so a chunked-only body's Body64 stayed framed.
	if strings.EqualFold(firstHeaderValue(head, "Transfer-Encoding"), "chunked") {
		unchunked, dok := dechunkForView(plain)
		if !dok {
			if compressed {
				view.DecodeError = "the chunk framing did not parse, so the compressed body could not be located"
			}
			return view
		}
		plain = unchunked
	}

	if !compressed {
		return view
	}
	decoded, err := httputil.DecodeBody(encoding, plain)
	if err != nil {
		view.DecodeError = err.Error()
		return view
	}
	plain = decoded
	decodedText := string(head) + "\r\n\r\n" + string(plain)
	view.Decoded = &decodedText
	return view
}

// firstHeaderValue reads one header out of a head block, first occurrence winning, skipping the
// status or request line.
func firstHeaderValue(head []byte, name string) string {
	normalised := bytes.ReplaceAll(head, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalised, []byte("\n"))
	prefix := strings.ToLower(name) + ":"
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(string(line)), prefix) {
			return strings.TrimSpace(string(line[len(prefix):]))
		}
	}
	return ""
}

// dechunkForView collapses chunk framing to the data it frames, reporting false for framing it cannot
// parse rather than guessing where the body is.
//
// A second implementation of proxy.dechunk, because that one is unexported in a package this one must
// not depend on — internal/proxy imports the capture pipeline, and a view helper reaching into it
// would invert the dependency. Kept minimal and refusing on anything unexpected: a view that showed a
// mis-dechunked body would be a rendering nobody can check against the wire.
func dechunkForView(body []byte) ([]byte, bool) {
	var out bytes.Buffer
	rest := body
	for {
		eol := bytes.Index(rest, []byte("\r\n"))
		if eol < 0 {
			return nil, false
		}
		sizeField := string(rest[:eol])
		// A chunk extension follows a semicolon and is not part of the size.
		if i := strings.IndexByte(sizeField, ';'); i >= 0 {
			sizeField = sizeField[:i]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeField), 16, 64)
		if err != nil || size < 0 {
			return nil, false
		}
		rest = rest[eol+2:]
		if size == 0 {
			// Last chunk. Trailers and the final CRLF are not part of the body.
			return out.Bytes(), true
		}
		if int64(len(rest)) < size+2 {
			return nil, false
		}
		out.Write(rest[:size])
		rest = rest[size+2:]
	}
}

func (s *Server) message(id uint64) (*core.StoredMessage, error) {
	return s.store.Get(core.MsgId(id))
}

// targetParts splits a UI "target" of the form http://host:port, https://host, or host:port into
// host, port, and whether TLS should be used. Port defaults per scheme.
func targetParts(target string) (host string, port uint16, tls bool, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, false, fmt.Errorf("empty target")
	}
	scheme := ""
	if i := strings.Index(target, "://"); i >= 0 {
		scheme = target[:i]
		target = target[i+3:]
	}
	switch strings.ToLower(scheme) {
	case "https":
		tls = true
	case "http", "":
		tls = false
	default:
		return "", 0, false, fmt.Errorf("unknown scheme %q", scheme)
	}

	// Strip any path/query that got pasted in; the tools send raw requests, not URLs.
	if i := strings.IndexAny(target, "/?"); i >= 0 {
		target = target[:i]
	}

	h, p, err := net.SplitHostPort(target)
	if err != nil {
		// Bare host: no port. Keep it as-is; SplitHostPort is only happy with "host:port".
		if strings.Count(target, ":") == 0 {
			h = target
			p = "0"
		} else {
			return "", 0, false, fmt.Errorf("malformed target %q: %w", target, err)
		}
	}
	if p == "0" || p == "" {
		if tls {
			p = "443"
		} else {
			p = "80"
		}
	}
	portInt, err := strconv.Atoi(p)
	if err != nil || portInt < 1 || portInt > 65535 {
		return "", 0, false, fmt.Errorf("invalid port %q", p)
	}
	return h, uint16(portInt), tls, nil
}

// parseRequestTarget extracts scheme/host/port/tls from a target string the way every tool handler
// needs it, returning a ready-to-dial authority.
func parseRequestTarget(target string) (host string, port uint16, tls bool, err error) {
	return targetParts(target)
}

// splitHostPort is a small helper for messages that carry host:port already.
func splitHostPort(hostPort string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		if i := strings.LastIndex(hostPort, ":"); i >= 0 {
			return hostPort[:i], atou16(hostPort[i+1:], 80)
		}
		return hostPort, 80
	}
	return host, atou16(portStr, 80)
}

func atou16(s string, def uint16) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return def
	}
	return uint16(n)
}

// unescapePathParam decodes a single percent-encoded component without tripping over a '+' that
// was never a space (path segments use %20, query strings use '+').
func unescapePathParam(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}
