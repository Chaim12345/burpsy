package intruder

import (
	"bytes"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Burp's "Set Connection header" attack setting, and the two attack-results settings that sit
// beside it (burpsy-react-ui-fmxv). Burp's own wording, from
// tools/intruder/configure-attack/settings.html:
//
//	Set Connection header - Add or update the Connection header with the value close. This may
//	mean attacks are performed more quickly when the server does not itself return a valid
//	Content-Length or Transfer-Encoding header.
//
// The other two live where they can actually act: StorePayloads is a report-shape decision and
// sits on Attack (engine.go); denial-of-service mode is not shipped at all and is refused at the
// wire with its reason (internal/web/api_tools.go).

// setConnectionClose adds or updates the request's Connection header to the value "close".
//
// Byte-exact by span. An existing Connection header has only its VALUE replaced, so the name's
// original spelling and casing, the separator the operator typed, and every other byte of the
// request survive untouched — this setting is a licence to set one header, not to normalise a
// template somebody wrote deliberately. A request that already says "close" (in any case) is
// returned unchanged rather than rewritten, so an attack cannot be told apart from the same attack
// with the box ticked when the template already had it.
//
// A request with no Connection header gets one appended as the last header line, in the line
// ending the request itself uses: a template written with bare LF stays bare LF. core.Parse is
// tolerant of both, and so is this.
//
// Content-Length does not need recomputing afterwards: the body is not touched, and the header is
// inserted after every insertion-point span the splice already consumed. That ordering is the
// reason this runs AFTER the payloads are spliced and never before — insertion points are byte
// offsets into the base request, so a header inserted ahead of them would move every span that
// follows and the attack would splice its payloads into the wrong bytes.
//
// A request with no header terminator is returned unchanged. There is nowhere honest to put a
// header in a buffer that never ends its head, and bolting one onto a guess would put bytes on the
// wire that the operator neither wrote nor asked for — the same refusal applyJarCookies
// (internal/web/intruder_cookies.go) already makes for the same reason.
//
// The terminator is checked here rather than left to core.Parse, which is deliberately tolerant:
// findHeaderEnd falls back to "treat the whole buffer as head, empty body" and returns no error, so
// Parse succeeding is not the same question as the message being well-framed.
func setConnectionClose(raw []byte) []byte {
	if !bytes.Contains(raw, []byte("\r\n\r\n")) && !bytes.Contains(raw, []byte("\n\n")) {
		return raw
	}
	shape, err := core.Parse(raw, core.DirectionRequest)
	if err != nil {
		return raw
	}
	if v := headerSpan(raw, shape, "connection"); v != nil {
		end := min(v.End(), len(raw))
		start := min(v.Offset, end)
		if bytes.EqualFold(bytes.TrimSpace(raw[start:end]), []byte("close")) {
			return raw
		}
		out := make([]byte, 0, len(raw)+8)
		out = append(out, raw[:start]...)
		out = append(out, "close"...)
		out = append(out, raw[end:]...)
		return out
	}

	// No Connection header. Append after the last header line — or, for a request that carries no
	// headers at all, after the request line, which is the only other place a header line may go.
	at := min(shape.ThirdToken.End(), len(raw))
	if n := len(shape.Headers); n > 0 {
		at = min(shape.Headers[n-1].Value.End(), len(raw))
	}
	// Read the line ending from the HEAD, not from `raw[:at]` and not from the whole message. A
	// request with no headers at all puts `at` at the end of the request line, before any line
	// ending has been seen; and a body may hold CRLF of its own that says nothing about how the
	// head is framed.
	eol := []byte("\n")
	if bytes.Contains(raw[:min(shape.Body.Offset, len(raw))], []byte("\r\n")) {
		eol = []byte("\r\n")
	}
	out := make([]byte, 0, len(raw)+20)
	out = append(out, raw[:at]...)
	out = append(out, eol...)
	out = append(out, "Connection: close"...)
	out = append(out, raw[at:]...)
	return out
}
