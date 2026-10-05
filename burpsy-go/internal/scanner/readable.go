package scanner

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
)

// readableResponse returns a stored response as the application sent it, which is what every check
// that reads a body needs (burpsy-react-ui-jgnf).
//
// Unpacking is opt-in on the proxy path (unpack_compressed_responses), so a stored response from a
// real server is usually gzip-encoded and often chunked. Read raw, every body check — reflections, DOM
// sinks, disclosure, secrets — matched compressed bytes and found nothing, which reads exactly like a
// clean response. Here the chunk framing comes off, a gzip/deflate body is decoded, and the head is
// rebuilt to describe what it now frames: Content-Encoding and Transfer-Encoding dropped,
// Content-Length set. Every other header is kept byte for byte, so header checks see the wire.
//
// undecodable is true when the body is encoded in a way this build cannot read (br, zstd, a chain, a
// broken stream): the response comes back with whatever could be undone — the chunk framing — and the
// caller counts it, because a check that then finds nothing has not shown the body is clean.
func readableResponse(raw []byte) (out []byte, undecodable bool) {
	head, body, ok := splitHeadAndBody(raw)
	if !ok {
		return raw, false
	}
	te := firstHeader(head, "Transfer-Encoding")
	ce := strings.TrimSpace(firstHeader(head, "Content-Encoding"))
	chunked := strings.EqualFold(strings.TrimSpace(te), "chunked")
	encoded := ce != "" && !strings.EqualFold(ce, "identity")
	if !chunked && !encoded {
		return raw, false
	}
	drop := map[string]bool{}
	if chunked {
		// The proxy stores a chunked response with its framing already removed but the header kept,
		// so a body that does not parse as chunks is usually the de-framed payload itself, not a broken
		// stream: carry on with it. Either way the head stops claiming framing the body does not have.
		if plain, ok := httputil.Dechunk(body); ok {
			body = plain
		}
		drop["transfer-encoding"] = true
	}
	if encoded {
		if !httputil.Unpackable(ce) {
			undecodable = true
		} else if plain, err := httputil.DecodeBody(ce, body); err != nil {
			undecodable = true
		} else {
			body = plain
			drop["content-encoding"] = true
		}
	}
	if len(drop) == 0 {
		return raw, undecodable
	}
	drop["content-length"] = true
	return rebuildHead(head, drop, len(body), body), undecodable
}

// readableBody is readableResponse's body alone, for the readers that never look at the head.
func readableBody(msg *core.StoredMessage) []byte {
	raw, _ := readableResponse(msg.Raw())
	if _, body, ok := splitHeadAndBody(raw); ok {
		return body
	}
	return msg.Body()
}

func splitHeadAndBody(raw []byte) (head, body []byte, ok bool) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i], raw[i+4:], true
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i], raw[i+2:], true
	}
	return nil, nil, false
}

// firstHeader reads one header's first value out of a head block, skipping the status line.
func firstHeader(head []byte, name string) string {
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// rebuildHead writes head without the dropped headers, adds Content-Length, and appends body.
func rebuildHead(head []byte, drop map[string]bool, length int, body []byte) []byte {
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	var out bytes.Buffer
	out.Grow(len(head) + len(body) + 32)
	for i, line := range lines {
		if i > 0 {
			if k, _, ok := strings.Cut(line, ":"); ok && drop[strings.ToLower(strings.TrimSpace(k))] {
				continue
			}
		}
		out.WriteString(line)
		out.WriteString("\r\n")
	}
	out.WriteString("Content-Length: " + strconv.Itoa(length) + "\r\n\r\n")
	out.Write(body)
	return out.Bytes()
}
