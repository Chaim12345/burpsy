package web

import (
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// Repeater's "Unpack compressed responses" (burpsy-react-ui-of0z).
//
// Burp: "By default, Burp automatically unpacks any gzip, deflate, and Brotli-compressed content
// received in responses." burpsy unpacks for DISPLAY: the exchange still stores the bytes that
// arrived — a capture that silently became a different message would misstate what the server
// sent — and the send's answer carries the unpacked rendering beside them. Brotli has no decoder in
// this build (httputil.Unpackable), which the answer says rather than showing compressed bytes as
// though nothing had been tried; gaps.md records it.

// unpackedResponse is raw with its body decoded: chunk framing removed, the Content-Encoding
// decoded, and the head rewritten to describe the result — Content-Encoding and a chunked
// Transfer-Encoding dropped, Content-Length set to the decoded length — in the head's own line
// ending. applies is false when the response declares no encoding (or identity); err names a
// declared encoding this build cannot decode or a body that would not decode.
func unpackedResponse(raw []byte) (out []byte, encoding string, applies bool, err error) {
	head, body := splitHeadBody(raw)
	encoding = firstHeaderValue(head, "Content-Encoding")
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		return nil, "", false, nil
	}
	if !httputil.Unpackable(encoding) {
		return nil, encoding, true, errUnpack("no decoder for Content-Encoding " + strconv.Quote(encoding) + " in this build; gzip and deflate are supported")
	}
	chunked := strings.EqualFold(firstHeaderValue(head, "Transfer-Encoding"), "chunked")
	if chunked {
		plain, ok := dechunkForView(body)
		if !ok {
			return nil, encoding, true, errUnpack("the chunk framing did not parse, so the compressed body could not be located")
		}
		body = plain
	}
	decoded, derr := httputil.DecodeBody(encoding, body)
	if derr != nil {
		return nil, encoding, true, errUnpack("the " + encoding + " body did not decode: " + derr.Error())
	}
	eol := "\r\n"
	if !strings.Contains(string(head), "\r\n") {
		eol = "\n"
	}
	lines := strings.Split(string(head), eol)
	kept := lines[:1]
	for _, line := range lines[1:] {
		name, value, _ := strings.Cut(line, ":")
		switch {
		case strings.EqualFold(strings.TrimSpace(name), "Content-Encoding"),
			strings.EqualFold(strings.TrimSpace(name), "Content-Length"):
			continue
		case chunked && strings.EqualFold(strings.TrimSpace(name), "Transfer-Encoding") &&
			strings.EqualFold(strings.TrimSpace(value), "chunked"):
			continue
		}
		kept = append(kept, line)
	}
	kept = append(kept, "Content-Length: "+strconv.Itoa(len(decoded)))
	out = append([]byte(strings.Join(kept, eol)+eol+eol), decoded...)
	return out, encoding, true, nil
}

type errUnpack string

func (e errUnpack) Error() string { return string(e) }
