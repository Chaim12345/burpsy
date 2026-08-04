// Package http2 renders HTTP/2 exchanges into HTTP/1-shaped bytes for history,
// matching crates/http2/src/normalise.rs so every existing tool keeps working.
package http2

import (
	"bytes"
	"fmt"
	"strings"
)

// Header is one field name/value pair, verbatim on the wire.
type Header struct {
	Name  string
	Value string
}

// RenderRequest builds `{method} {path} HTTP/2\r\n` + headers + body.
func RenderRequest(method, path, authority string, headers []Header, body []byte) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s %s HTTP/2\r\n", method, path)

	sawHost := false
	for _, h := range headers {
		if strings.EqualFold(h.Name, "content-length") {
			continue
		}
		if strings.EqualFold(h.Name, "host") {
			sawHost = true
		}
		writeField(&out, h.Name, h.Value)
	}
	if !sawHost && authority != "" {
		fmt.Fprintf(&out, "Host: %s\r\n", authority)
	}
	fmt.Fprintf(&out, "Content-Length: %d\r\n\r\n", len(body))
	out.Write(body)
	return out.Bytes()
}

// RenderResponse builds `HTTP/2 {status}\r\n` + headers + body.
func RenderResponse(status int, headers []Header, body []byte) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "HTTP/2 %d\r\n", status)

	for _, h := range headers {
		if strings.EqualFold(h.Name, "content-length") {
			continue
		}
		writeField(&out, h.Name, h.Value)
	}
	fmt.Fprintf(&out, "Content-Length: %d\r\n\r\n", len(body))
	out.Write(body)
	return out.Bytes()
}

func writeField(out *bytes.Buffer, name, value string) {
	out.WriteString(name)
	out.WriteString(": ")
	out.WriteString(value)
	out.WriteString("\r\n")
}

// HeadersFromHTTP converts net/http headers to the ordered list used by Render*.
func HeadersFromHTTP(hdr map[string][]string) []Header {
	if len(hdr) == 0 {
		return nil
	}
	out := make([]Header, 0, len(hdr))
	for name, vals := range hdr {
		for _, v := range vals {
			out = append(out, Header{Name: name, Value: v})
		}
	}
	return out
}

// IsHopHeader reports connection-specific headers that must not be forwarded on h2.
func IsHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-connection", "te", "trailer",
		"transfer-encoding", "upgrade", "host":
		return true
	default:
		return false
	}
}
