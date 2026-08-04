package http2

import (
	"bytes"
	"fmt"
	"strings"
)

// IsHTTP2Request reports whether raw bytes use the normalise-rendered request line.
func IsHTTP2Request(raw []byte) bool {
	lineEnd := bytes.Index(raw, []byte("\r\n"))
	if lineEnd < 0 {
		return false
	}
	return bytes.HasSuffix(raw[:lineEnd], []byte(" HTTP/2"))
}

// ParsedRequest is one HTTP/2 request in the shape RenderRequest produces.
type ParsedRequest struct {
	Method    string
	Path      string
	Authority string
	Headers   map[string]string
	Body      []byte
}

// ParseRequest reads a RenderRequest-shaped byte slice back into fields.
func ParseRequest(raw []byte) (ParsedRequest, error) {
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return ParsedRequest{}, fmt.Errorf("http2 request: missing header terminator")
	}
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) == 0 {
		return ParsedRequest{}, fmt.Errorf("http2 request: empty message")
	}
	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) != 3 || string(parts[2]) != "HTTP/2" {
		return ParsedRequest{}, fmt.Errorf("http2 request: expected METHOD PATH HTTP/2 start line")
	}
	out := ParsedRequest{
		Method:  string(parts[0]),
		Path:    string(parts[1]),
		Headers: make(map[string]string),
		Body:    body,
	}
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		name, value, ok := bytes.Cut(line, []byte(": "))
		if !ok {
			return ParsedRequest{}, fmt.Errorf("http2 request: malformed header line %q", line)
		}
		key := string(name)
		if strings.EqualFold(key, "content-length") {
			continue
		}
		if strings.EqualFold(key, "host") {
			out.Authority = string(value)
		}
		out.Headers[key] = string(value)
	}
	if out.Authority == "" {
		return ParsedRequest{}, fmt.Errorf("http2 request: missing Host header")
	}
	return out, nil
}
