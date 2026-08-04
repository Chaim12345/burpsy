package sender

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"golang.org/x/net/http2"
)

// The h2 half of the egress path: one request over one already-negotiated connection.
//
// # Why the connection is an argument
//
// This used to dial for itself, offering `h2` alone. Two things were wrong with that. Offering h2 alone
// means an HTTP/1.1-only target aborts the handshake with no_application_protocol, so a repeater resend
// of captured h2 bytes against a host that has since turned h2 off failed at the TLS layer instead of
// going out as HTTP/1.1 and saying so. And a dial inside here is a dial the protocol-selection path
// cannot see, so the connection it discovered the protocol on could not be the connection it sent on —
// which would mean two handshakes per request, and a cache that could only ever halve the waste.
//
// Now sender.go dials once, offering what the caller's intent asks for, and hands the connection to
// whichever of these two functions matches what ALPN actually chose. Discovery therefore costs nothing:
// it rides the connection the send needed anyway.
//
// # The response bytes are rendered, not captured verbatim
//
// h2 has no response bytes in the HTTP/1 sense — it has HPACK-encoded pseudo-headers and DATA frames.
// burpsyhttp2.RenderResponse produces the HTTP/1-shaped rendering the rest of the tool indexes and
// searches, which is the same rendering the proxy's h2 relay records, so history holds one shape rather
// than two. A caller that needs the frames themselves wants the frame-program path (h2program.go).

// h2Request is one request in the shape an h2 send needs: a method, a path, an authority, ordered
// fields and a body.
//
// Ordered fields rather than a map, because the h2 plan that produces one preserves the order the
// operator wrote — and because a map cannot hold two fields with the same name, which a request can.
type h2Request struct {
	Method    string
	Path      string
	Authority string
	Headers   []burpsyhttp2.Header
	Body      []byte
}

// h2RequestFromRaw reads bytes whose start line already says HTTP/2 — what the repeater replays — into
// the send shape.
//
// Hop-by-hop fields are dropped here rather than left for the transport to reject, matching what the
// previous version of this file did and what the proxy's h2 relay does with the same set.
func h2RequestFromRaw(raw []byte) (h2Request, error) {
	parsed, err := burpsyhttp2.ParseRequest(raw)
	if err != nil {
		return h2Request{}, err
	}
	out := h2Request{
		Method:    parsed.Method,
		Path:      parsed.Path,
		Authority: parsed.Authority,
		Body:      parsed.Body,
	}
	for name, value := range parsed.Headers {
		if burpsyhttp2.IsHopHeader(name) {
			continue
		}
		out.Headers = append(out.Headers, burpsyhttp2.Header{Name: name, Value: value})
	}
	return out, nil
}

// sendOverH2 runs one request over an already-negotiated h2 connection and returns the response in the
// HTTP/1-shaped rendering the store indexes.
func sendOverH2(ctx context.Context, conn net.Conn, req h2Request) ([]byte, error) {
	tr := &http2.Transport{}
	clientConn, err := tr.NewClientConn(conn)
	if err != nil {
		return nil, fmt.Errorf("h2 client conn: %w", err)
	}
	defer clientConn.Close()

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, "https://"+req.Authority+req.Path, body)
	if err != nil {
		return nil, fmt.Errorf("h2 request: %w", err)
	}
	httpReq.Host = req.Authority
	for _, h := range req.Headers {
		// Add, not Set: a request may carry two fields of the same name, and Set would silently keep the
		// last one.
		httpReq.Header.Add(h.Name, h.Value)
	}

	httpResp, err := clientConn.RoundTrip(httpReq)
	if err != nil {
		return nil, fmt.Errorf("h2 round trip: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("h2 read body: %w", err)
	}
	headers := burpsyhttp2.HeadersFromHTTP(httpResp.Header)
	return burpsyhttp2.RenderResponse(httpResp.StatusCode, headers, respBody), nil
}

// renderHTTP1 writes the HTTP/1.1 bytes an h2-shaped request becomes, for the one case that needs it: a
// caller replaying captured h2 bytes at a target that no longer negotiates h2.
//
// The alternative was to fail the send, which is what this path used to do — and failing tells an
// operator less than sending the request over the protocol the target actually offered and reporting the
// downgrade. The conversion is narrow because the input is narrow: bytes this tool rendered itself from
// an h2 exchange, so there are no framing headers to reconcile. Content-Length is written from the body
// because that is the only honest length; burpsyhttp2.ParseRequest drops whatever the input declared.
func renderHTTP1(req h2Request) []byte {
	var out bytes.Buffer
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	fmt.Fprintf(&out, "%s %s HTTP/1.1\r\n", method, req.Path)
	fmt.Fprintf(&out, "Host: %s\r\n", req.Authority)
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "host") || strings.EqualFold(h.Name, "content-length") {
			continue
		}
		fmt.Fprintf(&out, "%s: %s\r\n", h.Name, h.Value)
	}
	if len(req.Body) > 0 {
		fmt.Fprintf(&out, "Content-Length: %d\r\n", len(req.Body))
	}
	out.WriteString("\r\n")
	out.Write(req.Body)
	return out.Bytes()
}

// render is the HTTP/1-shaped rendering of this request, for a capture site that must store what went out
// rather than what it was handed.
//
// The same rendering the proxy's h2 relay records, so history holds one shape for h2 traffic whichever
// surface produced it. Not the literal wire octets — those are HPACK inside the transport — and
// SendOutcome.Rendered says so.
func (r h2Request) render() []byte {
	return burpsyhttp2.RenderRequest(r.Method, r.Path, r.Authority, r.Headers, r.Body)
}
