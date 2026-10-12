package scanner

// HTTP response header injection (CRLF injection / response splitting), the catalogue row Burp's Zwi
// implements. checks_reflection2.go owns the row's descriptor; this file is its evaluator.
//
// # Payload depth
//
// Zwi's own matrix is three separators (CRLF, CR, LF) in three encodings (raw, percent-encoded,
// NUL-prefixed). The encoded forms below cover that matrix in wire form and add the depth crlfuzz
// (github.com/dwisiswant0/crlfuzz) showed real targets need: a double-encoded separator for a
// component that decodes twice, the "%E5%98%8A%E5%98%8D" Unicode form (U+560A / U+560D, whose low
// bytes are LF and CR) for a stack that narrows characters to bytes, and the IIS "%u000d%u000a"
// form. Raw CR/LF bytes are only meaningful in a request header value — in a request line they end
// the line — so they are sent to header points only.
//
// # Where
//
// The request's own query, body and cookie values and its header values (bcheck insertion points),
// plus the URL path: a slash and the payload appended to it, the shape of the server-generated
// redirects ("Location: <path>/") that are the classic CRLF sink. A point is only probed once a plain
// marker sent through it is seen in the response's header block: injection into a header needs the
// value to reach one, and a point that never reflects cannot be shown vulnerable by any payload.
//
// # Evidence
//
// Text in the body proves nothing — a page that prints the parameter back contains the payload's
// header line as text whether or not anything was split. A finding needs a NEW response header that
// a client would actually parse: a header line named with a random token and carrying a random
// value (or a Set-Cookie for a random cookie name and value), read from the parsed header block —
// LF-terminated lines, a CR before the LF optional, a token before the colon (parsedResponseHeaders).
// It must be absent from the baseline, and a second probe through the same point and encoding with
// fresh names must split again. For a request-header point one more control applies: the same
// header line sent as an ordinary request header must NOT come back, so an application that echoes
// every request header into its response cannot pass for one whose header was split.

import (
	"context"
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// crlfSeparator is one separator in the form it is written on the wire.
type crlfSeparator struct {
	name string
	wire string
	// raw marks separator bytes that are only sent to request-header points.
	raw bool
}

var crlfSeparators = []crlfSeparator{
	{name: "%0d%0a", wire: "%0d%0a"},
	{name: "%0a", wire: "%0a"},
	{name: "%0d", wire: "%0d"},
	{name: "NUL-prefixed %00%0d%0a", wire: "%00%0d%0a"},
	{name: "double-encoded %250d%250a", wire: "%250d%250a"},
	{name: "double-encoded %250a", wire: "%250a"},
	{name: "Unicode %E5%98%8D%E5%98%8A", wire: "%E5%98%8D%E5%98%8A"},
	{name: "Unicode %E5%98%8A%E5%98%8D", wire: "%E5%98%8A%E5%98%8D"},
	{name: "%u000d%u000a", wire: "%u000d%u000a"},
	{name: "raw CRLF", wire: "\r\n", raw: true},
	{name: "raw LF", wire: "\n", raw: true},
	{name: "raw CR", wire: "\r", raw: true},
}

// crlfProbe is one probe's random names: an injected header and an injected cookie.
type crlfProbe struct {
	lead, header, value, cookie, cookieValue string
}

func newCRLFProbe() crlfProbe {
	return crlfProbe{
		lead:        newProbeCanary("c"),
		header:      "X-" + newProbeCanary("h"),
		value:       newProbeCanary("v"),
		cookie:      newProbeCanary("k"),
		cookieValue: newProbeCanary("w"),
	}
}

// payload splices sep before a header line and again before a Set-Cookie line. No spaces: a space in
// a request line or a query value would need an encoding of its own, and "Name:value" is a valid
// header line.
func (p crlfProbe) payload(sep string) string {
	return p.lead + sep + p.header + ":" + p.value + sep + "Set-Cookie:" + p.cookie + "=" + p.cookieValue
}

// split reports what of the probe arrived as parsed response headers.
func (p crlfProbe) split(raw []byte) string {
	head, _ := splitResponseHead(string(raw))
	for _, hd := range parsedResponseHeaders(head) {
		switch {
		case strings.EqualFold(hd[0], p.header) && hd[1] == p.value:
			return "a new response header " + hd[0] + ": " + hd[1]
		case strings.EqualFold(hd[0], "Set-Cookie"):
			name, rest, ok := strings.Cut(hd[1], "=")
			if ok && strings.TrimSpace(name) == p.cookie {
				if v, _, _ := strings.Cut(rest, ";"); strings.TrimSpace(v) == p.cookieValue {
					return "a new Set-Cookie header setting " + p.cookie + "=" + p.cookieValue
				}
			}
		}
	}
	return ""
}

// crlfSite is one place a payload can be put: an insertion point, or the URL path.
type crlfSite struct {
	label string
	point *bcheck.InsertionPoint
	// header marks a request-header point: raw separators apply and the echo control runs.
	header bool
}

func checkResponseHeaderInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, []string{"query", "body", "cookie", "header"})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", headerInjectionIssue, err)
	}
	points := h.Points()
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	sites := []crlfSite{{label: "the URL path"}}
	for i := range points {
		p := &points[i]
		sites = append(sites, crlfSite{label: string(p.Kind) + " " + p.Name, point: p, header: p.Kind == bcheck.IpHeader})
	}
	base := h.RequestBytes()
	send := func(s crlfSite, payload string) (ProbeResponse, bool) {
		if s.point == nil {
			res, err := h.SendRequestHTTP1(ctx, withPathSuffix(base, payload))
			return res, err == nil
		}
		res, err := h.guidedSendOpts(s.point, payload, bcheck.ApplyOptions{Raw: true}, ctx)
		return res, err == nil
	}
	baselineHead, _ := splitResponseHead(string(h.Baseline().Raw))

	for _, site := range sites {
		marker := newProbeCanary("r")
		if strings.Contains(baselineHead, marker) {
			continue
		}
		res, ok := send(site, marker)
		if !ok {
			continue
		}
		if head, _ := splitResponseHead(string(res.Raw)); !strings.Contains(head, marker) {
			continue
		}
		for _, sep := range crlfSeparators {
			if sep.raw && !site.header {
				continue
			}
			probe := newCRLFProbe()
			r1, ok := send(site, probe.payload(sep.wire))
			if !ok {
				continue
			}
			what := probe.split(r1.Raw)
			if what == "" || probe.split(h.Baseline().Raw) != "" {
				continue
			}
			again := newCRLFProbe()
			r2, ok := send(site, again.payload(sep.wire))
			if !ok || again.split(r2.Raw) == "" {
				continue
			}
			if site.header && echoesRequestHeaders(ctx, h, base) {
				continue
			}
			return []*Finding{buildProbeFinding(cc, headerInjectionIssue, "certain",
				"a "+sep.name+" separator injected into "+site.label+" produced "+what+
					"; a second probe with fresh names split the response again",
				"the value of "+site.label+" is copied into a response header without removing line breaks, so an "+
					"attacker can add response headers (including Set-Cookie) and, with an empty line, write the "+
					"response body")}, nil
		}
	}
	return nil, nil
}

// echoesRequestHeaders is the request-header control: a fresh header line sent as an ordinary
// request header, with no separator anywhere, comes back as a response header.
func echoesRequestHeaders(ctx context.Context, h *ProbeHarness, base []byte) bool {
	p := newCRLFProbe()
	res, err := h.SendRequestHTTP1(ctx, withHeaderPairs(base, [][2]string{{p.header, p.value}}))
	if err != nil {
		// No answer to the control is no evidence the header was split rather than echoed.
		return true
	}
	return p.split(res.Raw) != ""
}

// withPathSuffix appends "/" and suffix to the request target's path, before any query.
func withPathSuffix(raw []byte, suffix string) []byte {
	line, headers, body, eol := splitRequest(raw)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return raw
	}
	target, query, hasQuery := strings.Cut(parts[1], "?")
	if !strings.HasSuffix(target, "/") {
		target += "/"
	}
	target += suffix
	if hasQuery {
		target += "?" + query
	}
	parts[1] = target
	return joinRequest(strings.Join(parts, " "), headers, body, eol)
}
