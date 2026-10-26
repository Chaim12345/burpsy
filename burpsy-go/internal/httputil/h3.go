package httputil

// The one re-expression path onto HTTP/3 (burpsy-react-ui-vln3). HTTP/3 has no wire form an
// HTTP/1 byte string can be poured into verbatim, so a request carried over QUIC is always a
// re-expression: pseudo-headers plus fields, built here for both callers - the sender's explicit
// h3 pin (0hgx) and the proxy's Alt-Svc-selected h3 (vln3). One path, so the honesty of the
// re-expression is reviewed once and a bug in it has one place to live.
//
// The caller owns everything that is a policy decision: whether the request may go over h3 at
// all (the carriability bar - planH2 in the sender), the TLS configuration (verification, roots,
// version floor, SNI, client certificates), and how the outcome is reported. What lives here is
// only the mechanics that must not diverge: target parsing, request assembly, the round trip, and
// the HTTP/1-shaped rendering of the response.

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
)

// RequestURL parses authority + rawTarget into the URL a re-expressed request is built from.
//
// The rule is verbatim carry, never re-encode (burpsy-react-ui-swqq): the parsed form is used
// only when it round-trips to the exact bytes the operator wrote. url.Parse ACCEPTS-then-
// TRANSFORMS two shapes - '/a#b' loses its fragment, '/a b' comes back '%20'-encoded - so
// "Parse succeeded" is not "Parse preserved"; anything it transformed, and anything it refused
// (the percent escapes a path-confusion probe is made of, burpsy-react-ui-0vzb.25), takes the
// Opaque path, whose RequestURI is the bytes unexamined. Rejecting such targets hid the answer
// a probe was written to get; re-encoding them would be worse than failing: the server would be
// asked about a request the operator did not write, and the result would read as evidence about
// their probe.
//
// One deliberate asymmetry, pinned on both sides so nobody "fixes" one against the other: this
// helper carries a RAW SPACE verbatim ('/a b' is just bytes here), while the senders' carriability
// bars refuse the same target before any URL is built - a raw space breaks the request line's own
// tokenisation, and carrying what the parser refused would make burpsy the more-permissive parser
// (the smuggling shape; swqq). Both behaviors are the contract.
func RequestURL(authority, rawTarget string) (*url.URL, error) {
	if parsed, err := url.Parse("https://" + authority + rawTarget); err == nil && parsed.RequestURI() == rawTarget {
		return parsed, nil
	}
	path, query, hasQuery := strings.Cut(rawTarget, "?")
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		// Opaque renders a "//"-prefixed value as scheme:opaque, and a target with no leading
		// slash is not origin form at all; the carriability bar has already refused those, so
		// reaching here means the bytes came from a malformed replay. Say what they were.
		return nil, fmt.Errorf("unusable target %q", rawTarget)
	}
	return &url.URL{
		Scheme:     "https",
		Host:       authority,
		Opaque:     path,
		RawQuery:   query,
		ForceQuery: hasQuery,
	}, nil
}

// maxH3ResponseBodyBytes bounds the response body one h3 round trip buffers, so an origin
// streaming an unbounded body cannot exhaust memory. A package variable rather than the
// constant directly so a test can lower it; production code keeps MaxResponseBodyBytes,
// the same bound every other leg reads under.
var maxH3ResponseBodyBytes = int64(MaxResponseBodyBytes)

// RoundTripH3 carries one request over HTTP/3 and returns the response rendered HTTP/1-shaped,
// the same shape every other leg returns, so downstream readers never branch on the carrier.
//
// dialAuthority is the host:port QUIC dials (for the proxy's Alt-Svc leg, the advertised
// endpoint); authority is the request's :authority - what the request wrote in its Host field.
// The two differ whenever a send goes to one address under another's name. tlsConfig is the
// caller's policy, ServerName included; this function sets nothing on it.
//
// truncated reports that the response body ran past MaxResponseBodyBytes and was cut there:
// the rendered response carries what arrived up to the cap, and the caller owes the record a
// note saying the cut happened (PR #363 review: an uncapped read both risks memory and hides
// the cut). RenderResponse writes the true Content-Length of what it is given, so the rendered
// bytes stay self-consistent after the cut.
//
// One transport per call means one QUIC connection per request, matching the proxy's
// forward-per-request shape; pooling QUIC connections is a separate decision, not smuggled in
// here.
func RoundTripH3(ctx context.Context, tlsConfig *tls.Config, dialAuthority, authority, method, rawTarget string, headers []burpsyhttp2.Header, body []byte) (resp []byte, truncated bool, err error) {
	return roundTripH3(0, ctx, tlsConfig, dialAuthority, authority, method, rawTarget, headers, body)
}

// roundTripH3 is the shared body of both entry points. dialTimeout > 0 bounds only the
// handshake; maybeDelivered reports whether a QUIC connection ever existed, which is the
// honest line between "the request cannot have arrived" and "delivery is uncertain" - a
// connection is not proof the origin processed anything.
func roundTripH3(dialTimeout time.Duration, ctx context.Context, tlsConfig *tls.Config, dialAuthority, authority, method, rawTarget string, headers []burpsyhttp2.Header, body []byte) (resp []byte, maybeDelivered bool, truncated bool, err error) {
	target, err := RequestURL(dialAuthority, rawTarget)
	if err != nil {
		return nil, false, false, fmt.Errorf("HTTP/3 request target: %w", err)
	}
	httpReq := &http.Request{
		Method: method,
		URL:    target,
		Host:   authority,
		Header: make(http.Header),
	}
	if len(body) > 0 {
		httpReq.Body = io.NopCloser(bytes.NewReader(body))
		httpReq.ContentLength = int64(len(body))
	}
	httpReq = httpReq.WithContext(ctx)
	for _, h := range headers {
		// Add, not Set: a request may carry two fields of the same name, and Set would silently
		// keep the last one.
		httpReq.Header.Add(h.Name, h.Value)
	}

	// The dial hook is installed in both modes so maybeDelivered is honest even with no
	// separate dial bound: a failed round trip whose dial connected is "delivery uncertain",
	// never a safe automatic retry.
	transport := &http3.Transport{TLSClientConfig: tlsConfig}
	transport.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dialCtx := ctx
		cancel := func() {}
		if dialTimeout > 0 {
			dialCtx, cancel = context.WithTimeout(ctx, dialTimeout)
		}
		defer cancel()
		conn, err := quic.DialAddr(dialCtx, addr, tlsCfg, cfg)
		if err == nil {
			maybeDelivered = true
		}
		return conn, err
	}
	defer transport.Close()
	httpResp, err := transport.RoundTrip(httpReq)
	if err != nil {
		return nil, maybeDelivered, false, fmt.Errorf("HTTP/3 round trip: %w", err)
	}
	defer httpResp.Body.Close()
	// A connection exists and the request went out on it: from here on, delivery is
	// uncertain whatever happens next.
	maybeDelivered = true

	capBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxH3ResponseBodyBytes+1))
	if err != nil {
		return nil, true, false, fmt.Errorf("HTTP/3 read body: %w", err)
	}
	if int64(len(capBody)) > maxH3ResponseBodyBytes {
		truncated = true
		capBody = capBody[:maxH3ResponseBodyBytes]
	}
	return burpsyhttp2.RenderResponse(httpResp.StatusCode, burpsyhttp2.HeadersFromHTTP(httpResp.Header), capBody), true, truncated, nil
}
