package graphqlmap

// Transports. HTTPTransport is the batteries-included one for standalone library users;
// callers that must route probes through their own egress chokepoint implement Transport
// themselves, which is why the interface exists at all.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HTTPTransportOptions configures HTTPTransport, covering the Python tool's CLI surface.
type HTTPTransportOptions struct {
	// Proxy routes requests through an intercepting proxy (--proxy).
	Proxy string
	// InsecureSkipVerify mirrors requests' verify=False, which the Python tool always sets.
	// It defaults to false here: silently accepting any certificate is a choice a caller
	// should make explicitly, not inherit.
	InsecureSkipVerify bool
	Timeout            time.Duration
	// MaxBodyBytes caps how much of a response is read, so a hostile endpoint cannot
	// exhaust memory. Zero uses DefaultMaxBodyBytes.
	MaxBodyBytes int64
	Client       *http.Client
}

// DefaultMaxBodyBytes bounds a single response read.
const DefaultMaxBodyBytes = 8 << 20

// HTTPTransport is a net/http implementation of Transport.
type HTTPTransport struct {
	client   *http.Client
	maxBytes int64
}

// NewHTTPTransport builds a transport. A supplied Client is used as-is, so a caller that has
// already configured cookies or redirects keeps them.
func NewHTTPTransport(opts HTTPTransportOptions) (*HTTPTransport, error) {
	maxBytes := opts.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}
	if opts.Client != nil {
		return &HTTPTransport{client: opts.Client, maxBytes: maxBytes}, nil
	}
	tr := &http.Transport{}
	if opts.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if opts.Proxy != "" {
		u, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(u)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		// Long enough that a 30s sleep payload still returns rather than being cut off
		// and misread as no delay.
		timeout = 60 * time.Second
	}
	return &HTTPTransport{client: &http.Client{Transport: tr, Timeout: timeout}, maxBytes: maxBytes}, nil
}

// Do sends one request and times the round trip.
func (t *HTTPTransport) Do(ctx context.Context, req Request) (*Response, error) {
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	start := time.Now()
	res, err := t.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(res.Body, t.maxBytes))
	if err != nil {
		return nil, err
	}
	// Duration is measured across the body read, not just the header round trip: a
	// time-based payload that delays streaming would otherwise look instant.
	return &Response{Status: res.StatusCode, Body: raw, Duration: time.Since(start)}, nil
}

// TransportFunc adapts a function to Transport, for tests and for callers wiring an existing
// send path in one line.
type TransportFunc func(ctx context.Context, req Request) (*Response, error)

func (f TransportFunc) Do(ctx context.Context, req Request) (*Response, error) { return f(ctx, req) }
