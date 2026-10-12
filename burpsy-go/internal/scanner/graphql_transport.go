package scanner

// The adapter that lets pkg/graphqlmap drive probes through this scanner's egress chokepoint.
//
// graphqlmap ships its own HTTPTransport, and a caller outside burpsy should use it. Inside
// burpsy every probe has to leave through probeGate's AuthorisedSender, so the scanner
// supplies its own Transport instead. That is the whole reason the library takes an interface.

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/burpsy-go/burpsy/pkg/graphqlmap"
)

// scannerTransport routes graphqlmap requests through the authorised sender.
type scannerTransport struct {
	cc *CheckContext
}

// Do renders the library's Request as raw HTTP and sends it through the gate.
func (t *scannerTransport) Do(ctx context.Context, req graphqlmap.Request) (*graphqlmap.Response, error) {
	s, exchange := t.cc.Scanner, t.cc.Exchange
	if s == nil || exchange == nil {
		return nil, fmt.Errorf("graphql transport: no scanner or exchange: %w", errCapabilityMissing)
	}
	if s.sender == nil {
		return nil, fmt.Errorf("graphql transport: no sender; a GraphQL probe cannot be sent: %w", errCapabilityMissing)
	}
	gate := s.probeGate(ctx, exchange)
	if gate == nil {
		return nil, fmt.Errorf("graphql transport: no authorised sender: %w", errCapabilityMissing)
	}

	path := exchange.Path
	if req.Method == "GET" {
		// The library put the query in the URL; take the path+query from it so the request
		// line carries what it built.
		if u, err := url.Parse(req.URL); err == nil && u.RequestURI() != "" {
			path = u.RequestURI()
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", exchange.Host)
	for k, v := range req.Headers {
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	if len(req.Body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(req.Body))
	}
	b.WriteString("Connection: close\r\n\r\n")
	if len(req.Body) > 0 {
		b.Write(req.Body)
	}

	meter := meterFrom(ctx)
	meter.attempt()
	refusedBefore := gate.Refused()
	res, err := gate.Send(ctx, []byte(b.String()))
	if gate.Refused() > refusedBefore {
		meter.refusal()
		return nil, fmt.Errorf("graphql transport: refused: outside the engagement scope")
	}
	if err != nil {
		meter.failure()
		return nil, err
	}
	meter.succeeded()

	readable, _ := readableResponse(res.Raw)
	out := &graphqlmap.Response{Body: []byte(responseBody(string(readable))), Duration: res.Duration}
	if res.Status != nil {
		out.Status = *res.Status
	} else {
		out.Status = responseStatus(string(readable))
	}
	return out, nil
}

// newGraphQLClient builds a library client bound to the audited endpoint and this scanner's
// egress path.
func newGraphQLClient(cc *CheckContext, opts ...graphqlmap.Option) *graphqlmap.Client {
	endpoint := exchangeURL(cc.Exchange)
	base := []graphqlmap.Option{graphqlmap.WithMethod("POST"), graphqlmap.WithEncoding(graphqlmap.EncodingJSON)}
	return graphqlmap.New(endpoint, &scannerTransport{cc: cc}, append(base, opts...)...)
}
