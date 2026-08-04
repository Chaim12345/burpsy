package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"golang.org/x/net/http2"
)

func (s *Sender) sendH2Raw(ctx context.Context, host string, port uint16, useTLS bool, rawRequest []byte) ([]byte, error) {
	parsed, err := burpsyhttp2.ParseRequest(rawRequest)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return nil, fmt.Errorf("http/2 egress requires TLS")
	}

	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	dialer := &net.Dialer{Timeout: s.config.Timeout}
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !s.config.TLSVerify,
		NextProtos:         []string{"h2"},
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("h2 connection failed: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(s.config.Timeout))
	}

	tr := &http2.Transport{}
	clientConn, err := tr.NewClientConn(conn)
	if err != nil {
		return nil, fmt.Errorf("h2 client conn: %w", err)
	}
	defer clientConn.Close()

	url := "https://" + parsed.Authority + parsed.Path
	var body io.Reader
	if len(parsed.Body) > 0 {
		body = bytes.NewReader(parsed.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, parsed.Method, url, body)
	if err != nil {
		return nil, fmt.Errorf("h2 request: %w", err)
	}
	httpReq.Host = parsed.Authority
	for name, value := range parsed.Headers {
		if burpsyhttp2.IsHopHeader(name) {
			continue
		}
		httpReq.Header.Set(name, value)
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
