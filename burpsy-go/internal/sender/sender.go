// Package sender provides HTTP request sending capabilities.
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

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// Sender handles HTTP request sending.
type Sender struct {
client *http.Client
config *SenderConfig
}

// SenderConfig holds configuration for the sender.
type SenderConfig struct {
Timeout         time.Duration
MaxRedirects    int
FollowRedirects bool
TLSVerify       bool
ProxyURL        string
UserAgent       string
}

// DefaultSenderConfig returns default sender configuration.
func DefaultSenderConfig() *SenderConfig {
return &SenderConfig{
Timeout:         30 * time.Second,
MaxRedirects:    10,
FollowRedirects: true,
TLSVerify:       true,
UserAgent:       "burpsy/1.0",
}
}

// NewSender creates a new HTTP sender.
func NewSender(config *SenderConfig) *Sender {
if config == nil {
config = DefaultSenderConfig()
}

transport := &http.Transport{
Proxy: http.ProxyFromEnvironment,
DialContext: (&net.Dialer{
Timeout:   config.Timeout,
KeepAlive: 30 * time.Second,
}).DialContext,
ForceAttemptHTTP2:     true,
MaxIdleConns:          100,
IdleConnTimeout:       90 * time.Second,
TLSHandshakeTimeout:   10 * time.Second,
ExpectContinueTimeout: 1 * time.Second,
TLSClientConfig: &tls.Config{
InsecureSkipVerify: !config.TLSVerify,
},
}

client := &http.Client{
Transport: transport,
Timeout:   config.Timeout,
}

if !config.FollowRedirects {
client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
return http.ErrUseLastResponse
}
}

return &Sender{
client: client,
config: config,
}
}

// Request represents a raw HTTP request.
type Request struct {
Method  string
URL     string
Host    string
Path    string
Headers map[string]string
Body    []byte
TLS     bool
Port    uint16
}

// Response represents an HTTP response.
type Response struct {
StatusCode int
Status     string
Headers    map[string]string
Body       []byte
Version    string
Duration   time.Duration
}

// Send sends a raw HTTP request and returns the response.
func (s *Sender) Send(ctx context.Context, req *Request) (*Response, error) {
startTime := time.Now()

url := req.URL
if url == "" {
scheme := "http"
if req.TLS {
scheme = "https"
}
port := ""
if req.Port != 0 && ((req.TLS && req.Port != 443) || (!req.TLS && req.Port != 80)) {
port = fmt.Sprintf(":%d", req.Port)
}
url = fmt.Sprintf("%s://%s%s%s", scheme, req.Host, port, req.Path)
}

var bodyReader io.Reader
if len(req.Body) > 0 {
bodyReader = bytes.NewReader(req.Body)
}

httpReq, err := http.NewRequestWithContext(ctx, req.Method, url, bodyReader)
if err != nil {
return nil, fmt.Errorf("failed to create request: %w", err)
}

for k, v := range req.Headers {
httpReq.Header.Set(k, v)
}

if req.Host != "" {
httpReq.Host = req.Host
}

if httpReq.Header.Get("User-Agent") == "" {
httpReq.Header.Set("User-Agent", s.config.UserAgent)
}

httpResp, err := s.client.Do(httpReq)
if err != nil {
return nil, fmt.Errorf("request failed: %w", err)
}
defer httpResp.Body.Close()

body, err := io.ReadAll(httpResp.Body)
if err != nil {
return nil, fmt.Errorf("failed to read response body: %w", err)
}

headers := make(map[string]string)
for k, vv := range httpResp.Header {
if len(vv) > 0 {
headers[k] = vv[0]
}
}

duration := time.Since(startTime)

return &Response{
StatusCode: httpResp.StatusCode,
Status:     httpResp.Status,
Headers:    headers,
Body:       body,
Version:    httpResp.Proto,
Duration:   duration,
}, nil
}

// SendRaw sends a raw HTTP request string and returns the response.
func (s *Sender) SendRaw(ctx context.Context, host string, port uint16, useTLS bool, rawRequest []byte) ([]byte, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	var conn net.Conn
	var err error

	dialer := &net.Dialer{Timeout: s.config.Timeout}

	if useTLS {
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: !s.config.TLSVerify,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(s.config.Timeout))

	_, err = conn.Write(rawRequest)
	if err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}

	// Read exactly one response; keep-alive connections never EOF.
	response, err := httputil.ReadHTTPResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	return response, nil
}

// WithTimeout sets the timeout for the sender.
func (s *Sender) WithTimeout(timeout time.Duration) *Sender {
s.config.Timeout = timeout
s.client.Timeout = timeout
return s
}

// WithTLSVerify sets TLS verification.
func (s *Sender) WithTLSVerify(verify bool) *Sender {
s.config.TLSVerify = verify
if transport, ok := s.client.Transport.(*http.Transport); ok {
transport.TLSClientConfig.InsecureSkipVerify = !verify
}
return s
}
