package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// DefaultCADir returns the default CA directory path.
func DefaultCADir() string {
	// In real implementation, would use user config dir
	return "~/.burpsy/ca"
}

// TlsAction represents a TLS policy action.
type TlsAction int

const (
	TlsIntercept TlsAction = iota
	TlsPassthrough
)

// TlsPolicy controls TLS interception behavior.
type TlsPolicy struct {
	mu               sync.RWMutex
	passthrough      []string
	passthroughPorts []uint16
	engine           *TlsEngine
}

// NewTlsPolicy creates a new TLS policy.
func NewTlsPolicy() *TlsPolicy {
	return &TlsPolicy{
		passthrough:      make([]string, 0),
		passthroughPorts: make([]uint16, 0),
	}
}

// AddPassthrough adds a host pattern to passthrough.
func (p *TlsPolicy) AddPassthrough(pattern string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passthrough = append(p.passthrough, pattern)
}

// WithEngine sets the TLS engine for interception.
func (p *TlsPolicy) WithEngine(engine *TlsEngine) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.engine = engine
}

// ShouldPassthrough checks if a host should be passed through without interception.
func (p *TlsPolicy) ShouldPassthrough(host string, port uint16) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, pattern := range p.passthrough {
		if matchPattern(pattern, host) {
			return true
		}
	}

	for _, pport := range p.passthroughPorts {
		if pport == port {
			return true
		}
	}

	return false
}

// matchPattern checks if a host matches a wildcard pattern.
func matchPattern(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	return pattern == host
}

// TlsEngine handles TLS certificate generation and signing.
type TlsEngine struct {
	mu       sync.Mutex
	caCert   []byte
	caKey    []byte
	certPool sync.Map // cache of generated certificates
}

// LoadOrGenerateCA loads or generates a CA certificate.
func LoadOrGenerateCA(caDir string) (*TlsEngine, error) {
	// Simplified - in real implementation would load/generate actual CA
	return &TlsEngine{
		caCert: []byte("placeholder-ca-cert"),
		caKey:  []byte("placeholder-ca-key"),
	}, nil
}

// ProxyConfig holds all configuration for the proxy.
type ProxyConfig struct {
	store        *core.TrafficStore
	tls          *TlsPolicy
	scope        *core.Scope
	interceptor  *Interceptor
	matchReplace *MatchReplaceRules
	scanner      *PassiveScanner
	logger       *zap.Logger
}

// NewProxyConfig creates a new proxy configuration.
func NewProxyConfig(store *core.TrafficStore) *ProxyConfig {
	return &ProxyConfig{
		store: store,
		tls:   NewTlsPolicy(),
		scope: core.NewScopeAllowEverything(),
		logger: zap.NewNop(), // Default to nop logger
	}
}

// WithScope sets the scope for the proxy.
func (c *ProxyConfig) WithScope(scope *core.Scope) *ProxyConfig {
	c.scope = scope
	return c
}

// WithTlsPolicy sets the TLS policy.
func (c *ProxyConfig) WithTlsPolicy(policy *TlsPolicy) *ProxyConfig {
	c.tls = policy
	return c
}

// WithLogger sets the logger.
func (c *ProxyConfig) WithLogger(logger *zap.Logger) *ProxyConfig {
	c.logger = logger
	return c
}

// Server represents the proxy server.
type Server struct {
	config *ProxyConfig
}

// NewServer creates a new proxy server.
func NewServer(config *ProxyConfig) *Server {
	return &Server{
		config: config,
	}
}

// ListenAndServe starts the proxy server.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind proxy on %s: %w", addr, err)
	}
	defer listener.Close()

	s.config.logger.Info("proxy listening", zap.String("addr", addr))

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			s.config.logger.Warn("accept failed", zap.Error(err))
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set keep-alive
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(3 * time.Minute)
	}

	// Read initial request
	reader := bufio.NewReader(clientConn)
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(strings.TrimSpace(requestLine))
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	target := parts[1]

	// Handle CONNECT requests
	if strings.ToUpper(method) == "CONNECT" {
		s.handleConnect(clientConn, reader, target)
		return
	}

	// Handle regular HTTP requests
	s.handleHTTP(clientConn, reader, requestLine, method, target)
}

func (s *Server) handleConnect(clientConn net.Conn, reader *bufio.Reader, target string) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = "443"
	}

	port, _ := strconv.Atoi(portStr)

	// Check TLS policy
	if s.config.tls.ShouldPassthrough(host, uint16(port)) {
		// Tunnel without interception
		s.tunnelConnection(clientConn, target)
		return
	}

	// For now, tunnel all CONNECT requests
	// TLS interception would be implemented here
	s.tunnelConnection(clientConn, target)
}

func (s *Server) tunnelConnection(clientConn net.Conn, target string) {
	// Connect to upstream
	upstreamConn, err := net.Dial("tcp", target)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstreamConn.Close()

	// Send success response to client
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Record the tunnel in the store (simplified)
	exchange := &core.Exchange{
		Host:     strings.Split(target, ":")[0],
		Port:     443,
		TLS:      true,
		Method:   "CONNECT",
		Path:     target,
		Protocol: core.ProtocolHTTP1,
		StartedMs: uint64(time.Now().UnixMilli()),
	}
	s.config.store.AddExchange(exchange)

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstreamConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, upstreamConn)
		done <- struct{}{}
	}()

	<-done
}

func (s *Server) handleHTTP(clientConn net.Conn, reader *bufio.Reader, requestLine, method, target string) {
	startTime := time.Now()

	// Parse target
	host, port, path := parseTarget(target)
	if host == "" {
		// Try to get from Host header
		headers := readHeaders(reader)
		if h := headers.Get("Host"); h != "" {
			host, port = parseHostPort(h)
		}
	}

	if host == "" {
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	// Read full request
	requestData := readFullRequest(requestLine, reader)

	// Check scope
	inScope := s.config.scope.Contains(host, port, path, false)

	if !inScope {
		// Forward without storing
		s.forwardOnly(clientConn, requestData, host, port)
		return
	}

	// Store request
	reqID, err := s.config.store.Put(requestData, core.DirectionRequest)
	if err != nil {
		s.config.logger.Error("failed to store request", zap.Error(err))
	}

	// Forward to upstream
	responseData, err := s.forwardRequest(requestData, host, port)
	if err != nil {
		s.config.logger.Error("forward failed", zap.Error(err))
		return
	}

	// Store response
	respID, err := s.config.store.Put(responseData, core.DirectionResponse)
	if err != nil {
		s.config.logger.Error("failed to store response", zap.Error(err))
	}

	// Send to client
	clientConn.Write(responseData)

	// Create exchange record
	duration := uint64(time.Since(startTime).Milliseconds())
	exchange := &core.Exchange{
		Request:     reqID,
		Response:    &respID,
		Host:        host,
		Port:        port,
		TLS:         false,
		Method:      method,
		Path:        path,
		DurationMs:  duration,
		StartedMs:   uint64(startTime.UnixMilli()),
		Protocol:    core.ProtocolHTTP1,
		ResponseLen: len(responseData),
	}
	s.config.store.AddExchange(exchange)
}

func parseTarget(target string) (host string, port uint16, path string) {
	if strings.HasPrefix(target, "http://") {
		target = target[7:]
		parts := strings.SplitN(target, "/", 2)
		hostPort := parts[0]
		if len(parts) > 1 {
			path = "/" + parts[1]
		} else {
			path = "/"
		}
		host, port = parseHostPort(hostPort)
	} else if strings.HasPrefix(target, "https://") {
		target = target[8:]
		parts := strings.SplitN(target, "/", 2)
		hostPort := parts[0]
		if len(parts) > 1 {
			path = "/" + parts[1]
		} else {
			path = "/"
		}
		host, port = parseHostPort(hostPort)
	} else {
		// Origin form
		path = target
	}
	return
}

func parseHostPort(hostPort string) (host string, port uint16) {
	lastColon := strings.LastIndex(hostPort, ":")
	if lastColon == -1 {
		return hostPort, 80
	}
	host = hostPort[:lastColon]
	p, _ := strconv.Atoi(hostPort[lastColon+1:])
	if p <= 0 || p > 65535 {
		port = 80
	} else {
		port = uint16(p)
	}
	return
}

func readHeaders(reader *bufio.Reader) http.Header {
	headers := make(http.Header)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		line = strings.TrimSpace(line)
		if colon := strings.Index(line, ":"); colon > 0 {
			name := line[:colon]
			value := strings.TrimSpace(line[colon+1:])
			headers.Add(name, value)
		}
	}
	return headers
}

func readFullRequest(requestLine string, reader *bufio.Reader) []byte {
	var buf bytes.Buffer
	buf.WriteString(requestLine)

	// Read headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		buf.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Read body if Content-Length present
	headers := buf.String()
	if clIndex := strings.Index(headers, "Content-Length:"); clIndex != -1 {
		clStart := clIndex + 15
		clEnd := clStart
		for clEnd < len(headers) && headers[clEnd] != '\r' && headers[clEnd] != '\n' {
			clEnd++
		}
		if cl, err := strconv.Atoi(strings.TrimSpace(headers[clStart:clEnd])); err == nil && cl > 0 {
			body := make([]byte, cl)
			io.ReadFull(reader, body)
			buf.Write(body)
		}
	}

	return buf.Bytes()
}

func (s *Server) forwardOnly(clientConn net.Conn, requestData []byte, host string, port uint16) {
	upstreamConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	defer upstreamConn.Close()

	upstreamConn.Write(requestData)

	// Copy response back
	io.Copy(clientConn, upstreamConn)
}

func (s *Server) forwardRequest(requestData []byte, host string, port uint16) ([]byte, error) {
	upstreamConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	defer upstreamConn.Close()

	upstreamConn.Write(requestData)

	// Read response
	var response bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := upstreamConn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return response.Bytes(), err
		}
	}

	return response.Bytes(), nil
}

// Interceptor handles request/response interception.
type Interceptor struct {
	mu       sync.RWMutex
	enabled  bool
	rules    *InterceptRules
	heldReqs chan *HeldRequest
}

// InterceptRules holds interception rules.
type InterceptRules struct {
	requestRules  []InterceptRule
	responseRules []InterceptRule
}

// InterceptRule defines when to intercept.
type InterceptRule struct {
	Field     string
	Operator  string
	Value     string
	Enabled   bool
}

// HeldRequest represents a held request waiting for review.
type HeldRequest struct {
	ID      uint64
	Data    []byte
	Reason  string
	Respond chan HeldResponse
}

// HeldResponse is the response to a held request.
type HeldResponse struct {
	Action string // "send", "drop", "modify"
	Data   []byte
}

// MatchReplaceRules holds match and replace rules.
type MatchReplaceRules struct {
	mu    sync.RWMutex
	rules []MatchReplaceRule
}

// MatchReplaceRule defines a match and replace operation.
type MatchReplaceRule struct {
	Match     string
	Replace   string
	Regex     bool
	Category  string
	Target    string
	Enabled   bool
}

// PassiveScanner runs passive security scans.
type PassiveScanner struct {
	store *core.TrafficStore
}

// NewPassiveScanner creates a new passive scanner.
func NewPassiveScanner(store *core.TrafficStore) *PassiveScanner {
	return &PassiveScanner{
		store: store,
	}
}
