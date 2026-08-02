package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// DefaultCADir returns the default CA directory path.
func DefaultCADir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		// Fall back to the legacy home-directory location.
		if home, homeErr := os.UserHomeDir(); homeErr == nil {
			return filepath.Join(home, ".burpsy", "ca")
		}
		return "~/.burpsy/ca"
	}
	return filepath.Join(configDir, "burpsy", "ca")
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
	p.mu.Unlock()
	p.engine = engine
}

// AddPassthroughPort adds a port to passthrough.
func (p *TlsPolicy) AddPassthroughPort(port uint16) {
	p.mu.Lock()
	p.mu.Unlock()
	p.passthroughPorts = append(p.passthroughPorts, port)
}

// WithCommonDefaults returns a TLS policy with common pinned hosts.
func (p *TlsPolicy) WithCommonDefaults() *TlsPolicy {
	p.mu.Lock()
	defer p.mu.Unlock()
	common := []string{
		"*.apple.com", "*.google.com", "*.microsoft.com", "*.amazon.com",
		"*.github.com", "*.gitlab.com", "*.bitbucket.org",
		"*.cloudflare.com", "*.akamai.com", "*.fastly.com",
	}
	for _, h := range common {
		p.passthrough = append(p.passthrough, h)
	}
	return p
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
	caPriv   *rsa.PrivateKey
	certPool sync.Map // cache of generated certificates
}

// GetCertificate returns or generates a certificate for the given host.
func (e *TlsEngine) GetCertificate(host string) (*tls.Certificate, error) {
	// Check cache first
	if cert, ok := e.certPool.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Parse CA certificate
	caBlock, _ := pem.Decode(e.caCert)
	if caBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	keyBlock, _ := pem.Decode(e.caKey)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA key: %w", err)
	}
	e.caPriv = priv.(*rsa.PrivateKey)

	// Generate new key for this host
	hostPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	hostTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 30, 0), // Valid for 30 days
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		// IP targets are validated against IP SANs, not DNS names.
		hostTemplate.IPAddresses = []net.IP{ip}
	} else {
		hostTemplate.DNSNames = []string{host}
	}

	// Sign with CA
	hostBytes, err := x509.CreateCertificate(rand.Reader, &hostTemplate, caCert, &hostPriv.PublicKey, e.caPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create host certificate: %w", err)
	}

	// Encode certificate
	hostCertPEM := new(bytes.Buffer)
	if err := pem.Encode(hostCertPEM, &pem.Block{Type: "CERTIFICATE", Bytes: hostBytes}); err != nil {
		return nil, fmt.Errorf("failed to encode host certificate: %w", err)
	}

	// Encode private key
	hostKeyPEM := new(bytes.Buffer)
	hostPrivBytes, err := x509.MarshalPKCS8PrivateKey(hostPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal host key: %w", err)
	}
	if err := pem.Encode(hostKeyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: hostPrivBytes}); err != nil {
		return nil, fmt.Errorf("failed to encode host key: %w", err)
	}

	// Create tls.Certificate
	cert, err := tls.X509KeyPair(hostCertPEM.Bytes(), hostKeyPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	// Cache it
	e.certPool.Store(host, &cert)
	return &cert, nil
}

// LoadOrGenerateCA loads or generates a CA certificate.
func LoadOrGenerateCA(caDir string) (*TlsEngine, error) {
	// Expand tilde if present
	if strings.HasPrefix(caDir, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			caDir = filepath.Join(homeDir, caDir[2:])
		}
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}

	caCertPath := filepath.Join(caDir, "ca.crt")
	caKeyPath := filepath.Join(caDir, "ca.key")

	var caCert []byte
	var caKey []byte

	// Try to load existing CA
	certData, certErr := os.ReadFile(caCertPath)
	keyData, keyErr := os.ReadFile(caKeyPath)

	if certErr == nil && keyErr == nil {
		// Load existing CA
		caCert = certData
		caKey = keyData
	} else {
		// Generate new CA
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}

		// Create CA certificate template
		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, fmt.Errorf("failed to generate serial number: %w", err)
		}

		caTemplate := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"burpsy"},
				CommonName:   "burpsy MITM Proxy",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}

		// Self-sign the CA certificate
		caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &priv.PublicKey, priv)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA certificate: %w", err)
		}

		// Encode certificate
		caCertPEM := new(bytes.Buffer)
		if err := pem.Encode(caCertPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
			return nil, fmt.Errorf("failed to encode CA certificate: %w", err)
		}
		caCert = caCertPEM.Bytes()

		// Encode private key
		caKeyPEM := new(bytes.Buffer)
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		if err := pem.Encode(caKeyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
			return nil, fmt.Errorf("failed to encode CA key: %w", err)
		}
		caKey = caKeyPEM.Bytes()

		// Save to disk
		if err := os.WriteFile(caCertPath, caCert, 0600); err != nil {
			return nil, fmt.Errorf("failed to save CA certificate: %w", err)
		}
		if err := os.WriteFile(caKeyPath, caKey, 0600); err != nil {
			return nil, fmt.Errorf("failed to save CA key: %w", err)
		}
	}

	return &TlsEngine{
		caCert: caCert,
		caKey:  caKey,
	}, nil
}

// ProxyConfig holds all configuration for the proxy.
type ProxyConfig struct {
	store        *core.TrafficStore
	tls          *TlsPolicy
	scope        *core.Scope
	matchReplace *matchreplace.RuleSet
	scanner      *scanner.PassiveScanner
	findings     *core.FindingStore
	intercept    *intercept.Engine
	logger       *zap.Logger
}

// NewProxyConfig creates a new proxy configuration.
func NewProxyConfig(store *core.TrafficStore) *ProxyConfig {
	return &ProxyConfig{
		store:  store,
		tls:    NewTlsPolicy(),
		scope:  core.NewScopeAllowEverything(),
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

// WithScanner sets the passive scanner used to check captured traffic.
func (c *ProxyConfig) WithScanner(scanner *scanner.PassiveScanner) *ProxyConfig {
	c.scanner = scanner
	return c
}

// WithFindings sets the finding store that passive scan results are written to.
func (c *ProxyConfig) WithFindings(fs *core.FindingStore) *ProxyConfig {
	c.findings = fs
	return c
}

// WithIntercept sets the intercept hold-queue engine. When set, matching
// requests and responses are held for the operator instead of forwarded.
func (c *ProxyConfig) WithIntercept(engine *intercept.Engine) *ProxyConfig {
	c.intercept = engine
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

	// Passthrough hosts (or no engine configured) are blind-tunnelled.
	if s.config.tls.ShouldPassthrough(host, uint16(port)) || s.config.tls.engine == nil {
		s.tunnelConnection(clientConn, target)
		return
	}

	// Intercept: present a CA-signed leaf cert to the client, terminate TLS,
	// and re-encrypt to the origin so traffic can be recorded and scanned.
	s.interceptTLS(clientConn, host, uint16(port))
}

// interceptTLS decrypts a CONNECT tunnel: it answers with 200 Connection
// Established, terminates the client's TLS session with a leaf certificate
// signed by the configured CA, opens a second TLS session to the origin, and
// forwards HTTP in the clear between them while recording exchanges.
func (s *Server) interceptTLS(clientConn net.Conn, host string, port uint16) {
	// Signal the client that the tunnel is established.
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Sign a leaf certificate for this host.
	leaf, err := s.config.tls.engine.GetCertificate(host)
	if err != nil {
		s.config.logger.Error("certificate signing failed", zap.String("host", host), zap.Error(err))
		return
	}

	// TLS server side: terminate the client's TLS session.
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
	})
	if err := tlsClient.Handshake(); err != nil {
		// Handshake failures are common when clients reject the CA; drop quietly.
		return
	}
	defer tlsClient.Close()

	// TLS client side: connect to the origin.
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	upstream, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // standard testing-proxy behavior
	})
	if err != nil {
		s.config.logger.Error("upstream TLS dial failed", zap.String("host", host), zap.Error(err))
		return
	}
	defer upstream.Close()

	// Serve HTTP over the decrypted channel, recording exchanges.
	br := bufio.NewReader(tlsClient)
	for {
		requestLine, err := br.ReadString('\n')
		if err != nil {
			return
		}
		parts := strings.Fields(strings.TrimSpace(requestLine))
		if len(parts) < 2 {
			return
		}
		method := parts[0]
		reqTarget := parts[1]

		// Requests inside the tunnel are origin-form: GET /path HTTP/1.1.
		reqHost, reqPort, path := parseTarget(reqTarget)
		if reqHost == "" {
			reqHost, reqPort = host, port
		}

		requestData := readFullRequest(requestLine, br)
		startTime := time.Now()

		// Intercept: hold the decrypted request before it is forwarded upstream.
		if s.config.intercept != nil {
			if held := s.config.intercept.Hold(intercept.ParseMessage(
				intercept.DirectionRequest, reqHost, reqPort, true, method, path, requestData,
			)); held != nil {
				action, raw := held.Wait()
				if action == intercept.ActionDrop {
					return
				}
				requestData = raw
			}
		}

		inScope := s.config.scope.Contains(reqHost, reqPort, path, true)
		var reqID core.MsgId
		if inScope {
			reqID, err = s.config.store.Put(requestData, core.DirectionRequest)
			if err != nil {
				s.config.logger.Error("failed to store request", zap.Error(err))
			}
		}

		// Forward over the persistent upstream connection.
		if _, err := upstream.Write(requestData); err != nil {
			return
		}
		responseData, err := readHTTPResponse(upstream)
		if err != nil {
			return
		}

		if inScope {
			respID, err := s.config.store.Put(responseData, core.DirectionResponse)
			if err != nil {
				s.config.logger.Error("failed to store response", zap.Error(err))
			}

			exchange := &core.Exchange{
				Request:     reqID,
				Response:    &respID,
				Host:        reqHost,
				Port:        reqPort,
				TLS:         true,
				Method:      method,
				Path:        path,
				Status:      parseStatusCode(responseData),
				DurationMs:  uint64(time.Since(startTime).Milliseconds()),
				StartedMs:   uint64(startTime.UnixMilli()),
				Protocol:    core.ProtocolHTTP1,
				ResponseLen: len(responseData),
			}
			s.config.store.AddExchange(exchange)
			s.runPassiveScan(exchange)
		}

		// Apply Match & Replace on response
		if s.config.matchReplace != nil && s.config.matchReplace.Affects(matchreplace.DirResponse) {
			responseData = s.config.matchReplace.Apply(matchreplace.DirResponse, responseData)
		}

		// Intercept: hold the response before it reaches the client.
		if s.config.intercept != nil {
			if held := s.config.intercept.Hold(intercept.ParseMessage(
				intercept.DirectionResponse, reqHost, reqPort, true, method, path, responseData,
			)); held != nil {
				action, raw := held.Wait()
				if action == intercept.ActionDrop {
					return
				}
				responseData = raw
			}
		}

		// Return the response to the client.
		if _, err := tlsClient.Write(responseData); err != nil {
			return
		}
	}
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

	// Record the tunnel in the store (simplified: no decrypted request/response
	// messages, just the CONNECT tunnel itself).
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = strings.Split(target, ":")[0]
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 443
	}
	exchange := &core.Exchange{
		Host:      host,
		Port:      uint16(port),
		TLS:       true,
		Method:    "CONNECT",
		Path:      target,
		Protocol:  core.ProtocolHTTP1,
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

	// Intercept: hold the request for the operator before it is forwarded.
	// A held request blocks this connection until resolved; a drop closes the
	// connection without reaching upstream.
	if s.config.intercept != nil {
		if held := s.config.intercept.Hold(intercept.ParseMessage(
			intercept.DirectionRequest, host, port, false, method, path, requestData,
		)); held != nil {
			action, raw := held.Wait()
			if action == intercept.ActionDrop {
				clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
				return
			}
			requestData = raw
		}
	}

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

	// Apply Match & Replace on response
	if s.config.matchReplace != nil && s.config.matchReplace.Affects(matchreplace.DirResponse) {
		responseData = s.config.matchReplace.Apply(matchreplace.DirResponse, responseData)
	}

	// Intercept: hold the response for the operator before it reaches the client.
	if s.config.intercept != nil {
		if held := s.config.intercept.Hold(intercept.ParseMessage(
			intercept.DirectionResponse, host, port, false, method, path, responseData,
		)); held != nil {
			action, raw := held.Wait()
			if action == intercept.ActionDrop {
				return
			}
			responseData = raw
		}
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
		Status:      parseStatusCode(responseData),
		DurationMs:  duration,
		StartedMs:   uint64(startTime.UnixMilli()),
		Protocol:    core.ProtocolHTTP1,
		ResponseLen: len(responseData),
	}
	s.config.store.AddExchange(exchange)
	s.runPassiveScan(exchange)
}

// runPassiveScan runs the configured passive scanner over an exchange and
// persists any findings into the shared finding store.
func (s *Server) runPassiveScan(exchange *core.Exchange) {
	if s.config.scanner == nil || s.config.findings == nil {
		return
	}
	findings := s.config.scanner.Scan(exchange)
	for _, f := range findings {
		s.config.findings.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
		})
	}
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
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	upstreamConn, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer upstreamConn.Close()

	upstreamConn.Write(requestData)

	// Copy exactly one response back; keep-alive connections never EOF.
	if resp, err := readHTTPResponse(upstreamConn); err == nil {
		clientConn.Write(resp)
	}
}

func (s *Server) forwardRequest(requestData []byte, host string, port uint16) ([]byte, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	upstreamConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer upstreamConn.Close()

	if _, err := upstreamConn.Write(requestData); err != nil {
		return nil, err
	}

	return readHTTPResponse(upstreamConn)
}

// readHTTPResponse reads one complete HTTP response from conn, respecting
// Content-Length and chunked transfer encoding instead of waiting for EOF
// (which never comes on a keep-alive connection).
func readHTTPResponse(conn net.Conn) ([]byte, error) {
	return httputil.ReadHTTPResponse(conn)
}

// parseStatusCode extracts the 3-digit status code from an HTTP response's
// first line ("HTTP/1.1 200 OK"). It returns nil when the bytes do not parse
// as a response, so an absent status is recorded honestly as absent rather
// than guessed.
func parseStatusCode(raw []byte) *uint16 {
	idx := bytes.Index(raw, []byte("\r\n"))
	var line []byte
	if idx < 0 {
		idx = bytes.IndexByte(raw, '\n')
		if idx < 0 {
			return nil
		}
		line = raw[:idx]
	} else {
		line = raw[:idx]
	}
	fields := bytes.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	code, err := strconv.Atoi(string(fields[1]))
	if err != nil || code < 100 || code > 599 {
		return nil
	}
	u := uint16(code)
	return &u
}
