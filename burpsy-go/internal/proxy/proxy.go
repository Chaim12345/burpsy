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
	"errors"
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

// leafValidityDays is the leaf lifetime in days. 397 matches the Rust port's
// `MAX_LEAF_DAYS` (and Burp and mitmproxy): Chrome's 398-day cap applies only
// to publicly-trusted CAs and could tighten, so 397 is the free, future-proof
// choice. The NotBefore backdate absorbs a client clock a few minutes fast.
const leafValidityDays = 397

// TlsEngine handles TLS certificate generation and signing.
type TlsEngine struct {
	mu       sync.Mutex
	caCert   *x509.Certificate
	caPriv   *rsa.PrivateKey
	certPool sync.Map // cache of generated certificates
}

// GetCertificate returns or generates a certificate for the given host.
//
// The CA is parsed once at load (see LoadOrGenerateCA), so a cache miss signs
// and stores rather than re-decoding the CA PEMs. The leaf's NotBefore/NotAfter
// window is clamped to the CA's own validity, so a CA near the end of its life
// cannot mint a leaf that outlives it. The presented chain is leaf-then-CA —
// Firefox imports only roots from the Windows store and expects the server to
// supply the rest of the path, which is what lets a trust store holding just
// the CA validate every leaf.
func (e *TlsEngine) GetCertificate(host string) (*tls.Certificate, error) {
	// Check cache first
	if cert, ok := e.certPool.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-checked after taking the lock: two concurrent misses for the same
	// host would otherwise mint two leaves, and only one would be kept.
	if cert, ok := e.certPool.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

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

	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.AddDate(0, 0, leafValidityDays)
	if notBefore.Before(e.caCert.NotBefore) {
		notBefore = e.caCert.NotBefore
	}
	if notAfter.After(e.caCert.NotAfter) {
		notAfter = e.caCert.NotAfter
	}

	hostTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		// IP targets are validated against IP SANs, not DNS names.
		hostTemplate.IPAddresses = []net.IP{ip}
	} else {
		hostTemplate.DNSNames = []string{host}
	}

	// Sign with CA
	leafDER, err := x509.CreateCertificate(rand.Reader, &hostTemplate, e.caCert, &hostPriv.PublicKey, e.caPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create host certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host certificate: %w", err)
	}

	// Leaf first, then the CA. Leaf is filled in so crypto/tls does not
	// re-parse the DER on every handshake.
	cert := &tls.Certificate{
		Certificate: [][]byte{leafDER, e.caCert.Raw},
		PrivateKey:  hostPriv,
		Leaf:        leaf,
	}

	// Cache it
	e.certPool.Store(host, cert)
	return cert, nil
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

	// Try to load existing CA. A regenerated CA would invalidate any trust-store
	// install, so an existing pair is always preferred over minting a new one.
	certData, certErr := os.ReadFile(caCertPath)
	keyData, keyErr := os.ReadFile(caKeyPath)
	if certErr == nil && keyErr == nil {
		return loadCA(certData, keyData)
	}

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
		// Backdated: a client clock a few minutes fast must not reject a
		// freshly minted root.
		NotBefore:             time.Now().Add(-1 * time.Hour),
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
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA: %w", err)
	}

	// Encode certificate
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	// Encode private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	// The certificate is public; only the key is protected. The key is what
	// re-signing from it would need, so it is 0600.
	if err := os.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}
	if err := os.WriteFile(caKeyPath, caKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to save CA key: %w", err)
	}

	return &TlsEngine{
		caCert: caCert,
		caPriv: priv,
	}, nil
}

// loadCA parses and validates a persisted CA pair, returning a ready engine.
// Validation happens here rather than at the first handshake: a non-CA
// certificate, a key that does not match the certificate, or an expired root
// would otherwise surface as a confusing leaf-mint failure mid-session.
func loadCA(certData, keyData []byte) (*TlsEngine, error) {
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, errors.New("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, errors.New("failed to decode CA key PEM")
	}
	caKey, err := parseCAKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	if err := validateCA(caCert, caKey); err != nil {
		return nil, err
	}

	return &TlsEngine{
		caCert: caCert,
		caPriv: caKey,
	}, nil
}

// parseCAKey accepts both PKCS#1 and PKCS#8 encodings, so a CA persisted by any
// Go version or external tool is loadable.
func parseCAKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	any, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("failed to parse CA key PEM")
	}
	key, ok := any.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is %T, want *rsa.PrivateKey", any)
	}
	return key, nil
}

// validateCA refuses a CA pair that would fail cryptically mid-handshake. The
// checks mirror mitmproxy-go's load validation: the certificate must be a CA
// with certificate-signing permission, the key must be the certificate's key,
// and the certificate must be within its validity window.
func validateCA(caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	if !caCert.IsCA || !caCert.BasicConstraintsValid {
		return errors.New("CA certificate is not a certificate authority")
	}
	if caCert.KeyUsage != 0 && caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("CA certificate does not permit certificate signing")
	}
	if err := caKey.Validate(); err != nil {
		return fmt.Errorf("invalid CA private key: %w", err)
	}
	pub, ok := caCert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&caKey.PublicKey) {
		return errors.New("CA certificate and private key do not match")
	}
	now := time.Now()
	if now.Before(caCert.NotBefore) || now.After(caCert.NotAfter) {
		return errors.New("CA certificate is not currently valid")
	}
	return nil
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
	// stripWsExtensions removes the client's Sec-WebSocket-Extensions offer
	// from a handshake before forwarding it. See WithStripWsExtensions.
	stripWsExtensions bool
}

// NewProxyConfig creates a new proxy configuration.
func NewProxyConfig(store *core.TrafficStore) *ProxyConfig {
	return &ProxyConfig{
		store:  store,
		tls:    NewTlsPolicy(),
		scope:  core.NewScopeAllowEverything(),
		logger: zap.NewNop(), // Default to nop logger
		// On, matching Burp's default. A proxy that let permessage-deflate be
		// negotiated would record DEFLATE blocks and call them messages, so the
		// safe setting is the one that keeps the capture readable.
		stripWsExtensions: true,
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

// WithStripWsExtensions controls whether a WebSocket handshake's
// Sec-WebSocket-Extensions offer is removed before the request is forwarded.
//
// On by default, and deliberately a switch rather than an unconditional
// rewrite. Stripping keeps captures readable — see
// core.StripWsExtensionsHeader for why a negotiated permessage-deflate turns
// every recorded payload into an opaque DEFLATE block — but an origin is free
// to require the extension, and a tester who needs to reach such an origin must
// not be locked out by a capture-quality decision. With stripping off, frames
// that arrive compressed are recorded with a note saying so; they are never
// passed off as plaintext.
func (c *ProxyConfig) WithStripWsExtensions(strip bool) *ProxyConfig {
	c.stripWsExtensions = strip
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
	// The upstream side reads through one persistent buffered reader for the
	// life of the connection. A fresh bufio per response would discard whatever
	// it had buffered beyond the response body — which, on a keep-alive
	// connection, is the beginning of the next response — and it is what lets
	// the WebSocket handoff below keep the frame bytes that arrived with a 101.
	upstreamBR := bufio.NewReader(upstream)
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

		// Rewritten before the scope check and before the store, for the same
		// reasons as the plain path above: the wire bytes and the recorded
		// bytes must be the same bytes.
		var wsStripped []string
		if core.IsWsUpgradeRequest(requestData) {
			requestData, wsStripped = s.stripWsHandshake(requestData)
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

		// A request that asked to upgrade hands the connection off when the
		// origin answers 101. The response head must be read on its own,
		// because the bytes after it are WebSocket frames, not a response body.
		// This also ends the keep-alive loop — after an upgrade there are no
		// more HTTP requests on this connection, by definition.
		if core.IsWsUpgradeRequest(requestData) {
			head, err := httputil.ReadResponseHead(upstreamBR)
			if err != nil {
				return
			}
			if !core.IsWsUpgradeResponse(head) {
				body, err := httputil.ReadResponseBody(upstreamBR, head)
				if err != nil {
					return
				}
				responseData := append(head, body...)
				if !s.handleTLSResponse(tlsClient, method, reqHost, reqPort, path, reqID, inScope, responseData, startTime) {
					return
				}
				continue
			}

			exchangeID := uint64(0)
			if inScope {
				respID, err := s.config.store.Put(head, core.DirectionResponse)
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
					Status:      parseStatusCode(head),
					DurationMs:  uint64(time.Since(startTime).Milliseconds()),
					StartedMs:   uint64(startTime.UnixMilli()),
					Protocol:    core.ProtocolHTTP1,
					ResponseLen: len(head),
					// A handshake this proxy rewrote must not look pristine.
					Notes: wsStripNote(wsStripped),
				}
				s.config.store.AddExchange(exchange)
				exchangeID = exchange.ID
			}

			if _, err := tlsClient.Write(head); err != nil {
				return
			}
			var capture *wsCapture
			if exchangeID != 0 {
				capture = &wsCapture{scope: s.config.scope, host: reqHost, port: reqPort, tls: true, path: path}
			}
			s.relayWebsocket(exchangeID, tlsClient, br, upstream, upstreamBR, reqHost, reqPort, true, path, capture)
			return
		}

		head, err := httputil.ReadResponseHead(upstreamBR)
		if err != nil {
			return
		}
		body, err := httputil.ReadResponseBody(upstreamBR, head)
		if err != nil {
			return
		}
		responseData := append(head, body...)

		if !s.handleTLSResponse(tlsClient, method, reqHost, reqPort, path, reqID, inScope, responseData, startTime) {
			return
		}
	}
}

// handleTLSResponse completes one response in the TLS intercept loop: records
// it and its exchange when the exchange is in scope, applies Match & Replace,
// offers it to the intercept hold queue, and writes it to the client. It
// reports whether the connection should keep serving — an intercept drop ends
// the connection, exactly as the original path did.
func (s *Server) handleTLSResponse(clientConn net.Conn, method string, host string, port uint16, path string, reqID core.MsgId, inScope bool, responseData []byte, startTime time.Time) bool {
	if inScope {
		respID, err := s.config.store.Put(responseData, core.DirectionResponse)
		if err != nil {
			s.config.logger.Error("failed to store response", zap.Error(err))
		}

		exchange := &core.Exchange{
			Request:     reqID,
			Response:    &respID,
			Host:        host,
			Port:        port,
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
			intercept.DirectionResponse, host, port, true, method, path, responseData,
		)); held != nil {
			action, raw := held.Wait()
			if action == intercept.ActionDrop {
				return false
			}
			responseData = raw
		}
	}

	// Return the response to the client.
	if _, err := clientConn.Write(responseData); err != nil {
		return false
	}
	return true
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

	// The extension offer is removed here — after intercept, before the scope
	// check and before anything is stored. Before the scope check because the
	// rewrite decides what goes on the wire and retention is a separate
	// question, so the out-of-scope forward below sends exactly the same bytes
	// as the recorded path. Before the store because what history shows for
	// this request must be what upstream received.
	var wsStripped []string
	if core.IsWsUpgradeRequest(requestData) {
		requestData, wsStripped = s.stripWsHandshake(requestData)
	}

	// Check scope
	inScope := s.config.scope.Contains(host, port, path, false)

	if !inScope {
		// Forward without storing
		s.forwardOnly(clientConn, reader, requestData, host, port)
		return
	}

	// Store request
	reqID, err := s.config.store.Put(requestData, core.DirectionRequest)
	if err != nil {
		s.config.logger.Error("failed to store request", zap.Error(err))
	}

	// A request that asked to upgrade hands the connection off when the origin
	// answers 101: the response head must be read on its own, because the bytes
	// after it are WebSocket frames, not a response body. Gated on the request,
	// so every other request takes the identical path it always took.
	if core.IsWsUpgradeRequest(requestData) {
		s.handleWebSocketUpgrade(clientConn, reader, method, host, port, path, requestData, reqID, startTime, wsStripped)
		return
	}

	// Forward to upstream
	responseData, err := s.forwardRequest(requestData, host, port)
	if err != nil {
		s.config.logger.Error("forward failed", zap.Error(err))
		return
	}

	s.completeResponse(clientConn, method, host, port, false, path, requestData, reqID, responseData, startTime)
}

// completeResponse stores a response, applies Match & Replace, offers it to the
// intercept hold queue, writes it to the client, and records the exchange.
// Shared by the ordinary path and by a refused WebSocket upgrade, so a 4xx
// refusal is handled exactly like any other response.
func (s *Server) completeResponse(clientConn net.Conn, method string, host string, port uint16, tls bool, path string, requestData []byte, reqID core.MsgId, responseData []byte, startTime time.Time) {
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
			intercept.DirectionResponse, host, port, tls, method, path, responseData,
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
		TLS:         tls,
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

func (s *Server) forwardOnly(clientConn net.Conn, clientReader *bufio.Reader, requestData []byte, host string, port uint16) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	upstreamConn, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer upstreamConn.Close()

	upstreamConn.Write(requestData)

	// An upgrade request needs both directions for the life of the connection:
	// after a 101 the client keeps talking, and a one-way copy would leave it
	// able to receive but unable to send. Gated on the request rather than
	// applied unconditionally: an ordinary response ends at upstream EOF, and
	// additionally waiting for the client to close would hold a goroutine per
	// idle browser connection. Nothing is recorded either way — out-of-scope
	// traffic is forwarded, not retained.
	if core.IsWsUpgradeRequest(requestData) {
		br := bufio.NewReader(upstreamConn)
		head, err := httputil.ReadResponseHead(br)
		if err != nil {
			return
		}
		if core.IsWsUpgradeResponse(head) {
			clientConn.Write(head)
			s.relayWebsocket(0, clientConn, clientReader, upstreamConn, br,
				host, port, false, "", nil)
			return
		}
		body, err := httputil.ReadResponseBody(br, head)
		if err != nil {
			return
		}
		clientConn.Write(append(head, body...))
		return
	}

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
