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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/scanner"
	upstreamproxy "github.com/burpsy-go/burpsy/internal/upstream"
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
//
// `defer p.mu.Unlock()`, not `p.mu.Unlock()`: as written the lock was taken and released before the
// write, so the assignment ran unsynchronised while readers held the lock — a data race the mutex
// looked like it was preventing.
func (p *TlsPolicy) WithEngine(engine *TlsEngine) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.engine = engine
}

// AddPassthroughPort adds a port to passthrough. Same unlock-before-write defect as WithEngine.
func (p *TlsPolicy) AddPassthroughPort(port uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passthroughPorts = append(p.passthroughPorts, port)
}

// Passthrough returns a copy of the host patterns currently passed through without interception.
// A copy, because callers render this list in the UI while the proxy keeps matching against it.
func (p *TlsPolicy) Passthrough() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, len(p.passthrough))
	copy(out, p.passthrough)
	return out
}

// RemovePassthrough removes the first exact match of pattern and reports whether one was removed.
// Exact, not glob-equal: "*.bank.test" and "bank.test" are different rules an operator added
// deliberately, and removing by wildcard equality would delete a rule they did not select.
func (p *TlsPolicy) RemovePassthrough(pattern string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, existing := range p.passthrough {
		if existing == pattern {
			p.passthrough = append(p.passthrough[:i], p.passthrough[i+1:]...)
			return true
		}
	}
	return false
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
	// clientCerts supplies the TLS client certificate to present on the upstream
	// leg of an intercepted connection. Nil — the default — means none is ever
	// offered. See WithClientCerts.
	clientCerts alpn.ClientCertSource
	// stripWsExtensions removes the client's Sec-WebSocket-Extensions offer
	// from a handshake before forwarding it. See WithStripWsExtensions.
	stripWsExtensions bool
	// options is the live, operator-editable option set: the response modification
	// rules and the Accept-Encoding strip. Never nil after NewProxyConfig, and the
	// same pointer the web API holds — see WithOptions and internal/proxy/options.go.
	options *Options
	// upstream is the per-destination upstream proxy policy this proxy's origin-facing leg follows.
	// Nil dials origins directly, which is what this package did before the policy existed. Shared by
	// reference with internal/sender and with the /api/network/proxy handler, so an edit made in the
	// console reaches this leg without a restart — see internal/upstream.
	upstream *upstreamproxy.Policy
}

// NewProxyConfig creates a new proxy configuration.
func NewProxyConfig(store *core.TrafficStore) *ProxyConfig {
	return &ProxyConfig{
		store:   store,
		tls:     NewTlsPolicy(),
		scope:   core.NewScopeAllowEverything(),
		options: NewOptions(),
		logger:  zap.NewNop(), // Default to nop logger
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

// WithMatchReplace sets the match-and-replace rule set the proxy applies to live
// traffic. The same *matchreplace.RuleSet the web layer mutates is attached here — not
// a copy — so a rule an operator edits on the Match & Replace page takes effect on the
// wire, and the list that page renders can never disagree with the rules the proxy
// actually honours. Nil (the default) applies no rules, which is why every read of the
// field below is nil-guarded. cmd/burpsy shares one object between this config and the
// web server for exactly the reason it shares one intercept.Engine.
func (c *ProxyConfig) WithMatchReplace(rs *matchreplace.RuleSet) *ProxyConfig {
	c.matchReplace = rs
	return c
}

// WithUpstreamProxy routes this proxy's origin-facing leg through an upstream proxy policy.
//
// The policy is held by reference and consulted per dial, so a rule added through
// /api/network/proxy applies to the next connection this listener opens — a restart would be the wrong
// shape for a setting an operator changes while a browser is pointed at the proxy. Attach records that
// this surface holds it, which is what lets the API report that a rule reaches the listener and not
// only burpsy's own senders.
func (c *ProxyConfig) WithUpstreamProxy(policy *upstreamproxy.Policy) *ProxyConfig {
	c.upstream = policy
	if policy != nil {
		policy.Attach("proxy")
	}
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

// WithClientCerts sets the per-host client-certificate source consulted on the
// upstream leg of an intercepted TLS connection.
//
// Nil-means-off, and the nil case is the one to keep cheap: it is what every
// session without a client certificate configured runs, and it must cost nothing
// on a dial. alpn.Dialer installs no handshake callback at all when this is nil,
// so the common path is byte-for-byte the dial the proxy made before.
//
// This is the leg that makes TLS client authentication work through the proxy.
// The browser's own certificate cannot reach the origin — the browser is talking
// to burpsy's leaf, and burpsy opens a second connection onward — so before this
// existed the only way to reach such an app was to put its host on the TLS
// passthrough list, which is to say to give up interception entirely. ROADMAP.md
// lists exactly that as a reason hosts land on the passthrough list; this is the
// answer to it.
func (c *ProxyConfig) WithClientCerts(source alpn.ClientCertSource) *ProxyConfig {
	c.clientCerts = source
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

// WithOptions attaches the live option set, so the response modification rules and
// the Accept-Encoding strip can be turned on and off without restarting the proxy.
//
// The same pointer must be handed to the web server (web.Server.WithProxyOptions),
// for the reason WithTlsPolicy states about the passthrough list: two option sets
// would let the panel describe rules the relay is not applying. Nil leaves the
// config's own set in place rather than disabling the feature, so a caller that
// passes nil by accident gets "every rule off" instead of a nil dereference on the
// response path.
func (c *ProxyConfig) WithOptions(options *Options) *ProxyConfig {
	if options != nil {
		c.options = options
	}
	return c
}

// Options returns the live option set, for a caller that built the config and now
// needs to hand the same pointer to the web server.
func (c *ProxyConfig) Options() *Options { return c.options }

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

	// Bound the initial request line read: without a deadline a client that
	// opens many connections and never sends a newline pins one goroutine per
	// connection with no limit (slowloris). 30 s is generous for a line and
	// short enough to reclaim idle goroutines.
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	}

	// Read initial request
	reader := bufio.NewReader(clientConn)
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	// The request line is in; the rest of the exchange uses its own framing
	// (Content-Length / chunked / EOF), so clear the line-read deadline.
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetReadDeadline(time.Time{})
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

	// A malformed port must not silently become 0 (which then fails a dial to
	// :0). Fall back to the HTTPS default rather than guessing.
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		port = 443
	}

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

	clientOffer, replay, err := peekClientALPN(clientConn)
	if err != nil {
		return
	}

	intercepting := s.config.intercept != nil && s.config.intercept.Enabled()
	offer := AlpnOffer(clientOffer, intercepting)
	if len(clientOffer) > 0 && len(offer) == 0 {
		s.config.logger.Warn("client ALPN offer cannot be carried",
			zap.String("host", host),
			zap.Strings("offered", clientOffer),
			zap.Bool("intercepting", intercepting))
		return
	}

	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	upstream, negotiated, err := s.dialUpstreamTLS(host, addr, offer)
	if err != nil {
		s.config.logger.Error("upstream TLS dial failed", zap.String("host", host), zap.Error(err))
		return
	}
	defer upstream.Close()

	protocol, err := NegotiatedProtocol(negotiated)
	if err != nil {
		s.config.logger.Warn("upstream negotiated unknown ALPN",
			zap.String("host", host), zap.String("alpn", negotiated))
		return
	}

	// Sign a leaf certificate for this host.
	leaf, err := s.config.tls.engine.GetCertificate(host)
	if err != nil {
		s.config.logger.Error("certificate signing failed", zap.String("host", host), zap.Error(err))
		return
	}

	// TLS server side: offer the client exactly what the origin chose.
	tlsClient := tls.Server(replay, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   ClientALPNProtos(negotiated),
	})
	if err := tlsClient.Handshake(); err != nil {
		return
	}
	defer tlsClient.Close()

	if protocol == core.ProtocolHTTP2 {
		s.relayH2(tlsClient, upstream, host, port)
		return
	}

	// Serve HTTP/1.1 over the decrypted channel, recording exchanges.
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

		// Apply Match & Replace on the request — same position and same reasoning as the
		// plain path in handleHTTP: before intercept, before the scope-gated store, so the
		// bytes forwarded upstream equal the bytes recorded. Requests inside the tunnel
		// already arrive origin-form, so there is no toOriginForm step to precede it here.
		if s.config.matchReplace != nil && s.config.matchReplace.Affects(matchreplace.DirRequest) {
			requestData = s.config.matchReplace.Apply(matchreplace.DirRequest, requestData)
		}

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
		requestData = s.applyRequestRules(requestData)

		// Scope decides retention, not egress: an excluded request is still
		// forwarded, it is simply not kept. The request bytes are not stored
		// here — both halves of an exchange are put away together by the one
		// producer once it is complete. See handleHTTP.
		inScope := s.config.scope.Contains(reqHost, reqPort, path, true)

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
				if !s.handleTLSResponse(tlsClient, method, reqHost, reqPort, path, requestData, inScope, responseData, startTime) {
					return
				}
				continue
			}

			// The handshake goes through the same producer as any other exchange;
			// see handleWebSocketUpgrade for why it is recorded before the relay
			// starts rather than when the socket finally closes.
			var handshake *core.Exchange
			if inScope {
				handshake = s.record(scanner.CapturedExchange{
					Host:     reqHost,
					Port:     reqPort,
					TLS:      true,
					Method:   method,
					Path:     path,
					Request:  requestData,
					Response: head,
					Started:  startTime,
					Duration: time.Since(startTime),
					Protocol: core.ProtocolHTTP1,

					// A handshake this proxy rewrote must not look pristine.
					Notes: wsStripNote(wsStripped),
				})
			}

			if _, err := tlsClient.Write(head); err != nil {
				return
			}
			// Frames are captured when the handshake was, and attached to its row.
			// Gated on the row existing rather than on its id being non-zero:
			// exchange 0 is a real id — the first exchange in a fresh store has it
			// — and testing the id silently dropped that connection's frames.
			var capture *wsCapture
			exchangeID := core.ExchangeID(0)
			if handshake != nil {
				exchangeID = handshake.ID
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

		if !s.handleTLSResponse(tlsClient, method, reqHost, reqPort, path, requestData, inScope, responseData, startTime) {
			return
		}
	}
}

// handleTLSResponse completes one response in the TLS intercept loop: applies
// Match & Replace, offers it to the intercept hold queue, writes it to the
// client, and captures the exchange when it is in scope. It reports whether the
// connection should keep serving — an intercept drop ends the connection,
// exactly as the original path did.
//
// Same order, same producer and same reasoning as completeResponse; see there.
// The two used to differ in three ways that nothing chose: this one recorded the
// pre-rewrite bytes, indexed them before the operator had seen them, and had its
// own copy of the exchange literal. Only the retention gate is genuinely
// different, because a tunnel serves whatever the client asks for and scope
// decides which of it is kept.
func (s *Server) handleTLSResponse(clientConn net.Conn, method string, host string, port uint16, path string, requestData []byte, inScope bool, responseData []byte, startTime time.Time) bool {
	// Apply Match & Replace on response
	if s.config.matchReplace != nil && s.config.matchReplace.Affects(matchreplace.DirResponse) {
		responseData = s.config.matchReplace.Apply(matchreplace.DirResponse, responseData)
	}
	// Then the blanket response modification rules. This order, not the other one:
	// a Match & Replace rule is a pattern the operator wrote against the origin's
	// own bytes, and running "remove all JavaScript" first would delete the text
	// their rule was written to find. See applyResponseRules.
	responseData = s.applyResponseRules(responseData)

	// Intercept: hold the response before it reaches the client.
	var notes *string
	keepServing := true
	if s.config.intercept != nil {
		if held := s.config.intercept.Hold(intercept.ParseMessage(
			intercept.DirectionResponse, host, port, true, method, path, responseData,
		)); held != nil {
			action, raw := held.Wait()
			if action == intercept.ActionDrop {
				keepServing = false
				notes = interceptDropNote()
			} else {
				responseData = raw
			}
		}
	}

	// Return the response to the client. A write that fails ends the connection
	// but not the capture: the origin answered, and that is worth recording
	// whether or not the client was still listening.
	if keepServing {
		if _, err := clientConn.Write(responseData); err != nil {
			keepServing = false
		}
	}

	if inScope {
		s.record(scanner.CapturedExchange{
			Host:     host,
			Port:     port,
			TLS:      true,
			Method:   method,
			Path:     path,
			Request:  requestData,
			Response: responseData,
			Started:  startTime,
			Duration: time.Since(startTime),
			Protocol: core.ProtocolHTTP1,

			Notes: notes,
		})
	}
	return keepServing
}

func (s *Server) tunnelConnection(clientConn net.Conn, target string) {
	// Connect to upstream, through the configured upstream proxy when one covers this destination.
	// A blind tunnel is the one leg that passes the client's own CONNECT target through unchanged: it
	// is the only string the client gave us, and re-deriving it from a parse would risk tunnelling
	// somewhere other than where the client asked.
	upstreamConn, err := s.dialUpstreamAddr(context.Background(), target)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstreamConn.Close()

	// Send success response to client
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Record the tunnel in the store (simplified: no decrypted request/response
	// messages, just the CONNECT tunnel itself).
	//
	// # Why this one site does not go through scanner.Capture.Record
	//
	// Named, not overlooked. Every other capture site in this package is a
	// request/response pair whose bytes the proxy has in hand, and Record's whole
	// job is to put those bytes away and index them. A blind tunnel has no such
	// bytes: this row exists to say "a client opened a tunnel to this host and we
	// did not look inside", and it is asserted as message-less by
	// TestConnectPassthroughBlind, which requires store.Get(ex.Request) to fail.
	// Handing Record an empty pair would be refused (correctly), and synthesising
	// a CONNECT request and a 200 to satisfy it would put bytes in history that
	// no peer ever sent as a side effect of a refactor. The Rust original does
	// synthesise both halves plus a byte-count summary when the tunnel closes; if
	// that is wanted here it is a deliberate change to what a tunnel records, not
	// a consequence of collapsing the capture sites.
	//
	// The cost is that this is the one row in the proxy with no Response, which is
	// the shape internal/web/liveaudit.go's cursor stops at (it cannot tell a row
	// that will never be completed from one still in flight). Record now refuses
	// to mint that shape; this row is not minted by Record.
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
		Source:    core.SourceProxy,
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

	// Read the whole request first, and only then look for a Host header in the bytes
	// we already hold.
	//
	// # Why the order matters — this is Burp's "invisible proxying" case
	//
	// A proxy-aware client sends absolute-form (`GET http://host/path`), so parseTarget
	// has the host and this is the ordinary path. A client that is *not* proxy-aware —
	// one whose DNS or hosts file points the origin's name at this listener — sends
	// origin-form (`GET /path`) with the authority only in the Host header, which is
	// what Burp calls invisible proxying.
	//
	// That case used to be handled by calling readHeaders(reader) here, before
	// readFullRequest. readHeaders consumes the header block off the same *bufio.Reader,
	// so readFullRequest then started at the blank line and returned the request line
	// with no headers at all: the Host was found, and every header the client sent —
	// Host included — was dropped on the way upstream. The origin got a header-less
	// request, history recorded that same header-less request, and nothing anywhere
	// said so. Reading the message once and parsing the Host out of the bytes keeps a
	// single reader position and one copy of the request.
	requestData := readFullRequest(requestLine, reader)
	if host == "" {
		if h := headerValue(requestHead(requestData), "Host"); h != "" {
			host, port = parseHostPort(h)
		}
	}

	if host == "" {
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	// A client speaking to a proxy sends absolute-form — `GET http://host/path HTTP/1.1` (RFC 9112
	// §3.2.2) — but an origin server must be sent origin-form, `GET /path HTTP/1.1` (§3.2.1). This
	// request line was being forwarded verbatim, so the target saw the whole absolute URI as its
	// path. Some servers tolerate it; many route on the path and 404, and any application that
	// inspects its own path sees a different string than the one the operator sent. e2e-go.sh caught
	// it as a mismatch against Rust's behaviour on the very first proxied request.
	//
	// Rewritten here, before intercept and before the store, for the reason the comment further down
	// gives about the WebSocket strip: what history shows and what the operator edits must be the
	// bytes upstream receives. The tunnelled path (handleTunnel, below) needs none of this — requests
	// inside a CONNECT tunnel already arrive in origin-form.
	requestData = toOriginForm(requestData, target, path)

	// Apply Match & Replace on the request. Placed here for the same reason the response
	// direction is applied at the top of completeResponse: everything the proxy does *to*
	// the bytes happens before the operator's hold queue, before the scope check and before
	// anything is stored, so what upstream receives, what the operator edits in the intercept
	// window, and what history records are one set of bytes — the invariant toOriginForm's
	// comment states. Before the scope check specifically so the out-of-scope forwardOnly path
	// below sends the identical rewritten bytes it would have recorded had the host been in
	// scope. Request-direction rules (request_first_line, request_header, request_body) could
	// never fire until this call existed; only DirResponse was ever applied. A body rule that
	// changes the body length has its Content-Length corrected inside Apply when the operator
	// enabled that toggle — the same fix intercept's forward path performs after a body edit.
	if s.config.matchReplace != nil && s.config.matchReplace.Affects(matchreplace.DirRequest) {
		requestData = s.config.matchReplace.Apply(matchreplace.DirRequest, requestData)
	}

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
	// The request-direction options run in the same slot, for the same reasons. See
	// applyRequestRules.
	requestData = s.applyRequestRules(requestData)

	// Check scope
	inScope := s.config.scope.Contains(host, port, path, false)

	if !inScope {
		// Forward without storing
		s.forwardOnly(clientConn, reader, requestData, host, port)
		return
	}

	// The request is not stored here. Both messages are put away together, by the
	// one producer, once the exchange is complete — an exchange is a pair, and
	// storing half of it up front is what let the request id be paired with a
	// response that never arrived. A request whose forward fails below therefore
	// leaves nothing behind at all, rather than an unindexed message no view can
	// reach; the transport failure is logged, which is where it belongs.

	// A request that asked to upgrade hands the connection off when the origin
	// answers 101: the response head must be read on its own, because the bytes
	// after it are WebSocket frames, not a response body. Gated on the request,
	// so every other request takes the identical path it always took.
	if core.IsWsUpgradeRequest(requestData) {
		s.handleWebSocketUpgrade(clientConn, reader, method, host, port, path, requestData, startTime, wsStripped)
		return
	}

	// Forward to upstream
	responseData, err := s.forwardRequest(requestData, host, port)
	if err != nil {
		s.config.logger.Error("forward failed", zap.Error(err))
		return
	}

	s.completeResponse(clientConn, method, host, port, false, path, requestData, responseData, startTime)
}

// completeResponse delivers one response to the client and captures the exchange.
// Shared by the ordinary path and by a refused WebSocket upgrade, so a 4xx
// refusal is handled exactly like any other response.
//
// # The order, which is the only thing this function decides
//
// Everything the proxy does *to* the bytes happens first — Match & Replace, the
// operator's hold queue, the write to the client — and then one call to the
// shared producer with the bytes the client actually received. Those two halves
// are deliberately not interleaved: Record's job is store-put, exchange
// construction and indexing, and a proxy concern moved inside it would be a
// concern the crawler cannot use, which is how the second copy this collapses
// came about in the first place.
//
// Recording *after* the rewrite, rather than the origin's original, is the same
// rule the request side already follows ("what history shows for this request
// must be what upstream received"): an operator who rewrote a response must not
// find bytes nobody ever saw in history, because every later replay and every
// passive scan would then work from them. It is also what the Rust original
// does. The previous code here stored the pre-rewrite bytes and then described
// them with the post-rewrite status and length, so the row disagreed with the
// message it indexed whenever a response rule fired.
func (s *Server) completeResponse(clientConn net.Conn, method string, host string, port uint16, tls bool, path string, requestData []byte, responseData []byte, startTime time.Time) {
	// Apply Match & Replace on response, then the blanket response modification
	// rules — same order, and for the same reason, as handleTLSResponse.
	if s.config.matchReplace != nil && s.config.matchReplace.Affects(matchreplace.DirResponse) {
		responseData = s.config.matchReplace.Apply(matchreplace.DirResponse, responseData)
	}
	responseData = s.applyResponseRules(responseData)

	// Intercept: hold the response for the operator before it reaches the client.
	var notes *string
	dropped := false
	if s.config.intercept != nil {
		if held := s.config.intercept.Hold(intercept.ParseMessage(
			intercept.DirectionResponse, host, port, tls, method, path, responseData,
		)); held != nil {
			action, raw := held.Wait()
			if action == intercept.ActionDrop {
				dropped = true
				notes = interceptDropNote()
			} else {
				responseData = raw
			}
		}
	}

	// Send to client
	if !dropped {
		clientConn.Write(responseData)
	}

	s.record(scanner.CapturedExchange{
		Host:     host,
		Port:     port,
		TLS:      tls,
		Method:   method,
		Path:     path,
		Request:  requestData,
		Response: responseData,
		Started:  startTime,
		Duration: time.Since(startTime),
		Protocol: core.ProtocolHTTP1,

		Notes: notes,
	})
}

// interceptDropNote renders the exchange note for a response the operator
// refused to forward.
//
// The row is recorded at all for the same reason wsStripNote's is: the recorded
// bytes and the bytes the peer saw are not the same, and the difference is
// invisible in the bytes themselves. Recording nothing would let an operator
// drop a response and leave history showing a request that was never answered —
// the one reading of it that is definitely wrong.
func interceptDropNote() *string {
	note := "[burpsy] the operator dropped this response, so the client received nothing. " +
		"The bytes recorded here are the response as it stood when it was dropped — the origin's " +
		"answer, after any Match & Replace rule — which is the only record that it arrived at all."
	return &note
}

// applyResponseRules runs the operator's response modification rules over one
// response, in the one slot where doing so is safe.
//
// That slot is: after Match & Replace, before the intercept hold, before the write to
// the client and before the record. Everything downstream of here — what the operator
// sees held, what the client receives, what history stores, what the passive scanner
// reads — is then the same byte string, which is the invariant every comment on this
// package's capture sites exists to protect. Applying it after the write would put
// bytes in history no peer ever saw; applying it after the record would show the
// operator an origin response the browser never got.
//
// A thin wrapper rather than an inline call because both capture sites need it, and
// because the nil-tolerance belongs in one place: a Server built by a caller that
// never called WithOptions has no rules on, and must not crash finding that out.
func (s *Server) applyResponseRules(responseData []byte) []byte {
	return s.config.options.ApplyResponse(responseData)
}

// applyRequestRules runs the request-direction options over one outgoing request.
//
// Called in the same slot as the WebSocket extension strip — after intercept, before
// the scope check and before anything is stored — and for the same reasons that
// comment gives: before the scope check so an out-of-scope forward sends exactly the
// bytes the recorded path would, and before the store so history shows what upstream
// received.
//
// After intercept, which is worth being explicit about: an operator who edits a held
// request and puts Accept-Encoding back still gets it stripped while the option is on.
// That is the right behaviour for a blanket rule — the option says "this proxy does
// not accept compressed responses", which stays true regardless of what a single
// request asked for — and it is the same ordering stripWsHandshake already uses.
func (s *Server) applyRequestRules(requestData []byte) []byte {
	return s.config.options.ApplyRequest(requestData)
}

// record hands one completed exchange to scanner.Capture.Record: the shared
// producer, the same call the crawler makes, which is what CRAWL-02 means by
// "exactly the same path". It returns the row that was created, or nil when
// nothing could be captured.
//
// Nil rather than a partly-filled row, and logged rather than worked around.
// Record refuses a capture it cannot complete, because an exchange indexed with
// no response is indistinguishable from one whose response has not arrived yet
// and permanently stalls every cursor that walks the index in order — see
// scanner.Capture.Record. The proxy's report of that refusal is this log line;
// the crawler's is a skip record. Neither invents a row.
func (s *Server) record(x scanner.CapturedExchange) *core.Exchange {
	ex, err := s.capture().Record(x)
	if err != nil {
		s.config.logger.Error("failed to capture exchange",
			zap.String("host", x.Host),
			zap.String("method", x.Method),
			zap.String("path", x.Path),
			zap.Error(err))
		return nil
	}
	return ex
}

// runPassiveScan is gone with the last caller that needed it. It existed as the proxy's own name for
// "scan this exchange", and once every capture site records through Record — which scans as part of
// recording — nothing in this package had a scan to dispatch separately. Keeping a one-line production
// method alive for its tests would have made the scan look like a step a capture site can choose,
// which is exactly the freedom that let the two copies drift.

// capture is the proxy's handle on the shared capture-and-scan pipeline.
//
// Source is set here, once, rather than at each capture site. Every exchange this package records is
// traffic the operator's own client sent through the proxy, so the attribution is a property of the
// surface and not of the call — and a sixth capture site added later inherits it instead of having to
// remember it. The one row that does not come through this handle, the blind CONNECT tunnel, names
// itself explicitly.
func (s *Server) capture() scanner.Capture {
	return scanner.Capture{
		Store:    s.config.store,
		Scanner:  s.config.scanner,
		Findings: s.config.findings,
		Logger:   s.config.logger,
		Source:   core.SourceProxy,
	}
}

// toOriginForm rewrites an absolute-form request line to origin-form, leaving everything else byte
// for byte alone.
//
// `target` is the request-target as the client sent it and `path` is what parseTarget resolved it
// to, so a target with no scheme was already origin-form and the request is returned untouched —
// this must not "helpfully" rewrite anything else, including the asterisk-form target of an OPTIONS
// request. Only the first line is considered: the target string is replaced positionally within it
// rather than by re-serialising the line, so an unusual amount of whitespace between the method and
// the target survives, which matters for a tool whose job includes showing exactly what was sent.
func toOriginForm(requestData []byte, target, path string) []byte {
	if target == "" || path == "" || target == path {
		return requestData
	}
	// Only absolute-form is rewritten. parseTarget returns path == target for origin-form, caught
	// above; anything else without a scheme is left alone rather than guessed at.
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return requestData
	}
	end := bytes.IndexByte(requestData, '\n')
	if end < 0 {
		return requestData
	}
	line := requestData[:end]
	at := bytes.Index(line, []byte(target))
	if at < 0 {
		// The first line does not contain the target the caller parsed out of it. Nothing to do that
		// would not be a guess, and a wrong guess here corrupts the request.
		return requestData
	}
	out := make([]byte, 0, len(requestData)-len(target)+len(path))
	out = append(out, line[:at]...)
	out = append(out, path...)
	out = append(out, line[at+len(target):]...)
	return append(out, requestData[end:]...)
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

// readHeaders is gone with its only caller. It parsed the header block off the
// client's *bufio.Reader so handleHTTP could find a Host header when the request
// target carried no authority — and because it consumed those bytes, the
// readFullRequest call that followed returned a request with no headers. The
// authority is now read out of the fully-buffered request instead (headerValue in
// options.go), which cannot consume anything. Keeping this function as a helper
// nothing calls would leave the reader-consuming shape available to the next caller
// that needs a header early, which is exactly how the bug arrived.

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
	upstreamConn, err := s.dialUpstream(context.Background(), host, port)
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
	upstreamConn, err := s.dialUpstream(context.Background(), host, port)
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

// The proxy's own status-line parser used to live here. It is gone rather than
// unused: every exchange row is now built by scanner.Capture.Record, which reads
// the status off the response the store has already parsed, so a second parser
// in this package could only ever be a way for the row and the message it
// indexes to disagree about the same bytes. Its three test cases moved with it,
// to internal/scanner/capture_test.go.
