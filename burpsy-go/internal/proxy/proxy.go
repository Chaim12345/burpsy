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
	"regexp"
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
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
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

// maxBufferedRequestBody bounds one buffered request body.
//
// readFullRequest holds a whole message in memory because the intercept hold, the
// match-and-replace pass and the record all take one byte slice. A client-controlled bound is
// therefore part of reading a request at all, and the chunked path is where it matters most: a
// chunk stream can declare any size, so without a ceiling this reader is a memory-exhaustion
// primitive. 64 MiB is far above any legitimate API request and far below what would hurt.
const maxBufferedRequestBody = 64 << 20

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
	// selfSigned caches the self-signed leaves a listener in CertModeSelfSigned serves
	// (burpsy-react-ui-4trc). SEPARATE from certPool on purpose: the two modes produce
	// different certificates for the same hostname, and one cache would hand a listener
	// whichever mode happened to ask first.
	selfSigned sync.Map
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

	// No usable pair on disk: mint a fresh CA, persist it, and load it back so the
	// freshly minted pair is validated by the same loadCA path a persisted one is.
	caCertPEM, caKeyPEM, err := generateCAPEM()
	if err != nil {
		return nil, err
	}
	// The certificate is public; only the key is protected. The key is what
	// re-signing from it would need, so it is 0600.
	if err := os.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}
	if err := os.WriteFile(caKeyPath, caKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to save CA key: %w", err)
	}
	return loadCA(caCertPEM, caKeyPEM)
}

// generateCAPEM mints a fresh self-signed CA and returns its certificate and
// private key as PEM. It is the single place a CA is created: LoadOrGenerateCA on
// first run and (*TlsEngine).RegenerateCA at the operator's request both go through
// it, so the two paths cannot drift into producing differently-shaped roots. The
// 128-bit random serial and the new key mean two calls never produce the same CA,
// which is the property regeneration depends on.
func generateCAPEM() (certPEM, keyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
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

	// Self-sign the CA certificate.
	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	return certPEM, keyPEM, nil
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

// ImportCA replaces the signing CA at runtime, so an operator can supply their own
// pair without restarting — Burp's `configPanelCustomCACertificates`.
//
// Before this existed the capability was real and filesystem-only: LoadOrGenerateCA
// reads ca.crt/ca.key from -ca-dir at startup, so using your own CA meant stopping
// burpsy, placing two files, and starting again — losing the captured traffic. The
// UI's certificate section could only *download* the generated CA.
//
// # The cache is the whole difficulty
//
// certPool holds one leaf per host, each signed by the CA being replaced. Clients
// are about to be told to trust the *new* CA, so every cached leaf becomes a
// certificate they will reject — and because the cache is checked before anything
// else, they would keep being served indefinitely. Handshakes would fail with a
// trust error that looks like a misconfigured trust store, on hosts that worked a
// moment ago, and the operator would go looking in their browser.
//
// So the pool is emptied under the same lock that swaps the CA. Signing waits on
// that lock, so no leaf can be minted against a half-swapped pair.
//
// One race is deliberately left: GetCertificate's fast path reads the pool without
// the lock, so a handshake already past that read may still present a leaf signed
// by the old CA. It cannot be prevented from here — that connection's certificate
// was chosen before the import — and it resolves itself on the next handshake.
// Recorded rather than papered over.
//
// # Validation happens before anything is touched
//
// loadCA parses and runs validateCA against a fresh TlsEngine with no side effects,
// so a bad pair — not a CA, wrong key, expired — leaves the running CA and the
// cache exactly as they were. Importing a certificate that cannot sign would
// otherwise take TLS interception down completely, which is a worse outcome than
// refusing.
//
// Persisting to -ca-dir is the caller's job, not this method's: the engine does not
// know where it was loaded from, and a write failure must not leave the process
// signing with a CA that will not survive a restart without somebody being told.
func (e *TlsEngine) ImportCA(certPEM, keyPEM []byte) error {
	loaded, err := loadCA(certPEM, keyPEM)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.caCert = loaded.caCert
	e.caPriv = loaded.caPriv
	// Every cached leaf was signed by the CA just replaced. See above.
	e.certPool.Range(func(key, _ any) bool {
		e.certPool.Delete(key)
		return true
	})
	return nil
}

// RegenerateCA mints a brand-new self-signed CA, installs it as the signing CA,
// and returns its PEM so the caller can persist it. This is Burp's "Regenerate CA
// certificate" (BurpClass9617): the operator's escape hatch when the current CA's
// private key may have been exposed, or when a CA installed into a client's trust
// store during a finished engagement has to be retired.
//
// It reuses ImportCA rather than adding a second swap, so regeneration and import
// share one path: the same validation, the same locked replacement, and — the part
// that matters — the same leaf-cache invalidation. Every cached leaf was signed by
// the CA just replaced; a client about to be told to trust the new CA would
// otherwise keep being served a leaf it will reject. See ImportCA.
//
// The previous CA is gone from this process the moment this returns. If the caller
// then persists the returned PEM over the old ca.key on disk, it is gone for good —
// which is the point: a rotated-out signing key should not remain recoverable.
func (e *TlsEngine) RegenerateCA() (certPEM, keyPEM []byte, err error) {
	certPEM, keyPEM, err = generateCAPEM()
	if err != nil {
		return nil, nil, err
	}
	// generateCAPEM produced this pair, so ImportCA's validation cannot legitimately
	// reject it. If it somehow does, ImportCA validates before swapping, so the
	// running CA and the leaf cache are untouched — we surface the error rather than
	// report a rotation that did not happen.
	if err := e.ImportCA(certPEM, keyPEM); err != nil {
		return nil, nil, fmt.Errorf("freshly generated CA failed validation: %w", err)
	}
	return certPEM, keyPEM, nil
}

// CertPEM returns the current CA certificate as PEM.
//
// Read under the lock because ImportCA can replace it mid-flight, and because the
// one caller that matters is the endpoint serving /ca.crt: an operator who imports
// a CA and then downloads the certificate to install must receive the CA now in
// use, not the one this process started with. Serving the stale one would have them
// trust a CA that signs nothing.
func (e *TlsEngine) CertPEM() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.caCert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.caCert.Raw})
}

// CADescription reports who the current CA is and how long it lasts, for a UI that
// has to show which CA is in force after an import. Returns the subject common
// name, the NotAfter, and whether there is a CA at all.
func (e *TlsEngine) CADescription() (subject string, notAfter time.Time, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.caCert == nil {
		return "", time.Time{}, false
	}
	// A CA with no common name is legal, and a CA with a *wholly* empty subject is
	// legal too — self-signed CAs built by hand often have one. Both fallbacks are
	// needed: Subject.String() is itself "" for an empty RDN sequence, so the first
	// fallback alone still rendered a CA with no identity at all. Caught by
	// TestCADescriptionFallsBackWhenThereIsNoCommonName, which is why the serial is
	// the last resort — it is the one field a certificate must have, so the operator
	// can always tell two CAs apart even when neither is named.
	name := e.caCert.Subject.CommonName
	if name == "" {
		name = e.caCert.Subject.String()
	}
	if name == "" {
		name = fmt.Sprintf("(unnamed CA, serial %s)", e.caCert.SerialNumber)
	}
	return name, e.caCert.NotAfter, true
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
	// options is the live, operator-editable option set: the response modification
	// rules, the Accept-Encoding strip and the WebSocket handshake strip. Never nil
	// after NewProxyConfig, and the same pointer the web API holds — see WithOptions
	// and internal/proxy/options.go.
	options *Options
	// toolLog receives one row per exchange this listener relays, so proxied browser traffic
	// appears in the unified tool log (burpsy-react-ui-6dt). Nil — the default — records
	// nothing, which is what an embedder that owns no log gets. The console hands it the same
	// instance the Logger page reads and persists, so the capture axis, the capture filter
	// and the eviction counter apply to a proxied request exactly as they do to a Repeater
	// send. Set before NewServer rather than after: the field is read by every relay
	// goroutine, so a later write would be a data race, not a late binding.
	toolLog *toollog.ToolLog
	// cookieJar receives the Set-Cookie headers of every response this listener captures, so an
	// operator who browses the target logged-in through the proxy has a jar the other tools can draw
	// on. Nil absorbs nothing, which is what a proxy built without a session coordinator does. See
	// CookieAbsorber and WithCookieJar.
	cookieJar CookieAbsorber
	// upstream is the per-destination upstream proxy policy this proxy's origin-facing leg follows.
	// Nil dials origins directly, which is what this package did before the policy existed. Shared by
	// reference with internal/sender and with the /api/network/proxy handler, so an edit made in the
	// console reaches this leg without a restart — see internal/upstream.
	upstream *upstreamproxy.Policy
	// upstreamCarrier is the global SOCKS layer the interception leg's upstream connection is opened
	// through, beneath whatever proxy the destination rules selected. Shared by reference with
	// internal/sender and with the console, so one Settings edit reaches every leg. See
	// internal/upstream.Carrier.
	upstreamCarrier *upstreamproxy.Carrier
	// tlsVerify is the upstream-TLS policy the interception leg follows: whether the origin's
	// certificate is verified, against which roots, and under which protocol floor. Nil — the
	// default — attaches the default policy on first use, which verifies, so a proxy built without
	// WithUpstreamTLS still verifies rather than silently accepting anything. See tls_policy.go.
	tlsVerify *TLSPolicy
	// platformAuth is the per-host credential lookup consulted before a request is forwarded, so a
	// browser's traffic carries the credentials the operator configured under Settings → Network →
	// Platform authentication. Nil — the default — forwards every request unauthenticated, which is
	// what this proxy did for its whole life before the wiring. See WithPlatformAuth and
	// platform_auth.go for why the edit is a header insert and not a request rebuild.
	platformAuth PlatformAuthSource
	// streaming decides which hosts' responses are forwarded as they arrive rather than buffered to
	// completion, and how long an open-ended read runs before what has arrived is recorded and sent.
	//
	// It is a live holder rather than a plain value for the same reason upstream is: the operator
	// edits the list in Settings → Network while the proxy is running, and a value read once at
	// construction would make that edit a lie until a restart. See StreamingPolicy and
	// WithStreaming.
	streaming *StreamingPolicy
	// network is the same sender.NetworkSettings the sender (Repeater, Intruder, the scanner) holds,
	// shared by reference so one Settings edit reaches every egress (burpsy-react-ui-o1eu).
	//
	// Two of its settings decide how THIS leg behaves and neither was consulted before:
	//
	//   - Resolution overrides and the address-family policy. A split-horizon engagement reaches an
	//     internal host by an address DNS does not point at, and an operator who set that override
	//     while browsing through the proxy got a dial to the real DNS answer — the override silently
	//     did not apply to the tool they were using most.
	//   - ContinueSettings: an origin answering `Expect: 100-continue` with a 100, and whether to
	//     strip the Expect header on the way out.
	//
	// A pointer and not a value for the same reason streaming is: the operator edits these while the
	// proxy is running, and a copy read once at construction would make the edit a lie until a
	// restart. Nil — the default — leaves every previous behaviour in place (dial the name, forward
	// the bytes), which is what an embedder with no console gets.
	// network is the resolution and 100-continue half of the sender's NetworkSettings, held by VALUE
	// and updated in place by the console when the operator saves the Network panel
	// (burpsy-react-ui-o1eu).
	//
	// Two of its settings decide how THIS leg behaves and neither was consulted before:
	//
	//   - Resolution overrides and the address-family policy. A split-horizon engagement reaches an
	//     internal host by an address DNS does not point at, and an operator who set that override
	//     while browsing through the proxy got a dial to the real DNS answer — the override silently
	//     did not apply to the tool they were using most.
	//   - ContinueSettings: whether an interim 1xx is read past, and whether `Expect: 100-continue`
	//     is stripped on the way out.
	//
	// A pointer to a holder rather than a pointer to the sender's own struct: Sender.Network()
	// returns a COPY, so a pointer to it would freeze at the values in force at construction and
	// every later edit would be a lie. Nil — the default — leaves every previous behaviour in place
	// (dial the name, forward the bytes), which is what an embedder with no console gets. See
	// WithNetworkSettings and NetworkSettings().
	network *NetworkSettings
	// sessionCoordinator is the session-handling seam (burpsy-react-ui-9llt): the same
	// *session.Coordinator the sender and the crawler consult, so a rule the operator writes
	// governs the leg that carries their browser traffic too. Nil — the default — keeps today's
	// exact behaviour: no jar cookie is attached to a proxied request and no re-login is
	// attempted, and the relay is byte-for-byte what it always was. See session_gate.go.
	sessionCoordinator ProxySessionCoordinator
	// sessionRunner supplies the re-login macro's step runner. Held as a function rather than a
	// *session.MacroStepRunner because the runner is per-run state the wirer owns: the sender
	// builds one per send, and a proxy that cached one would reuse a closed connection's
	// transport across re-logins.
	sessionRunner proxyLoginRunner
	// sessionGate is the per-listener expiry state the coordinator's rules run against — the
	// templates this listener has seen answer 200 and the ones whose last response signalled an
	// expired session. Built by NewServer when a coordinator is attached, so a relay goroutine
	// never races a nil gate.
	sessionGate *sessionGate
	// LoginPagePattern is the optional body pattern that ALSO flags expiry: an application that
	// answers an expired cookie with the login form at HTTP 200 is invisible to the status-flip
	// signal, and this pattern is how the operator names that page. Nil — the default — detects
	// by status alone. The pattern is deliberately on the config rather than a rule: it names
	// the application's shape, not the engagement's rules.
	LoginPagePattern *regexp.Regexp
}

// NetworkSettings is the live holder for the resolution and 100-continue settings this leg follows.
// Never nil after NewProxyConfig, so a caller can set it without a nil check; the zero value is
// every previous behaviour.
type NetworkSettings struct {
	Resolution sender.ResolutionSettings
	Continue   sender.ContinueSettings
}

// NewNetworkSettings returns the live holder with the defaults this leg has always had plus the one
// that is a correction: Understand100 on, because returning an interim 1xx as a result is wrong for
// any client and Burp does the same (burpsy-react-ui-o1eu).
func NewNetworkSettings() *NetworkSettings {
	return &NetworkSettings{
		Continue: sender.ContinueSettings{Understand100: true, ExpectTimeoutMS: 1_000},
	}
}

// Set replaces the resolution and continue settings this leg follows, in place. The console calls
// this on every Network-panel save, so one edit reaches both legs (burpsy-react-ui-o1eu).
func (n *NetworkSettings) Set(resolution sender.ResolutionSettings, cont sender.ContinueSettings) {
	if n == nil {
		return
	}
	n.Resolution = resolution
	n.Continue = cont
}

// Network returns the live holder, for the console to update in place.
func (s *Server) Network() *NetworkSettings {
	if s.config == nil {
		return nil
	}
	return s.config.network
}

// NewProxyConfig creates a new proxy configuration.
func NewProxyConfig(store *core.TrafficStore) *ProxyConfig {
	c := &ProxyConfig{
		store:   store,
		tls:     NewTlsPolicy(),
		scope:   core.NewScopeAllowEverything(),
		options: NewOptions(),
		logger:  zap.NewNop(), // Default to nop logger
		// Never nil, so the console can push a Network-panel edit without a nil check and the
		// dial paths can read it unconditionally. The zero value is every previous behaviour:
		// no override, dial the name as given, and forward interim bytes verbatim
		// (burpsy-react-ui-o1eu). Understand100 is seeded ON because returning an interim status
		// as a result is wrong for any client — Burp's own default, and the sender's
		// (sender.DefaultNetworkSettings).
		network: &NetworkSettings{
			Continue: sender.ContinueSettings{Understand100: true, ExpectTimeoutMS: 1_000},
		},
	}
	// On, matching Burp's default. A proxy that let permessage-deflate be
	// negotiated would record DEFLATE blocks and call them messages, so the
	// safe setting is the one that keeps the capture readable. Seeded into the
	// live option set rather than a separate flag, so the operator's switch and
	// the relay's decision cannot disagree: Set cannot fail here, the key was
	// just put in OptionKeys.
	if err := c.options.Set(OptStripWsExtensions, true); err != nil {
		panic("proxy: " + err.Error())
	}
	// On, deliberately diverging from Burp's default-off: this engine has always
	// honoured the Host-header fallback for origin-form requests, and flipping that
	// default would break working setups on upgrade for no gain. The switch exists
	// so an operator can tighten the listener; see OptInvisibleProxy for the trade.
	if err := c.options.Set(OptInvisibleProxy, true); err != nil {
		panic("proxy: " + err.Error())
	}
	// On, deliberately diverging from Burp's default "Do nothing": this engine has
	// never retained out-of-scope traffic — every record site has always gated on
	// the scope verdict — so seeding OFF would silently start writing third-party
	// traffic to the store on upgrade. See OptDontLogOutOfScope for the trade.
	if err := c.options.Set(OptDontLogOutOfScope, true); err != nil {
		panic("proxy: " + err.Error())
	}
	// Proxy-* headers have always been stripped on the way upstream (the option's
	// comment says why), so the seed matches the behaviour the engine has always had.
	if err := c.options.Set(OptStripProxyHeaders, true); err != nil {
		panic("proxy: " + err.Error())
	}
	return c
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

// WithUpstreamCarrier attaches the global SOCKS layer to the interception leg's upstream connection.
//
// The same instance must be handed to the sender and the console, for the reason WithUpstreamProxy
// says: two carriers would let the panel describe a layer that only one surface honours
// (burpsy-react-ui-mr83 part 3).
func (c *ProxyConfig) WithUpstreamCarrier(carrier *upstreamproxy.Carrier) *ProxyConfig {
	if carrier != nil {
		c.upstreamCarrier = carrier
	}
	return c
}

// UpstreamCarrier returns the attached global SOCKS layer, or nil.
func (c *ProxyConfig) UpstreamCarrier() *upstreamproxy.Carrier { return c.upstreamCarrier }

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
//
// The setting lives in the live option set (OptStripWsExtensions), so it is
// the very value the Proxy settings panel edits: a caller here seeds it, an
// operator edit changes it, and the handshake reads it per connection — one
// value, no restart.
func (c *ProxyConfig) WithStripWsExtensions(strip bool) *ProxyConfig {
	if err := c.options.Set(OptStripWsExtensions, strip); err != nil {
		panic("proxy: " + err.Error())
	}
	return c
}

// WithToolLog attaches the unified tool log this listener records its relayed exchanges
// into (burpsy-react-ui-6dt). Nil — the default — records nothing, which is the behaviour
// every caller had before the listener was part of the log at all.
//
// The log is the whole tool log, not a proxy-specific sink, because the point of the wiring
// is that proxy traffic is a tool's traffic: it shares the capture axis (an operator can
// stop recording it and the Uncaptured counter says how many requests that cost), the
// capture filter, and the eviction counter with every other tool's rows.
func (c *ProxyConfig) WithToolLog(tl *toollog.ToolLog) *ProxyConfig {
	c.toolLog = tl
	return c
}

// CookieAbsorber is the shared session cookie jar, as this package needs to see it.
//
// An interface rather than the concrete *session.Coordinator so the absorption hook can be exercised
// without standing up a coordinator, and so nil stays a legal wiring. internal/session is a leaf
// package with no burpsy dependencies of its own, so naming its source constant here costs nothing.
// Implemented by *session.Coordinator.
//
// The method takes the raw response bytes, not a parsed header map, and that is the point: a login
// that sets a session cookie and a CSRF cookie sends two Set-Cookie lines, and every existing
// absorption call site in the tree hands the coordinator a map[string]string that can hold one of
// them. The proxy has the actual bytes, so it gives them.
type CookieAbsorber interface {
	// AbsorbResponseCookies folds every Set-Cookie header in `response` into the jar for this
	// authority, returning how many it found.
	AbsorbResponseCookies(src session.AbsorptionSource, host string, port uint16, tls bool, response []byte) int
	// AttachAbsorptionSource records that this surface feeds the jar, so an empty jar can be told
	// apart from a jar nothing is watching.
	AttachAbsorptionSource(src session.AbsorptionSource)
}

// WithCookieJar attaches the shared session cookie jar. Every response this listener captures has its
// Set-Cookie headers absorbed into it.
//
// This is the wiring behind Burp's "by default, the cookie jar is updated based on traffic from the
// Proxy". Without it the jar is fed only by login macros and the crawler's session gate, so an
// operator who logged in through their browser had an empty jar while the Session page told them
// their browsing should have filled it — a false statement about how the tool works, which is worse
// than a missing feature because it is invisible.
//
// Attach is called here rather than at the first absorption so the jar can report "the proxy is
// feeding me and no traffic has flowed yet" as a state distinct from "nothing is feeding me". Nil is
// the no-op: a proxy built without a coordinator absorbs nothing and says so.
//
// The same pointer the web server holds, the single-handle rule this package already applies to the
// TLS policy, the option set and the match & replace rules — a second jar would attach cookies the
// Session page cannot see.
func (c *ProxyConfig) WithCookieJar(jar CookieAbsorber) *ProxyConfig {
	if jar == nil {
		return c
	}
	c.cookieJar = jar
	jar.AttachAbsorptionSource(session.SourceProxy)
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
// WithNetworkSettings points this leg at the same network settings the sender holds, so the
// hostname-resolution overrides, the address-family preference and the 100-continue handling apply
// to proxied traffic and not only to the tools that send their own requests
// (burpsy-react-ui-o1eu).
//
// Shared by reference: the console edits these while the proxy runs, and a value copied at
// construction would stop honouring an edit the moment it was made.
func (c *ProxyConfig) WithNetworkSettings(n *NetworkSettings) *ProxyConfig {
	c.network = n
	return c
}

// WithSessionCoordinator attaches the session-handling coordinator the relay consults
// (burpsy-react-ui-9llt), along with the runner a re-login macro's steps dispatch through.
//
// The coordinator is the same one the sender and the crawler hold — not a copy — so a rule
// the operator edits while the proxy is running governs this leg without a restart, the
// same single-handle rule as Scope. The runner is a function because it is per-run state:
// the wirer hands the macro engine a fresh runner per re-login (the sender builds one per
// send), and a proxy that cached one would pin a transport across sessions.
//
// Attaching the coordinator is what arms the gate: NewServer builds the per-listener
// session state at construction, so the first flagged template re-logs in through the
// coordinator's single-flight rather than per request.
func (c *ProxyConfig) WithSessionCoordinator(coord ProxySessionCoordinator, runner proxyLoginRunner) *ProxyConfig {
	c.sessionCoordinator = coord
	c.sessionRunner = runner
	return c
}

func (c *ProxyConfig) WithLogger(logger *zap.Logger) *ProxyConfig {
	c.logger = logger
	return c
}

// Server represents the proxy server.
type Server struct {
	config *ProxyConfig

	// listeners is the set of sockets this engine serves, keyed by id, and listenerOrder
	// keeps them in report order with the boot listener first. listenerMu guards the map,
	// the order, the id counter and serveCtx; each boundListener has its own mutex for the
	// socket/spec pair the accept loop and the relay read. Rebind and the Add/Update/Remove
	// calls serialise on rebindMu so two concurrent changes cannot interleave their
	// listen/swap/close halves; the accept loops themselves never take rebindMu.
	//
	// serveCtx is ListenAndServe's context, kept so a listener added later can tie its
	// accept loop to the same lifetime. It is nil before ListenAndServe starts, which is
	// what makes AddListener refuse rather than bind a socket nothing would accept on.
	listeners     map[string]*boundListener
	listenerOrder []string
	listenerSeq   int
	serveCtx      context.Context
	listenerMu    sync.Mutex
	rebindMu      sync.Mutex
}

// NewServer creates a new proxy server.
func NewServer(config *ProxyConfig) *Server {
	// Touch both policies at construction so the fields are non-nil from the first request. Not for
	// behaviour — a streaming policy with no hosts declared behaves exactly like none attached, and
	// the default TLS policy verifies, which is the behaviour we want — but so no relay goroutine can
	// be the first to find one nil and have to decide what to do about that.
	_ = config.Streaming()
	_ = config.TLS()
	// The session gate is per-listener state (the templates this listener has seen flip), so it
	// is built here rather than in WithSessionCoordinator: a config built and then attached to a
	// server must not carry a gate another server already flagged templates on, and a relay
	// goroutine must never read a nil one. Only when a coordinator is attached — without one
	// there is nothing the gate could run a rule against, and withSessionRules' nil checks keep
	// the relay byte-for-byte what it was.
	if config.sessionCoordinator != nil && config.sessionGate == nil {
		config.sessionGate = newSessionGate(config.sessionRunner)
	}
	return &Server{
		config:    config,
		listeners: map[string]*boundListener{},
	}
}

// Streaming returns the live open-ended-response policy, so the web layer can push an operator's
// edit into it at the same moment it reaches the sender.
//
// Never nil for the reason ProxyConfig.Streaming is never nil: the response path asks it a question
// on every request, and a nil check at each of those sites is one of them eventually being forgotten.
func (s *Server) Streaming() *StreamingPolicy {
	if s == nil {
		return nil
	}
	return s.config.Streaming()
}

// bootListener is the entry -proxy-bind opened, or nil before ListenAndServe has started.
func (s *Server) bootListener() *boundListener {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	return s.listeners[bootListenerID]
}

// ListenerAddr returns the address the boot listener is bound to, in net.Addr form (an
// ephemeral port is resolved), or "" when nothing is listening.
//
// It answers about the boot listener specifically — the one -proxy-bind opened — because
// that is the listener every caller of this method means: cmd/burpsy's startup banner, the
// in-browser panel's proxy address and the single-listener half of the console's proxy
// settings. Listeners added on that page are reported by Listeners(), which is the surface
// that can describe more than one.
func (s *Server) ListenerAddr() string {
	bl := s.bootListener()
	if bl == nil {
		return ""
	}
	ln := bl.current()
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

// Rebind moves the boot listener to addr without dropping the process: the new socket is
// opened first, so a bind failure leaves the current listener serving untouched and is
// returned as an error rather than becoming an outage. In-flight connections on the old
// socket are not disturbed — only Accept is retired. It answers with the address that was
// serving before the move.
//
// The listener's other settings (redirect, force-TLS, invisible) are carried across
// unchanged: this is the move-the-socket call, not the edit-the-listener call, and an
// operator who re-binds from the Binding field must not silently lose a redirect they set
// on the same row. UpdateListener is the one that replaces a whole spec.
func (s *Server) Rebind(addr string) (string, error) {
	s.rebindMu.Lock()
	bl := s.bootListener()
	s.rebindMu.Unlock()
	if bl == nil {
		// Rebind before ListenAndServe: seed the boot entry so the accept loop binds from
		// it when it starts. This is the pre-start case the previous implementation
		// allowed, kept, and it is why ListenAndServe prefers a seeded bind over its own
		// argument.
		s.listenerMu.Lock()
		if s.listeners == nil {
			s.listeners = map[string]*boundListener{}
		}
		if s.listeners[bootListenerID] == nil {
			s.listeners[bootListenerID] = &boundListener{spec: ListenerSpec{ID: bootListenerID, Bind: addr}}
			s.listenerOrder = append([]string{bootListenerID}, s.listenerOrder...)
		} else {
			s.listeners[bootListenerID].spec.Bind = addr
		}
		s.listenerMu.Unlock()
		return "", nil
	}

	previous := s.ListenerAddr()
	spec, _ := bl.snapshot()
	spec.Bind = addr
	if _, err := s.UpdateListener(bootListenerID, spec); err != nil {
		return previous, err
	}
	return previous, nil
}

// closeListener shuts every live socket down and clears the collection, so a second
// ListenAndServe cannot inherit a closed listener by accident and the accept loops of
// listeners added at runtime return instead of spinning on a dead socket.
func (s *Server) closeListener() {
	s.listenerMu.Lock()
	entries := make([]*boundListener, 0, len(s.listeners))
	for _, bl := range s.listeners {
		entries = append(entries, bl)
	}
	s.listeners = map[string]*boundListener{}
	s.listenerOrder = nil
	s.serveCtx = nil
	s.listenerMu.Unlock()

	for _, bl := range entries {
		bl.mu.Lock()
		bl.closed = true
		ln := bl.ln
		bl.ln = nil
		bl.mu.Unlock()
		if ln != nil {
			ln.Close()
		}
	}
}

// ListenAndServe starts the proxy server. It binds the boot listener on addr and serves it
// on this goroutine, so the blocking contract every caller relies on is unchanged; listeners
// added later (AddListener) get their own accept loop tied to the same context.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	if s.ListenerAddr() != "" {
		return errors.New("proxy is already listening")
	}
	// A Rebind before start seeds the boot entry's bind; prefer it over the argument for
	// the reason the previous implementation bound from the field rather than from addr.
	s.listenerMu.Lock()
	if s.listeners == nil {
		s.listeners = map[string]*boundListener{}
	}
	if seeded := s.listeners[bootListenerID]; seeded != nil && seeded.spec.Bind != "" {
		addr = seeded.spec.Bind
	}
	s.listenerMu.Unlock()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind proxy on %s: %w", addr, err)
	}

	bl := &boundListener{spec: ListenerSpec{ID: bootListenerID, Bind: addr}, ln: listener}
	s.listenerMu.Lock()
	s.listeners[bootListenerID] = bl
	// Assigned, not prepended: a Rebind before start has already put the boot id in the
	// order, and appending it again would list one socket as two listeners. Nothing else can
	// be in there — AddListener refuses until serveCtx is set, which is the line below.
	s.listenerOrder = []string{bootListenerID}
	s.serveCtx = ctx
	s.listenerMu.Unlock()
	defer s.closeListener()

	// Cancellation has to reach the sockets, not just the loop condition: Accept blocks, so
	// a cancelled context that only the top of the loop consulted would leave every accept
	// loop — the boot one and each added one — parked until the next connection arrived.
	// Closing the sockets is what unblocks them.
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			s.closeListener()
		case <-stopped:
		}
	}()

	s.config.logger.Info("proxy listening", zap.String("addr", addr))

	s.serveListener(ctx, bl)
	return ctx.Err()
}

// handleConnection relays one connection under the default listener spec: no redirect, no
// forced TLS, invisible proxying inherited from the process-wide option. It is what the
// engine did before there was a listener collection at all, and it is kept as the entry
// point so a caller that has a connection and no listener behind it — the package's own
// relay tests — gets exactly the behaviour it always had.
func (s *Server) handleConnection(clientConn net.Conn) {
	s.handleConnectionOn(clientConn, ListenerSpec{})
}

// handleConnectionOn relays one connection under the spec of the listener that accepted it.
// The spec is a value, snapshotted at accept time: an operator editing a listener changes
// what the next connection does and never what a connection already in flight does.
func (s *Server) handleConnectionOn(clientConn net.Conn, spec ListenerSpec) {
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
		s.handleConnect(clientConn, reader, target, spec)
		return
	}

	// Handle regular HTTP requests
	s.handleHTTP(clientConn, reader, requestLine, method, target, spec)
}

func (s *Server) handleConnect(clientConn net.Conn, reader *bufio.Reader, target string, spec ListenerSpec) {
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

	// The listener's redirect (burpsy-react-ui-pfeg), applied here — before the passthrough
	// decision's dial and before the certificate is signed — because everything downstream
	// has to answer about the destination the bytes will actually reach.
	//
	// The one thing that keeps the client's own name is the leaf certificate, and that is
	// not an inconsistency: a client that asked for shop.example.com and was handed a
	// certificate for the redirect target would fail the handshake and never send the
	// request the redirect exists to move. So the cert is signed for certName below, while
	// the scope check, the egress fence and the recorded exchange all read the redirected
	// destination — the same rule the operator's per-request "Edit target" follows, and for
	// the same reason: a redirect must not be a way around the fence the engagement scope
	// puts up.
	//
	// "Force use of TLS" has nothing to do on this path and is not silently ignored: a
	// CONNECT tunnel's upstream leg is already TLS (interceptTLS re-encrypts to the origin,
	// tunnelConnection carries the client's own session), so the setting is already
	// satisfied for every byte that arrives this way. It is the plaintext path below that
	// it changes.
	certName := host
	host, port16 := spec.redirectFor(host, uint16(port))

	// Passthrough is decided on the name the CLIENT asked for, not the redirect target: the
	// passthrough patterns are the operator's list of hosts not to decrypt, and they name
	// the hosts their clients ask for.
	if s.config.tls.ShouldPassthrough(certName, uint16(port)) || s.config.tls.engine == nil {
		s.tunnelConnection(clientConn, net.JoinHostPort(host, strconv.Itoa(int(port16))))
		return
	}

	// Intercept: present a CA-signed leaf cert to the client, terminate TLS,
	// and re-encrypt to the origin so traffic can be recorded and scanned.
	s.interceptTLS(clientConn, host, port16, certName, spec)
}

// interceptTLS decrypts a CONNECT tunnel: it answers with 200 Connection
// Established, terminates the client's TLS session with a leaf certificate
// signed by the configured CA, opens a second TLS session to the origin, and
// forwards HTTP in the clear between them while recording exchanges.
// certName is the name the client asked for in its CONNECT, which is the only name a leaf
// certificate it will accept can carry. It is the same as host unless the listener redirects
// — see handleConnect for why the two are allowed to differ, and why nothing else does.
func (s *Server) interceptTLS(clientConn net.Conn, host string, port uint16, certName string, spec ListenerSpec) {
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

	// The downgrade note is a property of the tunnel, not of any one exchange in it, so it is
	// computed once here and carried into every row the tunnel records. A tunnel that carried h2
	// gets ""; a tunnel interception moved off h2 gets the explanation on all of them, because an
	// operator scrolling history must not have to infer the downgrade from one row and assume the
	// rest share it.
	downgrade := DowngradeNote(clientOffer, negotiated)
	if downgrade != "" {
		s.config.logger.Info("interception carried an HTTP/2 client over HTTP/1.1",
			zap.String("host", host), zap.Strings("offered", clientOffer))
	}

	// Sign a leaf certificate for the host the client asked for — not the destination, when
	// a redirect has moved them apart. See the signature comment.
	// The listener's own certificate selection (burpsy-react-ui-4trc), which defaults to exactly
	// what this line did before: a CA-signed leaf for the name the client asked for.
	leaf, err := s.certificateFor(spec, s.listenerCert(spec.ID), certName)
	if err != nil {
		s.config.logger.Error("certificate signing failed", zap.String("host", certName), zap.Error(err))
		return
	}

	// TLS server side: offer the client exactly what the origin chose.
	// The listener's protocol bounds ride the same spec. Zero on either side is crypto/tls's own
	// default, so a listener that names neither handshakes exactly as it did.
	minVersion, maxVersion := tlsVersionsFor(spec)
	tlsClient := tls.Server(replay, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   ClientALPNProtos(negotiated),
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
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

		// reqTLS is the destination's scheme, and it is a variable rather than the literal `true` this
		// used to pass everywhere because a retarget can move the request off TLS entirely
		// (burpsy-react-ui-akv). The scope check, the egress authorisation and the record all read it,
		// so each answers about where the bytes are actually going.
		reqTLS := true

		// retarget is the operator's edited destination for this iteration, nil when they left it
		// alone. Declared out here rather than inside the hold block because the forward below reads
		// it: which connection this request goes out on is decided after the hold resolves.
		var retarget *intercept.Target
		// requestEdited is whether the operator modified this request by hand, and it travels the same
		// way and for the same reason: the record below — and the record of the response it earns — has
		// to report it (burpsy-react-ui-sd0d).
		var requestEdited bool

		// Apply Match & Replace on the request — same position and same reasoning as the
		// plain path in handleHTTP: before intercept, before the scope-gated store, so the
		// bytes forwarded upstream equal the bytes recorded. Requests inside the tunnel
		// already arrive origin-form, so there is no toOriginForm step to precede it here.
		// The request's stage boundaries, by the same rule as the plaintext path's
		// (burpsy-react-ui-c05): stage 0 after the tunnel's origin-form normalisation, stage 1 after
		// the automatic rules and before the hold. See messageStages.
		reqStages := messageStages{original: requestData}
		requestData = s.applyMatchReplace(matchreplace.DirRequest, requestData, reqHost, reqPort, path, reqTLS)
		reqStages.auto = requestData
		// Intercept: hold the decrypted request before it is forwarded upstream.
		if s.config.intercept != nil {
			if held := s.config.intercept.Hold(intercept.ParseMessage(
				intercept.DirectionRequest, reqHost, reqPort, true, method, path, requestData,
			)); held != nil {
				action, raw, edited, heldEdited := held.Wait()
				requestEdited = heldEdited
				if action == intercept.ActionDrop {
					return
				}
				requestData = raw
				// Burp's "Edit target" (akv), applied above the scope check and the egress
				// authorisation so both answer about the destination the request will reach.
				if edited != nil {
					retarget = edited
					reqHost, reqPort, reqTLS = edited.Host, edited.Port, edited.TLS
				}
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

		// Same Miscellaneous request knobs as the plaintext path (5q8u/6s2), in the same
		// after-intercept slot and for the same reason — see that site's comment
		// (burpsy-react-ui-6keo).
		requestData = s.config.options.ApplyRequestEgress(requestData)

		// The bytes are final, so the method and path the rest of this iteration answers about are
		// re-read from them rather than kept from the client's line — see requestLineOf. Above the
		// scope check deliberately: the check below is the egress fence, and it must ask about the URL
		// this request is going to.
		method, path = refreshedRequestLine(requestData, method, path)

		// Scope decides retention, not egress: an excluded request is still
		// forwarded, it is simply not kept. The request bytes are not stored
		// here — both halves of an exchange are put away together by the one
		// producer once it is complete. See handleHTTP.
		inScope := s.config.scope.Contains(reqHost, reqPort, path, reqTLS)

		// ...unless the operator turned "Drop all out-of-scope requests" on, which is the one
		// setting that makes scope an egress fence as well (burpsy-react-ui-ckqx). The switch
		// was wired into core.Scope and read by nothing on this path, so the proxy — the source
		// of most of burpsy's traffic — forwarded excluded hosts exactly as before while the
		// settings page reported the fence was up.
		//
		// Answered rather than dropped silently: a closed connection is indistinguishable from
		// a network failure, and an operator who forgot the switch would debug the wrong thing.
		// Same shape as the intercept drop below.
		//
		// Written to tlsClient, not clientConn: inside this loop the client side is the decrypted
		// channel, and plaintext on the raw socket reaches the browser as "server gave HTTP
		// response to HTTPS client" — a TLS error, which is the one report that would send the
		// operator looking at certificates instead of at their scope list.
		if !s.config.scope.AuthoriseRequest(reqHost, reqPort, path, reqTLS) {
			tlsClient.Write(scopeDropResponse(reqHost, reqPort, path, reqTLS, s.config.scope))
			return
		}

		// A retargeted request (akv) goes out over its own connection, because the tunnel's own is
		// already dialled and its TLS is negotiated to the name the client asked for — a retarget
		// cannot ride it. The connection is closed after this one exchange, and the tunnel's own stays
		// where it is for whatever the client sends next; Burp's "Edit target" is per item, not a
		// repointing of the connection.
		//
		// A WebSocket upgrade is refused here rather than retargeted, and that is a correctness
		// limit rather than an unimplemented one: the client's frames keep arriving on this tunnel the
		// operator did not retarget, so a handshake sent elsewhere would get a relay whose two halves
		// talk to different origins. Answered, with the reason, so the operator is not left reading a
		// hang as a network fault.
		if retarget != nil {
			if core.IsWsUpgradeRequest(requestData) {
				s.config.logger.Warn("refused to retarget a WebSocket upgrade",
					zap.String("host", reqHost), zap.Uint16("port", reqPort))
				tlsClient.Write(wsRetargetRefusalResponse())
				continue
			}
			responseData, serverIP, firstByte, err := s.forwardRequest(requestData, reqHost, reqPort, reqTLS)
			if err != nil {
				s.config.logger.Error("retargeted forward failed", zap.Error(err))
				return
			}
			completed := time.Now()
			if !s.handleTLSResponse(tlsClient, method, reqHost, reqPort, reqTLS, path, requestData, reqStages, inScope, responseData, startTime, firstByte, completed, serverIP, requestEdited, downgrade, false, nil) {
				return
			}
			continue
		}

		// Forward over the persistent upstream connection.
		//
		// The credential is attached here rather than at the read, so every downstream use of
		// requestData — the forward, the record, the operator's own view in history — is the same
		// bytes that went out. Rewriting it after the forward instead would make the row and the
		// wire disagree, which is the one thing this proxy's record is not allowed to do.
		if _, err := upstream.Write(s.forForwarding(requestData, reqHost, method, path)); err != nil {
			return
		}

		// A request that asked to upgrade hands the connection off when the
		// origin answers 101. The response head must be read on its own,
		// because the bytes after it are WebSocket frames, not a response body.
		// This also ends the keep-alive loop — after an upgrade there are no
		// more HTTP requests on this connection, by definition.
		if core.IsWsUpgradeRequest(requestData) {
			// Timed, because the two response timers this path reports are the same two every
			// other path reports (burpsy-react-ui-jcdm): firstByte is when the origin's first
			// byte landed, completed is taken after the body below. An upgrade that is refused
			// carries an ordinary response and must be measured like one.
			head, firstByte, err := httputil.ReadResponseHeadTimed(upstreamBR)
			if err != nil {
				return
			}
			if !core.IsWsUpgradeResponse(head) {
				body, err := httputil.ReadResponseBody(upstreamBR, head)
				if err != nil {
					return
				}
				responseData := append(head, body...)
				completed := time.Now()
				if !s.handleTLSResponse(tlsClient, method, reqHost, reqPort, reqTLS, path, requestData, reqStages, inScope, responseData, startTime, firstByte, completed, serverIPOf(upstream), requestEdited, downgrade, false, nil) {
					return
				}
				continue
			}

			// The handshake goes through the same producer as any other exchange;
			// see handleWebSocketUpgrade for why it is recorded before the relay
			// starts rather than when the socket finally closes.
			var handshake *core.Exchange
			if inScope || !s.config.options.Get(OptDontLogOutOfScope) {
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
					// HTTP/1.1, and provably so: the ALPN policy settled on http/1.1 for this tunnel
					// (an h2 tunnel returns to relayH2 above and never opens this loop), which is
					// why the 101 is read off a bufio reader rather than an h2 stream. Written as the
					// constant rather than `protocol` because the value is not a choice here and a
					// variable would invite a future h2 hold path to reach this line and stamp
					// HTTP/1.1 on a multiplexed exchange.
					Protocol: core.ProtocolHTTP1,

					// The handshake's request stages. No response stages: a 101 has no body and the
					// response rules are not applied to it, so there is no earlier version of it to
					// retain — see ws.go's note on why rewriting a handshake would break it.
					RequestOriginal: reqStages.original,
					RequestAuto:     reqStages.auto,

					ServerIP:     serverIPOf(upstream),
					ListenerPort: listenerPortOf(clientConn),

					// A handshake the operator edited in the hold is "Edited" in history, by the same rule
					// as every other row (burpsy-react-ui-sd0d).
					UserEdited: requestEdited,

					// A handshake this proxy rewrote must not look pristine.
					Notes: wsStripNote(wsStripped),
				})
			} else {
				s.config.options.NoteOutOfScopeDrop()
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

		// Timed: firstByte is the instant the origin's first byte arrived, taken inside the
		// reader rather than guessed from around it, and completed is taken once the body is
		// in. The pair is what separates a slow-to-respond origin from a slow-BODY one, which a
		// single total cannot say (burpsy-react-ui-jcdm).
		head, firstByte, err := httputil.ReadResponseHeadTimed(upstreamBR)
		if err != nil {
			return
		}

		// A 401's challenge is the nonce a Digest credential has to be computed against, so it is
		// recorded here and the NEXT request on this connection can answer it. This is the whole of
		// Digest's reachability on the proxy leg: there is no retry, because re-sending a request the
		// browser did not ask to repeat against a host that is refusing it is how an account gets
		// locked out. One extra round trip on a connection that is already keep-alive is a fair price;
		// a credential storm is not. See platform_auth.go.
		learnFromChallenge(s.config.platformAuth, reqHost, platformAuthChallenges(head))

		// An open-ended response is forwarded as it arrives rather than buffered to completion.
		// Without this the client is sent nothing until the stream ends, and on an SSE feed or a
		// long-poll it never does — the browser shows a hung request (burpsy-react-ui-wet3).
		//
		// The two paths are genuinely different operations, not one with a flag: the streamed one
		// writes each chunk to the client as it lands, and only then offers the whole accumulated
		// response to the hold, the rules and the record. So an intercepted open-ended response is
		// forwarded live and NOT held for editing — which is the correct trade, because holding it
		// would mean holding the stream open for the operator, and an operator cannot edit bytes that
		// have not been sent yet. The alternative — buffering — is the defect.
		if s.streamsResponse(reqHost, head) {
			if !s.streamTLSResponse(tlsClient, upstream, upstreamBR, method, reqHost, reqPort, reqTLS, path, head, requestData, reqStages, inScope, startTime, firstByte, requestEdited, downgrade) {
				return
			}
			continue
		}

		body, err := httputil.ReadResponseBody(upstreamBR, head)
		if err != nil {
			return
		}
		responseData := append(head, body...)
		completed := time.Now()

		if !s.handleTLSResponse(tlsClient, method, reqHost, reqPort, reqTLS, path, requestData, reqStages, inScope, responseData, startTime, firstByte, completed, serverIPOf(upstream), requestEdited, downgrade, false, nil) {
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
// serverIP is threaded in rather than read here: this function holds the client side of the
// decrypted channel and not the upstream socket, and the destination address is a property of that
// socket. Passing it keeps the answer the one the exchange actually used (burpsy-react-ui-mr4p).
// requestEdited is whether the operator's own hold edited the request half of this exchange, which
// this function cannot see: the request hold resolved before the request was forwarded. It is
// threaded in so the recorded row's "Edited" column reports an operator edit in either direction,
// which is what Burp's flag means ("the request or response were modified by the user").
// alreadyWritten says the caller has already sent these exact bytes to the client, one chunk at a
// time, and this call is here only for the rules, the hold and the record.
//
// It is a parameter rather than a second recording function because the response half has four
// steps that must agree with each other — Match & Replace, the blanket rules, the hold, the record
// with its four stage boundaries — and a copy of those steps is how the two paths started disagreeing
// about what a response row means. The write is the ONLY step streaming does differently, so it is
// the only step this flag changes. See stream_response.go for why streaming cannot hold or rewrite.
func (s *Server) handleTLSResponse(clientConn net.Conn, method string, host string, port uint16, tls bool, path string, requestData []byte, reqStages messageStages, inScope bool, responseData []byte, startTime time.Time, firstByte, completed time.Time, serverIP string, requestEdited bool, downgrade string, alreadyWritten bool, extraNote *string) bool {
	// The response's stage boundaries, by the same rule as completeResponse's
	// (burpsy-react-ui-c05): stage 0 is the origin's bytes, stage 1 is after the automatic rules
	// and before the hold. See messageStages.
	respStages := messageStages{original: responseData}
	// Apply Match & Replace on response
	responseData = s.applyMatchReplace(matchreplace.DirResponse, responseData, host, port, path, tls)
	// Then the blanket response modification rules. This order, not the other one:
	// a Match & Replace rule is a pattern the operator wrote against the origin's
	// own bytes, and running "remove all JavaScript" first would delete the text
	// their rule was written to find. See applyResponseRules.
	//
	// Before the scope check, deliberately and unchanged: these are listener-level
	// rules, so scope decides what is retained and never what is rewritten. What is
	// new is that an out-of-scope rewrite is now *counted* as unrecorded — this
	// function has always rewritten out-of-scope HTTPS responses and then skipped the
	// record below, which left Counters.Modified including responses no history search
	// could ever turn up. See applyResponseRulesUnrecorded.
	// The branch is on whether the exchange will be *recorded*, not on the scope
	// verdict alone: with dont_log_out_of_scope off, an out-of-scope rewrite is
	// findable in history, and counting it as unrecorded would overstate what
	// history cannot show.
	recorded := inScope || !s.config.options.Get(OptDontLogOutOfScope)
	if recorded {
		responseData = s.applyResponseRules(responseData)
	} else {
		responseData = s.applyResponseRulesUnrecorded(responseData)
	}
	respStages.auto = responseData

	// Intercept: hold the response before it reaches the client.
	// Seeded with extraNote — the streaming path's "this never ended" — so a hold-drop below appends
	// to it rather than replacing it. Both are facts about the same exchange and the row has room
	// for both; a drop note that erased the streaming one would leave the operator unable to tell
	// why the stream was cut.
	notes := extraNote
	keepServing := true
	// responseEdited is the operator's own edit to the response half, paired below with the request
	// half this function was handed.
	var responseEdited bool
	if s.config.intercept != nil {
		if held := s.config.intercept.Hold(intercept.ParseMessage(
			intercept.DirectionResponse, host, port, tls, method, path, responseData,
		)); held != nil {
			// A response has no destination of its own to retarget: the bytes already came back from
			// one. The target is therefore ignored here rather than applied, and the engine only ever
			// sets it on a forward.
			action, raw, _, heldEdited := held.Wait()
			responseEdited = heldEdited
			if action == intercept.ActionDrop {
				keepServing = false
				notes = interceptDropNote()
			} else {
				responseData = raw
			}
		}
	}

	// Burp's "Set Connection: close on requests and on responses" (6s2): the response
	// half. The header says close and the loop below stops — the request half was set in
	// the relay, so both peers see the same decision and neither waits on a socket the
	// other is closing.
	if s.config.options.Get(OptSetConnectionClose) {
		responseData = forceConnectionClose(responseData)
		keepServing = false
	}

	// Return the response to the client. A write that fails ends the connection
	// but not the capture: the origin answered, and that is worth recording
	// whether or not the client was still listening.
	if keepServing && !alreadyWritten {
		if _, err := clientConn.Write(responseData); err != nil {
			keepServing = false
		}
	}

	if recorded {
		s.record(scanner.CapturedExchange{
			Host: host,
			Port: port,
			// The destination's scheme, not the tunnel's: a request retargeted to an http origin is
			// recorded as the plaintext exchange it was (burpsy-react-ui-akv). Recorded after the
			// rewrite, like everything else here — history must show what went on the wire.
			TLS:       tls,
			Method:    method,
			Path:      path,
			Request:   requestData,
			Response:  responseData,
			Started:   startTime,
			FirstByte: firstByte,
			Completed: completed,
			Protocol:  core.ProtocolHTTP1,

			RequestOriginal:  reqStages.original,
			RequestAuto:      reqStages.auto,
			ResponseOriginal: respStages.original,
			ResponseAuto:     respStages.auto,

			ServerIP:     serverIP,
			ListenerPort: listenerPortOf(clientConn),

			// Either direction being the operator's own work makes this row "Edited", which is Burp's
			// reading of the flag (burpsy-react-ui-sd0d). Deliberately not a comparison of the recorded
			// bytes against an earlier stage of themselves: that counts burpsy's own rewrites as the
			// operator's, which is the defect this replaces.
			UserEdited: requestEdited || responseEdited,

			Notes: withDowngradeNote(notes, downgrade),
		})
	} else {
		s.config.options.NoteOutOfScopeDrop()
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
		// Mime is deliberately left empty, and this is the one site where that is not a degraded
		// answer. A blind tunnel has no response bytes at all — that is the whole point of the row, as
		// the comment above explains — so there is no Content-Type to read and nothing to derive one
		// from. It is also the row with no Response, so a consumer can tell this "" ("nothing came
		// back") from a response that declared no type: see core.Exchange.Mime.
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

func (s *Server) handleHTTP(clientConn net.Conn, reader *bufio.Reader, requestLine, method, target string, spec ListenerSpec) {
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
		// The fallback is what "invisible proxying" means here, and it is gated:
		// with the option off a listener that was sent an origin-form request it
		// cannot attribute answers 400 below rather than guessing an authority out
		// of the headers. Burp's switch ("enable only if needed"), honoured live
		// through the option set so no restart separates the tick from the behaviour.
		//
		// Per listener since burpsy-react-ui-pfeg: the tick on this listener's row decides,
		// falling back to the process-wide switch when the row was left alone. That is what
		// keeps the control from being a no-op — invisible_proxy is seeded ON, so a plain
		// "listener OR global" would have made a listener ticked OFF still answer
		// origin-form requests.
		if h := headerValue(requestHead(requestData), "Host"); h != "" && spec.invisibleWith(s.config.options.Get(OptInvisibleProxy)) {
			host, port = parseHostPort(h)
		}
	}

	if host == "" {
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	// The listener's "Redirect to host" / "Redirect to port" (burpsy-react-ui-pfeg). Applied
	// here, above everything: the Match & Replace scope gate, the intercept window, the scope
	// check, the egress fence, the dial and the recorded exchange all then answer about the
	// destination the bytes actually reach, which is the rule the operator's per-request
	// "Edit target" already follows — a redirect must not be a way around the fence the
	// engagement scope puts up.
	//
	// The Host header is deliberately NOT rewritten. Redirecting is how a request for one
	// name is sent to another machine, and the name in that header is exactly what the
	// receiving origin needs to serve the right vhost — which is the whole point of the
	// non-proxy-aware setup this exists for. An operator who wants the header changed has
	// Match & Replace, which runs below.
	//
	// A retarget the operator types into the intercept window runs after this and therefore
	// wins: the listener's redirect is the standing rule, the hold is the one request they
	// are looking at.
	host, port = spec.redirectFor(host, port)

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
	// The request's stage boundaries (burpsy-react-ui-c05). Stage 0 is the client's bytes as they
	// are after toOriginForm, above; stage 1 is taken directly below, after the automatic rules and
	// before the hold, so an operator edit is what separates stage 1 from the recorded bytes. Both
	// are handed to the recorder unconditionally — a stage identical to the next costs no bytes,
	// and gating the capture on "M&R ran" would lose the stages of an exchange the operator edited
	// by hand. See messageStages.
	reqStages := messageStages{original: requestData}
	// scheme is the destination's scheme, and it is a variable rather than the literal `false` this
	// path knows it starts as, because a retarget can change it (burpsy-react-ui-akv). Everything
	// downstream that asks "is this TLS" — the Match & Replace scope gate below, the scope check, the
	// egress authorisation, the record — has to answer about the destination the bytes will actually
	// reach, not the one the client originally named. Declared above the gate so the gate reads the
	// destination in hand rather than one declared after it; the retarget the hold below may apply is
	// the one case this gate cannot see, and applyMatchReplace's comment says so.
	//
	// It starts at the listener's "Force use of TLS" rather than at false (burpsy-react-ui-pfeg):
	// that switch means the connection this proxy opens to the destination is TLS whatever the
	// client used to reach the listener, which is the sslstrip-shaped setup — a client speaking
	// plaintext to a listener that speaks HTTPS onward. Because scheme is the destination's, the
	// scope rules matched below are the https ones, and the exchange is recorded as the TLS
	// exchange it was on the wire.
	scheme := spec.ForceTLS
	requestData = s.applyMatchReplace(matchreplace.DirRequest, requestData, host, port, path, scheme)
	reqStages.auto = requestData
	// Intercept: hold the request for the operator before it is forwarded.
	// A held request blocks this connection until resolved; a drop closes the
	// connection without reaching upstream. heldNote/heldHighlight carry the
	// operator's annotation from the hold to the recorded exchange (5q8u).
	var heldNote, heldHighlight string
	// requestEdited is the operator's own edit to this request, threaded to whichever record this
	// exchange ends in — the plain response below or a WebSocket handshake. See
	// intercept.Held.userEdited for why it is read from the hold and not recomputed from the bytes.
	var requestEdited bool
	if s.config.intercept != nil {
		if held := s.config.intercept.Hold(intercept.ParseMessage(
			intercept.DirectionRequest, host, port, scheme, method, path, requestData,
		)); held != nil {
			action, raw, retarget, heldEdited := held.Wait()
			requestEdited = heldEdited
			if action == intercept.ActionDrop {
				clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
				return
			}
			requestData = raw
			// Burp's "Edit target" (akv): the operator's destination replaces the client's for this one
			// request. Applied here, above the scope check and above the egress authorisation, so both are
			// answered about where the request is actually going — a host typed into the intercept pane
			// must not be a way around the fence the engagement scope puts up.
			if retarget != nil {
				host, port, scheme = retarget.Host, retarget.Port, retarget.TLS
			}
			// The operator's annotation rides the hold to the recorded exchange: this is
			// Burp's "annotations that you make also appear against the item in the HTTP
			// history". Forwarded-but-unrecorded traffic (dont_log_out_of_scope) simply
			// drops it with the exchange, as everything else about an unrecorded
			// exchange does.
			if held.Comment != "" || held.Highlight != "" {
				heldNote = held.Comment
				heldHighlight = held.Highlight
			}
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

	// The two Miscellaneous request knobs (strip Proxy-* headers, Connection: close), in the same
	// after-intercept slot and for the same reason (burpsy-react-ui-6keo).
	//
	// This call used to sit ABOVE the hold, directly under a comment claiming it ran after it. With
	// "strip Proxy-* headers" seeded ON, a held request had already lost its Proxy-Authorization
	// and Proxy-Connection by the time the operator saw it — they could not read what the client
	// sent, could not decide about it, and could not put it back. Intercept exists to show the
	// client's real bytes; a transform applied before the hold is invisible and unrecoverable.
	//
	// The consequence, stated rather than glossed: the held request shows the client's headers,
	// while history and the wire both show the stripped ones. Those are different questions — "what
	// did the client send" and "what did burpsy send" — and the store runs after this line, so the
	// recorded bytes and the forwarded bytes stay identical, which is the invariant that matters.
	requestData = s.config.options.ApplyRequestEgress(requestData)

	// The bytes are final, so the method and path the scope check, the record and the WebSocket strip
	// below all answer about are re-read from them rather than kept from the client's line — see
	// requestLineOf. Every transformation that could have changed the line has now run.
	method, path = refreshedRequestLine(requestData, method, path)

	// The session seam (burpsy-react-ui-9llt): attach the jar's Cookie header, and when this
	// template was flagged by the previous response, re-login and carry the fresh cookie on
	// this request. Runs here — after every byte-level transform and after the operator's hold,
	// before the scope check — so what the origin receives, what history records and what the
	// operator edited are one set of bytes, the invariant every transform above states. Nil
	// coordinator is the unwired default and the call is a no-op, so the relay is unchanged
	// wherever the embedder attached no coordinator.
	requestData = s.withSessionRules(requestData, host, method, path, port, scheme)
	// withSessionRules may have rewritten the header block (a Cookie insert or a rebuild after
	// re-login), so the method and path are re-read from the final bytes for the same reason
	// refreshedRequestLine exists: what is recorded and what is sent must agree with each other.
	method, path = refreshedRequestLine(requestData, method, path)

	// Check scope. The scheme is the destination's, not the client's: a request retargeted from http to
	// https must be matched by the https arm of a scope rule, or the scheme arm would be answering a
	// question about a host the request is not going to.
	inScope := s.config.scope.Contains(host, port, path, scheme)

	// The egress half of the same question — see the TLS path for why this is answered rather
	// than dropped on the floor. It sits before the dont_log_out_of_scope branch below because
	// that branch forwards: a request refused at egress must not reach the origin by the
	// retention path either.
	if !s.config.scope.AuthoriseRequest(host, port, path, scheme) {
		clientConn.Write(scopeDropResponse(host, port, path, scheme, s.config.scope))
		return
	}

	// dont_log_out_of_scope decides retention, live: on (the seed) keeps the
	// engine's always-forward-never-keep behaviour for excluded hosts, off makes
	// an excluded exchange take the recorded path exactly as if it were in scope.
	// The bytes the origin receives do not change either way — the rules ran
	// before this check.
	if !inScope && s.config.options.Get(OptDontLogOutOfScope) {
		s.config.options.NoteOutOfScopeDrop()
		// Forward without storing. path travels because the response-direction Match & Replace
		// rules run on this path too and they need the target for their scope verdict — see
		// forwardOnly.
		s.forwardOnly(clientConn, reader, requestData, method, host, port, path, scheme)
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
		s.handleWebSocketUpgrade(clientConn, reader, method, host, port, path, scheme, requestData, reqStages, startTime, wsStripped, requestEdited)
		return
	}

	// An open-ended response is streamed rather than buffered to completion: forwardRequest reads the
	// whole response before this function sees any of it, and on an SSE stream or a long-poll the
	// whole response never exists (burpsy-react-ui-wet3). The branch has to be here, before the
	// forward, because the streaming path owns the upstream connection for as long as the stream
	// lasts — which is exactly what forwardRequest's defer Close() would not allow.
	//
	// Whether this response is open-ended is not knowable until the head arrives, so streamPlainResponse
	// makes the call itself and falls back to the ordinary buffered read when the origin framed its
	// response after all. That ordering — decide after the head, not before the dial — is what lets one
	// request go through either path without the caller guessing.
	s.streamPlainResponse(clientConn, requestData, host, port, scheme, path, method,
		reqStages, inScope, startTime, heldNote, heldHighlight, "", requestEdited)
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
// serverIP is threaded in for the reason handleTLSResponse's is: the upstream socket is owned and
// closed by the forwarder, so this is the last point the address is still knowable.
// requestEdited is whether the operator's own hold edited the request half of this exchange; see
// handleTLSResponse, which threads the same value for the same reason.
func (s *Server) completeResponse(clientConn net.Conn, method string, host string, port uint16, tls bool, path string, requestData []byte, reqStages messageStages, responseData []byte, startTime time.Time, firstByte, completed time.Time, heldNote, heldHighlight, serverIP string, requestEdited bool, downgrade string, alreadyWritten bool) {
	// The response's stage boundaries (burpsy-react-ui-c05): stage 0 is the origin's bytes as the
	// forwarder read them, stage 1 is after the automatic rules and before the hold. The recorded
	// bytes are stage 2. Same rule as the request side's — see messageStages.
	respStages := messageStages{original: responseData}
	// Apply Match & Replace on response, then the blanket response modification
	// rules — same order, and for the same reason, as handleTLSResponse.
	responseData = s.applyMatchReplace(matchreplace.DirResponse, responseData, host, port, path, tls)
	responseData = s.applyResponseRules(responseData)
	respStages.auto = responseData

	// Intercept: hold the response for the operator before it reaches the client.
	var notes *string
	var highlight string
	dropped := false
	// responseEdited is the operator's own edit to the response half; requestEdited, above, is the
	// other half of the same flag.
	var responseEdited bool
	if s.config.intercept != nil {
		if held := s.config.intercept.Hold(intercept.ParseMessage(
			intercept.DirectionResponse, host, port, tls, method, path, responseData,
		)); held != nil {
			// The destination is ignored for a response, by the same reasoning as
			// handleTLSResponse's: it has already been reached.
			action, raw, _, heldEdited := held.Wait()
			responseEdited = heldEdited
			if action == intercept.ActionDrop {
				dropped = true
				notes = interceptDropNote()
			} else {
				responseData = raw
			}
			// The response hold's own annotation, or the request hold's when this
			// response was not itself held: either way the operator marked this
			// exchange, and the mark belongs on the row in history (5q8u).
			if held.Comment != "" || held.Highlight != "" {
				if held.Comment != "" {
					notes = &held.Comment
				}
				highlight = held.Highlight
			}
		}
	}
	if notes == nil && heldNote != "" {
		notes = &heldNote
	}
	if highlight == "" {
		highlight = heldHighlight
	}

	// The response half of Connection: close (6s2) — the request half was already set in
	// the relay. This path serves one request per connection by shape, so only the header
	// needs to agree with what the relay does.
	if s.config.options.Get(OptSetConnectionClose) {
		responseData = forceConnectionClose(responseData)
	}

	// Send to client.
	//
	// alreadyWritten says the streaming path has already put these bytes on the wire, chunk by
	// chunk, and this call is here for the rules and the record. It is a parameter rather than a
	// second recording function for the reason handleTLSResponse's is: the response half has four
	// steps that must agree with each other, and a copy of them is how two paths start disagreeing
	// about what a row means. See stream_response.go.
	if !dropped && !alreadyWritten {
		clientConn.Write(responseData)
	}

	s.record(scanner.CapturedExchange{
		Host:      host,
		Port:      port,
		TLS:       tls,
		Method:    method,
		Path:      path,
		Request:   requestData,
		Response:  responseData,
		Started:   startTime,
		FirstByte: firstByte,
		Completed: completed,
		Protocol:  core.ProtocolHTTP1,

		RequestOriginal:  reqStages.original,
		RequestAuto:      reqStages.auto,
		ResponseOriginal: respStages.original,
		ResponseAuto:     respStages.auto,

		ServerIP:     serverIP,
		ListenerPort: listenerPortOf(clientConn),

		// Either direction being the operator's own work makes this row "Edited" (burpsy-react-ui-sd0d).
		UserEdited: requestEdited || responseEdited,

		Notes:     withDowngradeNote(notes, downgrade),
		Highlight: highlight,
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

// applyResponseRulesUnrecorded is applyResponseRules for a response whose exchange scope
// will keep out of history.
//
// The rules still run — see forwardOnly for why that is the point rather than an oversight
// — but a rewrite that leaves no trace in history would make Counters.Modified a number the
// operator cannot reconcile against anything they can look at. So the one thing this adds is
// the note: the rewrite happened, and here is the reason you will not find it.
//
// The comparison is on the slice header and contents both, via bytes.Equal, because
// ApplyResponse returns its input unchanged when no rule matched — reference equality would
// be the cheaper test but would silently stop counting the moment ApplyResponse started
// returning a copy.
func (s *Server) applyResponseRulesUnrecorded(responseData []byte) []byte {
	out := s.config.options.ApplyResponse(responseData)
	if !bytes.Equal(responseData, out) {
		s.config.options.NoteUnrecordedModification()
	}
	return out
}

// applyMatchReplace runs the Match & Replace rules over one message, honouring the set's
// "Only apply to in-scope items" restriction.
//
// # Why this replaced six inlined `if Affects(...) { Apply(...) }` blocks
//
// The restriction is a property of the rule set and a verdict about the target, so every
// call site has to ask both questions, in the right order, and only pay for the scope
// lookup when the restriction is on. Six copies of that is six places for the seventh call
// site — added later, by someone who has not read any of them — to get it wrong, and there
// were already two shapes in the wild: the HTTP sites asked Affects first and then applied,
// while the WebSocket call re-derived the direction by hand and asked its own question.
//
// # Why the gate is here and not in the engine
//
// internal/matchreplace sits below core in this tree's dependency direction and imports
// neither the scope matcher nor the store. The engine carries the *flag* because an operator
// edits it through the same endpoint that edits the rules and one object cannot be
// half-persisted; the proxy carries the *decision* because it already knows the target and
// already holds the scope. When the restriction turns a message away the engine is told, so
// the panel can distinguish "no rule matched" from "no rule was allowed to look".
//
// host/port/path/tls identify the exchange, and they are the destination the client named.
// On the plaintext and TLS request paths that is the destination in hand at this point,
// because the rules run above intercept: an operator's retarget applied in the hold is a
// destination this gate never saw. Documented rather than papered over — the alternative is
// running the rules after the hold, which would put bytes in history the operator never
// approved (see the ordering note at the call site in completeResponse).
func (s *Server) applyMatchReplace(dir matchreplace.Direction, raw []byte, host string, port uint16, path string, tls bool) []byte {
	rs := s.config.matchReplace
	if rs == nil || !rs.Affects(dir) {
		return raw
	}
	if rs.InScopeOnly() && !s.config.scope.Contains(host, port, path, tls) {
		rs.NoteScopeSkipped()
		return raw
	}
	return rs.Apply(dir, raw)
}

// matchReplaceApplies reports whether a rule will actually rewrite a message on this target,
// which is the question the WebSocket frame path needs and a different one from Affects.
//
// With the in-scope restriction on and this connection's target out of scope, the rules
// exist and will not run — and parsing every frame of the connection into whole messages in
// order to run nothing is work the operator's own setting asked not to be done. Burp's
// WebSocket table honours the same toggle, and its relay makes the same trade: an
// out-of-scope connection is relayed as opaque chunks and never reassembled.
//
// The count in NoteScopeSkipped therefore does not include messages on a connection that
// never entered the frame path: those were never offered to the gate, and counting them
// would mean inventing a message count for a relay that deliberately does not parse one.
func (s *Server) matchReplaceApplies(dir matchreplace.Direction, host string, port uint16, path string, tls bool) bool {
	rs := s.config.matchReplace
	if rs == nil || !rs.Affects(dir) {
		return false
	}
	return !rs.InScopeOnly() || s.config.scope.Contains(host, port, path, tls)
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

// withDowngradeNote merges the tunnel's protocol-downgrade explanation into whatever note the
// exchange already carries, and returns nil when neither exists.
//
// A tunnel that downgraded carries the same fact on every row, but a row can also have a note of its
// own — a held request the operator edited, a WebSocket handshake the proxy rewrote. Overwriting
// would lose that; returning the downgrade alone would lose the other. So they are joined, and the
// first clause is the tunnel's because it explains the protocol every row on this tunnel speaks.
func withDowngradeNote(existing *string, downgrade string) *string {
	if downgrade == "" {
		return existing
	}
	if existing == nil || *existing == "" {
		note := downgrade
		return &note
	}
	note := downgrade + "; " + *existing
	return &note
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
// Cookie absorption happens here, before the capture, for two reasons. It is the one funnel every
// capture site in this package goes through — HTTP/1, the h2 relay's rendered copy, and the WebSocket
// handshake — so a site added later inherits it the way it inherits the Source attribution. And it
// runs before Record's own refusals, because a Set-Cookie the origin sent is a fact about the session
// whether or not the exchange could be indexed: dropping the cookie because the row failed to store
// would lose the operator's session for a reason that has nothing to do with their session.
//
// Not gated on scope. Absorption is keyed by authority and read back by authority, so a cookie for a
// host no tool will ever address is inert; refusing to absorb it would instead mean an operator who
// narrowed scope mid-engagement silently stops accumulating the session they are logged in to.
func (s *Server) record(x scanner.CapturedExchange) *core.Exchange {
	if s.config.cookieJar != nil && len(x.Response) > 0 {
		s.config.cookieJar.AbsorbResponseCookies(session.SourceProxy, x.Host, x.Port, x.TLS, x.Response)
	}
	// The session gate reads the same response (burpsy-react-ui-9llt): the coordinator's
	// jar and validity rules, then the flip/pattern signals that flag the template the
	// next request re-logs in under. Same position as absorption — before Record's
	// refusals, because a session fact the origin stated is not contingent on the row
	// being indexable.
	s.noteProxiedResponse(x)
	ex, err := s.capture().Record(x)
	if err != nil {
		s.config.logger.Error("failed to capture exchange",
			zap.String("host", x.Host),
			zap.String("method", x.Method),
			zap.String("path", x.Path),
			zap.Error(err))
		// The request still came from the operator's client and was still relayed, so the
		// refusal gets a log row too — with no exchange to link and no response length,
		// which is exactly what Entry.Exchange's nil and Entry.ResponseLen's nil mean
		// (burpsy-react-ui-6dt). Dropping the row would make the unified log quieter about
		// a real send than any per-tool view is, which is the direction a log must never
		// fail in.
		s.noteProxied(x, 0, nil, nil, err.Error())
		return nil
	}
	if s.config.toolLog != nil {
		status := 0
		if ex.Status != nil {
			status = int(*ex.Status)
		}
		id := ex.ID
		s.noteProxied(x, status, toollog.Bytes(len(x.Response)), &id, "")
	}
	return ex
}

// noteProxied writes one tool-log row for an exchange this listener relayed.
//
// It exists so both outcomes of the capture are logged the same way instead of the success
// path being the only one that thought about the log: a stored exchange links to its bytes
// and carries the response length, a refused one carries the reason in the row's note and
// points at nothing. The length convention is the web layer's — toollog.Bytes(len(response))
// as api_tools.go writes it — rather than the parsed body length HTTP history shows, so a
// Logger row and the Repeater row for the same send are measured the same way.
func (s *Server) noteProxied(x scanner.CapturedExchange, status int, respLen *int, exchange *core.ExchangeID, note string) {
	tl := s.config.toolLog
	if tl == nil {
		return
	}
	// The row carries the response's media type so the capture filter can refuse it by type
	// (burpsy-react-ui-73vm) — this is the path a long engagement's log fills up from, and the
	// images and fonts the operator wants out of it arrive here. Derived with core.MimeEssence,
	// the same one-line answer Exchange.Mime uses, so a Logger row and a history row can never
	// disagree about what a response was.
	//
	// nil, not "", when there is no response at all (a refused or failed exchange): "" is the
	// positive fact that a response declared no usable Content-Type, and a row that never had a
	// response is not that. The filter never judges a nil.
	var mime *string
	if len(x.Response) > 0 {
		essence := core.MimeEssence(x.Response)
		mime = &essence
	}
	tl.RecordMime(toollog.ToolProxy, x.Host, x.Port, x.TLS, x.Method, x.Path, status,
		respLen, uint64(x.Duration.Milliseconds()), note, exchange, mime)
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

// refreshedRequestLine applies requestLineOf to a request whose bytes are final, keeping the values
// it was given when the line cannot be read. Split out from requestLineOf so the two call sites —
// the plain and the tunnelled relay paths — state the same fallback rule rather than each writing
// their own three-line version of it.
func refreshedRequestLine(raw []byte, method, path string) (string, string) {
	if m, p, ok := requestLineOf(raw); ok {
		return m, p
	}
	return method, path
}

// requestLineOf re-reads the method and path out of a request's first line.
//
// # Why the proxy needs this a second time
//
// method and path are parsed once, from the client's request line, at handleConnection. Everything
// after that point can rewrite the line — Match & Replace's request_first_line category, the
// request-direction option rules, and above all the operator's own hold in Intercept — and until this
// existed the locals kept the client's original answer for the rest of the exchange. Two things
// downstream read them:
//
//   - The scope check. A rule with a path prefix (core.NewScopeRuleWithPath) is evaluated against
//     this path, so an edit that moved a request under an excluded prefix was checked against the
//     path the client asked for and let through — the fence answered about a URL nobody was going to
//     send to. Same class as the retarget arming the host check above, and the reason that one is
//     re-run after the hold too.
//
//   - The recorded index row. core.Exchange.Path is what history, the site map and the search index
//     show without reading a message's bytes, so a row whose Path disagreed with its own request was
//     a row pointing at a URL the capture does not contain. The operator could see the Edited badge
//     and still have no idea which endpoint was touched.
//
// Absolute-form is honoured, not assumed away: the bytes are rewritten to origin-form before the
// hold (see toOriginForm), and an operator is free to type an absolute URL back into the held request.
// Returning ok=false on an unreadable head rather than guessing keeps a malformed line from silently
// repointing anything — the caller keeps what it had, and the bytes are still whatever they are.
func requestLineOf(raw []byte) (method, path string, ok bool) {
	end := bytes.IndexByte(raw, '\n')
	if end < 0 {
		return "", "", false
	}
	fields := strings.Fields(strings.TrimRight(string(raw[:end]), "\r\n"))
	if len(fields) < 2 {
		return "", "", false
	}
	target := fields[1]
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		_, _, p := parseTarget(target)
		if p == "" {
			return "", "", false
		}
		return fields[0], p, true
	}
	return fields[0], target, true
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

// readFullRequest reads one whole HTTP request off the client connection: the request line, the
// header block, and the body under the framing the head actually declares.
//
// Both framings are handled, and the difference matters more than it looks. The previous version
// recognised `Content-Length:` only, so a `Transfer-Encoding: chunked` upload was forwarded as a
// header promising a body that had never been read — the origin sat waiting for bytes that would
// never arrive, and the request recorded in history had no body at all (burpsy-react-ui-3tc7,
// reproduced at 98 bytes in / 53 out).
//
// A malformed length or chunk stream returns the message without a body rather than a message with
// a half-read one: a head that declares a body the reader could not read must not be forwarded
// claiming it was read, which is the same failure the old code produced for every chunked request.
//
// A chunked body is DE-chunked and the head rewritten to `Content-Length`, rather than re-framed.
// Everything downstream — the intercept hold, the match-and-replace pass, the operator's editor,
// the record — takes one byte slice and works on whole messages, so a re-framed stream would have to
// be decoded again at each of those. The rewiring is a rewrite of `Content-Length` alone; the
// original chunk-size and chunk extensions are not preserved, because the head no longer advertises
// them.
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

	head := buf.String()
	// Both header lookups fold case: "Content-Length:" and "content-length:" are the same field
	// (RFC 9110 §5.1), and a request written in either case has a body this must read. The previous
	// exact-case search meant a lower-case chunked or length-framed request was silently treated as
	// bodyless.
	length, lengthOK := headerInt(head, "content-length")
	chunked := headerHasToken(head, "transfer-encoding", "chunked")

	switch {
	case lengthOK && length > 0:
		body, ok := readExactly(reader, length)
		if !ok {
			// Short body: forward the head alone rather than a head promising bytes that are not
			// there. The origin will reject it, and the record will not claim a body it never read.
			return buf.Bytes()
		}
		buf.Write(body)
	case chunked:
		body, complete := readChunkedBody(reader)
		if !complete {
			// A chunk stream that ends early is not a body, and is certainly not one to forward.
			return buf.Bytes()
		}
		rewritten := rewriteChunkedToLength(head, len(body))
		if rewritten == "" {
			return buf.Bytes()
		}
		buf.Reset()
		buf.WriteString(rewritten)
		buf.Write(body)
	}

	return buf.Bytes()
}

// readExactly reads n bytes or reports that the stream ended first. io.ReadFull's EOF is not enough
// on its own here: a partial read that is then forwarded is the corruption this whole function
// exists to prevent.
func readExactly(reader *bufio.Reader, n int) ([]byte, bool) {
	if n < 0 || n > maxBufferedRequestBody {
		return nil, false
	}
	out := make([]byte, n)
	read, err := io.ReadFull(reader, out)
	if err != nil {
		return nil, false
	}
	return out[:read], true
}

// readChunkedBody decodes a chunked stream into its payload, following RFC 9112 §7.1: a hex size, an
// optional extension after ';', that many bytes, a CRLF, and finally the zero-size chunk with its
// trailers.
//
// The completeness flag is the point. A stream that ends before its zero chunk is not a complete body,
// and the caller must not forward a head that claims one.
func readChunkedBody(reader *bufio.Reader) ([]byte, bool) {
	var out bytes.Buffer
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, false
		}
		sizeText := strings.TrimSpace(line)
		if i := strings.IndexByte(sizeText, ';'); i >= 0 {
			sizeText = strings.TrimSpace(sizeText[:i])
		}
		size, err := strconv.ParseUint(sizeText, 16, 64)
		if err != nil {
			return nil, false
		}
		if size == 0 {
			// The terminal chunk. Trailers, if any, run to the blank line; read and discard them so
			// the next request on this connection starts at a message boundary.
			for {
				trailer, err := reader.ReadString('\n')
				if err != nil {
					return nil, false
				}
				if strings.TrimSpace(trailer) == "" {
					return out.Bytes(), true
				}
			}
		}
		if uint64(out.Len())+size > maxBufferedRequestBody {
			// A chunk stream that declares more than this is refused rather than buffered: the point
			// of this path is to hold one request in memory for the intercept and edit surfaces, and
			// an unbounded body would make that a memory-exhaustion primitive.
			return nil, false
		}
		chunk, ok := readExactly(reader, int(size))
		if !ok {
			return nil, false
		}
		out.Write(chunk)
		// The CRLF that ends every chunk's data is framing, not payload.
		if crlf, err := reader.Peek(2); err == nil && string(crlf) == "\r\n" {
			_, _ = reader.Discard(2)
		} else if lf, err := reader.Peek(1); err == nil && string(lf) == "\n" {
			_, _ = reader.Discard(1)
		}
	}
}

// rewriteChunkedToLength replaces the Transfer-Encoding header with a Content-Length carrying the
// decoded body's size, leaving every other header byte untouched — the name's casing, the spacing,
// the order. A rewritten header is the only head change the de-chunked body needs, and everything
// after it is the same head the client wrote.
func rewriteChunkedToLength(head string, bodyLen int) string {
	lines := strings.Split(head, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		name, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Transfer-Encoding") {
			// Dropped, not rewritten: the remaining values (gzip, and so on) describe a transfer
			// coding this body no longer uses. Keeping a partial value would be a lie about the
			// framing.
			continue
		}
		kept = append(kept, line)
	}
	// The Content-Length goes immediately before the blank line that ends the head, which is the
	// last element of `lines`.
	blank := len(kept) - 1
	if blank < 0 {
		return ""
	}
	kept = append(kept[:blank], append([]string{"Content-Length: " + strconv.Itoa(bodyLen)}, kept[blank:]...)...)
	return strings.Join(kept, "\n")
}

// headerInt reads a numeric header, case-insensitively. ok is false when the field is absent or
// unparseable, so a caller cannot mistake "no length" for "length zero".
func headerInt(head, name string) (int, bool) {
	value, ok := headerValueFold(head, name)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// headerHasToken reports whether a comma-separated header carries token, case-insensitively. Used
// for Transfer-Encoding, where "chunked" may be one of several codings and may carry parameters.
func headerHasToken(head, name, token string) bool {
	value, ok := headerValueFold(head, name)
	if !ok {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		if field, _, _ := strings.Cut(part, ";"); strings.EqualFold(strings.TrimSpace(field), token) {
			return true
		}
	}
	return false
}

// headerValueFold returns the first value of a named header, whatever case it was written in.
func headerValueFold(head, name string) (string, bool) {
	for _, line := range strings.Split(head, "\n") {
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(field), name) {
			return value, true
		}
	}
	return "", false
}

// serverIPOf is the destination's resolved IP as this socket actually reached it, for history's IP
// column (burpsy-react-ui-mr4p). Empty for a nil conn or an address with no host part.
//
// Read off the live socket rather than resolved by name, and that is the point: the row is a record
// of one exchange, and re-resolving the host later answers where the name points now. A round-robin
// DNS name or a failover would make that a different address, presented as a fact about a request
// that went somewhere else.
func serverIPOf(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return host
}

// listenerPortOf is the proxy listener port the client connected to, for history's Listener port
// column (burpsy-react-ui-he81). Zero for a nil conn or an unparseable address.
//
// Taken from the CLIENT connection's local address, which is the listener's own port by
// construction — asking the Server for its configured bind would answer with whatever it is bound
// to now, and a rebind (burpsy-react-ui-77m) makes that a different port from the one this request
// arrived on.
func listenerPortOf(conn net.Conn) uint16 {
	if conn == nil {
		return 0
	}
	addr := conn.LocalAddr()
	if addr == nil {
		return 0
	}
	_, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return 0
	}
	return uint16(port)
}

// scopeDropResponse is what a client gets when "Drop all out-of-scope requests" refuses its
// request. 403 rather than a closed connection, and the deciding rule in the body rather than an
// empty one: this refusal comes from a setting the operator may have enabled hours ago, and the
// difference between "burpsy refused this" and "the network failed" is the difference between a
// five-second fix and an afternoon.
//
// Explain names the rule that decided, the same text the Repeater and Intruder refusals carry, so
// one refusal is worded one way across the whole tool.
func scopeDropResponse(host string, port uint16, path string, tls bool, scope *core.Scope) []byte {
	body := "burpsy dropped this request: out-of-scope request handling is set to drop.\n" +
		scope.Explain(host, port, path, tls) + "\n"
	return []byte("HTTP/1.1 403 Forbidden\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body)
}

// wsRetargetRefusalResponse answers a held WebSocket upgrade the operator pointed at another
// destination (burpsy-react-ui-akv).
//
// Refused rather than retargeted, and this is a correctness boundary rather than a gap: the client's
// frames arrive on the tunnel the operator did not retarget, so a handshake sent elsewhere would
// produce a relay whose two halves are talking to different origins — the client's frames would keep
// going to the original host while the origin that answered is a different one. That is not a
// degraded version of the feature; it is two conversations mixed together. Answered with the reason
// so the operator sees a 502 with an explanation rather than a hang they would read as a network
// fault, which is the convention the scope drop already follows.
func wsRetargetRefusalResponse() []byte {
	body := "burpsy did not retarget this request: it is a WebSocket upgrade, whose frames keep " +
		"arriving on the connection the client opened. Retargeting the handshake would relay the client's " +
		"frames to the original origin while the response came from another one. Retarget a plain " +
		"request instead.\n"
	return []byte("HTTP/1.1 502 Bad Gateway\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body)
}

// forwardOnly forwards one out-of-scope exchange without retaining it.
//
// # The rules still run here, and that is the whole point of the function
//
// Scope decides what is *retained*, never what is *rewritten*. Both the request-direction options and
// the request-direction Match & Replace rules have already run by the time this is called — the
// caller's comment says so — and this function is where the response direction catches up: the
// response options and now the response Match & Replace rules as well.
//
// # Why Match & Replace was the last one missing
//
// handleTLSResponse has always applied the Match & Replace response rules before its own scope
// check, so an out-of-scope HTTPS response was rewritten while an out-of-scope plaintext one was
// written through untouched: same rule set, same scope verdict, opposite behaviour decided by which
// port the destination happened to listen on. That is the same asymmetry the response *options* had
// here before they were fixed (see the comment on the copy below), and it matters for the same
// reason: a rule that silently lapses for part of the traffic is worse than one that is off, because
// the panel says it is on. It also broke the invariant the request side is built on — that an
// out-of-scope forward sends exactly the bytes the recorded path would — for the response half only.
//
// Found by this file's own test for the in-scope restriction (burpsy-react-ui-rfgs), which asserted
// both directions were rewritten with the restriction off and got one.
// tls is the destination's scheme, and it is threaded rather than assumed plaintext because a
// listener with "Force use of TLS" set has to reach the origin over TLS on this path too
// (burpsy-react-ui-pfeg). This is the forward-but-do-not-record path, so an out-of-scope request
// on such a listener used to be the one request that quietly went out in the clear — the
// no-op the setting must not have.
func (s *Server) forwardOnly(clientConn net.Conn, clientReader *bufio.Reader, requestData []byte, method, host string, port uint16, path string, tls bool) {
	upstreamConn, err := s.dialUpstreamFor(context.Background(), host, port, tls)
	if err != nil {
		return
	}
	defer upstreamConn.Close()

	upstreamConn.Write(s.forForwarding(requestData, host, method, path))

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
		// A response that is not the 101 is an ordinary response — the upgrade was refused — so it
		// takes the same two steps as the plaintext copy below, in the same order and for the same
		// reason. The 101 itself is deliberately left alone: rewriting a handshake would break it,
		// and that is true on this path exactly as it is on the recorded one.
		resp := s.applyMatchReplace(matchreplace.DirResponse, append(head, body...), host, port, path, false)
		clientConn.Write(s.applyResponseRulesUnrecorded(resp))
		return
	}

	// Copy exactly one response back; keep-alive connections never EOF.
	//
	// The response modification rules run here too, and that is the fix for a real
	// asymmetry rather than a nicety. handleTLSResponse has always applied them before
	// its own `if inScope` check, so an out-of-scope HTTPS response was rewritten; this
	// path returned early and wrote the origin's bytes through untouched, so an
	// out-of-scope plaintext response was not. Same option, same scope verdict, opposite
	// behaviour decided by whether the destination happened to use TLS.
	//
	// The direction of the fix is set by what these rules are. "Remove all JavaScript"
	// and "remove <object> tags" are defensive — an operator turns them on to stop
	// content reaching their browser — and a defence that silently lapses for part of the
	// traffic is worse than one that is off, because the panel says it is on. It is also
	// what applyRequestRules already documents for the request direction: rules run
	// before the scope check so an out-of-scope forward sends exactly the bytes the
	// recorded path would. Scope decides what is *retained*, never what is *rewritten*.
	//
	// Unrecorded, hence the counter: nothing here is stored, so the rewrite is real but
	// invisible in history, and Counters.ModifiedUnrecorded is what makes it accountable.
	if resp, _, err := readHTTPResponse(upstreamConn); err == nil {
		// Match & Replace first, then the blanket response modification rules — the same order, and
		// for the same reason, as handleTLSResponse and completeResponse: a Match & Replace rule is
		// written against the origin's own bytes, and running "remove all JavaScript" first would
		// delete the text the rule was written to find.
		resp = s.applyMatchReplace(matchreplace.DirResponse, resp, host, port, path, false)
		clientConn.Write(s.applyResponseRulesUnrecorded(resp))
	}
}

// The resolved destination IP comes back with the response because this function owns the socket
// and closes it before returning: by the time the caller records the exchange there is nothing left
// to ask (burpsy-react-ui-mr4p). Empty on any path that never dialled.
// forwardRequest sends one request to one destination over a fresh connection and reads the whole
// response. tls decides whether that connection is wrapped, which is what makes an operator's
// retarget able to change the scheme as well as the host (burpsy-react-ui-akv).
//
// One request per connection, deliberately. This is the path a retarget uses, and a retargeted
// request has nowhere to keep a connection: the item the operator edited is one exchange, and
// holding a socket open to a host that the client never asked for would leave the proxy dialled into
// a destination nobody is talking to any more.
// dialUpstreamFor opens the connection to the destination in the destination's own scheme.
// It is the one place the plaintext relay decides between a TCP dial and a TLS one, so
// "Force use of TLS" reaches every caller by setting tls rather than by each caller
// remembering to branch.
func (s *Server) dialUpstreamFor(ctx context.Context, host string, port uint16, tls bool) (net.Conn, error) {
	if !tls {
		return s.dialUpstream(ctx, host, port)
	}
	// No ALPN offer: this path speaks HTTP/1.1 to the origin (the caller reads the response
	// head itself and is not negotiating a multiplexed connection), and offering h2 while
	// writing an HTTP/1.1 request line is how an origin that accepts h2 answers with a
	// protocol error.
	// The same address the plaintext path computes, so a hostname override is not silently bypassed
	// by the TLS leg (burpsy-react-ui-o1eu). The SNI stays `host`: an override replaces the lookup,
	// not the name the origin is asked for.
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if n := s.config.network; n != nil {
		addr = n.Resolution.DialAddress(context.Background(), host, port)
	}
	conn, _, err := s.dialUpstreamTLS(host, addr, nil)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *Server) forwardRequest(requestData []byte, host string, port uint16, tls bool) ([]byte, string, time.Time, error) {
	upstreamConn, err := s.dialUpstreamFor(context.Background(), host, port, tls)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	defer upstreamConn.Close()
	serverIP := serverIPOf(upstreamConn)

	if _, err := upstreamConn.Write(s.forForwarding(requestData, host, requestMethod(requestData), requestURI(requestData))); err != nil {
		return nil, serverIP, time.Time{}, err
	}

	// The first-byte instant is read here so a caller building an exchange row can report TTFB
	// (Burp's "Start response timer") separately from the total. The caller takes the completion
	// instant itself, right after this returns, which is when the last byte was read.
	// The operator's 100-continue handling decides whether an interim head is read past; on by
	// default, which is Burp's own default and the only correct answer when the client is a browser
	// (burpsy-react-ui-o1eu).
	understand100 := true
	if n := s.config.network; n != nil {
		understand100 = n.Continue.Understand100
	}
	resp, firstByte, err := readHTTPResponseSkippingInterim(upstreamConn, understand100)
	if err == nil {
		// Same reason as the keep-alive leg: a challenge learned here is what lets the NEXT request
		// through this proxy authenticate. This path dials a fresh connection each time, so the
		// learned nonce outlives the connection in the credential store rather than in a socket.
		if headEnd := requestHeadEnd(resp); headEnd > 0 {
			learnFromChallenge(s.config.platformAuth, host, platformAuthChallenges(resp[:headEnd]))
		}
	}
	return resp, serverIP, firstByte, err
}

// readHTTPResponse reads one complete HTTP response from conn, respecting
// Content-Length and chunked transfer encoding instead of waiting for EOF
// (which never comes on a keep-alive connection). It also reports the instant the
// first response byte arrived, for a caller reporting time-to-first-byte.
func readHTTPResponse(conn net.Conn) ([]byte, time.Time, error) {
	return httputil.ReadHTTPResponseTimed(conn)
}

// readHTTPResponseSkippingInterim is readHTTPResponse with the operator's 100-continue handling
// applied (burpsy-react-ui-o1eu): when Understand100 is on — the default, and Burp's — an interim
// 1xx head is read past and the FINAL response is returned, so a browser that sends
// `Expect: 100-continue` is not handed a bare "100 Continue" as the answer. A 101 is never skipped:
// it is the last HTTP response on that connection and the bytes after it belong to the upgraded
// protocol.
//
// Interim heads are counted and bounded, and the bound mirrors the sender's own (read.go:17): a peer
// that answers with interim statuses forever is keeping the connection busy for nothing, and needs a
// floor rather than a spin. The error names the count, so an operator can tell a misbehaving peer
// from a slow one.
func readHTTPResponseSkippingInterim(conn net.Conn, understand100 bool) ([]byte, time.Time, error) {
	if !understand100 {
		return readHTTPResponse(conn)
	}
	br := bufio.NewReader(conn)
	firstByte := time.Time{}
	for interim := 0; ; interim++ {
		head, at, err := httputil.ReadResponseHeadTimed(br)
		if err != nil {
			return nil, time.Time{}, err
		}
		if firstByte.IsZero() {
			firstByte = at
		}
		body, err := httputil.ReadResponseBody(br, head)
		if err != nil {
			return nil, time.Time{}, err
		}
		raw := make([]byte, 0, len(head)+len(body))
		raw = append(raw, head...)
		raw = append(raw, body...)
		if !isInterimResponseHead(head) {
			return raw, firstByte, nil
		}
		if interim+1 >= maxInterimResponses {
			return raw, firstByte, fmt.Errorf("peer sent %d interim responses without a final one", maxInterimResponses)
		}
		// A 1xx carries no body, so br sits at the start of the next head.
	}
}

// maxInterimResponses bounds how many interim heads this leg reads past before treating the peer as
// misbehaving. The same value the sender uses, for the same reason.
const maxInterimResponses = 8

// isInterimResponseHead reports whether a head is a 1xx that is not 101. Parsed off the status line
// rather than assumed from an offset, because this decides whether more bytes are read off the
// socket: reading again after a final response blocks until the peer's next response.
func isInterimResponseHead(head []byte) bool {
	if len(head) < 12 {
		return false
	}
	code := 0
	for _, b := range head[9:12] {
		if b < '0' || b > '9' {
			return false
		}
		code = code*10 + int(b-'0')
	}
	return code >= 100 && code < 200 && code != 101
}

// The proxy's own status-line parser used to live here. It is gone rather than
// unused: every exchange row is now built by scanner.Capture.Record, which reads
// the status off the response the store has already parsed, so a second parser
// in this package could only ever be a way for the row and the message it
// indexes to disagree about the same bytes. Its three test cases moved with it,
// to internal/scanner/capture_test.go.
