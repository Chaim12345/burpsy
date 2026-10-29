package proxy

// Per-listener server certificates and protocol selection (burpsy-react-ui-4trc).
//
// # What was unreachable
//
// Every intercepted connection was served a leaf signed by the process CA for the hostname the
// client asked for. That is the right default and it was the only behaviour: an operator who needed
// a listener to present a specific certificate — a client-cert-requiring origin's own bundle, a
// fixed hostname for a vhost that pins it, a self-signed leaf for a target that rejects the CA —
// had nowhere to say so.
//
// # Why a failed load must refuse the edit
//
// The dangerous shape here is a fallback. A listener configured with a PKCS#12 bundle that cannot
// be loaded — wrong password, moved file, truncated export — must not quietly serve the process
// CA's leaf instead: the operator would see a working listener, a browser that trusts it, and
// traffic flowing, with no signal that the certificate they configured is not the one on the wire.
// So a load failure is a validation error on the EDIT, and the listener keeps whatever it was
// serving before.
//
// # Why the password is held rather than consumed once
//
// A bundle is re-read when a listener is rebound, so the password has to outlive the first load.
// It is kept out of every report instead: ListenerStatus is built through redactedSpec, which
// blanks it, and nothing logs it.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// CertMode is how one listener obtains the certificate it serves.
type CertMode string

const (
	// CertModeCAPerHost signs a leaf per requested hostname from the process CA. The zero value
	// and the behaviour every listener had before this existed.
	CertModeCAPerHost CertMode = ""
	// CertModeCAFixed signs one leaf from the process CA for CertHostname, whatever name the
	// client asked for. Burp's "Generate a CA-signed certificate with a specific hostname".
	CertModeCAFixed CertMode = "ca-fixed"
	// CertModeSelfSigned serves a self-signed leaf — no CA involved, so a client that trusts the
	// process CA still sees an untrusted certificate. Burp's "Generate a self-signed certificate".
	CertModeSelfSigned CertMode = "self-signed"
	// CertModePKCS12 serves an operator-supplied bundle from CertFile, unlocked with CertPassword.
	CertModePKCS12 CertMode = "pkcs12"
)

// Valid reports whether the mode is one this proxy knows. An unknown mode is refused at the edit
// rather than defaulting, for the same reason a failed bundle load is: a listener serving something
// other than what its configuration names is the failure this whole file is written against.
func (m CertMode) Valid() bool {
	switch m {
	case CertModeCAPerHost, CertModeCAFixed, CertModeSelfSigned, CertModePKCS12:
		return true
	}
	return false
}

// validateCert checks one spec's certificate selection, loading a PKCS#12 bundle when it names one
// so a bad bundle fails the EDIT rather than the first connection.
//
// Returning the loaded certificate alongside the error is deliberate: the caller stores it on the
// bound listener, so the bundle is parsed once per edit instead of once per connection — and a
// connection can never be the thing that discovers the configuration is broken.
func validateCert(spec ListenerSpec) (*tls.Certificate, error) {
	if !spec.CertMode.Valid() {
		return nil, fmt.Errorf("listener certificate mode %q is not one of ca-per-host, ca-fixed, self-signed or pkcs12", spec.CertMode)
	}
	switch spec.CertMode {
	case CertModeCAFixed:
		if strings.TrimSpace(spec.CertHostname) == "" {
			return nil, fmt.Errorf("listener certificate mode %q needs a hostname to sign for; "+
				"without one the listener would fall back to signing for whatever name the client "+
				"asked for, which is a different mode wearing this one's name", spec.CertMode)
		}
		return nil, nil
	case CertModePKCS12:
		if strings.TrimSpace(spec.CertFile) == "" {
			return nil, fmt.Errorf("listener certificate mode %q needs a PKCS#12 file", spec.CertMode)
		}
		cert, err := loadPKCS12(spec.CertFile, spec.CertPassword)
		if err != nil {
			// Named with the file so an operator can tell a wrong password from a wrong path, and
			// returned as an edit failure: the listener keeps serving whatever it served before.
			return nil, fmt.Errorf("listener certificate bundle %q could not be loaded: %w; the "+
				"listener is unchanged rather than falling back to the process CA", spec.CertFile, err)
		}
		return cert, nil
	}
	return nil, nil
}

// loadPKCS12 reads a .p12/.pfx bundle into a usable TLS certificate.
func loadPKCS12(path, password string) (*tls.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, leaf, chain, err := pkcs12.DecodeChain(raw, password)
	if err != nil {
		return nil, err
	}
	if leaf == nil {
		return nil, fmt.Errorf("the bundle carries no leaf certificate")
	}
	out := &tls.Certificate{PrivateKey: key, Leaf: leaf}
	out.Certificate = append(out.Certificate, leaf.Raw)
	for _, c := range chain {
		// The intermediates are offered too: a client that trusts the bundle's issuer but holds no
		// intermediate cannot build a path without them, and "it works on my machine" is exactly
		// the shape that produces.
		out.Certificate = append(out.Certificate, c.Raw)
	}
	return out, nil
}

// certificateFor resolves the leaf this listener serves for one requested hostname.
//
// certName is the name the CLIENT asked for, which is not always the destination — a redirecting
// listener has moved them apart, and the certificate has to match what the client expects to see or
// the handshake fails before any of this matters.
func (s *Server) certificateFor(spec ListenerSpec, loaded *tls.Certificate, certName string) (*tls.Certificate, error) {
	// One read of the engine for the whole decision: interception can be switched off at runtime
	// (PUT /api/proxy/interception) between the passthrough check and this mint.
	engine := s.config.tls.Engine()
	if engine == nil && spec.CertMode != CertModePKCS12 {
		return nil, fmt.Errorf("TLS interception was switched off while %s was being intercepted", certName)
	}
	switch spec.CertMode {
	case CertModePKCS12:
		if loaded == nil {
			// Unreachable while every path that sets the mode also validates it, and an error
			// rather than a fallback because the alternative is serving the wrong certificate.
			return nil, fmt.Errorf("listener %s is configured for a PKCS#12 bundle that was never loaded", spec.ID)
		}
		return loaded, nil
	case CertModeSelfSigned:
		return engine.selfSignedCertificate(certName)
	case CertModeCAFixed:
		return engine.GetCertificate(spec.CertHostname)
	default:
		return engine.GetCertificate(certName)
	}
}

// tlsVersionsFor returns the min/max the listener's handshake should use. Zero on either side is
// left zero, which is crypto/tls's own default — a listener that names neither behaves as before.
func tlsVersionsFor(spec ListenerSpec) (uint16, uint16) {
	return spec.TLSMinVersion, spec.TLSMaxVersion
}

// redactedSpec is the spec as the API may report it: everything except the bundle password.
//
// A method on the type rather than a filter at each handler, because there is more than one place a
// listener is reported and a password leaking from the one that was forgotten is the whole risk.
func redactedSpec(spec ListenerSpec) ListenerSpec {
	spec.CertPassword = ""
	return spec
}

// selfSignedCertificate mints a leaf that signs itself — no CA in the path, so a client trusting
// the process CA still sees an untrusted certificate. That is the mode's POINT: it is for a target
// that rejects the CA, where the operator wants to see the untrusted-certificate behaviour rather
// than paper over it.
//
// Cached per host like the CA-signed leaves, in a separate pool: the two modes produce different
// certificates for the same hostname, and one cache would hand a listener whichever mode happened
// to ask first.
func (e *TlsEngine) selfSignedCertificate(host string) (*tls.Certificate, error) {
	e.poolMu.Lock()
	cached, ok := e.selfSigned.Get(host)
	e.poolMu.Unlock()
	if ok {
		return cached, nil
	}

	// Per-host singleflight, same shape as GetCertificate — except there is no CA
	// in the path, so the mint never touches e.mu: a CA swap neither waits for nor
	// invalidates self-signed leaves.
	v, err, _ := e.selfMint.Do(host, func() (any, error) {
		e.poolMu.Lock()
		cached, ok := e.selfSigned.Get(host)
		e.poolMu.Unlock()
		if ok {
			return cached, nil
		}

		cert, err := e.mintSelfSignedLeaf(host)
		if err != nil {
			return nil, err
		}
		e.poolMu.Lock()
		e.selfSigned.Add(host, cert)
		e.poolMu.Unlock()
		return cert, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*tls.Certificate), nil
}

// mintSelfSignedLeaf generates a fresh self-signed leaf for host.
func (e *TlsEngine) mintSelfSignedLeaf(host string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("self-signed key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("self-signed serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(0, 0, leafValidityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	// Template signed by ITSELF with its own key, which is the whole difference from GetCertificate.
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("self-signed certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing the self-signed certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}
