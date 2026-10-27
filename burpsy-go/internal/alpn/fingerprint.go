package alpn

// Browser-like TLS fingerprints for upstream dials (burpsy-react-ui-63pf).
//
// Go's own ClientHello has a stable JA3/JA4 signature that WAF and bot-detection front ends
// classify differently from a browser's. With a Fingerprint set, Dial presents a Chrome,
// Firefox, Safari or randomized hello (utls) instead, while everything around the hello -
// the carrier, verification, client certificates, MinVersion, the ALPN offer and the SNI
// override - keeps exactly the meaning Dial documents for it.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// Fingerprint selects the ClientHello a dial presents. The empty value is Go's own hello,
// which is what every dial sent before this existed; it stays the default so a caller that
// never asks for a fingerprint is byte-identical to one that did not have the option.
type Fingerprint string

const (
	FingerprintGo         Fingerprint = ""
	FingerprintChrome     Fingerprint = "chrome"
	FingerprintFirefox    Fingerprint = "firefox"
	FingerprintSafari     Fingerprint = "safari"
	FingerprintRandomized Fingerprint = "randomized"
)

// helloID maps the operator-facing selector onto a utls preset. An unknown selector is an
// error naming itself rather than a silent fall back to Go's hello: an operator who asked
// for a fingerprint and got Go's would be measuring the thing they meant to avoid.
func (f Fingerprint) helloID() (utls.ClientHelloID, error) {
	switch f {
	case FingerprintChrome:
		return utls.HelloChrome_Auto, nil
	case FingerprintFirefox:
		return utls.HelloFirefox_Auto, nil
	case FingerprintSafari:
		return utls.HelloSafari_Auto, nil
	case FingerprintRandomized:
		return utls.HelloRandomized, nil
	}
	return utls.ClientHelloID{}, fmt.Errorf("unknown TLS fingerprint %q (want chrome, firefox, safari or randomized)", string(f))
}

// dialFingerprinted is Dial with a utls ClientHello. Every field of Dialer maps onto the
// utls.Config the same way it maps onto the tls.Config in Dial, and any divergence there is
// a bug, not a behaviour: the fingerprint changes the bytes of the hello, nothing else.
func (d Dialer) dialFingerprinted(ctx context.Context, serverName, addr string, offer []string) (net.Conn, string, error) {
	helloID, err := d.Fingerprint.helloID()
	if err != nil {
		return nil, "", err
	}
	ucfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: d.InsecureSkipVerify,
		RootCAs:            d.RootCAs,
		MinVersion:         d.MinVersion,
	}
	if d.SNI != "" && d.SNI != serverName {
		ucfg.ServerName = d.SNI
		if !d.InsecureSkipVerify {
			// Same contract as Dial: verification still runs against the authority dialled,
			// with the same roots; the override only changes the name the hello carries.
			ucfg.InsecureSkipVerify = true
			ucfg.VerifyConnection = verifyAgainstUTLS(serverName, d.RootCAs)
		}
	}
	if len(offer) > 0 {
		ucfg.NextProtos = offer
	}
	if d.ClientCerts != nil {
		ucfg.GetClientCertificate = func(*utls.CertificateRequestInfo) (*utls.Certificate, error) {
			if found := d.ClientCerts.For(serverName); found != nil {
				return utlsCertificate(found), nil
			}
			return &utls.Certificate{}, nil
		}
	}

	// The ALPN offer is a contract of this package ("an empty offer sends no ALPN extension
	// at all"), and the presets carry their own: a Chrome hello would otherwise offer h2 on
	// a dial that promised http/1.1. The preset's ALPN extension is therefore rewritten to
	// the caller's offer - or removed when the offer is empty - which costs the hello a
	// little fidelity and keeps the package's promise.
	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		return nil, "", fmt.Errorf("TLS fingerprint %q: %w", string(d.Fingerprint), err)
	}
	exts := spec.Extensions[:0]
	for _, ext := range spec.Extensions {
		if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
			if len(offer) == 0 {
				continue
			}
			alpnExt.AlpnProtocols = offer
		}
		exts = append(exts, ext)
	}
	spec.Extensions = exts

	var carrier net.Conn
	if d.Carry != nil {
		carrier, err = d.Carry(ctx, "tcp", addr)
	} else {
		carrier, err = (&net.Dialer{Timeout: d.Timeout, Resolver: d.Resolver}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, "", err
	}
	// HelloCustom, not the preset's own ID: ApplyPreset does not mark the hello as built, so
	// a mimicking ID would be re-applied from scratch at handshake time (applyPresetByID is a
	// no-op only for HelloCustom) and the rewritten ALPN extension would be lost. Building
	// the spec from the preset and applying it onto a HelloCustom conn is the only path where
	// the hello the operator's offer demands is the hello that goes on the wire.
	uconn := utls.UClient(carrier, ucfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		_ = carrier.Close()
		return nil, "", fmt.Errorf("TLS fingerprint %q: %w", string(d.Fingerprint), err)
	}
	handshakeCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && d.Timeout > 0 {
		var cancel context.CancelFunc
		handshakeCtx, cancel = context.WithTimeout(ctx, d.Timeout)
		defer cancel()
	}
	if err := uconn.HandshakeContext(handshakeCtx); err != nil {
		_ = carrier.Close()
		return nil, "", err
	}
	// The preset, not the config, owns the offered version range: ApplyPreset overwrites
	// config.MinVersion/MaxVersion from the hello's supported-versions, because a hello that
	// advertises Chrome's extension set but Go's version floor would fool no classifier. The
	// configured floor is therefore enforced here, after the handshake and before a single
	// byte of data: a connection that negotiated below it is refused, never used.
	if version := uconn.ConnectionState().Version; d.MinVersion != 0 && version < d.MinVersion {
		_ = uconn.Close()
		return nil, "", fmt.Errorf("tls: the fingerprinted dial negotiated version 0x%04x, below the configured floor 0x%04x", version, d.MinVersion)
	}
	return uconn, uconn.ConnectionState().NegotiatedProtocol, nil
}

// utlsCertificate converts a parsed client certificate for the utls handshake. The fields
// mirror; utls keeps its own type because its fork predates some stdlib additions. A missing
// Leaf is parsed: utls matches the certificate against the server's signature algorithms
// through Leaf, and a nil Leaf degrades that to silently sending no certificate.
func utlsCertificate(c *tls.Certificate) *utls.Certificate {
	leaf := c.Leaf
	if leaf == nil && len(c.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(c.Certificate[0])
	}
	return &utls.Certificate{
		Certificate:                 c.Certificate,
		PrivateKey:                  c.PrivateKey,
		OCSPStaple:                  c.OCSPStaple,
		SignedCertificateTimestamps: c.SignedCertificateTimestamps,
		Leaf:                        leaf,
	}
}

// verifyAgainstUTLS is verifyAgainst for the utls fork's connection state: same check, same
// roots, same authority, different containing type.
func verifyAgainstUTLS(name string, roots *x509.CertPool) func(utls.ConnectionState) error {
	return func(cs utls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("tls: the server presented no certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			DNSName:       name,
			Roots:         roots,
			Intermediates: intermediates,
		})
		return err
	}
}

// PeerCertificates returns the chain the peer presented on a connection this package
// dialled, whether the handshake was stdlib or fingerprinted. Callers recording server
// certificates use it rather than asserting *tls.Conn, which a fingerprinted dial is not.
func PeerCertificates(conn net.Conn) []*x509.Certificate {
	switch c := conn.(type) {
	case *tls.Conn:
		return c.ConnectionState().PeerCertificates
	case *utls.UConn:
		return c.ConnectionState().PeerCertificates
	}
	return nil
}
