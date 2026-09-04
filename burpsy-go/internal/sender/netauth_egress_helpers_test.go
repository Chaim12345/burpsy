package sender

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/netauth"
	"software.sslmate.com/src/go-pkcs12"
)

// Fixtures for netauth_egress_test.go. Every certificate and PKCS#12 file here is generated
// during the test run and written under t.TempDir(): .gitignore excludes *.pem and *.key,
// and a committed client identity would be key material in the repository whatever the
// directory it sat in.

// generateClientIdentity mints a client leaf, encodes it as PKCS#12, and loads it back
// through the real LoadClientCert so the binding under test is one the production path
// produced. Returns the binding and the leaf DER for the server side to compare against.
//
// The round trip through a file matters: it is what proves the PKCS#12 decode produces a
// tls.Certificate crypto/tls will actually sign a handshake with, which is the one property
// a test that constructed a tls.Certificate directly would not check.
func generateClientIdentity(t *testing.T) (netauth.ClientCert, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "burpsy egress test client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("signing the client leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing the client leaf: %v", err)
	}

	const passphrase = "egress-fixture-passphrase"
	raw, err := pkcs12.Modern2023.Encode(key, leaf, nil, passphrase)
	if err != nil {
		t.Fatalf("encoding PKCS#12: %v", err)
	}
	path := filepath.Join(t.TempDir(), "client.p12")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing the PKCS#12 fixture: %v", err)
	}

	// 127.0.0.1 is what httptest listens on, so this is the pattern that has to match for the
	// certificate to be selected. alpn.Dialer looks the host up by the TLS ServerName, which
	// for these tests is the literal address.
	entry, err := netauth.LoadClientCert("127.0.0.1", path, passphrase)
	if err != nil {
		t.Fatalf("LoadClientCert on a file this test just wrote: %v", err)
	}
	return entry, leafDER
}

// tlsListenerRequiringClientCert starts a bare TLS listener that completes a handshake only
// when the client presents a certificate, and reads-then-closes whatever arrives.
//
// A raw listener rather than httptest.Server because the observation is the handshake
// itself: the raw-bytes path under test does not speak HTTP on this connection, and an HTTP
// server would report a protocol error rather than the handshake outcome the test is about.
func tlsListenerRequiringClientCert(t *testing.T) net.Listener {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a server key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("signing the server leaf: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   tls.RequireAnyClientCert,
	})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// The handshake is lazy until the first read, so force it and then let the connection
			// go. Errors are the client's to observe, not this goroutine's to report — a t.Error
			// from here could fire after the test returned.
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			conn.Close()
		}
	}()
	return listener
}

// splitAddr splits a host:port, naming the input when it cannot.
func splitAddr(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("unusable listener address %q: %w", addr, err)
	}
	return host, port, nil
}

// digestParams reads the parameters out of an `Authorization: Digest ...` header, so a test
// server can check the response hash rather than merely the header's presence.
//
// Deliberately a second, independent parser rather than a call into netauth: a server-side
// check that reused the client's own parser would agree with it by construction, including
// about a bug. This one is naive on purpose — it is reading a header this codebase generated,
// not defending against a hostile one.
func digestParams(header string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(strings.TrimPrefix(header, "Digest "), ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) != 2 {
			continue
		}
		out[strings.ToLower(parts[0])] = strings.Trim(parts[1], `"`)
	}
	return out
}

// expectedDigestResponse computes RFC 7616's qop=auth response with MD5, straight from the
// spec's own formula, for a test server to compare against.
//
// Written out here rather than shared with the implementation for the same reason
// digestParams is: an assertion that calls the code under test asserts nothing.
func expectedDigestResponse(username, realm, password, method, uri, nonce, nc, cnonce string) string {
	h := func(parts ...string) string {
		sum := md5.Sum([]byte(strings.Join(parts, ":")))
		return hex.EncodeToString(sum[:])
	}
	ha1 := h(username, realm, password)
	ha2 := h(method, uri)
	return h(ha1, nonce, nc, cnonce, "auth", ha2)
}
