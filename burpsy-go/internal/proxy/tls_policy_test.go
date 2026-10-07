package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
)

// Every intercepted TLS leg opened with InsecureSkipVerify: true and nothing anywhere could turn that
// off (burpsy-react-ui-f365). An operator comparing two builds of the same app could not tell from
// burpsy whether the certificate had changed, because a swapped, expired, self-signed or
// hostname-mismatched certificate was indistinguishable from a good one.
//
// These tests drive the real dialer against real origins with real certificates. A unit test on a bool
// would not have caught the original defect, which was that the value was not on the path at all.

func selfSignedCert(t *testing.T, commonName string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// startTLSOrigin runs a TLS listener with the given certificate and returns its host:port.
func startTLSOrigin(t *testing.T, cert tls.Certificate) (string, uint16) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 512)
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _ = conn.Read(buf) // read the request, then drop it
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	for _, c := range portStr {
		port = port*10 + uint16(c-'0')
	}
	return host, port
}

// The central claim: a self-signed certificate an operator has not added to the trust store is now
// refused, where before it was accepted silently.
func TestAnUntrustedOriginCertificateIsRefusedByDefault(t *testing.T) {
	cert := selfSignedCert(t, "self-signed.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	host, port := startTLSOrigin(t, cert)

	srv := NewServer(NewProxyConfig(nil).WithScope(testScope()))
	_, _, err := srv.dialUpstreamTLS(host, net.JoinHostPort(host, strconv.Itoa(int(port))), nil)
	if err == nil {
		t.Fatal("the handshake succeeded against a self-signed certificate: an operator comparing two builds " +
			"of the same app still could not tell whether the certificate changed (burpsy-react-ui-f365)")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Errorf("error = %q, want one that names the certificate; a bare handshake failure leaves the "+
			"operator unable to tell a certificate problem from a network one", err)
	}
}

// The escape hatch every assessor needs: turning verification off reaches this specific target and
// nothing else changes.
func TestVerificationCanBeTurnedOffForASelfSignedTarget(t *testing.T) {
	cert := selfSignedCert(t, "self-signed.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	host, port := startTLSOrigin(t, cert)

	srv := NewServer(NewProxyConfig(nil).WithScope(testScope()).WithUpstreamTLS(NewTLSPolicy().WithVerify(false)))
	conn, _, err := srv.dialUpstreamTLS(host, net.JoinHostPort(host, strconv.Itoa(int(port))), nil)
	if err != nil {
		t.Fatalf("the handshake failed with verification off: %v — the escape hatch is the answer to a "+
			"self-signed target and it has to work", err)
	}
	conn.Close()
}

// An EXPIRED certificate is refused with verification on, and accepted with it off. An assessor
// meeting an expired cert on a lab box is the common case; an operator comparing builds is the one the
// bead is about, and they need the two to be distinguishable.
func TestAnExpiredCertificateIsRefusedUnlessVerificationIsOff(t *testing.T) {
	expired := selfSignedCert(t, "expired.test", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	host, port := startTLSOrigin(t, expired)

	verifying := NewServer(NewProxyConfig(nil).WithScope(testScope()))
	if _, _, err := verifying.dialUpstreamTLS(host, net.JoinHostPort(host, strconv.Itoa(int(port))), nil); err == nil {
		t.Error("an expired certificate was accepted with verification on: the whole point of the setting " +
			"is that a changed certificate is visible")
	}

	permissive := NewServer(NewProxyConfig(nil).WithScope(testScope()).WithUpstreamTLS(NewTLSPolicy().WithVerify(false)))
	conn, _, err := permissive.dialUpstreamTLS(host, net.JoinHostPort(host, strconv.Itoa(int(port))), nil)
	if err != nil {
		t.Errorf("an expired certificate was refused with verification off: %v", err)
	} else {
		conn.Close()
	}
}

// A custom CA is the answer that keeps verification ON: the operator's own issuer is trusted, and
// everything else still is not.
func TestACustomCAIsTrustedWhileVerificationStaysOn(t *testing.T) {
	cert := selfSignedCert(t, "private-ca.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	host, port := startTLSOrigin(t, cert)

	// The origin's certificate, written out as the bundle the operator would supply.
	dir := t.TempDir()
	bundle := filepath.Join(dir, "corporate-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(bundle, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	policy := NewTLSPolicy()
	if err := policy.WithRootCAFile(bundle); err != nil {
		t.Fatalf("WithRootCAFile: %v", err)
	}
	srv := NewServer(NewProxyConfig(nil).WithScope(testScope()).WithUpstreamTLS(policy))
	conn, _, err := srv.dialUpstreamTLS(host, net.JoinHostPort(host, strconv.Itoa(int(port))), nil)
	if err != nil {
		t.Fatalf("the handshake failed with the operator's own CA trusted: %v — a custom CA is how a private "+
			"issuer is reached WITHOUT giving up verification, and if it does not work the only remaining "+
			"option is the switch this setting exists to avoid needing", err)
	}
	conn.Close()
}

// A CA bundle that is not a CA is reported when it is configured, not at some later handshake.
func TestAnUnreadableOrInvalidCABundleIsRefusedAtConfigurationTime(t *testing.T) {
	policy := NewTLSPolicy()

	if err := policy.WithRootCAFile(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Error("a missing CA file was accepted; the operator finds out at configuration time, not at a handshake")
	}

	notACert := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(notACert, []byte("this is not PEM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := policy.WithRootCAFile(notACert)
	if err == nil {
		t.Fatal("a file containing no certificates was accepted as a CA bundle")
	}
	if !strings.Contains(err.Error(), "no certificates") {
		t.Errorf("error = %q, want it to say the bundle held none", err)
	}
}

// A protocol floor below TLS 1.0 is refused rather than clamped, because there is no such protocol and
// accepting the number would be a setting that cannot mean what it says.
func TestAMinVersionBelowTLS10IsRefused(t *testing.T) {
	policy := NewTLSPolicy()
	if err := policy.WithMinVersion(0x0300); err == nil {
		t.Error("a version below TLS 1.0 was accepted; there is no protocol there to select")
	}
	if err := policy.WithMinVersion(tls.VersionTLS12); err != nil {
		t.Errorf("TLS 1.2 was refused: %v — lowering the floor for a legacy target is the case the setting exists for", err)
	}
	if got := policy.minVersion; got != tls.VersionTLS12 {
		t.Errorf("minVersion = 0x%04x, want 0x%04x", got, tls.VersionTLS12)
	}
}

// The default is verification ON, including for a proxy that never had a policy attached. A zero-value
// policy that verified nothing would reintroduce the original defect through the default path.
func TestAProxyWithNoPolicyAttachedStillVerifies(t *testing.T) {
	cfg := NewProxyConfig(nil).WithScope(testScope())
	if cfg.CarriesUpstreamTLS() {
		t.Error("a bare config claims to carry a TLS policy it was never given")
	}
	if !cfg.TLS().Verify() {
		t.Error("the default policy does not verify: a proxy built without WithUpstreamTLS accepts any " +
			"certificate, which is the defect this file exists to close")
	}
	// And it is attached by first use, so the dial path never sees nil.
	if !cfg.CarriesUpstreamTLS() {
		t.Error("TLS() did not attach the default policy; the dial path would have to nil-check on every connection")
	}
}

// The policy's three settings reach the dialer together. Reading them under one lock is what stops a
// handshake seeing verification from one edit and a root pool from another.
func TestThePolicyReachesTheDialerAsOneDecision(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	cert := selfSignedCert(t, "ca.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}

	policy := NewTLSPolicy().WithVerify(true)
	if err := policy.WithMinVersion(tls.VersionTLS12); err != nil {
		t.Fatal(err)
	}
	if err := policy.WithRootCAFile(bundle); err != nil {
		t.Fatal(err)
	}

	dialer := &alpn.Dialer{}
	policy.applyTo(dialer)

	if dialer.InsecureSkipVerify {
		t.Error("the dialer skips verification with the policy's verify=true")
	}
	if dialer.RootCAs == nil {
		t.Error("the custom CA did not reach the dialer: an operator who added a private issuer and kept " +
			"verification on would still be refused")
	}
	if dialer.MinVersion != tls.VersionTLS12 {
		t.Errorf("minVersion = 0x%04x, want 0x%04x", dialer.MinVersion, tls.VersionTLS12)
	}

	// Turning verification off must not silently drop the CA: an operator who flips the switch back
	// should not have to re-add their bundle.
	policy.WithVerify(false)
	second := &alpn.Dialer{}
	policy.applyTo(second)
	if !second.InsecureSkipVerify {
		t.Error("turning verification off did not reach the dialer")
	}
	if second.RootCAs == nil {
		t.Error("turning verification off dropped the custom CA; flipping the switch back would then need " +
			"the bundle re-added, and the operator would have no reason to know")
	}
}

// The startup restore must MUTATE the policy the proxy already holds, not replace it. The builder
// chain attaches the instance before the restore runs, so a restore that builds a new policy and
// assigns it to a local leaves the proxy on its default -- verifying -- while the console reports the
// operator's restored "do not verify". That is the panel and the leg disagreeing, and it is invisible
// until a self-signed target is refused.
//
// This asserts the SHAPE the wiring must have, by reading cmd/burpsy/main.go: the restore has to call
// a mutator on the attached variable, and must not assign a freshly built policy to it. A unit test on
// the policy cannot catch this, because the policy behaves correctly in isolation -- the bug was always
// in which instance the restore reached.
func TestTheStartupRestoreMutatesTheAttachedPolicyRatherThanReplacingIt(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "burpsy", "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	text := string(src)

	// The attach, and the restore, must name the same variable.
	attach := strings.Index(text, "proxyConfig.WithUpstreamTLS(restoredTLSPolicy)")
	restore := strings.Index(text, "restoredTLSPolicy.WithVerify(applied.TLS.Verify)")
	if attach < 0 || restore < 0 {
		t.Fatalf("the TLS policy is not wired as expected: attach at %d, restore at %d. The proxy leg must "+
			"be given the same instance the restore writes to (burpsy-react-ui-f365)", attach, restore)
	}
	if attach > restore {
		t.Errorf("the policy is attached at offset %d but the restore writes at %d: a restore that runs "+
			"before the attach cannot reach the instance the proxy holds", attach, restore)
	}

	// And the restore must not REPLACE the variable. An assignment of a freshly built policy is the
	// specific bug: the console would report the restored value while the proxy kept its default.
	if reassigned := strings.Contains(text, "restoredTLSPolicy = proxy.NewTLSPolicy()") ||
		strings.Contains(text, "restoredTLSPolicy = tlsPolicy"); reassigned {
		t.Error("the restore REPLACES the TLS policy instead of mutating the attached one: the proxy " +
			"would keep its default (verify on) while the console reported the operator's restored setting")
	}
}
