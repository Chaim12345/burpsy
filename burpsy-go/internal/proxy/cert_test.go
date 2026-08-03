package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestLeafChainIsLeafThenCA pins the parity contract the Rust port's
// mint_leaf sets: the presented chain is leaf-then-CA, so a trust store
// holding only the CA validates every leaf (Firefox imports only roots and
// expects the server to supply the rest of the path).
func TestLeafChainIsLeafThenCA(t *testing.T) {
	engine, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	leaf, err := engine.GetCertificate("parity.test")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	if len(leaf.Certificate) != 2 {
		t.Fatalf("chain has %d certs, want leaf + CA", len(leaf.Certificate))
	}
	if !bytes.Equal(leaf.Certificate[0], leaf.Leaf.Raw) {
		t.Error("chain leaf is not the parsed leaf")
	}
	caCert, err := x509.ParseCertificate(leaf.Certificate[1])
	if err != nil {
		t.Fatalf("parse chain CA: %v", err)
	}
	if !caCert.IsCA {
		t.Error("chain's second certificate is not a CA")
	}

	// The leaf must validate against the CA as the only root.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "parity.test"}); err != nil {
		t.Errorf("leaf fails verification against CA: %v", err)
	}
}

// TestLeafLifetimeMatchesRust pins the validity window the Rust port uses for
// leaves: NotBefore backdated one hour and NotAfter 397 days out (MAX_LEAF_DAYS,
// matching Burp and mitmproxy and immune to Chrome's 398-day public-CA cap).
func TestLeafLifetimeMatchesRust(t *testing.T) {
	engine, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	leaf, err := engine.GetCertificate("lifetime.test")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	lc := leaf.Leaf

	now := time.Now()
	if lc.NotBefore.After(now.Add(-30 * time.Minute)) {
		t.Errorf("leaf NotBefore %v is not backdated an hour", lc.NotBefore)
	}
	lifetime := lc.NotAfter.Sub(now)
	if lifetime < 396*24*time.Hour || lifetime > 398*24*time.Hour {
		t.Errorf("leaf lifetime %v, want ~397 days", lifetime)
	}
}

// TestLeafSANMatchesHost ensures DNS names and IP literals both land in the
// right SAN kind, mirroring the Rust SAN choice (exact host, never a wildcard).
func TestLeafSANMatchesHost(t *testing.T) {
	engine, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	dns, err := engine.GetCertificate("exact.test")
	if err != nil {
		t.Fatalf("GetCertificate dns: %v", err)
	}
	if len(dns.Leaf.DNSNames) != 1 || dns.Leaf.DNSNames[0] != "exact.test" {
		t.Errorf("leaf DNSNames = %v, want [exact.test]", dns.Leaf.DNSNames)
	}
	if len(dns.Leaf.IPAddresses) != 0 {
		t.Errorf("DNS leaf unexpectedly carries IP SANs %v", dns.Leaf.IPAddresses)
	}

	ip, err := engine.GetCertificate("10.1.2.3")
	if err != nil {
		t.Fatalf("GetCertificate ip: %v", err)
	}
	if len(ip.Leaf.IPAddresses) != 1 || ip.Leaf.IPAddresses[0].String() != "10.1.2.3" {
		t.Errorf("leaf IPAddresses = %v, want [10.1.2.3]", ip.Leaf.IPAddresses)
	}
	if len(ip.Leaf.DNSNames) != 0 {
		t.Errorf("IP leaf unexpectedly carries DNS SANs %v", ip.Leaf.DNSNames)
	}
}

// TestGetCertificateCachesPerHost asserts a host mints once and is served from
// the cache thereafter, while distinct hosts get distinct leaves.
func TestGetCertificateCachesPerHost(t *testing.T) {
	engine, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	a, err := engine.GetCertificate("cached.test")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	b, err := engine.GetCertificate("cached.test")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if a != b {
		t.Error("second GetCertificate returned a different leaf for the same host")
	}
	c, err := engine.GetCertificate("other.test")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if a == c {
		t.Error("distinct hosts must get distinct leaves")
	}
}

// TestLoadOrGenerateCAPersistsAndReuses asserts the CA is generated once and
// reloaded thereafter, and that the on-disk permissions match the Rust port
// (certificate 0644, key 0600). A regenerated CA would invalidate a trust-store
// install, so the reuse is the point.
func TestLoadOrGenerateCAPersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	b, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if !bytes.Equal(a.caCert.Raw, b.caCert.Raw) {
		t.Error("second load must reuse the persisted CA, not regenerate it")
	}

	if runtime.GOOS != "windows" {
		keyInfo, err := os.Stat(filepath.Join(dir, "ca.key"))
		if err != nil {
			t.Fatalf("stat ca.key: %v", err)
		}
		if mode := keyInfo.Mode().Perm(); mode != 0600 {
			t.Errorf("ca.key mode = %o, want 600", mode)
		}
		certInfo, err := os.Stat(filepath.Join(dir, "ca.crt"))
		if err != nil {
			t.Fatalf("stat ca.crt: %v", err)
		}
		if mode := certInfo.Mode().Perm(); mode != 0644 {
			t.Errorf("ca.crt mode = %o, want 644 (public)", mode)
		}
	}
}

// writeCAPair writes a CA cert/key pair straight to disk, bypassing
// LoadOrGenerateCA's generation path.
func writeCAPair(t *testing.T, dir string, tmpl *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}
}

func testCA(tmpl *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	if tmpl == nil {
		now := time.Now()
		tmpl = &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "test CA"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.AddDate(1, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
	}
	return tmpl, key, nil
}

// TestLoadOrGenerateCARejectsANonCA asserts a certificate that is not a CA is
// refused at load with a clear error rather than left to fail cryptically at
// the first leaf mint.
func TestLoadOrGenerateCARejectsANonCA(t *testing.T) {
	dir := t.TempDir()
	tmpl, key, err := testCA(nil)
	if err != nil {
		t.Fatalf("testCA: %v", err)
	}
	// Strip the CA-ness: same key, no basic constraints / IsCA.
	now := time.Now()
	tmpl = &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-a-ca"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	writeCAPair(t, dir, tmpl, key)
	if _, err := LoadOrGenerateCA(dir); err == nil {
		t.Fatal("LoadOrGenerateCA accepted a non-CA pair")
	}
}

// TestLoadOrGenerateCARejectsAMismatchedKey asserts a key that does not belong
// to the certificate is refused at load.
func TestLoadOrGenerateCARejectsAMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	tmpl, key, err := testCA(nil)
	if err != nil {
		t.Fatalf("testCA: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	// The cert is valid but the key on disk is a different key.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}
	if _, err := LoadOrGenerateCA(dir); err == nil {
		t.Fatal("LoadOrGenerateCA accepted a mismatched key pair")
	}
}

// TestLoadOrGenerateCARejectsAnExpiredCA asserts a root outside its validity
// window is refused at load.
func TestLoadOrGenerateCARejectsAnExpiredCA(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	tmpl, key, err := testCA(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired CA"},
		NotBefore:             now.AddDate(0, -2, 0),
		NotAfter:              now.AddDate(0, -1, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	if err != nil {
		t.Fatalf("testCA: %v", err)
	}
	writeCAPair(t, dir, tmpl, key)
	if _, err := LoadOrGenerateCA(dir); err == nil {
		t.Fatal("LoadOrGenerateCA accepted an expired CA")
	}
}
