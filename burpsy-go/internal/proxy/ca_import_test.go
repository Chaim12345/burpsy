package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// ---- importing an operator's own CA (W6 #10) -----------------------------------------------
//
// The capability was filesystem-only: LoadOrGenerateCA reads ca.crt/ca.key at startup, so using
// your own CA meant a restart and the loss of every captured exchange.
//
// The test that matters most here is the cache one. certPool holds a signed leaf per host and is
// consulted before anything else, so an import that replaced the CA and left the pool populated
// would keep serving leaves signed by a CA the client has just been told to stop trusting —
// producing trust failures on hosts that worked a moment ago, which an operator would go looking
// for in their browser rather than in burpsy.

// makeCA builds a usable CA pair. Separate from the engine's own generator so a test CA can be made
// deliberately wrong in the ways validateCA is supposed to catch.
func makeCA(t *testing.T, cn string, notBefore, notAfter time.Time, isCA bool, keyUsage x509.KeyUsage) (certPEM, keyPEM []byte, key *rsa.PrivateKey) {
	t.Helper()
	// 2048 to match what LoadOrGenerateCA mints; smaller would be faster but validateCA calls
	// key.Validate() and this is the size the production path actually exercises.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, key
}

func goodCA(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	c, k, _ := makeCA(t, cn, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), true,
		x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature)
	return c, k
}

// newEngine builds an engine holding a known CA, the way LoadOrGenerateCA would.
func newEngine(t *testing.T, cn string) *TlsEngine {
	t.Helper()
	certPEM, keyPEM := goodCA(t, cn)
	engine, err := loadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("loadCA: %v", err)
	}
	return engine
}

// The headline case: after an import, leaves are signed by the new CA.
func TestImportCAChangesWhoSignsLeaves(t *testing.T) {
	engine := newEngine(t, "burpsy original CA")

	before, err := engine.GetCertificate("example.test")
	if err != nil {
		t.Fatalf("GetCertificate before import: %v", err)
	}
	if got := before.Leaf.Issuer.CommonName; got != "burpsy original CA" {
		t.Fatalf("precondition: leaf issued by %q", got)
	}

	certPEM, keyPEM := goodCA(t, "operator's own CA")
	if err := engine.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}

	after, err := engine.GetCertificate("example.test")
	if err != nil {
		t.Fatalf("GetCertificate after import: %v", err)
	}
	if got := after.Leaf.Issuer.CommonName; got != "operator's own CA" {
		t.Errorf("leaf still issued by %q — the import did not take effect", got)
	}
}

// The cache test. Same host as before the import: if the pool were not emptied, the fast path would
// return the stale leaf and the assertion above would pass only for hosts never seen before.
func TestImportCAEmptiesTheLeafCache(t *testing.T) {
	engine := newEngine(t, "old CA")

	// Populate the cache for several hosts, so this cannot pass by clearing only one entry.
	hosts := []string{"a.test", "b.test", "c.test"}
	for _, h := range hosts {
		if _, err := engine.GetCertificate(h); err != nil {
			t.Fatalf("priming %s: %v", h, err)
		}
	}
	cached := 0
	engine.certPool.Range(func(_, _ any) bool { cached++; return true })
	if cached != len(hosts) {
		t.Fatalf("precondition: %d cached leaves, want %d", cached, len(hosts))
	}

	certPEM, keyPEM := goodCA(t, "new CA")
	if err := engine.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}

	remaining := 0
	engine.certPool.Range(func(k, _ any) bool {
		remaining++
		t.Errorf("leaf for %v survived the import; it is signed by a CA no client trusts any more", k)
		return true
	})
	if remaining != 0 {
		t.Errorf("%d stale leaves remain", remaining)
	}

	// And every host re-signs under the new CA, which is the property the operator experiences.
	for _, h := range hosts {
		cert, err := engine.GetCertificate(h)
		if err != nil {
			t.Fatalf("re-signing %s: %v", h, err)
		}
		if got := cert.Leaf.Issuer.CommonName; got != "new CA" {
			t.Errorf("%s re-signed by %q, want \"new CA\"", h, got)
		}
	}
}

// A refused import must leave the running CA and the cache untouched. Installing a CA that cannot
// sign would take TLS interception down entirely, which is worse than refusing — so "validate
// before replacing" is the invariant, and this is the test that holds it.
func TestARefusedImportChangesNothing(t *testing.T) {
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)

	// A key that does not match its certificate: build two pairs and cross them.
	certA, _ := goodCA(t, "cert A")
	_, keyB := goodCA(t, "cert B")

	notACert, notAKey, _ := makeCA(t, "leaf, not a CA", notBefore, notAfter, false, x509.KeyUsageDigitalSignature)
	noSignCert, noSignKey, _ := makeCA(t, "CA without certSign", notBefore, notAfter, true, x509.KeyUsageDigitalSignature)
	expiredCert, expiredKey, _ := makeCA(t, "expired CA", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), true, x509.KeyUsageCertSign)

	cases := []struct {
		name string
		cert []byte
		key  []byte
	}{
		{"mismatched key", certA, keyB},
		{"not a CA", notACert, notAKey},
		{"no certificate-signing usage", noSignCert, noSignKey},
		{"expired", expiredCert, expiredKey},
		{"cert is not PEM", []byte("this is not a certificate"), keyB},
		{"key is not PEM", certA, []byte("this is not a key")},
		{"both empty", nil, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newEngine(t, "incumbent CA")
			if _, err := engine.GetCertificate("keep.test"); err != nil {
				t.Fatalf("priming: %v", err)
			}

			if err := engine.ImportCA(tc.cert, tc.key); err == nil {
				t.Fatal("the import was accepted; TLS interception would now be signing with an " +
					"unusable CA")
			}

			// The incumbent must still be signing.
			subject, _, ok := engine.CADescription()
			if !ok || subject != "incumbent CA" {
				t.Errorf("CA is now %q (present=%v); a refused import must not replace it", subject, ok)
			}
			// And the cache must not have been flushed either — flushing on failure would discard
			// perfectly good leaves and cause a needless re-sign storm.
			cached := 0
			engine.certPool.Range(func(_, _ any) bool { cached++; return true })
			if cached != 1 {
				t.Errorf("%d cached leaves after a refused import, want 1 — the cache was touched", cached)
			}
		})
	}
}

// CertPEM must report the CA now in force, because /ca.crt is what the operator downloads to
// install. Serving the startup CA after an import would have them trust a certificate that signs
// nothing, which presents as every site failing.
func TestCertPEMFollowsTheImport(t *testing.T) {
	engine := newEngine(t, "before")

	first := engine.CertPEM()
	if len(first) == 0 {
		t.Fatal("CertPEM returned nothing for a loaded CA")
	}
	block, _ := pem.Decode(first)
	if block == nil {
		t.Fatal("CertPEM did not return PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("CertPEM is not a parseable certificate: %v", err)
	}
	if parsed.Subject.CommonName != "before" {
		t.Fatalf("precondition: CertPEM reports %q", parsed.Subject.CommonName)
	}

	certPEM, keyPEM := goodCA(t, "after")
	if err := engine.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}

	block2, _ := pem.Decode(engine.CertPEM())
	if block2 == nil {
		t.Fatal("CertPEM returned no PEM after the import")
	}
	parsed2, err := x509.ParseCertificate(block2.Bytes)
	if err != nil {
		t.Fatalf("parsing post-import CertPEM: %v", err)
	}
	if parsed2.Subject.CommonName != "after" {
		t.Errorf("CertPEM still reports %q; an operator would install a CA that signs nothing",
			parsed2.Subject.CommonName)
	}
}

// A leaf must never outlive the CA that signed it. GetCertificate clamps to the CA's window, and an
// imported CA with a short life is the case where that clamp earns its keep.
func TestLeavesAreClampedToAnImportedCAsValidity(t *testing.T) {
	engine := newEngine(t, "long-lived")

	shortNotAfter := time.Now().Add(2 * time.Hour)
	certPEM, keyPEM, _ := makeCA(t, "short-lived CA", time.Now().Add(-time.Minute), shortNotAfter,
		true, x509.KeyUsageCertSign)
	if err := engine.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}

	cert, err := engine.GetCertificate("clamped.test")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert.Leaf.NotAfter.After(shortNotAfter) {
		t.Errorf("leaf expires %v, after its CA at %v — the chain would be invalid for that window",
			cert.Leaf.NotAfter, shortNotAfter)
	}
}

// PKCS#8 keys must import, since that is what openssl emits by default and therefore what an
// operator bringing their own CA most likely has.
func TestImportAcceptsAPKCS8Key(t *testing.T) {
	engine := newEngine(t, "before")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "pkcs8 CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("pkcs8: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	if err := engine.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA with a PKCS#8 key: %v", err)
	}
	if subject, _, _ := engine.CADescription(); subject != "pkcs8 CA" {
		t.Errorf("CA is %q after importing a PKCS#8 pair", subject)
	}
}

// A CA with no common name is legal and must not render as an empty identity.
func TestCADescriptionFallsBackWhenThereIsNoCommonName(t *testing.T) {
	certPEM, keyPEM, _ := makeCA(t, "", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), true,
		x509.KeyUsageCertSign)
	engine, err := loadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("loadCA: %v", err)
	}
	subject, notAfter, ok := engine.CADescription()
	if !ok {
		t.Fatal("CADescription reports no CA for a loaded one")
	}
	if subject == "" {
		t.Error("subject is empty; the UI would show a CA with no identity")
	}
	if notAfter.IsZero() {
		t.Error("notAfter is zero")
	}
}
