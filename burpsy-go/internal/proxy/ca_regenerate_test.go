package proxy

import (
	"bytes"
	"testing"
)

// ---- regenerating the signing CA (Burp's "Regenerate CA certificate") ---------------------
//
// Regeneration mints a fresh CA and installs it through the same swap as import, so the property
// that matters is the same one import's cache test defends: the same host, primed before the swap,
// must re-sign under the NEW CA afterwards and no longer verify against the OLD one. If the cache
// were not cleared the fast path would keep serving the stale leaf and this would pass only for
// hosts never seen before.

func Test_regenerating_the_CA_installs_a_different_valid_CA_and_re_signs_leaves_under_it(t *testing.T) {
	engine := newEngine(t, "burpsy original CA")

	// Prime a leaf so the re-sign-after-regenerate check exercises the cache path.
	beforeLeaf, err := engine.GetCertificate("example.test")
	if err != nil {
		t.Fatalf("GetCertificate before regenerate: %v", err)
	}
	oldCA := engine.caCert
	if err := beforeLeaf.Leaf.CheckSignatureFrom(oldCA); err != nil {
		t.Fatalf("precondition: primed leaf is not signed by the current CA: %v", err)
	}

	certPEM, keyPEM, err := engine.RegenerateCA()
	if err != nil {
		t.Fatalf("RegenerateCA: %v", err)
	}
	newCA := engine.caCert

	// A genuinely different CA: different DER and a different serial. Both are asserted because a
	// generator that reused the serial while changing the key would still be a rotation an operator
	// could not tell apart from the outside.
	if bytes.Equal(newCA.Raw, oldCA.Raw) {
		t.Fatal("the regenerated CA is byte-identical to the old one — nothing rotated")
	}
	if newCA.SerialNumber.Cmp(oldCA.SerialNumber) == 0 {
		t.Errorf("the regenerated CA reused serial %s", newCA.SerialNumber)
	}

	// A valid, self-signed CA.
	if !newCA.IsCA || !newCA.BasicConstraintsValid {
		t.Errorf("regenerated cert is not a CA: IsCA=%v BasicConstraintsValid=%v",
			newCA.IsCA, newCA.BasicConstraintsValid)
	}
	if err := validateCA(newCA, engine.caPriv); err != nil {
		t.Errorf("validateCA on the regenerated pair: %v", err)
	}

	// The returned PEM — what the handler persists — parses back to the CA now in force, so a restart
	// that reloads it keeps signing with the new CA rather than a different one.
	loaded, err := loadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("loadCA of the returned PEM: %v", err)
	}
	if !bytes.Equal(loaded.caCert.Raw, newCA.Raw) {
		t.Error("the returned PEM is not the CA now in force")
	}

	// The headline property, in both directions. The same host re-signs under the NEW CA (cache was
	// cleared) and the fresh leaf does NOT verify against the OLD CA (the signer really changed).
	afterLeaf, err := engine.GetCertificate("example.test")
	if err != nil {
		t.Fatalf("GetCertificate after regenerate: %v", err)
	}
	if err := afterLeaf.Leaf.CheckSignatureFrom(newCA); err != nil {
		t.Errorf("the new leaf is not signed by the regenerated CA: %v", err)
	}
	if afterLeaf.Leaf.CheckSignatureFrom(oldCA) == nil {
		t.Error("the new leaf still verifies against the old CA — regeneration did not change the signer")
	}
}

// Two regenerations in a row produce two distinct CAs — the serial and key are freshly random each
// time, so an operator rotating twice does not land back on a CA a client may still have installed.
func Test_regenerating_the_CA_twice_yields_two_distinct_CAs(t *testing.T) {
	engine := newEngine(t, "burpsy original CA")

	if _, _, err := engine.RegenerateCA(); err != nil {
		t.Fatalf("first RegenerateCA: %v", err)
	}
	first := engine.caCert.Raw

	if _, _, err := engine.RegenerateCA(); err != nil {
		t.Fatalf("second RegenerateCA: %v", err)
	}
	second := engine.caCert.Raw

	if bytes.Equal(first, second) {
		t.Error("two regenerations produced the same CA")
	}
}
