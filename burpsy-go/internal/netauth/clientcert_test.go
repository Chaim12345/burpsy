package netauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// Every fixture here is generated at test time and written under t.TempDir(). Nothing
// key-bearing is committed: .gitignore excludes *.pem and *.key, and a checked-in PKCS#12
// would be exactly the "never commit CA material" rule broken in the one directory where
// it looks harmless.

// identity is a generated leaf and, optionally, the intermediate that issued it.
type identity struct {
	leaf         *x509.Certificate
	leafDER      []byte
	key          *ecdsa.PrivateKey
	intermediate *x509.Certificate
}

// newIdentity mints a self-signed leaf, or a leaf issued by a generated intermediate when
// withChain is set.
//
// ECDSA P-256 rather than RSA: the key is generated on every run of every test in this
// file, and a 2048-bit RSA keygen is tens of milliseconds of it for no extra coverage —
// crypto/tls treats both as a crypto.Signer, which is all LoadClientCert asks for.
func newIdentity(t *testing.T, commonName string, withChain bool) identity {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a leaf key: %v", err)
	}

	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	issuerCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	signWith := issuerCert
	signKey := key
	var intermediate *x509.Certificate

	if withChain {
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating an intermediate key: %v", err)
		}
		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: commonName + " intermediate"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("signing the intermediate: %v", err)
		}
		intermediate, err = x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatalf("parsing the intermediate: %v", err)
		}
		signWith = intermediate
		signKey = caKey
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, issuerCert, signWith, &key.PublicKey, signKey)
	if err != nil {
		t.Fatalf("signing the leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}
	return identity{leaf: leaf, leafDER: leafDER, key: key, intermediate: intermediate}
}

// writeP12 encodes an identity as PKCS#12 under a temporary path and returns it.
func writeP12(t *testing.T, id identity, passphrase string) string {
	t.Helper()
	var chain []*x509.Certificate
	if id.intermediate != nil {
		chain = append(chain, id.intermediate)
	}
	// Modern2023 rather than the legacy encoders: both decode, and pinning the modern one
	// keeps the fixture from depending on RC2, which some builds of Go refuse outright.
	raw, err := pkcs12.Modern2023.Encode(id.key, id.leaf, chain, passphrase)
	if err != nil {
		t.Fatalf("encoding PKCS#12: %v", err)
	}
	path := filepath.Join(t.TempDir(), "identity.p12")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func Test_a_pkcs12_identity_loads_and_exposes_only_metadata(t *testing.T) {
	id := newIdentity(t, "client.example.com", false)
	path := writeP12(t, id, testPassphrase)

	entry, err := LoadClientCert("*.example.com", path, testPassphrase)
	if err != nil {
		t.Fatalf("LoadClientCert: %v", err)
	}

	if entry.Subject != id.leaf.Subject.String() {
		t.Errorf("subject is %q, want %q", entry.Subject, id.leaf.Subject.String())
	}
	// The fingerprint is what an operator compares against what the server's logs say it
	// received, so it must be the SHA-256 of the leaf DER and nothing else.
	want := sha256.Sum256(id.leafDER)
	if entry.Fingerprint != hex.EncodeToString(want[:]) {
		t.Errorf("fingerprint is %q, want the SHA-256 of the leaf DER %q",
			entry.Fingerprint, hex.EncodeToString(want[:]))
	}
	if entry.NotAfter == "" || entry.Issuer == "" {
		t.Errorf("the panel needs an issuer and an expiry to show which identity is bound: %+v", entry)
	}

	store := NewClientCerts()
	store.Add(entry)

	// The binding must actually produce a usable certificate for a covered host — a stored
	// path with no signer behind it is a row on the panel that no handshake carries.
	cert := store.For("api.example.com")
	if cert == nil {
		t.Fatal("*.example.com did not cover api.example.com")
	}
	if cert.PrivateKey == nil || len(cert.Certificate) == 0 {
		t.Fatal("the bound certificate has no key or no chain, so it cannot sign a handshake")
	}
	if store.For("elsewhere.test") != nil {
		t.Error("a host outside the pattern was given a certificate")
	}

	// And nothing serialisable carries the passphrase or key material.
	for name, subject := range map[string]any{"store": store, "view": store.View(), "entry": entry} {
		encoded, err := json.Marshal(subject)
		if err != nil {
			t.Fatalf("marshalling %s: %v", name, err)
		}
		if strings.Contains(string(encoded), testPassphrase) {
			t.Errorf("%s serialised the PKCS#12 passphrase: %s", name, encoded)
		}
	}
	if !store.View()[0].HasPassphrase {
		t.Error("has_passphrase is false for a file that needed one, which reads as unprotected")
	}
}

// The chain, not just the leaf. A client certificate issued by an intermediate must present
// leaf-plus-intermediates or the server cannot build a path to its trust anchor — and that
// failure surfaces minutes later at the server, looking nothing like a missing intermediate.
func Test_an_intermediate_is_presented_with_the_leaf(t *testing.T) {
	id := newIdentity(t, "chained.example.com", true)
	entry, err := LoadClientCert("chained.example.com", writeP12(t, id, testPassphrase), testPassphrase)
	if err != nil {
		t.Fatalf("LoadClientCert: %v", err)
	}
	store := NewClientCerts()
	store.Add(entry)
	cert := store.For("chained.example.com")
	if cert == nil {
		t.Fatal("no certificate for the bound host")
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("the Certificate message carries %d entries; a leaf issued by an intermediate needs "+
			"both, or the server answers unknown-CA", len(cert.Certificate))
	}
	// Leaf first: that is the order crypto/tls writes the message in and the order a server
	// builds a path from.
	if string(cert.Certificate[0]) != string(id.leafDER) {
		t.Error("the leaf is not first in the chain")
	}
}

// Each failure mode is named separately, because the operator's next action differs: retype
// the passphrase, or find the right file. One "could not load certificate" would leave them
// guessing between four things.
func Test_each_load_failure_names_what_to_fix(t *testing.T) {
	id := newIdentity(t, "client.example.com", false)
	good := writeP12(t, id, testPassphrase)

	dir := t.TempDir()
	notP12 := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notP12, []byte("this is not a PKCS#12 file"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyFile := filepath.Join(dir, "empty.p12")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		host, path string
		passphrase string
		wantIn     string
	}{
		{"no host", "", good, testPassphrase, "host pattern"},
		{"no path", "example.com", "", testPassphrase, "PKCS#12 file"},
		{"missing file", "example.com", filepath.Join(dir, "absent.p12"), testPassphrase, "no PKCS#12 file at"},
		{"empty file", "example.com", emptyFile, testPassphrase, "is empty"},
		{"wrong passphrase", "example.com", good, "wrong", "passphrase"},
		{"not a p12", "example.com", notP12, testPassphrase, "not a PKCS#12 file this build can read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadClientCert(tc.host, tc.path, tc.passphrase)
			if err == nil {
				t.Fatalf("LoadClientCert accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("the error does not name what to fix.\ngot:  %v\nwant it to contain: %q", err, tc.wantIn)
			}
			// A rejected passphrase must not be echoed back in the message — the error text
			// reaches the browser, and an operator's mistyped secret in a 400 body is still a
			// disclosure.
			if tc.passphrase != "" && strings.Contains(err.Error(), tc.passphrase) {
				t.Errorf("the error echoes the passphrase back: %v", err)
			}
		})
	}
}

// A passwordless PKCS#12 is legal, and worth distinguishing from one whose passphrase is
// stored — has_passphrase must not claim protection that is not there.
func Test_a_passwordless_pkcs12_is_accepted_and_reported_as_such(t *testing.T) {
	id := newIdentity(t, "open.example.com", false)
	var chain []*x509.Certificate
	raw, err := pkcs12.Passwordless.Encode(id.key, id.leaf, chain, "")
	if err != nil {
		t.Fatalf("encoding a passwordless PKCS#12: %v", err)
	}
	path := filepath.Join(t.TempDir(), "open.p12")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	entry, err := LoadClientCert("open.example.com", path, "")
	if err != nil {
		t.Fatalf("LoadClientCert: %v", err)
	}
	if entry.view().HasPassphrase {
		t.Error("has_passphrase is true for a file that has none, which claims protection that is absent")
	}
}

// Restore re-reads every file rather than trusting the row, and reports the rows it could
// not rebuild alongside the ones it could. Both halves are true and the caller has to
// report both: silently dropping a binding would make the panel claim an identity is bound
// when no handshake will carry it.
func Test_restore_returns_what_it_loaded_and_names_what_it_could_not(t *testing.T) {
	id := newIdentity(t, "live.example.com", false)
	good := writeP12(t, id, testPassphrase)
	gone := filepath.Join(t.TempDir(), "deleted-since.p12")

	store, failures := RestoreClientCerts([]ClientCertRow{
		{Host: "live.example.com", Path: good, Passphrase: testPassphrase},
		{Host: "stale.example.com", Path: gone, Passphrase: testPassphrase},
	})

	if store.Len() != 1 {
		t.Fatalf("expected the one loadable binding to survive, got %d", store.Len())
	}
	if store.For("live.example.com") == nil {
		t.Error("the loadable binding is not presentable")
	}
	if len(failures) != 1 {
		t.Fatalf("expected exactly one named failure, got %d: %v", len(failures), failures)
	}
	if !strings.Contains(failures[0].Error(), "stale.example.com") {
		t.Errorf("the failure does not name which binding it was: %v", failures[0])
	}
}

// A persisted row whose scheme this build does not implement is dropped and named, never
// coerced. Coercing it to Basic would send the operator's password to a host under a scheme
// they never chose.
//
// ntlmv1 rather than ntlmv2 as the refused row: NTLMv2 is implemented now, so this test
// would otherwise be asserting a refusal the build no longer makes. NTLMv1 is the scheme
// that is still refused, and for a reason worth keeping under test — a row that was
// written by some other tool, or by a future build, must be dropped and named rather than
// coerced into v2, because "the operator chose v1" and "the operator got v2" are different
// credentials on the wire.
func Test_restoring_credentials_refuses_an_unknown_scheme_rather_than_coercing_it(t *testing.T) {
	store, failures := RestoreCredentials([]CredentialRow{
		{Host: "ok.example.com", Scheme: "basic", Username: "admin", Password: testPassword},
		{Host: "ntlm1.example.com", Scheme: "ntlmv1", Username: "admin", Password: testPassword},
		{Host: "", Scheme: "basic", Username: "admin", Password: testPassword},
	})
	if store.Len() != 1 {
		t.Fatalf("expected one restored rule, got %d", store.Len())
	}
	if _, ok := store.Match("ntlm1.example.com"); ok {
		t.Error("the NTLMv1 row was restored under some other scheme; a credential must never be " +
			"presented under a scheme the operator did not choose, and an upgrade to v2 is still a " +
			"different credential than the one on the panel")
	}
	if len(failures) != 2 {
		t.Fatalf("expected the NTLMv1 row and the hostless row to be named, got %d: %v", len(failures), failures)
	}
}

// A restored NTLMv2 row must come back as a working NTLMv2 rule, domain and all. The
// migration that added the columns defaults them to empty, so a row that carries a domain
// and loses it on restore would look identical to one that never had one — and would
// authenticate as a different account.
func Test_restoring_an_ntlmv2_row_keeps_its_domain_and_workstation(t *testing.T) {
	store, failures := RestoreCredentials([]CredentialRow{
		{Host: "dc.example.com", Scheme: "ntlmv2", Username: "alice", Password: testPassword,
			Domain: "CORP", Workstation: "LAPTOP"},
	})
	if len(failures) != 0 {
		t.Fatalf("an NTLMv2 row failed to restore: %v", failures)
	}
	rule, ok := store.Match("dc.example.com")
	if !ok {
		t.Fatal("the NTLMv2 row did not restore into a matchable rule")
	}
	if rule.Scheme != SchemeNTLMv2 {
		t.Errorf("the restored rule's scheme is %q, not ntlmv2", rule.Scheme)
	}
	if rule.Domain != "CORP" {
		t.Errorf("the restored rule's domain is %q, not CORP; NTOWFv2 hashes the domain, so losing it "+
			"across a restart authenticates as a different account with no error saying so", rule.Domain)
	}
	if rule.Workstation != "LAPTOP" {
		t.Errorf("the restored rule's workstation is %q, not LAPTOP", rule.Workstation)
	}
}

// A row written before the domain column existed reads back with empty strings. For Basic
// and Digest that is correct and must not be refused — otherwise upgrading the binary
// would silently drop every credential the operator had.
func Test_restoring_a_pre_migration_row_with_no_domain_still_works(t *testing.T) {
	store, failures := RestoreCredentials([]CredentialRow{
		{Host: "old.example.com", Scheme: "basic", Username: "admin", Password: testPassword},
		{Host: "olddigest.example.com", Scheme: "digest", Username: "admin", Password: testPassword, Realm: "r"},
	})
	if len(failures) != 0 {
		t.Fatalf("rows written before the domain column existed were refused on restore, which would "+
			"drop every credential an operator had when they upgraded: %v", failures)
	}
	if store.Len() != 2 {
		t.Fatalf("expected both pre-migration rows to restore, got %d", store.Len())
	}
}
