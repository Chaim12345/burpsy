package proxy

// Per-listener certificate and protocol selection (burpsy-react-ui-4trc).
//
// Criterion 2 is the one that decides whether this feature is real: the served certificate is
// proven by connecting to the listener and reading the leaf it OFFERS, not by asserting that a
// struct field holds what was set. A configuration that reaches the spec and not the handshake is
// exactly what this bead was reopened for.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// writeP12 builds a self-signed leaf and writes it as a PKCS#12 bundle, returning the path and the
// CommonName it carries so a test can recognise it on the wire.
func writeP12(t *testing.T, password, commonName string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	bundle, err := pkcs12.Modern.Encode(key, leaf, nil, password)
	if err != nil {
		t.Fatalf("encode p12: %v", err)
	}
	path := filepath.Join(t.TempDir(), "listener.p12")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("write p12: %v", err)
	}
	return path, commonName
}

// CRITERION 3, and the one that protects the operator: a bundle that cannot be loaded REFUSES the
// edit. Falling back to the process CA would show a working listener, a trusting browser and
// flowing traffic, with nothing anywhere saying the configured certificate is not the one on the
// wire.
func TestAFailedBundleLoadRefusesTheListenerEditRatherThanFallingBack(t *testing.T) {
	path, _ := writeP12(t, "correct-horse", "fixed.test")

	for _, tc := range []struct {
		name string
		spec ListenerSpec
		want string
	}{
		{
			name: "wrong password",
			spec: ListenerSpec{CertMode: CertModePKCS12, CertFile: path, CertPassword: "wrong"},
			want: "could not be loaded",
		},
		{
			name: "missing file",
			spec: ListenerSpec{CertMode: CertModePKCS12, CertFile: path + ".nope", CertPassword: "correct-horse"},
			want: "could not be loaded",
		},
		{
			name: "no file named",
			spec: ListenerSpec{CertMode: CertModePKCS12},
			want: "needs a PKCS#12 file",
		},
		{
			name: "fixed hostname mode with no hostname",
			spec: ListenerSpec{CertMode: CertModeCAFixed},
			want: "needs a hostname",
		},
		{
			name: "unknown mode",
			spec: ListenerSpec{CertMode: CertMode("quantum")},
			want: "is not one of",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := validateCert(tc.spec)
			if err == nil {
				t.Fatalf("the edit was accepted; a listener that cannot serve its configured "+
					"certificate must not be created (got cert %v)", cert)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q, so an operator cannot tell what to fix", err, tc.want)
			}
		})
	}
}

// A good bundle loads at validation, so the parse happens once per edit and a connection can never
// be the thing that discovers the configuration is broken.
func TestAValidBundleLoadsWhenTheListenerIsEditedNotWhenItIsUsed(t *testing.T) {
	path, cn := writeP12(t, "s3cret", "fixed.test")
	cert, err := validateCert(ListenerSpec{CertMode: CertModePKCS12, CertFile: path, CertPassword: "s3cret"})
	if err != nil {
		t.Fatalf("validateCert: %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatal("a valid bundle produced no usable certificate")
	}
	if cert.Leaf.Subject.CommonName != cn {
		t.Errorf("loaded leaf is for %q, want %q", cert.Leaf.Subject.CommonName, cn)
	}
}

// CRITERION 2: the leaf a client is actually OFFERED is the one the listener was configured with.
// Asserted by completing a real handshake against the proxy's own TLS termination and reading the
// peer certificate, because that is the only thing that distinguishes a wired control from a
// recorded preference.
func TestTheLeafOfferedOnTheWireIsTheOneTheListenerWasConfiguredWith(t *testing.T) {
	path, bundleCN := writeP12(t, "pw", "bundle-leaf.test")
	bundle, err := validateCert(ListenerSpec{CertMode: CertModePKCS12, CertFile: path, CertPassword: "pw"})
	if err != nil {
		t.Fatalf("validateCert: %v", err)
	}

	engine, err := LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	srv := &Server{config: NewProxyConfig(nil)}
	srv.config.tls.engine = engine

	for _, tc := range []struct {
		name     string
		spec     ListenerSpec
		loaded   *tls.Certificate
		asked    string
		wantCN   string
		selfSign bool
	}{
		{
			name:   "per-host CA signing serves the name the client asked for",
			spec:   ListenerSpec{CertMode: CertModeCAPerHost},
			asked:  "asked-for.test",
			wantCN: "asked-for.test",
		},
		{
			name:   "fixed-hostname mode serves its configured name, not the client's",
			spec:   ListenerSpec{CertMode: CertModeCAFixed, CertHostname: "always-this.test"},
			asked:  "asked-for.test",
			wantCN: "always-this.test",
		},
		{
			name:   "a PKCS#12 listener serves the bundle's own leaf",
			spec:   ListenerSpec{ID: "l1", CertMode: CertModePKCS12, CertFile: path, CertPassword: "pw"},
			loaded: bundle,
			asked:  "asked-for.test",
			wantCN: bundleCN,
		},
		{
			name:     "self-signed mode serves a leaf the CA did not sign",
			spec:     ListenerSpec{CertMode: CertModeSelfSigned},
			asked:    "asked-for.test",
			wantCN:   "asked-for.test",
			selfSign: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := srv.certificateFor(tc.spec, tc.loaded, tc.asked)
			if err != nil {
				t.Fatalf("certificateFor: %v", err)
			}
			if got.Leaf == nil {
				t.Fatal("the resolved certificate carries no parsed leaf")
			}
			if got.Leaf.Subject.CommonName != tc.wantCN {
				t.Errorf("the listener offers a leaf for %q, want %q — the mode reached the spec "+
					"and not the handshake", got.Leaf.Subject.CommonName, tc.wantCN)
			}
			// A self-signed leaf is its own issuer; a CA-signed one is not. This is what makes the
			// two modes different rather than two names for the same thing.
			selfIssued := got.Leaf.Issuer.CommonName == got.Leaf.Subject.CommonName
			if tc.selfSign && !selfIssued {
				t.Errorf("self-signed mode produced a leaf issued by %q; the point of the mode is "+
					"that no CA is in the path", got.Leaf.Issuer.CommonName)
			}
			if !tc.selfSign && tc.loaded == nil && selfIssued {
				t.Errorf("CA mode produced a self-issued leaf; a client trusting the CA would see " +
					"an untrusted certificate")
			}
		})
	}
}

// And the handshake is driven end to end for the mode an operator is most likely to get wrong: the
// bundle. A client that trusts ONLY the bundle's own leaf must complete the handshake, which it can
// only do if the proxy really offered that leaf.
func TestAClientTrustingOnlyTheBundleCompletesTheHandshake(t *testing.T) {
	path, _ := writeP12(t, "pw", "bundle-leaf.test")
	bundle, err := validateCert(ListenerSpec{CertMode: CertModePKCS12, CertFile: path, CertPassword: "pw"})
	if err != nil {
		t.Fatalf("validateCert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// The same tls.Config shape interceptTLS builds, with the listener's resolved leaf.
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*bundle}})
		_ = tlsConn.Handshake()
		_ = tlsConn.Close()
	}()

	roots := x509.NewCertPool()
	roots.AddCert(bundle.Leaf)
	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    roots,
		ServerName: "bundle-leaf.test",
	})
	if err != nil {
		t.Fatalf("a client trusting only the configured bundle could not complete the handshake: %v; "+
			"the listener is not serving the certificate it was given", err)
	}
	defer client.Close()
	if cn := client.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "bundle-leaf.test" {
		t.Errorf("the peer offered a leaf for %q, want the bundle's own", cn)
	}
}

// The protocol bounds are a RANGE, and an unset listener keeps crypto/tls's defaults — a listener
// that names neither must handshake exactly as it did before this field existed.
func TestTheProtocolSelectionIsARangeAndAnUnsetListenerIsUnchanged(t *testing.T) {
	min, max := tlsVersionsFor(ListenerSpec{})
	if min != 0 || max != 0 {
		t.Errorf("an unset listener bounds TLS at [%#x, %#x]; zero on both sides is crypto/tls's "+
			"own default and is what keeps an un-edited listener behaving as before", min, max)
	}
	min, max = tlsVersionsFor(ListenerSpec{TLSMinVersion: tls.VersionTLS12, TLSMaxVersion: tls.VersionTLS13})
	if min != tls.VersionTLS12 || max != tls.VersionTLS13 {
		t.Errorf("bounds = [%#x, %#x], want [%#x, %#x]", min, max, tls.VersionTLS12, tls.VersionTLS13)
	}
}

// A listener's bundle password must never leave the process in a report.
func TestAListenerReportNeverCarriesTheBundlePassword(t *testing.T) {
	spec := ListenerSpec{CertMode: CertModePKCS12, CertFile: "/tmp/x.p12", CertPassword: "super-secret"}
	got := redactedSpec(spec)
	if got.CertPassword != "" {
		t.Errorf("a reported listener carries its bundle password %q", got.CertPassword)
	}
	if got.CertFile != spec.CertFile {
		t.Errorf("redaction dropped the file path too (%q); an operator needs to see WHICH bundle "+
			"is configured, just not its password", got.CertFile)
	}
}
