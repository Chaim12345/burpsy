package alpn

// The 63pf contract: a fingerprinted dial changes the ClientHello's bytes and nothing else.
// Each test below pins one mapping onto the utls config - verification, client certificates,
// MinVersion, the ALPN offer, and the SNI override - so a utls upgrade that drops one fails
// loudly here rather than silently in the field.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// helloCapture records what the server side of the handshake saw. handshakes receives one
// signal per server-side handshake completion: the client's Dial returns when its own flight
// leaves, which is before the server has processed it, so any assertion about what the
// server saw waits on this.
type helloCapture struct {
	mu         sync.Mutex
	serverName string
	protos     []string
	peerCerts  int
	handshakes chan struct{}
}

// testServer runs a TLS listener with a self-signed 127.0.0.1 cert, capturing each
// ClientHello, answering one connection and closing.
func testServer(t *testing.T, configure func(*tls.Config)) (addr string, cert *x509.Certificate, captured *helloCapture) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "burpsy fingerprint test"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}

	captured = &helloCapture{handshakes: make(chan struct{}, 8)}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			captured.mu.Lock()
			captured.serverName = hello.ServerName
			captured.protos = hello.SupportedProtos
			captured.mu.Unlock()
			return nil, nil
		},
	}
	if configure != nil {
		configure(cfg)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
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
			go func(c net.Conn) {
				defer c.Close()
				tc, ok := c.(*tls.Conn)
				if !ok {
					return
				}
				if err := tc.Handshake(); err == nil {
					captured.mu.Lock()
					captured.peerCerts = len(tc.ConnectionState().PeerCertificates)
					captured.mu.Unlock()
				}
				captured.handshakes <- struct{}{}
				// Hold briefly so the client can finish reading its handshake flight.
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()
	return ln.Addr().String(), cert, captured
}

func rootsFor(t *testing.T, cert *x509.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

type staticCerts struct{ cert *tls.Certificate }

func (s staticCerts) For(string) *tls.Certificate { return s.cert }

func dialOne(d Dialer, addr string, offer []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := d.Dial(ctx, "127.0.0.1", addr, offer)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func Test_a_fingerprinted_dial_verifies_against_the_configured_roots(t *testing.T) {
	addr, cert, _ := testServer(t, nil)
	d := Dialer{Fingerprint: FingerprintChrome, RootCAs: rootsFor(t, cert)}
	if err := dialOne(d, addr, nil); err != nil {
		t.Fatalf("a fingerprinted dial with the right roots failed verification: %v", err)
	}
	// Wrong roots must still fail: verification was mapped, not skipped.
	d.RootCAs = x509.NewCertPool()
	if err := dialOne(d, addr, nil); err == nil {
		t.Fatal("a fingerprinted dial verified against an empty root pool")
	}
}

func Test_a_fingerprinted_dial_presents_the_bound_client_certificate(t *testing.T) {
	addr, _, captured := testServer(t, func(cfg *tls.Config) {
		cfg.ClientAuth = tls.RequestClientCert
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject:      pkix.Name{CommonName: "fingerprint client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	d := Dialer{
		Fingerprint:        FingerprintFirefox,
		InsecureSkipVerify: true,
		ClientCerts:        staticCerts{cert: &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
	}
	if err := dialOne(d, addr, nil); err != nil {
		t.Fatalf("the fingerprinted dial failed: %v", err)
	}
	select {
	case <-captured.handshakes:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never completed the handshake")
	}
	captured.mu.Lock()
	defer captured.mu.Unlock()
	if captured.peerCerts == 0 {
		t.Fatal("the server saw no client certificate: ClientCerts was not mapped onto the utls config")
	}
}

func Test_a_fingerprinted_dial_honours_min_version(t *testing.T) {
	addr, cert, _ := testServer(t, func(cfg *tls.Config) {
		cfg.MaxVersion = tls.VersionTLS12
	})
	d := Dialer{Fingerprint: FingerprintSafari, RootCAs: rootsFor(t, cert), MinVersion: tls.VersionTLS13}
	if err := dialOne(d, addr, nil); err == nil {
		t.Fatal("TLS 1.3 was demanded of a TLS 1.2 server and the handshake still succeeded")
	}
	d.MinVersion = tls.VersionTLS12
	if err := dialOne(d, addr, nil); err != nil {
		t.Fatalf("TLS 1.2 floor against a TLS 1.2 server failed: %v", err)
	}
}

func Test_a_fingerprinted_dial_keeps_the_alpn_offer_contract(t *testing.T) {
	addr, cert, captured := testServer(t, func(cfg *tls.Config) {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	})
	d := Dialer{Fingerprint: FingerprintChrome, RootCAs: rootsFor(t, cert)}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, negotiated, err := d.Dial(ctx, "127.0.0.1", addr, []string{"h2", "http/1.1"})
	if err != nil {
		t.Fatalf("h2 offer failed: %v", err)
	}
	_ = conn.Close()
	if negotiated != "h2" {
		t.Fatalf("negotiated %q, want h2: the preset's own ALPN overrode the caller's offer", negotiated)
	}

	// An empty offer sends no ALPN extension at all, preset or no preset.
	_, _, err = d.Dial(ctx, "127.0.0.1", addr, nil)
	if err == nil && captured.protos != nil && len(captured.protos) > 0 {
		// The capture holds the most recent hello; it must have carried no ALPN.
		t.Fatalf("an empty offer still advertised %v", captured.protos)
	}
}

func Test_a_fingerprinted_dial_carries_the_sni_override_but_verifies_the_dialled_name(t *testing.T) {
	addr, cert, captured := testServer(t, nil)
	d := Dialer{
		Fingerprint: FingerprintChrome,
		RootCAs:     rootsFor(t, cert),
		SNI:         "probe.example",
	}
	if err := dialOne(d, addr, nil); err != nil {
		t.Fatalf("the override dial failed: %v", err)
	}
	if captured.serverName != "probe.example" {
		t.Fatalf("the server saw SNI %q, want the override: SNI was not mapped onto the utls config", captured.serverName)
	}
}

func Test_an_unknown_fingerprint_is_an_error_not_a_silent_go_hello(t *testing.T) {
	addr, _, _ := testServer(t, nil)
	d := Dialer{Fingerprint: Fingerprint("netscape"), InsecureSkipVerify: true}
	err := dialOne(d, addr, nil)
	if err == nil || !strings.Contains(err.Error(), "netscape") {
		t.Fatalf("err = %v, want an unknown-fingerprint error naming the selector", err)
	}
}

func Test_an_empty_fingerprint_is_still_the_go_hello(t *testing.T) {
	addr, cert, _ := testServer(t, nil)
	d := Dialer{RootCAs: rootsFor(t, cert)}
	conn, err := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, _, err := d.Dial(ctx, "127.0.0.1", addr, nil)
		return c, err
	}()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*tls.Conn); !ok {
		t.Fatalf("an empty fingerprint returned %T, want the stdlib *tls.Conn path", conn)
	}
}
