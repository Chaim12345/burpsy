package sender

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
)

// burpsy-react-ui-o388-predial-vs-dial residual (3): an embedder that edits a bound
// *tls.Certificate IN PLACE. The freeze used to keep the store's pointer and hash its leaf at
// capture, while crypto/tls read the pointed-to value later, at the server's
// CertificateRequest — so an edit landing between the two put a connection on the wire under a
// certificate its stamp did not name. Flipping the value back then made the stamp match again,
// and the next send rode a connection that had presented the other certificate (the ABA the
// freeze exists to close).
//
// The server's GetConfigForClient runs after the client's capture and before the client's
// certificate is chosen, so it is a deterministic interposition point for "between capture and
// consumption".

// pointerCerts answers every host with one *tls.Certificate the test edits in place.
type pointerCerts struct{ p *tls.Certificate }

func (c pointerCerts) For(string) *tls.Certificate { return c.p }

func selfSignedClientCert(t *testing.T, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "burpsy in-place cert test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestAnInPlaceCertificateEditBetweenCaptureAndHandshakeCannotMislabelAPooledConnection(t *testing.T) {
	certA := selfSignedClientCert(t, 1)
	certB := selfSignedClientCert(t, 2)
	bound := new(tls.Certificate)
	*bound = certA

	config := DefaultSenderConfig()
	config.ClientCerts = pointerCerts{p: bound}
	config.TLSVerify = false
	s := keepAliveSenderFor(t, config)

	var mu sync.Mutex
	var perRequest [][]byte // the leaf each request's connection presented
	var hellos int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		var leaf []byte
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			leaf = r.TLS.PeerCertificates[0].Raw
		}
		perRequest = append(perRequest, leaf)
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
		NextProtos: []string{alpn.HTTP11},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			defer mu.Unlock()
			hellos++
			if hellos == 1 {
				// The embedder's in-place edit, landing after the client captured its dial
				// identity and before it answers the CertificateRequest.
				*bound = certB
			}
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()
	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	send := func() {
		t.Helper()
		resp, _, err := s.SendRawOutcome(context.Background(), host, port, true, rawGet(host, port), ProtocolPreferenceAuto)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		if !strings.HasSuffix(string(resp), "ok") {
			t.Fatalf("send answered %q", resp)
		}
	}

	send()
	// The embedder flips the binding back to A. A connection stamped A must have presented A.
	*bound = certA
	send()

	mu.Lock()
	defer mu.Unlock()
	if len(perRequest) != 2 {
		t.Fatalf("the server saw %d requests, want 2", len(perRequest))
	}
	if !bytes.Equal(perRequest[1], certA.Certificate[0]) {
		t.Fatalf("the send made while certificate A was bound rode a connection that presented %s "+
			"(handshakes: %d): the stamp named one certificate and the handshake presented another",
			map[bool]string{true: "certificate B", false: "no certificate"}[bytes.Equal(perRequest[1], certB.Certificate[0])], hellos)
	}
}
