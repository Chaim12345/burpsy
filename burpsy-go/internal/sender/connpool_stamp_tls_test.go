package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/netauth"
)

// R3: a client-certificate binding landing between two sends on a caller-owned ConnPool. The idle
// connection's handshake presented no certificate, so only a fresh handshake can present the bound
// one. The server records the certificate each handshake actually presented.
func TestStampClientCertBindRetiresCallerPoolConn(t *testing.T) {
	certs := netauth.NewClientCerts()
	cfg := DefaultSenderConfig()
	cfg.ClientCerts = certs
	cfg.TLSVerify = false
	s := NewSender(cfg)

	var mu sync.Mutex
	var presented [][]byte
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
		NextProtos: []string{alpn.HTTP11},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			mu.Lock()
			defer mu.Unlock()
			if len(rawCerts) == 0 {
				presented = append(presented, nil)
			} else {
				presented = append(presented, rawCerts[0])
			}
			return nil
		},
	}
	srv.StartTLS()
	defer srv.Close()
	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	auth := NewAuthorisedSender(allowAll{}, s, host, port, true)
	pool := NewConnPool(2)
	defer pool.Close()
	raw := rawGet(host, port)
	send := func() {
		t.Helper()
		res, err := auth.SendReusing(context.Background(), pool, raw, ProtocolPreferenceAuto)
		if err != nil || !strings.HasSuffix(string(res.Raw), "ok") {
			t.Fatalf("send: %v %q", err, res.Raw)
		}
	}

	send() // no binding: presents nothing
	identity, leafDER := generateClientIdentity(t)
	certs.Add(identity)
	send()

	mu.Lock()
	defer mu.Unlock()
	if len(presented) != 2 || pool.Reused() != 0 {
		t.Fatalf("handshakes=%d reused=%d, want 2 and 0: the connection dialled before the bind carried the send", len(presented), pool.Reused())
	}
	if presented[0] != nil {
		t.Error("first handshake presented a certificate before any binding")
	}
	if !bytes.Equal(presented[1], leafDER) {
		t.Error("second handshake did not present the bound certificate")
	}
}
