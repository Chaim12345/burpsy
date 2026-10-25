package sender

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/burpsy-go/burpsy/internal/core"
)

// startH3Server brings up a real HTTP/3 server on a loopback UDP port and returns its address
// plus a channel that reports what each request looked like when it arrived.
func startH3Server(t *testing.T) (host string, port uint16, seen <-chan string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a server key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
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

	arrived := make(chan string, 4)
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading the request body: %v", err)
			}
			// r.RequestURI, not r.URL.RequestURI(): the server sets it verbatim from :path, so
			// it is the exact bytes the client put on the wire.
			arrived <- fmt.Sprintf("%s %s %s %q", r.Method, r.RequestURI, r.Header.Get("X-Op"), body)
			w.Header().Set("X-Carrier", "h3")
			_, _ = w.Write([]byte("h3-ok"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listening on udp: %v", err)
	}
	go func() { _ = server.Serve(udp) }()
	t.Cleanup(func() { _ = server.Close(); _ = udp.Close() })

	hostPort := udp.LocalAddr().String()
	host, portStr, err := splitAddr(hostPort)
	if err != nil {
		t.Fatalf("splitting the h3 listener address: %v", err)
	}
	var portNum int
	if _, err := fmt.Sscanf(portStr, "%d", &portNum); err != nil {
		t.Fatalf("reading the h3 listener port: %v", err)
	}
	return host, uint16(portNum), arrived
}

// ProtocolPreferenceHTTP3 re-expresses the request over QUIC and reports the carrier honestly.
func TestSendRawOutcomeHTTP3SendsTheRequestOverQUICAndSaysSo(t *testing.T) {
	host, port, arrived := startH3Server(t)
	sender := NewSender(&SenderConfig{TLSVerify: false})

	raw := []byte("POST /h3?q=1 HTTP/1.1\r\nHost: example.test\r\nX-Op: burpsy\r\nContent-Length: 5\r\n\r\nhello")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, outcome, err := sender.SendRawOutcome(ctx, host, port, true, raw, ProtocolPreferenceHTTP3)
	if err != nil {
		t.Fatalf("SendRawOutcome: %v", err)
	}
	if outcome.Protocol != core.ProtocolHTTP3 {
		t.Fatalf("outcome protocol = %v, want HTTP/3", outcome.Protocol)
	}
	if outcome.Negotiated != "h3" {
		t.Fatalf("negotiated = %q, want h3", outcome.Negotiated)
	}
	if !strings.Contains(string(resp), "h3-ok") {
		t.Fatalf("response did not carry the h3 body:\n%s", resp)
	}
	select {
	case got := <-arrived:
		if got != `POST /h3?q=1 burpsy "hello"` {
			t.Fatalf("the server saw %q, want the request re-expressed as written", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the h3 server never saw a request")
	}
}

// ProtocolPreferenceHTTP3 never silently falls back: a plaintext target is an error, not h1.
func TestSendRawOutcomeHTTP3RefusesAPlaintextTarget(t *testing.T) {
	sender := NewSender(&SenderConfig{TLSVerify: false})
	raw := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := sender.SendRawOutcome(ctx, "127.0.0.1", 80, false, raw, ProtocolPreferenceHTTP3)
	if err == nil {
		t.Fatal("a plaintext target under an explicit h3 preference sent something instead of failing")
	}
	if !strings.Contains(err.Error(), "HTTP/3") {
		t.Fatalf("the error must name the preference, got %v", err)
	}
}

// ProtocolPreferenceHTTP3 never silently drops: a construct h3 cannot carry is an error naming it.
func TestSendRawOutcomeHTTP3RefusesARequestItCannotCarry(t *testing.T) {
	sender := NewSender(&SenderConfig{TLSVerify: false})
	raw := []byte("POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := sender.SendRawOutcome(ctx, "127.0.0.1", 443, true, raw, ProtocolPreferenceHTTP3)
	if err == nil {
		t.Fatal("a chunked request under an explicit h3 preference sent something instead of failing")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "transfer-encoding") {
		t.Fatalf("the error must name the uncarriable construct, got %v", err)
	}
}

// ProtocolPreferenceHTTP3 against an endpoint that never answers QUIC is an error, not a quiet
// slide onto h2 or HTTP/1.1 — the report must never say h3 for bytes h1 carried.
func TestSendRawOutcomeHTTP3FailsAgainstAnEndpointThatDoesNotAnswerQUIC(t *testing.T) {
	// A TCP listener guarantees the address is bound, so the UDP dial can only ever time out:
	// nothing on this port will ever complete a QUIC handshake.
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on tcp: %v", err)
	}
	defer tcp.Close()
	host, portStr, err := splitAddr(tcp.Addr().String())
	if err != nil {
		t.Fatalf("splitting the tcp listener address: %v", err)
	}
	var portNum int
	if _, err := fmt.Sscanf(portStr, "%d", &portNum); err != nil {
		t.Fatalf("reading the tcp listener port: %v", err)
	}

	sender := NewSender(&SenderConfig{TLSVerify: false})
	raw := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err = sender.SendRawOutcome(ctx, host, uint16(portNum), true, raw, ProtocolPreferenceHTTP3)
	if err == nil {
		t.Fatal("an endpoint that never answers QUIC sent something instead of failing")
	}
}

// burpsy-react-ui-swqq: the parse-transformed shapes ride h3 byte-for-byte, exactly as h2 carries
// them - one RequestURL, one verbatim rule, both legs.
func TestH3SendCarriesParseTransformedTargetsVerbatim(t *testing.T) {
	for _, target := range []string{"/a#b", "/a?x=1#frag", "/a#b?c=d"} {
		t.Run(target, func(t *testing.T) {
			host, port, arrived := startH3Server(t)
			sender := NewSender(&SenderConfig{TLSVerify: false})
			raw := []byte("GET " + target + " HTTP/1.1\r\nHost: example.test\r\nX-Op: burpsy\r\n\r\n")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, _, err := sender.SendRawOutcome(ctx, host, port, true, raw, ProtocolPreferenceHTTP3); err != nil {
				t.Fatalf("SendRawOutcome: %v", err)
			}
			select {
			case got := <-arrived:
				want := "GET " + target + ` burpsy ""`
				if got != want {
					t.Fatalf("the h3 server saw %q, want %q - :path was not verbatim", got, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the h3 server never saw a request")
			}
		})
	}
}

// '/a b' never reaches RequestURL on this leg either: the request line's own tokenisation
// refuses it (same bar as h2), and under the explicit h3 pin the refusal is the strict error.
func TestH3SendRefusesARawSpaceInTheRequestLine(t *testing.T) {
	sender := NewSender(&SenderConfig{TLSVerify: false})
	raw := []byte("GET /a b HTTP/1.1\r\nHost: example.test\r\n\r\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := sender.SendRawOutcome(ctx, "127.0.0.1", 443, true, raw, ProtocolPreferenceHTTP3)
	if err == nil {
		t.Fatal("a request line with a raw space went to h3 instead of being refused")
	}
	if !strings.Contains(err.Error(), "request line") {
		t.Fatalf("the refusal must name the request line, got %v", err)
	}
}
