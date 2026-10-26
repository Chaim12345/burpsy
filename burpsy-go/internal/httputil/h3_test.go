package httputil

// RoundTripH3 is the one re-expression path onto HTTP/3 (vln3): both the sender's explicit h3 pin
// and the proxy's Alt-Svc-selected h3 builds their request and reads their response here, so a
// utls-style bug in the re-expression has exactly one place to live.

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

	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
)

func startH3Origin(t *testing.T) (addr string, seen <-chan string) {
	t.Helper()
	return startH3OriginWithHandler(t, nil)
}

// startH3OriginWithHandler is startH3Origin with an optional handler of its own; nil keeps the
// "h3-ok" echo the existing callers are written against.
func startH3OriginWithHandler(t *testing.T, handler http.HandlerFunc) (addr string, seen <-chan string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(13),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	arrived := make(chan string, 4)
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			arrived <- fmt.Sprintf("%s %s %s %q", r.Method, r.URL.RequestURI(), r.Header.Get("X-Op"), body)
			_, _ = w.Write([]byte("h3-ok"))
		}
	}
	server := &http3.Server{
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(udp) }()
	t.Cleanup(func() { _ = server.Close(); _ = udp.Close() })
	return udp.LocalAddr().String(), arrived
}

// A request carried over QUIC arrives re-expressed exactly - method, target, fields, body - and
// the response comes back rendered HTTP/1-shaped, the same shape every other leg returns.
func TestRoundTripH3CarriesTheRequestAsWritten(t *testing.T) {
	addr, arrived := startH3Origin(t)
	tlsConfig := &tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true, NextProtos: []string{"h3"}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, truncated, err := RoundTripH3(ctx, tlsConfig, addr, "example.test", "POST", "/h3?q=1",
		[]burpsyhttp2.Header{{Name: "x-op", Value: "burpsy"}}, []byte("hello"))
	if err != nil {
		t.Fatalf("RoundTripH3: %v", err)
	}
	if truncated {
		t.Fatal("a five-byte body must not come back cut")
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

// A target no URL form can hold is an error naming the bytes, never a silent re-escape.
func TestRoundTripH3RefusesAnUnusableTarget(t *testing.T) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := RoundTripH3(ctx, tlsConfig, "127.0.0.1:443", "example.test", "GET", "not-a-path", nil, nil); err == nil {
		t.Fatal("a target with no leading slash round-tripped instead of failing")
	}
}

// A body past the cap comes back cut at the cap, marked truncated, with a rendered head whose
// Content-Length tells the truth about the bytes that survived (PR #363 review: the read was
// uncapped, and an unbounded origin body could exhaust memory while the record stayed silent).
func TestRoundTripH3CapsTheResponseBody(t *testing.T) {
	defer func(prev int64) { maxH3ResponseBodyBytes = prev }(maxH3ResponseBodyBytes)
	maxH3ResponseBodyBytes = 8
	addr, _ := startH3OriginWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789abcdef"))
	})
	tlsConfig := &tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, truncated, err := RoundTripH3(ctx, tlsConfig, addr, "example.test", "GET", "/", nil, nil)
	if err != nil {
		t.Fatalf("RoundTripH3: %v", err)
	}
	if !truncated {
		t.Fatal("a 16-byte body under an 8-byte cap was not marked cut")
	}
	if !strings.Contains(string(resp), "01234567") || strings.Contains(string(resp), "012345678") {
		t.Fatalf("the body was not cut at the cap:\n%s", resp)
	}
	if !strings.Contains(string(resp), "Content-Length: 8") {
		t.Fatalf("the rendered head lies about the cut body's length:\n%s", resp)
	}
}

// A dial that never connected is the only h3 failure that may be retried on another carrier:
// maybeDelivered stays false (PR #363 review: the request cannot have reached the origin).
func TestRoundTripH3MeasuredDialFailureIsNotSent(t *testing.T) {
	// A UDP port nobody listens on: the handshake times out under the dial bound.
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := udp.LocalAddr().String()
	_ = udp.Close()
	tlsConfig := &tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, maybeDelivered, _, err := RoundTripH3Measured(300*time.Millisecond, ctx, tlsConfig, addr, "example.test", "GET", "/", nil, nil)
	if err == nil {
		t.Fatal("a round trip to a dead endpoint succeeded")
	}
	if maybeDelivered {
		t.Fatal("a dial that never connected was reported as possibly delivered")
	}
}

// A failure after the connection existed leaves delivery uncertain - the origin may have the
// request or not, and this side cannot know: maybeDelivered comes back true, which is what
// stops the proxy from automatically replaying the request over HTTP/1.1 (PR #363 review).
func TestRoundTripH3MeasuredPostConnectFailureIsSent(t *testing.T) {
	addr, _ := startH3OriginWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		// Hold the response open past the client's deadline: the connection exists, the
		// request arrived, and the exchange dies waiting.
		<-r.Context().Done()
	})
	tlsConfig := &tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, maybeDelivered, _, err := RoundTripH3Measured(5*time.Second, ctx, tlsConfig, addr, "example.test", "GET", "/", nil, nil)
	if err == nil {
		t.Fatal("a round trip whose response never came succeeded")
	}
	if !maybeDelivered {
		t.Fatal("a failure after the handshake was reported as safe to replay")
	}
}

// Cancelling the exchange after the handshake is the same uncertain shape: the connection
// existed, the request may or may not have been processed, so maybeDelivered is true and the
// error is the cancellation - never a safe automatic retry (PR #363 review).
func TestRoundTripH3MeasuredCancelAfterHandshakeIsUncertain(t *testing.T) {
	addr, _ := startH3OriginWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	tlsConfig := &tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	_, maybeDelivered, _, err := RoundTripH3Measured(5*time.Second, ctx, tlsConfig, addr, "example.test", "GET", "/", nil, nil)
	if err == nil {
		t.Fatal("a cancelled exchange succeeded")
	}
	if !maybeDelivered {
		t.Fatal("a cancellation after the handshake was reported as safe to replay")
	}
}
