package scanner

// A real hidden-HTTP/2 origin, and the two negatives that bound the claim.
//
// # Why this is here and not in internal/vulnapp
//
// vulnapp declares endpoints as *paths on one shared server*, and this row is per-host: the verdict
// depends only on that server's ALPN and frame behaviour, which is identical for every path on it.
// So no pair of vulnapp paths can differ in the way this row measures, and no quiet twin exists — a
// constraint vulnapp_final.go already records for this row. It is not an httptest limitation that
// could be worked around; the fixture has to be its own listener, which is what these tests build.
//
// The origin is deliberately not an http.Server. A Go http.Server over TLS either advertises h2 in
// ALPN and speaks it, or does neither — it cannot be the thing this row is about. A real hidden-h2
// origin advertises http/1.1 and *still* reads frames written at it, which is a property of the
// listener, so the listener is hand-rolled: it answers a client preface with a SETTINGS frame and
// anything else with an HTTP/1.1 error.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/core"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// h2Origin describes what a fixture origin advertises and what it will actually read.
type h2Origin struct {
	// advertiseH2 puts "h2" in the ALPN offer the listener answers with.
	advertiseH2 bool
	// readsFrames makes the listener answer a client preface with a SETTINGS frame. A listener that
	// does not is an ordinary HTTP/1.1 server as far as this probe can tell.
	readsFrames bool
}

// startOrigin runs one TLS listener with the given behaviour and returns its host and port.
func startOrigin(t *testing.T, o h2Origin) (string, uint16) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}

	next := []string{"http/1.1"}
	if o.advertiseH2 {
		next = []string{"h2", "http/1.1"}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   next,
	})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveOrigin(conn, o)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", uint16(addr.Port)
}

func serveOrigin(conn net.Conn, o h2Origin) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	preface := make([]byte, len(burpsyhttp2.ConnectionPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}
	if o.readsFrames && string(preface) == string(burpsyhttp2.ConnectionPreface) {
		// The least an HTTP/2 server may say back: an empty SETTINGS frame.
		ack := burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeSettings, 0, 0, nil)
		conn.Write(burpsyhttp2.H2FrameProgram{Frames: []burpsyhttp2.FrameSpec{ack}}.Encode())
		// Hold the connection open past the probe's read window so the reply is not raced by a
		// close the client would report as the connection ending instead.
		time.Sleep(100 * time.Millisecond)
		return
	}
	conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
}

// hiddenH2Context wires a scanner whose sender does not verify certificates at one fixture origin.
func hiddenH2Context(t *testing.T, host string, port uint16) *CheckContext {
	t.Helper()
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	cfg.Timeout = 5 * time.Second
	scan := NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithSender(sender.NewSender(cfg))
	return NewCheckContext(scan, &core.Exchange{
		Host:   host,
		Port:   port,
		TLS:    true,
		Method: "GET",
		Path:   "/",
	}, nil)
}

func TestAnOriginThatHidesHTTP2BehindAnHTTP11ALPNIsReported(t *testing.T) {
	host, port := startOrigin(t, h2Origin{advertiseH2: false, readsFrames: true})
	findings, err := checkHiddenHTTP2(context.Background(), hiddenH2Context(t, host, port))
	if err != nil {
		t.Fatalf("check failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1; this origin advertises http/1.1 and reads HTTP/2 frames anyway",
			len(findings))
	}
	if findings[0].Name != "Hidden HTTP 2" {
		t.Errorf("finding name = %q", findings[0].Name)
	}
}

func TestAnOriginThatAdvertisesHTTP2IsNotHidingIt(t *testing.T) {
	// The old check's false positive lived here: it fired on every h2-capable host. An origin whose
	// ALPN offers h2 is advertising it, so there is nothing hidden however well it speaks it.
	host, port := startOrigin(t, h2Origin{advertiseH2: true, readsFrames: true})
	findings, err := checkHiddenHTTP2(context.Background(), hiddenH2Context(t, host, port))
	if err != nil {
		t.Fatalf("check failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0; an advertised h2 surface is not a hidden one", len(findings))
	}
}

func TestAnHTTP11OnlyOriginIsNotReported(t *testing.T) {
	host, port := startOrigin(t, h2Origin{advertiseH2: false, readsFrames: false})
	findings, err := checkHiddenHTTP2(context.Background(), hiddenH2Context(t, host, port))
	if err != nil {
		t.Fatalf("check failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0; this origin neither advertises nor reads HTTP/2", len(findings))
	}
}

// A guard against the mechanism silently reverting: the probe must survive an ALPN that never
// offered h2. If SendFrameProgram's refusal path ever reclaims this call, the check can never fire.
func TestForcingHTTP2WritesFramesPastAnHTTP11ALPN(t *testing.T) {
	host, port := startOrigin(t, h2Origin{advertiseH2: false, readsFrames: true})
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	cfg.Timeout = 5 * time.Second
	gate := sender.NewAuthorisedSender(noEngagementScope{}, sender.NewSender(cfg), host, port, true)

	program := burpsyhttp2.NewH2FrameProgram(
		burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeSettings, 0, 0, nil),
	)

	if _, err := gate.SendFrameProgram(context.Background(), program); err == nil {
		t.Error("the unforced send reached an origin that negotiated http/1.1; it must refuse")
	}

	res, err := gate.SendFrameProgramForcingHTTP2(context.Background(), program)
	if err != nil {
		t.Fatalf("the forced send failed: %v", err)
	}
	if res.Negotiated == "h2" {
		t.Fatalf("this origin was supposed to negotiate http/1.1, not h2")
	}
	if len(res.ReplyFrames) == 0 {
		t.Errorf("no HTTP/2 frames came back from an origin that reads them; read ended %q, %d octets",
			res.ReadEnded, len(res.Response))
	}
}
