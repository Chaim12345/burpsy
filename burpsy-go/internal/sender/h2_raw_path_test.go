package sender

// burpsy-react-ui-0vzb.25: an h2 send must carry the request-target's bytes verbatim, including
// percent escapes net/url would reject (%%32%65, %zz). The target IS the probe — CVE-2023-25690's
// path-confusion checks send exactly those — so re-escaping it tests a different request and
// rejecting it (the old behaviour: http.NewRequest failed url.Parse and the send errored out) hides
// the answer entirely.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/core"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// rawH2Peer is a frame-level h2 endpoint that records the :path it is sent and answers 200.
//
// Not httptest: the stdlib's h2 server parses :path into a URL before the handler runs and rejects
// what it cannot parse — which is the very input this test exists to send. The claim under test is
// what left our side of the wire, so the peer reads the HEADERS block itself.
type rawH2Peer struct {
	host string
	port uint16

	mu    sync.Mutex
	paths []string
}

func startRawH2Peer(t *testing.T) *rawH2Peer {
	t.Helper()
	p := &rawH2Peer{}
	// Borrow httptest's certificate, the way startRecordingServer does: it is the leaf every sender
	// test already trusts with TLSVerify off, and minting one here would test the mint, not the path.
	base := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base.StartTLS()
	cert := base.TLS.Certificates
	base.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: cert, NextProtos: []string{alpn.H2}})
	t.Cleanup(func() { tlsLn.Close() })
	host, port, err := hostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("listener address: %v", err)
	}
	p.host, p.port = host, port
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.exchange(conn)
		}
	}()
	return p
}

// exchange serves one connection: settings handshake, one request's HEADERS block, a 200 answer.
func (p *rawH2Peer) exchange(conn net.Conn) {
	defer conn.Close()
	// A stuck test must not wedge the goroutine forever; a real answer is microseconds away on
	// loopback, so ten seconds is failure, not patience.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fr := http2.NewFramer(conn, conn)
	// The server's connection preface is a SETTINGS frame (RFC 9113 §3.5); sending it first lets the
	// client write its own preface and request without waiting on us.
	if err := fr.WriteSettings(); err != nil {
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	var block []byte
	var streamID uint32
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					return
				}
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				if err := fr.WritePing(true, f.Data); err != nil {
					return
				}
			}
		case *http2.HeadersFrame:
			streamID = f.StreamID
			block = append(block[:0], f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				p.answer(fr, streamID, block)
				return
			}
		case *http2.ContinuationFrame:
			block = append(block, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				p.answer(fr, streamID, block)
				return
			}
		}
	}
}

// answer records the block's :path and writes a minimal 200 with a two-byte body.
func (p *rawH2Peer) answer(fr *http2.Framer, streamID uint32, block []byte) {
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(block)
	if err != nil {
		return
	}
	for _, hf := range fields {
		if hf.Name == ":path" {
			p.mu.Lock()
			p.paths = append(p.paths, hf.Value)
			p.mu.Unlock()
		}
	}
	var head bytes.Buffer
	enc := hpack.NewEncoder(&head)
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "2"})
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: head.Bytes(), EndHeaders: true}); err != nil {
		return
	}
	_ = fr.WriteData(streamID, true, []byte("ok"))
}

func (p *rawH2Peer) lastPath(t *testing.T) string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.paths) == 0 {
		t.Fatal("the peer recorded no :path — the request never arrived as h2")
	}
	return p.paths[len(p.paths)-1]
}

// sendRawToH2 sends raw at the peer and insists it was h2 that carried it, returning the response.
func sendRawToH2(t *testing.T, s *Sender, peer *rawH2Peer, raw []byte) []byte {
	t.Helper()
	resp, outcome, err := s.SendRawOutcome(context.Background(), peer.host, peer.port, true, raw, ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if outcome.Negotiated != alpn.H2 || outcome.Protocol != core.ProtocolHTTP2 {
		t.Fatalf("the exchange did not go out as h2 (negotiated %q, protocol %v) — the :path claim would be untested", outcome.Negotiated, outcome.Protocol)
	}
	if outcome.Downgraded() {
		t.Fatalf("an h2 send must carry no downgrade, got %v", outcome.Downgrade)
	}
	return resp
}

// The bead's case: an operator-written path whose escapes are invalid reaches the wire byte-for-byte.
func TestSendH2CarriesARawPathWithInvalidPercentEscapesVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
	}{
		{"the bcheck corpus probe", "/%%32%65"},
		{"an invalid escape in the query", "/x%%32?y=%zz"},
		{"an incomplete escape at the end", "/trail%"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := startRawH2Peer(t)
			s := testSender()
			raw := []byte("GET " + tc.target + " HTTP/1.1\r\nHost: " + formatHostPort(peer.host, peer.port) + "\r\n\r\n")
			resp := sendRawToH2(t, s, peer, raw)
			if got := peer.lastPath(t); got != tc.target {
				t.Fatalf("the peer saw :path %q — the probe was rewritten on the way out; want %q verbatim", got, tc.target)
			}
			if !bytes.HasPrefix(resp, []byte("HTTP/2 200")) {
				t.Fatalf("response was not the peer's 200: %q", firstLine(resp))
			}
		})
	}
}

// The same carry for a replayed h2-native request line (what the repeater resends).
func TestSendH2ReplayCarriesARawPathWithInvalidPercentEscapesVerbatim(t *testing.T) {
	peer := startRawH2Peer(t)
	s := testSender()
	raw := []byte("GET /%%32%65 HTTP/2\r\nHost: " + formatHostPort(peer.host, peer.port) + "\r\n\r\n")
	sendRawToH2(t, s, peer, raw)
	if got := peer.lastPath(t); got != "/%%32%65" {
		t.Fatalf("the peer saw :path %q, want the replayed %q verbatim", got, "/%%32%65")
	}
}

// Regression pins: targets net/url already accepted must reach the wire unchanged — the fix routes
// through the same parse it always used when the parse succeeds, and "//"-prefixed targets keep
// working because only that path can carry them.
func TestSendH2StillCarriesParseableTargetsVerbatim(t *testing.T) {
	for _, target := range []string{"/a%20b?c=d", "//double/slash", "/"} {
		peer := startRawH2Peer(t)
		s := testSender()
		raw := []byte("GET " + target + " HTTP/1.1\r\nHost: " + formatHostPort(peer.host, peer.port) + "\r\n\r\n")
		sendRawToH2(t, s, peer, raw)
		if got := peer.lastPath(t); got != target {
			t.Fatalf("the peer saw :path %q, want %q verbatim", got, target)
		}
	}
}
