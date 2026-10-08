// Package h2test is a raw HTTP/2 origin for tests that must see a request's header list exactly as the
// wire carried it.
//
// net/http's HTTP/2 server cannot be that origin: it is a compliant implementation, so it rejects a
// field value containing CR or LF, an uppercase name, or a pseudo-header after a regular field before a
// handler ever runs. Those are precisely the requests a kettled send (burpsy-react-ui-jae5) exists to
// make. This server decodes the request block with burpsy's own HPACK decoder, which keeps every octet,
// and answers one stream per connection. It is test support only — the same role net/http/httptest
// plays — and nothing outside a _test.go file imports it.
package h2test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
)

// Options shapes how the origin behaves.
type Options struct {
	// InitialWindow, when non-zero, is advertised as SETTINGS_INITIAL_WINDOW_SIZE, and the origin then
	// returns flow-control credit only as it reads DATA — so a client that ignores the window overruns it.
	InitialWindow uint32
	// RequireSettingsAck withholds the response until the client acknowledges the origin's SETTINGS.
	RequireSettingsAck bool
	// Ping sends a PING after SETTINGS and withholds the response until it is acknowledged.
	Ping bool
	// Reset answers the stream with RST_STREAM(PROTOCOL_ERROR) instead of a response.
	Reset bool
	// ResponseBody is the body sent back; empty sends "ok".
	ResponseBody []byte
}

// Request is one request as the origin decoded it.
type Request struct {
	Fields []burpsyhttp2.HeaderField
	Body   []byte
	// FlowViolation is set when the client sent more DATA than the window it had been given.
	FlowViolation bool
}

// Server is a running origin.
type Server struct {
	Host     string
	Port     uint16
	Accepted atomic.Int64

	mu       sync.Mutex
	requests []Request
}

// Requests is every request decoded so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Start runs an origin on 127.0.0.1 that negotiates h2 over TLS with httptest's certificate, so a
// sender with verification off reaches it. It stops when the test ends.
func Start(t testing.TB, opts Options) *Server {
	t.Helper()
	base := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base.StartTLS()
	cert := base.TLS.Certificates
	base.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: cert, NextProtos: []string{"h2"}})
	t.Cleanup(func() { tlsLn.Close() })
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	s := &Server{Host: host, Port: uint16(port)}
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			s.Accepted.Add(1)
			go s.serve(conn, opts)
		}
	}()
	return s
}

func writeFrame(w io.Writer, ty, flags uint8, stream uint32, payload []byte) error {
	hdr := burpsyhttp2.NewFrameSpec(ty, flags, stream, payload).Header().Encode()
	_, err := w.Write(append(hdr[:], payload...))
	return err
}

func (s *Server) serve(conn net.Conn, opts Options) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	preface := make([]byte, len(burpsyhttp2.ConnectionPreface))
	if _, err := io.ReadFull(br, preface); err != nil || string(preface) != burpsyhttp2.ConnectionPreface {
		return
	}
	var settings []byte
	window := int64(65535)
	if opts.InitialWindow != 0 {
		settings = binary.BigEndian.AppendUint16(settings, 0x4)
		settings = binary.BigEndian.AppendUint32(settings, opts.InitialWindow)
		window = int64(opts.InitialWindow)
	}
	if writeFrame(conn, burpsyhttp2.TypeSettings, 0, 0, settings) != nil {
		return
	}
	pingAcked := !opts.Ping
	if opts.Ping {
		if writeFrame(conn, burpsyhttp2.TypePing, 0, 0, []byte("burpsy!!")) != nil {
			return
		}
	}
	settingsAcked := !opts.RequireSettingsAck
	decoder := burpsyhttp2.NewDecoder(4096)
	var block []byte
	var req Request
	// endStream and headersDone are separate because END_STREAM rides the HEADERS frame while
	// END_HEADERS may arrive on a later CONTINUATION: a request is complete only when both have.
	endStream, headersDone, answered := false, false, false
	connWindow := int64(65535)
	for {
		var head [burpsyhttp2.FrameHeaderLen]byte
		if _, err := io.ReadFull(br, head[:]); err != nil {
			return
		}
		hdr, _ := burpsyhttp2.DecodeFrameHeader(head[:])
		if hdr.Len > 16384 {
			// This origin never raises SETTINGS_MAX_FRAME_SIZE, so a larger frame is a FRAME_SIZE_ERROR
			// (RFC 9113 §4.2), answered the way a real server answers it.
			writeFrame(conn, burpsyhttp2.TypeGoAway, 0, 0, binary.BigEndian.AppendUint32(make([]byte, 4), 6))
			return
		}
		payload := make([]byte, hdr.Len)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}
		switch hdr.Type {
		case burpsyhttp2.TypeSettings:
			if hdr.Flags&burpsyhttp2.FlagAck != 0 {
				settingsAcked = true
			} else if writeFrame(conn, burpsyhttp2.TypeSettings, burpsyhttp2.FlagAck, 0, nil) != nil {
				return
			}
		case burpsyhttp2.TypePing:
			if hdr.Flags&burpsyhttp2.FlagAck != 0 && string(payload) == "burpsy!!" {
				pingAcked = true
			}
		case burpsyhttp2.TypeHeaders, burpsyhttp2.TypeContinuation:
			block = append(block, payload...)
			if hdr.Flags&burpsyhttp2.FlagEndHeaders != 0 {
				fields, err := decoder.Decode(block)
				if err != nil {
					return
				}
				req.Fields = fields
				block = nil
				headersDone = true
			}
			if hdr.Flags&burpsyhttp2.FlagEndStream != 0 {
				endStream = true
			}
		case burpsyhttp2.TypeData:
			connWindow -= int64(len(payload))
			window -= int64(len(payload))
			if opts.InitialWindow != 0 && (window < 0 || connWindow < 0) {
				req.FlowViolation = true
			}
			req.Body = append(req.Body, payload...)
			if len(payload) > 0 {
				inc := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
				if writeFrame(conn, burpsyhttp2.TypeWindowUpdate, 0, 0, inc) != nil ||
					writeFrame(conn, burpsyhttp2.TypeWindowUpdate, 0, 1, inc) != nil {
					return
				}
				connWindow += int64(len(payload))
				window += int64(len(payload))
			}
			if hdr.Flags&burpsyhttp2.FlagEndStream != 0 {
				endStream = true
			}
		}
		if endStream && headersDone && settingsAcked && pingAcked && !answered {
			answered = true
			s.mu.Lock()
			s.requests = append(s.requests, req)
			s.mu.Unlock()
			if opts.Reset {
				writeFrame(conn, burpsyhttp2.TypeRSTStream, 0, 1, binary.BigEndian.AppendUint32(nil, 1))
				continue
			}
			body := opts.ResponseBody
			if len(body) == 0 {
				body = []byte("ok")
			}
			respBlock := burpsyhttp2.EncodeLiteral([]burpsyhttp2.HeaderField{
				burpsyhttp2.NewHeaderField(":status", "200"),
				burpsyhttp2.NewHeaderField("content-type", "text/plain"),
				burpsyhttp2.NewHeaderField("x-fields-seen", strconv.Itoa(len(req.Fields))),
			})
			if writeFrame(conn, burpsyhttp2.TypeHeaders, burpsyhttp2.FlagEndHeaders, 1, respBlock) != nil {
				return
			}
			for len(body) > 0 {
				n := min(len(body), 16384)
				var flags uint8
				if n == len(body) {
					flags = burpsyhttp2.FlagEndStream
				}
				if writeFrame(conn, burpsyhttp2.TypeData, flags, 1, body[:n]) != nil {
					return
				}
				body = body[n:]
			}
		}
	}
}
