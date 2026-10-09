package sender

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"golang.org/x/net/http2/hpack"
)

// A kettled request's send (burpsy-react-ui-jae5): one HTTP/2 request whose header list is exactly the
// list the operator wrote, CR/LF, casing and pseudo-header order included.
//
// # Why neither existing h2 path can carry one
//
// The ordinary h2 send (h2.go) goes through golang.org/x/net/http2, which is a compliant client: it
// lowercases names, rejects a value containing CR or LF, and writes pseudo-headers in its own order.
// Every one of those is a correction a kettled request exists to avoid. The frame-program path
// (h2program.go) carries any header block verbatim, but it is write-then-read-for-a-window: it never
// acknowledges the peer's SETTINGS, never answers a PING, ignores flow control, and returns octets
// rather than a response. A server is entitled to wait for the SETTINGS ACK, and a response larger than
// the initial window stalls.
//
// So this is the frame-program path's authorisation and dial with a small interactive exchange on top:
// one stream, the HEADERS block written literally (http2.EncodeLiteral), the peer's SETTINGS and PINGs
// acknowledged, DATA paced by flow control, and stream 1 read until END_STREAM, RST_STREAM or GOAWAY —
// whichever ended it is named.
//
// # The gate is the frame-program gate
//
// The request's HEADERS program is classified by http2.Authorise and acted on by authoriseProgram, the
// same switch SendFrameProgram uses. So a kettled list the classifier cannot decide — a space in :path, a
// second :path — is refused by name before anything is dialled, and a list it can decide is checked
// against the engagement scope per addressed request, :authority included. Nothing here is a second
// scope check.

// h2FieldsMaxWindow is the largest flow-control window HTTP/2 allows (RFC 9113 §6.9.1), advertised as
// this connection's initial window and topped up on the connection, so the response is never paced by
// our own receive window.
const h2FieldsMaxWindow = 1<<31 - 1

// h2FieldsDefaultFrame is SETTINGS_MAX_FRAME_SIZE's initial value, which every peer accepts until it
// says otherwise.
const h2FieldsDefaultFrame = 16384

// h2FieldsMaxResponseBlock bounds one response header block.
const h2FieldsMaxResponseBlock = 1 << 20

// H2FieldsResult is one kettled send: what was authorised, what went out, and the response.
type H2FieldsResult struct {
	// Authorisation is the classifier's verdict on the request's HEADERS program, carried even on a
	// refusal so the caller can show which construct stopped it.
	Authorisation burpsyhttp2.Authorisation
	// Negotiated is the ALPN protocol the handshake settled on.
	Negotiated string
	// HeaderBlock is the HPACK block written, before it was split into frames.
	HeaderBlock []byte
	// Status is the final response's :status, 0 when none arrived.
	Status int
	// ResponseFields is the final response's decoded header list in order, :status included.
	ResponseFields []burpsyhttp2.HeaderField
	// Trailers is a trailing header block, when the peer sent one.
	Trailers []burpsyhttp2.HeaderField
	// Body is the response's DATA payloads, padding removed.
	Body []byte
	// Response is the HTTP/1-shaped rendering history stores, the same shape the ordinary h2 path
	// renders (http2.RenderResponse).
	Response []byte
	// Ended names what ended the read: the stream ending, a reset, a GOAWAY, the peer closing, the
	// deadline.
	Ended    string
	Started  time.Time
	Duration time.Duration
}

// SendH2Fields authorises one HTTP/2 request given as a literal field list and, if the scope agrees,
// sends it on a fresh connection and reads its response.
//
// The order is SendFrameProgram's: classify, authorise, pace, dial, write. A TLS target that does not
// negotiate h2 is refused by name rather than forced (dialForProgram), because a kettled request has no
// HTTP/1.1 form to fall back to. A response that ends without a final HEADERS block is an error naming
// how the stream ended — a reset is frequently the answer a header-injection probe was looking for, and
// it must not read as an empty 200.
func (a *AuthorisedSender) SendH2Fields(
	ctx context.Context, fields []burpsyhttp2.HeaderField, body []byte,
) (H2FieldsResult, error) {
	block := burpsyhttp2.EncodeLiteral(fields)
	headerFrames := h2FieldsHeaderFrames(block, len(body) == 0)
	res := H2FieldsResult{
		HeaderBlock:   block,
		Authorisation: burpsyhttp2.Authorise(burpsyhttp2.NewH2FrameProgram(headerFrames...)),
	}
	if err := a.authoriseProgram(res.Authorisation); err != nil {
		return res, err
	}
	release, err := a.pacing(ctx)
	if err != nil {
		return res, err
	}
	defer release()

	conn, negotiated, err := a.dialForProgram(ctx, false)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	defer watchCancel(ctx, conn)()
	res.Negotiated = negotiated

	res.Started = time.Now()
	a.net.setDeadline(ctx, conn, a.host)
	ex := &h2FieldsExchange{
		conn:         conn,
		br:           bufio.NewReader(conn),
		decoder:      hpack.NewDecoder(4096, nil),
		connWindow:   65535,
		streamWindow: 65535,
		peerInitial:  65535,
		maxFrame:     h2FieldsDefaultFrame,
		pending:      body,
	}
	err = ex.run(headerFrames)
	res.Duration = time.Since(res.Started)
	res.Ended = ex.ended
	res.Status, res.ResponseFields, res.Trailers, res.Body = ex.status, ex.fields, ex.trailers, ex.body
	if ex.wrote {
		a.sent.Add(1)
	}
	if err != nil {
		return res, err
	}
	if ex.status == 0 {
		return res, fmt.Errorf("no response: %s before the server sent a response header block", ex.ended)
	}
	res.Response = burpsyhttp2.RenderResponse(ex.status, responseHeaders(ex.fields, ex.trailers), ex.body)
	return res, nil
}

// h2FieldsHeaderFrames splits a header block into a HEADERS frame and as many CONTINUATIONs as the
// default frame size needs, on stream 1.
func h2FieldsHeaderFrames(block []byte, endStream bool) []burpsyhttp2.FrameSpec {
	var frames []burpsyhttp2.FrameSpec
	first := true
	for {
		chunk := block
		if len(chunk) > h2FieldsDefaultFrame {
			chunk = block[:h2FieldsDefaultFrame]
		}
		block = block[len(chunk):]
		var flags uint8
		if len(block) == 0 {
			flags |= burpsyhttp2.FlagEndHeaders
		}
		ty := burpsyhttp2.TypeContinuation
		if first {
			ty = burpsyhttp2.TypeHeaders
			if endStream {
				flags |= burpsyhttp2.FlagEndStream
			}
		}
		frames = append(frames, burpsyhttp2.NewFrameSpec(ty, flags, 1, append([]byte(nil), chunk...)))
		first = false
		if len(block) == 0 {
			return frames
		}
	}
}

// responseHeaders converts a decoded response list into the rendering's header shape, without the
// :status pseudo-header (which the rendering's status line carries) and with any trailers after.
func responseHeaders(fields, trailers []burpsyhttp2.HeaderField) []burpsyhttp2.Header {
	out := make([]burpsyhttp2.Header, 0, len(fields)+len(trailers))
	for _, list := range [][]burpsyhttp2.HeaderField{fields, trailers} {
		for _, f := range list {
			if strings.HasPrefix(string(f.Name), ":") {
				continue
			}
			out = append(out, burpsyhttp2.Header{Name: string(f.Name), Value: string(f.Value)})
		}
	}
	return out
}

// h2FieldsExchange is the state of one single-stream exchange: flow-control windows, the response
// being assembled, and the request body still to send.
type h2FieldsExchange struct {
	conn net.Conn
	br   *bufio.Reader
	// decoder reads the server's blocks. x/net's decoder rather than burpsy's own: a server Huffman-codes
	// its strings as a matter of course, and internal/http2's decoder refuses Huffman rather than
	// guess. The request side needs no decoder — it is written literally.
	decoder *hpack.Decoder

	connWindow, streamWindow int64
	peerInitial              int64
	maxFrame                 int
	pending                  []byte
	wrote                    bool
	// peerSettings is set once the server's first SETTINGS has arrived. No DATA goes out before it: a
	// server may shrink the initial window there, and while sending on the default 65535 meanwhile is
	// legal (§6.9.2 lets the window go negative), a body that arrives before the server has said how
	// much it will take is the case most likely to be answered with FLOW_CONTROL_ERROR by a strict peer.
	peerSettings bool

	// block accumulates a response header block across CONTINUATIONs.
	block    []byte
	blockEnd bool

	interim  int
	status   int
	fields   []burpsyhttp2.HeaderField
	trailers []burpsyhttp2.HeaderField
	body     []byte
	ended    string
}

// errH2FieldsDone ends the read loop when stream 1 is finished.
var errH2FieldsDone = errors.New("done")

// run writes the opening frames and then reads until stream 1 ends.
func (x *h2FieldsExchange) run(headerFrames []burpsyhttp2.FrameSpec) error {
	settings := make([]byte, 0, 12)
	settings = appendSetting(settings, 0x2, 0)                 // SETTINGS_ENABLE_PUSH: no pushes
	settings = appendSetting(settings, 0x4, h2FieldsMaxWindow) // SETTINGS_INITIAL_WINDOW_SIZE
	opening := burpsyhttp2.H2FrameProgram{Preface: true, Frames: append([]burpsyhttp2.FrameSpec{
		burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeSettings, 0, 0, settings),
		burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeWindowUpdate, 0, 0, windowIncrement(h2FieldsMaxWindow-65535)),
	}, headerFrames...)}
	if _, err := x.conn.Write(opening.Encode()); err != nil {
		return fmt.Errorf("writing the request: %w", err)
	}
	x.wrote = true
	if err := x.pump(); err != nil {
		return err
	}
	for {
		hdr, payload, err := x.readFrame()
		if err != nil {
			var netErr net.Error
			switch {
			case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
				x.ended = "the server closed the connection"
			case errors.As(err, &netErr) && netErr.Timeout():
				x.ended = "the response timeout passed"
			default:
				x.ended = "the read failed: " + err.Error()
			}
			// A response whose head arrived and whose body was cut short is still a response, and the cut
			// is named in ended rather than turned into an error that throws the head away. With no head
			// at all, SendH2Fields turns ended into the error.
			return nil
		}
		if err := x.handle(hdr, payload); err != nil {
			if errors.Is(err, errH2FieldsDone) {
				return nil
			}
			return err
		}
	}
}

// readFrame reads one whole frame. A declared length beyond the 24-bit maximum is impossible, so the
// largest read is bounded by the field itself.
func (x *h2FieldsExchange) readFrame() (burpsyhttp2.FrameHeader, []byte, error) {
	var head [burpsyhttp2.FrameHeaderLen]byte
	if _, err := io.ReadFull(x.br, head[:]); err != nil {
		return burpsyhttp2.FrameHeader{}, nil, err
	}
	hdr, _ := burpsyhttp2.DecodeFrameHeader(head[:])
	payload := make([]byte, hdr.Len)
	if _, err := io.ReadFull(x.br, payload); err != nil {
		return hdr, nil, err
	}
	return hdr, payload, nil
}

// handle acts on one frame from the peer.
func (x *h2FieldsExchange) handle(hdr burpsyhttp2.FrameHeader, payload []byte) error {
	stream := hdr.StreamIDMasked()
	switch hdr.Type {
	case burpsyhttp2.TypeSettings:
		if hdr.Flags&burpsyhttp2.FlagAck != 0 {
			return nil
		}
		x.peerSettings = true
		for i := 0; i+6 <= len(payload); i += 6 {
			id := binary.BigEndian.Uint16(payload[i:])
			val := binary.BigEndian.Uint32(payload[i+2:])
			switch id {
			case 0x4: // SETTINGS_INITIAL_WINDOW_SIZE: applies retroactively to the open stream (§6.9.2)
				x.streamWindow += int64(val) - x.peerInitial
				x.peerInitial = int64(val)
			case 0x5: // SETTINGS_MAX_FRAME_SIZE
				if val >= h2FieldsDefaultFrame && val <= burpsyhttp2.MaxFramePayload {
					x.maxFrame = int(val)
				}
			}
		}
		if err := x.write(burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeSettings, burpsyhttp2.FlagAck, 0, nil)); err != nil {
			return err
		}
		return x.pump()
	case burpsyhttp2.TypePing:
		if hdr.Flags&burpsyhttp2.FlagAck != 0 {
			return nil
		}
		return x.write(burpsyhttp2.NewFrameSpec(burpsyhttp2.TypePing, burpsyhttp2.FlagAck, 0, payload))
	case burpsyhttp2.TypeWindowUpdate:
		if len(payload) < 4 {
			return nil
		}
		inc := int64(binary.BigEndian.Uint32(payload) & 0x7fff_ffff)
		switch stream {
		case 0:
			x.connWindow += inc
		case 1:
			x.streamWindow += inc
		}
		return x.pump()
	case burpsyhttp2.TypeGoAway:
		code, debug := uint32(0), ""
		if len(payload) >= 8 {
			code = binary.BigEndian.Uint32(payload[4:8])
			debug = string(payload[8:])
		}
		x.ended = "the server sent GOAWAY (" + h2ErrorName(code) + ")"
		if debug != "" {
			x.ended += ": " + strconv.Quote(debug)
		}
		if x.status == 0 {
			return errors.New("no response: " + x.ended)
		}
		return errH2FieldsDone
	case burpsyhttp2.TypeRSTStream:
		if stream != 1 {
			return nil
		}
		code := uint32(0)
		if len(payload) >= 4 {
			code = binary.BigEndian.Uint32(payload)
		}
		x.ended = "the server reset the stream (" + h2ErrorName(code) + ")"
		if x.status == 0 {
			return errors.New("no response: " + x.ended)
		}
		return errH2FieldsDone
	case burpsyhttp2.TypeHeaders, burpsyhttp2.TypeContinuation:
		if stream != 1 {
			return nil
		}
		fragment := payload
		if hdr.Type == burpsyhttp2.TypeHeaders {
			frag, ok := headersFragment(hdr.Flags, payload)
			if !ok {
				return errors.New("the server's HEADERS frame is padded past its own length")
			}
			fragment = frag
			// A fresh slice, never a reslice: the decoded fields of the previous block may share its
			// backing array.
			x.block = nil
			x.blockEnd = hdr.Flags&burpsyhttp2.FlagEndStream != 0
		}
		x.block = append(x.block, fragment...)
		if len(x.block) > h2FieldsMaxResponseBlock {
			// A peer that keeps a header block open with CONTINUATIONs would otherwise grow this without
			// bound (the CONTINUATION flood).
			return fmt.Errorf("the server's response header block passed %d bytes without ending", h2FieldsMaxResponseBlock)
		}
		if hdr.Flags&burpsyhttp2.FlagEndHeaders == 0 {
			return nil
		}
		decoded, err := x.decoder.DecodeFull(x.block)
		if err != nil {
			return fmt.Errorf("the server's header block does not decode: %w", err)
		}
		fields := make([]burpsyhttp2.HeaderField, len(decoded))
		for i, f := range decoded {
			fields[i] = burpsyhttp2.NewHeaderField(f.Name, f.Value)
		}
		return x.acceptBlock(fields)
	case burpsyhttp2.TypeData:
		if stream != 1 {
			return nil
		}
		data := payload
		if hdr.Flags&burpsyhttp2.FlagPadded != 0 && len(data) > 0 {
			pad := int(data[0])
			if pad < len(data) {
				data = data[1 : len(data)-pad]
			} else {
				data = nil
			}
		}
		if len(x.body)+len(data) > httputil.MaxResponseBodyBytes {
			x.ended = fmt.Sprintf("the response body passed the %d-byte cap and was cut there", httputil.MaxResponseBodyBytes)
			x.body = append(x.body, data[:httputil.MaxResponseBodyBytes-len(x.body)]...)
			return errH2FieldsDone
		}
		x.body = append(x.body, data...)
		if hdr.Flags&burpsyhttp2.FlagEndStream != 0 {
			x.ended = "the stream ended"
			return errH2FieldsDone
		}
	}
	return nil
}

// acceptBlock files a decoded header block as the response head, an interim head, or trailers.
func (x *h2FieldsExchange) acceptBlock(fields []burpsyhttp2.HeaderField) error {
	if x.status != 0 {
		x.trailers = fields
	} else {
		status := 0
		for _, f := range fields {
			if string(f.Name) == ":status" {
				status, _ = strconv.Atoi(string(f.Value))
				break
			}
		}
		if status == 0 {
			return errors.New("the server's response header block carries no :status")
		}
		if status >= 100 && status < 200 {
			// An interim head (§8.1): the final response follows on the same stream. Bounded the way the
			// HTTP/1 read bounds them (maxInterimResponses), so a peer cannot keep the stream busy forever.
			x.interim++
			if x.interim > maxInterimResponses {
				return fmt.Errorf("the server sent more than %d interim (1xx) heads without a final response", maxInterimResponses)
			}
			return nil
		}
		x.status, x.fields = status, fields
	}
	if x.blockEnd {
		x.ended = "the stream ended"
		return errH2FieldsDone
	}
	return nil
}

// pump writes as much of the request body as both flow-control windows allow, ending the stream with
// the last DATA frame.
func (x *h2FieldsExchange) pump() error {
	if !x.peerSettings {
		return nil
	}
	for len(x.pending) > 0 && x.connWindow > 0 && x.streamWindow > 0 {
		n := int64(len(x.pending))
		// Written out rather than the min builtin: a test file in this package declares its own
		// two-argument min, which shadows the builtin package-wide under go vet.
		for _, bound := range []int64{int64(x.maxFrame), x.connWindow, x.streamWindow} {
			if bound < n {
				n = bound
			}
		}
		chunk := x.pending[:n]
		x.pending = x.pending[n:]
		var flags uint8
		if len(x.pending) == 0 {
			flags = burpsyhttp2.FlagEndStream
		}
		if err := x.write(burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeData, flags, 1, chunk)); err != nil {
			return err
		}
		x.connWindow -= n
		x.streamWindow -= n
	}
	return nil
}

func (x *h2FieldsExchange) write(spec burpsyhttp2.FrameSpec) error {
	hdr := spec.Header().Encode()
	if _, err := x.conn.Write(append(hdr[:], spec.Payload...)); err != nil {
		return fmt.Errorf("writing to the server: %w", err)
	}
	return nil
}

// headersFragment cuts the header-block fragment out of a HEADERS payload (§6.2).
func headersFragment(flags uint8, payload []byte) ([]byte, bool) {
	if flags&burpsyhttp2.FlagPadded != 0 {
		if len(payload) == 0 {
			return nil, false
		}
		pad := int(payload[0])
		payload = payload[1:]
		if pad > len(payload) {
			return nil, false
		}
		payload = payload[:len(payload)-pad]
	}
	if flags&burpsyhttp2.FlagPriority != 0 {
		if len(payload) < 5 {
			return nil, false
		}
		payload = payload[5:]
	}
	return payload, true
}

func appendSetting(out []byte, id uint16, value uint32) []byte {
	out = binary.BigEndian.AppendUint16(out, id)
	return binary.BigEndian.AppendUint32(out, value)
}

func windowIncrement(n uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, n&0x7fff_ffff)
}

// h2ErrorName names an RFC 9113 §7 error code.
func h2ErrorName(code uint32) string {
	names := []string{
		"NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR", "SETTINGS_TIMEOUT",
		"STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM", "CANCEL", "COMPRESSION_ERROR",
		"CONNECT_ERROR", "ENHANCE_YOUR_CALM", "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED",
	}
	if int(code) < len(names) {
		return names[code]
	}
	return fmt.Sprintf("error code 0x%x", code)
}
