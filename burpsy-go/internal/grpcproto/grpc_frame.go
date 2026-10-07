package grpcproto

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// gRPC length-prefixed framing (burpsy-react-ui-3x2g). A gRPC message body is one or more frames,
// each a 1-byte compression flag, a 4-byte big-endian length, and that many message bytes:
//
//	+--------+----------------+==================+
//	| flag(1)| length(4, BE)  | message (length) |
//	+--------+----------------+==================+
//
// gRPC-web over HTTP/1 uses the same framing (plus a trailer frame with the high bit of the flag
// set), which is why recognising it in the proxy is what makes a gRPC-web body readable in history
// and Repeater, not only a raw HTTP/2 DATA frame.

// Frame is one gRPC message frame. Compressed is the flag's low bit; a compressed frame's message is
// not a protobuf message until it is inflated, which this package does not do — it is surfaced so the
// editor can say "compressed" rather than present nonsense.
type Frame struct {
	Compressed bool
	// Trailer marks the gRPC-web trailer frame (flag bit 0x80): its "message" is a block of HTTP
	// trailer headers, not protobuf, so the editor shows it as text.
	Trailer bool
	Message []byte
}

// IsGRPCContentType reports whether a Content-Type names gRPC, so a caller can decide to unframe
// before decoding. Covers application/grpc, application/grpc+proto and the grpc-web spellings.
func IsGRPCContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/grpc", "application/grpc+proto", "application/grpc-web",
		"application/grpc-web+proto", "application/grpc-web-text":
		return true
	}
	return strings.HasPrefix(ct, "application/grpc")
}

// IsProtobufContentType reports whether a Content-Type names bare protobuf (not gRPC-framed).
func IsProtobufContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/protobuf", "application/x-protobuf", "application/vnd.google.protobuf":
		return true
	}
	return false
}

// Unframe splits a gRPC body into its frames. It returns an error on a frame whose declared length
// runs past the body, so a truncated capture is reported rather than decoded into a wrong field tree.
func Unframe(body []byte) ([]Frame, error) {
	var frames []Frame
	i := 0
	for i < len(body) {
		if i+5 > len(body) {
			return nil, fmt.Errorf("grpc: truncated frame header at offset %d", i)
		}
		flag := body[i]
		length := int(binary.BigEndian.Uint32(body[i+1 : i+5]))
		start := i + 5
		end := start + length
		if length < 0 || end > len(body) || end < start {
			return nil, fmt.Errorf("grpc: frame at offset %d declares %d bytes past the body", i, length)
		}
		frames = append(frames, Frame{
			Compressed: flag&0x01 != 0,
			Trailer:    flag&0x80 != 0,
			Message:    body[start:end],
		})
		i = end
	}
	return frames, nil
}

// Frame renders one message as a single uncompressed gRPC frame.
func FrameMessage(message []byte) []byte {
	out := make([]byte, 5+len(message))
	out[0] = 0
	binary.BigEndian.PutUint32(out[1:5], uint32(len(message)))
	copy(out[5:], message)
	return out
}

// Reframe renders several frames back into a gRPC body, preserving each frame's flag bits.
func Reframe(frames []Frame) []byte {
	var out []byte
	for _, f := range frames {
		var flag byte
		if f.Compressed {
			flag |= 0x01
		}
		if f.Trailer {
			flag |= 0x80
		}
		header := make([]byte, 5)
		header[0] = flag
		binary.BigEndian.PutUint32(header[1:5], uint32(len(f.Message)))
		out = append(out, header...)
		out = append(out, f.Message...)
	}
	return out
}
