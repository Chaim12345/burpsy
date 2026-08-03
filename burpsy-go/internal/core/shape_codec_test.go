package core

import (
	"reflect"
	"testing"
)

// A persisted shape must come back exactly, because every span in the message is
// resolved through it. This is the round trip a restore depends on.
func TestAShapeSurvivesEncodingExactly(t *testing.T) {
	raw := []byte("POST /a/b?c=d HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n" +
		"X-Long-Header-Name: some rather longer value here\r\n\r\nhello")
	want, err := Parse(raw, DirectionRequest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got, err := DecodeShape(EncodeShape(want))
	if err != nil {
		t.Fatalf("DecodeShape: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shape did not survive the round trip:\n got %+v\nwant %+v", got, want)
	}

	// The decoded shape must resolve the same bytes as the parsed one.
	decoded := &StoredMessage{ID: 0, Shape: got, resident: raw}
	if h := string(decoded.Header("content-length")); h != "5" {
		t.Errorf("Header(content-length) via the decoded shape = %q, want %q", h, "5")
	}
	if b := string(decoded.Body()); b != "hello" {
		t.Errorf("Body() via the decoded shape = %q, want %q", b, "hello")
	}
}

// A response shape carries its direction, which decides how the three start-line
// tokens are read. Losing it would make a response parse as a request.
func TestAResponseShapeKeepsItsDirection(t *testing.T) {
	raw := []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	want, err := Parse(raw, DirectionResponse)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := DecodeShape(EncodeShape(want))
	if err != nil {
		t.Fatalf("DecodeShape: %v", err)
	}
	if got.Direction != DirectionResponse {
		t.Errorf("direction = %v, want DirectionResponse", got.Direction)
	}
	decoded := &StoredMessage{Shape: got, resident: raw}
	if tok := decoded.Text(got.SecondToken); tok != "404" {
		t.Errorf("status token = %q, want %q", tok, "404")
	}
}

// A message with no headers at all must encode and decode as such, rather than
// as a shape with one empty header.
func TestAShapeWithNoHeadersRoundTrips(t *testing.T) {
	got, err := DecodeShape(EncodeShape(MessageShape{Direction: DirectionRequest}))
	if err != nil {
		t.Fatalf("DecodeShape: %v", err)
	}
	if len(got.Headers) != 0 {
		t.Errorf("headers = %d, want 0", len(got.Headers))
	}
}

// A truncated or padded encoding must be refused. A half-decoded shape would not
// fail loudly: it would resolve headers to the wrong bytes, which is the silent
// mis-resolution the span model exists to rule out.
func TestACorruptShapeIsRefusedRatherThanPartlyDecoded(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: a.test\r\nAccept: */*\r\n\r\n")
	shape, err := Parse(raw, DirectionRequest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	full := EncodeShape(shape)

	for _, cut := range []int{1, len(full) / 2, len(full) - 1} {
		if _, err := DecodeShape(full[:cut]); err == nil {
			t.Errorf("DecodeShape accepted a buffer truncated to %d of %d bytes", cut, len(full))
		}
	}
	if _, err := DecodeShape(append(append([]byte{}, full...), 0x00)); err == nil {
		t.Error("DecodeShape accepted trailing bytes after a complete shape")
	}
	if _, err := DecodeShape(nil); err == nil {
		t.Error("DecodeShape accepted an empty buffer")
	}
	// A header count far larger than the buffer could hold must be refused
	// before it is used to size an allocation.
	if _, err := DecodeShape([]byte{0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f}); err == nil {
		t.Error("DecodeShape accepted an impossible header count")
	}
}
