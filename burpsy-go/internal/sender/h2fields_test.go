package sender

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/alpn"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/http2/h2test"
)

// kettledFields is a request no compliant client would send: an uppercase name and a header whose value
// carries CR LF followed by something shaped like another header.
func kettledFields(authority, path string) []burpsyhttp2.HeaderField {
	return []burpsyhttp2.HeaderField{
		burpsyhttp2.NewHeaderField(":method", "POST"),
		burpsyhttp2.NewHeaderField(":scheme", "https"),
		burpsyhttp2.NewHeaderField(":authority", authority),
		burpsyhttp2.NewHeaderField(":path", path),
		burpsyhttp2.NewHeaderField("X-Upper", "1"),
		burpsyhttp2.NewHeaderField("x-inject", "a\r\nTransfer-Encoding: chunked"),
	}
}

// jae5: the field list reaches the origin as one HPACK header list, the CR LF inside one field's value
// and the casing intact, and the response comes back rendered.
func TestSendH2FieldsPutsCRLFOnTheWireInOneField(t *testing.T) {
	srv := h2test.Start(t, h2test.Options{ResponseBody: []byte("pong")})
	authority := formatHostPort(srv.Host, srv.Port)
	a := NewAuthorisedSender(pathScope(srv.Host, "/allowed"), testSender(), srv.Host, srv.Port, true)
	fields := kettledFields(authority, "/allowed")

	res, err := a.SendH2Fields(context.Background(), fields, []byte("body"))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	got := srv.Requests()
	if len(got) != 1 {
		t.Fatalf("the origin decoded %d requests, want 1", len(got))
	}
	if !burpsyhttp2.HeaderFieldsEqual(got[0].Fields, fields) {
		t.Fatalf("the origin decoded %q, want exactly %q", got[0].Fields, fields)
	}
	if string(got[0].Body) != "body" {
		t.Fatalf("the origin read body %q", got[0].Body)
	}
	if res.Status != 200 || string(res.Body) != "pong" {
		t.Fatalf("got status %d body %q", res.Status, res.Body)
	}
	if !strings.HasPrefix(string(res.Response), "HTTP/2 200\r\n") || !strings.HasSuffix(string(res.Response), "\r\n\r\npong") {
		t.Fatalf("the rendering is not the h2 response shape: %q", res.Response)
	}
	if !strings.Contains(string(res.Response), "x-fields-seen: 6\r\n") {
		t.Fatalf("the response headers did not survive rendering: %q", res.Response)
	}
	if res.Ended != "the stream ended" || res.Negotiated != alpn.H2 {
		t.Fatalf("ended %q, negotiated %q", res.Ended, res.Negotiated)
	}
	if a.Sent() != 1 || a.Refused() != 0 {
		t.Fatalf("counters say sent=%d refused=%d", a.Sent(), a.Refused())
	}
}

// A body larger than the window the origin grants must be paced by its WINDOW_UPDATEs, not written
// whole, and must still arrive byte for byte.
func TestSendH2FieldsHonoursFlowControl(t *testing.T) {
	srv := h2test.Start(t, h2test.Options{InitialWindow: 1000})
	a := NewAuthorisedSender(pathScope(srv.Host, "/"), testSender(), srv.Host, srv.Port, true)
	body := bytes.Repeat([]byte("0123456789abcdef"), 12_000) // 192000 bytes, several windows' worth

	if _, err := a.SendH2Fields(context.Background(), kettledFields(formatHostPort(srv.Host, srv.Port), "/"), body); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := srv.Requests()
	if len(got) != 1 || got[0].FlowViolation {
		t.Fatalf("the origin saw a flow-control overrun (requests %d)", len(got))
	}
	if !bytes.Equal(got[0].Body, body) {
		t.Fatalf("the body arrived as %d bytes, want %d intact", len(got[0].Body), len(body))
	}
}

// An origin that waits for the SETTINGS ACK and a PING answer before responding is answered — the two
// things the write-then-read frame-program path never does.
func TestSendH2FieldsAcknowledgesSettingsAndPing(t *testing.T) {
	srv := h2test.Start(t, h2test.Options{RequireSettingsAck: true, Ping: true})
	a := NewAuthorisedSender(pathScope(srv.Host, "/"), testSender(), srv.Host, srv.Port, true)
	res, err := a.SendH2Fields(context.Background(), kettledFields(formatHostPort(srv.Host, srv.Port), "/"), nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("status %d", res.Status)
	}
}

// A reset is the answer, named — never an empty response.
func TestSendH2FieldsNamesAReset(t *testing.T) {
	srv := h2test.Start(t, h2test.Options{Reset: true})
	a := NewAuthorisedSender(pathScope(srv.Host, "/"), testSender(), srv.Host, srv.Port, true)
	res, err := a.SendH2Fields(context.Background(), kettledFields(formatHostPort(srv.Host, srv.Port), "/"), nil)
	if err == nil || !strings.Contains(err.Error(), "reset the stream (PROTOCOL_ERROR)") {
		t.Fatalf("want the reset named, got %v", err)
	}
	if len(res.Response) != 0 {
		t.Fatalf("a reset stream rendered a response: %q", res.Response)
	}
}

// An h1-only target is refused by name: a kettled request has no HTTP/1.1 form.
func TestSendH2FieldsRefusesAnHTTP11Target(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.HTTP11}, false)
	a := NewAuthorisedSender(pathScope(srv.host, "/"), testSender(), srv.host, srv.port, true)
	_, err := a.SendH2Fields(context.Background(), kettledFields(formatHostPort(srv.host, srv.port), "/"), nil)
	if err == nil || !strings.Contains(err.Error(), `negotiated "http/1.1"`) {
		t.Fatalf("want the HTTP/1.1 negotiation named, got %v", err)
	}
	if srv.served.Load() != 0 {
		t.Fatal("an HTTP/1.1 target was sent a request")
	}
}

// The classifier's refusals stop a kettled list before anything is dialled: a space in :path, and a path
// outside the scope.
func TestSendH2FieldsIsRefusedBeforeTheDial(t *testing.T) {
	srv := h2test.Start(t, h2test.Options{})
	authority := formatHostPort(srv.Host, srv.Port)
	for name, fields := range map[string][]burpsyhttp2.HeaderField{
		"space in :path": kettledFields(authority, "/allowed /x"),
		"out of scope":   kettledFields(authority, "/elsewhere"),
	} {
		t.Run(name, func(t *testing.T) {
			a := NewAuthorisedSender(pathScope(srv.Host, "/allowed"), testSender(), srv.Host, srv.Port, true)
			_, err := a.SendH2Fields(context.Background(), fields, nil)
			if err == nil || !strings.HasPrefix(err.Error(), "refused: ") {
				t.Fatalf("want a refusal, got %v", err)
			}
			if a.Refused() != 1 || a.Sent() != 0 {
				t.Fatalf("counters say sent=%d refused=%d", a.Sent(), a.Refused())
			}
		})
	}
	if srv.Accepted.Load() != 0 {
		t.Fatalf("a refused list reached the origin (%d connections)", srv.Accepted.Load())
	}
}

// A header block larger than one frame goes out as HEADERS plus CONTINUATION and decodes whole.
func TestSendH2FieldsSplitsALargeBlock(t *testing.T) {
	srv := h2test.Start(t, h2test.Options{})
	a := NewAuthorisedSender(pathScope(srv.Host, "/"), testSender(), srv.Host, srv.Port, true)
	fields := append(kettledFields(formatHostPort(srv.Host, srv.Port), "/"),
		burpsyhttp2.NewHeaderField("x-big", strings.Repeat("v", 40_000)))
	if _, err := a.SendH2Fields(context.Background(), fields, nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := srv.Requests(); len(got) != 1 || !burpsyhttp2.HeaderFieldsEqual(got[0].Fields, fields) {
		t.Fatal("the split block did not decode to the list written")
	}
}

// Interop with a compliant server: net/http's own HTTP/2 server answers a list it accepts, so the
// exchange (preface, SETTINGS, ACKs, flow control) is not only right against this package's test origin.
func TestSendH2FieldsInteroperatesWithNetHTTP(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	authority := formatHostPort(srv.host, srv.port)
	a := NewAuthorisedSender(pathScope(srv.host, "/"), testSender(), srv.host, srv.port, true)
	fields := []burpsyhttp2.HeaderField{
		burpsyhttp2.NewHeaderField(":method", "POST"),
		burpsyhttp2.NewHeaderField(":scheme", "https"),
		burpsyhttp2.NewHeaderField(":authority", authority),
		burpsyhttp2.NewHeaderField(":path", "/"),
		burpsyhttp2.NewHeaderField("x-plain", "1"),
	}
	res, err := a.SendH2Fields(context.Background(), fields, bytes.Repeat([]byte("x"), 100_000))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Status != 200 || string(res.Body) != "ok" || srv.lastProto(t) != "HTTP/2.0" {
		t.Fatalf("status %d body %q", res.Status, res.Body)
	}
}
