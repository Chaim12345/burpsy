package scanner

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// frameProgramResult is one sent program's result, in the shape SendFrameProgram returns. Built here rather
// than by sending, because the claim under test is the attribution and the envelope, and internal/sender
// already proves the octets reach a real h2 server.
func frameProgramResult(t *testing.T, path string, reply []byte, readEnded string) sender.FrameProgramResult {
	t.Helper()
	enc := http2.NewEncoder(4096)
	block := enc.Encode([]http2.HeaderField{
		http2.NewHeaderField(":method", "GET"),
		http2.NewHeaderField(":scheme", "https"),
		http2.NewHeaderField(":authority", "shop.test"),
		http2.NewHeaderField(":path", path),
	})
	program := http2.NewH2FrameProgram(
		http2.NewFrameSpec(http2.TypeSettings, 0, 0, nil),
		// An even client-initiated stream id: a deliberate §5.1.1 violation, so the recorded row has
		// violations to report.
		http2.NewFrameSpec(http2.TypeHeaders, http2.FlagEndHeaders|http2.FlagEndStream, 2, block),
	)
	frames, tail := http2.ReadFrames(reply)
	return sender.FrameProgramResult{
		Host:          "shop.test",
		Port:          443,
		TLS:           true,
		Program:       program,
		Authorisation: http2.Authorise(program),
		Violations:    http2.Audit(program),
		Sent:          program.Encode(),
		Response:      reply,
		ReplyFrames:   frames,
		ReplyTail:     tail,
		Negotiated:    "h2",
		Started:       time.Now().Add(-20 * time.Millisecond),
		Duration:      20 * time.Millisecond,
		ReadEnded:     readEnded,
	}
}

// H2-03: a frame program's capture goes through the one capture path, attributed and labelled.
func TestRecordFrameProgramGoesThroughTheOneCapturePath(t *testing.T) {
	store := core.NewTrafficStore()
	capture := Capture{Store: store}
	// A GOAWAY, which is a plausible answer to a deliberately malformed program.
	reply := []byte{0, 0, 8, 0x7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1}
	res := frameProgramResult(t, "/allowed", reply, "the read window closed")

	ex, err := capture.RecordFrameProgram(res)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if ex.Source != core.SourceRepeater {
		t.Fatalf("want the row attributed, got %q", ex.Source)
	}
	if !ex.Source.Attributed() {
		t.Fatal("a frame program must never be recorded unattributed")
	}
	if ex.Protocol != core.ProtocolHTTP2 {
		t.Fatalf("want HTTP/2, got %v", ex.Protocol)
	}
	if ex.Method != FrameProgramMethod || ex.Path != "/allowed" {
		t.Fatalf("want the program labelled and placed, got %s %s", ex.Method, ex.Path)
	}
	if ex.Status != nil {
		t.Fatalf("a frame program has no status; got %d", *ex.Status)
	}
	if ex.Notes == nil {
		t.Fatal("the row must say that its bytes are frames")
	}
	for _, want := range []string{"frame program", "2 frames sent", "the read window closed"} {
		if !strings.Contains(*ex.Notes, want) {
			t.Fatalf("notes %q does not mention %q", *ex.Notes, want)
		}
	}
	if !strings.Contains(*ex.Notes, "deliberate violations") {
		t.Fatalf("notes %q does not report the violations", *ex.Notes)
	}

	// The stored request holds the program's exact octets as its body, so nothing was re-encoded on the way
	// into history.
	req, err := store.Get(ex.Request)
	if err != nil {
		t.Fatalf("reading the stored request: %v", err)
	}
	if !bytes.Equal(req.Body(), res.Sent) {
		t.Fatalf("the stored body is not the octets sent (%d vs %d bytes)", len(req.Body()), len(res.Sent))
	}
	if got := string(req.Raw()); !strings.HasPrefix(got, FrameProgramMethod+" /allowed HTTP/2\r\n") {
		t.Fatalf("the envelope must label itself: %q", firstLine(got))
	}
	if got := string(req.Header("X-Burpsy-Alpn")); got != "h2" {
		t.Fatalf("want the negotiated protocol recorded, got %q", got)
	}

	resp, err := store.Get(*ex.Response)
	if err != nil {
		t.Fatalf("reading the stored reply: %v", err)
	}
	if !bytes.Equal(resp.Body(), reply) {
		t.Fatalf("the stored reply body is not the octets received")
	}
	if got := string(resp.Header("X-Burpsy-Read-Ended")); got != "the read window closed" {
		t.Fatalf("want the read outcome recorded, got %q", got)
	}
	if len(store.Exchanges()) != 1 {
		t.Fatalf("want one indexed exchange, got %d", len(store.Exchanges()))
	}
}

// A peer that answered nothing is a result, and is recorded as one: an empty reply body, and the reason the
// read stopped.
func TestAProgramThatDrewNoReplyIsStillRecorded(t *testing.T) {
	store := core.NewTrafficStore()
	capture := Capture{Store: store}
	res := frameProgramResult(t, "/allowed", nil, "the peer closed the connection")

	ex, err := capture.RecordFrameProgram(res)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	resp, err := store.Get(*ex.Response)
	if err != nil {
		t.Fatalf("reading the stored reply: %v", err)
	}
	if len(resp.Body()) != 0 {
		t.Fatalf("nothing arrived, so nothing must be invented: %q", resp.Body())
	}
	if got := string(resp.Header("X-Burpsy-Read-Ended")); got != "the peer closed the connection" {
		t.Fatalf("want the silence explained, got %q", got)
	}
	if got := string(resp.Header("X-Burpsy-Frames")); got != "0" {
		t.Fatalf("want zero frames reported, got %q", got)
	}
}

// A program that was refused or never dialled has no bytes at all, and must not become an indexed row —
// that is the invariant Record's ErrNoResponse protects.
func TestARefusedProgramIsNotIndexed(t *testing.T) {
	store := core.NewTrafficStore()
	capture := Capture{Store: store}
	res := frameProgramResult(t, "/allowed", nil, "")
	res.Sent = nil

	_, err := capture.RecordFrameProgram(res)
	if !errors.Is(err, ErrNoResponse) {
		t.Fatalf("want ErrNoResponse, got %v", err)
	}
	if len(store.Exchanges()) != 0 {
		t.Fatalf("want nothing indexed, got %d exchanges", len(store.Exchanges()))
	}
}

// A program that addresses no request is recorded at a token that cannot be read as a path.
func TestAConnectionOnlyProgramIsRecordedWithoutInventingAPath(t *testing.T) {
	store := core.NewTrafficStore()
	capture := Capture{Store: store}
	program := http2.NewH2FrameProgram(http2.NewFrameSpec(http2.TypeSettings, 0, 0, nil))
	res := sender.FrameProgramResult{
		Host:          "shop.test",
		Port:          443,
		TLS:           true,
		Program:       program,
		Authorisation: http2.Authorise(program),
		Sent:          program.Encode(),
		Started:       time.Now(),
		ReadEnded:     "the read window closed",
	}

	ex, err := capture.RecordFrameProgram(res)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if ex.Path != FrameProgramNoPath {
		t.Fatalf("want %q, got %q", FrameProgramNoPath, ex.Path)
	}
	if !strings.Contains(*ex.Notes, "host level only") {
		t.Fatalf("the row must say which decision authorised it: %q", *ex.Notes)
	}
	req, err := store.Get(ex.Request)
	if err != nil {
		t.Fatalf("reading the stored request: %v", err)
	}
	if got := string(req.Header("X-Burpsy-Requests-Authorised")); got != "0" {
		t.Fatalf("want zero addressed requests reported, got %q", got)
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
