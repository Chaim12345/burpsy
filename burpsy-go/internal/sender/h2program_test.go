package sender

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/core"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
)

// programFor builds a decidable frame program addressing one path: the preface, a SETTINGS frame (which is
// what RFC 9113 §3.4 requires first), and one complete header block.
func programFor(authority, path string, readForMS uint64) burpsyhttp2.H2FrameProgram {
	enc := burpsyhttp2.NewEncoder(4096)
	block := enc.Encode([]burpsyhttp2.HeaderField{
		burpsyhttp2.NewHeaderField(":method", "GET"),
		burpsyhttp2.NewHeaderField(":scheme", "https"),
		burpsyhttp2.NewHeaderField(":authority", authority),
		burpsyhttp2.NewHeaderField(":path", path),
	})
	program := burpsyhttp2.NewH2FrameProgram(
		burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeSettings, 0, 0, nil),
		burpsyhttp2.NewFrameSpec(
			burpsyhttp2.TypeHeaders,
			burpsyhttp2.FlagEndHeaders|burpsyhttp2.FlagEndStream,
			1,
			block,
		),
	)
	program.ReadForMS = readForMS
	return program
}

// pathScope admits exactly one path prefix on one host, so an out-of-scope program is refused on scope
// grounds rather than on a dial failure.
func pathScope(host, prefix string) *core.Scope {
	sc := core.NewScope()
	sc.Add(core.NewScopeRuleWithPath(core.ScopeInclude, host, prefix))
	return sc
}

// H2-03: a cleanly decodable, in-scope program is sendable and reaches the target.
func TestSendFrameProgramReachesAnAuthorisedTarget(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	authority := formatHostPort(srv.host, srv.port)
	a := NewAuthorisedSender(pathScope(srv.host, "/allowed"), testSender(), srv.host, srv.port, true)

	res, err := a.SendFrameProgram(context.Background(), programFor(authority, "/allowed", 800))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Authorisation.Verdict != burpsyhttp2.VerdictAuthorisable {
		t.Fatalf("want an authorisable verdict, got %s", res.Authorisation.Explain())
	}
	if got := srv.served.Load(); got != 1 {
		t.Fatalf("the target served %d requests, want 1", got)
	}
	if got := srv.lastProto(t); got != "HTTP/2.0" {
		t.Fatalf("the program arrived as %s", got)
	}
	if res.Negotiated != alpn.H2 {
		t.Fatalf("negotiated %q, want h2", res.Negotiated)
	}
	if len(res.Sent) == 0 || !strings.HasPrefix(string(res.Sent), burpsyhttp2.ConnectionPreface) {
		t.Fatal("the octets written must begin with the client preface")
	}
	if len(res.Response) == 0 || len(res.ReplyFrames) == 0 {
		t.Fatalf("want frames back, got %d octets and %d frames", len(res.Response), len(res.ReplyFrames))
	}
	if res.ReadEnded == "" {
		t.Fatal("the result must say what ended the read")
	}
	if a.Sent() != 1 || a.Refused() != 0 {
		t.Fatalf("counters say sent=%d refused=%d", a.Sent(), a.Refused())
	}
}

// H2-03, the critical one: a program the peer would decode differently is refused, and the target receives
// nothing at all — not even a handshake.
func TestAnUndecidableProgramNeverReachesTheTarget(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	authority := formatHostPort(srv.host, srv.port)
	// core.NewScope with no rules admits everything, so scope cannot be what stops this.
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), testSender(), srv.host, srv.port, true)

	program := programFor(authority, "/allowed", 800)
	block := program.Frames[1].Payload
	program.Frames[1] = program.Frames[1].Malformed(burpsyhttp2.DeclareLength(uint32(len(block) - 4)))

	res, err := a.SendFrameProgram(context.Background(), program)
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), "declares") || !strings.Contains(err.Error(), "frames by the declared length") {
		t.Fatalf("the refusal must name the construct and why: %v", err)
	}
	if got := srv.served.Load(); got != 0 {
		t.Fatalf("the target served %d requests; a refused program must reach nothing", got)
	}
	if got := srv.hellos.Load(); got != 0 {
		t.Fatalf("the target saw %d TLS handshakes; a refused program must not dial", got)
	}
	if len(res.Sent) != 0 {
		t.Fatalf("nothing must be written, got %d octets", len(res.Sent))
	}
	if a.Sent() != 0 || a.Refused() != 1 {
		t.Fatalf("counters say sent=%d refused=%d", a.Sent(), a.Refused())
	}
	// The report is still returned, so a caller can show what was wrong with the program it wrote.
	if res.Authorisation.Verdict != burpsyhttp2.VerdictUndecidable || len(res.Authorisation.Refusals) == 0 {
		t.Fatalf("want the refusals carried on the result, got %+v", res.Authorisation)
	}
}

// H2-03: the same gate every other send passes. An out-of-scope path is refused before the dial.
func TestAnOutOfScopeProgramPathIsRefusedBeforeTheDial(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	authority := formatHostPort(srv.host, srv.port)
	a := NewAuthorisedSender(pathScope(srv.host, "/allowed"), testSender(), srv.host, srv.port, true)

	_, err := a.SendFrameProgram(context.Background(), programFor(authority, "/secret", 800))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("want a scope refusal, got %v", err)
	}
	if got := srv.hellos.Load(); got != 0 {
		t.Fatalf("the target saw %d handshakes", got)
	}
	if a.Refused() != 1 {
		t.Fatalf("refused=%d", a.Refused())
	}
}

// H2-03: an h2 intermediary routes on :authority, so a block naming another authority is checked against
// the scope as well as the connection.
func TestAProgramNamingAnotherAuthorityIsCheckedAgainstItToo(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	sc := core.NewScope()
	sc.AddInclude(srv.host)
	a := NewAuthorisedSender(sc, testSender(), srv.host, srv.port, true)

	_, err := a.SendFrameProgram(context.Background(), programFor("internal.test", "/allowed", 800))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("want a refusal naming the addressed authority, got %v", err)
	}
	if !strings.Contains(err.Error(), "internal.test") {
		t.Fatalf("the refusal must name the authority it refused: %v", err)
	}
	if got := srv.hellos.Load(); got != 0 {
		t.Fatalf("the target saw %d handshakes", got)
	}
}

// H2-03: a program that addresses no request gets the host-level decision, and it is a real decision.
func TestAConnectionOnlyProgramIsAuthorisedAtHostLevel(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	settingsOnly := burpsyhttp2.NewH2FrameProgram(
		burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeSettings, 0, 0, nil),
	)
	settingsOnly.ReadForMS = 400

	admitted := NewAuthorisedSender(core.NewScopeAllowEverything(), testSender(), srv.host, srv.port, true)
	res, err := admitted.SendFrameProgram(context.Background(), settingsOnly)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Authorisation.Verdict != burpsyhttp2.VerdictConnectionOnly {
		t.Fatalf("want a host-level verdict, got %s", res.Authorisation.Explain())
	}
	if len(res.Sent) == 0 {
		t.Fatal("the program should have been written")
	}

	excluded := core.NewScope()
	excluded.AddExclude(srv.host)
	refused := NewAuthorisedSender(excluded, testSender(), srv.host, srv.port, true)
	_, err = refused.SendFrameProgram(context.Background(), settingsOnly)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("want a host-level refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), "addresses no request") {
		t.Fatalf("the refusal must say which decision it could not get: %v", err)
	}
}

// pathOnlyScope answers the per-request question and nothing else, standing in for a scope handle that
// does not implement the host-level one.
type pathOnlyScope struct{}

func (pathOnlyScope) AuthoriseRaw(string, uint16, bool, []byte) error { return nil }

// H2-03: a question that cannot be asked is a refusal, never a pass.
func TestAConnectionOnlyProgramIsRefusedWhenTheHostQuestionCannotBeAsked(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	settingsOnly := burpsyhttp2.NewH2FrameProgram(
		burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeSettings, 0, 0, nil),
	)
	settingsOnly.ReadForMS = 100
	a := NewAuthorisedSender(pathOnlyScope{}, testSender(), srv.host, srv.port, true)

	_, err := a.SendFrameProgram(context.Background(), settingsOnly)
	if err == nil || !strings.Contains(err.Error(), "cannot answer") {
		t.Fatalf("want a refusal naming the missing question, got %v", err)
	}
	if got := srv.hellos.Load(); got != 0 {
		t.Fatalf("the target saw %d handshakes", got)
	}
}

// H2-03: a deliberately illegal but decidable program sends. This is the capability, not just the guard.
func TestADeliberatelyIllegalProgramStillSends(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	authority := formatHostPort(srv.host, srv.port)
	program := programFor(authority, "/allowed", 600)
	// The reserved bit set on the HEADERS frame: a sender must leave it clear (§5.1.1), the peer must ignore
	// it, and neither half changes which octets the block is.
	program.Frames[1] = program.Frames[1].Malformed(burpsyhttp2.SetReservedBit())
	a := NewAuthorisedSender(pathScope(srv.host, "/allowed"), testSender(), srv.host, srv.port, true)

	res, err := a.SendFrameProgram(context.Background(), program)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(res.Violations) == 0 {
		t.Fatal("this program is supposed to break a rule; Audit found none")
	}
	if got := srv.served.Load(); got != 1 {
		t.Fatalf("the target served %d requests, want 1", got)
	}
}

// H2-03: a target that will not negotiate h2 is told about, rather than failing in the TLS layer.
func TestAFrameProgramAtAnHTTP11TargetSaysSo(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.HTTP11}, false)
	authority := formatHostPort(srv.host, srv.port)
	s := testSender()
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), s, srv.host, srv.port, true)

	_, err := a.SendFrameProgram(context.Background(), programFor(authority, "/allowed", 200))
	if err == nil {
		t.Fatal("want an error naming the negotiation")
	}
	if !strings.Contains(err.Error(), "http/1.1") || !strings.Contains(err.Error(), "no HTTP/1.1 form") {
		t.Fatalf("the error must say what was negotiated and why that is fatal here: %v", err)
	}
	// The handshake still taught the cache something true.
	if got := s.KnownProtocol(srv.host, srv.port, true); got != ProtocolSupportHTTP11 {
		t.Fatalf("want the authority learnt as http/1.1, got %v", got)
	}
}

// H2-03: cleartext prior-knowledge h2c is allowed here, because a program carries its own preface. The
// request path takes the opposite decision, and protocol.go says why.
func TestAFrameProgramOverCleartextUsesPriorKnowledge(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	var conns atomic.Int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				mu.Lock()
				got = append(got, buf[:n]...)
				mu.Unlock()
				// A GOAWAY-shaped reply is enough: the claim is that the octets arrived on a cleartext
				// connection and that what came back is returned as frames.
				c.Write([]byte{0, 0, 8, 0x7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1})
			}(conn)
		}
	}()
	host, port, err := hostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("listener address: %v", err)
	}
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), testSender(), host, port, false)

	res, err := a.SendFrameProgram(context.Background(), programFor(host, "/allowed", 300))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Negotiated != "" {
		t.Fatalf("cleartext negotiates nothing, got %q", res.Negotiated)
	}
	mu.Lock()
	received := string(got)
	mu.Unlock()
	if !strings.HasPrefix(received, burpsyhttp2.ConnectionPreface) {
		t.Fatalf("the peer did not receive the preface: %q", received)
	}
	if len(res.ReplyFrames) != 1 || res.ReplyFrames[0].Header.Type != burpsyhttp2.TypeGoAway {
		t.Fatalf("want the reply parsed as one GOAWAY, got %+v", res.ReplyFrames)
	}
	if conns.Load() != 1 {
		t.Fatalf("want one connection, got %d", conns.Load())
	}
}

// A program asking for no read window gets none, and says that is what happened rather than looking like a
// peer that answered nothing.
func TestAZeroReadWindowIsReportedAsSuch(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.H2}, true)
	authority := formatHostPort(srv.host, srv.port)
	program := programFor(authority, "/allowed", 0)
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), testSender(), srv.host, srv.port, true)

	res, err := a.SendFrameProgram(context.Background(), program)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(res.Response) != 0 {
		t.Fatalf("want nothing read, got %d octets", len(res.Response))
	}
	if !strings.Contains(res.ReadEnded, "no read window") {
		t.Fatalf("want the zero window named, got %q", res.ReadEnded)
	}
}
