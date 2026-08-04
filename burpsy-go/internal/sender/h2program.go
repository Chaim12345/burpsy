package sender

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
)

// The send path for a deliberately malformed HTTP/2 frame program (H2-03).
//
// # Why this could not exist until the classifier did
//
// internal/http2 could build a spec-illegal frame program and name every rule it broke since the frame
// layer landed, and deliberately had no route to a socket. The obstacle was authorisation, not
// transport: a program with a dishonest length or an unterminated header block cannot have its `:path`
// fields authorised individually, because the peer will not decode the block we decoded. That is
// http2.Authorise's subject, and this file is what it unblocks — it adds a transport and nothing else to
// the authorisation story. Every refusal here comes from the classifier by name; none of them is
// invented at this layer.
//
// # The gate is the same gate
//
// A frame program goes through AuthorisedSender, which is the one chokepoint every egress passes
// (HARD-03), and every request the program addresses is checked individually against the same
// ScopeChecker every ordinary send uses. There is no bypass, no override and no "advanced" flag — see
// http2/authorise.go on why an override would be a waiver of the tool's ability to *know* rather than a
// waiver of a rule.
//
// Two checks per addressed request, not one. The dialled authority is checked because that is where the
// octets go; the block's own `:authority` is checked as well when it names one, because an h2
// intermediary routes on `:authority` and not on the connection it arrived over. A program that reaches
// an in-scope front end carrying an out-of-scope `:authority` is asking that front end to fetch
// something the engagement never agreed to, and only the second check sees it.
//
// # h2c is allowed here, and is not allowed on the request path
//
// protocol.go refuses to guess h2c for an ordinary request: a plaintext target has no ALPN, RFC 9113
// deleted the Upgrade: h2c dance, and writing an h2 preface at an HTTP/1.1 server produces a 400 that
// reads like a finding.
//
// A frame program is the one case where that argument does not hold, because a program *carries its own
// preface*. Writing the preface and then frames on a cleartext connection is exactly RFC 9113 §3.3
// prior-knowledge h2c — there is nothing to negotiate and nothing being guessed at. Refusing it would
// remove the only well-defined h2c case in the tool while claiming caution. So a cleartext frame program
// sends, and a cleartext *request* still does not.
//
// # What comes back is octets
//
// A program's reply is not an HTTP response and is not turned into one. The raw bytes are returned, plus
// ReadFrames' parse of them and the Tail it could not complete — a peer that died mid-frame is
// frequently the result a probe was looking for, so the leftover is reported rather than dropped.

// HostScopeChecker is the host-level scope question, which a program addressing no request needs.
//
// A separate, optional interface rather than a method added to ScopeChecker: both core.Scope and
// core.SharedScope already implement it, and widening ScopeChecker would break every other
// implementation — including the fakes in tests, which is how a widened interface quietly becomes a
// mock's opinion rather than the scope's. A handle that does not implement it cannot be asked, and a
// question that cannot be asked is a refusal, never a pass.
type HostScopeChecker interface {
	MayContainHost(host string, port uint16, tls bool) bool
}

// FrameProgramResult is one frame program's send: what was authorised, what went out, and what came
// back.
type FrameProgramResult struct {
	Host string
	Port uint16
	TLS  bool
	// Program is what was classified, whether or not it was sent. Carried so a refusal can be shown
	// against the program that earned it without the caller having to keep its own copy alongside the
	// result.
	Program burpsyhttp2.H2FrameProgram
	// Authorisation is what the classifier concluded, carried even on success so a caller can show which
	// requests it authorised rather than asserting that it did.
	Authorisation burpsyhttp2.Authorisation
	// Violations is Audit's report on the program that was sent. Reported, never enforced: breaking rules
	// on purpose is the point, and a program with twenty violations sends exactly as readily as one with
	// none, provided every one of them is decidable.
	Violations []burpsyhttp2.Violation
	// Sent is the octets written, preface included — the exact bytes, so a capture holds what went on the
	// wire rather than a re-encoding of it.
	Sent []byte
	// Response is whatever came back within the program's read window, verbatim. Empty is a real result:
	// a peer that answered nothing answered nothing.
	Response []byte
	// ReplyFrames is ReadFrames' parse of Response, and ReplyTail what it could not turn into a whole
	// frame. Named for the reply rather than "Frames", because Program.Frames is the other set of frames in
	// this struct and a reader must never have to guess which one a field means.
	ReplyFrames []burpsyhttp2.RawFrame
	ReplyTail   burpsyhttp2.Tail
	// ReadEnded says what stopped the read: the window closing, the peer closing, or a read error. Empty
	// only when nothing was written, because a program that was refused never read anything.
	ReadEnded string
	// Negotiated is the ALPN value the handshake settled on; "" for a cleartext prior-knowledge send,
	// which negotiates nothing.
	Negotiated string
	Started    time.Time
	Duration   time.Duration
}

// SendFrameProgram authorises a frame program and, if every request it addresses is in scope, puts its
// octets on a fresh connection and reads the reply.
//
// The order is the whole point: classify, authorise, dial, write. Nothing dials before the scope has
// agreed — a refused program leaves no trace on the target, not even a handshake — and nothing here can
// authorise a request the classifier could not name.
func (a *AuthorisedSender) SendFrameProgram(
	ctx context.Context,
	program burpsyhttp2.H2FrameProgram,
) (FrameProgramResult, error) {
	res := FrameProgramResult{
		Host:          a.host,
		Port:          a.port,
		TLS:           a.tls,
		Program:       program,
		Authorisation: burpsyhttp2.Authorise(program),
		Violations:    burpsyhttp2.Audit(program),
	}

	switch res.Authorisation.Verdict {
	case burpsyhttp2.VerdictUndecidable:
		a.refused.Add(1)
		return res, fmt.Errorf("refused: this frame program is %s", res.Authorisation.Explain())
	case burpsyhttp2.VerdictConnectionOnly:
		if err := a.authoriseHostOnly(); err != nil {
			a.refused.Add(1)
			return res, err
		}
	case burpsyhttp2.VerdictAuthorisable:
		for _, req := range res.Authorisation.Requests {
			if err := a.authoriseProgramRequest(req); err != nil {
				a.refused.Add(1)
				return res, err
			}
		}
	default:
		// A verdict this build does not know how to act on is a refusal, not a pass. The alternative — a
		// default that sends — would mean a verdict added later reaches the wire before anyone teaches this
		// switch what it means.
		a.refused.Add(1)
		return res, fmt.Errorf("refused: this build cannot act on verdict %d", int(res.Authorisation.Verdict))
	}

	conn, negotiated, err := a.dialForProgram(ctx)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	res.Negotiated = negotiated

	res.Sent = program.Encode()
	res.Started = time.Now()
	a.net.setDeadline(ctx, conn)
	if _, err := conn.Write(res.Sent); err != nil {
		res.Duration = time.Since(res.Started)
		return res, fmt.Errorf("writing the frame program: %w", err)
	}
	a.sent.Add(1)
	res.Response, res.ReadEnded = readForWindow(conn, program.ReadForMS)
	res.Duration = time.Since(res.Started)
	res.ReplyFrames, res.ReplyTail = burpsyhttp2.ReadFrames(res.Response)
	return res, nil
}

// authoriseHostOnly asks the host-level question for a program that addresses no request.
func (a *AuthorisedSender) authoriseHostOnly() error {
	hostScope, ok := a.scope.(HostScopeChecker)
	if !ok {
		return fmt.Errorf("refused: this program addresses no request, so only a host-level scope "+
			"decision is available, and this scope handle (%T) cannot answer one", a.scope)
	}
	if !hostScope.MayContainHost(a.host, a.port, a.tls) {
		return fmt.Errorf("refused: this program addresses no request, and the engagement scope admits "+
			"no path at all on %s", formatAuthority(a.host, a.port, a.tls))
	}
	return nil
}

// authoriseProgramRequest runs one addressed request through the same scope gate an ordinary send uses,
// for the dialled authority and — when the block names one — for the authority the block itself
// addresses.
func (a *AuthorisedSender) authoriseProgramRequest(req burpsyhttp2.ProgramRequest) error {
	raw := burpsyhttp2.RenderRequest(req.Method, req.Path, req.Authority, nil, nil)
	if err := a.scope.AuthoriseRaw(a.host, a.port, a.tls, raw); err != nil {
		return fmt.Errorf("refused: frame %d's request: %w", req.Frame, err)
	}
	if req.Authority == "" {
		// No `:authority`, so the request addresses the connection's own authority and the check above was
		// the whole question. http2.ProgramRequest documents why that is decidable rather than refused.
		return nil
	}
	host, port, isTLS, err := authorityOf(a.programRequestURL(req))
	if err != nil {
		return fmt.Errorf("refused: frame %d names an authority this sender cannot read: %w", req.Frame, err)
	}
	if host == a.host && port == a.port && isTLS == a.tls {
		return nil
	}
	if err := a.scope.AuthoriseRaw(host, port, isTLS, raw); err != nil {
		return fmt.Errorf("refused: frame %d addresses %s over a connection to %s, and %w",
			req.Frame, formatAuthority(host, port, isTLS), formatAuthority(a.host, a.port, a.tls), err)
	}
	return nil
}

// programRequestURL is the absolute URL a block's `:scheme` and `:authority` name, for authorityOf.
//
// The block's scheme wins when it names one this sender can dial, because `:scheme` is what an
// intermediary routes on; otherwise the connection's own scheme stands in. A scheme neither http nor
// https is left as written so authorityOf refuses it by name rather than having it quietly replaced with
// something dialable.
func (a *AuthorisedSender) programRequestURL(req burpsyhttp2.ProgramRequest) string {
	scheme := req.Scheme
	if scheme == "" {
		scheme = "http"
		if a.tls {
			scheme = "https"
		}
	}
	return scheme + "://" + req.Authority
}

// dialForProgram opens the connection a frame program needs: TLS with h2 negotiated, or cleartext for
// the prior-knowledge case.
//
// Both protocols are offered on the TLS path even though only h2 can carry a program. Offering h2 alone
// makes an HTTP/1.1-only target abort the handshake with an opaque TLS alert; offering both means the
// target says "http/1.1" and the operator gets told that the target does not speak h2 — which is the
// actual finding, and one worth learning into the per-authority cache while we are here.
func (a *AuthorisedSender) dialForProgram(ctx context.Context) (net.Conn, string, error) {
	if !a.tls {
		dialer := &net.Dialer{Timeout: a.net.config.Timeout}
		conn, err := dialer.DialContext(ctx, "tcp",
			net.JoinHostPort(a.host, strconv.Itoa(int(a.port))))
		if err != nil {
			return nil, "", fmt.Errorf("connection failed: %w", err)
		}
		return conn, "", nil
	}
	conn, negotiated, err := a.net.dialTLS(ctx, a.host, a.port, alpn.EgressOffer(true))
	if err != nil {
		return nil, "", fmt.Errorf("connection failed: %w", err)
	}
	a.net.protocols.learn(a.host, a.port, a.tls, negotiated)
	if negotiated != alpn.H2 {
		conn.Close()
		what := "no ALPN protocol at all"
		if negotiated != "" {
			what = fmt.Sprintf("%q", negotiated)
		}
		return nil, negotiated, fmt.Errorf(
			"%s negotiated %s, so it will not read HTTP/2 frames; a frame program has no HTTP/1.1 form to "+
				"fall back to", formatAuthority(a.host, a.port, a.tls), what)
	}
	return conn, negotiated, nil
}

// readForWindow reads until the program's read window closes or the peer stops, and says which of those
// happened.
//
// Everything read is kept, including a partial frame: a peer that answered three frames and then hung up
// has answered three frames, and truncation is frequently the result a probe was looking for. What ended
// the read is returned rather than dropped, because "the window closed while the peer was still talking"
// and "the peer hung up after two frames" are different findings that produce identical bytes.
//
// A zero window reads nothing at all, which is what a program asking for zero asked for — the result then
// carries no response bytes, and the capture layer refuses to index it rather than storing a half
// exchange (see scanner.Record).
func readForWindow(conn net.Conn, readForMS uint64) (out []byte, ended string) {
	if readForMS == 0 {
		return nil, "the program asked for no read window"
	}
	deadline := time.Now().Add(time.Duration(readForMS) * time.Millisecond)
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 16*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			var netErr net.Error
			switch {
			case errors.Is(err, io.EOF):
				return out, "the peer closed the connection"
			case errors.As(err, &netErr) && netErr.Timeout():
				return out, "the read window closed"
			default:
				return out, fmt.Sprintf("the read failed: %v", err)
			}
		}
		if !time.Now().Before(deadline) {
			return out, "the read window closed"
		}
	}
}
