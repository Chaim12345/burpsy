package scanner

// Cross-site WebSocket hijacking (burpsy-react-ui-0vzb.11).
//
// # The class
//
// A WebSocket handshake is an ordinary cross-origin GET as far as the browser is concerned: a page
// on any origin may open one, the browser attaches the target's cookies, and the Same-Origin Policy
// does not stop the page reading what the socket says. The handshake's Origin header is the only
// thing the server can tell the attacker's page from its own by. A server that authenticates the
// socket by cookie alone and does not check Origin hands an authenticated, two-way channel to
// whatever page the victim visits (Christian Schneider, "Cross-Site WebSocket Hijacking", 2013;
// PortSwigger Web Security Academy, "Cross-site WebSocket hijacking").
//
// # What is tested
//
// Only a captured handshake that opened a socket (101) and carries ambient credentials: a Cookie
// header, no Authorization header, no secret-shaped value in the query string and no secret-shaped
// subprotocol — a token the attacker's page would have to know is a defence this check does not
// second-guess. Three handshakes are sent, each a clone of the captured one with a fresh key and no
// extensions (wsclient.CloneHandshake), each read only until the first data message arrives or a
// short window ends, then closed. No frame is ever sent to the server: replaying a client message
// could be a state change, so the check reads only what the server volunteers on connect.
//
//	A  the handshake as captured (original Origin, cookies) — the authenticated reference
//	F  Origin: https://<random>.invalid, same cookies       — the attacker's page
//	N  original Origin, no Cookie header                     — the anonymous control
//
// # Evidence
//
// F answering 101 shows the server did not reject a foreign Origin. That alone does not show the
// socket is authenticated — a public feed accepts everyone — so a finding also needs one of:
//
//   - N refused (not 101): the cookies are what admits the socket. Firm.
//   - The first message F received equals A's and differs from N's (digit runs masked, so a
//     timestamp does not decide it): the foreign page got the authenticated session's view. Firm.
//
// When F answers 101 and N does too but no message arrived on any socket, nothing distinguishes the
// authenticated socket from a public one: that is reported tentative. When messages arrived and do
// not show the authenticated view reaching F (A equals N: a public socket; F equals N: the server
// dropped the session for the foreign origin), nothing is reported.
//
// SameSite is not evaluated: the check sees the cookies the handshake carried, not the attributes
// they were set with, and a Lax or Strict session cookie would not be sent by a cross-site page.
// The finding says so.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/wsclient"
)

// IssueWebSocketHijacking is the burpsy row this check reports; see BurpsyNativeRows.
const IssueWebSocketHijacking = "Cross-site WebSocket hijacking"

// wsHijackEnabled is the check's own switch.
func wsHijackEnabled(c *ScanConfig) bool { return c != nil && c.CheckWebSocketHijacking }

// wsHijackTiming bounds one handshake and the wait for its first message. A package variable so the
// tests can shorten it; nothing in the product writes it.
var wsHijackTiming = struct {
	handshake, firstMessage time.Duration
}{handshake: 10 * time.Second, firstMessage: 3 * time.Second}

// withWebSocketHijacking adds this check to the runner of the descriptor it rides ("Cross-site request
// forgery", whose own check runs only under its own switch). A proven finding from either half is
// returned even when the other failed.
func withWebSocketHijacking(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		var innerF []*Finding
		var innerErr error
		if finalChecksEnabled(cc.Config) {
			innerF, innerErr = inner(ctx, cc)
		}
		var wsF []*Finding
		var wsErr error
		if wsHijackEnabled(cc.Config) {
			wsF, wsErr = checkWebSocketHijacking(ctx, cc)
		}
		out := append(innerF, wsF...)
		switch {
		case len(wsF) > 0:
			return out, nil
		case innerErr != nil:
			return innerF, innerErr
		case wsErr != nil:
			return innerF, wsErr
		}
		return out, nil
	}
}

// secretShaped matches a value long and mixed enough to be a credential rather than a word: 16 or
// more URL-safe characters including both a letter and a digit.
var secretShaped = regexp.MustCompile(`^[A-Za-z0-9_\-.~+/=%]{16,}$`)

func looksLikeSecret(v string) bool {
	return secretShaped.MatchString(v) && strings.ContainsAny(v, "0123456789") &&
		strings.IndexFunc(v, func(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }) >= 0
}

// wsCookieOnlyHandshake reports whether a raw request is a WebSocket handshake authenticated by
// ambient cookies alone, and why not when it is not.
func wsCookieOnlyHandshake(raw string) (bool, string) {
	if !strings.EqualFold(headerValue(raw, "Upgrade"), "websocket") || headerValue(raw, "Sec-WebSocket-Key") == "" {
		return false, "not a WebSocket handshake"
	}
	if headerValue(raw, "Cookie") == "" {
		return false, "the handshake carries no cookie, so a cross-site page has no ambient credential to ride"
	}
	if headerValue(raw, "Authorization") != "" {
		return false, "the handshake carries an Authorization header a cross-site page cannot set"
	}
	for _, p := range strings.Split(headerValue(raw, "Sec-WebSocket-Protocol"), ",") {
		if looksLikeSecret(strings.TrimSpace(p)) {
			return false, "the handshake carries a token in its subprotocol"
		}
	}
	line := raw
	if i := strings.Index(raw, "\r\n"); i >= 0 {
		line = raw[:i]
	}
	if parts := strings.SplitN(line, " ", 3); len(parts) == 3 {
		if _, q, ok := strings.Cut(parts[1], "?"); ok {
			for _, kv := range strings.Split(q, "&") {
				_, v, _ := strings.Cut(kv, "=")
				if looksLikeSecret(v) {
					return false, "the handshake URL carries a token"
				}
			}
		}
	}
	return true, ""
}

// rawSetHeader returns raw with every instance of name removed and, when value is non-empty, one
// "name: value" line added at the end of the header block. The body is untouched.
func rawSetHeader(raw, name, value string) string {
	head, body, ok := strings.Cut(raw, "\r\n\r\n")
	if !ok {
		head, body = strings.TrimRight(raw, "\r\n"), ""
	}
	lines := strings.Split(head, "\r\n")
	kept := lines[:1:1]
	for _, l := range lines[1:] {
		n, _, _ := strings.Cut(l, ":")
		if strings.EqualFold(strings.TrimSpace(n), name) {
			continue
		}
		kept = append(kept, l)
	}
	if value != "" {
		kept = append(kept, name+": "+value)
	}
	return strings.Join(kept, "\r\n") + "\r\n\r\n" + body
}

// wsObservation is one handshake's outcome.
type wsObservation struct {
	status   int    // the handshake's status; 0 when no response was read
	opened   bool   // 101
	message  string // the first data message, "" when none arrived
	gotMsg   bool
	closed   bool // the server closed before any message
	failNote string
}

func (o wsObservation) summary() string {
	if o.status == 0 {
		return "no response (" + o.failNote + ")"
	}
	s := fmt.Sprintf("HTTP %d", o.status)
	if !o.opened {
		return s
	}
	switch {
	case o.gotMsg:
		m := o.message
		if len(m) > 160 {
			m = m[:160] + "..."
		}
		s += fmt.Sprintf(", first message %q", m)
	case o.closed:
		s += ", closed with no message"
	default:
		s += ", no message within the window"
	}
	return s
}

var errWSRefusedByScope = errors.New("refused: outside the engagement scope")

// wsHandshake sends one handshake through the exchange's scope gate and reads the first message.
func wsHandshake(ctx context.Context, cc *CheckContext, raw []byte) (wsObservation, error) {
	gate := cc.Scanner.probeGate(ctx, cc.Exchange)
	if gate == nil {
		return wsObservation{}, fmt.Errorf("no authorised sender: %w", errCapabilityMissing)
	}
	meter := meterFrom(ctx)
	meter.attempt()
	hctx, cancel := context.WithTimeout(ctx, wsHijackTiming.handshake)
	defer cancel()
	refusedBefore := gate.Refused()
	up, err := gate.SendUpgrade(hctx, raw)
	if gate.Refused() > refusedBefore {
		meter.refusal()
		return wsObservation{}, fmt.Errorf("%w: %v", errWSRefusedByScope, err)
	}
	if err != nil {
		if st := httputil.ResponseStatus(up.RawResp); st != nil {
			meter.succeeded()
			return wsObservation{status: *st}, nil
		}
		meter.failure()
		return wsObservation{failNote: err.Error()}, nil
	}
	meter.succeeded()
	defer up.Conn.Close()
	obs := wsObservation{status: 101, opened: true}

	rs := core.NewWsReassembler(1 << 20)
	buf := make([]byte, 16*1024)
	deadline := time.Now().Add(wsHijackTiming.firstMessage)
	_ = up.Conn.SetReadDeadline(deadline)
	for !obs.gotMsg && !obs.closed && time.Now().Before(deadline) {
		n, rerr := up.Reader.Read(buf)
		if n > 0 {
			if ferr := rs.Feed(buf[:n]); ferr != nil {
				obs.closed = true
				break
			}
			for ev := rs.Pop(); ev != nil; ev = rs.Pop() {
				switch ev.Opcode {
				case core.WsOpcodeText, core.WsOpcodeBinary:
					if !obs.gotMsg && !ev.Compressed {
						obs.message, obs.gotMsg = string(ev.Payload), true
					}
				case core.WsOpcodeClose:
					obs.closed = true
				}
			}
		}
		if rerr != nil {
			if !isTimeoutErr(rerr) {
				obs.closed = true
			}
			break
		}
	}
	// A polite close, masked as a client frame must be; the socket is dropped either way.
	_ = up.Conn.SetWriteDeadline(time.Now().Add(time.Second))
	mask := [4]byte{0x5b, 0x1e, 0x7a, 0x33}
	_, _ = up.Conn.Write(core.EncodeWsFrame(core.WsOpcodeClose, []byte{0x03, 0xe8}, &mask))
	return obs, nil
}

func isTimeoutErr(err error) bool {
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}

// wsDigits masks digit runs, so a message that differs only by a timestamp or counter compares equal.
var wsDigits = regexp.MustCompile(`[0-9]+`)

func wsSameMessage(a, b string) bool {
	return wsDigits.ReplaceAllString(a, "0") == wsDigits.ReplaceAllString(b, "0")
}

// checkWebSocketHijacking runs the three handshakes against one captured WebSocket handshake.
func checkWebSocketHijacking(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if ok, _ := wsCookieOnlyHandshake(raw); !ok {
		return nil, nil
	}
	if st := httputil.ResponseStatus([]byte(responseRaw(cc.Scanner, cc.Exchange))); st == nil || *st != 101 {
		// The capture did not open a socket; there is no authenticated connection to compare with.
		return nil, nil
	}
	if cc.Scanner.sender == nil {
		return nil, fmt.Errorf("%s: no sender: %w", IssueWebSocketHijacking, errCapabilityMissing)
	}
	clone := func(edit func(string) string) ([]byte, error) {
		b, err := wsclient.CloneHandshake([]byte(raw))
		if err != nil {
			return nil, err
		}
		return []byte(edit(string(b))), nil
	}
	origOrigin := headerValue(raw, "Origin")
	foreign := "https://" + randHex(12) + ".invalid"

	send := func(edit func(string) string) (wsObservation, error) {
		b, err := clone(edit)
		if err != nil {
			return wsObservation{}, err
		}
		return wsHandshake(ctx, cc, b)
	}
	authed, err := send(func(s string) string { return s })
	if err != nil {
		return nil, fmt.Errorf("%s: %w", IssueWebSocketHijacking, err)
	}
	if !authed.opened {
		// The captured handshake no longer opens a socket (an expired session, a gone endpoint).
		return nil, nil
	}
	cross, err := send(func(s string) string { return rawSetHeader(s, "Origin", foreign) })
	if err != nil {
		return nil, fmt.Errorf("%s: %w", IssueWebSocketHijacking, err)
	}
	if !cross.opened {
		// The foreign Origin was refused: the server checks it.
		return nil, nil
	}
	anon, err := send(func(s string) string { return rawSetHeader(s, "Cookie", "") })
	if err != nil {
		return nil, fmt.Errorf("%s: %w", IssueWebSocketHijacking, err)
	}
	if anon.status == 0 {
		return nil, fmt.Errorf("%s: the cookie-less control got no response (%s): %w",
			IssueWebSocketHijacking, anon.failNote, errCheckInconclusive)
	}

	var confidence, proof string
	switch {
	case !anon.opened:
		confidence = "firm"
		proof = fmt.Sprintf("Without its cookies the same handshake was refused (HTTP %d), so the cookies are "+
			"what admits the socket, and a page on a foreign origin was admitted with them.", anon.status)
	case cross.gotMsg && authed.gotMsg && anon.gotMsg &&
		wsSameMessage(cross.message, authed.message) && !wsSameMessage(anon.message, authed.message):
		confidence = "firm"
		proof = "The socket opened from the foreign origin received the same first message as the " +
			"authenticated socket, and a socket opened without cookies received a different one: the " +
			"foreign page was given the authenticated session's view."
	case !authed.gotMsg && !cross.gotMsg && !anon.gotMsg:
		confidence = "tentative"
		proof = "The socket also opens without cookies and no socket sent a message on connect, so " +
			"nothing shown here distinguishes an authenticated socket from a public one; only the " +
			"acceptance of the foreign Origin is demonstrated."
	default:
		// Messages arrived and do not show the authenticated view reaching the foreign origin.
		return nil, nil
	}

	evidence := strings.Join([]string{
		"Origin " + quoteOrNone(origOrigin) + " with cookies: " + authed.summary(),
		"Origin " + foreign + " with cookies: " + cross.summary(),
		"Origin " + quoteOrNone(origOrigin) + " without cookies: " + anon.summary(),
	}, "\n")
	detail := "The WebSocket handshake to this URL is authenticated by cookies and was accepted with Origin " +
		foreign + ", an origin the application does not serve. " + proof + " A page on any origin can " +
		"therefore open this socket in a victim's browser and read and send messages as the victim, " +
		"unless the session cookie is SameSite=Lax or Strict (not evaluated: the handshake shows the cookies " +
		"sent, not the attributes they were set with). No message was sent on any socket."
	f := buildHeaderFinding(cc, IssueWebSocketHijacking, "high", confidence, evidence, detail)
	return []*Finding{f}, nil
}

func quoteOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
