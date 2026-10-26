package sender

// The synchronized send: the wire half of a Repeater group in Parallel mode
// (burpsy-react-ui-ajp6).
//
// Burp's parallel mode is not "send N requests at once". Its docs promise the requests
// "arrive in full at the same time": for HTTP/1 it withholds each request's last byte and
// releases those bytes down the separate connections simultaneously, so that request N does
// not leave at 10:00:00.001 merely because a scheduler woke its goroutine there. Go fan-out
// cannot make that promise — the goroutine that happens to be scheduled first wins the race
// the feature exists to remove — so a group labelled Parallel that is plain fan-out reports a
// successful simultaneous send for a test that tested nothing. That is this project's stated
// worst outcome, which is why the barrier lives here rather than behind a UI label change.
//
// # What is synchronized, and what deliberately is not
//
// The hold is the FINAL BYTE of the request only. Everything before it — dial, TLS handshake,
// the head of the request — happens whenever each goroutine gets there, because nothing about
// when a request *begins* bears on the race the mode tests; what bears is when it *completes
// its arrival*. One byte is also the smallest unit a TCP stream can hold and still flush
// everything before it: holding more would delay the target's parsing of the head for no
// benefit, holding less is impossible.
//
// HTTP/2 is NOT synchronized here, and a synchronized group pins HTTP/1.1 for three reasons:
// (1) burpsy's h2 path re-encodes the request into frames, so there is no "final byte of the
// operator's raw" to hold — the honest equivalent is Burp's single-packet HEADERS attack, a
// different mechanism; (2) a barrier across one h2 connection is meaningless and across
// several is the same HTTP/1 problem in a heavier frame; (3) refusing the h2 preference for
// the synchronized mode is visible in the result's Outcome.Downgrade, so an operator who
// pointed Parallel at an h2-only target learns why it went out as HTTP/1.1 instead of the
// mode silently changing what was measured.
//
// # The barrier contract
//
// The caller (api_repeater_group.go) opens one goroutine per item, each dialing its own
// connection through this method. When every goroutine has written its request-minus-one-byte
// — or failed before that, which also counts as "arrived" so a straggler never waits on a
// dead connection — the shared barrier releases and every goroutine writes its held byte.
// The sender therefore takes a release channel it waits on after the partial write, and the
// caller closes that channel once every item has reported readiness over a second channel.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/core"
)

// SyncPoints is the two-channel contract one synchronized group shares.
//
// ready is closed BY this method's caller-orchestrator? No — read it the other way: each send
// signals readiness by sending on ready, and the orchestrator closes release when all N have
// signalled (or failed). The sender's own goroutine waits on release. Both channels are
// provided by the caller; only the group size knows when "all" is all.
type SyncPoints struct {
	// Ready receives one signal per send that has reached its hold point (including sends
	// that failed on the way there — a failure is an arrival, or the barrier would deadlock
	// on a dead connection).
	Ready chan<- struct{}
	// Release closes when every member has signalled; every send resumes on close.
	Release <-chan struct{}
}

// SendSynchronized sends one HTTP/1 request whose final byte is withheld until Release.
//
// The raw is pinned to HTTP/1.1 (ProtocolPreferenceHTTP1) even on a TLS connection: the ALPN
// offer excludes h2 so a conformant front end cannot negotiate it, and the outcome records the
// downgrade for the same reason SendAs does — a preference is not a scope waiver and the
// operator sees what carried their bytes. The dial, the handshake and the head of the write
// happen before the hold; only the last byte waits.
//
// Returns the response, the send's outcome, and the error — the same three SendRawOutcome
// does, so the group's per-item recording does not fork.
func (s *Sender) SendSynchronized(ctx context.Context, host string, port uint16, useTLS bool, raw []byte, sync SyncPoints) ([]byte, SendOutcome, error) {
	if len(raw) == 0 {
		// Signalled like every other failure: the barrier counts arrivals, and an empty
		// request is one member that will never hold a byte.
		signalReady(sync)
		return nil, SendOutcome{}, fmt.Errorf("synchronized send: the request is empty, so there is no byte to withhold")
	}
	// planSend with the HTTP/1 preference: no h2 offer, no downgrade laundering. A request
	// that must not be rewritten (Transfer-Encoding, duplicated lengths) is refused by the
	// same rules every other raw send follows — and a send that never reached its hold point
	// still signals readiness, because the barrier's contract counts a failure as an arrival.
	if _, err := planSend(raw, useTLS, ProtocolPreferenceHTTP1); err != nil {
		signalReady(sync)
		return nil, SendOutcome{}, err
	}

	var conn net.Conn
	if !useTLS {
		c, cerr := s.dialPlain(ctx, host, port, s.captureDialIdentity(host, false))
		if cerr != nil {
			signalReady(sync)
			return nil, SendOutcome{}, fmt.Errorf("connection failed: %w", cerr)
		}
		conn = c
	} else {
		c, _, cerr := s.dialTLS(ctx, host, port, alpn.EgressOffer(false), s.captureDialIdentity(host, true))
		if cerr != nil {
			signalReady(sync)
			return nil, SendOutcome{}, fmt.Errorf("connection failed: %w", cerr)
		}
		conn = c
	}
	defer conn.Close()
	defer watchCancel(ctx, conn)()

	return s.sendSynchronizedOn(ctx, conn, raw, sync)
}

// sendSynchronizedOn performs the held write on an established connection. Split from
// SendSynchronized so the barrier's sequencing is testable against a recording conn — the
// dial is transport plumbing, and the hold is the contract.
func (s *Sender) sendSynchronizedOn(ctx context.Context, conn net.Conn, raw []byte, sync SyncPoints) ([]byte, SendOutcome, error) {
	settings := s.Network()
	host := hostOf(raw)
	// The two-phase write: everything but the final byte now, the final byte after release.
	s.setDeadline(ctx, conn, host)
	if _, err := conn.Write(raw[:len(raw)-1]); err != nil {
		signalReady(sync)
		return nil, SendOutcome{}, fmt.Errorf("write failed: %w", explainCancellation(ctx, err))
	}
	// Held. Signal, wait for the group, then let the byte go.
	signalReady(sync)
	select {
	case <-sync.Release:
	case <-ctx.Done():
		return nil, SendOutcome{}, fmt.Errorf("synchronized send cancelled while holding the final byte: %w", ctx.Err())
	}
	if _, err := conn.Write(raw[len(raw)-1:]); err != nil {
		return nil, SendOutcome{}, fmt.Errorf("write failed: %w", explainCancellation(ctx, err))
	}

	response, rerr := readResponse(
		bufio.NewReader(conn),
		settings.Continue.Understand100,
		settings.Streaming.isStreaming(host),
		eventStreamPromoter(ctx, conn, settings),
	)
	if rerr != nil {
		return nil, SendOutcome{}, fmt.Errorf("read failed: %w", explainCancellation(ctx, rerr))
	}
	return response, SendOutcome{Protocol: core.ProtocolHTTP1}, rerr
}

// hostOf reads the Host header out of a raw request, for the streaming check and the
// deadline's log line. The full parse is not needed on this path: the request was already
// planned by SendSynchronized's caller.
func hostOf(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 6 && strings.EqualFold(line[:6], "host:") {
			return strings.TrimSpace(line[6:])
		}
	}
	return ""
}

// signalReady reports arrival without panicking on a nil channel, which a caller with no
// barrier (a single synchronized send, in a test) legitimately passes.
func signalReady(sync SyncPoints) {
	if sync.Ready != nil {
		select {
		case sync.Ready <- struct{}{}:
		default:
			// The orchestrator is not reading (already released, or abandoned): arrival has
			// been reported enough, and blocking here would hang a send whose group moved on.
		}
	}
}
