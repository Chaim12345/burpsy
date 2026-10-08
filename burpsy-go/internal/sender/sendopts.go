package sender

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Per-send options carried on the context (burpsy-react-ui-mmca).
//
// # Why on the context and not on NetworkSettings
//
// NetworkSettings is one process-wide document: the scanner, Repeater, Intruder and the crawler all
// read the same Timeouts through Sender.Network(). Burp's RequestOptions.withResponseTimeout is the
// opposite shape — a bound for *this* request — and the only way to give one Repeater tab a
// deliberately long read (a time-based probe that sleeps for 20 seconds) used to be raising the
// global read timeout for every tool at once. Mutating the shared settings for one send would also be
// raced by every other send in the process.
//
// So the option rides the send's own context, the one value every raw send path in this package is
// already handed, and setDeadline prefers it over Network().readTimeout(host). Nothing in
// NetworkSettings changes, which TestAContextResponseTimeoutBoundsOneSendAndLeavesTheNetworkAlone
// pins with a DeepEqual before and after.
//
// # Which paths honour it
//
// Every raw-byte path that bounds its exchange through setDeadline: SendRawOutcome (HTTP/1.1 and
// h2), SendPipelined, SendKeepAlive, TimedRead's write half, SendSynchronized, SendFrameProgram and
// the pooled path in connpool.go. The typed Sender.Send path rides net/http's own client and is not
// covered; nothing that offers this option sends through it.

// SendOptions is one send's overrides of the standing network settings.
type SendOptions struct {
	// ResponseTimeout bounds how long this send waits for its response, replacing the network
	// settings' read timeout for this send only. Zero means "no override": the standing read timeout
	// applies exactly as before. A context deadline that falls earlier still wins — a caller that set
	// one is describing the whole operation, which a response timeout is a part of.
	ResponseTimeout time.Duration
	// StreamingTimeout is this send's streaming-response window (burpsy-react-ui-of0z — Burp's
	// per-tab "Streaming response timeout"), meaningful only when StreamingTimeoutSet. While set, a
	// response this send treats as streaming is read for this long and what arrived is returned: a
	// response from a host declared open-ended, a text/event-stream response that is chunked or
	// unframed (whether or not the network setting promotes event streams), and an unframed
	// read-until-close response such as a held long-poll. Zero means no cutoff — Burp's "To turn off
	// the timeout, set it to 0" — and the read then ends when the peer closes, the operator cancels,
	// or the streaming body cap is reached.
	StreamingTimeout    time.Duration
	StreamingTimeoutSet bool
	// SNI replaces the server name this send's TLS ClientHello carries (burpsy-react-ui-k011 —
	// Repeater's "Override SNI"). Only the ClientHello changes: the address dialled, the Host header
	// and the name the certificate is verified against stay the target's (see alpn.Dialer.SNI). A
	// redirect hop never carries it — HopContext strips it — because the override names this
	// target's handshake, not wherever a Location points next. Empty means no override.
	SNI string
}

// sniOverride is the ClientHello server name ctx asks for, or "".
func sniOverride(ctx context.Context) string {
	opts, ok := SendOptionsFrom(ctx)
	if !ok {
		return ""
	}
	return opts.SNI
}

// HopContext is ctx for a redirect hop: the per-send options that describe this target alone (the
// SNI override) are removed, and the ones that describe the whole send (the response timeout, the
// streaming window) are kept.
func HopContext(ctx context.Context) context.Context {
	opts, ok := SendOptionsFrom(ctx)
	if !ok || opts.SNI == "" {
		return ctx
	}
	opts.SNI = ""
	return WithSendOptions(ctx, opts)
}

// ValidateSNI refuses a server name a ClientHello cannot carry: empty, longer than a DNS name, an IP
// literal (crypto/tls sends no SNI for one, so the override would silently send none), or a character
// outside letters, digits, '.', '-' and '_'. field names the request key.
func ValidateSNI(field, name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("%s must be 1 to 253 characters, got %d", field, len(name))
	}
	if net.ParseIP(name) != nil {
		return fmt.Errorf("%s %q is an IP address; a ClientHello carries no SNI for an IP, so the override would send none", field, name)
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return fmt.Errorf("%s %q contains %q; a server name is letters, digits, '.', '-' and '_'", field, name, r)
		}
	}
	return nil
}

type sendOptionsKey struct{}

// WithSendOptions returns a context carrying opts for every send made with it.
func WithSendOptions(ctx context.Context, opts SendOptions) context.Context {
	return context.WithValue(ctx, sendOptionsKey{}, opts)
}

// SendOptionsFrom returns the options ctx carries, and whether it carries any.
func SendOptionsFrom(ctx context.Context) (SendOptions, bool) {
	opts, ok := ctx.Value(sendOptionsKey{}).(SendOptions)
	return opts, ok
}

// responseTimeoutOf is the per-send response timeout ctx carries, or zero.
func responseTimeoutOf(ctx context.Context) time.Duration {
	opts, ok := SendOptionsFrom(ctx)
	if !ok || opts.ResponseTimeout <= 0 {
		return 0
	}
	return opts.ResponseTimeout
}

// overrideDeadline is the deadline a per-send response timeout imposes on an exchange starting now,
// clamped to the context's own deadline when that falls earlier. ok is false when ctx carries no
// override, and the caller then applies the standing rule unchanged.
//
// The clamp is the whole reason this is not a one-liner. An Intruder attempt always runs under a
// context deadline (its total per-attempt bound, timeout_ms), and setDeadline used to let any context
// deadline short-circuit everything else — so an override consulted after that branch would never
// fire in Intruder at all. Here the earlier of the two wins, whichever it is.
func overrideDeadline(ctx context.Context) (time.Time, bool) {
	rt := responseTimeoutOf(ctx)
	if rt <= 0 {
		return time.Time{}, false
	}
	deadline := time.Now().Add(rt)
	if ctxDeadline, has := ctx.Deadline(); has && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline, true
}

// hasOwnBound reports whether ctx bounds its sends itself — a context deadline or a per-send response
// timeout. The event-stream promoter re-arms the read with the streaming window only when neither is
// present: extending a read past a bound the caller set for this send would make the override a
// suggestion.
func hasOwnBound(ctx context.Context) bool {
	if _, has := ctx.Deadline(); has {
		return true
	}
	return responseTimeoutOf(ctx) > 0
}

// explainResponseTimeout names a deadline error that the per-send response timeout produced, so it
// reads as the operator's own bound rather than as a bare "i/o timeout" that blames the network. It
// returns err unchanged when ctx carries no override, when the context itself has ended (that is
// explainCancellation's account to give), or when err is not a deadline error.
func explainResponseTimeout(ctx context.Context, err error) error {
	if err == nil || ctx.Err() != nil {
		return err
	}
	rt := responseTimeoutOf(ctx)
	if rt <= 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return fmt.Errorf("no response within this send's response timeout of %s: %w", rt, err)
}

// ValidateResponseTimeoutMS refuses a per-send response timeout an API caller cannot mean: zero or
// negative (omit the field for the standing read timeout — a zero here would read as "no bound at
// all", the opposite of what a field named for a bound asks), or longer than the longest bound the
// network settings accept. field names the request key, so the refusal says which one.
func ValidateResponseTimeoutMS(field string, ms int64) error {
	if ms <= 0 {
		return fmt.Errorf("%s is %d; give a positive number of milliseconds, or omit it to use the "+
			"standing read timeout", field, ms)
	}
	if ms > MaxTimeoutMS {
		return fmt.Errorf("%s is %d, longer than the %d ms this tool will wait", field, ms, MaxTimeoutMS)
	}
	return nil
}

// streamingOverride is the per-send streaming window ctx carries, and whether it carries one.
func streamingOverride(ctx context.Context) (time.Duration, bool) {
	opts, ok := SendOptionsFrom(ctx)
	if !ok || !opts.StreamingTimeoutSet {
		return 0, false
	}
	return opts.StreamingTimeout, true
}

// streamingDeadline is the deadline a per-send streaming window imposes from now, clamped to the
// context's own deadline when that is earlier. The zero time means "no deadline" (a window of 0 with
// no context deadline), which is what SetReadDeadline takes to clear one.
func streamingDeadline(ctx context.Context, window time.Duration) time.Time {
	var deadline time.Time
	if window > 0 {
		deadline = time.Now().Add(window)
	}
	if ctxDeadline, has := ctx.Deadline(); has && (deadline.IsZero() || ctxDeadline.Before(deadline)) {
		deadline = ctxDeadline
	}
	return deadline
}

// ValidateStreamingTimeoutMS refuses a per-send streaming window an API caller cannot mean: negative,
// or longer than the longest bound the network settings accept. Zero is valid and means no cutoff.
func ValidateStreamingTimeoutMS(field string, ms int64) error {
	if ms < 0 {
		return fmt.Errorf("%s is %d; give 0 for no cutoff or a positive number of milliseconds", field, ms)
	}
	if ms > MaxTimeoutMS {
		return fmt.Errorf("%s is %d, longer than the %d ms this tool will wait", field, ms, MaxTimeoutMS)
	}
	return nil
}
