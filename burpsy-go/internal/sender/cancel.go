package sender

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Cancellation that reaches the socket.
//
// # The bug this exists for
//
// Every send in this package takes a context, and setDeadline honoured it — but only its *deadline*.
// A context cancelled without a deadline, which is what `context.WithCancel` and an HTTP client
// disconnect both produce, changed nothing: `conn.Read` stayed blocked until the configured read
// timeout expired, whatever the caller wanted.
//
// The visible consequence was on Repeater. The handler threads r.Context() into the sender, and Go's
// http.Server cancels that context when the browser goes away — so a Cancel button looked like it
// only needed an AbortController on the fetch. It did not: the browser would have stopped waiting
// while the request continued to the target for up to the whole read timeout. An operator would have
// pressed Cancel, seen the request stop, and been wrong about whether their bytes reached the target.
// On a tool used under engagement rules that is a worse failure than having no Cancel at all, which
// is why this went in before the button did.
//
// It is not only Repeater. Cancelling a crawl, an audit or a scan task left every in-flight socket
// blocked the same way, so the task's own cancellation was honest about intent and not about traffic.
//
// # Why a deadline in the past rather than closing the connection
//
// Setting a past deadline makes the in-progress Read or Write return immediately, and the caller's
// own `defer conn.Close()` still runs in its normal order. Closing the connection from another
// goroutine would race that Close and, on some paths, race a read that is mid-buffer — the deadline
// route unblocks without taking ownership of a connection this goroutine does not own.
//
// The cost is the error: an unblocked read reports a timeout, not a cancellation. explainCancellation
// is what keeps that from being reported as "the target was slow".

// watchCancel unblocks conn's in-flight I/O when ctx is cancelled, and returns a stop function that
// must be called before the connection is reused or closed.
//
// Install it once per connection, next to the `defer conn.Close()` that owns it:
//
//	conn, err := s.dialOne(ctx, host, port, useTLS)
//	…
//	defer conn.Close()
//	defer watchCancel(ctx, conn)()
//
// The two defers run in the right order — stop first, then Close — because defers are LIFO.
//
// Per connection rather than per request: a batch that re-arms its deadline for each request in a
// loop would otherwise leave one watcher per iteration behind, and a stale watcher firing a past
// deadline on a connection still in use would fail a later, unrelated read.
func watchCancel(ctx context.Context, conn net.Conn) func() {
	// A context that can never be cancelled needs no goroutine. context.Background() and
	// context.TODO() both return nil here, and those are common in tests and in one-shot CLI paths.
	if ctx.Done() == nil {
		return func() {}
	}

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// A deadline already in the past: the current Read or Write returns at once, and so does
			// any that follows. Errors are ignored deliberately — the connection may already be
			// closed by the owning goroutine, which is a race this function is allowed to lose.
			_ = conn.SetDeadline(time.Now())
		case <-stopped:
		}
	}()
	return func() { close(stopped) }
}

// explainCancellation replaces a timeout error with the cancellation that actually caused it.
//
// When watchCancel fires, the I/O error is a deadline error and says nothing about cancelling —
// which would be reported to the operator, and written into the tool log, as though the target had
// been slow. That is precisely the wrong account: nobody waited, and the request was abandoned on
// purpose.
//
// Returns err unchanged when the context is fine, so a genuine timeout is still reported as one.
// Ordering matters here: a real timeout on a live context must not be relabelled, and a cancellation
// must not be reported as a timeout, so the context is consulted rather than the error text.
func explainCancellation(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	cause := ctx.Err()
	if cause == nil {
		return err
	}
	// Only a deadline error is reinterpreted. A cancellation that arrived after a read had already
	// failed for its own reason — a connection reset, a malformed response — must keep the real
	// reason, because that is a fact about the target and the cancellation is not.
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		// A deadline the caller set, which setDeadline had already put on the socket. This really is
		// a timeout, and naming it as the caller's own bound is more use than "i/o timeout".
		return fmt.Errorf("the send exceeded its deadline: %w", cause)
	}
	return fmt.Errorf("the send was cancelled before a response arrived: %w", cause)
}
