package sender

import (
	"context"
	"time"
)

// TimedOutcome is one authorised TimedRead: what came back, whether the settle window closed first,
// and how long the exchange took from the write to the end of the read.
type TimedOutcome struct {
	// Response is the response read, complete when TimedOut is false. When the window closed part-way
	// through a response it holds what had arrived, which is evidence rather than a reply.
	Response []byte
	// TimedOut is true when the settle window closed before a complete response was read.
	TimedOut bool
	// Elapsed covers dial, write and read: a caller comparing two probes compares like with like.
	Elapsed time.Duration
}

// TimedRead is the scope-gated form of Sender.TimedRead: the bytes are authorised against the
// engagement scope before anything is dialled, the send is paced like every other send through this
// sender, and only then is the one-request connection opened.
//
// Sender.TimedRead's doc comment puts authorisation on the caller; this is that caller, so a timing
// probe (request smuggling's CL.TE / TE.CL detection is the one that needs it) has no way out of the
// process that skips the gate. A refusal is counted and returned exactly as Send's is.
func (a *AuthorisedSender) TimedRead(ctx context.Context, raw []byte, settle time.Duration) (TimedOutcome, error) {
	if err := a.scope.AuthoriseRaw(a.host, a.port, a.tls, raw); err != nil {
		a.refused.Add(1)
		return TimedOutcome{}, err
	}
	release, err := a.pacing(ctx)
	if err != nil {
		return TimedOutcome{}, err
	}
	defer release()
	start := time.Now()
	resp, timedOut, err := a.net.TimedRead(ctx, a.host, a.port, a.tls, raw, settle)
	out := TimedOutcome{Response: resp, TimedOut: timedOut, Elapsed: time.Since(start)}
	if err != nil {
		return out, err
	}
	a.sent.Add(1)
	return out, nil
}
