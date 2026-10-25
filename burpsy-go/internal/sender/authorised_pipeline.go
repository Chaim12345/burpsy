package sender

// The pipelined and keep-alive batch sends, gated like every other send (W1's burpsy-react-ui-0vzb.40).
// A batch is several requests down one connection - exactly the shape a request-smuggling probe is
// made of, and exactly why the gate is per raw: a smuggled prefix can address a different target
// than the socket, so every member is authorised on the bytes that will actually leave, before any
// byte of the batch moves.
//
// Per-member order is the slice-1 order, verbatim: the extension HTTP hook rewrites the member,
// then AuthoriseRaw gates the hook's OUTPUT, then the pacer admits, then the wire. Response hooks
// are deliberately not applied (the same choice SendSynchronizedGroup makes): a smuggling or
// desync check compares what the target did, not what a plugin made of it.
//
// Unlike the synchronized group, one member's refusal does not abort the batch: the refused member
// is counted on Refused, carries its refusal on ReadErr, and the rest send. Results are
// index-preserved against the input, so the caller zips nothing back together. A hookRequest error
// IS a member refusal - the only error it returns is the scope refusal of a plugin's replacement,
// already counted on Refused exactly as if the replaced bytes had arrived from the caller - so it
// lands on that member like any other refusal rather than aborting the batch. A pacing decline is
// the batch-level contract: no member leaves, every member that would have sent carries the
// decline by name, and the group error is non-nil.

import (
	"context"
	"errors"
	"fmt"
)

// SendPipelined sends every authorised member down one fresh connection and reads the responses
// in order. See the package comment above for the gating contract.
func (a *AuthorisedSender) SendPipelined(ctx context.Context, raws [][]byte) ([]PipelinedExchange, error) {
	return a.sendBatch(ctx, raws, func(ctx context.Context, batch [][]byte) ([]PipelinedExchange, error) {
		return a.net.SendPipelined(ctx, a.host, a.port, a.tls, batch)
	})
}

// SendKeepAlive sends every authorised member down one keep-alive connection, reading each
// response before writing the next. See the package comment above for the gating contract.
func (a *AuthorisedSender) SendKeepAlive(ctx context.Context, raws [][]byte) ([]PipelinedExchange, error) {
	return a.sendBatch(ctx, raws, func(ctx context.Context, batch [][]byte) ([]PipelinedExchange, error) {
		return a.net.SendKeepAlive(ctx, a.host, a.port, a.tls, batch)
	})
}

func (a *AuthorisedSender) sendBatch(ctx context.Context, raws [][]byte, delegate func(context.Context, [][]byte) ([]PipelinedExchange, error)) ([]PipelinedExchange, error) {
	if len(raws) == 0 {
		return nil, errors.New("refused: a batch has no members")
	}

	// Per member, in slice-1 order: hook, then gate the hook's OUTPUT. hookRequest's only error
	// is the scope refusal of a replacement, already counted on Refused - the member carries it
	// and the batch carries on, exactly as if the replaced bytes had arrived from the caller.
	results := make([]PipelinedExchange, len(raws))
	survivors := make([][]byte, 0, len(raws))
	survivorIndex := make([]int, 0, len(raws))
	for i, raw := range raws {
		results[i].Raw = raw
		if a.net.hook() != nil {
			hooked, err := a.hookRequest(ctx, raw)
			if err != nil {
				results[i].ReadErr = err
				continue
			}
			raw = hooked
			results[i].Raw = hooked
		}
		if err := a.scope.AuthoriseRaw(a.host, a.port, a.tls, raw); err != nil {
			a.refused.Add(1)
			results[i].ReadErr = err
			continue
		}
		survivors = append(survivors, raw)
		survivorIndex = append(survivorIndex, i)
	}
	if len(survivors) == 0 {
		return results, nil
	}

	// Pacing admits the batch that will actually ride the connection, like SendSynchronizedGroup.
	release := func() {}
	if a.pace != nil {
		gp, ok := a.pace.(GroupPacer)
		if !ok {
			err := errors.New("declined: pacing cannot admit the batch atomically (the configured pacer has no group contract)")
			return a.declineBatch(results, survivorIndex, err), err
		}
		r, err := gp.PaceN(ctx, len(survivors))
		if err != nil {
			wrapped := fmt.Errorf("declined: pacing cannot admit %d at once: %w", len(survivors), err)
			return a.declineBatch(results, survivorIndex, wrapped), wrapped
		}
		if r != nil {
			release = r
		}
	}
	defer release()

	exchanges, err := delegate(ctx, survivors)
	if err != nil {
		return nil, err
	}
	a.sent.Add(int64(len(survivors)))
	for j, exchange := range exchanges {
		results[survivorIndex[j]] = exchange
	}
	return results, nil
}

// declineBatch marks every member that would have sent with the one decline, so the caller's
// per-member report reads "unproven: pacing" for each rather than one bare error detached from
// the members it stopped. Members already refused keep their refusal - it is the truer story.
func (a *AuthorisedSender) declineBatch(results []PipelinedExchange, survivorIndex []int, err error) []PipelinedExchange {
	for _, i := range survivorIndex {
		results[i].ReadErr = err
	}
	return results
}
