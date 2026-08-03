package sender

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// ScopeChecker is the per-request gate an AuthorisedSender asks about the exact bytes about to be
// written. Both core.Scope and core.SharedScope implement it; the interface keeps sender free of
// a concrete core type.
type ScopeChecker interface {
	AuthoriseRaw(host string, port uint16, isTLS bool, raw []byte) error
}

// AuthorisedResult is one authorised send's outcome.
type AuthorisedResult struct {
	Raw      []byte
	Duration time.Duration
	Status   *int
}

// AuthorisedSender is a sender bound to one named target whose scope is checked against the
// request bytes actually about to go on the wire — not the target string the operator typed.
// This is the sender half of the intruder guarantee: a payload spliced into a path position can
// rewrite the request line, and only the bytes about to be written can be trusted. The scope
// check happens before the dial, so an out-of-scope request never reaches the transport.
//
// Ports burpsy-sender's AuthorisedSender contract: the scope handle is bound at construction,
// every send is checked individually, a refusal is counted and returned as the send's error,
// and the transport is never reached on refusal.
type AuthorisedSender struct {
	scope   ScopeChecker
	net     *Sender
	host    string
	port    uint16
	tls     bool
	sent    atomic.Int64
	refused atomic.Int64
}

// NewAuthorisedSender binds a scope gate and a raw sender to one named target.
func NewAuthorisedSender(scope ScopeChecker, net *Sender, host string, port uint16, tls bool) *AuthorisedSender {
	return &AuthorisedSender{scope: scope, net: net, host: host, port: port, tls: tls}
}

// Send checks the request bytes against the scope, then — and only then — writes them.
// The refused count includes requests refused on either scope or readability grounds; a request
// that fails to send at the transport is neither sent nor refused, and is reported by the caller.
func (a *AuthorisedSender) Send(ctx context.Context, raw []byte) (AuthorisedResult, error) {
	if err := a.scope.AuthoriseRaw(a.host, a.port, a.tls, raw); err != nil {
		a.refused.Add(1)
		return AuthorisedResult{}, err
	}
	start := time.Now()
	resp, err := a.net.SendRaw(ctx, a.host, a.port, a.tls, raw)
	if err != nil {
		return AuthorisedResult{}, err
	}
	a.sent.Add(1)
	return AuthorisedResult{
		Raw:      resp,
		Duration: time.Since(start),
		Status:   httputil.ResponseStatus(resp),
	}, nil
}

// Sent counts the requests that cleared the gate and reached the transport.
func (a *AuthorisedSender) Sent() int64 { return a.sent.Load() }

// Refused counts the requests the scope stopped before the dial.
func (a *AuthorisedSender) Refused() int64 { return a.refused.Load() }
