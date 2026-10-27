package sender

import (
	"fmt"
	"net"
	"time"
)

// TimeoutOverride is a scan run's own connect and response timeouts — Burp's
// scanner/audit_project_option_overrides/{connect_timeout,normal_timeout}, which "override any you
// may have configured in the global settings" for the audit and for nothing else
// (Documentation/burp/documentation/scanner/scan-configurations/audit-settings.html, "Audit network
// timeouts"; read at Zbuj.java:19-22, build 51467).
//
// A nil field is "not overridden": the engagement's own bound stands. A zero duration is Burp's
// "never time out" (desktop/settings/network/connections.html: "If you set any of these settings to
// zero or leave them blank, Burp will never time out when performing that function").
type TimeoutOverride struct {
	// Connect bounds the TCP connect and the TLS handshake.
	Connect *time.Duration
	// Normal bounds the wait for the response once the connection is up — Burp's "how long Burp waits
	// before abandoning a request and recording a timeout".
	Normal *time.Duration
}

// Empty reports whether the override changes nothing.
func (o TimeoutOverride) Empty() bool { return o.Connect == nil && o.Normal == nil }

// DeriveWithTimeouts returns a sender that is this one with the run's timeouts in place of the
// engagement's, leaving this one exactly as it was.
//
// # Why a derived sender and not a mutation
//
// WithTimeout and ApplyNetwork both rewrite the receiver, and the receiver is the engagement sender:
// cmd/burpsy builds ONE and hands it to the scanner, Repeater, Intruder and the web layer. An audit
// configuration that said "10 s timeouts" and applied them there would change every other tool's
// timeouts for as long as the audit ran, and race every send in flight. The derived sender owns its
// own settings and its own transport (http.Transport reads its timeouts when a connection is opened,
// so the bound has to live in a transport of its own) and shares everything else that is a property
// of the engagement rather than of a timeout: the configuration's TLS policy, client certificates,
// platform authentication and upstream proxy (copied, so a later WithTimeout on either cannot reach
// the other), the SOCKS carrier, the cookie jar and the protocol cache (shared pointers — what one
// learnt about an authority's ALPN is true for both).
//
// The settings are a snapshot of the engagement's at the moment of derivation. A run is built once
// and lives for one audit; an operator who edits the network settings while it runs gets them on the
// next run, which is the same answer an in-flight send already gets from ApplyNetwork.
//
// # It is not a second egress path
//
// A derived sender is a *Sender like any other: it reaches a socket only through an AuthorisedSender
// wrapping it, which runs the scope gate on the rendered bytes before the dial. Nothing here can
// widen what may be sent; it can only change how long a send may take.
//
// # How the two Burp timeouts map onto three bounds
//
// burpsy splits connect, read and total; Burp has connect and "normal". Connect maps onto ConnectMS.
// Normal maps onto ReadMS, which both send paths apply after the dial (the raw path as the connection
// deadline, the typed path as the response-header timeout). TotalMS — which on the typed path bounds
// the whole exchange, dial included — becomes connect + normal, so neither phase's bound can be cut
// short by a total nobody typed. A phase that is unbounded (zero) leaves the total unbounded too, and
// the bounded phase is still enforced by its own bound. The total is capped at MaxTimeoutMS, the
// ceiling every settings document has.
//
// A context deadline can only tighten a derived sender's bound, never loosen it (strictBounds): a run
// that said "time out after 1 s" means it for a probe whose caller also set a per-probe budget of 30 s.
func (s *Sender) DeriveWithTimeouts(o TimeoutOverride) (*Sender, error) {
	if s == nil {
		return nil, fmt.Errorf("there is no sender to derive a run's timeouts from")
	}
	// The carrier is read in the same locked section as the config and the settings: WithUpstreamCarrier
	// writes it under s.mu, so reading it after the unlock was a data race, and could pair the settings
	// from before a swap with the carrier from after it (burpsy-react-ui-o388-predial-vs-dial residual 4).
	s.mu.RLock()
	cfg := *s.config
	settings := s.net
	carrier := s.carrier
	s.mu.RUnlock()

	connect := settings.Timeouts.ConnectMS
	if o.Connect != nil {
		connect = durationMS(*o.Connect)
	}
	// The engagement's effective response bound is its read bound when it has one and its total
	// otherwise — readTimeout's own fall-through, which is the bound a raw send actually waits under.
	read := settings.Timeouts.ReadMS
	if read == 0 {
		read = settings.Timeouts.TotalMS
	}
	if o.Normal != nil {
		read = durationMS(*o.Normal)
	}
	total := 0
	if connect > 0 && read > 0 {
		total = connect + read
		if total > MaxTimeoutMS {
			total = MaxTimeoutMS
		}
	}
	settings.Timeouts = TimeoutSettings{ConnectMS: connect, ReadMS: read, TotalMS: total}
	if err := settings.Validate(); err != nil {
		return nil, fmt.Errorf("the run's timeouts cannot be applied: %w", err)
	}
	cfg.Timeout = time.Duration(total) * time.Millisecond

	return &Sender{
		client:       buildClient(&cfg, settings, carrier),
		config:       &cfg,
		net:          settings,
		jar:          s.jar,
		carrier:      carrier,
		protocols:    s.protocols,
		upstream:     s.upstream,
		upstreamErr:  s.upstreamErr,
		strictBounds: true,
	}, nil
}

// CloseIdleConnections releases the typed path's idle pooled connections. A derived run sender calls
// it when its run ends: its transport is its own, and nothing else will ever reuse those connections.
func (s *Sender) CloseIdleConnections() {
	if s == nil {
		return
	}
	if c := s.httpClient(); c != nil {
		c.CloseIdleConnections()
	}
}

// DropKeptConnections closes every connection this sender is holding open for reuse: the raw path's
// HTTP/1 keep-alive pool and the typed path's idle pooled connections.
//
// For a change of identity rather than of settings (burpsy-react-ui-oava). A kept TLS connection
// already completed its handshake, so it carries whatever client certificate was presented when it
// was dialled; after a project switch replaces the client-certificate bindings, reusing it would
// send the incoming project's requests under the outgoing project's identity. Closing them makes the
// next send dial, and present, under the bindings now in force. Sends in flight finish on the
// connection they already hold, as for ApplyNetwork.
func (s *Sender) DropKeptConnections() {
	if s == nil {
		return
	}
	s.pool.closeAll()
	s.CloseIdleConnections()
}

func durationMS(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d / time.Millisecond)
}

// defaultExchangeBound ends one exchange's read when neither the operator's timeouts nor the
// caller's context does: an unbounded read on a connection the peer keeps open is a hang-forever
// primitive (757d). A var, not a const, so a test can shrink it rather than wait it out.
var defaultExchangeBound = 30 * time.Second

// deadlineFor is the connection deadline one raw send gets: the context's when it has one, the
// sender's own bound otherwise — and, for a derived run sender, whichever of the two is sooner.
// When neither exists the built-in defaultExchangeBound answers: every exchange is bounded.
func (s *Sender) deadlineFor(ctxDeadline time.Time, hasCtx bool, host string) (time.Time, bool) {
	bound := s.Network().readTimeout(host)
	switch {
	case hasCtx && s.strictBounds && bound > 0:
		if own := time.Now().Add(bound); own.Before(ctxDeadline) {
			return own, true
		}
		return ctxDeadline, true
	case hasCtx:
		return ctxDeadline, true
	case bound > 0:
		return time.Now().Add(bound), true
	}
	// Neither the operator nor the caller bounded this exchange: the built-in bound does. A read
	// with no deadline at all hangs for as long as the peer keeps the connection open, which a
	// keep-alive peer has every reason to do (757d).
	return time.Now().Add(defaultExchangeBound), true
}

// applyDeadline sets conn's deadline from deadlineFor.
func (s *Sender) applyDeadline(conn net.Conn, ctxDeadline time.Time, hasCtx bool, host string) {
	if d, ok := s.deadlineFor(ctxDeadline, hasCtx, host); ok {
		conn.SetDeadline(d)
	}
}
