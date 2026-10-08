// Package sender provides HTTP request sending capabilities.
package sender

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/upstream"
)

// Sender handles HTTP request sending.
type Sender struct {
	// mu guards client, config and net together, because they are one decision: the transport is built
	// from the other two, so a reader that saw a new setting and an old client would dial with a
	// timeout nothing configured.
	//
	// It also fixes a race that was already here. WithTimeout and WithTLSVerify mutated
	// client.Timeout and the transport's TLSClientConfig in place, which is a data race against any
	// concurrent Send — and the fields they wrote are exactly the ones the settings surface now
	// changes at runtime, so leaving them unguarded would have turned a latent race into a routine one.
	mu     sync.RWMutex
	client *http.Client
	config *SenderConfig
	net    NetworkSettings
	// tlsCAs caches the root pool built from each custom CA path the operator has configured, keyed by
	// the path. Building a CertPool parses every system root, and this is the handshake path for every
	// TLS send, so a per-dial build would be a real cost. Guarded separately from mu because it is
	// written on the send path and read by nothing else — the dial builds its own copy of the value.
	tlsMu  sync.Mutex
	tlsCAs map[string]*x509.CertPool
	// pool holds the HTTP/1 connections kept alive for reuse (ry5n, keepalive.go). Its zero value is
	// an empty pool.
	pool http1Pool
	// jar is the cookie store a followed redirect chain replays from, and the same store its hops'
	// responses are absorbed into. Nil means no replay, which is the default: burpsy sends what an
	// operator wrote, and a cookie the target set mid-chain is not something they asked to send
	// (burpsy-react-ui-mr83). See CookieJar for why this is an interface rather than the session
	// package's own type, which imports this one.
	//
	// On the Sender rather than on AuthorisedSender because the choice is a NETWORK SETTING and every
	// authorised sender shares this one: a setting that a caller had to pass to each of twenty
	// construction sites is a setting half of them will forget.
	jar CookieJar
	// carrier is the global SOCKS layer this sender's egress legs are opened through. Nil means no
	// carrier, which is the behaviour every send had before it existed. See
	// internal/upstream.Carrier.
	carrier *upstream.Carrier
	// protocols is what this sender has learnt about each authority's ALPN, plus the protocol-coverage
	// counters. One per Sender rather than one per authority handle, so an intruder run and the scan
	// that preceded it share what either of them discovered — see protocol.go. Its own state is
	// atomic, so it is deliberately outside mu.
	protocols *ProtocolCache
	// upstream is the resolved upstream proxy policy every dial in this file goes through, and nil
	// only when neither SenderConfig.ProxyURL nor SenderConfig.Upstream was set.
	upstream *upstream.Policy
	// upstreamErr is a proxy configuration this sender cannot honour. Non-nil makes every dial fail
	// with it: an operator who configured a proxy must not have their traffic go out direct because
	// the configuration was unusable. See NewSender.
	upstreamErr error
}

// SenderConfig holds configuration for the sender.
//
// Every field here is read by NewSender. That is worth stating because two of them were not: a
// MaxRedirects that nothing enforced (the bound really in effect was the stdlib's own coincidental
// 10) and a ProxyURL that nothing dialled (the proxy really came from $HTTP_PROXY). A config field
// that lies is worse than a missing one, because a reader who finds it stops looking for the real
// answer. Both are gone — one deleted, one wired.
type SenderConfig struct {
	Timeout   time.Duration
	TLSVerify bool
	// ProxyURL routes this sender's own egress through an explicit upstream proxy. Empty means
	// dial the authorised authority and nothing else.
	//
	// Explicit, never ambient. The transport used to carry http.ProxyFromEnvironment, so an
	// $HTTP_PROXY exported for any unrelated reason silently re-routed burpsy's own attack traffic
	// through a third party that no scope decision was ever made about — and the authority actually
	// dialled is the one thing AuthorisedSender exists to pin down.
	//
	// It is the *whole-sender* proxy: a single destination-independent upstream. Set Upstream instead
	// for per-destination rules; the two are equivalent when Upstream has one default rule and no
	// patterns, and NewSender folds a ProxyURL into exactly that so there is one resolution path
	// rather than two. Setting both is a configuration error and NewSender refuses to guess between
	// them — see NewSender.
	ProxyURL string
	// Upstream is the per-destination upstream proxy policy this sender's egress follows: an ordered
	// host-pattern list with a default, shared by reference so a live edit through
	// /api/network/proxy reaches every sender holding it. Nil dials origins directly.
	Upstream  *upstream.Policy
	UserAgent string
	// ClientCerts, when set, supplies the TLS client certificate to present to a host that asks for
	// one. Nil means none is ever offered — the behaviour before client TLS authentication existed.
	//
	// The type is alpn's one-method interface, not internal/netauth's concrete store, so this package
	// keeps its existing dependency set and a test can bind one certificate without building a
	// credential store. Held here rather than on Sender because both dial paths need it and both read
	// their knobs from the config.
	ClientCerts alpn.ClientCertSource
	// UpstreamCarrier is the global SOCKS layer this sender's egress legs are opened through.
	// Nil means no carrier, which is the behaviour every send had before the layer existed.
	//
	// It is here rather than only on the Sender because the client is built during construction, from
	// the config, before a Sender exists to hold anything.
	UpstreamCarrier *upstream.Carrier
	// PlatformAuth, when set, is consulted for an Authorization header to present on the typed send
	// path — Burp's Settings → Network → Platform authentication.
	//
	// Deliberately not applied to the raw-bytes path. SendRawOutcome's contract is that it sends what
	// the caller wrote, verbatim, and the desync and smuggling probes this tool exists to send depend
	// on that byte-for-byte fidelity; splicing a header into those bytes would change the framing the
	// probe is measuring. A raw caller that wants a credential presented sets the header itself, which
	// it is already constructing the request line by hand to do.
	PlatformAuth PlatformAuth
}

// PlatformAuth is the per-host credential lookup the typed send path consults.
//
// An interface for the same reason ClientCerts is one: internal/netauth owns the rules, the schemes
// and the secrets, and this package only needs to ask two questions of them. Satisfied by
// *netauth.Credentials.
type PlatformAuth interface {
	// Authorization returns the header value to present for one request, and whether there is one.
	// False is an ordinary answer, not a failure: a Digest rule has nothing to send until the host has
	// challenged once.
	Authorization(host, method, uri string) (string, bool)
	// Learn records a challenge from a 401 so the next attempt can authenticate, reporting whether the
	// challenge is usable. See netauth.Credentials.Learn.
	Learn(host, wwwAuthenticate string) (bool, error)
}

// DefaultSenderConfig returns default sender configuration.
func DefaultSenderConfig() *SenderConfig {
	return &SenderConfig{
		Timeout:   30 * time.Second,
		TLSVerify: true,
		UserAgent: "burpsy/1.0",
	}
}

// NewSender creates a new HTTP sender.
//
// # Redirects are never followed
//
// A 30x comes back to the caller as the response it is. Following one is a decision only the caller
// can make: a Location may name any authority at all, while the authority a scope decision was made
// about is the one in the request that produced the 30x. A follow inside the transport dials the
// next hop with no gate in front of it — that is the "hostile target steers you at an internal
// service" escape, and it does not become safe for being three hops deep. There is deliberately no
// config knob to switch it back on, because a knob would restore exactly the ungated hop. A caller
// that wants the next hop asks for it explicitly, through an AuthorisedSender bound to the new
// authority so the new target is genuinely re-authorised; internal/crawler re-admits a Location into
// its frontier for precisely this reason.
//
// Burp's Repeater does not follow redirects by default either, so an operator sees the 30x rather
// than its consequence.
// # Every dial goes through the upstream proxy policy, not only the typed one
//
// SenderConfig.ProxyURL used to configure http.Transport.Proxy and nothing else, which covered exactly
// one of this package's five dial sites: Send's typed path. SendRaw, the pipelined desync probes, the
// frame-program path and the ALPN discovery handshake all opened their own sockets and ignored it. A
// proxy setting that covers the repeater but not the smuggling probe is the "partial result looking
// complete" defect in its purest form, so the policy is resolved once here and every dial in this
// package — see dialPlain and dialTLS — goes through it.
//
// The typed path keeps net/http's own HTTP-proxy handling (absolute-form for cleartext, CONNECT for
// TLS) because that is ordinary client behaviour over bytes net/http composed itself. The raw paths
// tunnel with CONNECT instead, because their bytes are operator-authored and frequently malformed on
// purpose — see upstream.Proxy.DialContext. SOCKS is applied in the dialer for both, so there is one
// SOCKS implementation rather than net/http's for one path and ours for the others.
func NewSender(config *SenderConfig) *Sender {
	if config == nil {
		config = DefaultSenderConfig()
	}
	settings := networkFromConfig(config)
	policy, policyErr := resolveUpstream(config)
	carrier := config.UpstreamCarrier
	return &Sender{
		client:      buildClient(config, settings, carrier),
		config:      config,
		net:         settings,
		protocols:   newProtocolCache(),
		upstream:    policy,
		upstreamErr: policyErr,
	}
}

// networkFromConfig derives the starting network settings from a SenderConfig, so every existing caller
// keeps the behaviour it had before these settings existed.
//
// SenderConfig.Timeout becomes the total bound, because that is what it was: it set both the client
// timeout and the dialer timeout, and the client timeout is the one that bounded the exchange.
//
// # Connect gets 10s, and that is a deliberate change
//
// Two literals disagreed about the connect bound. The transport's DialContext used config.Timeout
// (30 seconds by default) while its TLSHandshakeTimeout was 10 seconds, so a plaintext dial had three
// times the budget of a TLS handshake for no stated reason. A single named setting has to pick one, and
// 10s is the right pick: a TCP connect that has not completed in ten seconds is not going to, and the
// tighter of two accidental values is the one that was actually deliberate. The alternative — taking
// the looser 30s — would have widened a bound nobody asked to widen in order to avoid admitting the
// literals disagreed.
//
// A caller that asked for a *shorter* total than that keeps it: clamping connect down to the total is
// what preserves `&SenderConfig{Timeout: 3 * time.Second}` meaning a three-second dial, which is what
// several tests rely on.
func networkFromConfig(config *SenderConfig) NetworkSettings {
	settings := DefaultNetworkSettings()
	total := int(config.Timeout / time.Millisecond)
	settings.Timeouts.TotalMS = total
	if total > 0 && settings.Timeouts.ConnectMS > total {
		settings.Timeouts.ConnectMS = total
	}
	return settings
}

// buildClient builds the typed path's http.Client for one (config, settings) pair.
//
// Split out of NewSender because ApplyNetwork has to build a new one: http.Transport's timeouts are
// read when a connection is established rather than on every request, so mutating the live transport's
// fields would both race with in-flight sends and leave already-idle connections on the old values. A
// fresh transport per settings change costs one connection pool, which is the honest price of a
// timeout change that actually takes effect.
func buildClient(config *SenderConfig, settings NetworkSettings, carrier *upstream.Carrier) *http.Client {
	// Resolved here rather than passed in because every caller of buildClient already holds the
	// config this derives from, and threading it through four call sites would let one of them
	// forget. A policy that cannot be built is carried, not swallowed: see the Proxy hook below.
	policy, policyErr := resolveUpstream(config)

	transport := &http.Transport{
		// The dial composes BOTH network concerns, and taking either merge side alone would have
		// dropped one of them silently:
		//
		//   * the hostname-resolution table, via overrideAddr on the address and the configured
		//     resolver inside settings.dialer() — where the request actually goes;
		//   * the upstream proxy policy, via upstream.Dialer — what opens the socket.
		//
		// Base is what keeps them from cancelling out. Without it upstream.Dialer builds its own bare
		// net.Dialer, so configuring a proxy would quietly also mean "and stop honouring my resolver".
		// A nil policy makes upstream.Dialer a plain net.Dialer, so an unconfigured sender dials
		// exactly as it always did.
		//
		// Only the host part of the address is substituted, which leaves the TLS ServerName the
		// transport derived from the URL untouched — an override changes where a request goes, never
		// which vhost it asks for.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := upstream.Dialer{
				Policy:  policy,
				Timeout: time.Duration(settings.Timeouts.ConnectMS) * time.Millisecond,
				Base:    settings.dialer(),
				// The global SOCKS layer, applied beneath whatever the policy resolved. The same
				// instance the proxy leg and the console hold, so one Settings edit reaches every
				// surface (burpsy-react-ui-mr83 part 3).
				Carrier: carrier,
			}
			// The family preference is applied here too, and on the same rule as the raw path's
			// dialAddress: an override is an operator naming one address and is never second-guessed, and
			// the system preference leaves the hostname for the dialer to resolve. Two dial paths that
			// disagreed here would be a Repeater send that reached an IPv6-only host and a scanner probe
			// on the same host that did not.
			target := settings.overrideAddr(addr)
			if host, _, err := net.SplitHostPort(addr); err == nil {
				if resolved, rerr := settings.resolveForDial(ctx, host); rerr == nil && resolved != "" {
					if _, _, perr := net.SplitHostPort(target); perr == nil {
						_, resolvedPort, _ := net.SplitHostPort(target)
						target = net.JoinHostPort(resolved, resolvedPort)
					}
				}
			}
			return dialer.DialContext(ctx, network, target)
		},
		// Burp's "Default to HTTP/2" (ry5n) reaches the typed path too: off, no h2 is attempted.
		ForceAttemptHTTP2:     settings.DefaultToHTTP2(),
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   time.Duration(settings.Timeouts.ConnectMS) * time.Millisecond,
		ResponseHeaderTimeout: time.Duration(settings.Timeouts.ReadMS) * time.Millisecond,
		ExpectContinueTimeout: time.Duration(settings.Continue.ExpectTimeoutMS) * time.Millisecond,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.TLSVerify,
		},
	}

	if config.ClientCerts != nil {
		// The typed path does not go through dialTLS — it hands the whole exchange to
		// http.Transport — so the client-certificate hook has to be installed here as well as
		// there. TLSClientConfig cannot carry it: GetClientCertificate is not told which host it is
		// being asked about (see alpn.Dialer.ClientCerts), and this transport is shared across every
		// authority the sender talks to, so one shared callback could not choose per host.
		// DialTLSContext is the hook that still knows the address.
		//
		// Installed only when a certificate source is attached, so a sender without one keeps the
		// stdlib's own TLS setup byte for byte and this feature cannot regress the common path.
		//
		// config, not config.TLSVerify: WithTLSVerify mutates the config this closure was built from,
		// so reading the field at dial time keeps the two paths in agreement. Capturing the bool would
		// have frozen it, and WithTLSVerify would have silently stopped working for TLS sends.
		transport.DialTLSContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("unusable TLS target %q: %w", addr, err)
			}
			// Composed with the other two dial concerns, exactly as dialTLS is: the resolution
			// table decides the address and the resolver, the upstream policy decides what opens
			// the socket under the handshake, and the certificate source decides what is presented
			// on it. A client-cert dial that quietly stopped honouring either of the other two
			// would be the half-covered settings defect these units exist to close.
			dialer := alpn.Dialer{
				InsecureSkipVerify: !config.TLSVerify,
				Timeout:            time.Duration(settings.Timeouts.ConnectMS) * time.Millisecond,
				Resolver:           settings.dialer().Resolver,
				ClientCerts:        config.ClientCerts,
			}
			if policy != nil && !policy.Empty() {
				dialer.Carry = upstream.Dialer{Policy: policy, Timeout: config.Timeout, Base: settings.dialer()}.DialContext
			}
			addr = settings.overrideAddr(addr)
			// EgressOffer(true) matches ForceAttemptHTTP2 above: the transport inspects the negotiated
			// protocol on the connection it is handed and uses h2 when ALPN chose it, so offering h2
			// here keeps the protocol behaviour the same as the stdlib dial it replaces.
			conn, _, err := dialer.Dial(ctx, host, addr, alpn.EgressOffer(true))
			if err != nil {
				return nil, err
			}
			return conn, nil
		}
	}

	if policyErr != nil {
		// A proxy the operator asked for and that cannot be used must fail the send, not silently
		// become a direct connection: "my traffic went straight to the target" is the one outcome an
		// operator who configured a proxy did not ask for. Transport.Proxy is the earliest hook that
		// can refuse the typed path; the raw paths refuse in dialPlain/dialTLS.
		transport.Proxy = func(*http.Request) (*url.URL, error) { return nil, policyErr }
	} else if policy != nil {
		transport.Proxy = policy.HTTPProxyForRequest
	}

	return &http.Client{
		Transport: transport,
		Timeout:   settings.exchangeTimeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Network reports the settings this sender is currently applying.
func (s *Sender) Network() NetworkSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.net
}

// ApplyNetwork installs new network settings and rebuilds the typed path's transport for them.
//
// It validates first and changes nothing on refusal: a half-applied settings document — the new
// timeouts in force and the new resolution table not, say — is a state no operator asked for and none
// could diagnose. Sends already in flight finish on the old client, which is the only coherent
// answer for a request whose dial already happened under the old rules.
func (s *Sender) ApplyNetwork(settings NetworkSettings) error {
	normalised := settings.Normalise()
	if err := normalised.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.net = normalised
	s.client = buildClient(s.config, normalised, s.carrier)
	// A kept connection was dialled under the settings just replaced (resolution, TLS, timeouts), so
	// none of them may carry the next send.
	s.pool.closeAll()
	return nil
}

// httpClient returns the client to send one typed request with.
func (s *Sender) httpClient() *http.Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client
}

// tlsVerify reports whether certificate verification is on, under the lock that guards config.
func (s *Sender) tlsVerify() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.TLSVerify
}

// userAgent is the User-Agent header a request with none of its own is given.
func (s *Sender) userAgent() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.UserAgent
}

// resolveUpstream turns the two proxy fields into the one policy every dial follows.
//
// Both set is refused rather than resolved by precedence: ProxyURL and Upstream are two answers to
// "where does this sender's traffic go", and picking one would send traffic somewhere the operator did
// not unambiguously ask for. A ProxyURL alone becomes a policy with that default and no patterns,
// which is the same thing expressed once.
func resolveUpstream(config *SenderConfig) (*upstream.Policy, error) {
	if config.ProxyURL != "" && config.Upstream != nil {
		return nil, fmt.Errorf("sender has both ProxyURL %q and an upstream proxy policy; set one",
			config.ProxyURL)
	}
	if config.Upstream != nil {
		config.Upstream.Attach("sender")
		return config.Upstream, nil
	}
	if config.ProxyURL == "" {
		return nil, nil
	}
	policy := upstream.NewPolicy()
	if err := policy.SetDefault(config.ProxyURL); err != nil {
		return nil, fmt.Errorf("sender proxy URL is unusable: %w", err)
	}
	policy.Attach("sender")
	return policy, nil
}

// dialPlain opens one cleartext TCP connection to an authority, through the upstream proxy policy.
//
// The single cleartext dial site for this whole package: sendHTTP1Plain, dialOne's cleartext arm and
// dialForProgram's cleartext arm all come here, so a proxy setting cannot cover some of them and not
// others. That was the state before — three independent net.Dialers, none of which had heard of
// SenderConfig.ProxyURL.
func (s *Sender) dialPlain(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if s.upstreamErr != nil {
		return nil, s.upstreamErr
	}
	// Both concerns, composed in the one place every raw plaintext dial goes through.
	//
	// dialAddress applies the hostname-resolution override; Base carries the configured resolver into
	// whatever TCP connection upstream.Dialer opens, to the proxy or to the origin. Building a bare
	// net.Dialer here instead — which is what this did before the network settings landed — would have
	// meant that configuring a proxy silently stopped honouring the operator's resolver.
	settings := s.Network()
	dialer := upstream.Dialer{
		Policy: s.upstream,
		// The global SOCKS layer. Every dial in this package carries it, not just the transport's:
		// the raw path — which is the one Repeater sends through, and therefore the one an operator
		// exercising the setting from the UI actually uses — would otherwise go direct and make the
		// setting look installed and inert (burpsy-react-ui-mr83 part 3).
		Carrier: s.carrier,
		Timeout: time.Duration(settings.Timeouts.ConnectMS) * time.Millisecond,
		Base:    settings.dialer(),
	}
	return dialer.DialContext(ctx, "tcp", settings.dialAddressFor(ctx, host, port))
}

// Protocols reports which protocol carried this sender's sends, why the HTTP/1.1 ones did, and what is
// known about each authority's ALPN. See protocol.go for why a downgrade is always named.
func (s *Sender) Protocols() ProtocolReport { return s.protocols.Report() }

// KnownProtocol reports what this sender has learnt about one authority, without handshaking. A caller
// that has never sent to it gets ProtocolSupportUnknown, which is deliberately not HTTP/1.1.
func (s *Sender) KnownProtocol(host string, port uint16, useTLS bool) ProtocolSupport {
	return s.protocols.Lookup(host, port, useTLS)
}

// ProtocolFor reports what an authority's ALPN says, handshaking once and remembering the answer.
//
// For a caller that needs to know before it builds a request — a UI showing what a target speaks, the
// frame-program path deciding whether a refusal is worth explaining in h2 terms. A send never needs
// this: it learns from the connection it was going to open anyway, which is why ProtocolReport counts
// discovery handshakes separately from sends.
//
// A plaintext authority answers ProtocolSupportHTTP11 with no handshake at all, because cleartext has
// no ALPN — see protocol.go on h2c.
func (s *Sender) ProtocolFor(ctx context.Context, host string, port uint16, useTLS bool) (ProtocolSupport, error) {
	if !useTLS {
		return ProtocolSupportHTTP11, nil
	}
	if known := s.protocols.Lookup(host, port, useTLS); known != ProtocolSupportUnknown {
		s.protocols.hits.Add(1)
		return known, nil
	}
	conn, negotiated, err := s.dialTLS(ctx, host, port, alpn.EgressOffer(true))
	if err != nil {
		return ProtocolSupportUnknown, fmt.Errorf("discovering %s's protocol: %w",
			formatAuthority(host, port, useTLS), err)
	}
	conn.Close()
	s.protocols.handshakes.Add(1)
	s.protocols.learn(host, port, useTLS, negotiated)
	return s.protocols.Lookup(host, port, useTLS), nil
}

// dialTLS opens one TLS connection with the given ALPN offer, through the shared negotiation logic the
// proxy's upstream leg uses. Certificate verification follows SenderConfig.TLSVerify, unlike the proxy's
// leg — see internal/alpn.
//
// The upstream proxy carries the connection, not the handshake: alpn.Dialer.Carry gets the tunnel and
// the TLS session is still end-to-end with the origin, so the certificate verified and the protocol
// negotiated are the origin's own. A proxy that terminated TLS here would be reporting its own ALPN as
// the target's.
func (s *Sender) dialTLS(ctx context.Context, host string, port uint16, offer []string) (*tls.Conn, string, error) {
	if s.upstreamErr != nil {
		return nil, "", s.upstreamErr
	}
	// Same composition as dialPlain, for the TLS path. The resolution table decides the address and
	// the resolver; the upstream policy decides what opens the socket under the handshake.
	//
	// The TLS session stays end-to-end with the origin either way: Carry hands alpn.Dialer an already
	// open tunnel and the handshake runs on top of it, so the certificate verified and the protocol
	// negotiated are the origin's, not the proxy's. Base is what stops the proxied branch from losing
	// the operator's resolver on its way to the proxy.
	settings := s.Network()
	connect := time.Duration(settings.Timeouts.ConnectMS) * time.Millisecond
	// All three dial concerns in one place. A client certificate configured for this host is
	// presented here too, which covers every raw-bytes TLS path in the package at once:
	// SendRawOutcome, ProtocolFor's discovery handshake, dialOne's pipelining and desync probes, and
	// dialForProgram's frame programs all funnel through this function.
	// Verification follows the network settings, not the construction-time field, so one edit reaches
	// every leg. SenderConfig.TLSVerify is still read, and is the fallback for a sender built without
	// network settings applied — which is every test and every embedder that never called ApplyNetwork.
	// burpsy-react-ui-f365: the setting existed on the sender and was invisible, which is half of why
	// the proxy's permanent off looked like a design decision rather than a gap.
	verify, roots, minVersion := s.tlsPolicy(settings)
	dialer := alpn.Dialer{
		InsecureSkipVerify: !verify,
		RootCAs:            roots,
		MinVersion:         minVersion,
		Timeout:            connect,
		Resolver:           settings.dialer().Resolver,
		ClientCerts:        s.config.ClientCerts,
	}
	// The carrier is on the path whether or not an upstream policy is configured. Gating it on
	// `s.upstream != nil && !s.upstream.Empty()` is the bug the live pass caught: with no HTTP proxy
	// configured — the ordinary case for an operator who only wants a SOCKS hop — the raw path opened
	// a bare socket, so the layer was configured, reported as configured, and never carried a single
	// connection. Burp's setting says "every outbound connection", and the gate made it mean "every
	// connection to an upstream proxy" (burpsy-react-ui-mr83 part 3).
	if s.upstream != nil && !s.upstream.Empty() || s.carrier != nil {
		dialer.Carry = upstream.Dialer{
			Policy:  s.upstream,
			Carrier: s.carrier,
			Timeout: connect,
			Base:    settings.dialer(),
		}.DialContext
	}
	return dialer.Dial(ctx, host, settings.dialAddressFor(ctx, host, port), offer)
}

// Request represents a raw HTTP request.
type Request struct {
	Method  string
	URL     string
	Host    string
	Path    string
	Headers map[string]string
	Body    []byte
	TLS     bool
	Port    uint16
}

// Response represents an HTTP response.
type Response struct {
	StatusCode int
	Status     string
	Headers    map[string]string
	Body       []byte
	Version    string
	Duration   time.Duration
	// Raw is the exact bytes this response arrived as, when they are known. The typed transport path
	// builds a Response straight off http.Response and has no byte image to attach — nil here means
	// "ask whoever sent it", never "the response was empty". Parsers that start from bytes
	// (responseFromRaw) set it, which is what lets a redirect chain hand its caller the final
	// response's real bytes instead of a reconstruction.
	Raw []byte
	// Outcome is which protocol carried the request, and why it was not HTTP/2 when it was not.
	//
	// Version already carries the stdlib's protocol string ("HTTP/2.0"), which is the same fact in a form
	// nothing can count: a caller reading it has to match on text, and a caller wanting to know *why* an
	// h2-capable sender used HTTP/1.1 has nowhere to look. See protocol.go.
	Outcome SendOutcome
}

// effectiveTarget resolves one Request into the absolute URL the transport will dial.
//
// One function and one parse, because Send dials this URL and Render writes its RequestURI on the
// request line: the bytes AuthorisedSender.SendRequest hands the scope gate and the request the
// transport actually writes therefore cannot disagree about where the request is going. Two
// independent constructions of the same target is how a gate ends up authorising a path the wire
// never carried — including the percent-encoding differences url.Parse introduces, which a
// hand-built request line would not reproduce.
func effectiveTarget(req *Request) (*url.URL, error) {
	raw := req.URL
	if raw == "" {
		scheme := "http"
		if req.TLS {
			scheme = "https"
		}
		port := ""
		if req.Port != 0 && ((req.TLS && req.Port != 443) || (!req.TLS && req.Port != 80)) {
			port = fmt.Sprintf(":%d", req.Port)
		}
		raw = fmt.Sprintf("%s://%s%s%s", scheme, req.Host, port, req.Path)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("unusable target %q: %w", raw, err)
	}
	return parsed, nil
}

// Render returns the HTTP/1.1 bytes this Request describes, for a caller that must inspect a request
// before anything is sent. AuthorisedSender.SendRequest renders one to hand the scope gate the
// request line it is about to authorise.
//
// Header order is sorted rather than Go's randomised map order, so one Request always renders the
// same bytes: a gate reading nondeterministic input is a gate whose refusals cannot be reproduced.
// The Host line comes from the authority that will be dialled, not from any Headers["Host"] the
// caller set, because that is what net/http writes — Request.write takes Host from the request, and
// WriteSubset excludes the header. Rendering the caller's copy instead would show a Host that never
// goes on the wire.
func (s *Sender) Render(req *Request) ([]byte, error) {
	target, err := effectiveTarget(req)
	if err != nil {
		return nil, err
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	host := req.Host
	if host == "" {
		host = target.Host
	}

	dropExpect := s.Network().Continue.RemoveExpect
	headers := make(map[string]string, len(req.Headers)+1)
	haveUserAgent := false
	for k, v := range req.Headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		// Dropped here as well as in Send, so the rendered bytes the scope gate reads are the bytes the
		// transport will write. A header stripped on only one of the two paths is how a gate comes to
		// authorise a request that is not the one sent.
		if dropExpect && strings.EqualFold(k, "Expect") {
			continue
		}
		if strings.EqualFold(k, "User-Agent") {
			haveUserAgent = true
		}
		headers[k] = v
	}
	if agent := s.userAgent(); !haveUserAgent && agent != "" {
		// Mirrors what Send fills in, so the rendered request is the one that would be sent rather
		// than one header short of it.
		headers["User-Agent"] = agent
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)

	var out bytes.Buffer
	fmt.Fprintf(&out, "%s %s HTTP/1.1\r\n", method, target.RequestURI())
	fmt.Fprintf(&out, "Host: %s\r\n", host)
	for _, k := range names {
		fmt.Fprintf(&out, "%s: %s\r\n", k, headers[k])
	}
	out.WriteString("\r\n")
	out.Write(req.Body)
	return out.Bytes(), nil
}

// Send does not authorise anything against the engagement scope: it builds the request and dials.
// AuthorisedSender.SendRequest is the entry point that gates a typed request, and the only one any
// request-originating surface should hold (HARD-03).
//
// It stays exported because the active scanner reaches it through its own scope check
// (ActiveScanner.sendTestRequest) and because AuthorisedSender.SendRequest is built on it. New
// callers want the authorised entry point.
// # Platform authentication
//
// A credential configured for the target's host is presented here — preemptively for Basic, and after
// one challenge for Digest. See sendOnce and the retry below.
func (s *Sender) Send(ctx context.Context, req *Request) (*Response, error) {
	target, err := effectiveTarget(req)
	if err != nil {
		return nil, err
	}

	resp, challenges, err := s.sendOnce(ctx, req, target)
	if err != nil {
		return nil, err
	}

	// The Digest second leg. A 401 carrying a challenge is not a failure for a host we hold a
	// credential for: it is the nonce the response has to be computed against, which is the only way
	// Digest can work at all. Learn caches it and reports whether it is answerable; a second 401 with
	// the same nonce means the credential itself was rejected, and Learn returns false so this cannot
	// loop.
	//
	// Bounded at exactly one retry, deliberately. A loop bounded by an attempt count would keep
	// sending the operator's credentials at a host that keeps refusing them, which on an engagement is
	// how an account gets locked out.
	if resp.StatusCode == http.StatusUnauthorized && s.config.PlatformAuth != nil && len(challenges) > 0 {
		host, _, _, authErr := authorityOf(target.String())
		if authErr == nil {
			for _, challenge := range challenges {
				usable, _ := s.config.PlatformAuth.Learn(host, challenge)
				if !usable {
					continue
				}
				retried, _, retryErr := s.sendOnce(ctx, req, target)
				if retryErr != nil {
					// The retry failed at the transport. The first response is real and already read, so
					// it is returned rather than replaced by an error about a request the caller never
					// asked for.
					return resp, nil
				}
				return retried, nil
			}
		}
	}
	return resp, nil
}

// sendOnce performs exactly one typed exchange and reports any authentication challenges the response
// carried.
//
// Split out of Send so the Digest retry is one more call rather than a second copy of the request
// construction: two constructions of the same request is how a retry ends up differing from the
// original in a way nobody intended. The body is rebuilt from req.Body on each call, which is what
// makes a retry possible at all — an io.Reader would already be drained.
func (s *Sender) sendOnce(ctx context.Context, req *Request, target *url.URL) (*Response, []string, error) {
	startTime := time.Now()

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	if req.Host != "" {
		httpReq.Host = req.Host
	}

	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", s.userAgent())
	}

	// The typed path is the one place a request header is removed on the operator's instruction, and
	// only here: the raw path carries the operator's own bytes, and stripping a header out of those
	// would be this package editing a probe it was asked to send verbatim. A peer that stalls on
	// Expect: 100-continue is what the setting is for, and a caller who wants that behaviour on raw
	// bytes edits the bytes.
	if s.Network().Continue.RemoveExpect {
		httpReq.Header.Del("Expect")
	}

	// A caller's own Authorization header always wins. An operator editing a request in Repeater and
	// typing a credential into it means that credential, and a per-host rule silently replacing it
	// would make the request they are looking at not the request that goes out.
	if s.config.PlatformAuth != nil && httpReq.Header.Get("Authorization") == "" {
		if host, _, _, err := authorityOf(target.String()); err == nil {
			method := req.Method
			if method == "" {
				method = http.MethodGet
			}
			// RequestURI, not the full URL: the Digest response hashes the request-target exactly as it
			// appears on the request line, so any other rendering produces a hash the server cannot
			// reproduce.
			if value, ok := s.config.PlatformAuth.Authorization(host, method, target.RequestURI()); ok {
				httpReq.Header.Set("Authorization", value)
			}
		}
	}

	// httpClient(), not s.client: the accessor takes the read lock, and ApplyNetwork rebuilds the
	// client under the write lock when a timeout changes. Reading the field directly would race it.
	httpResp, err := s.httpClient().Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	headers := make(map[string]string)
	for k, vv := range httpResp.Header {
		if len(vv) > 0 {
			headers[k] = vv[0]
		}
	}

	// Every WWW-Authenticate value, not just the first. A server may send Basic and Digest as two
	// separate headers, and Response.Headers keeps only one value per name — so the map above would
	// hide the Digest challenge behind the Basic one exactly when it is needed.
	challenges := httpResp.Header.Values("Www-Authenticate")

	duration := time.Since(startTime)

	return &Response{
		StatusCode: httpResp.StatusCode,
		Status:     httpResp.Status,
		Headers:    headers,
		Body:       body,
		Version:    httpResp.Proto,
		Duration:   duration,
		Outcome:    s.observe(target, httpResp),
	}, challenges, nil
}

// observe records what the stdlib transport actually negotiated for one typed send.
//
// The typed path does not choose a protocol the way SendRawOutcome does — http.Transport was already
// built with ForceAttemptHTTP2, so it offers h2 on every TLS dial and uses it when ALPN agrees. What was
// missing is the same thing that was missing on the raw path: nothing said which protocol carried the
// request, so a scan run entirely over HTTP/1.1 against an h2 front end looked exactly like one run over
// h2. Reading it back off the response costs nothing and makes it countable.
//
// The response's own TLS state is the source, not a second handshake and not a guess: it is the
// connection this exchange actually used.
func (s *Sender) observe(target *url.URL, resp *http.Response) SendOutcome {
	host, port, isTLS, err := authorityOf(target.String())
	if err != nil {
		// A URL the transport dialled but authorityOf cannot read is not something to invent an authority
		// for. The outcome is still reported for this send; it just contributes nothing to the
		// per-authority table.
		return newOutcome("", ProtocolSupportUnknown, downgradeFromResponse(resp, false, ""), nil, nil)
	}
	negotiated := ""
	if resp.TLS != nil {
		negotiated = resp.TLS.NegotiatedProtocol
	}
	if isTLS {
		s.protocols.learn(host, port, isTLS, negotiated)
	}
	// The exchange completed — observe runs on a response — so this send is counted. No rendering is carried:
	// the typed path's caller holds a *Request rather than bytes, and Sender.Render is the one place that
	// turns one into the other.
	//
	// No ServerIP here: the stdlib transport owns its connections and does not hand the dialled
	// address to this layer. Inventing one by re-resolving would report where the name points now
	// rather than where this request went, which is exactly the lie the field exists not to tell.
	return s.finish(host, port, isTLS, negotiated, downgradeFromResponse(resp, isTLS, negotiated), nil, nil, "", nil)
}

// downgradeFromResponse names why a typed send did not travel over h2, or nil when it did.
func downgradeFromResponse(resp *http.Response, isTLS bool, negotiated string) *Downgrade {
	if resp.ProtoMajor == 2 {
		return nil
	}
	switch {
	case !isTLS:
		return &Downgrade{Reason: DowngradePlaintextTarget}
	case negotiated == "":
		return &Downgrade{Reason: DowngradeNoALPN}
	default:
		down := &Downgrade{Reason: DowngradeNegotiatedHTTP11}
		if negotiated != alpn.HTTP11 {
			down.Detail = negotiated
		}
		return down
	}
}

// SendRaw sends a raw HTTP request string and returns the response, using HTTP/2 when the target
// negotiates it and the bytes can be carried over it unchanged.
//
// The outcome is dropped here for the callers that only want the response bytes; SendRawOutcome is the
// same send with the protocol decision returned. Either way the decision is counted, so a caller that
// ignores it does not make it invisible — Sender.Protocols still reports it.
func (s *Sender) SendRaw(ctx context.Context, host string, port uint16, useTLS bool, rawRequest []byte) ([]byte, error) {
	resp, _, err := s.SendRawOutcome(ctx, host, port, useTLS, rawRequest, ProtocolPreferenceAuto)
	return resp, err
}

// SendRawOutcome sends raw bytes and reports which protocol carried them.
//
// # What it decides, in order
//
// Whether h2 is even offered on the dial is decided from the bytes and the caller's preference, before
// any connection exists (planSend). Then one dial happens, with that offer, and what ALPN chose decides
// which stack writes: an h2 target gets the request re-encoded as h2 on that same connection, anything
// else gets the HTTP/1.1 bytes on that same connection. There is never a second handshake — discovery is
// a side effect of the connection the send needed anyway, which is why an intruder run pays for exactly
// one handshake per request rather than two.
//
// # The one thing it will not do
//
// It will not change what is being asked in order to use a newer protocol. A request carrying a
// Transfer-Encoding, a duplicated Content-Length, an unreadable request line — the probes this tool
// exists to send — go out as HTTP/1.1 verbatim, with a Downgrade naming the construct. See protocol.go.
func (s *Sender) SendRawOutcome(
	ctx context.Context,
	host string,
	port uint16,
	useTLS bool,
	rawRequest []byte,
	pref ProtocolPreference,
) ([]byte, SendOutcome, error) {
	settings := s.Network()
	projectHTTP1 := pref == ProtocolPreferenceAuto && !settings.DefaultToHTTP2() && !burpsyhttp2.IsHTTP2Request(rawRequest)
	if projectHTTP1 {
		// Burp's "Default to HTTP/2" off (ry5n): a send that named no protocol is planned as pinned,
		// and reported under its own reason so the coverage report says why h2 never happened.
		pref = ProtocolPreferenceHTTP1
	}
	plan, err := planSend(rawRequest, useTLS, pref)
	if err != nil {
		return nil, SendOutcome{}, err
	}
	if projectHTTP1 && plan.block != nil && plan.block.Reason == DowngradePinnedByCaller {
		plan.block = &Downgrade{Reason: DowngradeProjectDefaultHTTP1}
	}

	// Keep-alive (ry5n): an HTTP/1 send may ride a connection an earlier send left reusable.
	keep := settings.KeepAliveHTTP1() && !settings.Streaming.isStreaming(host)
	key := poolKey(host, port, useTLS)
	if keep {
		if ic := s.pool.take(key, plan.wantH2); ic != nil {
			resp, err := s.exchangeHTTP1(ctx, ic.conn, ic.br, host, plan.http1)
			if err == nil || !staleReuse(err) {
				down := plan.block
				if down == nil {
					down = &Downgrade{Reason: DowngradeNegotiatedHTTP11, Forced: plan.mustH2}
					if ic.negotiated == "" {
						down = &Downgrade{Reason: DowngradeNoALPN, Forced: plan.mustH2}
					}
				}
				out := s.finish(host, port, useTLS, ic.negotiated, down, nil, nil, remoteIP(ic.conn), err)
				s.release(key, ic, plan.http1, resp, err)
				return resp, out, err
			}
			// The server closed it while it sat idle; this send gets a fresh connection.
			ic.conn.Close()
		}
	}

	if !useTLS {
		// No ALPN exists on cleartext, so nothing was negotiated and nothing is learnt about this
		// authority beyond what cleartext implies.
		resp, ip, err := s.sendHTTP1Plain(ctx, host, port, plan.http1, keep)
		out := s.finish(host, port, useTLS, "", plan.block, nil, nil, ip, err)
		return resp, out, err
	}

	conn, negotiated, err := s.dialTLS(ctx, host, port, alpn.EgressOffer(plan.wantH2))
	if err != nil {
		return nil, SendOutcome{}, fmt.Errorf("connection failed: %w", err)
	}
	kept := false
	defer func() {
		if !kept {
			conn.Close()
		}
	}()
	// See cancel.go: without this, cancelling the context leaves the read blocked until the
	// configured timeout, whatever the caller asked for.
	defer watchCancel(ctx, conn)()
	if plan.wantH2 {
		// Learnt only when h2 was actually offered. A handshake that offered http/1.1 alone and got
		// http/1.1 back is no evidence at all about whether the target speaks h2, and recording it as
		// ProtocolSupportHTTP11 would turn our own choice into a claim about the target.
		s.protocols.learn(host, port, useTLS, negotiated)
	}

	if plan.wantH2 && negotiated == alpn.H2 {
		s.setDeadline(ctx, conn, host)
		resp, err := sendOverH2(ctx, conn, plan.http2)
		out := s.finish(host, port, useTLS, negotiated, nil, plan.rewrites, plan.http2.render(), remoteIP(conn), err)
		return resp, out, err
	}

	down := plan.block
	if down == nil {
		// h2 was offered and did not happen: the two ways that can go are different findings, so they
		// are different reasons.
		if negotiated == "" {
			down = &Downgrade{Reason: DowngradeNoALPN, Forced: plan.mustH2}
		} else {
			down = &Downgrade{Reason: DowngradeNegotiatedHTTP11, Forced: plan.mustH2}
			if negotiated != alpn.HTTP11 {
				// Unreachable against a conformant peer, which must choose from the offer or fail the
				// handshake. Named rather than collapsed, so a peer that does this is visible instead of
				// being reported as an ordinary http/1.1 negotiation.
				down.Detail = negotiated
			}
		}
	}
	if keep {
		br := bufio.NewReader(conn)
		stop := watchCancel(ctx, conn)
		resp, err := s.exchangeHTTP1(ctx, conn, br, host, plan.http1)
		stop()
		out := s.finish(host, port, useTLS, negotiated, down, nil, nil, remoteIP(conn), err)
		if err == nil && reusableAfter(plan.http1, resp) {
			kept = true
			s.pool.put(key, &idleConn{conn: conn, br: br, negotiated: negotiated, offeredH2: plan.wantH2})
		}
		return resp, out, err
	}
	resp, err := s.writeHTTP1(ctx, conn, host, plan.http1)
	out := s.finish(host, port, useTLS, negotiated, down, nil, nil, remoteIP(conn), err)
	return resp, out, err
}

// release returns a reused connection to the pool when its exchange left it reusable, and closes it
// otherwise.
func (s *Sender) release(key string, ic *idleConn, request, response []byte, err error) {
	if err == nil && reusableAfter(request, response) {
		s.pool.put(key, ic)
		return
	}
	ic.conn.Close()
}

// finish builds one send's outcome, counts it when the exchange actually completed, and returns it stamped
// with what is known about the authority. One function so the counters cannot be updated at some return
// paths and not others.
//
// A send that failed at the transport is returned but not counted, matching AuthorisedSender's own rule
// that such a request is "neither sent nor refused": the protocol report is a record of exchanges that
// happened, and counting an attempt that never reached the peer as protocol coverage would inflate exactly
// the number an operator reads as coverage. The outcome still names the protocol, so a caller reporting the
// failure can say what it was attempted over.
func (s *Sender) finish(
	host string,
	port uint16,
	useTLS bool,
	negotiated string,
	down *Downgrade,
	rewrites []Rewrite,
	rendered []byte,
	serverIP string,
	err error,
) SendOutcome {
	out := newOutcome(negotiated, s.protocols.Lookup(host, port, useTLS), down, rewrites, rendered)
	// Stamp even on a failed send when the connection existed: "where did these bytes go" is
	// answerable by anything that reached a socket, and a dial that connected but then failed
	// still went somewhere real. A failure before any dial leaves it empty.
	out.ServerIP = serverIP
	if err == nil {
		s.protocols.record(out)
	}
	return out
}

// remoteIP is the host half of a connection's remote address, read off the live socket — the
// same fact proxy.serverIPOf records for its leg, so both producers of an exchange row answer
// "which address did this name resolve to *for this request*" the same way. Empty for a nil
// connection or an unparseable address, which a caller reports as absence rather than guessing.
func remoteIP(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return host
}

// sendPlan is what protocol selection decided from the request bytes alone, before any connection
// exists.
type sendPlan struct {
	// wantH2 says whether the dial offers h2. False means block says why not.
	wantH2 bool
	// mustH2 says whether the caller pinned ProtocolPreferenceForceH2 for this send, and is valid only
	// when wantH2: it is the field sendPlan used to be missing entirely (burpsy-react-ui-57yk).
	// planSend switched on only !useTLS and ProtocolPreferenceHTTP1, so Auto and ForceH2 fell through
	// to the same branch and produced byte-identical plans — the preference was parsed at the web
	// layer and then had nowhere to go. wantH2 alone cannot carry "the operator specifically asked for
	// h2" versus "h2 happens to be on offer": both read as true. mustH2 is that missing bit, read back
	// at SendRawOutcome's negotiated-http/1.1 branch to mark the resulting Downgrade as one a Force
	// pin, not Auto, produced — see Downgrade.Forced. It does not change what gets dialled: Force
	// still offers h2 and still falls back on the same terms Auto does (planSend's own comment below,
	// and force_h2_test.go, both predate this field and already fix that half — an h2-only offer would
	// abort the handshake at exactly the target an operator pinning Force is trying to observe).
	mustH2 bool
	// http2 is the request to send if ALPN chooses h2; valid only when wantH2.
	http2 h2Request
	// http1 is the bytes to write if it does not. For HTTP/1.1 input these are the caller's own bytes,
	// unmodified — the whole point of refusing an unfaithful upgrade.
	http1 []byte
	// rewrites are the changes re-expressing the request as h2 makes; reported on a successful h2 send.
	rewrites []Rewrite
	// block is why h2 was not offered; nil when wantH2.
	block *Downgrade
}

// planSend decides, from the bytes and the caller's preference, what to offer and what to write.
//
// The error return is for bytes that cannot be sent at all — a start line claiming HTTP/2 that does not
// parse. That is not a downgrade: there is no HTTP/1.1 request to fall back to, and inventing one would
// send something the caller did not write.
func planSend(raw []byte, useTLS bool, pref ProtocolPreference) (sendPlan, error) {
	if burpsyhttp2.IsHTTP2Request(raw) {
		req, err := h2RequestFromRaw(raw)
		if err != nil {
			return sendPlan{}, err
		}
		// Bytes that already say HTTP/2 have an HTTP/1.1 rendering available, so a target that will not
		// take h2 still gets the request rather than a failed handshake — see renderHTTP1.
		plan := sendPlan{wantH2: true, mustH2: pref == ProtocolPreferenceForceH2, http2: req, http1: renderHTTP1(req)}
		switch {
		case !useTLS:
			plan.wantH2 = false
			plan.mustH2 = false
			plan.block = &Downgrade{Reason: DowngradePlaintextTarget}
		case pref == ProtocolPreferenceHTTP1:
			plan.wantH2 = false
			plan.mustH2 = false
			plan.block = &Downgrade{Reason: DowngradePinnedByCaller}
		}
		return plan, nil
	}

	plan := sendPlan{http1: raw}
	switch {
	case !useTLS:
		plan.block = &Downgrade{Reason: DowngradePlaintextTarget}
		return plan, nil
	case pref == ProtocolPreferenceHTTP1:
		plan.block = &Downgrade{Reason: DowngradePinnedByCaller}
		return plan, nil
	}
	h2, block := planH2(raw)
	if block != nil {
		// Force-h2 cannot change what h2 can carry: the construct that blocks Auto blocks this
		// too. The plan is not marked wantH2, so the dial offers http/1.1 and the bytes go out
		// verbatim with the reason naming the construct — the honest answer to "use h2" when h2
		// has nowhere to put the request. Nor is it marked mustH2: h2 was never offered, so there is
		// nothing a Force pin can be said to have required and then not gotten.
		plan.block = block
		return plan, nil
	}
	plan.wantH2 = true
	plan.mustH2 = pref == ProtocolPreferenceForceH2
	plan.http2 = h2Request{
		Method:    h2.Method,
		Path:      h2.Path,
		Authority: h2.Authority,
		Headers:   h2.Headers,
		Body:      h2.Body,
	}
	plan.rewrites = h2.Rewrites
	return plan, nil
}

// sendHTTP1Plain dials cleartext and writes one request. The dialled address is returned
// alongside the response, because a caller recording the exchange wants where the socket went
// — the same fact the TLS path reads off its own connection (burpsy-react-ui-gj4f).
//
// With keep set, a connection the exchange left reusable is kept for the next send (keepalive.go).
func (s *Sender) sendHTTP1Plain(ctx context.Context, host string, port uint16, raw []byte, keep bool) ([]byte, string, error) {
	conn, err := s.dialPlain(ctx, host, port)
	if err != nil {
		return nil, "", fmt.Errorf("connection failed: %w", err)
	}
	ip := remoteIP(conn)
	br := bufio.NewReader(conn)
	// Cancelling the context must unblock the read, not merely be noticed after it. See cancel.go.
	stop := watchCancel(ctx, conn)
	resp, err := s.exchangeHTTP1(ctx, conn, br, host, raw)
	stop()
	if keep && err == nil && reusableAfter(raw, resp) {
		s.pool.put(poolKey(host, port, false), &idleConn{conn: conn, br: br})
	} else {
		conn.Close()
	}
	return resp, ip, err
}

// writeHTTP1 writes one request on an open connection and reads exactly one response back.
//
// host is carried in rather than read off the connection because it decides two things the address
// cannot: whether this authority's responses are declared open-ended, and — under a resolution
// override — the connection's remote address is not the host at all.
func (s *Sender) writeHTTP1(ctx context.Context, conn net.Conn, host string, raw []byte) ([]byte, error) {
	return s.exchangeHTTP1(ctx, conn, bufio.NewReader(conn), host, raw)
}

// exchangeHTTP1 is writeHTTP1 on a connection whose reader is kept with it, which a kept-alive
// connection needs: bytes buffered past one response belong to the connection, not to the read.
func (s *Sender) exchangeHTTP1(ctx context.Context, conn net.Conn, br *bufio.Reader, host string, raw []byte) ([]byte, error) {
	settings := s.Network()
	s.setDeadline(ctx, conn, host)
	if _, err := conn.Write(raw); err != nil {
		return nil, fmt.Errorf("write failed: %w", explainCancellation(ctx, err))
	}
	// Read exactly one *final* response; keep-alive connections never EOF, and an interim 1xx is not
	// the response — see read.go.
	response, err := readResponse(
		br,
		settings.Continue.Understand100,
		settings.Streaming.isStreaming(host),
		eventStreamPromoter(ctx, conn, settings),
	)
	if err != nil {
		// explainCancellation, because an unblocked read reports a deadline error: reporting a
		// cancelled send as "read failed: i/o timeout" would blame the target for a decision the
		// operator made. See cancel.go.
		return nil, fmt.Errorf("read failed: %w", explainCancellation(ctx, err))
	}
	return response, nil
}

// setDeadline bounds one exchange by the context's deadline when it has one, and by the configured
// read timeout otherwise. The context wins because a caller that set one is describing the whole
// operation, which the configured per-send timeout knows nothing about.
//
// The per-send bound now comes from NetworkSettings.readTimeout rather than one Timeout standing in for
// everything, which is what lets a declared streaming host wait longer than an ordinary one without
// every other send waiting that long too. Zero means no deadline of our own — the previous code could
// not express that, because a zero SenderConfig.Timeout set a deadline in the past and failed every
// read instantly.
func (s *Sender) setDeadline(ctx context.Context, conn net.Conn, host string) {
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		return
	}
	if bound := s.Network().readTimeout(host); bound > 0 {
		conn.SetDeadline(time.Now().Add(bound))
	}
}

// WithTimeout sets the total timeout for the sender, rebuilding the transport so the change reaches
// connections opened after it.
// CarriesPlatformAuth reports whether this sender was built with a
// platform-authentication lookup attached.
//
// # Why this is exported at all
//
// It exists so the panel can tell the operator the truth. Both network-authentication
// sources are constructor-time properties of a Sender — the client-certificate hook is
// installed into the http.Transport by NewSender, and an http.Transport must not have
// its dial hooks rewritten after first use — so there is no honest way to attach one to
// a running sender, and this package deliberately offers no method that pretends
// otherwise.
//
// The consequence is a wiring order that can be got wrong: a Sender built without these
// and a credential store the API can write to would give an operator a rule on the panel
// that no request ever carries. That is precisely the "partial result looking complete"
// failure this codebase treats as a bug, so the API asks these two questions and says
// what it finds instead of assuming. cmd/burpsy builds every sender with both attached,
// so the shipped binary answers true; a Server assembled without them answers false and
// the panel says the rules are stored but not presented.
func (s *Sender) CarriesPlatformAuth() bool { return s.config.PlatformAuth != nil }

// CarriesClientCerts reports whether this sender was built with a client-certificate
// source attached. See CarriesPlatformAuth for why this is a question worth asking.
func (s *Sender) CarriesClientCerts() bool { return s.config.ClientCerts != nil }

// WithTimeout sets the timeout for the sender.
func (s *Sender) WithTimeout(timeout time.Duration) *Sender {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Timeout = timeout
	s.net.Timeouts.TotalMS = int(timeout / time.Millisecond)
	if total := s.net.Timeouts.TotalMS; total > 0 && s.net.Timeouts.ConnectMS > total {
		s.net.Timeouts.ConnectMS = total
	}
	s.client = buildClient(s.config, s.net, s.carrier)
	return s
}

// WithTLSVerify sets TLS verification.
func (s *Sender) WithTLSVerify(verify bool) *Sender {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.TLSVerify = verify
	// A fresh transport rather than a write into the live one's tls.Config: that config is read by
	// every handshake, including one happening on another goroutine right now.
	s.client = buildClient(s.config, s.net, s.carrier)
	return s
}

// tlsPolicy resolves the verification decision, root pool and protocol floor for one dial.
//
// The root pool is built once per distinct CA path and cached, because it is expensive to construct
// and it is on the handshake path for every TLS send. A path that fails to load resolves to no pool and
// the system one — a send that cannot read the operator's CA still reaches the target, and says so by
// failing verification if the target's issuer is not in the system pool, which is a clearer outcome
// than refusing to dial at all.
//
// The cache is a mutex-guarded map rather than a sync.Once because the path can change while the sender
// runs, which is the whole point of the setting being live.
func (s *Sender) tlsPolicy(settings NetworkSettings) (verify bool, roots *x509.CertPool, minVersion uint16) {
	verify = s.config.TLSVerify
	minVersion = settings.TLS.MinVersion
	path := strings.TrimSpace(settings.TLS.RootCAPath)
	if path == "" {
		return verify, nil, minVersion
	}

	s.tlsMu.Lock()
	defer s.tlsMu.Unlock()
	if s.tlsCAs == nil {
		s.tlsCAs = make(map[string]*x509.CertPool)
	}
	if pool, seen := s.tlsCAs[path]; seen {
		return verify, pool, minVersion
	}
	pool := loadCABundle(path)
	s.tlsCAs[path] = pool
	return verify, pool, minVersion
}

// loadCABundle reads a PEM file into a pool that also holds the system roots, reporting nil when the
// file cannot be read or contains no certificates.
//
// Nil rather than an error because a dial has no way to report "your CA file is missing" that is more
// useful than the handshake failure it causes, and because refusing the dial would mean one missing
// file silently disables every TLS send rather than only the targets it was meant to cover.
func loadCABundle(path string) *x509.CertPool {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil
	}
	return pool
}

// WithCookieJar attaches the cookie store a followed redirect chain replays from, and returns the
// sender so it can be chained onto construction.
//
// Nil is a no-op rather than a clear, matching every other With* here: a sender that never opted in
// has no jar, and Redirects.ReplayCookies with no jar simply sends nothing, which is the honest
// reading of a setting whose store is not there.
func (s *Sender) WithCookieJar(jar CookieJar) *Sender {
	if s != nil {
		s.jar = jar
	}
	return s
}

// CookieJar returns the attached cookie store, or nil.
func (s *Sender) CookieJar() CookieJar {
	if s == nil {
		return nil
	}
	return s.jar
}

// WithUpstreamCarrier attaches the global SOCKS layer to this sender's egress legs.
//
// The SAME instance must be handed to the proxy and the web server, for the reason the upstream
// policy's own wiring says: two carriers would let the panel describe a layer only one surface
// honours.
func (s *Sender) WithUpstreamCarrier(carrier *upstream.Carrier) *Sender {
	if s == nil {
		return s
	}
	s.carrier = carrier
	// The config too, because the next client rebuild reads from there rather than from the Sender —
	// a WithTLSVerify or a settings change would otherwise drop the carrier silently.
	if s.config != nil {
		s.config.UpstreamCarrier = carrier
	}
	// And the CLIENT is rebuilt now, not on the next edit. The client captured the carrier at
	// construction, so setting the field afterwards would leave the transport dialling through a nil
	// layer while the field reported one — the live pass caught exactly that: the console reported the
	// carrier configured, every dial site read the field, and the connection still went out direct.
	s.mu.Lock()
	s.client = buildClient(s.config, s.net, carrier)
	s.mu.Unlock()
	return s
}

// UpstreamCarrier returns the attached global SOCKS layer, or nil.
func (s *Sender) UpstreamCarrier() *upstream.Carrier {
	if s == nil {
		return nil
	}
	return s.carrier
}
