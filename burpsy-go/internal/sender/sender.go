// Package sender provides HTTP request sending capabilities.
package sender

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
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
	// protocols is what this sender has learnt about each authority's ALPN, plus the protocol-coverage
	// counters. One per Sender rather than one per authority handle, so an intruder run and the scan
	// that preceded it share what either of them discovered — see protocol.go. Its own state is
	// atomic, so it is deliberately outside mu.
	protocols *ProtocolCache
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
	// dialled is the one thing AuthorisedSender exists to pin down. burpsy's proxy listener does not
	// route through this field (internal/proxy dials origins itself), so nothing in the tool
	// depended on the old behaviour.
	ProxyURL  string
	UserAgent string
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
func NewSender(config *SenderConfig) *Sender {
	if config == nil {
		config = DefaultSenderConfig()
	}
	settings := networkFromConfig(config)
	return &Sender{
		client:    buildClient(config, settings),
		config:    config,
		net:       settings,
		protocols: newProtocolCache(),
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
func buildClient(config *SenderConfig, settings NetworkSettings) *http.Client {
	transport := &http.Transport{
		// The dial is wrapped rather than handed over so the hostname-resolution table applies to the
		// typed path too. The transport hands us the address it computed from the URL; we substitute
		// only the host part, which leaves the TLS ServerName the transport derived from that same URL
		// untouched — the override is meant to change where the request goes, never which vhost it
		// asks for.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return settings.dialer().DialContext(ctx, network, settings.overrideAddr(addr))
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   time.Duration(settings.Timeouts.ConnectMS) * time.Millisecond,
		ResponseHeaderTimeout: time.Duration(settings.Timeouts.ReadMS) * time.Millisecond,
		ExpectContinueTimeout: time.Duration(settings.Continue.ExpectTimeoutMS) * time.Millisecond,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.TLSVerify,
		},
	}

	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			// A proxy the operator asked for and that cannot be used must fail the send, not
			// silently become a direct connection: "my traffic went straight to the target" is the
			// one outcome an operator who configured a proxy did not ask for.
			transport.Proxy = func(*http.Request) (*url.URL, error) {
				return nil, fmt.Errorf("sender proxy URL %q is unusable: %w", config.ProxyURL, err)
			}
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
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
	s.client = buildClient(s.config, normalised)
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
// The two arguments alpn.Dialer.Dial takes for what looks like one thing are why the hostname-resolution
// table can work at all on TLS: serverName stays the host the operator named, so SNI and certificate
// verification are still about that name, while addr is where the bytes go. An override that rewrote
// both would test whatever the address serves by default instead of the vhost under test.
func (s *Sender) dialTLS(ctx context.Context, host string, port uint16, offer []string) (*tls.Conn, string, error) {
	settings := s.Network()
	dialer := alpn.Dialer{
		InsecureSkipVerify: !s.tlsVerify(),
		Timeout:            time.Duration(settings.Timeouts.ConnectMS) * time.Millisecond,
		Resolver:           settings.Resolution.resolver(),
	}
	return dialer.Dial(ctx, host, settings.dialAddress(host, port), offer)
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
func (s *Sender) Send(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()

	target, err := effectiveTarget(req)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
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

	httpResp, err := s.httpClient().Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	headers := make(map[string]string)
	for k, vv := range httpResp.Header {
		if len(vv) > 0 {
			headers[k] = vv[0]
		}
	}

	duration := time.Since(startTime)

	return &Response{
		StatusCode: httpResp.StatusCode,
		Status:     httpResp.Status,
		Headers:    headers,
		Body:       body,
		Version:    httpResp.Proto,
		Duration:   duration,
		Outcome:    s.observe(target, httpResp),
	}, nil
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
	return s.finish(host, port, isTLS, negotiated, downgradeFromResponse(resp, isTLS, negotiated), nil, nil, nil)
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
	plan, err := planSend(rawRequest, useTLS, pref)
	if err != nil {
		return nil, SendOutcome{}, err
	}

	if !useTLS {
		// No ALPN exists on cleartext, so nothing was negotiated and nothing is learnt about this
		// authority beyond what cleartext implies.
		resp, err := s.sendHTTP1Plain(ctx, host, port, plan.http1)
		out := s.finish(host, port, useTLS, "", plan.block, nil, nil, err)
		return resp, out, err
	}

	conn, negotiated, err := s.dialTLS(ctx, host, port, alpn.EgressOffer(plan.wantH2))
	if err != nil {
		return nil, SendOutcome{}, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()
	if plan.wantH2 {
		// Learnt only when h2 was actually offered. A handshake that offered http/1.1 alone and got
		// http/1.1 back is no evidence at all about whether the target speaks h2, and recording it as
		// ProtocolSupportHTTP11 would turn our own choice into a claim about the target.
		s.protocols.learn(host, port, useTLS, negotiated)
	}

	if plan.wantH2 && negotiated == alpn.H2 {
		s.setDeadline(ctx, conn, host)
		resp, err := sendOverH2(ctx, conn, plan.http2)
		out := s.finish(host, port, useTLS, negotiated, nil, plan.rewrites, plan.http2.render(), err)
		return resp, out, err
	}

	down := plan.block
	if down == nil {
		// h2 was offered and did not happen: the two ways that can go are different findings, so they
		// are different reasons.
		if negotiated == "" {
			down = &Downgrade{Reason: DowngradeNoALPN}
		} else {
			down = &Downgrade{Reason: DowngradeNegotiatedHTTP11}
			if negotiated != alpn.HTTP11 {
				// Unreachable against a conformant peer, which must choose from the offer or fail the
				// handshake. Named rather than collapsed, so a peer that does this is visible instead of
				// being reported as an ordinary http/1.1 negotiation.
				down.Detail = negotiated
			}
		}
	}
	resp, err := s.writeHTTP1(ctx, conn, host, plan.http1)
	out := s.finish(host, port, useTLS, negotiated, down, nil, nil, err)
	return resp, out, err
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
	err error,
) SendOutcome {
	out := newOutcome(negotiated, s.protocols.Lookup(host, port, useTLS), down, rewrites, rendered)
	if err == nil {
		s.protocols.record(out)
	}
	return out
}

// sendPlan is what protocol selection decided from the request bytes alone, before any connection
// exists.
type sendPlan struct {
	// wantH2 says whether the dial offers h2. False means block says why not.
	wantH2 bool
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
		plan := sendPlan{wantH2: true, http2: req, http1: renderHTTP1(req)}
		switch {
		case !useTLS:
			plan.wantH2 = false
			plan.block = &Downgrade{Reason: DowngradePlaintextTarget}
		case pref == ProtocolPreferenceHTTP1:
			plan.wantH2 = false
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
		plan.block = block
		return plan, nil
	}
	plan.wantH2 = true
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

// sendHTTP1Plain dials cleartext and writes one request.
func (s *Sender) sendHTTP1Plain(ctx context.Context, host string, port uint16, raw []byte) ([]byte, error) {
	settings := s.Network()
	conn, err := settings.dialer().DialContext(ctx, "tcp", settings.dialAddress(host, port))
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()
	return s.writeHTTP1(ctx, conn, host, raw)
}

// writeHTTP1 writes one request on an open connection and reads exactly one response back.
//
// host is carried in rather than read off the connection because it decides two things the address
// cannot: whether this authority's responses are declared open-ended, and — under a resolution
// override — the connection's remote address is not the host at all.
func (s *Sender) writeHTTP1(ctx context.Context, conn net.Conn, host string, raw []byte) ([]byte, error) {
	settings := s.Network()
	s.setDeadline(ctx, conn, host)
	if _, err := conn.Write(raw); err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}
	// Read exactly one *final* response; keep-alive connections never EOF, and an interim 1xx is not
	// the response — see read.go.
	response, err := readResponse(
		bufio.NewReader(conn),
		settings.Continue.Understand100,
		settings.Streaming.isStreaming(host),
	)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
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
func (s *Sender) WithTimeout(timeout time.Duration) *Sender {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Timeout = timeout
	s.net.Timeouts.TotalMS = int(timeout / time.Millisecond)
	if total := s.net.Timeouts.TotalMS; total > 0 && s.net.Timeouts.ConnectMS > total {
		s.net.Timeouts.ConnectMS = total
	}
	s.client = buildClient(s.config, s.net)
	return s
}

// WithTLSVerify sets TLS verification.
func (s *Sender) WithTLSVerify(verify bool) *Sender {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.TLSVerify = verify
	// A fresh transport rather than a write into the live one's tls.Config: that config is read by
	// every handshake, including one happening on another goroutine right now.
	s.client = buildClient(s.config, s.net)
	return s
}
