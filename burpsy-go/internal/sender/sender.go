// Package sender provides HTTP request sending capabilities.
package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/httputil"
)

// Sender handles HTTP request sending.
type Sender struct {
	client *http.Client
	config *SenderConfig
	// protocols is what this sender has learnt about each authority's ALPN, plus the protocol-coverage
	// counters. One per Sender rather than one per authority handle, so an intruder run and the scan
	// that preceded it share what either of them discovered — see protocol.go.
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
	// ClientCerts, when set, supplies the TLS client certificate to present to a host that asks for
	// one. Nil means none is ever offered — the behaviour before client TLS authentication existed.
	//
	// The type is alpn's one-method interface, not internal/netauth's concrete store, so this package
	// keeps its existing dependency set and a test can bind one certificate without building a
	// credential store. Held here rather than on Sender because both dial paths need it and both read
	// their knobs from the config.
	ClientCerts alpn.ClientCertSource
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
func NewSender(config *SenderConfig) *Sender {
	if config == nil {
		config = DefaultSenderConfig()
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
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
			dialer := alpn.Dialer{
				InsecureSkipVerify: !config.TLSVerify,
				Timeout:            config.Timeout,
				ClientCerts:        config.ClientCerts,
			}
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

	return &Sender{
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		config:    config,
		protocols: newProtocolCache(),
	}
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
// A client certificate configured for this host is presented here, which covers every raw-bytes TLS
// path in the package at once: SendRawOutcome, ProtocolFor's discovery handshake, dialOne's
// pipelining and desync probes, and dialForProgram's frame programs all funnel through this one
// function.
func (s *Sender) dialTLS(ctx context.Context, host string, port uint16, offer []string) (*tls.Conn, string, error) {
	dialer := alpn.Dialer{
		InsecureSkipVerify: !s.config.TLSVerify,
		Timeout:            s.config.Timeout,
		ClientCerts:        s.config.ClientCerts,
	}
	return dialer.Dial(ctx, host, net.JoinHostPort(host, strconv.Itoa(int(port))), offer)
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

	headers := make(map[string]string, len(req.Headers)+1)
	haveUserAgent := false
	for k, v := range req.Headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		if strings.EqualFold(k, "User-Agent") {
			haveUserAgent = true
		}
		headers[k] = v
	}
	if !haveUserAgent && s.config.UserAgent != "" {
		// Mirrors what Send fills in, so the rendered request is the one that would be sent rather
		// than one header short of it.
		headers["User-Agent"] = s.config.UserAgent
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
		httpReq.Header.Set("User-Agent", s.config.UserAgent)
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

	httpResp, err := s.client.Do(httpReq)
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
		s.setDeadline(ctx, conn)
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
	resp, err := s.writeHTTP1(ctx, conn, plan.http1)
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
	dialer := &net.Dialer{Timeout: s.config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()
	return s.writeHTTP1(ctx, conn, raw)
}

// writeHTTP1 writes one request on an open connection and reads exactly one response back.
func (s *Sender) writeHTTP1(ctx context.Context, conn net.Conn, raw []byte) ([]byte, error) {
	s.setDeadline(ctx, conn)
	if _, err := conn.Write(raw); err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}
	// Read exactly one response; keep-alive connections never EOF.
	response, err := httputil.ReadHTTPResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	return response, nil
}

// setDeadline bounds one exchange by the context's deadline when it has one, and by the configured
// timeout otherwise. The context wins because a caller that set one is describing the whole operation,
// which the configured per-send timeout knows nothing about.
func (s *Sender) setDeadline(ctx context.Context, conn net.Conn) {
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		return
	}
	conn.SetDeadline(time.Now().Add(s.config.Timeout))
}

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
	s.config.Timeout = timeout
	s.client.Timeout = timeout
	return s
}

// WithTLSVerify sets TLS verification.
func (s *Sender) WithTLSVerify(verify bool) *Sender {
	s.config.TLSVerify = verify
	if transport, ok := s.client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig.InsecureSkipVerify = !verify
	}
	return s
}
