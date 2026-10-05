package proxy

import (
	"strings"
	"sync"
	"time"
)

// This file is the proxy's half of Burp's open-ended response handling.
//
// # The defect this exists to fix
//
// Burp's own documentation (settings/network/http.html:96-104) names the failure in one breath:
// waiting for a response to end before forwarding any of it means that for an open-ended response
// "none of the response is ever forwarded", and the fix is that "The Proxy passes these responses
// straight through to the client in real time." burpsy buffered every response — httputil's
// ReadResponseBody copies an unframed body until EOF, and on an SSE stream or a long-poll EOF never
// comes — so a browser got nothing at all until the connection's own deadline eventually fired. To
// the client that is a hung target (burpsy-react-ui-wet3).
//
// The sender already had the concept: internal/sender's StreamingSettings is a per-host list plus a
// window, and internal/sender/read.go drains a declared host's stream instead of erroring on it.
// This is that policy on the proxy leg, over the same persisted settings, so one list in the console
// governs both.
//
// # Why the list is an allowlist and not a sniff
//
// A response with no Content-Length and no Transfer-Encoding is *usually* open-ended, and usually is
// not: an HTTP/1.0 close-delimited body has the same shape and does end. Streaming every unframed
// response would break the ordinary one — its bytes would reach the client before Match & Replace
// and the intercept hold had seen them, which is the whole reason those run first. So the operator
// names the hosts, exactly as they do for the sender, and everything else keeps the buffered path.
// That is also the only shape that can be correct: a proxy cannot tell "this stream is still
// coming" from "this body ended and the peer forgot a header" without waiting, and waiting is the
// defect.

// DefaultStreamingWindow is how long an open-ended read runs when the operator has named no window
// of their own.
//
// 30 seconds matches what the proxy already allows an ordinary response to take, so a stream gets
// the same patience an ordinary exchange does before burpsy gives up and records what arrived. It is
// not a stream's natural length — an SSE feed can run for hours — but it is long enough that a
// browser renders every event a target emits while an operator is watching, and bounded enough that
// one chatty endpoint does not pin a goroutine and a connection indefinitely. An operator who wants
// longer sets it; one who wants it shorter gets the same bound a normal request already had.
const DefaultStreamingWindow = 30 * time.Second

// MaxStreamingWindow bounds the configured window.
//
// Twenty minutes, the same ceiling the sender's MaxTimeoutMS sets on its own streaming knob. The two
// are the same decision — how long one operator will let one response run — and letting the proxy
// accept a larger value than the sender would mean the same console config behaved differently
// depending on which tool sent the request.
const MaxStreamingWindow = 20 * time.Minute

// StreamingPolicy is the live set of hosts whose responses are forwarded as they arrive.
//
// Mutable through Set, guarded by a mutex, and read on the response path of every relay goroutine —
// which is why it is a holder rather than a plain struct passed at construction. The same
// arrangement internal/proxy's Options and TlsPolicy already use, for the same reason: an operator
// edits these in Settings while traffic is flowing, and a snapshot taken at startup would make the
// edit a lie until a restart.
type StreamingPolicy struct {
	mu     sync.RWMutex
	hosts  []string
	window time.Duration
	// unmatched counts responses that were streamed because nothing framed them, on a host the
	// operator did not name. It exists so a support conversation about "my event stream shows up
	// empty" can be answered from the counter rather than guessed at.
	unmatched int

	// The three response-handling switches, Burp's streaming_responses.* keys (Zrgt.java:88,100,111).
	// They govern what the operator does with a response once it is recognised as streaming, where the
	// host list and the window govern which responses that is and for how long. Defaults reproduce the
	// behaviour that shipped before the switches existed, so a policy nobody has touched behaves as it
	// did: streamed bodies are stored, chunk metadata is left exactly as it arrived, and a framed
	// text/event-stream response takes the buffered path like any other framed response.
	store                  bool
	stripChunked           bool
	treatEventStreamStream bool
}

// NewStreamingPolicy returns a policy with no hosts declared, which is the correct default: a proxy
// that streamed every unframed response would break close-delimited HTTP/1.0 bodies and the Match &
// Replace rules that run before the write. The window is the default one so a policy that has had
// its host list set is immediately usable.
func NewStreamingPolicy() *StreamingPolicy {
	// store defaults on: before the switch existed the proxy recorded every streamed response, so an
	// embedder that never touches the policy keeps that. The other two default off for the same
	// reason — off is what the code did before they existed.
	return &StreamingPolicy{window: DefaultStreamingWindow, store: true}
}

// WithStreaming attaches the streaming policy, so a host the operator declares in Settings → Network
// is forwarded in real time through the proxy leg as well as the sender leg.
//
// The same pointer must be handed to the web server (web.Server.WithStreaming) so an edit in the
// console reaches this leg. Two policies would let the panel describe a list the relay does not
// obey, which is the failure WithOptions and WithUpstream exist to prevent.
func (c *ProxyConfig) WithStreaming(policy *StreamingPolicy) *ProxyConfig {
	if policy != nil {
		c.streaming = policy
	}
	return c
}

// Streaming returns the attached policy, or a default one when none was attached.
//
// Never nil, for the same reason Options is never nil: a Server built by a caller that never called
// WithStreaming still has to answer "is this host open-ended?" on every response, and a nil check at
// each of those call sites is a place one of them will be forgotten. A default policy declares no
// hosts, so an embedder that never opted in gets the buffered behaviour it had before.
func (c *ProxyConfig) Streaming() *StreamingPolicy {
	if c.streaming == nil {
		c.streaming = NewStreamingPolicy()
	}
	return c.streaming
}

// Set replaces the declared hosts and the window.
//
// An empty host list is accepted and means "no host is declared", which is the honest reading of an
// operator clearing the field — it turns streaming off rather than leaving the previous list in
// force. A window of zero means the default, and a negative one is refused: a window that has already
// passed would stream nothing at all, which looks exactly like the bug this policy fixes.
func (p *StreamingPolicy) Set(hosts []string, window time.Duration) error {
	if window < 0 {
		return errNegativeStreamingWindow(window)
	}
	if window == 0 {
		window = DefaultStreamingWindow
	}
	if window > MaxStreamingWindow {
		window = MaxStreamingWindow
	}
	cleaned := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			cleaned = append(cleaned, h)
		}
	}
	p.mu.Lock()
	p.hosts = cleaned
	p.window = window
	p.mu.Unlock()
	return nil
}

// SetResponseHandling replaces the three response-handling switches.
//
// It is separate from Set because the two answer different questions and change on different edits in
// the console: Set is the host list and the window — which responses stream and for how long —
// while these three are what the operator does with a streamed response once it is recognised. Keeping
// them apart also means the existing Set callers and their tests do not grow a signature for a
// decision they do not make.
func (p *StreamingPolicy) SetResponseHandling(store, stripChunkedMetadata, treatEventStreamAsStreaming bool) {
	p.mu.Lock()
	p.store = store
	p.stripChunked = stripChunkedMetadata
	p.treatEventStreamStream = treatEventStreamAsStreaming
	p.mu.Unlock()
}

// Store reports whether a streamed response's body is recorded to history.
//
// When off, the streamed bytes still reach the client live — the switch never changes what the
// browser receives — but history keeps the head and a note instead of the body, which is Burp's
// "Store streaming responses (may result in large temp files)" turned off: the operator watched the
// stream and chose not to pay the temp-file cost of keeping it.
func (p *StreamingPolicy) Store() bool {
	if p == nil {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.store
}

// StripChunkedMetadata reports whether chunk framing is removed from a streamed chunked response.
//
// When on, a chunked streamed response is forwarded with its Transfer-Encoding header dropped and its
// decoded payload sent close-delimited, which is what a client that cannot be told the body is chunked
// while it is in fact being dechunked actually needs. When off, the response is forwarded exactly as
// it arrived, which is the behaviour that shipped.
func (p *StreamingPolicy) StripChunkedMetadata() bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stripChunked
}

// TreatEventStreamAsStreaming reports whether a framed text/event-stream response is streamed.
//
// A frameless or chunked event stream already streams on its framing alone; this switch is for the
// one shape that does not — an SSE response that carries a Content-Length and would otherwise be
// buffered until it ended. With it on, a response whose Content-Type is text/event-stream streams
// however it is framed, which is Burp's "Treat text/event-stream responses as streaming".
func (p *StreamingPolicy) TreatEventStreamAsStreaming() bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.treatEventStreamStream
}

// Hosts returns the declared host list, copied.
func (p *StreamingPolicy) Hosts() []string {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.hosts...)
}

// Window returns how long an open-ended read runs.
func (p *StreamingPolicy) Window() time.Duration {
	if p == nil {
		return DefaultStreamingWindow
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.window
}

// IsStreaming reports whether host's responses are declared open-ended.
//
// Matching is the sender's rule, kept identical so one list behaves the same in both tools: an entry
// is either an exact hostname or a `*.example.com` suffix pattern, compared case-insensitively
// against the hostname alone. A pattern is matched with its leading dot and the wildcard removed, so
// `*.example.com` covers `api.example.com` and not `example.com` itself — which is the distinction
// an operator means when they write the wildcard, and the sender's rule already.
func (p *StreamingPolicy) IsStreaming(host string) bool {
	if p == nil {
		return false
	}
	needle := strings.ToLower(hostnameOf(host))
	if needle == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pattern := range p.hosts {
		if pattern == needle {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if strings.HasSuffix(needle, suffix) {
				return true
			}
		}
	}
	return false
}

// NoteUnframed records that a response with no framing was seen on a host the operator has not
// declared open-ended.
//
// This is a diagnostic, not a decision. The response is still streamed — an unframed response that
// never ends cannot be served any other way without hanging the client, and a proxy that buffered it
// is the defect this whole path fixes. What the counter answers is the question an operator cannot
// otherwise answer: "the stream arrives empty, is the proxy holding it?" A non-zero count says the
// proxy saw a response it could not frame and streamed it anyway, which is the expected shape for a
// stream and the reason to add the host to the list.
func (p *StreamingPolicy) NoteUnframed() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.unmatched++
	p.mu.Unlock()
}

// UnframedResponses reports how many responses were streamed because nothing framed them on an
// undeclared host.
func (p *StreamingPolicy) UnframedResponses() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.unmatched
}

// hostnameOf strips a port and brackets from an authority, so "api.example.com:8443" and
// "[::1]:443" both reduce to something the pattern list can be compared against.
func hostnameOf(host string) string {
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end > 0 {
			return host[1:end]
		}
		return host
	}
	if idx := strings.LastIndexByte(host, ':'); idx > 0 {
		// Only strip when what follows is digits: a bare IPv6 literal has several colons and no port.
		if isAllDigits(host[idx+1:]) {
			return host[:idx]
		}
	}
	return host
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func errNegativeStreamingWindow(window time.Duration) error {
	return &streamingWindowError{window: window}
}

type streamingWindowError struct{ window time.Duration }

func (e *streamingWindowError) Error() string {
	return "the open-ended response window cannot be negative: " +
		e.window.String() + " has already passed, so it would stream nothing at all"
}
