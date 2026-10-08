package web

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// repeaterSendOptions is one send's overrides — Burp Repeater's config-override menu, carried per
// request rather than as global state. Every field is optional and absent means "the standing
// behaviour": the redirect policy falls back to the network settings, the protocol preference to
// auto, and the request transforms to off. A per-send override must not have to mutate the global
// table to take effect — that would be raced by every other send in the process.
//
// What is deliberately absent: an ALPN override (the sender's protocol choice is per-authority
// cached and h2 carries no ALPN knob a raw-byte send could honour — offering it would be a switch
// that does nothing), and "process cookies in redirections" as a separate switch (hops are built by
// sender.FollowRedirects, which does not replay cookies; the honest answer is that the feature does
// not exist yet, not a checkbox that lies).
type repeaterSendOptions struct {
	// RedirectMode overrides the network settings' policy for this one send: "never", "on_site",
	// "in_scope", "always", or empty for the standing policy. The scope still authorises every hop —
	// see sender.RedirectAlways for why "always" here is not Burp's "anywhere".
	RedirectMode string `json:"redirect_mode,omitempty"`
	// ProtocolPreference pins the transport: "auto" (the default), "http1" to put the bytes on
	// the wire as written, or "http2" to require h2 when the request is carriable (both pins are
	// reported as downgrades when they do not happen, never silent — see ProtocolPreferenceHTTP1
	// and ProtocolPreferenceForceH2). Still deliberately absent: an ALPN override, which no
	// raw-byte send could honour.
	ProtocolPreference string `json:"protocol_preference,omitempty"`
	// ProcessCookies attaches the session coordinator's cookie jar for the target when the request
	// carries no Cookie header of its own. A header the operator wrote always wins.
	ProcessCookies bool `json:"process_cookies,omitempty"`
	// StripConnection removes any Connection header before sending. Burp's switch exists because a
	// replayed capture's hop-by-hop header can break the fresh connection a replay dials.
	StripConnection bool `json:"strip_connection,omitempty"`
	// NormalizeLineEndings rewrites bare LF to CRLF across the request. A request pasted from a
	// Unix editor has LF endings, and some servers treat the bare-LF request line as malformed.
	NormalizeLineEndings bool `json:"normalize_line_endings,omitempty"`
	// UpdateContentLength recomputes Content-Length from the body when a body is present. An
	// operator who edited a body without fixing the header sends a request that truncates or
	// overruns; this makes the header follow the body instead of the other way round.
	UpdateContentLength bool `json:"update_content_length,omitempty"`
	// ResponseTimeoutMS is Burp's per-request response timeout (RequestOptions.withResponseTimeout,
	// burpsy-react-ui-mmca): how long this send waits for its response, in place of the network
	// settings' read timeout — for this send only. A deliberately slow time-based probe in one tab
	// used to mean raising the global read timeout for every tool. Nil is the standing read timeout.
	// It rides the send's context (sender.WithSendOptions), so it bounds every hop of a followed
	// redirect chain too and never mutates NetworkSettings.
	ResponseTimeoutMS *int64 `json:"response_timeout_ms,omitempty"`
	// StreamingTimeoutMS is Burp's per-tab "Streaming response timeout" (burpsy-react-ui-of0z): how
	// long this send reads a response it treats as streaming before returning what arrived — see
	// sender.SendOptions.StreamingTimeout for which responses those are. 0 is no cutoff (Burp's own
	// "set it to 0"); nil is the network settings' streaming window and promotion rule.
	StreamingTimeoutMS *int64 `json:"streaming_timeout_ms,omitempty"`
	// UnpackResponses is Burp's "Unpack compressed responses" (of0z). Nil is Burp's default, ON: a
	// gzip- or deflate-encoded response is also returned decoded (response_unpacked) for the pane to
	// show. false shows the compressed bytes. Display only either way — the stored response is always
	// the bytes that arrived.
	UnpackResponses *bool `json:"unpack_responses,omitempty"`
	// H2ConnectionReuse is Burp's "HTTP/2 connection reuse" (burpsy-react-ui-adkx): this tab's h2
	// sends ride one connection per target, kept open between sends (idle TTL repeaterH2SessionTTL),
	// and each answer says whether it was the connection's first request ("new") or a later one
	// ("reused"). Off — every send the first on a fresh connection — is burpsy's default, where
	// Burp's is on; gaps.md records it.
	H2ConnectionReuse bool `json:"h2_connection_reuse,omitempty"`
	// EnforceProtocolCrossDomain is Burp's "Use selected protocol for cross-domain redirects"
	// (adkx): a followed hop to another host uses the protocol that carried this send, instead of
	// negotiating its own. Off (Burp's default) negotiates each hop as normal.
	EnforceProtocolCrossDomain bool `json:"enforce_protocol_cross_domain,omitempty"`
}

// unpack reports whether this send's response is unpacked for display: Burp's default, on, unless
// the tab turned it off.
func (o repeaterSendOptions) unpack() bool {
	return o.UnpackResponses == nil || *o.UnpackResponses
}

// validate refuses the whole options object when any key it names is not understood, naming the key
// — the same validate-all-before-apply contract the proxy options PUT uses. A partial apply would
// send bytes shaped by an option the caller believes was something else.
func (o repeaterSendOptions) validate() error {
	switch sender.RedirectMode(o.RedirectMode) {
	case "", sender.RedirectNever, sender.RedirectOnSite, sender.RedirectInScope, sender.RedirectAlways:
	default:
		return fmt.Errorf("redirect_mode: unknown mode %q (want never, on_site, in_scope, always, or empty for the standing policy)", o.RedirectMode)
	}
	switch o.ProtocolPreference {
	case "", "auto", "http1", "http2":
	default:
		return fmt.Errorf("protocol_preference: unknown preference %q (want auto, http1, http2, or empty for auto)", o.ProtocolPreference)
	}
	if o.ResponseTimeoutMS != nil {
		if err := sender.ValidateResponseTimeoutMS("response_timeout_ms", *o.ResponseTimeoutMS); err != nil {
			return err
		}
	}
	if o.StreamingTimeoutMS != nil {
		if err := sender.ValidateStreamingTimeoutMS("streaming_timeout_ms", *o.StreamingTimeoutMS); err != nil {
			return err
		}
	}
	return nil
}

// sendContext is ctx carrying this send's response timeout, or ctx itself when there is none. Only
// called post-validate.
func (o repeaterSendOptions) sendContext(ctx context.Context) context.Context {
	if o.ResponseTimeoutMS == nil && o.StreamingTimeoutMS == nil {
		return ctx
	}
	var opts sender.SendOptions
	if o.ResponseTimeoutMS != nil {
		opts.ResponseTimeout = time.Duration(*o.ResponseTimeoutMS) * time.Millisecond
	}
	if o.StreamingTimeoutMS != nil {
		opts.StreamingTimeout = time.Duration(*o.StreamingTimeoutMS) * time.Millisecond
		opts.StreamingTimeoutSet = true
	}
	return sender.WithSendOptions(ctx, opts)
}

// protocolPreference maps the wire value onto the sender's enum. Only called post-validate.
// "http2" is the force pin (burpsy-react-ui-745): the send must ride h2 when the request can be
// carried over it at all — the same representability bar Auto applies, so a request h2 has
// nowhere to put still goes out as HTTP/1.1 with its construct named, and a target that declines
// h2 at ALPN reports the downgrade instead of failing the connection.
func (o repeaterSendOptions) protocolPreference() sender.ProtocolPreference {
	switch o.ProtocolPreference {
	case "http1":
		return sender.ProtocolPreferenceHTTP1
	case "http2":
		return sender.ProtocolPreferenceForceH2
	default:
		return sender.ProtocolPreferenceAuto
	}
}

// redirectPolicy is the policy this send follows: the override when one was given, otherwise the
// network settings' standing policy.
func (o repeaterSendOptions) redirectPolicy(standing sender.RedirectSettings) sender.RedirectSettings {
	if o.RedirectMode == "" {
		return standing
	}
	// The hop budget is an anti-loop bound, not a policy choice, so the override keeps the
	// standing budget and replaces only the mode. ReplayCookies is kept for the same reason: it is
	// an operator's standing decision about whether a chain may carry a target-set credential, not a
	// choice a per-send mode dropdown should silently revoke. Rebuilding the struct field by field
	// is what lost it — the override read as "always, no cookies" when the operator had said
	// otherwise in Settings, and nothing on screen said so (burpsy-react-ui-mr83).
	//
	// Copying the standing value and replacing one field is the shape that keeps a field ADDED to
	// RedirectSettings later from defaulting to false here, which is the same class of bug as a
	// struct literal quietly losing a new field.
	policy := standing
	policy.Mode = sender.RedirectMode(o.RedirectMode)
	return policy
}

// applyToRequest returns the bytes to put on the wire: the operator's request with the enabled
// transforms applied in a fixed order (cookies, Connection strip, line endings, Content-Length —
// length last, so it measures the body the earlier steps settled). The input is never modified.
func (o repeaterSendOptions) applyToRequest(raw []byte, cookieHeader string) []byte {
	next := raw
	if o.ProcessCookies && cookieHeader != "" && !repeaterHasHeader(next, "Cookie") {
		next = repeaterInsertHeader(next, "Cookie", cookieHeader)
	}
	if o.StripConnection {
		next = repeaterRemoveHeader(next, "Connection")
	}
	if o.NormalizeLineEndings {
		// Two steps: folding CRLF to LF first means an already-CRLF request comes back unchanged
		// instead of growing a CR on every line.
		next = bytes.ReplaceAll(next, []byte("\r\n"), []byte("\n"))
		next = bytes.ReplaceAll(next, []byte("\n"), []byte("\r\n"))
	}
	if o.UpdateContentLength {
		next = repeaterUpdateContentLength(next)
	}
	return next
}

// repeaterHeadBody cuts a request into its header block and body at the first blank line. head is
// the header lines *without* their final CRLF, so a reconstruction is join(head) + CRLF + CRLF +
// body and no step can double the blank line. terminated is false when no blank line exists: there
// is no body to speak of and no well-defined place to append a header — callers that add headers
// skip it. (Named with the repeater prefix because api_sequencer_capture.go already owns the
// unprefixed shape with a different arity.)
func repeaterHeadBody(raw []byte) (head, body []byte, terminated bool) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i], raw[i+4:], true
	}
	return raw, nil, false
}

// repeaterHasHeader reports whether the header block already carries a header with the given name
// (case-insensitive, as it must be — "cookie" matches "Cookie:").
func repeaterHasHeader(raw []byte, name string) bool {
	head, _, _ := repeaterHeadBody(raw)
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		if i := bytes.IndexByte(line, ':'); i > 0 && strings.EqualFold(string(line[:i]), name) {
			return true
		}
	}
	return false
}

// repeaterRemoveHeader deletes every header line with the given name, case-insensitively, and
// rebuilds the request. The blank-line terminator is re-added exactly once because head carries no
// trailing CRLF.
func repeaterRemoveHeader(raw []byte, name string) []byte {
	head, body, terminated := repeaterHeadBody(raw)
	lines := bytes.Split(head, []byte("\r\n"))
	kept := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if i := bytes.IndexByte(line, ':'); i > 0 && strings.EqualFold(string(line[:i]), name) {
			continue
		}
		kept = append(kept, line)
	}
	out := bytes.Join(kept, []byte("\r\n"))
	if terminated {
		return append(append(out, '\r', '\n', '\r', '\n'), body...)
	}
	return out
}

// repeaterInsertHeader adds one header at the end of the header block. A request with no header
// terminator is left alone — there is nowhere honest to put it.
func repeaterInsertHeader(raw []byte, name, value string) []byte {
	head, body, terminated := repeaterHeadBody(raw)
	if !terminated {
		return raw
	}
	out := append(append([]byte{}, head...), []byte("\r\n"+name+": "+value+"\r\n\r\n")...)
	return append(out, body...)
}

// repeaterUpdateContentLength rewrites Content-Length from the actual body. When a body exists and
// no Content-Length header is present, one is added; when the body is empty the header is removed
// rather than written as zero, because a GET carrying "Content-Length: 0" is the kind of
// discrepancy some servers reject and none need.
func repeaterUpdateContentLength(raw []byte) []byte {
	_, body, terminated := repeaterHeadBody(raw)
	if !terminated {
		return raw
	}
	hadLength := repeaterHasHeader(raw, "Content-Length")
	if len(body) == 0 {
		if !hadLength {
			return raw
		}
		return repeaterRemoveHeader(raw, "Content-Length")
	}
	next := repeaterRemoveHeader(raw, "Content-Length")
	return repeaterInsertHeader(next, "Content-Length", strconv.Itoa(len(body)))
}
