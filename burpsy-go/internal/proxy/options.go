package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// The proxy's live option set: Burp's Proxy → Response modification rules and the
// two Miscellaneous knobs this engine can actually honour.
//
// # Why this is its own type rather than more ProxyConfig fields
//
// Everything on ProxyConfig is settled once, at construction, by a flag. These are
// not: an operator turns "Remove all JavaScript" on to get past a client-side
// redirect, looks at one page, and turns it off again. A flag read at startup is
// the wrong shape for that, and the alternative — restarting the proxy mid-engagement
// — throws away the capture's continuity. So the option set is a shared, mutex-guarded
// object that the proxy reads on the hot path and the web API writes, exactly the
// arrangement TlsPolicy already uses for passthrough rules. Two copies (one the UI
// edits, one the relay obeys) is the failure this shape exists to prevent.
//
// # Why the counters live here too
//
// A response-modification rule is not a rule that always fires. It cannot touch a
// gzipped body, it must not touch a body that is not HTML, and this build cannot
// reach an HTTP/2 response at all. An operator who ticks a box and sees no change
// has to be able to tell "the rule found nothing to rewrite" from "the rule was
// never allowed to look" — so every outcome is counted and reported, and the panel
// shows the breakdown rather than a checkbox that silently did nothing.

// OptionKey is the wire name of one editable option. Named constants rather than
// bare strings so the handler, the persistence layer and the proxy cannot disagree
// about what an option is called.
type OptionKey string

const (
	// OptUnhideHiddenFormFields rewrites `type="hidden"` to `type="text"` on
	// `<input>` elements, so a hidden field can be edited in the browser.
	OptUnhideHiddenFormFields OptionKey = "unhide_hidden_form_fields"
	// OptEnableDisabledFormFields removes the `disabled` attribute from form
	// controls — input, textarea, select, option, button and the fieldset that
	// disables its descendants — so a greyed-out control can be used. Burp's
	// "Enable disabled form fields" (configPanelProxyModificationRules:121).
	//
	// Burp renders a "Prominently highlight unhidden fields" sub-option next to
	// unhide_hidden_form_fields; that sub-option is deliberately not implemented.
	// It injects marker markup the origin never sent into a body burpsy also
	// records and passively scans, which unhideHiddenFormFields already rejects
	// for exactly that reason — the field's type in history is the record of what
	// happened. The same decision covers highlighting.
	OptEnableDisabledFormFields OptionKey = "enable_disabled_form_fields"
	// OptRemoveInputFieldLengthLimits removes `maxlength` attributes from
	// `<input>` and `<textarea>` elements, so an over-long value can be submitted.
	// Burp's "Remove input field length limits"
	// (configPanelProxyModificationRules:129).
	OptRemoveInputFieldLengthLimits OptionKey = "remove_input_field_length_limits"
	// OptRemoveObjectTags removes `<object>…</object>` elements and their content.
	OptRemoveObjectTags OptionKey = "remove_object_tags"
	// OptRemoveJSFormValidation removes `onsubmit` and `onreset` handler
	// attributes: the two hooks a form's client-side validation runs from.
	OptRemoveJSFormValidation OptionKey = "remove_javascript_form_validation"
	// OptRemoveAllJavaScript removes `<script>…</script>` elements, every `on*`
	// inline handler attribute, and `javascript:` hrefs.
	OptRemoveAllJavaScript OptionKey = "remove_all_javascript"
	// OptConvertHTTPSLinks rewrites `https://` to `http://` inside href, src and
	// action attribute values.
	OptConvertHTTPSLinks OptionKey = "convert_https_links_to_http"
	// OptRemoveSecureFlagFromCookies removes the `Secure` attribute from
	// Set-Cookie response headers, so a session cookie the origin marked
	// HTTPS-only is transmitted over plaintext HTTP and can be captured. Burp's
	// "Remove secure flag from cookies" (configPanelProxyModificationRules:169).
	//
	// Not a body rule and not in responseRules: it rewrites the head, and it must
	// reach every response — a gzip body's headers are plaintext, and a JSON
	// endpoint can set cookies just as an HTML page can — so Content-Type and
	// Content-Encoding, which gate the body rules, must not gate it. It runs on
	// the same live option set and is counted by the same counters as the body
	// rules; like them it cannot reach an HTTP/2 relayed response (NoteRelayedHTTP2).
	OptRemoveSecureFlagFromCookies OptionKey = "remove_secure_flag_from_cookies"
	// OptStripAcceptEncoding removes the Accept-Encoding header from requests on
	// the way out. Burp's own wording for this option ends "(if not unpacking
	// compressed data)": it is the alternative to OptUnpackCompressedResponses
	// below, not a decompressor. Stripping only *asks* the origin for an
	// uncompressed response; an origin is free to compress anyway, and the change
	// is visible server-side, so the traffic recorded is no longer exactly what
	// the client would have received.
	//
	// The proxy path can unpack gzip, x-gzip, deflate, br and zstd itself
	// (httputil.Unpackable), so for those the unpack switch is the less
	// intrusive choice. Stripping is still the only way the response rules above
	// get a rewritable body from an origin that answers in a chain of encodings,
	// which this build does not unwind.
	OptStripAcceptEncoding OptionKey = "strip_accept_encoding"
	// OptUnpackCompressedRequests decompresses a gzip, deflate, br or zstd request
	// body before the request is forwarded, dropping its Content-Encoding and
	// fixing Content-Length. Burp's proxyOptionsUnpackCompressedRequests.
	//
	// Its own switch rather than one shared with the response direction, because
	// they are not the same decision: unpacking a request changes the bytes the
	// *origin* receives, which an application may reject, while unpacking a
	// response changes only what the browser receives.
	OptUnpackCompressedRequests OptionKey = "unpack_compressed_requests"
	// OptUnpackCompressedResponses decompresses a gzip, deflate, br or zstd
	// response body so the response modification rules above can reach it,
	// dropping its Content-Encoding and fixing Content-Length. Burp's
	// proxyOptionsUnpackCompressedResponses; its search keywords are literally
	// "unpack gzip" and "unpack deflate".
	//
	// This is the answer to strip_accept_encoding being the only previous option.
	// Stripping Accept-Encoding changes what the client asks the origin for and is
	// detectable server-side, so it forced a choice between reading the traffic and
	// observing the traffic the client would really have received. Unpacking asks
	// the origin for nothing different.
	//
	// A response carrying an encoding this build cannot decode — a chain, or a
	// name with no decoder here — is counted as SkippedUnsupportedEncoding rather
	// than reported as unpacked. See internal/httputil.Unpackable.
	OptUnpackCompressedResponses OptionKey = "unpack_compressed_responses"
	// OptStripWsExtensions removes the client's Sec-WebSocket-Extensions offer from
	// an upgrade request before it is forwarded, so the origin cannot negotiate
	// permessage-deflate and the relayed frames are captured in the clear rather
	// than as opaque DEFLATE blocks. Burp's
	// proxy.miscellaneous.strip_sec_websocket_extensions_headers_in_incoming_requests.
	//
	// Not a response rule and not applied through ApplyRequest: it rewrites the
	// handshake, which no other message ever carries, so the strip lives on the
	// WebSocket path (stripWsHandshake) and reads this set live — the same
	// set-on/off-without-a-restart contract the response rules have. On by
	// default, seeded by NewProxyConfig, because a proxy that let the extension
	// be negotiated would record compressed frames and call them messages.
	OptStripWsExtensions OptionKey = "strip_sec_websocket_extensions"
	// OptDontLogOutOfScope decides whether an exchange the scope excludes is
	// recorded at all — Burp's "don't send items to Proxy history or live tasks,
	// if out of scope" (configPanelProxyMiscellaneousDontLogOutOfScopeItems), one
	// third of Burp's Proxy history logging panel, whose other two choices ("Ask
	// me what to do each time", "Do nothing") have no burpsy equivalent.
	//
	// Not a response rule and not in responseRules: it rewrites nothing. It is a
	// retention decision read live at each record site — the same
	// set-on/off-without-a-restart contract the rules have — and it deliberately
	// does not gate what the rules do to the bytes, only whether the exchange
	// survives them: scope decides what is *retained*, never what is *rewritten*.
	//
	// Seeded ON, unlike Burp's default "Do nothing", because this engine has never
	// retained out-of-scope traffic: every record site has always gated on the
	// scope verdict. Seeding OFF would silently start writing third-party traffic
	// to the store on upgrade. The switch's value is the other direction — an
	// operator who wants Burp's log-everything behaviour can now have it — and the
	// exchanges it drops are counted (Counters.DroppedOutOfScope) so an empty
	// history is distinguishable from a mis-set scope.
	OptDontLogOutOfScope OptionKey = "dont_log_out_of_scope"
	// OptInvisibleProxy decides whether an origin-form request (`GET /path`) whose
	// authority arrives only in its Host header is forwarded to that host — Burp's
	// "Support invisible proxying (enable only if needed)". A non-proxy-aware client
	// whose DNS points an origin's name at this listener speaks exactly this shape;
	// with the option off the listener answers 400, which is the honest answer for a
	// plain proxy that was sent a request it cannot attribute.
	//
	// Seeded ON, unlike Burp's default-off, because this engine has always honoured
	// the Host-header fallback: flipping the default would break working setups on
	// upgrade in exchange for nothing. The switch exists so the behaviour can be
	// tightened, and the divergence from Burp's default is deliberate and stated.
	OptInvisibleProxy OptionKey = "invisible_proxy"
	// OptStripProxyHeaders removes the Proxy-* header family from incoming
	// requests before they are forwarded — Burp's
	// "strip Proxy-* headers in incoming requests"
	// (configPanelProxyMiscellaneous). These headers are instructions to a proxy
	// from the client; forwarded to an origin they are smuggling surface, and
	// Burp strips them for exactly that reason. Seeded ON, unlike Burp's
	// default-off, because this engine has never forwarded one — flipping the
	// default would change behaviour on upgrade for nothing. The switch exists
	// to be able to send them, which is occasionally what a test of an origin's
	// own Proxy-header handling needs.
	OptStripProxyHeaders OptionKey = "strip_proxy_headers"
	// OptSetConnectionClose rewrites the request's Connection header to close
	// and sets it on the response — Burp's "Set "Connection: close" on
	// requests and on responses" (configPanelProxyMiscellaneous). Off by
	// default: the relay already honours the client's own Connection header,
	// and forcing close on everything trades keep-alive throughput for a
	// determinism most sessions do not need. When on, both directions close
	// after one exchange.
	OptSetConnectionClose OptionKey = "set_connection_close"
	// OptUseHTTP10ToServer sends every forwarded request with an HTTP/1.0 request line, Burp's "Use
	// HTTP/1.0 in requests to server" (burpsy-react-ui-0q9d), for a legacy origin that mishandles 1.1.
	// Only the version token changes: a request whose body is chunked keeps its framing, which an
	// HTTP/1.0 origin may refuse, and that refusal is the origin's answer to the operator's choice.
	OptUseHTTP10ToServer OptionKey = "use_http10_to_server"
	// OptUseHTTP10ToClient answers the browser with an HTTP/1.0 status line, Burp's "Use HTTP/1.0 in
	// responses to client" (0q9d). Applied with the other response options, so history records the
	// response the browser received.
	OptUseHTTP10ToClient OptionKey = "use_http10_to_client"
	// OptSuppressErrorMessages stops burpsy sending its own explanatory error responses to the browser
	// (a refused scope or egress, a failed CONNECT, an unattributable request), Burp's "Suppress Burp
	// error messages in browser" (0q9d). The connection is closed instead, and the event is still
	// logged and counted where it was before.
	OptSuppressErrorMessages OptionKey = "suppress_error_messages"
	// OptDisableWebInterface turns off the in-browser interface at http://burpsuite (and http://burpsy,
	// and the listener's own address), Burp's "Disable web interface at http://burpsuite"
	// (burpsy-react-ui-beof). Useful on a listener bound to an unprotected interface.
	OptDisableWebInterface OptionKey = "disable_web_interface"
)

// OptionKeys is every editable option, in the order the panel renders them.
// Exported so the API can list the valid keys in a 400 rather than making the
// caller guess, and so a key added here appears in both without a second edit.
var OptionKeys = []OptionKey{
	OptUnhideHiddenFormFields,
	OptEnableDisabledFormFields,
	OptRemoveInputFieldLengthLimits,
	OptRemoveObjectTags,
	OptRemoveJSFormValidation,
	OptRemoveAllJavaScript,
	OptConvertHTTPSLinks,
	OptRemoveSecureFlagFromCookies,
	OptStripAcceptEncoding,
	OptUnpackCompressedRequests,
	OptUnpackCompressedResponses,
	OptStripWsExtensions,
	OptDontLogOutOfScope,
	OptInvisibleProxy,
	OptStripProxyHeaders,
	OptSetConnectionClose,
	OptUseHTTP10ToServer,
	OptUseHTTP10ToClient,
	OptSuppressErrorMessages,
	OptDisableWebInterface,
}

// KnownOption reports whether a wire-name key is one of the editable options. The
// API's PUT validates the whole patch through this before applying any of it, so a
// request with one bad key changes nothing.
func KnownOption(key OptionKey) bool {
	for _, known := range OptionKeys {
		if known == key {
			return true
		}
	}
	return false
}

// ErrUnknownOption is returned by Set for a key that is not in OptionKeys. The
// handler turns it into a 400 naming the key, because silently accepting an
// unknown option is how a client ends up believing it has enabled something.
var ErrUnknownOption = errors.New("unknown proxy option")

// responseRules are the options that rewrite a response body. Separated from the
// full list because ApplyResponse must be able to answer "is any of this on?"
// without paying for the head parse — and because a request-direction option
// arriving in this set would make every response look eligible.
var responseRules = []OptionKey{
	OptUnhideHiddenFormFields,
	// The two form-control rules are placed with unhide rather than in Burp's
	// render order: all three edit the same controls, and their order relative to
	// each other cannot matter — each touches a different attribute.
	OptEnableDisabledFormFields,
	OptRemoveInputFieldLengthLimits,
	OptRemoveObjectTags,
	OptRemoveJSFormValidation,
	OptRemoveAllJavaScript,
	OptConvertHTTPSLinks,
}

// Counters is one snapshot of what the response rules actually did.
type Counters struct {
	// Considered is responses that reached ApplyResponse while at least one
	// response rule was enabled. Responses that arrived with every rule off are
	// not counted at all: they were never candidates, and counting them would
	// make the skip ratios meaningless.
	Considered uint64 `json:"responses_considered"`
	Modified   uint64 `json:"responses_modified"`
	// Unchanged is a response the rules were allowed to rewrite and found nothing
	// to rewrite in. Distinct from every Skipped* below, which are responses the
	// rules never got to look at.
	Unchanged uint64 `json:"responses_unchanged"`
	// SkippedCompressed is a response carrying a Content-Encoding that was left
	// alone: unpack_compressed_responses is off, or it is on and the encoding is one
	// this build cannot decode (see SkippedUnsupportedEncoding, which is the subset
	// naming that second reason). Turn on unpack_compressed_responses, or
	// strip_accept_encoding to stop the origin sending them at all.
	SkippedCompressed uint64 `json:"skipped_compressed"`
	// SkippedUnsupportedEncoding is the subset of SkippedCompressed where unpacking
	// was ON and the encoding could not be decoded anyway — a chain, an encoding
	// with no decoder here, or a body that failed to decompress. It is separate
	// because the two say different things to an operator who has just ticked the
	// box: "the switch is off" is something they can fix, and "this build cannot
	// decode that encoding" is not.
	SkippedUnsupportedEncoding uint64 `json:"skipped_unsupported_encoding"`
	// UnpackedResponses and UnpackedRequests count messages actually decompressed,
	// not messages seen while the switch was on: a switch that saw no compressed
	// traffic must not read as a switch that is working.
	UnpackedResponses uint64 `json:"unpacked_responses"`
	UnpackedRequests  uint64 `json:"unpacked_requests"`
	SkippedNotHTML    uint64 `json:"skipped_not_html"`
	// SkippedUnframed is a response with no header/body separator, or with chunk
	// framing that would not parse. Neither can be rewritten without guessing
	// where the body is.
	SkippedUnframed uint64 `json:"skipped_unframed"`
	// RelayedHTTP2 is an HTTP/2 response these rules could not reach — see
	// NoteRelayedHTTP2.
	RelayedHTTP2 uint64 `json:"relayed_http2"`
	// AcceptEncodingStripped counts requests strip_accept_encoding actually
	// changed, not requests it saw: a request that never offered an encoding is
	// not evidence the option is working.
	AcceptEncodingStripped uint64 `json:"accept_encoding_stripped"`
	// Dechunked counts responses whose chunk framing was collapsed to a
	// Content-Length body so a rule could rewrite it. Reported because it is a
	// change to the framing the origin chose, and an operator comparing burpsy's
	// history against a packet capture should be able to see that it happened.
	Dechunked uint64 `json:"dechunked"`
	// ModifiedUnrecorded is the subset of Modified that scope kept out of history:
	// the rules rewrote the bytes the client received, and no exchange exists to
	// show it.
	//
	// It exists because without it Modified is unreconcilable. The rules run on all
	// traffic through the listener — that is what a listener-level rule means, and it
	// is the same ordering applyRequestRules already uses so an out-of-scope forward
	// sends the bytes the recorded path would — but only in-scope exchanges are
	// stored. So an operator reading "responses_modified: 40" could search all of
	// history, find four modified responses, and have no way to learn whether the
	// other thirty-six were a counter bug or a scope decision. This says which.
	//
	// Modified - ModifiedUnrecorded is the number findable in history, by
	// construction.
	ModifiedUnrecorded uint64 `json:"responses_modified_unrecorded"`
	// DroppedOutOfScope counts exchanges the proxy forwarded but did not record
	// because the scope excluded them while dont_log_out_of_scope was on. It is
	// the answer to "why is my history empty" that a silent drop cannot give: a
	// scope typo and a quiet target look identical without it, and an operator
	// auditing what was retained — or, sharper, what was *not* retained, which is
	// the whole point of the switch — needs the number.
	//
	// It counts drops caused by the switch only. An exchange recorded because the
	// operator turned the switch off is not a drop, and neither is traffic the
	// blind CONNECT tunnel cannot see.
	DroppedOutOfScope uint64 `json:"exchanges_dropped_out_of_scope"`
}

// Options is the live option set. Safe for concurrent use: the proxy reads it once
// per message, the API writes it from a handler goroutine.
type Options struct {
	mu    sync.RWMutex
	flags map[OptionKey]bool

	// Counters are atomics rather than mutex-guarded fields because they are
	// written on the response hot path and read only when someone opens the panel.
	considered             atomic.Uint64
	modified               atomic.Uint64
	unchanged              atomic.Uint64
	skippedCompressed      atomic.Uint64
	skippedUnsupportedEnc  atomic.Uint64
	unpackedResponses      atomic.Uint64
	unpackedRequests       atomic.Uint64
	skippedNotHTML         atomic.Uint64
	skippedUnframed        atomic.Uint64
	relayedHTTP2           atomic.Uint64
	acceptEncodingStripped atomic.Uint64
	dechunked              atomic.Uint64
	modifiedUnrecorded     atomic.Uint64
	droppedOutOfScope      atomic.Uint64
}

// NewOptions returns an option set with every rule off.
//
// Off, not Burp's defaults, and deliberately: every one of these rules changes what
// the browser receives, and burpsy's stated invariant is that captured bytes are the
// bytes on the wire. A default that silently rewrote traffic would make the first
// capture of every new session a lie about the origin. Burp defaults them off too.
func NewOptions() *Options {
	flags := make(map[OptionKey]bool, len(OptionKeys))
	for _, key := range OptionKeys {
		flags[key] = false
	}
	return &Options{flags: flags}
}

// Get reports whether one option is on. An unknown key reads as off rather than
// panicking: a caller asking about an option that does not exist is asking whether
// a behaviour is enabled, and the answer is no.
func (o *Options) Get(key OptionKey) bool {
	if o == nil {
		return false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.flags[key]
}

// Set turns one option on or off, refusing a key that is not in OptionKeys.
func (o *Options) Set(key OptionKey, on bool) error {
	if o == nil {
		return fmt.Errorf("%w: no option set is attached", ErrUnknownOption)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.flags[key]; !ok {
		return fmt.Errorf("%w %q", ErrUnknownOption, key)
	}
	o.flags[key] = on
	return nil
}

// Snapshot returns every option and its state, keyed by wire name.
func (o *Options) Snapshot() map[string]bool {
	out := make(map[string]bool, len(OptionKeys))
	if o == nil {
		for _, key := range OptionKeys {
			out[string(key)] = false
		}
		return out
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, key := range OptionKeys {
		out[string(key)] = o.flags[key]
	}
	return out
}

// Counters returns the current tallies.
func (o *Options) Counters() Counters {
	if o == nil {
		return Counters{}
	}
	return Counters{
		Considered:                 o.considered.Load(),
		Modified:                   o.modified.Load(),
		Unchanged:                  o.unchanged.Load(),
		SkippedCompressed:          o.skippedCompressed.Load(),
		SkippedUnsupportedEncoding: o.skippedUnsupportedEnc.Load(),
		UnpackedResponses:          o.unpackedResponses.Load(),
		UnpackedRequests:           o.unpackedRequests.Load(),
		SkippedNotHTML:             o.skippedNotHTML.Load(),
		SkippedUnframed:            o.skippedUnframed.Load(),
		RelayedHTTP2:               o.relayedHTTP2.Load(),
		AcceptEncodingStripped:     o.acceptEncodingStripped.Load(),
		Dechunked:                  o.dechunked.Load(),
		ModifiedUnrecorded:         o.modifiedUnrecorded.Load(),
		DroppedOutOfScope:          o.droppedOutOfScope.Load(),
	}
}

// NoteUnrecordedModification records that one response the rules rewrote will not appear
// in history, because scope excluded the exchange.
//
// Called by the proxy rather than inferred inside ApplyResponse, because ApplyResponse is
// handed bytes and nothing else: whether the exchange that owns them gets stored is a
// scope decision made by the caller, and the option set has no way to see it. The caller
// only calls this when the bytes actually changed, so the counter stays a subset of
// Modified rather than a count of out-of-scope traffic.
func (o *Options) NoteUnrecordedModification() {
	if o == nil {
		return
	}
	o.modifiedUnrecorded.Add(1)
}

// NoteOutOfScopeDrop records that one exchange was forwarded but not stored,
// because the scope excluded it and dont_log_out_of_scope is on.
//
// Called by the proxy at each record site it skips for this reason, so the count
// is the number of exchanges the switch cost the operator, wherever the record
// decision lives. Turning the switch off stops the counter, not the traffic.
func (o *Options) NoteOutOfScopeDrop() {
	if o == nil {
		return
	}
	o.droppedOutOfScope.Add(1)
}

// NoteRelayedHTTP2 records that one HTTP/2 response went past without the response
// rules being able to touch it.
//
// Called from the h2 relay rather than having ApplyResponse handle h2, because the
// h2 path does not have a response message to rewrite: it copies the origin's frames
// to the client and separately *renders* an HTTP/1-shaped copy for history. Rewriting
// that rendering would put bytes in history the browser never received, which is the
// one thing every comment on this package's capture sites is written to prevent. So
// the honest answer is "these rules do not reach HTTP/2", counted here so the panel
// can say it with a number instead of a caveat.
func (o *Options) NoteRelayedHTTP2() {
	if o == nil {
		return
	}
	o.relayedHTTP2.Add(1)
}

// ---- request direction ---------------------------------------------------------

// ApplyRequest rewrites a request on its way upstream. Returns raw unchanged when
// nothing applies, so the ordinary path allocates nothing.
func (o *Options) ApplyRequest(raw []byte) []byte {
	if o == nil {
		return raw
	}
	out := raw
	// Unpacking first, then the header strip. Order matters only in that the strip must not be able to
	// remove a header the unpack step needed to read; Accept-Encoding is a request for the *response*
	// and Content-Encoding describes this body, so they do not interact — the ordering is fixed and
	// documented rather than left to chance.
	if o.Get(OptUnpackCompressedRequests) {
		if unpacked, ok := o.unpack(out, &o.unpackedRequests); ok {
			out = unpacked
		}
	}
	if o.Get(OptStripAcceptEncoding) {
		if stripped, removed := removeHeader(out, "Accept-Encoding"); removed {
			o.acceptEncodingStripped.Add(1)
			out = stripped
		}
	}
	return out
}

// unpack decompresses one message's body in place in the message, dropping Content-Encoding and
// fixing Content-Length. It reports false, and changes nothing, whenever it cannot.
//
// Every refusal is counted, on the same principle the response rules already follow: an operator who
// ticks "unpack compressed" and sees no change must be able to tell "there was nothing compressed"
// from "the encoding could not be decoded" from "the framing did not parse".
//
// A body that fails to decompress is left byte-for-byte alone rather than partially replaced. Handing
// a rule half a document — or handing the client one — is worse than not unpacking: the rule would
// rewrite what it could see and the browser would receive a document cut in the middle.
func (o *Options) unpack(raw []byte, counter *atomic.Uint64) ([]byte, bool) {
	head, body, sep, ok := httputil.SplitHeadBody(raw)
	if !ok {
		o.skippedUnframed.Add(1)
		return raw, false
	}
	encoding, _ := httputil.HeaderValue(head, "Content-Encoding")
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		// Nothing to unpack. Not counted at all: an uncompressed message is not a skip, it is a
		// message the switch has no business touching, and counting it would make the skip ratios
		// meaningless the way Considered already documents for the response rules.
		return raw, false
	}
	if !httputil.Unpackable(encoding) {
		// A chain of encodings, or one with no decoder here. Counted twice on purpose:
		// SkippedCompressed keeps its meaning as "a compressed message no rule reached", and the
		// narrower counter says the switch was on and could not help.
		o.skippedCompressed.Add(1)
		o.skippedUnsupportedEnc.Add(1)
		return raw, false
	}

	te, _ := httputil.HeaderValue(head, "Transfer-Encoding")
	chunked := strings.EqualFold(te, "chunked")
	compressed := body
	if chunked {
		// Dechunk before decompressing: the chunk sizes frame the compressed bytes, and feeding
		// `size CRLF data CRLF` to gzip decodes the size prefix as payload.
		decoded, dok := httputil.Dechunk(body)
		if !dok {
			o.skippedUnframed.Add(1)
			return raw, false
		}
		compressed = decoded
	}

	plain, err := httputil.DecodeBody(encoding, compressed)
	if err != nil {
		o.skippedCompressed.Add(1)
		o.skippedUnsupportedEnc.Add(1)
		return raw, false
	}
	if chunked {
		o.dechunked.Add(1)
	}
	counter.Add(1)
	// Content-Encoding goes, because the body is no longer encoded and leaving the header would tell
	// the recipient to decompress plaintext. rebuild drops Content-Length and Transfer-Encoding and
	// writes the new length.
	return rebuild(head, sep, plain, chunked, true), true
}

// ---- response direction --------------------------------------------------------

// ApplyResponse rewrites a response body according to the enabled rules, and returns
// raw unchanged when it cannot or need not.
//
// # What it refuses to do, and why each refusal is counted
//
//   - A body with a Content-Encoding is left alone *unless* unpack_compressed_responses
//     is on. Applying "remove all JavaScript" to gzip bytes would find no script tags,
//     report success, and hand the browser a corrupted stream, so with the switch off the
//     response is skipped and counted. With it on the body is decompressed first and the
//     rules run on plaintext — which is why the switch exists: before it, a compressed
//     response was permanently in the "the rule was never allowed to look" state, and
//     strip_accept_encoding was the only escape.
//   - An encoding this build cannot decode (a chain, or a name with no decoder here) is
//     still left alone with the switch on, counted as SkippedUnsupportedEncoding as well,
//     because "the switch is off" and "this build cannot decode that encoding" are different
//     things to tell an operator.
//   - A body that is not HTML is left alone. These are HTML rewrites; running them over
//     JSON, CSS or an image is at best a no-op and at worst silent corruption.
//   - A body with no header/body separator is left alone: there is nothing to locate.
//
// # Chunk framing
//
// httputil.ReadResponseBody preserves chunk framing verbatim, so a chunked body arrives
// here as `size CRLF data CRLF …`. Rewriting inside that would leave every size prefix
// wrong. Rather than skip — chunked HTML is most of the real web, and a rule that skips
// most of the web is a rule that does not work — the framing is collapsed to a single
// Content-Length body, but only when a rule actually changed something. A response no
// rule touched is returned byte-for-byte, framing included.
func (o *Options) ApplyResponse(raw []byte) []byte {
	if o == nil {
		return raw
	}
	out := o.applyResponseRules(raw)
	if o.Get(OptUseHTTP10ToClient) {
		ruled := out
		out = withHTTPVersion(out, "HTTP/1.0", true)
		// Counted like any other response rewrite, so the panel's Modified total agrees with history.
		// A response the rules already rewrote was counted there and is not counted twice.
		if !bytes.Equal(out, ruled) && bytes.Equal(ruled, raw) {
			o.considered.Add(1)
			o.modified.Add(1)
		}
	}
	return out
}

// withHTTPVersion rewrites the version token of a message's first line: the third token of a request
// line, or the first token of a status line. A message whose first line does not carry an HTTP/1.x
// version is returned unchanged.
func withHTTPVersion(raw []byte, version string, response bool) []byte {
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 {
		return raw
	}
	line := string(raw[:nl])
	cr := strings.HasSuffix(line, "\r")
	line = strings.TrimSuffix(line, "\r")
	var rewritten string
	if response {
		ver, rest, ok := strings.Cut(line, " ")
		if !ok || !strings.HasPrefix(ver, "HTTP/1.") || ver == version {
			return raw
		}
		rewritten = version + " " + rest
	} else {
		i := strings.LastIndexByte(line, ' ')
		if i < 0 || !strings.HasPrefix(line[i+1:], "HTTP/1.") || line[i+1:] == version {
			return raw
		}
		rewritten = line[:i+1] + version
	}
	if cr {
		rewritten += "\r"
	}
	out := make([]byte, 0, len(raw)-len(line)+len(rewritten))
	out = append(out, rewritten...)
	return append(out, raw[nl:]...)
}

// applyResponseRules is the response options other than the version switch.
func (o *Options) applyResponseRules(raw []byte) []byte {

	o.mu.RLock()
	enabled := make(map[OptionKey]bool, len(responseRules))
	any := false
	for _, key := range responseRules {
		if o.flags[key] {
			enabled[key] = true
			any = true
		}
	}
	unpacking := o.flags[OptUnpackCompressedResponses]
	cookieStrip := o.flags[OptRemoveSecureFlagFromCookies]
	o.mu.RUnlock()
	// The cookie-flag strip counts as something to do on its own, exactly as
	// unpacking does: it is a rule, only aimed at the head instead of the body.
	if !any && !unpacking && !cookieStrip {
		return raw
	}
	o.considered.Add(1)

	head, body, sep, ok := httputil.SplitHeadBody(raw)
	if !ok {
		o.skippedUnframed.Add(1)
		return raw
	}
	if encoding, _ := httputil.HeaderValue(head, "Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		// Unpack when the operator asked for it, then carry on with the decompressed message — this is
		// the whole point of the switch: "the rule found nothing to rewrite" and "the rule was never
		// allowed to look" were the two states this package was built to distinguish, and a
		// compressed body was permanently in the second.
		//
		// Every early return here still offers the head to the cookie-flag strip first: a gzip
		// body's headers are plaintext, and a Set-Cookie header is as strippable on a compressed
		// response as on any other. The strip is the only change that can survive these skips,
		// because it is the only one that does not depend on reading the body.
		if !unpacking {
			o.skippedCompressed.Add(1)
			return o.headOnlyResult(raw, head, sep, body, cookieStrip)
		}
		unpacked, uok := o.unpack(raw, &o.unpackedResponses)
		if !uok {
			// unpack counted the reason. SkippedCompressed is added there too, so the panel's
			// "Skipped: compressed" total still covers every compressed response no rule reached.
			return o.headOnlyResult(raw, head, sep, body, cookieStrip)
		}
		// Re-split, because the head and the framing have both changed. Recursion is deliberately not
		// used: the message now carries no Content-Encoding, so a second pass could not reach this
		// branch again, and an explicit re-split says that rather than relying on it.
		raw = unpacked
		head, body, sep, ok = httputil.SplitHeadBody(raw)
		if !ok {
			o.skippedUnframed.Add(1)
			return raw
		}
		if !any {
			// Decompressed, and no rewriting rule to run. The decompressed message is the result: the
			// switch's job is to make the body readable, and Modified counts it because the bytes
			// really did change. The cookie-flag strip rides along on the decompressed head, which is
			// the head the browser actually receives.
			if head, changed := stripSecureCookieAttributes(head, cookieStrip); changed {
				o.modified.Add(1)
				return concatMessage(head, sep, body)
			}
			o.modified.Add(1)
			return raw
		}
	}
	// The cookie-flag strip runs after the unpack branch so it rewrites the head the browser will
	// receive — the decompressed head, when unpacking happened — and before the body gates, which
	// must not gate it: Content-Type and Content-Encoding say nothing about whether a Set-Cookie
	// header is present.
	headChanged := false
	if cookieStrip {
		if newHead, changed := stripSecureCookieAttributes(head, true); changed {
			head, headChanged = newHead, true
		}
	}
	if !any {
		// Only the unpacking and cookie switches were enabled, and this response gave them
		// nothing to do: no Content-Encoding to unpack, no Secure flag to strip. Counted
		// unchanged rather than silent, on the same principle as every other no-op here.
		if headChanged {
			o.modified.Add(1)
			return concatMessage(head, sep, body)
		}
		o.unchanged.Add(1)
		return raw
	}
	if !isHTMLResponse(head) {
		o.skippedNotHTML.Add(1)
		if headChanged {
			o.modified.Add(1)
			return concatMessage(head, sep, body)
		}
		return raw
	}

	te, _ := httputil.HeaderValue(head, "Transfer-Encoding")
	chunked := strings.EqualFold(te, "chunked")
	plain := body
	if chunked {
		decoded, ok := httputil.Dechunk(body)
		if !ok {
			o.skippedUnframed.Add(1)
			// The body rules are out, but the head rule is not: it never needed the body. A
			// strip that already happened must survive this skip, exactly as it survives the
			// not-HTML one above — the two skips differ in what they could read, not in
			// whether the cookie flag is still there to remove.
			if headChanged {
				o.modified.Add(1)
				return concatMessage(head, sep, body)
			}
			return raw
		}
		plain = decoded
	}

	// Order is fixed and documented rather than incidental: remove-all-JavaScript
	// is a superset of the form-validation rule, so running it first means the
	// narrower rule has nothing left to find — which is the correct outcome when
	// both are ticked, and the alternative (narrow first) does the same work twice.
	out := plain
	if enabled[OptRemoveAllJavaScript] {
		out = removeAllJavaScript(out)
	}
	if enabled[OptRemoveJSFormValidation] {
		out = removeFormValidationHandlers(out)
	}
	if enabled[OptRemoveObjectTags] {
		out = removeObjectTags(out)
	}
	if enabled[OptUnhideHiddenFormFields] {
		out = unhideHiddenFormFields(out)
	}
	if enabled[OptEnableDisabledFormFields] {
		out = enableDisabledFormFields(out)
	}
	if enabled[OptRemoveInputFieldLengthLimits] {
		out = removeInputFieldLengthLimits(out)
	}
	if enabled[OptConvertHTTPSLinks] {
		out = convertHTTPSLinks(out)
	}

	if bytes.Equal(out, plain) {
		// Nothing in the BODY fired. The original bytes go back, chunk framing and all — a
		// body the rules did not change must not be re-framed as a side effect of having
		// been looked at.
		//
		// The head rule is checked first, and that ordering is the fix for a real bug: this
		// branch used to return `raw` unconditionally, so with a body rule ticked and nothing
		// for it to match, a Set-Cookie Secure flag the operator had asked to strip was
		// silently kept — and the response was counted `unchanged`, which said the option had
		// nothing to do when in fact it had done the work and had the result thrown away.
		// Every other skip path already offered the head its change first; this one and the
		// unparseable-chunking one are the two that did not.
		if headChanged {
			o.modified.Add(1)
			return concatMessage(head, sep, body)
		}
		o.unchanged.Add(1)
		return raw
	}
	if chunked {
		o.dechunked.Add(1)
	}
	o.modified.Add(1)
	// wasEncoded false: any Content-Encoding was already removed by the unpack step above, so there is
	// none left to drop and claiming otherwise here would hide where it happened.
	return rebuild(head, sep, out, chunked, false)
}

// ---- the rules -----------------------------------------------------------------
//
// Regex, not a parser, and stated as a limitation rather than left to be discovered:
// these run on the proxy hot path over bodies that are frequently not well-formed
// HTML, and a tolerant parser that re-serialises would change bytes no rule asked it
// to change — which breaks the one invariant this package is built around. The cost
// is that an attribute-shaped run of text inside a text node or a comment can be
// caught. Burp's own rules are blunt in the same way; the counters are how an
// operator sees that a rule fired at all.

var (
	// A `<script>` element and its content. Non-greedy, so two script elements are
	// two matches rather than one span swallowing everything between them. A
	// `<script>` with no closing tag is left alone: there is no way to bound it that
	// is not a guess about where the author meant it to end.
	reScriptElement = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>`)
	// An inline event-handler attribute, quoted or bare.
	reEventHandler = regexp.MustCompile(`(?is)\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	// A javascript: URL in a navigable attribute. Replaced with "#" rather than
	// deleted, because deleting the attribute turns a link into a non-link and the
	// page's layout changes for a reason unrelated to script execution.
	reJavaScriptURL = regexp.MustCompile(`(?is)(\s(?:href|src)\s*=\s*)("\s*javascript:[^"]*"|'\s*javascript:[^']*'|javascript:[^\s>]*)`)
	// The two handlers a form's client-side validation actually runs from.
	reFormValidationHandler = regexp.MustCompile(`(?is)\son(?:submit|reset)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	// An `<object>` element and its content, plus the self-closing form.
	reObjectElement     = regexp.MustCompile(`(?is)<object\b[^>]*>.*?</object\s*>`)
	reObjectSelfClosing = regexp.MustCompile(`(?is)<object\b[^>]*/>`)
	// `type="hidden"` on an input, in each of the three quoting styles HTML allows.
	// Three patterns because RE2 has no backreferences, so `type=(["']?)hidden\1`
	// is not expressible — and matching the quotes independently would rewrite
	// `type="hidden'` into something that was never valid either way.
	reHiddenDouble   = regexp.MustCompile(`(?is)(<input\b[^>]*?\btype\s*=\s*)"hidden"`)
	reHiddenSingle   = regexp.MustCompile(`(?is)(<input\b[^>]*?\btype\s*=\s*)'hidden'`)
	reHiddenBare     = regexp.MustCompile(`(?is)(<input\b[^>]*?\btype\s*=\s*)hidden\b`)
	reHTTPSAttribute = regexp.MustCompile(`(?is)(\s(?:href|src|action)\s*=\s*["']?)https://`)
)

func removeAllJavaScript(body []byte) []byte {
	out := reScriptElement.ReplaceAll(body, nil)
	out = reEventHandler.ReplaceAll(out, nil)
	return reJavaScriptURL.ReplaceAll(out, []byte(`${1}"#"`))
}

func removeFormValidationHandlers(body []byte) []byte {
	return reFormValidationHandler.ReplaceAll(body, nil)
}

func removeObjectTags(body []byte) []byte {
	out := reObjectElement.ReplaceAll(body, nil)
	return reObjectSelfClosing.ReplaceAll(out, nil)
}

// unhideHiddenFormFields swaps the type only, and does not add a visible marker.
//
// Burp annotates each unhidden field so a tester can see which ones were hidden.
// That is deliberately not done here: it inserts markup the origin never sent into
// a body burpsy also records and passively scans, so a scanner rule matching on the
// marker would report a finding against burpsy's own text. The field's `type` in
// history is the record of what happened.
func unhideHiddenFormFields(body []byte) []byte {
	out := reHiddenDouble.ReplaceAll(body, []byte(`${1}"text"`))
	out = reHiddenSingle.ReplaceAll(out, []byte(`${1}'text'`))
	return reHiddenBare.ReplaceAll(out, []byte(`${1}text`))
}

func convertHTTPSLinks(body []byte) []byte {
	return reHTTPSAttribute.ReplaceAll(body, []byte(`${1}http://`))
}

// enableDisabledFormFields and removeInputFieldLengthLimits each delete one
// attribute from the form controls that carry it, in each of the spellings HTML
// allows: bare (`disabled`), `disabled="disabled"`, `disabled='disabled'`, and
// with whitespace around the `=`. RE2 has no backreferences and the value is
// always the attribute's own name, so one pattern per attribute covers every
// quoting style the way the hidden-type rule above covers them with three.
//
// The controls listed are the ones the HTML spec defines `disabled` on; a
// `disabled` on anything else is not a form control and is left alone.
var (
	// The trailing `([\s/>])` plays the part a lookahead would: it guarantees the
	// word ended — `disabled` must not match inside `disabledx` or a value's
	// continuation — and is written back unchanged through ${3}.
	//
	// The prefix is `tagPrefix`, not `[^>]*?`, and that is the whole correctness of these two
	// rules. `[^>]*?` can stop anywhere, including in the middle of a quoted attribute VALUE, so
	// these deleted the word `disabled` out of ordinary prose:
	//
	//	<input type="text" title="temporarily disabled sorry">
	//	-> <input type="text" title="temporarily sorry">
	//
	// — silently corrupting a page the operator was reading, in a rule they had enabled for an
	// unrelated reason (burpsy-react-ui-q1cm). Burp's implementation is parser-based and does not
	// touch text.
	//
	// RE2 has no lookbehind and no backreferences, so "not inside a quoted value" cannot be
	// asserted directly. tagPrefix gets there structurally instead: it consumes either a character
	// that is not a quote or `>`, or an ENTIRE quoted run. It therefore cannot stop part-way
	// through a value — it either takes the whole thing or stops before it opens.
	reDisabledAttribute  = regexp.MustCompile(`(?is)(<(?:input|textarea|select|option|button|fieldset)\b` + tagPrefix + `)\s+disabled(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?([\s/>])`)
	reMaxlengthAttribute = regexp.MustCompile(`(?is)(<(?:input|textarea)\b` + tagPrefix + `)\s+maxlength(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?([\s/>])`)
)

// tagPrefix matches the attributes between a tag name and the attribute a rule is looking for,
// treating a quoted value as one indivisible unit. See reDisabledAttribute for why that matters.
const tagPrefix = `(?:[^>"']|"[^"]*"|'[^']*')*?`

func enableDisabledFormFields(body []byte) []byte {
	return reDisabledAttribute.ReplaceAll(body, []byte(`${1}${3}`))
}

func removeInputFieldLengthLimits(body []byte) []byte {
	return reMaxlengthAttribute.ReplaceAll(body, []byte(`${1}${3}`))
}

// stripSecureCookieAttributes removes the `Secure` attribute from every
// Set-Cookie header in a response head. It reports false, and changes nothing,
// when no header carried one — so a head the rule did not touch is never
// rebuilt, and the caller can return the original bytes.
//
// Only an attribute that is exactly `Secure` (case-insensitive) is removed: a
// cookie *value* that merely contains the letters, or another attribute such as
// `SiteSafe`, survives. Other headers are not examined, so a body or a
// non-cookie header mentioning "Secure" cannot be touched by a rule aimed at
// cookie flags.
func stripSecureCookieAttributes(head []byte, enabled bool) ([]byte, bool) {
	if !enabled {
		return head, false
	}
	changed := false
	lines := bytes.Split(head, []byte("\n"))
	for i, line := range lines {
		if i == 0 {
			continue // the status line cannot carry a cookie
		}
		trimmed := bytes.TrimRight(line, "\r")
		if len(trimmed) < len("set-cookie:") {
			continue
		}
		name, value, found := bytes.Cut(trimmed, []byte(":"))
		if !found || !strings.EqualFold(string(name), "set-cookie") {
			continue
		}
		parts := strings.Split(string(value), ";")
		kept := parts[:0]
		stripped := false
		for _, part := range parts {
			if strings.EqualFold(strings.TrimSpace(part), "secure") {
				stripped = true
				continue
			}
			kept = append(kept, part)
		}
		if !stripped {
			continue
		}
		changed = true
		newLine := append(bytes.Clone(name), ':')
		newLine = append(newLine, strings.Join(kept, ";")...)
		if bytes.HasSuffix(line, []byte("\r")) {
			newLine = append(newLine, '\r')
		}
		lines[i] = newLine
	}
	if !changed {
		return head, false
	}
	return bytes.Join(lines, []byte("\n")), true
}

// headOnlyResult answers a response whose body rules could not or did not run,
// but whose head the cookie-flag strip may have changed. When the strip changed
// nothing the original bytes come back untouched; when it did, the new head is
// spliced onto the untouched body and the change is counted as a modification —
// the message the client receives is not the message the origin sent, which is
// the definition every counter here is written around.
//
// The body is spliced verbatim, framing included: no header describing it
// changed, so no framing decision is made on its behalf.
func (o *Options) headOnlyResult(raw, head, sep, body []byte, cookieStrip bool) []byte {
	if newHead, changed := stripSecureCookieAttributes(head, cookieStrip); changed {
		o.modified.Add(1)
		return concatMessage(newHead, sep, body)
	}
	return raw
}

// concatMessage splices a head back onto a body with the separator that divided
// them. Used where only the head changed: rebuild would recompute
// Content-Length and normalise framing, and a body that was not edited must not
// be re-framed as a side effect of its head being edited.
func concatMessage(head, sep, body []byte) []byte {
	out := make([]byte, 0, len(head)+len(sep)+len(body))
	out = append(out, head...)
	out = append(out, sep...)
	return append(out, body...)
}

// ---- message surgery -----------------------------------------------------------

// requestHead returns the head of a message, or the whole thing when there is no
// separator. Used by the plain-HTTP path to read a Host header out of bytes it has
// already buffered, rather than consuming the reader a second time.
func requestHead(raw []byte) []byte {
	if head, _, _, ok := httputil.SplitHeadBody(raw); ok {
		return head
	}
	return raw
}

// isHTMLResponse reports whether the Content-Type names HTML. A response with no
// Content-Type at all is treated as not-HTML: guessing from the body would mean
// these rules rewriting something whose type nobody declared.
func isHTMLResponse(head []byte) bool {
	ct0, _ := httputil.HeaderValue(head, "Content-Type")
	ct := strings.ToLower(ct0)
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml")
}

// removeHeader deletes every occurrence of one header from a message, returning
// whether anything was removed. Only the head is touched, and the separator and body
// are copied through unchanged.
func removeHeader(raw []byte, name string) ([]byte, bool) {
	head, body, sep, ok := httputil.SplitHeadBody(raw)
	if !ok {
		return raw, false
	}
	crlf := bytes.Contains(head, []byte("\r\n"))
	normalised := bytes.ReplaceAll(head, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalised, []byte("\n"))
	prefix := strings.ToLower(name) + ":"

	kept := make([][]byte, 0, len(lines))
	removed := false
	for i, line := range lines {
		if i > 0 && strings.HasPrefix(strings.ToLower(string(line)), prefix) {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return raw, false
	}
	eol := []byte("\n")
	if crlf {
		eol = []byte("\r\n")
	}
	var out bytes.Buffer
	out.Grow(len(raw))
	for i, line := range kept {
		if i > 0 {
			out.Write(eol)
		}
		out.Write(line)
	}
	out.Write(sep)
	out.Write(body)
	return out.Bytes(), true
}

// stripProxyHeaderFamily deletes every header whose name begins with "Proxy-" from a
// request — Burp's "strip Proxy-* headers in incoming requests". The prefix match is
// the point: the family (Proxy-Connection, Proxy-Authorization, …) is defined by the
// prefix, not by a closed list.
func stripProxyHeaderFamily(raw []byte) ([]byte, bool) {
	head, body, sep, ok := httputil.SplitHeadBody(raw)
	if !ok {
		return raw, false
	}
	crlf := bytes.Contains(head, []byte("\r\n"))
	normalised := bytes.ReplaceAll(head, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalised, []byte("\n"))

	kept := make([][]byte, 0, len(lines))
	removed := false
	for i, line := range lines {
		if i > 0 && strings.HasPrefix(strings.ToLower(string(line)), "proxy-") {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return raw, false
	}
	eol := []byte("\n")
	if crlf {
		eol = []byte("\r\n")
	}
	var out bytes.Buffer
	out.Grow(len(raw))
	for i, line := range kept {
		if i > 0 {
			out.Write(eol)
		}
		out.Write(line)
	}
	out.Write(sep)
	out.Write(body)
	return out.Bytes(), true
}

// forceConnectionClose rewrites the request's Connection header to "close" (adding one
// when absent) — Burp's "Set Connection: close on requests and on responses". The
// response half is the relay's job: it closes after one exchange when this option is on.
func forceConnectionClose(raw []byte) []byte {
	head, body, sep, ok := httputil.SplitHeadBody(raw)
	if !ok {
		return raw
	}
	crlf := bytes.Contains(head, []byte("\r\n"))
	normalised := bytes.ReplaceAll(head, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalised, []byte("\n"))

	found := false
	for i, line := range lines {
		if i > 0 && strings.HasPrefix(strings.ToLower(string(line)), "connection:") {
			if strings.EqualFold(strings.TrimSpace(string(line[len("connection:"):])), "close") {
				return raw
			}
			lines[i] = []byte("Connection: close")
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, []byte("Connection: close"))
	}
	eol := []byte("\n")
	if crlf {
		eol = []byte("\r\n")
	}
	var out bytes.Buffer
	out.Grow(len(raw) + 24)
	for i, line := range lines {
		if i > 0 {
			out.Write(eol)
		}
		out.Write(line)
	}
	out.Write(sep)
	out.Write(body)
	return out.Bytes()
}

// ApplyRequestEgress runs the two Miscellaneous knobs that shape an outgoing request:
// strip Proxy-* headers (Burp's configPanelProxyMiscellaneous strip) and set
// Connection: close. Called by the relay after Match & Replace and intercept — on the
// bytes that will actually go on the wire, so what the operator edits and what history
// records stay one set.
func (o *Options) ApplyRequestEgress(raw []byte) []byte {
	if o == nil {
		return raw
	}
	out := raw
	if o.Get(OptStripProxyHeaders) {
		if stripped, changed := stripProxyHeaderFamily(out); changed {
			out = stripped
		}
	}
	if o.Get(OptSetConnectionClose) {
		out = forceConnectionClose(out)
	}
	if o.Get(OptUseHTTP10ToServer) {
		out = withHTTPVersion(out, "HTTP/1.0", false)
	}
	return out
}

// rebuild reassembles a message around a new body, fixing Content-Length and — when
// the original was chunked — dropping the Transfer-Encoding header the new body no
// longer uses. Every other header line is copied through byte for byte.
func rebuild(head, sep, body []byte, wasChunked, wasEncoded bool) []byte {
	crlf := bytes.Contains(head, []byte("\r\n"))
	normalised := bytes.ReplaceAll(head, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalised, []byte("\n"))

	kept := make([][]byte, 0, len(lines)+1)
	for i, line := range lines {
		if i == 0 {
			kept = append(kept, line)
			continue
		}
		lower := strings.ToLower(string(line))
		if strings.HasPrefix(lower, "content-length:") {
			continue
		}
		if wasChunked && strings.HasPrefix(lower, "transfer-encoding:") {
			continue
		}
		// The body is plaintext now, so the header describing it as encoded must go. Leaving it would
		// tell the recipient to decompress bytes that are not compressed, which is a broken page
		// rather than an unrewritten one.
		if wasEncoded && strings.HasPrefix(lower, "content-encoding:") {
			continue
		}
		kept = append(kept, line)
	}
	kept = append(kept, []byte("Content-Length: "+strconv.Itoa(len(body))))

	eol := []byte("\n")
	if crlf {
		eol = []byte("\r\n")
	}
	var out bytes.Buffer
	out.Grow(len(body) + len(head) + 32)
	for i, line := range kept {
		if i > 0 {
			out.Write(eol)
		}
		out.Write(line)
	}
	out.Write(sep)
	out.Write(body)
	return out.Bytes()
}
