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

	"github.com/burpsy-go/burpsy/internal/core"
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
	// OptEnableDisabledFormFields removes `disabled` attributes on form fields so greyed-out controls can be edited.
	OptEnableDisabledFormFields OptionKey = "enable_disabled_form_fields"
	// OptRemoveInputLengthLimits removes `maxlength` attributes from form input/textarea controls.
	OptRemoveInputLengthLimits OptionKey = "remove_input_field_length_limits"
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
	// OptRemoveCookieSecureFlag removes the `; Secure` attribute from Set-Cookie headers.
	OptRemoveCookieSecureFlag OptionKey = "remove_cookie_secure_flag"
	// OptStripAcceptEncoding removes the Accept-Encoding header from requests on
	// the way out. Burp's own wording for this option ends "(if not unpacking
	// compressed data)", which is exactly this build's situation: it has no
	// decompressor on the proxy path, so asking the origin for plaintext is the
	// only way the response rules above get a body they can rewrite.
	OptStripAcceptEncoding OptionKey = "strip_accept_encoding"
	// OptUnpackCompressedRequests decompresses a gzip or deflate request body before
	// the request is forwarded, dropping its Content-Encoding and fixing
	// Content-Length. Burp's proxyOptionsUnpackCompressedRequests.
	//
	// Its own switch rather than one shared with the response direction, because
	// they are not the same decision: unpacking a request changes the bytes the
	// *origin* receives, which an application may reject, while unpacking a
	// response changes only what the browser receives.
	OptUnpackCompressedRequests OptionKey = "unpack_compressed_requests"
	// OptUnpackCompressedResponses decompresses a gzip or deflate response body so
	// the response modification rules above can reach it, dropping its
	// Content-Encoding and fixing Content-Length. Burp's
	// proxyOptionsUnpackCompressedResponses; its search keywords are literally
	// "unpack gzip" and "unpack deflate".
	//
	// This is the answer to strip_accept_encoding being the only previous option.
	// Stripping Accept-Encoding changes what the client asks the origin for and is
	// detectable server-side, so it forced a choice between reading the traffic and
	// observing the traffic the client would really have received. Unpacking asks
	// the origin for nothing different.
	//
	// br and zstd are not decoded — there is no standard-library decoder for either
	// — and a response carrying one is counted as SkippedUnsupportedEncoding rather
	// than reported as unpacked. See internal/httputil.Unpackable.
	OptUnpackCompressedResponses OptionKey = "unpack_compressed_responses"
	// OptStripWsExtensions strips the Sec-WebSocket-Extensions header from WebSocket handshakes,
	// so the origin cannot negotiate permessage-deflate and captured frames stay in the clear.
	// Burp's proxy.miscellaneous.strip_sec_websocket_extensions_headers_in_incoming_requests.
	OptStripWsExtensions OptionKey = "strip_sec_websocket_extensions"
	// OptInvisibleProxying enables support for invisible proxying (non-proxy-aware clients).
	OptInvisibleProxying OptionKey = "invisible_proxying"
	// OptDontLogOutOfScopeItems prevents logging/storing out-of-scope items in proxy history.
	OptDontLogOutOfScopeItems OptionKey = "dont_log_out_of_scope_items"
)

// OptionKeys is every editable option, in the order the panel renders them.
// Exported so the API can list the valid keys in a 400 rather than making the
// caller guess, and so a key added here appears in both without a second edit.
var OptionKeys = []OptionKey{
	OptUnhideHiddenFormFields,
	OptEnableDisabledFormFields,
	OptRemoveInputLengthLimits,
	OptRemoveObjectTags,
	OptRemoveJSFormValidation,
	OptRemoveAllJavaScript,
	OptConvertHTTPSLinks,
	OptRemoveCookieSecureFlag,
	OptStripAcceptEncoding,
	OptUnpackCompressedRequests,
	OptUnpackCompressedResponses,
	OptStripWsExtensions,
	OptInvisibleProxying,
	OptDontLogOutOfScopeItems,
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
	OptEnableDisabledFormFields,
	OptRemoveInputLengthLimits,
	OptRemoveObjectTags,
	OptRemoveJSFormValidation,
	OptRemoveAllJavaScript,
	OptConvertHTTPSLinks,
	OptRemoveCookieSecureFlag,
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
	// was ON and the encoding could not be decoded anyway — br or zstd, or a body
	// that failed to decompress. It is separate because the two say different things
	// to an operator who has just ticked the box: "the switch is off" is something
	// they can fix, and "this build cannot decode brotli" is not.
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
	ModifiedUnrecorded uint64 `json:"responses_modified_unrecorded"`
	// DroppedOutOfScope counts exchanges that were dropped from recording because
	// dont_log_out_of_scope_items was enabled.
	DroppedOutOfScope uint64 `json:"dropped_out_of_scope"`
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
	flags[OptStripWsExtensions] = true
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

// NoteDroppedOutOfScope records an exchange dropped from store recording because
// dont_log_out_of_scope_items was enabled.
func (o *Options) NoteDroppedOutOfScope() {
	if o == nil {
		return
	}
	o.droppedOutOfScope.Add(1)
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
	if o.Get(OptStripWsExtensions) && core.IsWsUpgradeRequest(out) {
		if stripped, _, err := core.StripWsExtensionsHeader(out); err == nil {
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
	head, body, sep, ok := splitMessage(raw)
	if !ok {
		o.skippedUnframed.Add(1)
		return raw, false
	}
	encoding := headerValue(head, "Content-Encoding")
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		// Nothing to unpack. Not counted at all: an uncompressed message is not a skip, it is a
		// message the switch has no business touching, and counting it would make the skip ratios
		// meaningless the way Considered already documents for the response rules.
		return raw, false
	}
	if !httputil.Unpackable(encoding) {
		// br, zstd, or a chain of encodings. Counted twice on purpose: SkippedCompressed keeps its
		// meaning as "a compressed message no rule reached", and the narrower counter says the switch
		// was on and could not help.
		o.skippedCompressed.Add(1)
		o.skippedUnsupportedEnc.Add(1)
		return raw, false
	}

	chunked := strings.EqualFold(headerValue(head, "Transfer-Encoding"), "chunked")
	compressed := body
	if chunked {
		// Dechunk before decompressing: the chunk sizes frame the compressed bytes, and feeding
		// `size CRLF data CRLF` to gzip decodes the size prefix as payload.
		decoded, dok := dechunk(body)
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
//   - An encoding this build cannot decode (br, zstd, a chain) is still left alone with the
//     switch on, counted as SkippedUnsupportedEncoding as well, because "the switch is off"
//     and "this build has no brotli decoder" are different things to tell an operator.
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
	o.mu.RUnlock()
	// Unpacking counts as something to do on its own. It is not a rewriting rule — it makes the
	// response *readable*, in history and in every consumer downstream — so a response that is
	// decompressed and matched by no rule is still a response this changed, and returning early on
	// `!any` would have made the switch a no-op unless another box was also ticked.
	if !any && !unpacking {
		return raw
	}
	o.considered.Add(1)

	head, body, sep, ok := splitMessage(raw)
	if !ok {
		o.skippedUnframed.Add(1)
		return raw
	}
	if encoding := headerValue(head, "Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		// Unpack when the operator asked for it, then carry on with the decompressed message — this is
		// the whole point of the switch: "the rule found nothing to rewrite" and "the rule was never
		// allowed to look" were the two states this package was built to distinguish, and a
		// compressed body was permanently in the second.
		if !unpacking {
			o.skippedCompressed.Add(1)
			return raw
		}
		unpacked, uok := o.unpack(raw, &o.unpackedResponses)
		if !uok {
			// unpack counted the reason. SkippedCompressed is added there too, so the panel's
			// "Skipped: compressed" total still covers every compressed response no rule reached.
			return raw
		}
		// Re-split, because the head and the framing have both changed. Recursion is deliberately not
		// used: the message now carries no Content-Encoding, so a second pass could not reach this
		// branch again, and an explicit re-split says that rather than relying on it.
		raw = unpacked
		head, body, sep, ok = splitMessage(raw)
		if !ok {
			o.skippedUnframed.Add(1)
			return raw
		}
		if !any {
			// Decompressed, and no rewriting rule to run. The decompressed message is the result: the
			// switch's job is to make the body readable, and Modified counts it because the bytes
			// really did change.
			o.modified.Add(1)
			return raw
		}
	}
	if !isHTMLResponse(head) {
		o.skippedNotHTML.Add(1)
		return raw
	}

	headModified := false
	if enabled[OptRemoveCookieSecureFlag] {
		newHead := removeCookieSecureFlag(head)
		if !bytes.Equal(newHead, head) {
			head = newHead
			headModified = true
		}
	}

	if !isHTMLResponse(head) {
		if headModified {
			o.modified.Add(1)
			return rebuild(head, sep, body, false, false)
		}
		o.skippedNotHTML.Add(1)
		return raw
	}

	chunked := strings.EqualFold(headerValue(head, "Transfer-Encoding"), "chunked")
	plain := body
	if chunked {
		decoded, ok := dechunk(body)
		if !ok {
			o.skippedUnframed.Add(1)
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
	if enabled[OptRemoveInputLengthLimits] {
		out = removeInputLengthLimits(out)
	}
	if enabled[OptConvertHTTPSLinks] {
		out = convertHTTPSLinks(out)
	}

	if !headModified && bytes.Equal(out, plain) {
		// Nothing fired. Return the original bytes, chunk framing and all: a
		// response the rules did not change must not be re-framed as a side effect
		// of having been looked at.
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
	reHiddenDouble      = regexp.MustCompile(`(?is)(<input\b[^>]*?\btype\s*=\s*)"hidden"`)
	reHiddenSingle      = regexp.MustCompile(`(?is)(<input\b[^>]*?\btype\s*=\s*)'hidden'`)
	reHiddenBare        = regexp.MustCompile(`(?is)(<input\b[^>]*?\btype\s*=\s*)hidden\b`)
	reDisabledAttr      = regexp.MustCompile(`(?is)\sdisabled\b(\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?`)
	reMaxLengthAttr     = regexp.MustCompile(`(?is)\smaxlength\b(\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?`)
	reCookieSecureFlag  = regexp.MustCompile(`(?i)(Set-Cookie\s*:[^\r\n]*?);\s*Secure\b`)
	reHTTPSAttribute    = regexp.MustCompile(`(?is)(\s(?:href|src|action)\s*=\s*["']?)https://`)
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

func enableDisabledFormFields(body []byte) []byte {
	return reDisabledAttr.ReplaceAll(body, nil)
}

func removeInputLengthLimits(body []byte) []byte {
	return reMaxLengthAttr.ReplaceAll(body, nil)
}

func removeCookieSecureFlag(msg []byte) []byte {
	return reCookieSecureFlag.ReplaceAll(msg, []byte(`${1}`))
}

func convertHTTPSLinks(body []byte) []byte {
	return reHTTPSAttribute.ReplaceAll(body, []byte(`${1}http://`))
}

// ---- message surgery -----------------------------------------------------------

// splitMessage returns the head (status line and headers, without the terminator),
// the body, and the separator that divided them, so a rebuild can put back the same
// line endings it found rather than normalising a message it was only asked to edit.
func splitMessage(raw []byte) (head, body, sep []byte, ok bool) {
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[:idx], raw[idx+4:], []byte("\r\n\r\n"), true
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[:idx], raw[idx+2:], []byte("\n\n"), true
	}
	return nil, nil, nil, false
}

// requestHead returns the head of a message, or the whole thing when there is no
// separator. Used by the plain-HTTP path to read a Host header out of bytes it has
// already buffered, rather than consuming the reader a second time.
func requestHead(raw []byte) []byte {
	if head, _, _, ok := splitMessage(raw); ok {
		return head
	}
	return raw
}

// headerValue reads one header out of a head block, or "" when it is absent. The
// first occurrence wins, matching how every parser in this tree reads a header that
// should not be repeated.
func headerValue(head []byte, name string) string {
	prefix := strings.ToLower(name) + ":"
	for _, line := range splitHeadLines(head) {
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(string(line)), prefix) {
			return strings.TrimSpace(string(line[len(prefix):]))
		}
	}
	return ""
}

// splitHeadLines splits a head into lines, skipping the status/request line, and
// tolerating both CRLF and bare LF.
func splitHeadLines(head []byte) [][]byte {
	normalised := bytes.ReplaceAll(head, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalised, []byte("\n"))
	if len(lines) <= 1 {
		return nil
	}
	return lines[1:]
}

// isHTMLResponse reports whether the Content-Type names HTML. A response with no
// Content-Type at all is treated as not-HTML: guessing from the body would mean
// these rules rewriting something whose type nobody declared.
func isHTMLResponse(head []byte) bool {
	ct := strings.ToLower(headerValue(head, "Content-Type"))
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml")
}

// removeHeader deletes every occurrence of one header from a message, returning
// whether anything was removed. Only the head is touched, and the separator and body
// are copied through unchanged.
func removeHeader(raw []byte, name string) ([]byte, bool) {
	head, body, sep, ok := splitMessage(raw)
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

// dechunk collapses `size CRLF data CRLF … 0 CRLF trailer CRLF` to the data. It
// returns false for framing it cannot parse, so a malformed body is left alone
// rather than guessed at.
func dechunk(body []byte) ([]byte, bool) {
	var out bytes.Buffer
	rest := body
	for {
		eol := bytes.IndexByte(rest, '\n')
		if eol < 0 {
			return nil, false
		}
		sizeLine := strings.TrimSpace(string(rest[:eol]))
		rest = rest[eol+1:]
		// A chunk extension (`1a;name=value`) is legal and its size is the part
		// before the semicolon.
		if semi := strings.IndexByte(sizeLine, ';'); semi >= 0 {
			sizeLine = strings.TrimSpace(sizeLine[:semi])
		}
		size, err := strconv.ParseInt(sizeLine, 16, 64)
		if err != nil || size < 0 {
			return nil, false
		}
		if size == 0 {
			// Terminating chunk. The trailer, if any, is discarded with the framing
			// it belonged to: a Content-Length body has nowhere to put one.
			return out.Bytes(), true
		}
		if int64(len(rest)) < size {
			return nil, false
		}
		out.Write(rest[:size])
		rest = rest[size:]
		// The CRLF after the chunk data.
		if len(rest) >= 2 && rest[0] == '\r' && rest[1] == '\n' {
			rest = rest[2:]
		} else if len(rest) >= 1 && rest[0] == '\n' {
			rest = rest[1:]
		} else {
			return nil, false
		}
	}
}
