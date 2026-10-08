package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/session"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/query"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/sequencer"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// ---- Repeater ----------------------------------------------------------------------------------

// repeaterSendReq mirrors repeater.ts's send payload.
type repeaterSendReq struct {
	Target   string `json:"target"`   // e.g. "http://host:port" or "host:port"
	Protocol string `json:"protocol"` // optional "http" / "https"
	Request  string `json:"request"`  // raw request text
	// RequestBase64, when set, is the request's exact bytes base64-encoded, and takes precedence over
	// Request (burpsy-react-ui-ytkk). A JSON string cannot carry a binary body: a non-UTF-8 byte is
	// replaced with U+FFFD on the way through, so a protobuf/gRPC body edited in Repeater and sent as
	// `request` would go out corrupted. Base64 round-trips the exact octets, and Go's
	// string([]byte)/[]byte(string) is byte-exact, so the decoded bytes reach the sender unchanged.
	RequestBase64 string `json:"request_base64,omitempty"`
	// FromExchange is the exchange this send was built from, when the operator reached Repeater via
	// send-to rather than by typing a request. Recorded as the new exchange's parent so a resend can
	// be traced back to the capture it came from. A pointer because exchange 0 is a real exchange and
	// is very often the first thing sent to Repeater.
	FromExchange *core.ExchangeID `json:"from_exchange,omitempty"`
	// Options carries the per-send overrides (Burp Repeater's config-override menu). Nil means the
	// standing behaviour in full — the zero options are the defaults, so an absent object and an
	// empty one mean the same thing.
	Options *repeaterSendOptions `json:"options,omitempty"`
	// Note is the tab's Notes panel text (burpsy-react-ui-jva5), recorded as the new exchange's
	// comment. Burp: "if you send a message from Repeater to another tool, your notes and
	// highlights are copied across" — every tool that reads an exchange's notes (HTTP history's
	// comment column, Organizer's add, Logger) then has it without a second channel. Empty records
	// no comment rather than an empty one.
	Note string `json:"note,omitempty"`
	// SNI is the tab's Override SNI (burpsy-react-ui-k011): the server name the TLS ClientHello
	// carries instead of the target's, to reproduce an SNI-based external service interaction with a
	// Collaborator domain. Only the ClientHello changes — the address dialled, the Host header and
	// certificate verification stay the target's — and a redirect hop never carries it. Empty is no
	// override. Refused on a plaintext target, where there is no ClientHello to put it in.
	SNI string `json:"sni,omitempty"`
	// TabID is the Repeater tab this send comes from, which keys the tab's reused h2 connection when
	// h2_connection_reuse is on (adkx). Opaque to the server; absent shares one key.
	TabID string `json:"tab_id,omitempty"`
}

// validRepeaterSNI checks an Override SNI against the target it rides: a valid server name, on a TLS
// target. field names the request key.
func validRepeaterSNI(field, sni string, tls bool) error {
	if sni == "" {
		return nil
	}
	if !tls {
		return fmt.Errorf("refused: %s is set but the target is plain HTTP; there is no TLS ClientHello to carry it", field)
	}
	if err := sender.ValidateSNI(field, sni); err != nil {
		return fmt.Errorf("refused: %w", err)
	}
	return nil
}

// maxRepeaterNoteBytes bounds a tab note carried on a send. A note is prose about one request, and
// it is persisted with the exchange; a megabyte "note" is a paste into the wrong box, refused with
// the limit named rather than silently stored or truncated.
const maxRepeaterNoteBytes = 64 << 10

// validRepeaterNote refuses a note over the bound. field names the request key so a group send can
// say which item carried it.
func validRepeaterNote(field, note string) error {
	if len(note) > maxRepeaterNoteBytes {
		return fmt.Errorf("refused: %s is %d bytes; a tab note is at most %d bytes", field, len(note), maxRepeaterNoteBytes)
	}
	return nil
}

// repeaterSendResp mirrors repeater.ts's SendResp.
type repeaterSendResp struct {
	Status        int             `json:"status"`
	DurationMs    uint64          `json:"duration_ms"`
	Response      string          `json:"response"`
	RequestMsgID  uint64          `json:"request_msg_id"`
	ResponseMsgID uint64          `json:"response_msg_id"`
	ExchangeID    core.ExchangeID `json:"exchange_id"`
	// ResponseBodyBase64 is the response body's exact octets when they are not UTF-8 — the same rule and
	// the same decoding as a MessageView's body_base64 — so the response pane can show a binary body
	// (a gRPC reply in the Protobuf tab, burpsy-react-ui-3pco) that `response` cannot carry.
	ResponseBodyBase64 string `json:"response_body_base64,omitempty"`
	// Redirects is the chain this send produced, and it is present only when the response was a 30x.
	//
	// `response` above stays the response to the request the operator wrote — that is the contract
	// Repeater has, and replacing those bytes with a later hop's would hide the Set-Cookie and the
	// Location an operator opened Repeater to look at. So the chain is reported alongside rather than
	// substituted, with every hop saying whether it was followed and why not when it was not. A nil
	// field means "not a redirect"; a field present with `followed: false` on every hop means the
	// policy or the scope stopped it, which are different facts and are named differently.
	Redirects *repeaterRedirects `json:"redirects,omitempty"`
	// ResponseUnpacked is the response with its compressed body decoded for display, present only
	// when the response declared a Content-Encoding this build decodes and the tab unpacks (Burp's
	// default; of0z). `response` stays the bytes that arrived, which is also what is stored.
	ResponseUnpacked string `json:"response_unpacked,omitempty"`
	// ResponseUnpackedBodyBase64 is the unpacked body's exact octets when they are not UTF-8, by the
	// same rule as response_body_base64.
	ResponseUnpackedBodyBase64 string `json:"response_unpacked_body_base64,omitempty"`
	// UnpackedFrom names the encoding that was decoded, or that could not be.
	UnpackedFrom string `json:"unpacked_from,omitempty"`
	// UnpackError says why a compressed response is shown packed: no decoder for its encoding, or a
	// body that would not decode. Absent when there was nothing to unpack or it unpacked.
	UnpackError string `json:"unpack_error,omitempty"`
	// H2Connection says, when the tab reuses HTTP/2 connections (adkx), whether this request was the
	// first on its connection ("new"), a later one ("reused"), or did not ride h2 at all ("not-h2").
	// Absent when reuse is off, where every request is the first on a fresh connection.
	H2Connection string `json:"h2_connection,omitempty"`
}

// repeaterRedirects is the follow outcome as the panel reads it.
type repeaterRedirects struct {
	// Mode is the policy that was in force, so a chain that followed nothing says whether that is
	// because following is off or because something refused it.
	Mode string `json:"mode"`
	// Sent counts every request this exchange put on the wire, the operator's own included.
	Sent int `json:"sent"`
	// Complete is false when the chain was still redirecting when it stopped.
	Complete bool          `json:"complete"`
	Hops     []repeaterHop `json:"hops"`
	// FinalStatus is the status of the last response received, which differs from `status` above
	// whenever a hop was actually followed.
	FinalStatus int `json:"final_status"`
	// Error is set when the chain could not be evaluated at all — the response was unreadable, say.
	// Reported rather than dropped: "we did not look" must not render as "there was nothing to follow".
	Error string `json:"error,omitempty"`
}

// repeaterHop is one hop as the panel reads it: the sender's hop decision plus, on a followed hop, the
// bytes its request put on the wire and the bytes that came back.
//
// The bytes are the point of this shape — Burp stores the full requests and responses of a redirection
// chain with each result item, and the previous wire shape answered every question about a hop except
// the one an operator follows a chain to ask. They ride here rather than on sender.RedirectHop's own
// JSON because the byte images are engine state there; what a browser sees is this layer's decision.
type repeaterHop struct {
	sender.RedirectHop
	// Request and Response carry the hop's wire bytes as text, empty when the hop was not followed —
	// a hop that was never sent has no bytes, and an empty string means exactly that rather than
	// "an empty request or response happened".
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
}

// repeaterSendSpec is one Repeater send resolved to everything the wire half needs: the authority to
// dial, the exact bytes to write, and the bookkeeping the exchange row records.
//
// It exists so /api/repeater/send and /api/repeater/send-group cannot drift. A group send is N sends,
// and the moment "N sends" meant a second copy of the target parsing, the options validation, the
// transform order and the scope gate, one of the two copies would be the one that stops matching —
// and the one that stops matching is always the one whose scope decision nobody re-read.
type repeaterSendSpec struct {
	Host string
	Port uint16
	TLS  bool
	// Raw is what goes on the wire: the operator's request with this send's transforms applied.
	Raw []byte
	// AsWritten is the request text *before* the transforms, which is what the exchange row's Method
	// and Path are read from — the same source the single send has always used, so a transform cannot
	// silently re-label a history row.
	AsWritten string
	Options   repeaterSendOptions
	From      *core.ExchangeID
	// Note is the tab's note, written onto the exchange as its comment (jva5). Set by the handlers
	// after prepareRepeaterSend, because it shapes the record, not the wire.
	Note string
	// SNI is the tab's Override SNI (k011), validated by the handlers against TLS.
	SNI string
	// TabID keys the tab's reused h2 connection, and H2Sessions is the pool it lives in — set only
	// when the tab asked for HTTP/2 connection reuse (adkx).
	TabID      string
	H2Sessions *sender.H2Sessions
}

// sendContext is ctx carrying everything this send overrides: the tab's options (response timeout,
// streaming window) and its Override SNI.
func (spec repeaterSendSpec) sendContext(ctx context.Context) context.Context {
	ctx = spec.Options.sendContext(ctx)
	if spec.SNI == "" && spec.H2Sessions == nil {
		return ctx
	}
	opts, _ := sender.SendOptionsFrom(ctx)
	opts.SNI = spec.SNI
	if spec.H2Sessions != nil {
		opts.H2Sessions = spec.H2Sessions
		opts.H2SessionKey = spec.TabID
	}
	return sender.WithSendOptions(ctx, opts)
}

// prepareRepeaterSend resolves one send's target, validates its options, applies its transforms and
// runs the host-level scope gate, in that order. It returns the HTTP status a refusal should carry,
// so the two handlers report an identical refusal for identical input; code is 0 on success.
//
// The order is load-bearing and is the single send's original order: options are validated before
// anything they could affect, because a send that half-applied an options object would put bytes on
// the wire shaped by an option the caller believes was something else.
func (s *Server) prepareRepeaterSend(
	target, protocol, request string, options *repeaterSendOptions, from *core.ExchangeID,
) (spec repeaterSendSpec, code int, err error) {
	host, port, tls, err := targetParts(target)
	if err != nil {
		return repeaterSendSpec{}, http.StatusBadRequest, err
	}
	if strings.EqualFold(protocol, "https") {
		tls = true
	} else if strings.EqualFold(protocol, "http") {
		tls = false
	}
	if strings.TrimSpace(request) == "" {
		return repeaterSendSpec{}, http.StatusBadRequest, errors.New("Empty request")
	}
	var opts repeaterSendOptions
	if options != nil {
		opts = *options
		if verr := opts.validate(); verr != nil {
			return repeaterSendSpec{}, http.StatusBadRequest, fmt.Errorf("refused: %w", verr)
		}
	}
	// The transforms run before the scope gate on the transformed bytes — though the gate is
	// host-level and no transform changes the authority, so this ordering is about the stored
	// exchange recording what actually went out, not about which bytes the gate saw.
	raw := opts.applyToRequest([]byte(request), s.cookieHeaderFor(host, port, tls, targetPathOf(target)))
	// The repeater sends to whatever target the operator types, so it is gated
	// by scope for the same reason the intruder is: a scope the operator set to
	// constrain outbound traffic must not be bypassable by sending raw bytes
	// here. The request line is not parsed (the operator owns it), so this is a
	// host-level check, the same first layer the intruder applies.
	if !s.scope.MayContainHost(host, port, tls) {
		return repeaterSendSpec{}, http.StatusForbidden, errors.New("refused: " + s.scope.Explain(host, port, "/", tls))
	}
	spec = repeaterSendSpec{
		Host: host, Port: port, TLS: tls, Raw: raw, AsWritten: request, Options: opts, From: from,
	}
	if opts.H2ConnectionReuse {
		spec.H2Sessions = s.repeaterH2Sessions()
	}
	return spec, 0, nil
}

// recordRepeaterExchange persists both halves of one completed send, writes its exchange row and its
// tool-log line, and returns the response the panel reads. The redirect chain is not evaluated here —
// see sendOneRepeaterRequest, which adds it, and the group send's single-connection mode, which
// deliberately does not.
//
// duration is passed in rather than measured here because not every caller can measure one: a send
// that rode a shared socket inside sender.SendKeepAlive has no per-exchange timing to report, and
// core.UnmeasuredDuration is how that is said out loud instead of being written as a zero that reads
// as an instantaneous send.
func (s *Server) recordRepeaterExchange(
	spec repeaterSendSpec, rawResp []byte, protocol core.Protocol, duration core.ExchangeDuration, started time.Time,
) (resp repeaterSendResp, ex *core.Exchange) {
	// Persist both halves so history/decoder can reference them. A failed Put
	// must not be silently swallowed: an exchange referencing a non-existent
	// message ID would 404 in history lookups. Log and degrade rather than
	// advertise a bad id.
	reqMsgID, err := s.store.Put(spec.Raw, core.DirectionRequest)
	if err != nil {
		s.logger.Error("repeater: failed to store request", zap.Error(err))
	}
	respMsgID, err := s.store.Put(rawResp, core.DirectionResponse)
	if err != nil {
		s.logger.Error("repeater: failed to store response", zap.Error(err))
	}

	status := parseResponseStatus(rawResp)

	ex = &core.Exchange{
		Host:        spec.Host,
		Port:        spec.Port,
		TLS:         spec.TLS,
		Method:      firstLineMethod(spec.AsWritten),
		Path:        firstLinePath(spec.AsWritten),
		Status:      status,
		ResponseLen: len(rawResp),
		// From the bytes that just came back, for the same reason ResponseLen is taken here: history
		// serves index rows and must not reopen a response to type it. See core.Exchange.Mime.
		Mime:      core.MimeEssence(rawResp),
		StartedMs: uint64(started.UnixMilli()),
		Duration:  duration,
		Request:   core.MsgPtr(reqMsgID),
		Response:  &respMsgID,
		// What actually carried the send, not what the request bytes asked for. outcome.Downgrade says why
		// it was HTTP/1.1 when it was, and Sender.Protocols counts it across every surface.
		Protocol: protocol,
		// Lineage, when the caller named one. Validated rather than trusted: a parent id pointing at
		// nothing would be a link that resolves to the wrong row or to no row, which is the failure
		// mode the whole exchange-id typing exercise exists to stop.
		ParentID: s.validParent(spec.From),
		// SourceRepeater, not the unattributed zero value: this was not traffic the operator's
		// client proxied, and HTTP history must not claim it was. It is recorded in the tool log
		// below, which is the view whose subject is requests burpsy itself made — the same way
		// Burp keeps a Repeater send out of Proxy history.
		Source: core.SourceRepeater,
	}
	if spec.Note != "" {
		// A copy: the spec outlives this row only briefly, but a pointer into a struct field that a
		// later caller reuses is the kind of aliasing that writes one tab's note onto another's row.
		note := spec.Note
		ex.Notes = &note
	}
	s.store.AddExchange(ex)

	// The cookie jar's monitored-tool set (burpsy-react-ui-sn3j): a Repeater response is a
	// response the operator drove by hand, and Burp's jar can be configured to monitor the
	// Repeater for exactly this. Absorbed from the raw bytes at the capture point — the same
	// discipline the proxy path holds — and after the store write so a jar error can never lose
	// the exchange. Source-attributed so the toggle can tell this surface's responses from the
	// proxy's in Observation.
	if s.sessionCoordinator != nil {
		s.sessionCoordinator.AbsorbResponseCookies(session.SourceRepeater, spec.Host, spec.Port, spec.TLS, rawResp)
	}

	// The same count the exchange row carries, taken from the same bytes, so Logger and HTTP history
	// cannot disagree about the size of one send.
	// Linked to the exchange just written, so Logger's message viewer can resolve this row's bytes
	// (burpsy-react-ui-5bl). &ex.ID, never a zero: the traffic store counts from zero, so exchange 0
	// is a real row and a nil-less zero would point the viewer at the wrong message pair.
	s.toolLog.Record(toollog.ToolRepeater, spec.Host, spec.Port, spec.TLS, ex.Method, ex.Path, intOrZero(status),
		toollog.Bytes(len(rawResp)), ex.Duration.Millis(), "", &ex.ID)

	resp = repeaterSendResp{
		Status:             intOrZero(status),
		DurationMs:         ex.Duration.Millis(),
		Response:           string(rawResp),
		RequestMsgID:       uint64(reqMsgID),
		ResponseMsgID:      uint64(respMsgID),
		ExchangeID:         ex.ID,
		ResponseBodyBase64: displayBodyBase64(rawResp),
	}
	if spec.Options.unpack() {
		// Display only (of0z): the stored response above is the bytes that arrived.
		if unpacked, encoding, applies, uerr := unpackedResponse(rawResp); applies {
			resp.UnpackedFrom = encoding
			if uerr != nil {
				resp.UnpackError = uerr.Error()
			} else {
				resp.ResponseUnpacked = string(unpacked)
				resp.ResponseUnpackedBodyBase64 = displayBodyBase64(unpacked)
			}
		}
	}
	return resp, ex
}

// sendOneRepeaterRequest is one send on its own fresh connection, end to end: the wire, the stored
// exchange, the tool log and the redirect chain. It is the whole of /api/repeater/send's wire half,
// and it is what the group send's two separate-connection modes fan out over — sequentially or
// concurrently — so those modes reinvent no scope-checking and no result-shaping.
func (s *Server) sendOneRepeaterRequest(ctx context.Context, spec repeaterSendSpec) (repeaterSendResp, error) {
	// SendRaw handles a raw HTTP request (possibly HTTP/1.0-style with Host line) over the wire.
	// Timed here because SendRaw does not report a duration and the exchange row used to be written with a
	// hardcoded zero — which, before core.ExchangeDuration existed, was indistinguishable from a
	// sub-millisecond send, so the repeater's own "duration_ms: 0" reply looked like a measurement.
	//
	// SendRawOutcome rather than SendRaw because this row records a Protocol, and since H2-04 the answer is
	// no longer knowable from the request bytes: an HTTP/1.1 request to a target that negotiates h2 goes out
	// as h2. The field used to be a hardcoded ProtocolHTTP1, which was already wrong whenever an operator
	// The tab's response timeout (mmca) rides the context, so it bounds this send and every redirect
	// hop below without touching the network settings the next send reads.
	ctx = spec.sendContext(ctx)
	sendStarted := time.Now()
	rawResp, outcome, err := s.sender.SendRawOutcome(ctx, spec.Host, spec.Port, spec.TLS, spec.Raw, spec.Options.protocolPreference())
	elapsed := time.Since(sendStarted)
	if err != nil {
		// Surface the dial/parse error to the UI so Repeater is not silently empty.
		// nil, not zero: the send never reached a response, which is a different fact from a response
		// that arrived with no bytes in it.
		// nil exchange as well as nil length: the send never reached a response, so nothing was
		// stored and there are no bytes for Logger's viewer to resolve.
		s.toolLog.Record(toollog.ToolRepeater, spec.Host, spec.Port, spec.TLS, "SEND", "", 0, nil, 0, err.Error(), nil)
		return repeaterSendResp{}, err
	}
	resp, _ := s.recordRepeaterExchange(spec, rawResp, outcome.Protocol, core.MeasuredDuration(elapsed), sendStarted)
	if spec.H2Sessions != nil {
		// Whether this request was the first on its connection — the fact HTTP/2 connection reuse
		// exists to let an operator control (adkx).
		switch {
		case outcome.Protocol != core.ProtocolHTTP2:
			resp.H2Connection = "not-h2"
		case outcome.ConnectionReused:
			resp.H2Connection = "reused"
		default:
			resp.H2Connection = "new"
		}
	}
	// HopContext: a hop keeps the send's timeouts but never the SNI override, which names this
	// target's handshake rather than wherever a Location points next (k011).
	resp.Redirects = s.followRepeaterRedirects(sender.HopContext(ctx), spec.Host, spec.Port, spec.TLS, spec.Raw, rawResp, spec.Options, outcome.Protocol)
	return resp, nil
}

func (s *Server) handleRepeaterSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req repeaterSendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	request := req.Request
	if req.RequestBase64 != "" {
		b, derr := base64.StdEncoding.DecodeString(req.RequestBase64)
		if derr != nil {
			http.Error(w, "request_base64 is not valid base64", http.StatusBadRequest)
			return
		}
		request = string(b)
	}
	if err := validRepeaterNote("note", req.Note); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	spec, code, err := s.prepareRepeaterSend(req.Target, req.Protocol, request, req.Options, req.FromExchange)
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	spec.Note = req.Note
	if err := validRepeaterSNI("sni", req.SNI, spec.TLS); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	spec.SNI = req.SNI
	spec.TabID = req.TabID
	resp, err := s.sendOneRepeaterRequest(r.Context(), spec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// followRepeaterRedirects applies this send's redirect policy to a send that already happened — the
// per-send override when one was given, otherwise the network settings' standing policy.
//
// Returns nil when the response is not a redirect, so the field is absent for the ordinary case rather
// than present and empty — a client can treat its presence as "there was a chain here".
//
// The hops go through sender.AuthorisedSender, which is what makes offering this safe: the repeater's own
// gate on the first request is host-level by design, but a hop is a request a Location chose, so it is
// authorised on its rendered bytes for the authority it names. Under the default RedirectNever nothing
// is sent and the answer records that the policy is what stopped it — so an operator who never opens the
// Network panel gets one request per click, exactly as before.
func (s *Server) followRepeaterRedirects(
	ctx context.Context, host string, port uint16, tls bool, raw, rawResp []byte, opts repeaterSendOptions,
	carried core.Protocol,
) *repeaterRedirects {
	standing := s.sender.Network().Redirects
	policy := opts.redirectPolicy(standing)
	if opts.EnforceProtocolCrossDomain {
		// Burp's "selected protocol" is the one this request went out over (adkx).
		policy.CrossDomainProtocol = sender.ProtocolPreferenceHTTP1
		if carried == core.ProtocolHTTP2 {
			policy.CrossDomainProtocol = sender.ProtocolPreferenceForceH2
		}
	}
	mode := string(policy.Mode)
	authorised := sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls)
	result, err := authorised.FollowRedirectsAfterPolicy(ctx, raw, rawResp, policy)
	if err != nil {
		// The send succeeded and this did not, so the exchange still stands. Naming the failure is the
		// honest option: a nil here would say "not a redirect", which is a claim we cannot make.
		return &repeaterRedirects{Mode: mode, Sent: 1, Hops: []repeaterHop{}, Error: err.Error()}
	}
	if len(result.Hops) == 0 {
		return nil
	}
	final := 0
	if result.Final != nil {
		final = result.Final.StatusCode
	}
	// The hop bytes are carried as text, not a message id to fetch: the chain arrives alongside the
	// send's own response and is rendered by the same panel in the same breath, so a second round trip
	// per hop would buy nothing the bytes on this response do not already carry. Each one is bounded by
	// the same response cap the first response is, so a fat landing page is no wider here than
	// `response` above.
	hops := make([]repeaterHop, len(result.Hops))
	for i, hop := range result.Hops {
		hops[i] = repeaterHop{RedirectHop: hop}
		if len(hop.RequestRaw) > 0 {
			hops[i].Request = string(hop.RequestRaw)
		}
		if len(hop.ResponseRaw) > 0 {
			hops[i].Response = string(hop.ResponseRaw)
		}
	}
	return &repeaterRedirects{
		Mode:        mode,
		Sent:        result.Sent,
		Complete:    result.Complete,
		Hops:        hops,
		FinalStatus: final,
	}
}

// targetPathOf extracts the request path from a wire target for the cookie jar's §5.4
// path-match ("http://host:port/api/x" -> "/api/x"). The cookie jar decides per request which
// cookies the request carries, and the path is the component of the target that decides it —
// the same split targetParts performs for the authority, for the other half of the rule.
func targetPathOf(target string) string {
	rest := target
	if cut := strings.Index(rest, "://"); cut >= 0 {
		rest = rest[cut+3:]
	}
	start := strings.IndexAny(rest, "/?#")
	if start < 0 {
		return "/"
	}
	rest = rest[start:]
	if end := strings.IndexAny(rest, "?#"); end >= 0 {
		rest = rest[:end]
	}
	if rest == "" {
		return "/"
	}
	return rest
}

// cookieHeaderFor returns the session coordinator's cookie header for the target, or empty when
// there is no coordinator — a nil check, not a hope: the coordinator is an optional capability and
// a nil dereference here would take the whole send down for an option that is off by default.
func (s *Server) cookieHeaderFor(host string, port uint16, tls bool, path string) string {
	if s.sessionCoordinator == nil {
		return ""
	}
	return s.sessionCoordinator.CookieHeader(host, port, tls, path)
}

// ---- Intruder ----------------------------------------------------------------------------------

// The wire contract here is the Rust web layer's (crates/web/src/lib.rs), consumed byte-for-byte
// by the bundled UI's intruder.ts: PointsReq/PointView for inspection, and RunReq/RunView — or
// the legacy flat AttemptView[] array — for an attack. Both shapes come off the same engine, so
// there is one execution path, one rate limiter, and one place scope is enforced.

const (
	intruderDefaultRPS         = 20.0
	intruderMinRPS             = 0.01
	intruderMaxInFlightCeiling = 999
	// intruderMaxDelayIncrementMS is Burp's own validation bound on a delay in milliseconds
	// (Zb33, the same 600000 that bounds "Pause before retry"). An increment is applied once per
	// request, so beyond this a two-request attack is already an hour long.
	intruderMaxDelayIncrementMS = 600000
	intruderDefaultMaxPayloads  = 10_000
	intruderMaxThrottleStatuses = 32
	// The legacy form keeps its original 500-request cap so a fat paste cannot become an
	// accidental DoS; the report form's bound is the operator's.
	intruderLegacyBound  = 500
	intruderDefaultBound = 5_000
	intruderMaxBound     = 200_000
	// Per-send timeout, matching burpsy-sender's default. The Go sender dials fresh per send, so
	// the bound is applied per request rather than to the attack as a whole.
	intruderDefaultTimeoutMS = 15_000
)

// intruderPointsReq mirrors the Rust PointsReq: which stored message, and whether to discover
// every position family or the defaults.
type intruderPointsReq struct {
	MsgID uint64 `json:"msg_id"`
	All   bool   `json:"all"`
	// PayloadPlacement is Burp's "Automatic payload placement" (burpsy-react-ui-1krs): "" or
	// "replace" (the default, what every request got before) or "append". The run request carries the
	// same field, and the two must agree: these are the spans the UI shows, and /run builds its own.
	PayloadPlacement string `json:"payload_placement,omitempty"`
}

// PointView is one discoverable insertion point. Index is the position in the returned slice —
// that is the handle the UI echoes back in a run's `points`, not a byte offset.
//
// Offset and Len are the bytes a payload goes into: for an appending position (placement "append",
// burpsy-react-ui-1krs) that is the zero-length point after the value — or, for a nested value whose
// outer encoding is rebuilt, the whole value. Current is always the base value the position carries,
// so an appended position still names the text its payloads are added to rather than "".
type PointView struct {
	Index     int    `json:"index"`
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Offset    int    `json:"offset"`
	Len       int    `json:"len"`
	Current   string `json:"current"`
	Placement string `json:"placement"`
}

// intruderPointConfig is the discovery configuration both /points and /run build from a request, so
// the positions the UI shows are the positions the attack splices — the same family set and the same
// placement, from one function.
func intruderPointConfig(all bool, placement string) (*intruder.PointConfig, error) {
	cfg := intruder.DefaultPointConfig()
	if all {
		cfg = intruder.AllPointConfig()
	}
	p, err := intruder.ParsePlacement(placement)
	if err != nil {
		return nil, err
	}
	cfg.Placement = p
	return cfg, nil
}

// handleIntruderPoints inspects a stored request for attack insertion points. The UI sends the
// message id it just captured; this answers with the Rust PointView shape.
func (s *Server) handleIntruderPoints(w http.ResponseWriter, r *http.Request) {
	// Every other route in this file guards its verb; these two did not, so a GET reached the body
	// decoder, failed on an empty body and answered "Invalid request body" — a complaint about the
	// payload for what is really a wrong-method call. Phase 1's move to Go 1.22 `"POST /api/..."`
	// patterns makes the whole class unrepresentable; until then it is spelled out.
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req intruderPointsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	msg, err := s.store.Get(core.MsgId(req.MsgID))
	if err != nil {
		http.Error(w, "no such message", http.StatusNotFound)
		return
	}
	cfg, err := intruderPointConfig(req.All, req.PayloadPlacement)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	found := intruder.FindPoints(msg, cfg)
	out := make([]PointView, 0, len(found))
	for i, p := range found {
		placement := intruder.PlacementReplace
		if p.Append {
			placement = intruder.PlacementAppend
		}
		out = append(out, PointView{
			Index:     i,
			Kind:      p.Kind.String(),
			Label:     p.Label,
			Offset:    p.Span.Offset,
			Len:       p.Span.Len,
			Current:   msg.Text(p.BaseSpan()),
			Placement: placement.String(),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// intruderRunReq mirrors the Rust RunReq. Pointers distinguish "absent" from "zero", which the
// request semantics depend on (a named empty mode list is a 400, an absent one is sniper).
// autoPauseReq is the wire form of Burp's auto-pause settings: the expression list, the
// appears/missing mode, simple-string vs regex matching, and case sensitivity.
type autoPauseReq struct {
	Expressions   []string `json:"expressions"`
	Missing       bool     `json:"missing"`
	Simple        bool     `json:"simple"`
	CaseSensitive bool     `json:"case_sensitive"`
}

type intruderRunReq struct {
	MsgID      uint64 `json:"msg_id"`
	Target     string `json:"target"`
	All        bool   `json:"all"`
	PointIndex *int   `json:"point_index"`
	// PayloadPlacement is "Automatic payload placement" (1krs), the same field /points takes: the
	// discovered positions `points` indexes are rebuilt here with it, so it must be what the UI
	// discovered with. Manual points are never affected.
	PayloadPlacement string                    `json:"payload_placement,omitempty"`
	ManualPoints     *[]intruder.ManualSpan    `json:"manual_points"`
	Payloads         *[]string                 `json:"payloads"`
	Mode             *string                   `json:"mode"`
	Points           *[]int                    `json:"points"`
	PayloadSets      *[][]string               `json:"payload_sets"`
	PayloadSources   *[]intruder.PayloadSource `json:"payload_sources"`
	PayloadRules     *[]intruder.RuleSpec      `json:"payload_rules"`
	// AutoPause is Burp's auto-pause (burpsy-react-ui-8f2): pause the attack when any listed
	// expression appears in a response (or, with missing=true, when none does). Nil is
	// unconfigured. Simple strings are case-folded unless case_sensitive; regex entries
	// carry their own case flags, the way Go's regexp works.
	AutoPause *autoPauseReq `json:"auto_pause"`
	// RecursiveGrep is Burp's Recursive grep payload type (ztuu). Non-nil switches the engine to
	// the serial chain driver: send the initial payload, extract the next from each response.
	// The struct is the wire form of the per-position payload source {"type":"recursive_grep"}
	// — carried as its own request field rather than only inside payload_sources because the
	// chain has attack-level consequences (forced serial execution, unbounded-at-launch set)
	// that belong to the run, not to one position's generator.
	RecursiveGrep *intruder.RecursiveGrepSource `json:"recursive_grep"`
	// URLEncode is Burp's "URL-encode these characters" (burpsy-react-ui-8cbc): the
	// characters percent-encoded in every generated payload as the final pass, after the
	// rule chain. Empty (or absent) means no extra encoding — matching the off state, not
	// an empty set that would encode nothing anyway. Spaces and control characters are
	// always encoded additionally, because a request containing them cannot be delivered.
	URLEncode   *string `json:"url_encode_characters"`
	MaxPayloads *int    `json:"max_payloads"`
	GrepMatch   *string `json:"grep_match"`
	GrepExtract *string `json:"grep_extract"`
	// GrepMatchList is Burp's full Grep - Match form (irt): a LIST of expressions, one results
	// column per expression counting occurrences. The single-string grep_match above is kept
	// unchanged — the bundled UI and the wire contract both send it, and both shapes mean the
	// same thing when the list holds one item.
	GrepMatchList *[]string `json:"grep_match_list"`
	// GrepMatchSimple is Burp's Match type radio: simple strings (quoted, case-folded) vs
	// regexes compiled as-is. Nil and true mean simple, which is how the single grep_match has
	// always behaved (quoteRegex on the UI side, tpy).
	GrepMatchSimple *bool `json:"grep_match_simple"`
	// GrepMatchCaseSensitive turns off the case-folding a simple-string match applies.
	GrepMatchCaseSensitive *bool `json:"grep_match_case_sensitive"`
	// GrepMatchExcludeHeaders searches the response body only — Burp's "Exclude HTTP headers".
	GrepMatchExcludeHeaders *bool `json:"grep_match_exclude_headers"`
	// GrepPayloads is Burp's Grep - Payloads (burpsy-react-ui-7qc3): {enabled, case_sensitive,
	// exclude_headers, match_pre_url_encoded}, each false when omitted from the object. Nil — the field
	// absent — is the reflection check every attack ran before it existed (intruder.LegacyGrepPayloads:
	// on, case-sensitive, headers included, matched as sent), so a scripted attack's buckets do not
	// change unless the request says so. The bundled UI always sends the object.
	GrepPayloads *intruder.GrepPayloads `json:"grep_payloads,omitempty"`
	// CaptureFilter is Burp's results capture filter (burpsy-react-ui-ip2b): {discard_no_response, term,
	// regex, case_sensitive, negate, statuses}. Items it rejects are counted (sent/failed, buckets, the
	// report's discarded) but leave no results row and no stored request or response. Nil captures
	// everything, as every attack did before it existed. Distinct from the page's view filter, which only
	// hides rows that were captured.
	CaptureFilter *intruder.CaptureFilterSpec `json:"capture_filter,omitempty"`
	// StoreRequests and StoreResponses are Burp's "Store requests / responses" attack-results settings
	// (burpsy-react-ui-nqww): whether the exact requests (the attempt rows' and each bucket's) and each
	// bucket's exemplar response go into the traffic store. Nil is true — Burp's default and what every
	// attack did before the fields existed. Off, the ids go out null and the report's requests_stored /
	// responses_stored say why; the attack still sends, buckets, greps and feeds the session jar.
	StoreRequests  *bool `json:"store_requests,omitempty"`
	StoreResponses *bool `json:"store_responses,omitempty"`
	// Retries is Burp's "Number of retries on network failure" (n39). Nil means Burp's own
	// default of 3 — Zrur: requireNonNullElse(numretries, "3") — because the operator who
	// never thought about error handling is exactly the person Burp's default protects, and a
	// zero-default would make the flaky-target case the loud one. Explicit 0 disables.
	Retries *int `json:"retries"`
	// Baseline is Burp's "Make unmodified baseline request" (v34): issue the template with all
	// positions at their base values as item 0, so every attack response has a base response to
	// compare against. False unless asked.
	Baseline *bool `json:"baseline"`
	// RetryDelayMS is Burp's "Pause before retry" in milliseconds. Nil means Burp's 2000
	// (Zrur: "2000" beside pausebeforeretry); the accepted range is Burp's own validation
	// bound (Zb33): 0..600000.
	RetryDelayMS *int                   `json:"retry_delay_ms"`
	Pool         *string                `json:"pool"`
	AutoThrottle *intruder.AutoThrottle `json:"auto_throttle"`
	RPS          *float64               `json:"rps"`
	MaxInFlight  *int                   `json:"max_in_flight"`
	// DelayJitterPercent is Burp's resource-pool "With random variations" (nn0n), as a percentage
	// of the interval `rps` states: 25 makes every gap between requests land somewhere in ±25% of
	// it. Percent rather than the engine's fraction because that is the number on the screen and
	// the conversion belongs on one side of the wire, not in the browser. Omitted or 0 is the flat
	// spacing every attack has always had.
	DelayJitterPercent *float64 `json:"delay_jitter_percent"`
	// DelayIncrementMS is Burp's throttleIncrementMillis: each gap is this many milliseconds
	// longer than the one before it, so an attack that starts inside a rate-limit window stays
	// inside it as the window fills. Bounded at both ends — see intruderMaxDelayIncrementMS.
	DelayIncrementMS *int `json:"delay_increment_ms"`
	// DelaySeed seeds the jitter. Omitted is 0, which is a seed like any other: the schedule is
	// replayable either way, and an operator who wants a different shape of traffic per run sends
	// a different number. See intruder.DelayVariation.
	DelaySeed   *uint64 `json:"delay_seed"`
	MaxRequests *int    `json:"max_requests"`
	// TimeoutMS is the TOTAL per-attempt deadline: the whole send, a followed redirect chain included.
	// Nil is intruderDefaultTimeoutMS. Unchanged by response_timeout_ms below, which is a different
	// bound.
	TimeoutMS *uint64 `json:"timeout_ms"`
	// ResponseTimeoutMS is Burp's per-request response timeout (RequestOptions.withResponseTimeout,
	// burpsy-react-ui-mmca): how long each request in this attack waits for its response, replacing
	// the network settings' read timeout for this attack's sends only — the shared settings every
	// other tool reads are not touched. Nil is the standing read timeout. It is clamped by timeout_ms
	// when that is shorter, and refused when it is longer than a timeout_ms that was given, because
	// the operator typed two bounds and one of them could never apply.
	ResponseTimeoutMS *int64 `json:"response_timeout_ms,omitempty"`
	// FollowRedirects is Burp's Intruder "Follow redirections" (tools/intruder/configure-attack/
	// settings.html: Never / On-site only / In-scope only / Always). Nil or empty is the standing
	// network policy — the same fallback repeaterSendOptions.RedirectMode uses for Repeater's own
	// per-send override — so an attack that never mentions it behaves exactly as one always did
	// (RedirectNever by default). "process cookies in redirections" is deliberately not offered
	// here, for the same reason repeater_options.go's doc comment gives: hops are built by
	// sender.FollowRedirectsAfterPolicy, which does not replay cookies, and a checkbox for a
	// feature that does not exist would lie.
	FollowRedirects *string `json:"follow_redirects"`
	// SetConnectionClose and StorePayloads are Burp's other two attack settings
	// (burpsy-react-ui-fmxv): "Set Connection header" (add or update Connection: close) and
	// "Store full payloads" (retain the full payload values for each result). Both are the engine's
	// Attack.SetConnectionClose / Attack.StorePayloads, reached here for the first time — the engine
	// half landed in 29a7ee3 with no way to set either.
	//
	// Pointers so an absent field means "not asked for", which is what every attack sent before
	// this means. A plain bool cannot tell that from an explicit false, and the difference is
	// whether a client's saved attack resumes with the setting on or off.
	SetConnectionClose *bool `json:"set_connection_close,omitempty"`
	StorePayloads      *bool `json:"store_full_payloads,omitempty"`
	// HTTP1ConnectionReuse is Burp's "HTTP/1 connection reuse" (burpsy-react-ui-xhqr): requests ride
	// idle HTTP/1 connections to the target, at most max_in_flight of them, instead of dialling once
	// per request. Every request is still authorised on its own bytes (AuthorisedSender.SendReusing).
	// Nil or false is the old behaviour — one connection per request, closed after the response. The
	// bundled UI sends true, Burp's own default; an API client that never names it keeps what it had.
	// Refused together with set_connection_close: a request that says Connection: close is never
	// reused, so the pair would describe an attack that asked for reuse and could never get any.
	HTTP1ConnectionReuse *bool `json:"http1_connection_reuse,omitempty"`
	// HTTPVersion is Burp's per-attack "HTTP version" override (xhqr): "" (or absent) negotiates as
	// every send does, "http1" pins HTTP/1.1 so the bytes go out as written, "http2" requires h2
	// where the request can be carried over it. Pins that do not happen are reported as downgrades,
	// the same as Repeater's protocol_preference.
	HTTPVersion *string `json:"http_version,omitempty"`
	// UpdateHostHeader is Burp's "Update Host header to match target" (burpsy-react-ui-ety8): every
	// request's Host header is rewritten to the attack's target authority, after the payload splice,
	// so a captured request retargeted at another host does not go out naming the old one. Skipped —
	// and the report says why — when a selected position covers the Host header (the position being
	// fuzzed wins, Burp's rule for cookies too) or the base request does not carry exactly one Host
	// header. The bundled UI sends true, Burp's default; an absent field means false, which is what
	// every API client got before this existed. gaps.md records the split.
	UpdateHostHeader *bool `json:"update_host_header,omitempty"`
}

// intruderLimits resolves one attack's bounds: a saved pool by name, or the inline form.
//
// # Why a name cannot coexist with inline limits
//
// `pool` used to be a label and nothing else — intruder.RateLimit documents Name as "an identifier,
// not a handle: nothing here looks it up" — so a request could carry a pool name and its own rps and
// have both accepted, with only the name reaching the report. Now the name resolves to saved bounds,
// which makes that combination a contradiction: two answers to "how fast may this attack run", one
// of which would be dropped, and an AttackReport that names the pool in both cases. So it is
// refused, naming both halves.
//
// # Why an unknown name is refused rather than treated as a label
//
// The old behaviour would make a deleted or renamed pool run the attack at whatever inline default
// was in play, while the report said the pool's name — an attack running faster than the operator
// authorised, describing itself as bounded. pool.ErrNoSuchPool exists for exactly this, and the
// error names the pools that *are* saved so the fix is in the message.
func (s *Server) intruderLimits(req intruderRunReq) (intruder.RateLimit, error) {
	named := req.Pool != nil && strings.TrimSpace(*req.Pool) != ""
	if named {
		if req.RPS != nil || req.MaxInFlight != nil || req.AutoThrottle != nil ||
			req.DelayJitterPercent != nil || req.DelayIncrementMS != nil || req.DelaySeed != nil {
			return intruder.RateLimit{}, fmt.Errorf(
				"this attack names the pool %q and also sets its own limits; the pool already states "+
					"rps, max_in_flight, automatic throttling and how its delay varies, so send one or "+
					"the other",
				strings.TrimSpace(*req.Pool))
		}
		limit, err := s.pools.Limit(strings.TrimSpace(*req.Pool))
		if err != nil {
			return intruder.RateLimit{}, fmt.Errorf("%w (saved pools: %s)", err, availablePools(s.pools))
		}
		return limit, nil
	}

	// The inline form, unchanged. Bounded at BOTH ends: a rate below one request per two minutes is
	// not a rate anyone means, and there is deliberately no way to turn the rate cap off over HTTP.
	// (A saved pool can express "no rate cap, concurrency only" because it is an object an operator
	// deliberately configured; a per-call parameter that could do it would be one typo away.)
	rps := intruderDefaultRPS
	if req.RPS != nil {
		if *req.RPS < intruderMinRPS {
			return intruder.RateLimit{}, fmt.Errorf("rps must be at least %v, got %v", intruderMinRPS, *req.RPS)
		}
		rps = math.Min(*req.RPS, 1000.0)
	}
	maxInFlight := 10
	if req.MaxInFlight != nil {
		maxInFlight = *req.MaxInFlight
	}
	maxInFlight = clampInt(maxInFlight, 1, intruderMaxInFlightCeiling)
	limits := intruder.NewRateLimit(&rps, 1, maxInFlight)
	// An empty-string pool is still allowed to label the attack, which is what it always did: the
	// name is carried into the report and looked up only when it is not empty.
	if req.Pool != nil {
		limits = limits.Named(*req.Pool)
	}
	if at := req.AutoThrottle; at != nil {
		if len(at.Statuses) > intruderMaxThrottleStatuses {
			return intruder.RateLimit{}, fmt.Errorf("auto_throttle lists %d statuses, more than the %d allowed",
				len(at.Statuses), intruderMaxThrottleStatuses)
		}
		limits = limits.WithAutoThrottle(at)
	}
	// Burp's resource-pool variations (nn0n). Sent only when the operator asked for one, so an
	// attack that never mentions them takes the flat spacing through a code path the engine
	// short-circuits before any schedule exists. The engine refuses the combinations it cannot
	// honour — a jitter that would schedule a zero gap, an increment that shortens one — and the
	// refusal is handed straight back rather than clamped, so the operator learns which of their
	// two numbers was the impossible one.
	if req.DelayJitterPercent != nil || req.DelayIncrementMS != nil || req.DelaySeed != nil {
		variation := intruder.DelayVariation{}
		if p := req.DelayJitterPercent; p != nil {
			if *p < 0 || *p >= 100 {
				return intruder.RateLimit{}, fmt.Errorf(
					"delay_jitter_percent must be at least 0 and below 100 (at 100%% a downward "+
						"variation is a zero gap, and beyond it a negative one), got %v", *p)
			}
			variation.Jitter = *p / 100
		}
		if inc := req.DelayIncrementMS; inc != nil {
			if *inc < 0 || *inc > intruderMaxDelayIncrementMS {
				return intruder.RateLimit{}, fmt.Errorf(
					"delay_increment_ms must be between 0 and %d, got %d", intruderMaxDelayIncrementMS, *inc)
			}
			variation.IncrementMS = *inc
		}
		if seed := req.DelaySeed; seed != nil {
			variation.Seed = *seed
		}
		varied, err := limits.WithVariation(&variation)
		if err != nil {
			return intruder.RateLimit{}, err
		}
		limits = varied
	}
	return limits, nil
}

// intruderLimitStatus maps a limit failure to its status: a named pool that is not saved is 404,
// because the request is well formed and the world is not what the caller thought.
func intruderLimitStatus(err error) int {
	if errors.Is(err, pool.ErrNoSuchPool) {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// intruderRedirectPolicy resolves one attack's "Follow redirections" setting to the sender's
// redirect policy: the request's override when it named one, otherwise the network settings'
// standing policy — repeaterSendOptions.redirectPolicy's rule, reused rather than reinvented so
// the two tools cannot drift on what "the standing policy" means. The hop budget always comes
// from the standing settings: MaxHops is an anti-loop bound, not a policy choice an attack gets
// to relax, because the same chain-following code a single Repeater send uses now runs once per
// attempt, and a bigger budget here is a bigger budget for every one of a 200,000-request attack.
func intruderRedirectPolicy(mode *string, standing sender.RedirectSettings) (sender.RedirectSettings, error) {
	if mode == nil || *mode == "" {
		return standing, nil
	}
	switch sender.RedirectMode(*mode) {
	case sender.RedirectNever, sender.RedirectOnSite, sender.RedirectInScope, sender.RedirectAlways:
		return sender.RedirectSettings{Mode: sender.RedirectMode(*mode), MaxHops: standing.MaxHops}, nil
	default:
		return sender.RedirectSettings{}, fmt.Errorf(
			"follow_redirects: unknown mode %q (want never, on_site, in_scope, always, or empty for the standing policy)", *mode)
	}
}

// AttemptView is the legacy one-position form's row.
type AttemptView struct {
	Payload     string  `json:"payload"`
	Status      *int    `json:"status"`
	Len         int     `json:"len"`
	DurationMS  uint64  `json:"duration_ms"`
	Error       *string `json:"error"`
	GrepMatched *bool   `json:"grep_matched"`
	GrepExtract *string `json:"grep_extract"`
	// GrepMatchCounts is the expression list's per-item occurrence count (irt). Empty when no
	// list was configured.
	GrepMatchCounts []int `json:"grep_match_counts"`
}

// BucketExample resolves one ordinal — a bucket's first ordinal, or any other attempt ordinal the
// report kept — back to the exact payload combination the engine actually sent, so the operator
// never has to reconstruct it by hand. FirstOrdinal is the field name for historical reasons (the
// bucket table was the first consumer); despite the name, RunView.Examples carries one entry per
// distinct ordinal across both the bucket table and the attempts table.
type BucketExample struct {
	FirstOrdinal int      `json:"first_ordinal"`
	Payloads     []string `json:"payloads"`
}

// RunView is the full report shape: the bucketed summary, payloads behind every bucket and every
// kept attempt (keyed by ordinal in Examples — see BucketExample), and the honest per-set
// counting (what was capped, truncated, skipped or dropped).
type RunView struct {
	Report      intruder.AttackReport `json:"report"`
	Examples    []BucketExample       `json:"examples"`
	PayloadSets []intruder.PayloadSet `json:"payload_sets"`
	// SessionCookies says what the session cookie jar contributed to this attack. Always present, so
	// "the jar was empty" and "the jar was never consulted" are not the same JSON — the reading that
	// makes a whole unauthenticated attack look like a finding about the endpoint.
	SessionCookies intruderSessionCookies `json:"session_cookies"`
	// RedirectsFollowed is how many additional requests this attack sent chasing a 3xx, summed
	// across every attempt (tirx). Zero whenever follow_redirects names RedirectNever (the default)
	// or every hop was refused by policy or scope — the same "prove the setting did something"
	// discipline AutoThrottleEngaged already holds the rate limiter to.
	RedirectsFollowed int `json:"redirects_followed"`
	// ConnectionsOpened and ConnectionsReused are what HTTP/1 connection reuse did (xhqr): sockets
	// this attack dialled, and requests that completed on a socket an earlier request had used. Both
	// null when reuse was off — every request then had a connection of its own and nothing was
	// counted — so "reuse was off" and "reuse was on and never happened" are different JSON. Redirect
	// hops always dial their own connection and are in neither count.
	ConnectionsOpened *int64 `json:"connections_opened"`
	ConnectionsReused *int64 `json:"connections_reused"`
	// HostHeaderUpdated says "Update Host header to match target" (ety8) was applied: every request's
	// Host header was rewritten to the target authority, except the HostHeaderUntouched ones.
	// HostHeaderSkipped is why it was not applied at all when it was asked for — a position covers
	// the Host header, or the base request does not carry exactly one — and empty otherwise.
	// HostHeaderUntouched counts requests a payload left with other than one Host header, which were
	// sent as spliced rather than rewritten: a payload that adds a Host header is a probe, and
	// choosing which of two to rewrite would change what it tests.
	HostHeaderUpdated   bool   `json:"host_header_updated"`
	HostHeaderSkipped   string `json:"host_header_skipped"`
	HostHeaderUntouched int    `json:"host_header_untouched"`
}

// intruderSessionCookies reports the jar's contribution to one attack, by cookie name.
//
// Names only. Values are session tokens by construction, and an attack report is a document that gets
// pasted into tickets — the same reason Coordinator.logExtraction never logs a resolved value.
type intruderSessionCookies struct {
	// Attached are the jar cookie names merged into every request, sorted.
	Attached []string `json:"attached"`
	// Exempt are cookie names the attack is fuzzing, which the jar deliberately did not overwrite.
	// Burp's rule; see internal/web/intruder_cookies.go.
	Exempt []string `json:"exempt"`
	// JarEmpty distinguishes "the jar holds nothing for this authority" from "nothing was attached
	// because every jar cookie was a fuzzed position". Both give an empty Attached list and mean
	// different things about whether the attack was authenticated.
	JarEmpty bool `json:"jar_empty"`
}

// intruderSessionCookieView builds the report from the same two inputs the send path used, so the
// report cannot claim a cookie the wire did not carry.
func intruderSessionCookieView(jarHeader string, exempt map[string]bool) intruderSessionCookies {
	out := intruderSessionCookies{
		Attached: []string{},
		Exempt:   []string{},
		JarEmpty: jarHeader == "",
	}
	for name := range exempt {
		out.Exempt = append(out.Exempt, name)
	}
	for _, p := range parseCookieHeader(jarHeader) {
		if p.name == "" || exempt[strings.ToLower(p.name)] {
			continue
		}
		out.Attached = append(out.Attached, p.name)
	}
	sort.Strings(out.Attached)
	sort.Strings(out.Exempt)
	return out
}

// handleIntruderRun runs an attack: sniper, battering ram, pitchfork or cluster bomb.
//
// A request that names no mode, no payload_sets and no payload_sources is the single-position
// sniper form the bundled UI posts, and gets back the flat array of per-attempt rows that UI
// renders. Anything else gets the full RunView. Both shapes come off the same engine, so the
// legacy array is a projection of the report.
func (s *Server) handleIntruderRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req intruderRunReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	msg, err := s.store.Get(core.MsgId(req.MsgID))
	if err != nil {
		http.Error(w, "no such message", http.StatusNotFound)
		return
	}
	host, port, tls, err := targetParts(req.Target)
	if err != nil {
		http.Error(w, "bad target: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Two layers, because one cannot do this job. Here we only know the host: the paths this
	// attack will actually request do not exist yet, and a payload spliced into a path position
	// invents them. So this refuses a host that is wholly out of scope, and every spliced request
	// is judged again on its own bytes by the authorising sender below.
	if !s.scope.MayContainHost(host, port, tls) {
		http.Error(w, "refused: "+s.scope.Explain(host, port, "/", tls), http.StatusForbidden)
		return
	}
	// Naming a generator or a mode is as clear a statement that the operator wants the full
	// report as anything else, so both select the report shape.
	legacy := req.Mode == nil && req.PayloadSets == nil && req.PayloadSources == nil
	kind := intruder.AttackKindSniper
	if req.Mode != nil {
		k, ok := intruder.ParseAttackKind(*req.Mode)
		if !ok {
			http.Error(w, fmt.Sprintf("unknown mode %q: expected sniper, battering_ram, pitchfork or cluster_bomb", *req.Mode), http.StatusBadRequest)
			return
		}
		kind = k
	}

	cfg, err := intruderPointConfig(req.All, req.PayloadPlacement)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	discovered := intruder.FindPoints(msg, cfg)
	wanted, err := selectPoints(req.Points, req.PointIndex, len(discovered))
	if err != nil && req.ManualPoints == nil {
		// A refusal is only final when no manual markers back it up: a manual-only attack selects no
		// discovered point, and that is the whole point of marking one by hand.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Manual markers are byte ranges the operator marked by hand (Burp's Add §). They join the
	// attack alongside the selected discovered points — never filtered through selectPoints,
	// which indexes the discovered list — and they count toward the same position bounds.
	manual, err := intruder.ManualPoints(msg.Raw(), derefManual(req.ManualPoints))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	selected := make([]intruder.InsertionPoint, 0, len(wanted)+len(manual))
	for _, i := range wanted {
		selected = append(selected, discovered[i])
	}
	// Manual-vs-discovered overlap is refused here, naming the marking, rather than left to the
	// splice's earliest-span-wins rule, which would silently drop one of the two payloads. The splice's
	// own predicate, so a zero-length appended position touching a manual marker's edge is refused
	// here rather than dropped there (1krs).
	for _, m := range manual {
		for _, d := range selected {
			if intruder.SpansOverlap(m.Span, d.Span) {
				http.Error(w, fmt.Sprintf("manual point %q overlaps discovered point %q", m.Label, d.Label), http.StatusBadRequest)
				return
			}
		}
	}
	selected = append(selected, manual...)
	// Burp's rule, and a sound one: one position makes the multi-set modes meaningless, and twenty
	// is where a cluster bomb stops being an attack and becomes an outage. Manual markers count
	// toward it: an operator who marks three byte ranges has three payload positions, whatever
	// the discoverer found.
	if (kind == intruder.AttackKindPitchfork || kind == intruder.AttackKindClusterBomb) &&
		(len(selected) < 2 || len(selected) > 20) {
		http.Error(w, fmt.Sprintf("%s requires between 2 and 20 payload positions, got %d", kind, len(selected)), http.StatusBadRequest)
		return
	}
	// The send settings, resolved before any payload is generated: a refused setting must not leave
	// minted Collaborator addresses behind in the hub, and must not be discovered on the first send.
	// See intruder_send.go.
	sendPlan, err := s.buildIntruderSendPlan(req, msg.Raw(), selected, host, port, tls)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer sendPlan.close()

	// A literal list is a PayloadSource variant, so the three request shapes collapse to one type
	// here and everything downstream — count checks, resolution, processing — happens once.
	sources, err := intruderSources(req.PayloadSources, req.PayloadSets, req.Payloads, kind, len(selected))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Compiled once, before any payload is generated: an unparseable pattern is one error here
	// rather than N identical drops inside the attack.
	rules := req.PayloadRules
	if rules == nil {
		rules = &[]intruder.RuleSpec{}
	}
	chain, err := intruder.NewChain(*rules)
	if err != nil {
		http.Error(w, "payload rule: "+err.Error(), http.StatusBadRequest)
		return
	}
	payloadCap := intruderDefaultMaxPayloads
	if req.MaxPayloads != nil {
		payloadCap = *req.MaxPayloads
	}
	payloadCap = clampInt(payloadCap, 1, intruder.MaxPayloads)
	// Generate, then process, then done — all of it before the plan is built, so plan.Len() is
	// the number of requests and a payload a rule dropped never occupies an ordinal.
	resolved := make([]intruder.PayloadSet, 0, len(sources))
	// copyFrom records, per position, the earlier position it mirrors. Handed to the plan below so
	// the copied position is filled from its source's ordinal rather than its own
	// (burpsy-react-ui-kwe0).
	copyFrom := make(map[int]int)
	for i, src := range sources {
		// copy_other (2g13) is resolved here, against the sources already in `resolved`, rather
		// than inside PayloadSource.Resolve: it has no generator of its own, and what it copies
		// is the *processed* items of another position — the same bytes that position's own
		// splice uses, after its own rule chain and URL-encoding already ran. Copying earlier in
		// the pipeline (or re-running the chain/encoding on the copy) would let the two positions
		// diverge, defeating the one thing this payload type exists to guarantee.
		//
		// Pitchfork only. It works there because pitchfork's Fill (plan.go) advances every
		// position's set at the *same* index i — two positions given identical Items therefore
		// receive identical payloads on every request. Cluster bomb's mixed-radix Fill advances
		// each position's set at a rate that depends on its own position in the radix system, so
		// two identical Items lists would coincide on some ordinals and diverge on most of the
		// rest — a copy that is right most of the time is a correctness bug with a very good
		// disguise, and refusing it is more honest than shipping that. Making it exact for cluster
		// bomb needs the engine to read another position's *resolved slot* at splice time
		// (engine.go's per-ordinal loop), not a static payload list — a larger change than this
		// bead's evidence asks for, and it is refused by name here rather than silently.
		// The Collaborator payload type (hi8): mint Count fresh addresses at launch and hand
		// Resolve an ordinary list, so the engine sees exactly the payloads that will reach the
		// wire. The mint is the Collaborator page's own primitive (collaboratorMarker + the
		// channel's domain), so an attack's payloads land in the hub the Collaborator page
		// polls — the operator sees the interaction attributed to the address the attack used.
		// Refusal before any request goes out when no channel is configured: Burp's own
		// behaviour (Zcc_ ends the payload set on a missing channel) would silently shorten the
		// attack instead, and a shortened OOB sweep reads as a clean one.
		if src.Type == "collaborator" {
			cfg := src.Collaborator
			if cfg == nil {
				http.Error(w, fmt.Sprintf("payload set %d (collaborator): missing configuration", i), http.StatusBadRequest)
				return
			}
			count := cfg.Count
			if count < 1 {
				count = 1 // Burp's panel treats a non-number as 0 and stops; one payload is what a click means
			}
			if count > maxCollaboratorBatch {
				http.Error(w, fmt.Sprintf("payload set %d (collaborator): count %d exceeds the batch bound of %d; a batch that large is a script's job, not a click's",
					i, count, maxCollaboratorBatch), http.StatusBadRequest)
				return
			}
			channel, err := s.scanner.OOBChannel(r.Context())
			if err != nil {
				http.Error(w, fmt.Sprintf("payload set %d (collaborator): no out-of-band interaction channel is configured, so no payload can be minted — an address for a channel nothing polls would report every OOB check as clean when none of them ran: %v",
					i, err), http.StatusConflict)
				return
			}
			// Nil = Burp's checked default (see CollaboratorSource.IncludeLocation).
			includeLocation := cfg.IncludeLocation == nil || *cfg.IncludeLocation
			items := make([]string, 0, count)
			for j := 0; j < count; j++ {
				marker, err := collaboratorMarker()
				if err != nil {
					http.Error(w, fmt.Sprintf("payload set %d (collaborator): minting failed: %v", i, err), http.StatusInternalServerError)
					return
				}
				addr := marker
				if includeLocation {
					addr = marker + "." + channel.Domain()
				}
				items = append(items, addr)
			}
			// Record the mint in the hub the Collaborator page reads, so the payloads an attack
			// used are visible and attributable there — the same accounting the page's own
			// mint button gets.
			hub := s.collab()
			now := time.Now()
			hubRows := make([]mintedPayload, 0, len(items))
			for _, addr := range items {
				marker := strings.TrimSuffix(addr, "."+channel.Domain())
				hubRows = append(hubRows, mintedPayload{Address: addr, Marker: marker, MintedAt: now})
			}
			hub.mu.Lock()
			hub.minted = append(hub.minted, hubRows...)
			hub.mu.Unlock()

			resolved = append(resolved, intruder.PayloadSet{
				Kind:       "collaborator",
				Items:      items,
				Count:      len(items),
				Total:      uint64(len(items)),
				TotalExact: true,
				MaxCount:   payloadCap,
				Skipped:    0,
				Dropped:    []intruder.DropReason{},
			})
			continue
		}
		if src.Type == "copy_other" {
			// Cluster bomb is supported now, and the reason it was not is worth keeping: its mixed-radix
			// Fill advances each position's set at a rate that depends on that position's place in the
			// radix system, so aliasing the source's PAYLOADS and stepping the copy by its own ordinal
			// made the two coincide on some requests and diverge on the rest — a copy that is right most
			// of the time, which is the worst possible disguise for a correctness bug. The plan now
			// decodes the SOURCE's digit for the copied position (plan.go's Fill), which is exact by
			// construction, and that is what this payload type exists to guarantee
			// (burpsy-react-ui-kwe0).
			//
			// Sniper and battering ram stay refused, and for a different reason than cluster bomb did:
			// they advance ONE set across every position, so "another position's payload" has no
			// per-position meaning to copy from.
			if kind == intruder.AttackKindSniper || kind == intruder.AttackKindBatteringRam {
				http.Error(w, fmt.Sprintf(
					"payload set %d (copy_other): %s advances one payload set across every position, so there is no per-position payload to copy; use pitchfork or cluster bomb",
					i, kind), http.StatusBadRequest)
				return
			}
			target := -1
			if src.CopyOther != nil {
				target = src.CopyOther.Position
			}
			if target < 0 || target >= i {
				http.Error(w, fmt.Sprintf(
					"payload set %d (copy_other): position %d must name an earlier position in this attack (0..%d)",
					i, target, i-1), http.StatusBadRequest)
				return
			}
			copied := resolved[target]
			copied.Kind = "copy_other"
			// Recorded for the plan, which fills the copied position from its SOURCE's ordinal. The
			// aliasing below is still what the request bytes are read from; the mapping is what makes
			// the two positions receive the SAME payload on every request under a radix that advances
			// each position at its own rate.
			copyFrom[i] = target
			resolved = append(resolved, copied)
			continue
		}
		ps, err := src.Resolve(payloadCap)
		if err != nil {
			http.Error(w, fmt.Sprintf("payload set %d (%s): %s", i, src.AsStr(), err), http.StatusBadRequest)
			return
		}
		ps.Kind = src.AsStr()
		chain.Run(ps)
		// The safety net, after the operator's chain (burpsy-react-ui-8cbc): Burp runs this
		// final pass regardless of payload type, so an explicit encode rule and this compose
		// rather than compete.
		if req.URLEncode != nil {
			intruder.URLEncodeSet(ps, *req.URLEncode)
		}
		resolved = append(resolved, *ps)
	}

	grep, err := buildGrep(req.GrepMatch, req.GrepExtract, req.GrepMatchList,
		req.GrepMatchSimple, req.GrepMatchCaseSensitive, req.GrepMatchExcludeHeaders)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Compiled before any request is sent, like the grep patterns: a filter whose term does not compile
	// would otherwise capture everything or nothing, and either is a filter the operator did not set.
	var capture *intruder.CaptureFilter
	if req.CaptureFilter != nil {
		if capture, err = intruder.NewCaptureFilter(*req.CaptureFilter); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	// A named pool and inline limits are two ways of saying the same thing, and an attack may use
	// either — a pool is a resolution step in front of the inline form, not a replacement for it. What
	// it may not do is say both: the operator would have typed two different sets of bounds and had
	// one of them silently ignored, with the report naming the pool either way.
	limits, lerr := s.intruderLimits(req)
	if lerr != nil {
		http.Error(w, lerr.Error(), intruderLimitStatus(lerr))
		return
	}
	bound := intruderDefaultBound
	if legacy {
		bound = intruderLegacyBound
	} else if req.MaxRequests != nil {
		bound = clampInt(*req.MaxRequests, 1, intruderMaxBound)
	}

	setLens := make([]int, 0, len(resolved))
	for _, set := range resolved {
		setLens = append(setLens, len(set.Items))
	}
	plan := intruder.NewAttackPlan(kind, len(selected), setLens, bound).WithCopies(copyFrom)

	ctx := r.Context()
	send := sendPlan.sendFn(ctx)
	// The response recorder remains the engine's one-per-bucket exemplar rule. The exact-request
	// recorder is attached to the attack after construction below, for the bounded attempt rows.
	record := func(raw []byte) uint64 {
		id, _ := s.store.Put(raw, core.DirectionResponse)
		return uint64(id)
	}
	// The jar's monitored-tool set (burpsy-react-ui-sn3j): the response opening each result bucket
	// offers the jar its Set-Cookie lines — one per distinct behaviour the attack saw, not one per
	// request, the restraint the engine's memory contract already holds. It is the engine's Observe
	// hook rather than part of record, because a response the capture filter discards (ip2b) or an
	// attack that does not store responses (nqww) must not silently stop the jar learning.
	observe := func(raw []byte) {
		if s.sessionCoordinator != nil {
			s.sessionCoordinator.AbsorbResponseCookies(session.SourceIntruder, host, port, tls, raw)
		}
	}

	control := intruder.NewControl()
	attack := intruder.NewAttack(msg.Raw(), selected, resolved, plan).
		WithLimits(limits).
		WithGrep(grep).
		WithControl(control).
		// Burp's other two attack settings (fmxv), attached only when the request names them, so
		// an attack sent before this field set is byte-for-byte what it always was. A nil here is
		// "off" at the engine, which is the same thing — the fields exist so the UI can ask.
		WithSetConnectionClose(req.SetConnectionClose != nil && *req.SetConnectionClose).
		WithStorePayloads(req.StorePayloads != nil && *req.StorePayloads)
	if req.GrepPayloads != nil {
		attack.WithGrepPayloads(*req.GrepPayloads)
	}
	attack.WithCapture(capture)
	attack.Observe = observe
	// Recursive grep (ztuu): the chain driver. Attached only when the request names it, so an
	// ordinary attack's Run path is byte-for-byte what it always was. Two wire shapes carry the
	// config: the explicit request field, and a per-position payload_sources entry (Burp's own
	// shape — the payload type is chosen per position). The source form wins when both name one,
	// because the source is what the operator saw in the payload-type menu.
	var recursiveSource *intruder.RecursiveGrepSource
	for _, src := range sources {
		if src.RecursiveGrep != nil {
			recursiveSource = src.RecursiveGrep
			break
		}
	}
	if recursiveSource != nil && req.RecursiveGrep != nil {
		http.Error(w, "recursive_grep appears both as a payload source and as the request's recursive_grep field; send one — the two forms would compete for which chain runs",
			http.StatusBadRequest)
		return
	}
	if recursiveSource != nil {
		req.RecursiveGrep = recursiveSource
	}
	if req.RecursiveGrep != nil {
		re, err := regexp.Compile(req.RecursiveGrep.ExtractRe)
		if err != nil {
			http.Error(w, fmt.Sprintf("recursive_grep: extract pattern does not compile: %v", err), http.StatusBadRequest)
			return
		}
		attack.WithRecursive(&intruder.RecursiveGrep{Re: re, StopDuplicate: req.RecursiveGrep.StopDuplicate})
		// Burp forces the resource pool to max concurrent 1 for these attacks (Zsvp.Zx: the pool
		// builder answers 1 whenever the attack uses a recursive-grep source), rather than
		// refusing the operator's pool. Same here: the serial driver ignores concurrency by
		// construction, so clamping is the honest action — the report then names the pool that
		// ran at 1, and an operator who wonders why a fast pool ran serially can read this
		// comment in the code rather than a refusal in the UI. Refusing instead would make
		// the payload type unusable from the bundled UI, whose default max_in_flight is 10.
		limits.MaxInFlight = 1
		limits.Burst = 1
	}
	// Error handling (n39): Burp's defaults — 3 retries, 2000ms pause — applied when the
	// request does not name its own, because "intermittent network failures are common when
	// testing" (Burp's own settings prose) and the operator who omitted the field is the
	// person those defaults exist for. The pause bound is Burp's own: 0..600000ms (Zb33:
	// "Pause before retry must be between 0 and 600000").
	retries := 3
	if req.Retries != nil {
		retries = *req.Retries
	}
	if retries < 0 {
		http.Error(w, fmt.Sprintf("retries must be 0 (disable) or more, got %d", retries), http.StatusBadRequest)
		return
	}
	retryDelay := 2000 * time.Millisecond
	if req.RetryDelayMS != nil {
		if *req.RetryDelayMS < 0 || *req.RetryDelayMS > 600_000 {
			http.Error(w, fmt.Sprintf("retry_delay_ms must be between 0 and 600000, got %d", *req.RetryDelayMS), http.StatusBadRequest)
			return
		}
		retryDelay = time.Duration(*req.RetryDelayMS) * time.Millisecond
	}
	attack.WithRetries(retries, retryDelay)
	if req.Baseline != nil {
		attack.WithBaseline(*req.Baseline)
	}
	// Auto-pause (burpsy-react-ui-8f2): compiled once, refused here if an expression does
	// not compile — an auto-pause that silently never fires is a control that lies by
	// omission, the same rule the grep patterns follow.
	if req.AutoPause != nil && len(req.AutoPause.Expressions) > 0 {
		ap, err := intruder.NewAutoPause(req.AutoPause.Expressions, req.AutoPause.Simple,
			req.AutoPause.Missing, req.AutoPause.CaseSensitive)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		attack.WithAutoPause(ap)
	}
	// The dashboard's Pause all tasks reaches the attack driver, alongside the attack's own
	// pause/resume controls (burpsy-react-ui-cijs). Two gates because they answer different
	// questions, and an operator who pressed "pause everything" should not have to find this
	// attack's own button as well.
	attack.SuiteGate = s.tasks.GateCheck
	// "Store requests" / "Store responses" (nqww), Burp's defaults on.
	attack.RecordRequest = req.StoreRequests == nil || *req.StoreRequests
	attack.StoreResponses = req.StoreResponses == nil || *req.StoreResponses
	attack.RequestFn = func(raw []byte) uint64 {
		id, err := s.store.Put(raw, core.DirectionRequest)
		if err != nil {
			return 0
		}
		return uint64(id)
	}
	// On the dashboard for the duration of the attack (DASH-01). The total is the plan's length —
	// what will actually be sent — not the combination count, which is what the plan's bound already
	// refused; the refusal shows up as the gated bucket on the result instead.
	task := s.tasks.Start(dash.KindIntruder, fmt.Sprintf("%s %s:%d", kind, host, port), uint64(plan.Len()))

	// Cancellable, at last. dash.Handle.WithCancel's own doc has named "intruder attack stop" as one
	// of its three consumers since it was written, and this handler never called it — so
	// Task.Cancellable() was false for every attack and the dashboard rendered no stop button for the
	// one kind of task that can send 200,000 requests.
	//
	// Derived from r.Context() rather than context.Background(), unlike the sequencer capture: the
	// attack runs inside this handler, so a client that disconnects mid-attack means an attack whose
	// report nobody will read, and stopping it is right. The sequencer's capture outlives its request
	// and needs the opposite.
	taskCtx, cancelTask := task.WithCancel(ctx)
	defer cancelTask()
	attackDone := make(chan struct{})
	defer close(attackDone)
	control.StopOnContext(taskCtx, attackDone, "stopped from the dashboard")

	// Registered for the duration, so /api/intruder/attacks/{id}/{pause|resume|stop} can reach it
	// while this request is still holding the attack's response open.
	s.attacks.add(&runningAttack{
		taskID: task.ID(), kind: kind.String(), planned: plan.Len(),
		target: fmt.Sprintf("%s:%d", host, port), control: control,
	})
	defer s.attacks.remove(task.ID())

	// HTTP/1 connection reuse (xhqr) is bounded by the attack's own concurrency, read off the attack
	// after every adjustment above, so the pool can never hold more sockets than the attack can use.
	sendPlan.startPool(attack.Limits.MaxInFlight)
	report := intruder.Run(attack, send, record)
	task.Advance(uint64(report.Sent + report.Failed))
	// Stop, not Finish, for an attack that was halted. A stopped run reported as done is a report over
	// an unknown prefix of the payload set presented as a complete answer — dash.Task.Complete()
	// exists to refuse exactly that, and it can only do so if the state it is given is honest.
	if report.Status == intruder.StatusStopped {
		task.Stop(report.Breakdown(), report.StopReason)
	} else {
		task.Finish(report.Breakdown())
	}

	if legacy {
		rows := make([]AttemptView, 0, len(report.Attempts))
		for _, a := range report.Attempts {
			payload := ""
			if len(report.ChainPayloads) > 0 {
				// The recursive chain (ztuu): plan arithmetic cannot name a response-derived
				// payload, so the driver recorded it — read the record instead of the plan.
				if a.Ordinal < len(report.ChainPayloads) {
					payload = report.ChainPayloads[a.Ordinal]
				}
			} else if pl := payloadsAt(plan, resolved, payloadOrdinal(report, a.Ordinal)); len(pl) > 0 {
				payload = pl[0]
			}
			rows = append(rows, AttemptView{
				Payload:         payload,
				Status:          a.Status,
				Len:             a.ResponseLen,
				DurationMS:      uint64(a.DurationMS),
				Error:           a.Error,
				GrepMatched:     a.GrepMatched,
				GrepExtract:     a.GrepExtract,
				GrepMatchCounts: a.GrepMatchCounts,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rows)
		return
	}

	// Every bucket's first ordinal, plus every attempt ordinal the report actually kept — not just
	// buckets. The bundled UI can reconstruct an ordinal's payloads itself (pure arithmetic on the
	// plan), but only from what the *browser* typed; a payload-processing rule runs server-side at
	// resolve time (see internal/intruder/process.go), so a count-preserving rule like add_prefix
	// changes every byte the client cannot see. Only the resolved set — what this handler already
	// has in `resolved`, post-chain — names what was actually sent. Bounded by report.DetailLimit
	// (internal/intruder/engine.go), so this does not unbound the response (burpsy-react-ui-fvx).
	seenOrdinal := make(map[int]bool, len(report.Buckets)+len(report.Attempts))
	examples := make([]BucketExample, 0, len(report.Buckets)+len(report.Attempts))
	// For the recursive chain (ztuu), the plan cannot name the payloads — the driver recorded
	// them per ordinal (report.ChainPayloads), and every example reads that record instead.
	examplePayloads := func(ordinal int) []string {
		if report.Baseline && ordinal == 0 {
			// Item 0 is the baseline request (v34): no payloads at all. Falling through to plan
			// arithmetic would label the baseline row with the FIRST attack payload — exactly
			// the mislabel the ordinal shift exists to prevent.
			return []string{}
		}
		if len(report.ChainPayloads) > 0 {
			if ordinal < len(report.ChainPayloads) {
				return []string{report.ChainPayloads[ordinal]}
			}
			return []string{}
		}
		return payloadsAt(plan, resolved, payloadOrdinal(report, ordinal))
	}
	for _, b := range report.Buckets {
		examples = append(examples, BucketExample{
			FirstOrdinal: b.FirstOrdinal,
			Payloads:     examplePayloads(b.FirstOrdinal),
		})
		seenOrdinal[b.FirstOrdinal] = true
		// A bucket whose opening response the capture filter discarded keeps its exemplar from a later
		// ordinal (ip2b); that ordinal's payloads are what its stored exchange carries.
		if eo := b.ExampleOrdinal; eo != nil && !seenOrdinal[*eo] {
			seenOrdinal[*eo] = true
			if pl := examplePayloads(*eo); len(pl) > 0 {
				examples = append(examples, BucketExample{FirstOrdinal: *eo, Payloads: pl})
			}
		}
	}
	for _, a := range report.Attempts {
		if seenOrdinal[a.Ordinal] {
			continue
		}
		seenOrdinal[a.Ordinal] = true
		if pl := examplePayloads(a.Ordinal); len(pl) > 0 {
			examples = append(examples, BucketExample{FirstOrdinal: a.Ordinal, Payloads: pl})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RunView{
		Report:              *report,
		Examples:            examples,
		PayloadSets:         resolved,
		SessionCookies:      intruderSessionCookieView(sendPlan.jarHeader, sendPlan.exemptCookies),
		RedirectsFollowed:   int(sendPlan.redirectsFollowed.Load()),
		ConnectionsOpened:   sendPlan.connectionsOpened(),
		ConnectionsReused:   sendPlan.connectionsReused(),
		HostHeaderUpdated:   sendPlan.hostValue != "",
		HostHeaderSkipped:   sendPlan.hostSkipped,
		HostHeaderUntouched: int(sendPlan.hostUntouched.Load()),
	})
}

// selectPoints resolves the `points` / `point_index` forms to a validated index list, refusing a
// duplicate or an out-of-range position — a duplicate would overlap and the splice would silently
// drop one of the payloads.
func selectPoints(points *[]int, pointIndex *int, found int) ([]int, error) {
	switch {
	case points != nil:
		seen := make(map[int]bool, len(*points))
		for _, i := range *points {
			if i < 0 || i >= found {
				return nil, fmt.Errorf("point %d out of range: %d points found", i, found)
			}
			if seen[i] {
				return nil, fmt.Errorf("insertion point %d selected twice", i)
			}
			seen[i] = true
		}
		return *points, nil
	case pointIndex != nil:
		if *pointIndex < 0 || *pointIndex >= found {
			return nil, fmt.Errorf("point %d out of range: %d points found", *pointIndex, found)
		}
		return []int{*pointIndex}, nil
	default:
		return nil, errors.New("no insertion point selected: pass point_index or points")
	}
}

// derefManual normalises the optional manual-points field: an absent field marks nothing.
func derefManual(spans *[]intruder.ManualSpan) []intruder.ManualSpan {
	if spans == nil {
		return nil
	}
	return *spans
}

// intruderSources collapses the three payload request shapes into one PayloadSource list and
// enforces the per-mode set count.
func intruderSources(sources *[]intruder.PayloadSource, sets *[][]string, payloads *[]string, kind intruder.AttackKind, positions int) ([]intruder.PayloadSource, error) {
	var out []intruder.PayloadSource
	switch {
	case sources != nil:
		out = *sources
	case sets != nil:
		for _, items := range *sets {
			out = append(out, intruder.PayloadSource{Type: "list", List: &intruder.ListSource{Items: items}})
		}
	case payloads != nil:
		out = []intruder.PayloadSource{{Type: "list", List: &intruder.ListSource{Items: *payloads}}}
	default:
		return nil, errors.New("no payloads: pass payloads, payload_sets or payload_sources")
	}
	need := 1
	if kind == intruder.AttackKindPitchfork || kind == intruder.AttackKindClusterBomb {
		need = positions
	}
	if len(out) != need {
		return nil, fmt.Errorf("%s needs exactly %d payload set(s), got %d", kind, need, len(out))
	}
	return out, nil
}

// buildGrep compiles the operator's grep patterns, if any. Go's regexp is RE2, which bounds
// matching memory by construction (lazy DFA), so the Rust GREP_SIZE_LIMIT has no knob to turn:
// the safety property it guarded holds without one.
//
// matchList is the irt form: a list of expressions plus Burp's three flags (Match type, Case
// sensitive, Exclude HTTP headers). The single grep_match and the list are the same feature at
// two sizes, so sending both is refused — the operator would have typed two expression sets and
// had one silently dropped, the exact silent-compete trap the recursive_grep two-form refusal
// already refuses.
func buildGrep(matchRe, extractRe *string, matchList *[]string, simple, caseSensitive, excludeHeaders *bool) (intruder.Grep, error) {
	var g intruder.Grep
	var err error
	if matchRe != nil && *matchRe != "" {
		g.MatchRe, err = regexp.Compile(*matchRe)
		if err != nil {
			return g, fmt.Errorf("bad grep_match pattern: %v", err)
		}
	}
	if extractRe != nil && *extractRe != "" {
		g.ExtractRe, err = regexp.Compile(*extractRe)
		if err != nil {
			return g, fmt.Errorf("bad grep_extract pattern: %v", err)
		}
	}
	if matchList != nil {
		hasSingle := matchRe != nil && *matchRe != ""
		if hasSingle {
			return g, fmt.Errorf("grep_match and grep_match_list are the same feature at two sizes; send one — a request carrying both would silently drop one of the two expression sets")
		}
		// Nil simple means simple: the single-string grep_match has always behaved as a literal
		// (quoteRegex folds the decision into the pattern client-side), so the list's default
		// keeps that behaviour rather than inventing a regex-by-default break.
		isSimple := simple == nil || *simple
		caseSensitive := caseSensitive != nil && *caseSensitive
		exclude := excludeHeaders != nil && *excludeHeaders
		nonEmpty := make([]string, 0, len(*matchList))
		for _, e := range *matchList {
			if strings.TrimSpace(e) != "" {
				nonEmpty = append(nonEmpty, e)
			}
		}
		if len(nonEmpty) == 0 {
			return g, fmt.Errorf("grep_match_list carries no expression; send at least one, or omit the list")
		}
		g.MatchList, err = intruder.NewMatchList(nonEmpty, isSimple, caseSensitive, exclude)
		if err != nil {
			return g, err
		}
	}
	return g, nil
}

// payloadOrdinal maps a report ordinal to the plan ordinal payloadsAt needs: with Burp's
// baseline request enabled (v34) the baseline is item 0 and the plan's ordinals shift by one.
func payloadOrdinal(report *intruder.AttackReport, ordinal int) int {
	if report.Baseline && ordinal > 0 {
		return ordinal - 1
	}
	return ordinal
}

// payloadsAt recovers the payload combination behind a plan ordinal. This is why results can hold
// an ordinal and nothing else: the plan is a pure function of the index.
// Never nil: BucketExample.Payloads goes out as `payloads` and types.tools.ts declares it
// `string[]`, so an ordinal the plan cannot place must be an empty array rather than a `null` the
// browser was told could not happen (burpsy-react-ui-9pxd).
func payloadsAt(plan *intruder.AttackPlan, sets []intruder.PayloadSet, ordinal int) []string {
	out := []string{}
	var asg intruder.Assignment
	if !plan.Fill(ordinal, &asg) {
		return out
	}
	for _, slot := range asg.Slots {
		if slot.Set < 0 || slot.Set >= len(sets) {
			continue
		}
		items := sets[slot.Set].Items
		if slot.Payload >= 0 && slot.Payload < len(items) {
			out = append(out, items[slot.Payload])
		}
	}
	return out
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---- Scanner -----------------------------------------------------------------------------------

// scannerFinding mirrors scanner.ts's result shape.
type scannerFinding struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Param       string `json:"param"`
	Evidence    string `json:"evidence"`
}

// liveAuditEnableReq mirrors dashboard.ts's setAudit body.
//
// Query is a pointer so "absent" and "empty" stay apart: a POST that only flips the switch leaves the
// installed filter alone, and `"query": ""` is the explicit way to clear it. Collapsing them would mean
// every toggle silently widened the sweep back to the whole engagement scope.
type liveAuditEnableReq struct {
	Enabled bool    `json:"enabled"`
	Query   *string `json:"query"`
	// TrafficSource is the per-source gate choice (zk35): "proxy" (the default — only the
	// operator's own proxied captures) or "everything" (any tool's in-scope captures, so a
	// crawl with the sweep on gets its discoveries audited as they land). Pointer so an
	// absent field never changes the choice; an unknown value is refused by the state.
	TrafficSource *string `json:"traffic_source"`
	// RetryStalled asks for the iyqg operator action: rewind the cursor to the stalled
	// exchange so the next tick waits on it with the stall budget carried, not restarted.
	// Distinguished from absent by pointer so a plain {enabled} toggle from an older client
	// never means "retry" — but a plain {enabled} POST already carries the current switch,
	// so the two compose without a second route.
	RetryStalled *bool `json:"retry_stalled"`
}

// handleScannerLive is the /api/scanner/live endpoint: GET reports the sweep state,
// POST flips the enabled switch. The body shape mirrors dashboard.ts's LiveAuditResp.
func (s *Server) handleScannerLive(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.liveAuditStatus())
	case http.MethodPost:
		var req liveAuditEnableReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if s.liveAudit != nil {
			if req.TrafficSource != nil {
				if err := s.liveAudit.SetTrafficSource(LiveAuditTrafficSource(*req.TrafficSource)); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				s.events.Record(dash.EventLiveAuditScoped, dash.SeverityInfo, fmt.Sprintf(
					"the live audit now admits %q-captured traffic", *req.TrafficSource))
			}
			// The retry action runs before the switch handling: a stalled sweep being retried is
			// enabled by definition (it is running ticks), and ordering keeps "enable" the
			// body's last word. A retry requested while nothing is stalled is refused with a
			// 409 rather than a silent 200 — an operator pressing the button wants to know the
			// stall already cleared, not a no-op they must infer from stalled_at disappearing.
			if req.RetryStalled != nil && *req.RetryStalled {
				if !s.liveAudit.RetryStalled() {
					http.Error(w, "not stalled: the sweep is not waiting on any exchange right now", http.StatusConflict)
					return
				}
				s.events.Record(dash.EventLiveAuditStalled, dash.SeverityInfo,
					"the operator re-queued the stalled exchange; the sweep will wait on it again with its stall budget carried")
			}
			// The query is installed before the switch is flipped. If it will not parse the request is
			// refused and nothing changes — a filter the operator believed they had set, followed by a
			// sweep running against the whole scope because the parse failed quietly, is the one
			// outcome an operator setting a filter must never get.
			if req.Query != nil {
				if err := s.liveAudit.SetQuery(*req.Query); err != nil {
					http.Error(w, "live audit query: "+query.Render(err), http.StatusBadRequest)
					return
				}
				if *req.Query == "" {
					s.events.Record(dash.EventLiveAuditScoped, dash.SeverityInfo,
						"the live audit query was cleared; every in-scope exchange is now eligible")
				} else {
					s.events.Record(dash.EventLiveAuditScoped, dash.SeverityInfo,
						"the live audit is now filtered to: "+*req.Query)
				}
			}
			was := s.liveAudit.IsEnabled()
			s.liveAudit.SetEnabled(req.Enabled)
			if was != req.Enabled {
				kind, detail := dash.EventLiveAuditDisabled, "the operator switched the live active audit off"
				if req.Enabled {
					kind, detail = dash.EventLiveAuditEnabled, "the operator switched the live active audit on; active checks will now be sent at newly captured in-scope traffic"
				}
				s.events.Record(kind, dash.SeverityInfo, detail)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.liveAuditStatus())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- Sequencer ---------------------------------------------------------------------------------

// sequencerAnalyseReq mirrors AnalyseReq in crates/web/src/routes/sequencer.rs:
// text (one token per line), pre-split tokens, or neither — and an optional
// forced encoding. The pointer on Tokens distinguishes "absent" from "empty",
// which matters because an explicit empty array is a valid (empty) sample while
// an absent one is a caller error.
type sequencerAnalyseReq struct {
	Text     *string   `json:"text"`
	Tokens   *[]string `json:"tokens"`
	Encoding *string   `json:"encoding"`
	// SignificancePercent is the operator's significance level, as a percentage:
	// 0.03 means 0.03%, not 3%. Burp makes this the input to the whole analysis
	// ("you can choose the probability you use to interpret the randomness of
	// your findings"), and it reaches exactly one part of the report — the
	// effective-entropy curve. A pointer so an absent level is answered with the
	// default and marked as defaulted, rather than being indistinguishable from
	// an operator who typed the default.
	SignificancePercent *float64 `json:"significance_percent"`
	// Burp's "Token handling" (burpsy-react-ui-i4u). PadMode is "none" | "start" | "end"; the
	// statistical tests can only run over tokens of one length, so a variable-length sample is
	// padded up to the longest and WHERE decides which byte positions the analysis reads.
	//
	// Absent means none, which is what every existing caller means and what the analysis did before
	// this existed. An unknown value is refused by name rather than falling back to none — a
	// silently ignored pad mode would leave the operator reading an unpadded analysis believing it
	// was padded.
	PadMode *string `json:"pad_mode"`
	// PadByte is the single character to pad with. Burp's own default is '0'. A string rather than a
	// number so the wire carries what the operator typed; anything that is not exactly one byte is
	// refused, because a two-character "pad byte" cannot mean anything.
	PadByte *string `json:"pad_byte"`
	// Base64Decode is Burp's "Base64-decode before analyzing": a base64 token's randomness is in the
	// bytes it encodes, not the alphabet it is written in. A token that is not valid base64 is
	// refused by the engine naming which one, rather than analysed as a different sample.
	Base64Decode *bool `json:"base64_decode"`
	// DisabledTests is Burp's per-test switch for this one analysis (burpsy-react-ui-3iao): the
	// AnalysisTest ids to leave out, e.g. ["compression"]. A pointer so "absent" — run what the saved
	// sequencer settings leave on — is distinct from an explicit empty list, which runs every test
	// whatever the settings say. An unknown id is refused naming the accepted set: an id silently
	// ignored would leave the operator reading a verdict that still counted the test they removed.
	// "Redo analysis" is this request sent again with a different list; the report marks each
	// disabled test as not run, by name.
	DisabledTests *[]string `json:"disabled_tests"`
}

// parsePadMode maps the wire's "none" | "start" | "end" onto the engine's PadMode. Unknown values
// are refused naming the value, the same rule the encoding field follows: a pad mode that was
// silently dropped would produce an unpadded report under a padded label.
func parsePadMode(raw string) (sequencer.PadMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "none":
		return sequencer.PadNone, nil
	case "start":
		return sequencer.PadStart, nil
	case "end":
		return sequencer.PadEnd, nil
	}
	return sequencer.PadNone, fmt.Errorf("pad_mode %s is not one of none, start or end", strconv.Quote(raw))
}

// parseEncoding maps the UI's "hex" | "base64" | "raw" onto the engine's
// Encoding, naming anything else rather than silently ignoring it.
func parseEncoding(name string) (sequencer.Encoding, error) {
	switch name {
	case "hex":
		return sequencer.EncodingHex, nil
	case "base64":
		return sequencer.EncodingBase64, nil
	case "raw":
		return sequencer.EncodingRaw, nil
	}
	return 0, fmt.Errorf("unknown encoding %q: expected hex, base64 or raw", name)
}

// handleSequencerAnalyse answers a pasted token list in one synchronous call —
// the Sequencer's paste mode. Takes no state at all, which is the point: pasted
// text is not traffic, so there is no scope decision to make and nothing to
// record. The response is the full SequencerReport (internal/web/ui/src/
// sequencer.ts), not the legacy aggregate shape this endpoint used to return.
func (s *Server) handleSequencerAnalyse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req sequencerAnalyseReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	var tokens []string
	switch {
	case req.Tokens != nil:
		for _, t := range *req.Tokens {
			if t != "" {
				tokens = append(tokens, t)
			}
		}
	case req.Text != nil:
		tokens = sequencer.TokensFromText(*req.Text)
	default:
		http.Error(w, "no tokens: pass text (one per line) or tokens", http.StatusBadRequest)
		return
	}
	var encoding *sequencer.Encoding
	if req.Encoding != nil {
		e, err := parseEncoding(*req.Encoding)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		encoding = &e
	}
	// An empty paste is answered rather than refused: the report says "no tokens
	// were supplied", and that is more useful to whoever pasted the wrong buffer
	// than a 400 with no analysis in it.
	// Token handling, decided before the significance branch because it changes the SAMPLE rather
	// than how the sample is interpreted.
	opts := sequencer.Options{Encoding: encoding, PadByte: '0'}
	if req.PadMode != nil {
		mode, err := parsePadMode(*req.PadMode)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		opts.Pad = mode
	}
	if req.PadByte != nil {
		if len([]byte(*req.PadByte)) != 1 {
			http.Error(w, fmt.Sprintf(
				"pad_byte %s is not a single byte; padding inserts one byte per position, so a pad character must be exactly one",
				strconv.Quote(*req.PadByte)), http.StatusBadRequest)
			return
		}
		opts.PadByte = (*req.PadByte)[0]
	}
	// The saved analysis settings (burpsy-react-ui-nm81) govern whatever this request does not say for
	// itself: which tests run, and whether tokens are base64-decoded first.
	saved := s.sequencerSettings()
	opts.Base64Decode = saved.TokenHandling.Base64DecodeBeforeAnalyzing
	if req.Base64Decode != nil {
		opts.Base64Decode = *req.Base64Decode
	}
	opts.DisabledTests = saved.DisabledTests()
	if req.DisabledTests != nil {
		for _, id := range *req.DisabledTests {
			if !sequencer.KnownAnalysisTest(id) {
				http.Error(w, fmt.Sprintf("disabled_tests names %s, which is not a test this analysis runs; the tests are %s",
					strconv.Quote(id), strings.Join(sequencerTestIDs(), ", ")), http.StatusBadRequest)
				return
			}
		}
		opts.DisabledTests = append([]string(nil), *req.DisabledTests...)
	}

	w.Header().Set("Content-Type", "application/json")
	if req.SignificancePercent == nil {
		opts.SignificancePercent = sequencer.DefaultSignificancePercent
		opts.SignificanceDefaulted = true
		rep, err := sequencer.AnalyseOpts(tokens, opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(rep)
		return
	}
	// Refused, not clamped. A level above 10% or below 0.001% is outside the
	// range Burp's analysis is defined over, and silently moving it to the edge
	// would answer a different question under the operator's number — the same
	// refusal the encoding field makes for an unknown alphabet.
	if !sequencer.ValidSignificancePercent(*req.SignificancePercent) {
		http.Error(w, fmt.Sprintf(
			"significance_percent %g is outside the range this analysis is defined over: %g to %g, as a percentage (0.03 means 0.03%%, not 3%%). Burp's own guidance puts FIPS work at 0.002%%-0.03%% and scientific work at 1%%-5%%.",
			*req.SignificancePercent, sequencer.MinSignificancePercent, sequencer.MaxSignificancePercent),
			http.StatusBadRequest)
		return
	}
	opts.SignificancePercent = *req.SignificancePercent
	rep, err := sequencer.AnalyseOpts(tokens, opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(rep)
}

// helpers ----------------------------------------------------------------------------------------

func parseResponseStatus(raw []byte) *uint16 {
	s := firstLineStatus(raw)
	if s == nil {
		return nil
	}
	return s
}

func firstLineStatus(raw []byte) *uint16 {
	line := string(raw)
	if i := strings.Index(line, "\r\n"); i >= 0 {
		line = line[:i]
	} else if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil && n >= 100 && n <= 599 {
			v := uint16(n)
			return &v
		}
	}
	return nil
}

func firstLineMethod(req string) string {
	if i := strings.IndexByte(req, ' '); i >= 0 {
		return req[:i]
	}
	return ""
}

// firstLinePath is the request target as a *path*, with an absolute-form request line reduced to
// origin form.
//
// RFC 7230 §5.3 allows two forms in a request line, and both reach here. Origin-form
// (`POST /login HTTP/1.1`) is what a browser sends to a server; absolute-form
// (`POST http://host:9091/login HTTP/1.1`) is what it sends to a *proxy*, so it is exactly what the
// store holds for captured traffic — and therefore exactly what send-to-Repeater hands back when the
// operator resends it.
//
// Returning that verbatim made the whole URI the exchange's Path. One resend of /login then split on
// its own slashes and grew a phantom branch in the site map — `http:` → “ → `127.0.0.1:9091` →
// `login` — four nodes for one request, with the resource listed twice in the tree and findings on
// the copy attributed to a path no server ever served.
func firstLinePath(req string) string {
	lines := strings.SplitN(req, "\n", 2)
	if len(lines) == 0 {
		return ""
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return ""
	}
	return originForm(parts[1])
}

// originForm reduces an absolute-form request target to its path and query.
//
// Anything that does not parse as an absolute URI is returned unchanged: asterisk-form (`OPTIONS *`)
// and authority-form (`CONNECT host:443`) are legal targets that are not paths, and rewriting them
// into one would be inventing a request that was never sent.
func originForm(target string) string {
	if !strings.Contains(target, "://") {
		return target
	}
	u, err := url.Parse(target)
	if err != nil || u.Path == "" {
		return target
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}

func intOrZero(p *uint16) int {
	if p == nil {
		return 0
	}
	return int(*p)
}

// validParent returns id when it names an exchange that exists, and nil otherwise.
//
// A caller-supplied id is not evidence that the row is there. Storing an unresolvable parent would
// put a dangling link in the lineage graph, and a reader following it would land on nothing or —
// worse, if the store later grows past it — on an unrelated exchange.
func (s *Server) validParent(id *core.ExchangeID) *core.ExchangeID {
	if id == nil {
		return nil
	}
	if _, err := s.store.GetExchange(*id); err != nil {
		return nil
	}
	return id
}
