package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	// FromExchange is the exchange this send was built from, when the operator reached Repeater via
	// send-to rather than by typing a request. Recorded as the new exchange's parent so a resend can
	// be traced back to the capture it came from. A pointer because exchange 0 is a real exchange and
	// is very often the first thing sent to Repeater.
	FromExchange *core.ExchangeID `json:"from_exchange,omitempty"`
	// Options carries the per-send overrides (Burp Repeater's config-override menu). Nil means the
	// standing behaviour in full — the zero options are the defaults, so an absent object and an
	// empty one mean the same thing.
	Options *repeaterSendOptions `json:"options,omitempty"`
}

// repeaterSendResp mirrors repeater.ts's SendResp.
type repeaterSendResp struct {
	Status        int             `json:"status"`
	DurationMs    uint64          `json:"duration_ms"`
	Response      string          `json:"response"`
	RequestMsgID  uint64          `json:"request_msg_id"`
	ResponseMsgID uint64          `json:"response_msg_id"`
	ExchangeID    core.ExchangeID `json:"exchange_id"`
	// Redirects is the chain this send produced, and it is present only when the response was a 30x.
	//
	// `response` above stays the response to the request the operator wrote — that is the contract
	// Repeater has, and replacing those bytes with a later hop's would hide the Set-Cookie and the
	// Location an operator opened Repeater to look at. So the chain is reported alongside rather than
	// substituted, with every hop saying whether it was followed and why not when it was not. A nil
	// field means "not a redirect"; a field present with `followed: false` on every hop means the
	// policy or the scope stopped it, which are different facts and are named differently.
	Redirects *repeaterRedirects `json:"redirects,omitempty"`
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
	raw := opts.applyToRequest([]byte(request), s.cookieHeaderFor(host, port, tls))
	// The repeater sends to whatever target the operator types, so it is gated
	// by scope for the same reason the intruder is: a scope the operator set to
	// constrain outbound traffic must not be bypassable by sending raw bytes
	// here. The request line is not parsed (the operator owns it), so this is a
	// host-level check, the same first layer the intruder applies.
	if !s.scope.MayContainHost(host, port, tls) {
		return repeaterSendSpec{}, http.StatusForbidden, errors.New("refused: " + s.scope.Explain(host, port, "/", tls))
	}
	return repeaterSendSpec{
		Host: host, Port: port, TLS: tls, Raw: raw, AsWritten: request, Options: opts, From: from,
	}, 0, nil
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
		Request:   reqMsgID,
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
	s.store.AddExchange(ex)

	// The same count the exchange row carries, taken from the same bytes, so Logger and HTTP history
	// cannot disagree about the size of one send.
	// Linked to the exchange just written, so Logger's message viewer can resolve this row's bytes
	// (burpsy-react-ui-5bl). &ex.ID, never a zero: the traffic store counts from zero, so exchange 0
	// is a real row and a nil-less zero would point the viewer at the wrong message pair.
	s.toolLog.Record(toollog.ToolRepeater, spec.Host, spec.Port, spec.TLS, ex.Method, ex.Path, intOrZero(status),
		toollog.Bytes(len(rawResp)), ex.Duration.Millis(), "", &ex.ID)

	return repeaterSendResp{
		Status:        intOrZero(status),
		DurationMs:    ex.Duration.Millis(),
		Response:      string(rawResp),
		RequestMsgID:  uint64(reqMsgID),
		ResponseMsgID: uint64(respMsgID),
		ExchangeID:    ex.ID,
	}, ex
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
	resp.Redirects = s.followRepeaterRedirects(ctx, spec.Host, spec.Port, spec.TLS, spec.Raw, rawResp, spec.Options)
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
	spec, code, err := s.prepareRepeaterSend(req.Target, req.Protocol, req.Request, req.Options, req.FromExchange)
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
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
) *repeaterRedirects {
	standing := s.sender.Network().Redirects
	policy := opts.redirectPolicy(standing)
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

// cookieHeaderFor returns the session coordinator's cookie header for the target, or empty when
// there is no coordinator — a nil check, not a hope: the coordinator is an optional capability and
// a nil dereference here would take the whole send down for an option that is off by default.
func (s *Server) cookieHeaderFor(host string, port uint16, tls bool) string {
	if s.sessionCoordinator == nil {
		return ""
	}
	return s.sessionCoordinator.CookieHeader(host, port, tls)
}

// ---- Intruder ----------------------------------------------------------------------------------

// The wire contract here is the Rust web layer's (crates/web/src/lib.rs), consumed byte-for-byte
// by the bundled UI's intruder.ts: PointsReq/PointView for inspection, and RunReq/RunView — or
// the legacy flat AttemptView[] array — for an attack. Both shapes come off the same engine, so
// there is one execution path, one rate limiter, and one place scope is enforced.

const (
	intruderDefaultRPS          = 20.0
	intruderMinRPS              = 0.01
	intruderMaxInFlightCeiling  = 999
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
}

// PointView is one discoverable insertion point. Index is the position in the returned slice —
// that is the handle the UI echoes back in a run's `points`, not a byte offset.
type PointView struct {
	Index   int    `json:"index"`
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Offset  int    `json:"offset"`
	Len     int    `json:"len"`
	Current string `json:"current"`
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
	cfg := intruder.DefaultPointConfig()
	if req.All {
		cfg = intruder.AllPointConfig()
	}
	found := intruder.FindPoints(msg, cfg)
	out := make([]PointView, 0, len(found))
	for i, p := range found {
		out = append(out, PointView{
			Index:   i,
			Kind:    p.Kind.String(),
			Label:   p.Label,
			Offset:  p.Span.Offset,
			Len:     p.Span.Len,
			Current: msg.Text(p.Span),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// intruderRunReq mirrors the Rust RunReq. Pointers distinguish "absent" from "zero", which the
// request semantics depend on (a named empty mode list is a 400, an absent one is sniper).
type intruderRunReq struct {
	MsgID          uint64                    `json:"msg_id"`
	Target         string                    `json:"target"`
	All            bool                      `json:"all"`
	PointIndex     *int                      `json:"point_index"`
	ManualPoints   *[]intruder.ManualSpan    `json:"manual_points"`
	Payloads       *[]string                 `json:"payloads"`
	Mode           *string                   `json:"mode"`
	Points         *[]int                    `json:"points"`
	PayloadSets    *[][]string               `json:"payload_sets"`
	PayloadSources *[]intruder.PayloadSource `json:"payload_sources"`
	PayloadRules   *[]intruder.RuleSpec      `json:"payload_rules"`
	// URLEncode is Burp's "URL-encode these characters" (burpsy-react-ui-8cbc): the
	// characters percent-encoded in every generated payload as the final pass, after the
	// rule chain. Empty (or absent) means no extra encoding — matching the off state, not
	// an empty set that would encode nothing anyway. Spaces and control characters are
	// always encoded additionally, because a request containing them cannot be delivered.
	URLEncode    *string                `json:"url_encode_characters"`
	MaxPayloads  *int                   `json:"max_payloads"`
	GrepMatch    *string                `json:"grep_match"`
	GrepExtract  *string                `json:"grep_extract"`
	Pool         *string                `json:"pool"`
	AutoThrottle *intruder.AutoThrottle `json:"auto_throttle"`
	RPS          *float64               `json:"rps"`
	MaxInFlight  *int                   `json:"max_in_flight"`
	MaxRequests  *int                   `json:"max_requests"`
	TimeoutMS    *uint64                `json:"timeout_ms"`
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
		if req.RPS != nil || req.MaxInFlight != nil || req.AutoThrottle != nil {
			return intruder.RateLimit{}, fmt.Errorf(
				"this attack names the pool %q and also sets its own limits; the pool already states "+
					"rps, max_in_flight and automatic throttling, so send one or the other",
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

// AttemptView is the legacy one-position form's row.
type AttemptView struct {
	Payload     string  `json:"payload"`
	Status      *int    `json:"status"`
	Len         int     `json:"len"`
	DurationMS  uint64  `json:"duration_ms"`
	Error       *string `json:"error"`
	GrepMatched *bool   `json:"grep_matched"`
	GrepExtract *string `json:"grep_extract"`
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

	cfg := intruder.DefaultPointConfig()
	if req.All {
		cfg = intruder.AllPointConfig()
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
	// splice's earliest-span-wins rule, which would silently drop one of the two payloads.
	for _, m := range manual {
		for _, d := range selected {
			if m.Span.Offset < d.Span.Offset+d.Span.Len && d.Span.Offset < m.Span.Offset+m.Span.Len {
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
	for i, src := range sources {
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

	grep, err := buildGrep(req.GrepMatch, req.GrepExtract)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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
	plan := intruder.NewAttackPlan(kind, len(selected), setLens, bound)

	timeout := time.Duration(intruderDefaultTimeoutMS) * time.Millisecond
	if req.TimeoutMS != nil {
		timeout = time.Duration(*req.TimeoutMS) * time.Millisecond
	}

	// One authorising sender for the whole attack. The scope decision still happens once per
	// spliced request — which is what matters, because a payload landing in a path position
	// rewrites the request line, so the request that goes out may address something a host-level
	// check never saw.
	auth := sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls)
	ctx := r.Context()

	// The session cookie jar, applied to every spliced request. Burp's jar "is shared between all of
	// Burp's tools"; before this it reached only the Repeater, so an attack against an authenticated
	// endpoint reported the login wall instead of the endpoint. Resolved once here rather than per
	// request: an attack must ask the same question of every payload, and a jar that changed
	// mid-attack would make the buckets incomparable.
	//
	// exemptCookies are the cookie names this attack is fuzzing. Burp: "when the Scanner or Intruder
	// makes a request that manipulates a cookie […] the session handling action is not applied to
	// that request." Refreshing the position being fuzzed from the jar would send the same request
	// every time and produce one meaningless bucket. See internal/web/intruder_cookies.go.
	jarHeader := s.cookieHeaderFor(host, port, tls)
	exemptCookies := exemptCookieNames(selected)

	send := func(raw []byte) (intruder.Sent, error) {
		sctx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			sctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		// After the splice, never before: insertion points are byte spans into the base request, and
		// a header added to the base would shift every span after it.
		raw = applyJarCookies(raw, jarHeader, exemptCookies)
		res, err := auth.Send(sctx, raw)
		if err != nil {
			return intruder.Sent{}, err
		}
		return intruder.Sent{Raw: res.Raw, Duration: res.Duration, Status: res.Status}, nil
	}
	record := func(raw []byte) uint64 {
		id, _ := s.store.Put(raw, core.DirectionResponse)
		return uint64(id)
	}

	control := intruder.NewControl()
	attack := intruder.NewAttack(msg.Raw(), selected, resolved, plan).
		WithLimits(limits).
		WithGrep(grep).
		WithControl(control)
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
			if pl := payloadsAt(plan, resolved, a.Ordinal); len(pl) > 0 {
				payload = pl[0]
			}
			rows = append(rows, AttemptView{
				Payload:     payload,
				Status:      a.Status,
				Len:         a.ResponseLen,
				DurationMS:  uint64(a.DurationMS),
				Error:       a.Error,
				GrepMatched: a.GrepMatched,
				GrepExtract: a.GrepExtract,
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
	for _, b := range report.Buckets {
		examples = append(examples, BucketExample{
			FirstOrdinal: b.FirstOrdinal,
			Payloads:     payloadsAt(plan, resolved, b.FirstOrdinal),
		})
		seenOrdinal[b.FirstOrdinal] = true
	}
	for _, a := range report.Attempts {
		if seenOrdinal[a.Ordinal] {
			continue
		}
		seenOrdinal[a.Ordinal] = true
		if pl := payloadsAt(plan, resolved, a.Ordinal); len(pl) > 0 {
			examples = append(examples, BucketExample{FirstOrdinal: a.Ordinal, Payloads: pl})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RunView{
		Report:         *report,
		Examples:       examples,
		PayloadSets:    resolved,
		SessionCookies: intruderSessionCookieView(jarHeader, exemptCookies),
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
func buildGrep(matchRe, extractRe *string) (intruder.Grep, error) {
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
	return g, nil
}

// payloadsAt recovers the payload combination behind a plan ordinal. This is why results can hold
// an ordinal and nothing else: the plan is a pure function of the index.
func payloadsAt(plan *intruder.AttackPlan, sets []intruder.PayloadSet, ordinal int) []string {
	var asg intruder.Assignment
	if !plan.Fill(ordinal, &asg) {
		return nil
	}
	var out []string
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sequencer.AnalyseAs(tokens, encoding))
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
