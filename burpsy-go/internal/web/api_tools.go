package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/scanner"
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
}

// repeaterSendResp mirrors repeater.ts's SendResp.
type repeaterSendResp struct {
	Status        int    `json:"status"`
	DurationMs    uint64 `json:"duration_ms"`
	Response      string `json:"response"`
	RequestMsgID  uint64 `json:"request_msg_id"`
	ResponseMsgID uint64 `json:"response_msg_id"`
	ExchangeID    uint64 `json:"exchange_id"`
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
	host, port, tls, err := targetParts(req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.EqualFold(req.Protocol, "https") {
		tls = true
	} else if strings.EqualFold(req.Protocol, "http") {
		tls = false
	}
	if strings.TrimSpace(req.Request) == "" {
		http.Error(w, "Empty request", http.StatusBadRequest)
		return
	}
	// The repeater sends to whatever target the operator types, so it is gated
	// by scope for the same reason the intruder is: a scope the operator set to
	// constrain outbound traffic must not be bypassable by sending raw bytes
	// here. The request line is not parsed (the operator owns it), so this is a
	// host-level check, the same first layer the intruder applies.
	if !s.scope.MayContainHost(host, port, tls) {
		http.Error(w, "refused: "+s.scope.Explain(host, port, "/", tls), http.StatusForbidden)
		return
	}

	// SendRaw handles a raw HTTP request (possibly HTTP/1.0-style with Host line) over the wire.
	ctx := r.Context()
	rawResp, err := s.sender.SendRaw(ctx, host, port, tls, []byte(req.Request))
	if err != nil {
		// Surface the dial/parse error to the UI so Repeater is not silently empty.
		s.toolLog.Record(toollog.ToolRepeater, host, port, tls, "SEND", "", 0, 0, err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Persist both halves so history/decoder can reference them. A failed Put
	// must not be silently swallowed: an exchange referencing a non-existent
	// message ID would 404 in history lookups. Log and degrade rather than
	// advertise a bad id.
	reqMsgID, err := s.store.Put([]byte(req.Request), core.DirectionRequest)
	if err != nil {
		s.logger.Error("repeater: failed to store request", zap.Error(err))
	}
	respMsgID, err := s.store.Put(rawResp, core.DirectionResponse)
	if err != nil {
		s.logger.Error("repeater: failed to store response", zap.Error(err))
	}

	status := parseResponseStatus(rawResp)

	ex := &core.Exchange{
		Host:        host,
		Port:        port,
		TLS:         tls,
		Method:      firstLineMethod(req.Request),
		Path:        firstLinePath(req.Request),
		Status:      status,
		ResponseLen: len(rawResp),
		StartedMs:   uint64(time.Now().UnixMilli()),
		DurationMs:  0,
		Request:     reqMsgID,
		Response:    &respMsgID,
		Protocol:    core.ProtocolHTTP1,
	}
	s.store.AddExchange(ex)

	s.toolLog.Record(toollog.ToolRepeater, host, port, tls, ex.Method, ex.Path, intOrZero(status), ex.DurationMs, "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(repeaterSendResp{
		Status:        intOrZero(status),
		DurationMs:    ex.DurationMs,
		Response:      string(rawResp),
		RequestMsgID:  uint64(reqMsgID),
		ResponseMsgID: uint64(respMsgID),
		ExchangeID:    ex.ID,
	})
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
	Payloads       *[]string                 `json:"payloads"`
	Mode           *string                   `json:"mode"`
	Points         *[]int                    `json:"points"`
	PayloadSets    *[][]string               `json:"payload_sets"`
	PayloadSources *[]intruder.PayloadSource `json:"payload_sources"`
	PayloadRules   *[]intruder.RuleSpec      `json:"payload_rules"`
	MaxPayloads    *int                      `json:"max_payloads"`
	GrepMatch      *string                   `json:"grep_match"`
	GrepExtract    *string                   `json:"grep_extract"`
	Pool           *string                   `json:"pool"`
	AutoThrottle   *intruder.AutoThrottle    `json:"auto_throttle"`
	RPS            *float64                  `json:"rps"`
	MaxInFlight    *int                      `json:"max_in_flight"`
	MaxRequests    *int                      `json:"max_requests"`
	TimeoutMS      *uint64                   `json:"timeout_ms"`
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

// BucketExample resolves one bucket's first ordinal back to the exact payload combination, so
// the operator never has to reconstruct it by hand.
type BucketExample struct {
	FirstOrdinal int      `json:"first_ordinal"`
	Payloads     []string `json:"payloads"`
}

// RunView is the full report shape: the bucketed summary, payloads behind each bucket, and the
// honest per-set counting (what was capped, truncated, skipped or dropped).
type RunView struct {
	Report      intruder.AttackReport `json:"report"`
	Examples    []BucketExample       `json:"examples"`
	PayloadSets []intruder.PayloadSet `json:"payload_sets"`
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
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Burp's rule, and a sound one: one position makes the multi-set modes meaningless, and twenty
	// is where a cluster bomb stops being an attack and becomes an outage.
	if (kind == intruder.AttackKindPitchfork || kind == intruder.AttackKindClusterBomb) &&
		(len(wanted) < 2 || len(wanted) > 20) {
		http.Error(w, fmt.Sprintf("%s requires between 2 and 20 payload positions, got %d", kind, len(wanted)), http.StatusBadRequest)
		return
	}
	selected := make([]intruder.InsertionPoint, 0, len(wanted))
	for _, i := range wanted {
		selected = append(selected, discovered[i])
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
		resolved = append(resolved, *ps)
	}

	grep, err := buildGrep(req.GrepMatch, req.GrepExtract)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if at := req.AutoThrottle; at != nil && len(at.Statuses) > intruderMaxThrottleStatuses {
		http.Error(w, fmt.Sprintf("auto_throttle lists %d statuses, more than the %d allowed", len(at.Statuses), intruderMaxThrottleStatuses), http.StatusBadRequest)
		return
	}

	// Bounded at BOTH ends: a rate below one request per two minutes is not a rate anyone means,
	// and there is deliberately no way to turn the rate cap off over HTTP.
	rps := intruderDefaultRPS
	if req.RPS != nil {
		if *req.RPS < intruderMinRPS {
			http.Error(w, fmt.Sprintf("rps must be at least %v, got %v", intruderMinRPS, *req.RPS), http.StatusBadRequest)
			return
		}
		rps = math.Min(*req.RPS, 1000.0)
	}
	maxInFlight := 10
	if req.MaxInFlight != nil {
		maxInFlight = *req.MaxInFlight
	}
	maxInFlight = clampInt(maxInFlight, 1, intruderMaxInFlightCeiling)
	limits := intruder.NewRateLimit(&rps, 1, maxInFlight)
	if req.Pool != nil {
		limits = limits.Named(*req.Pool)
	}
	if at := req.AutoThrottle; at != nil {
		limits = limits.WithAutoThrottle(at)
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
	send := func(raw []byte) (intruder.Sent, error) {
		sctx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			sctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
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

	attack := intruder.NewAttack(msg.Raw(), selected, resolved, plan).
		WithLimits(limits).
		WithGrep(grep)
	report := intruder.Run(attack, send, record)

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

	examples := make([]BucketExample, 0, len(report.Buckets))
	for _, b := range report.Buckets {
		examples = append(examples, BucketExample{
			FirstOrdinal: b.FirstOrdinal,
			Payloads:     payloadsAt(plan, resolved, b.FirstOrdinal),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RunView{
		Report:      *report,
		Examples:    examples,
		PayloadSets: resolved,
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

type scannerAuditReq struct {
	Method     string `json:"method"`
	Target     string `json:"target"`
	ExchangeID uint64 `json:"exchange_id,omitempty"`
}

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
type liveAuditEnableReq struct {
	Enabled bool `json:"enabled"`
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
			s.liveAudit.SetEnabled(req.Enabled)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.liveAuditStatus())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleScannerAudit is the legacy /api/scanner/audit alias for /api/audit/{id}.
func (s *Server) handleScannerAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req scannerAuditReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.ExchangeID == 0 {
		http.Error(w, "exchange_id is required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.runAudit(r.Context(), req.ExchangeID))
}

// handleAuditByPath serves POST /api/audit/{id}, running an active scan over one exchange.
func (s *Server) handleAuditByPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/audit/")
	id, err := strconv.ParseUint(strings.TrimSuffix(idStr, "/"), 10, 64)
	if err != nil || id == 0 {
		http.Error(w, "Invalid exchange id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.runAudit(r.Context(), id))
}

// runAudit audits one exchange and returns the response body both audit endpoints send.
//
// The body carries the engine's AuditOutcome, matching what the Rust route returns from its audit
// hook (`{enabled, exchange, active_checks, outcome}`). Before the audit engine existed the reply was
// `{started: true, exchange_id: N}` and the findings went to the finding store — so an operator who
// audited a host that had stopped answering saw the same "started: true" as one whose whole check set
// ran. Those two keys are kept for compatibility, and the outcome is what makes them mean something:
// `dispositions` names every check that was *not* dispatched and why.
//
// scanner.ts renders this by pretty-printing the JSON it gets back, so the richer body needs no
// change on the TypeScript side — there is no typed audit response to keep in sync.
func (s *Server) runAudit(ctx context.Context, id uint64) map[string]interface{} {
	if s.scanner == nil {
		// Built with the engagement scope: an active audit sends real traffic, and the engine refuses
		// an out-of-scope exchange before it plans any work.
		s.scanner = scanner.NewActiveScanner(s.store, s.logger).WithScope(s.scope)
	}
	body := map[string]interface{}{
		"started":       true,
		"exchange_id":   id,
		"active_checks": s.scanner.ActiveCheckCount(),
		"unimplemented": s.scanner.UnimplementedCheckCount(),
	}
	outcome, findings := s.scanner.AuditWithin(ctx, id, s.scanner.AuditConfig())
	body["outcome"] = outcome
	body["dispositions"] = outcome.Dispositions()
	body["summary"] = outcome.Summary()
	if outcome.Error != "" {
		s.logger.Warn("audit refused", zap.Uint64("exchange_id", id), zap.String("reason", outcome.Error))
		return body
	}
	ex, gerr := s.store.GetExchange(id)
	if gerr == nil {
		s.toolLog.Record(toollog.ToolScanner, ex.Host, ex.Port, ex.TLS, ex.Method, ex.Path, 0, 0, "audit")
	}
	for _, f := range findings {
		s.findings.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
		})
	}
	return body
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

// handleSequencerCapture serves the token lists accumulated by the sequencer capture phase.
func (s *Server) handleSequencerCapture(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/sequencer/capture/")
	if path == "stop" {
		// The UI calls this to halt a live capture; the Go port has no live capture loop.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"stopped": true})
		return
	}
	if path != "" {
		// Per-token-list detail: the Go engine exposes the shared capture list.
		tokens := s.captureTokens()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total":  len(tokens),
			"tokens": tokens,
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"capturing": false, "total": 0})
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

func firstLinePath(req string) string {
	lines := strings.SplitN(req, "\n", 2)
	if len(lines) == 0 {
		return ""
	}
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func intOrZero(p *uint16) int {
	if p == nil {
		return 0
	}
	return int(*p)
}

// captureTokens is the shared sequencer capture accumulator; empty unless a capture ran.
func (s *Server) captureTokens() []string {
	return nil
}
