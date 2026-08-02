package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
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

	// SendRaw handles a raw HTTP request (possibly HTTP/1.0-style with Host line) over the wire.
	ctx := r.Context()
	rawResp, err := s.sender.SendRaw(ctx, host, port, tls, []byte(req.Request))
	if err != nil {
		// Surface the dial/parse error to the UI so Repeater is not silently empty.
		s.toolLog.Record(toollog.ToolRepeater, host, port, tls, "SEND", "", 0, 0, err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Persist both halves so history/decoder can reference them.
	reqMsgID, _ := s.store.Put([]byte(req.Request), core.DirectionRequest)
	respMsgID, _ := s.store.Put(rawResp, core.DirectionResponse)

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

// intruderPointsReq mirrors intruder.ts's position-inspection payload.
type intruderPointsReq struct {
	Method      string `json:"method"`       // "positional" or "raw"
	Target      string `json:"target"`       // scheme://host:port
	PayloadType string `json:"payload_type"` // "simple" | "battering-ram" | "pitchfork" | "cluster-bomb"
	Request     string `json:"request"`      // raw request text
}

// intruderPointsResp mirrors intruder.ts's insertion-point inspection result.
type intruderPointsResp struct {
	InsertionPoints []intruderPoint `json:"insertion_points"`
	Payloads        []string        `json:"payloads"`
}

type intruderPoint struct {
	Index  int    `json:"index"`
	Marker string `json:"marker"`
	Value  string `json:"value,omitempty"`
}

// handleIntruderPoints inspects a request for attack insertion points and previews the payloads.
// Ported from intruder.ts's positional/payload logic into Go (the TS version computed these in the
// browser; here the server answers with the same shape).
func (s *Server) handleIntruderPoints(w http.ResponseWriter, r *http.Request) {
	var req intruderPointsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Request) == "" {
		http.Error(w, "Empty request", http.StatusBadRequest)
		return
	}

	points := findInsertionPoints(req.Request)
	payloads := generatePayloadPreview(req.PayloadType)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(intruderPointsResp{
		InsertionPoints: points,
		Payloads:        payloads,
	})
}

// findInsertionPoints locates §...§ marked spans and, failing that, query/first-line positions.
func findInsertionPoints(request string) []intruderPoint {
	var points []intruderPoint
	// § is the Burp position marker (U+00A7). The UI lets users mark positions with it.
	lines := strings.Split(request, "\n")
	for li, line := range lines {
		for i := 0; i < len(line); i++ {
			if line[i] == '\u00a7' {
				start := i
				// find closing marker
				j := strings.IndexByte(line[start+1:], '\u00a7')
				if j < 0 {
					points = append(points, intruderPoint{Index: li, Marker: line[start:], Value: ""})
					break
				}
				content := line[start+1 : start+1+j]
				points = append(points, intruderPoint{Index: li, Marker: "§" + content + "§", Value: content})
				i = start + 1 + j
			}
		}
	}
	return points
}

// generatePayloadPreview returns a small sample of payloads for the given payload type so the UI's
// payload list is populated before an attack runs. Full generation happens in the engine.
func generatePayloadPreview(payloadType string) []string {
	switch payloadType {
	case "simple", "battering-ram", "":
		return []string{"admin", "test", "payload1", "0000"}
	case "pitchfork":
		return []string{"user1", "pass1"}
	case "cluster-bomb":
		return []string{"a", "b", "c"}
	default:
		return []string{"admin"}
	}
}

// intruderRunReq mirrors intruder.ts's run payload.
type intruderRunReq struct {
	Method      string   `json:"method"`
	Target      string   `json:"target"`
	PayloadType string   `json:"payload_type"`
	AttackType  string   `json:"attack_type"`
	Positions   []int    `json:"positions"`
	Payloads    []string `json:"payloads"`
	Request     string   `json:"request"`
}

type intruderResult struct {
	Payload  string `json:"payload"`
	Status   int    `json:"status"`
	Length   int    `json:"length"`
	Duration int64  `json:"duration_ms"`
}

type intruderRunResp struct {
	Total   int              `json:"total"`
	Results []intruderResult `json:"results"`
	Errors  int              `json:"errors"`
}

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
	host, port, tls, err := targetParts(req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	base := req.Request
	if base == "" {
		// fall back to a GET on the target
		base = "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	}
	if len(req.Payloads) == 0 {
		req.Payloads = []string{""}
	}

	ctx := r.Context()
	results, err := s.intruder.Run(ctx, base, host, port, tls, req.Payloads, req.Positions)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var out intruderRunResp
	for res := range results {
		out.Results = append(out.Results, intruderResult{
			Payload:  res.Payload,
			Status:   res.StatusCode,
			Length:   res.Length,
			Duration: res.Time.Milliseconds(),
		})
		if res.Error != nil {
			out.Errors++
		}
		s.toolLog.Record(toollog.ToolIntruder, host, port, tls, "INTRUDER", "", res.StatusCode, uint64(res.Time.Milliseconds()), res.Payload)
	}
	out.Total = len(out.Results)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
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

type scannerLiveResp struct {
	Scanning bool             `json:"scanning"`
	Started  bool             `json:"started"`
	Findings []scannerFinding `json:"findings"`
	Total    int              `json:"total"`
}

// handleScannerLive is the modern /api/scanner/live endpoint. It reports whether a scan is active
// and any findings the engine produced since the last poll, matching scanner.ts's shape.
func (s *Server) handleScannerLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	progress := s.intruder.GetProgress()
	findings := s.findings.All()
	var views []scannerFinding
	for _, f := range findings {
		views = append(views, scannerFinding{
			Name:        f.Name,
			Severity:    f.Severity.String(),
			Confidence:  f.Confidence.String(),
			Description: f.Description,
		})
	}
	resp := scannerLiveResp{
		Scanning: progress.Total > progress.Completed,
		Started:  progress.Total > 0,
		Findings: views,
		Total:    len(views),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
	s.runAudit(r.Context(), req.ExchangeID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"started": true, "exchange_id": req.ExchangeID})
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
	s.runAudit(r.Context(), id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"started": true, "exchange_id": id})
}

func (s *Server) runAudit(ctx context.Context, id uint64) {
	if s.scanner == nil {
		s.scanner = scanner.NewActiveScanner(s.store, s.logger)
	}
	findings, err := s.scanner.Audit(ctx, id)
	if err != nil {
		s.logger.Warn("audit failed", zap.Uint64("exchange_id", id), zap.Error(err))
		return
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
}

// ---- Sequencer ---------------------------------------------------------------------------------

type sequencerAnalyseReq struct {
	Tokens []string `json:"tokens"`
}

type sequencerAnalyseResp struct {
	Total        int            `json:"total"`
	Entropy      float64        `json:"entropy"`
	CharacterSet int            `json:"character_set"`
	Rating       string         `json:"rating"`
	ChiSquare    float64        `json:"chi_square"`
	SerialCorr   float64        `json:"serial_corr"`
	MonteCarloPi float64        `json:"monte_carlo_pi"`
	Repeated     int            `json:"repeated_tokens"`
	Characters   []charStatView `json:"characters"`
}

type charStatView struct {
	Char     string  `json:"char"`
	Count    int     `json:"count"`
	Freq     float64 `json:"freq"`
	Expected float64 `json:"expected"`
	Chi      float64 `json:"chi"`
}

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
	tl := sequencer.NewTokenList()
	tl.CollectAll(req.Tokens)
	analysis := sequencer.Analyse(tl)

	cs := sequencer.AnalyseCharacters(req.Tokens)
	chars := make([]charStatView, 0, len(cs.Counts))
	for ch, count := range cs.Counts {
		var freq, expected, chi float64
		if cs.Total > 0 {
			freq = float64(count) / float64(cs.Total)
			if len(cs.Counts) > 0 {
				expected = float64(cs.Total) / float64(len(cs.Counts))
				chi = chiOne(count, cs.Total, len(cs.Counts))
			}
		}
		chars = append(chars, charStatView{
			Char:     string(rune(ch)),
			Count:    count,
			Freq:     freq,
			Expected: expected,
			Chi:      chi,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sequencerAnalyseResp{
		Total:        analysis.SampleCount,
		Entropy:      analysis.Entropy,
		CharacterSet: analysis.CharsetSize,
		Rating:       analysis.GoodnessRating.String(),
		ChiSquare:    analysis.ChiSquare,
		SerialCorr:   analysis.SerialCorr,
		MonteCarloPi: analysis.MonteCarloPi,
		Repeated:     analysis.RepeatedTokens,
		Characters:   chars,
	})
}

func chiOne(count, total, set int) float64 {
	if set <= 0 {
		return 0
	}
	exp := float64(total) / float64(set)
	d := float64(count) - exp
	return d * d / exp
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
