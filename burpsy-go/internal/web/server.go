package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/sitemap"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// Server represents the web API server.
type Server struct {
	store    *core.TrafficStore
	scope    *core.Scope
	logger   *zap.Logger
	mux      *http.ServeMux
	sender   *sender.Sender
	intruder *intruder.Intruder
	scanner  *scanner.ActiveScanner
	findings *core.FindingStore
	sitemap  *sitemap.SiteMap
	sessionCoordinator *session.Coordinator
	matchReplace *matchreplace.RuleSet
	toolLog     *toollog.ToolLog
}

// NewServer creates a new web server.
func NewServer(store *core.TrafficStore, scope *core.Scope) *Server {
	s := &Server{
		store:    store,
		scope:    scope,
		logger:   zap.NewNop(),
		mux:      http.NewServeMux(),
		sender:   sender.NewSender(sender.DefaultSenderConfig()),
		findings: core.NewFindingStore(),
		sitemap:  sitemap.New(),
		sessionCoordinator: session.NewCoordinator(zap.NewNop()),
		matchReplace:       matchreplace.NewRuleSet(),
		toolLog:            toollog.New(),
	}
	s.setupRoutes()
	return s
}

// WithLogger sets the logger.
func (s *Server) WithLogger(logger *zap.Logger) *Server {
	s.logger = logger
	return s
}

// WithSender sets the HTTP sender used by the repeater.
func (s *Server) WithSender(snd *sender.Sender) *Server {
	s.sender = snd
	return s
}

// WithIntruder sets the intruder engine used by the intruder endpoint.
func (s *Server) WithIntruder(intr *intruder.Intruder) *Server {
	s.intruder = intr
	return s
}

// WithScanner sets the active scanner used by the audit endpoint.
func (s *Server) WithScanner(scan *scanner.ActiveScanner) *Server {
	s.scanner = scan
	return s
}

// WithFindings sets the findings store.
func (s *Server) WithFindings(fs *core.FindingStore) *Server {
	s.findings = fs
	return s
}

// WithSitemap sets the sitemap.
func (s *Server) WithSitemap(sm *sitemap.SiteMap) *Server {
	s.sitemap = sm
	return s
}

// WithSessionCoordinator sets the session coordinator.
func (s *Server) WithSessionCoordinator(sc *session.Coordinator) *Server {
	s.sessionCoordinator = sc
	return s
}

// WithMatchReplace sets the match/replace rule set.
func (s *Server) WithMatchReplace(mr *matchreplace.RuleSet) *Server {
	s.matchReplace = mr
	return s
}

// WithToolLog sets the tool log.
func (s *Server) WithToolLog(tl *toollog.ToolLog) *Server {
	s.toolLog = tl
	return s
}

func (s *Server) setupRoutes() {
	// API routes
	s.mux.HandleFunc("/api/history", s.handleHistory)
	s.mux.HandleFunc("/api/messages/", s.handleMessage)
	s.mux.HandleFunc("/api/exchanges/", s.handleExchange)
	s.mux.HandleFunc("/api/scope", s.handleScope)
	s.mux.HandleFunc("/api/findings", s.handleFindings)
	s.mux.HandleFunc("/api/repeater/send", s.handleRepeaterSend)
	s.mux.HandleFunc("/api/intruder/run", s.handleIntruderRun)
	s.mux.HandleFunc("/api/scanner/audit", s.handleScannerAudit)

	// Session routes
	s.mux.HandleFunc("/api/session/rules", s.handleSessionRules)
	s.mux.HandleFunc("/api/session/rules/", s.handleSessionRuleDetail)
	s.mux.HandleFunc("/api/session/cookies", s.handleSessionCookies)
	
	// Sitemap routes
	s.mux.HandleFunc("/api/sitemap", s.handleSitemap)
	
	// Match/Replace routes
	s.mux.HandleFunc("/api/tools/rules", s.handleMatchReplaceRules)
	
	// Tool log routes
	s.mux.HandleFunc("/api/tools/log", s.handleToolLog)
	
	// Scanner report export
	s.mux.HandleFunc("/api/scanner/report", s.handleScannerReport)
	
	// UI route
	s.mux.HandleFunc("/", s.handleUI)
}

// ListenAndServe starts the web server.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	server := &http.Server{
		Addr:    addr,
		Handler: s.mux,
	}

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	s.logger.Info("web server listening", zap.String("addr", addr))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// HistoryResponse represents the history API response.
type HistoryResponse struct {
	Exchanges []*ExchangeView `json:"exchanges"`
	Total     int             `json:"total"`
}

// ExchangeView is a simplified exchange view for the API.
type ExchangeView struct {
	ID          uint64  `json:"id"`
	Host        string  `json:"host"`
	Port        uint16  `json:"port"`
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	Status      *uint16 `json:"status,omitempty"`
	TLS         bool    `json:"tls"`
	DurationMs  uint64  `json:"duration_ms"`
	ResponseLen int     `json:"response_len"`
	Protocol    string  `json:"protocol"`
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	exchanges := s.store.Exchanges()
	views := make([]*ExchangeView, len(exchanges))

	for i, ex := range exchanges {
		protocol := "HTTP/1.1"
		if ex.Protocol == core.ProtocolHTTP2 {
			protocol = "HTTP/2"
		}
		views[i] = &ExchangeView{
			ID:          ex.ID,
			Host:        ex.Host,
			Port:        ex.Port,
			Method:      ex.Method,
			Path:        ex.Path,
			Status:      ex.Status,
			TLS:         ex.TLS,
			DurationMs:  ex.DurationMs,
			ResponseLen: ex.ResponseLen,
			Protocol:    protocol,
		}
	}

	resp := HistoryResponse{
		Exchanges: views,
		Total:     len(views),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	// Extract message ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/messages/")
	id, err := strconv.ParseUint(path, 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}

	msg, err := s.store.Get(core.MsgId(id))
	if err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":        msg.ID,
		"raw":       string(msg.Raw),
		"direction": msg.Shape.Direction,
		"headers":   getHeaders(msg),
		"body":      string(msg.Body()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getHeaders extracts headers from a StoredMessage as a map.
func getHeaders(msg *core.StoredMessage) map[string]string {
	headers := make(map[string]string)
	for _, h := range msg.Shape.Headers {
		name := string(msg.Slice(h.Name))
		value := string(msg.Slice(h.Value))
		headers[name] = value
	}
	return headers
}

func (s *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/exchanges/")
	id, err := strconv.ParseUint(path, 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
		return
	}

	exchange, err := s.store.GetExchange(id)
	if err != nil {
		http.Error(w, "Exchange not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exchange)
}

// ScopeRequest represents a scope modification request.
type ScopeRequest struct {
	Action  string `json:"action"`  // "include" or "exclude"
	Pattern string `json:"pattern"`
}

func (s *Server) handleScope(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getScope(w, r)
	case http.MethodPost:
		s.updateScope(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getScope(w http.ResponseWriter, r *http.Request) {
	// Return current scope rules
	rules := s.scope.Rules()
	type ruleView struct {
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
	}
	views := make([]ruleView, 0, len(rules))
	for _, rule := range rules {
		kind := "include"
		if rule.Kind == core.ScopeExclude {
			kind = "exclude"
		}
		views = append(views, ruleView{Kind: kind, Pattern: rule.Pattern})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scope": views,
	})
}

func (s *Server) updateScope(w http.ResponseWriter, r *http.Request) {
	var req ScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	rule := core.NewScopeRule(core.ScopeInclude, req.Pattern)
	if req.Action == "exclude" {
		rule = core.NewScopeRule(core.ScopeExclude, req.Pattern)
	}

	s.scope.Add(rule)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// FindingView represents a finding for the API.
type FindingView struct {
	ID          uint64 `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Description string `json:"description"`
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	findings := s.findings.All()
	views := make([]FindingView, 0, len(findings))
	for _, f := range findings {
		views = append(views, FindingView{
			ID:          f.ID,
			Name:        f.Name,
			Severity:    f.Severity.String(),
			Confidence:  f.Confidence.String(),
			Description: f.Description,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": views,
		"total":    len(views),
	})
}

// RepeaterRequest represents a repeater send request.
type RepeaterRequest struct {
	Request   string `json:"request"`
	Host      string `json:"host"`
	Port      uint16 `json:"port"`
	TLS       bool   `json:"tls"`
	TLSVerify bool   `json:"tls_verify"` // default false: skip certificate verification
}

func (s *Server) handleRepeaterSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RepeaterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Host == "" {
		http.Error(w, "Host is required", http.StatusBadRequest)
		return
	}

	// Send the raw request through the sender.
	snd := s.sender
	if req.TLS && !req.TLSVerify {
		// Per-request sender that skips certificate verification; the shared
		// sender keeps its configured policy.
		cfg := sender.DefaultSenderConfig()
		cfg.TLSVerify = false
		snd = sender.NewSender(cfg)
	}
	resp, err := snd.SendRaw(r.Context(), req.Host, req.Port, req.TLS, []byte(req.Request))
	if err != nil {
		http.Error(w, fmt.Sprintf("Send failed: %v", err), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "sent",
		"host":     req.Host,
		"port":     req.Port,
		"response": string(resp),
	})
}

// IntruderRequest represents an intruder attack request.
type IntruderRequest struct {
	BaseRequest   string   `json:"base_request"`
	Host          string   `json:"host"`
	Port          uint16   `json:"port"`
	TLS           bool     `json:"tls"`
	Payloads      []string `json:"payloads"`
	AttackType    string   `json:"attack_type"` // "sniper", "battering ram", "pitchfork", "cluster bomb"
	Positions     []int    `json:"positions"`   // byte offsets for §markers
}

func (s *Server) handleIntruderRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req IntruderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Host == "" || len(req.Payloads) == 0 {
		http.Error(w, "Host and payloads are required", http.StatusBadRequest)
		return
	}

	var intr *intruder.Intruder
	if s.intruder != nil {
		intr = s.intruder
	} else {
		intr = intruder.NewIntruder(s.logger)
	}

	// Parse § marker positions from the base request.
	var positions []int
	for i, r := range req.BaseRequest {
		if r == '§' {
			positions = append(positions, i)
		}
	}

	resultsCh, err := intr.Run(r.Context(), req.BaseRequest, req.Host, req.Port, req.TLS, req.Payloads, positions)
	if err != nil {
		http.Error(w, fmt.Sprintf("Attack failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Collect results (bounded: drain the channel).
	type resultView struct {
		Payload    string `json:"payload"`
		StatusCode int    `json:"status_code"`
		Length     int    `json:"length"`
		Error      string `json:"error,omitempty"`
	}
	var results []resultView
	for res := range resultsCh {
		view := resultView{Payload: res.Payload, StatusCode: res.StatusCode, Length: res.Length}
		if res.Error != nil {
			view.Error = res.Error.Error()
		}
		results = append(results, view)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "completed",
		"payload_count": len(req.Payloads),
		"results":      results,
	})
}

// AuditRequest represents a scanner audit request.
type AuditRequest struct {
	ExchangeID uint64 `json:"exchange_id"`
}

func (s *Server) handleScannerAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	scan := s.scanner
	if scan == nil {
		scan = scanner.NewActiveScanner(s.store, s.logger).WithSender(s.sender)
	}

	// Run audit against the requested exchange.
	findings, err := scan.Audit(r.Context(), req.ExchangeID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Audit failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Persist findings into the finding store so they surface in /api/findings.
	for _, f := range findings {
		s.findings.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
		})
	}

	type findingView struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Confidence  string `json:"confidence"`
		Description string `json:"description"`
		URL         string `json:"url"`
		Evidence    string `json:"evidence"`
	}
	views := make([]findingView, 0, len(findings))
	for _, f := range findings {
		views = append(views, findingView{
			Name:        f.Name,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			Description: f.Description,
			URL:         f.URL,
			Evidence:    f.Evidence,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "completed",
		"findings": views,
	})
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	// Serve the static web UI, embedded at build time.
	uiHandler(w, r)
}

// handleSessionRules handles GET / POST /api/session/rules
func (s *Server) handleSessionRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := s.sessionCoordinator.AllRules()
		json.NewEncoder(w).Encode(rules)
	case http.MethodPost:
		var rule session.SessionRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		id := s.sessionCoordinator.AddRule(&rule)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": id})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSessionRuleDetail handles PUT / DELETE /api/session/rules/{id}
func (s *Server) handleSessionRuleDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/session/rules/")
	if path == "" {
		http.Error(w, "Missing rule ID", http.StatusBadRequest)
		return
	}
	// Parse ID
	var id session.RuleID
	if _, err := fmt.Sscanf(path, "%d", &id); err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		s.sessionCoordinator.RemoveRule(id)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		var rule session.SessionRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		id = s.sessionCoordinator.AddRule(&rule)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": id})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSessionCookies handles GET /api/session/cookies
func (s *Server) handleSessionCookies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// For now return empty - would need host/port/tls params
	json.NewEncoder(w).Encode(map[string]string{})
}

// handleSitemap handles GET /api/sitemap
func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.sitemap.Sync(s.store)
	hosts := s.sitemap.Hosts()
	json.NewEncoder(w).Encode(hosts)
}

// handleMatchReplaceRules handles GET / PUT /api/tools/rules
func (s *Server) handleMatchReplaceRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := s.matchReplace.Rules()
		json.NewEncoder(w).Encode(rules)
	case http.MethodPut:
		var rules []*matchreplace.Rule
		if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		s.matchReplace.SetRules(rules)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleToolLog handles GET /api/tools/log
func (s *Server) handleToolLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	entries := s.toolLog.All()
	json.NewEncoder(w).Encode(entries)
}

// handleScannerReport handles GET /api/scanner/report
func (s *Server) handleScannerReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	format := r.URL.Query().Get("format")
	var fmt scanner.ExportFormat
	switch strings.ToLower(format) {
	case "json":
		fmt = scanner.FormatJSON
	case "sarif":
		fmt = scanner.FormatSARIF
	case "html":
		fmt = scanner.FormatHTML
	default:
		fmt = scanner.FormatJSON
	}
	result := s.scanner.Export(fmt, s.scope)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}
	switch result.Format {
	case scanner.FormatHTML:
		w.Header().Set("Content-Type", "text/html")
	default:
		w.Header().Set("Content-Type", "application/json")
	}
	w.Write(result.Bytes)
}
