package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// Server represents the web API server.
type Server struct {
	store   *core.TrafficStore
	scope   *core.Scope
	logger  *zap.Logger
	mux     *http.ServeMux
}

// NewServer creates a new web server.
func NewServer(store *core.TrafficStore, scope *core.Scope) *Server {
	s := &Server{
		store:  store,
		scope:  scope,
		logger: zap.NewNop(),
		mux:    http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

// WithLogger sets the logger.
func (s *Server) WithLogger(logger *zap.Logger) *Server {
	s.logger = logger
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scope": "configured",
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
	// This would integrate with a findings store
	findings := []FindingView{}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": findings,
		"total":    len(findings),
	})
}

// RepeaterRequest represents a repeater send request.
type RepeaterRequest struct {
	Request string `json:"request"`
	Host    string `json:"host"`
	Port    uint16 `json:"port"`
	TLS     bool   `json:"tls"`
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

	// Send the request (simplified - would use sender package)
	response := map[string]interface{}{
		"status": "sent",
		"host":   req.Host,
		"port":   req.Port,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// IntruderRequest represents an intruder attack request.
type IntruderRequest struct {
	BaseRequest   string   `json:"base_request"`
	Host          string   `json:"host"`
	Port          uint16   `json:"port"`
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

	// Start attack (simplified - would use intruder package)
	response := map[string]interface{}{
		"status":      "started",
		"attack_id":   1,
		"payload_count": len(req.Payloads),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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

	// Run audit (simplified - would use scanner package)
	response := map[string]interface{}{
		"status": "completed",
		"findings": []interface{}{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	// Serve the web UI (would serve static files in production)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
    <title>burpsy - Security Testing Proxy</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 2rem; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #333; }
        .status { padding: 1rem; background: #f0f0f0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>burpsy</h1>
        <div class="status">
            <p>Proxy and web UI are running.</p>
            <p>API endpoints available at /api/*</p>
        </div>
    </div>
</body>
</html>`)
}
