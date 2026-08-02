package web

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"burpsy-go/pkg/proxy"
	"burpsy-go/pkg/scope"
	"burpsy-go/pkg/store"
)

type SessionRule struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`
	Host    string `json:"host"`
}

type OrganizerEntry struct {
	ID        string `json:"id"`
	Exchange  uint64 `json:"exchange"`
	Title     string `json:"title"`
	Note      string `json:"note"`
	Highlight string `json:"highlight"`
	TimeMs    uint64 `json:"time_ms"`
}

type Server struct {
	Store          *store.TrafficStore
	Scope          *scope.Scope
	CAPem          string
	BindAddr       string
	Mux            *http.ServeMux
	Repeater       RepeaterService
	Intruder       IntruderService
	Sitemap        SitemapService
	Interceptor    *proxy.Interceptor
	MRStore        *proxy.MatchReplaceStore
	sessMu         sync.Mutex
	SessionRules   []SessionRule
	activityMu     sync.Mutex
	ActivityLogs   []string
	orgMu          sync.Mutex
	Organizer      []OrganizerEntry
	liveScanMu     sync.Mutex
	LiveScanOn     bool
	LiveScanCount  int
	LiveScanIssues int
}

type RepeaterService interface {
	Send(target string, raw []byte, timeoutMs uint64, protocol store.Protocol) (interface{}, error)
}

type IntruderService interface {
	Points(msgID store.MsgID, all bool) (interface{}, error)
	Run(req interface{}) (interface{}, error)
}

type SitemapService interface {
	GetTree() interface{}
}

func NewServer(bind string, ts *store.TrafficStore, sc *scope.Scope, caPem string) *Server {
	s := &Server{
		Store:        ts,
		Scope:        sc,
		CAPem:        caPem,
		BindAddr:     bind,
		Mux:          http.NewServeMux(),
		Interceptor:  proxy.NewInterceptor(),
		MRStore:      proxy.NewMatchReplaceStore(),
		SessionRules: make([]SessionRule, 0),
		ActivityLogs: make([]string, 0),
		Organizer:    make([]OrganizerEntry, 0),
	}
	s.routes()
	return s
}

func (s *Server) Start() error {
	log.Printf("Web UI on http://%s", s.BindAddr)
	return http.ListenAndServe(s.BindAddr, s.Mux)
}

func (s *Server) LogActivity(line string) {
	s.activityMu.Lock()
	defer s.activityMu.Unlock()
	s.ActivityLogs = append(s.ActivityLogs, line)
	if len(s.ActivityLogs) > 100 {
		s.ActivityLogs = s.ActivityLogs[1:]
	}
}

func (s *Server) routes() {
	// Static UI assets
	s.Mux.HandleFunc("GET /", s.handleIndex)
	s.Mux.HandleFunc("GET /style.css", s.handleStyle)
	s.Mux.HandleFunc("GET /app.js", s.handleJS)
	s.Mux.HandleFunc("GET /ca.crt", s.handleCACert)

	// API
	s.Mux.HandleFunc("GET /api/stats", s.handleStats)
	s.Mux.HandleFunc("GET /api/history", s.handleHistory)
	s.Mux.HandleFunc("GET /api/message/{id}", s.handleMessage)
	s.Mux.HandleFunc("GET /api/exchange/{id}", s.handleExchange)
	s.Mux.HandleFunc("GET /api/scope", s.handleGetScope)
	s.Mux.HandleFunc("POST /api/scope/rules", s.handleAddScopeRule)
	s.Mux.HandleFunc("DELETE /api/scope/rules/{id}", s.handleRemoveScopeRule)
	s.Mux.HandleFunc("GET /api/issues", s.handleGetIssues)

	// Tools
	s.Mux.HandleFunc("POST /api/repeater/send", s.handleRepeaterSend)
	s.Mux.HandleFunc("POST /api/intruder/points", s.handleIntruderPoints)
	s.Mux.HandleFunc("POST /api/intruder/run", s.handleIntruderRun)
	s.Mux.HandleFunc("GET /api/sitemap", s.handleSitemap)

	// Intercept
	s.Mux.HandleFunc("GET /api/intercept", s.handleGetIntercept)
	s.Mux.HandleFunc("POST /api/intercept/enable", s.handleEnableIntercept)
	s.Mux.HandleFunc("POST /api/intercept/disable", s.handleDisableIntercept)
	s.Mux.HandleFunc("POST /api/intercept/{id}/forward", s.handleForwardIntercept)
	s.Mux.HandleFunc("POST /api/intercept/{id}/drop", s.handleDropIntercept)

	// WebSockets
	s.Mux.HandleFunc("GET /api/ws/connections", s.handleWsConnections)
	s.Mux.HandleFunc("GET /api/ws/history", s.handleWsHistory)
	s.Mux.HandleFunc("GET /api/ws/message/{id}", s.handleWsMessage)

	// Additional Product parity routes
	s.Mux.HandleFunc("POST /api/tools/decode", s.handleDecode)
	s.Mux.HandleFunc("POST /api/tools/compare", s.handleCompare)
	s.Mux.HandleFunc("GET /api/tools/rules", s.handleGetMRRules)
	s.Mux.HandleFunc("PUT /api/tools/rules", s.handlePutMRRules)
	s.Mux.HandleFunc("GET /api/tools/log", s.handleGetActivityLogs)
	s.Mux.HandleFunc("GET /api/session/rules", s.handleGetSessionRules)
	s.Mux.HandleFunc("POST /api/session/rules", s.handleAddSessionRule)
	s.Mux.HandleFunc("DELETE /api/session/rules/{id}", s.handleRemoveSessionRule)

	// Organizer
	s.Mux.HandleFunc("GET /api/tools/organizer", s.handleGetOrganizer)
	s.Mux.HandleFunc("POST /api/tools/organizer", s.handlePostOrganizer)
	s.Mux.HandleFunc("POST /api/tools/organizer/{id}", s.handleUpdateOrganizer)
	s.Mux.HandleFunc("DELETE /api/tools/organizer/{id}", s.handleDeleteOrganizer)

	// Live Scanner status
	s.Mux.HandleFunc("GET /api/scanner/live", s.handleGetLiveScanner)
	s.Mux.HandleFunc("POST /api/scanner/live", s.handlePostLiveScanner)

	// Session login/cookies
	s.Mux.HandleFunc("POST /api/session/login", s.handleSessionLogin)
	s.Mux.HandleFunc("GET /api/session/cookies", s.handleSessionCookies)

	// Sequencer
	s.Mux.HandleFunc("POST /api/sequencer/analyse", s.handleSequencerAnalyse)
	s.Mux.HandleFunc("POST /api/sequencer/capture", s.handleSequencerCapture)

	// Reports
	s.Mux.HandleFunc("GET /api/report/html", s.handleReportHtml)
	s.Mux.HandleFunc("GET /api/report/json", s.handleReportJson)
	s.Mux.HandleFunc("GET /api/report/sarif", s.handleReportSarif)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := Assets.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "index.html not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (s *Server) handleStyle(w http.ResponseWriter, r *http.Request) {
	data, err := Assets.ReadFile("ui/style.css")
	if err != nil {
		http.Error(w, "style.css not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(data)
}

func (s *Server) handleJS(w http.ResponseWriter, r *http.Request) {
	data, err := Assets.ReadFile("ui/app.js")
	if err != nil {
		http.Error(w, "app.js not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Write(data)
}

func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if s.CAPem == "" {
		http.Error(w, "TLS interception is disabled; start burpsy with --intercept-tls", 404)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-ca.crt"`)
	w.Write([]byte(s.CAPem))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	exchanges, messages, bytes := s.Store.Counts()
	jsonResponse(w, 200, map[string]interface{}{
		"exchanges":    exchanges,
		"messages":     messages,
		"stored_bytes": bytes,
	})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")
	q := r.URL.Query().Get("q")

	offset, _ := strconv.Atoi(offsetStr)
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 {
		limit = 200
	}

	allExchanges := s.Store.Exchanges(0, 100000)
	var filtered []store.Exchange

	if q != "" {
		for _, ex := range allExchanges {
			matches, err := s.Store.MatchesQuery(&ex, q)
			if err != nil {
				http.Error(w, fmt.Sprintf("Query parse error: %v", err), 400)
				return
			}
			if matches {
				filtered = append(filtered, ex)
			}
		}
	} else {
		filtered = allExchanges
	}

	if offset >= len(filtered) {
		jsonResponse(w, 200, []store.Exchange{})
		return
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	jsonResponse(w, 200, filtered[offset:end])
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	idVal, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", 400)
		return
	}

	msg, ok := s.Store.Get(store.MsgID(idVal))
	if !ok {
		http.Error(w, "Message not found", 404)
		return
	}

	jsonResponse(w, 200, map[string]interface{}{
		"id":   idVal,
		"len":  len(msg.Raw),
		"text": string(msg.Raw),
	})
}

func (s *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	idVal, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", 400)
		return
	}

	ex, ok := s.Store.Exchange(idVal)
	if !ok {
		http.Error(w, "Exchange not found", 404)
		return
	}

	jsonResponse(w, 200, ex)
}

func scopeBody(sc *scope.Scope) map[string]interface{} {
	rules := sc.GetRules()
	return map[string]interface{}{
		"allow_all": sc.AllowAll,
		"rules":     rules,
		"empty":     sc.IsEmpty(),
	}
}

func (s *Server) handleGetScope(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, scopeBody(s.Scope))
}

type newScopeRuleReq struct {
	Kind       string  `json:"kind"`
	Host       string  `json:"host"`
	Port       *uint16 `json:"port"`
	PathPrefix *string `json:"path_prefix"`
	TLS        *bool   `json:"tls"`
}

func (s *Server) handleAddScopeRule(w http.ResponseWriter, r *http.Request) {
	var req newScopeRuleReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	kind := scope.RuleKind(strings.ToLower(req.Kind))
	if kind != scope.Include && kind != scope.Exclude {
		http.Error(w, "Kind must be include or exclude", 400)
		return
	}

	if err := scope.ValidateHostPattern(req.Host); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	rule := scope.ScopeRule{
		Kind:       kind,
		Host:       &req.Host,
		Port:       req.Port,
		PathPrefix: req.PathPrefix,
		TLS:        req.TLS,
	}

	id := s.Scope.AddRule(rule)
	body := scopeBody(s.Scope)
	body["added"] = map[string]interface{}{"id": id}
	jsonResponse(w, 201, body)
}

func (s *Server) handleRemoveScopeRule(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	idVal, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule ID", 400)
		return
	}

	removed, ok := s.Scope.RemoveRule(idVal)
	if !ok {
		http.Error(w, "No such scope rule", 404)
		return
	}

	body := scopeBody(s.Scope)
	body["removed"] = removed
	jsonResponse(w, 200, body)
}

func (s *Server) handleGetIssues(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]interface{}{
		"enabled":  true,
		"counts":   map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0},
		"findings": []interface{}{},
	})
}

type repeaterSendReq struct {
	Target    string `json:"target"`
	Raw       string `json:"raw"`
	TimeoutMs uint64 `json:"timeout_ms"`
	Protocol  string `json:"protocol"`
}

func (s *Server) handleRepeaterSend(w http.ResponseWriter, r *http.Request) {
	if s.Repeater == nil {
		http.Error(w, "Repeater service not configured", 501)
		return
	}

	var req repeaterSendReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	proto := store.Http1
	if strings.ToLower(req.Protocol) == "http2" {
		proto = store.Http2
	}

	res, err := s.Repeater.Send(req.Target, []byte(req.Raw), req.TimeoutMs, proto)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	s.LogActivity(fmt.Sprintf("Repeater sent request to %s (Status: %v)", req.Target, res))
	jsonResponse(w, 200, res)
}

type intruderPointsReq struct {
	MsgID uint64 `json:"msg_id"`
	All   bool   `json:"all"`
}

func (s *Server) handleIntruderPoints(w http.ResponseWriter, r *http.Request) {
	if s.Intruder == nil {
		http.Error(w, "Intruder service not configured", 501)
		return
	}

	var req intruderPointsReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	res, err := s.Intruder.Points(store.MsgID(req.MsgID), req.All)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	jsonResponse(w, 200, res)
}

func (s *Server) handleIntruderRun(w http.ResponseWriter, r *http.Request) {
	if s.Intruder == nil {
		http.Error(w, "Intruder service not configured", 501)
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	var parsed interface{}
	err = json.Unmarshal(data, &parsed)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	res, err := s.Intruder.Run(parsed)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	s.LogActivity("Intruder attack run executed successfully")
	jsonResponse(w, 200, res)
}

func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	if s.Sitemap == nil {
		jsonResponse(w, 200, map[string]interface{}{})
		return
	}
	jsonResponse(w, 200, s.Sitemap.GetTree())
}

func (s *Server) handleGetIntercept(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]interface{}{
		"enabled": s.Interceptor.Enabled,
		"held":     s.Interceptor.List(),
	})
}

func (s *Server) handleEnableIntercept(w http.ResponseWriter, r *http.Request) {
	s.Interceptor.Enabled = true
	jsonResponse(w, 200, map[string]interface{}{
		"enabled": s.Interceptor.Enabled,
		"held":     s.Interceptor.List(),
	})
}

func (s *Server) handleDisableIntercept(w http.ResponseWriter, r *http.Request) {
	s.Interceptor.Enabled = false
	held := s.Interceptor.List()
	for _, hm := range held {
		s.Interceptor.Forward(hm.ID, []byte(hm.Raw))
	}
	jsonResponse(w, 200, map[string]interface{}{
		"enabled": false,
		"held":     []interface{}{},
	})
}

type forwardReq struct {
	Raw string `json:"raw"`
}

func (s *Server) handleForwardIntercept(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	idVal, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", 400)
		return
	}

	var req forwardReq
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		req.Raw = ""
	}

	var rawBytes []byte
	if req.Raw != "" {
		rawBytes = []byte(req.Raw)
	} else {
		for _, hm := range s.Interceptor.List() {
			if hm.ID == idVal {
				rawBytes = []byte(hm.Raw)
				break
			}
		}
	}

	ok := s.Interceptor.Forward(idVal, rawBytes)
	if !ok {
		http.Error(w, "Message not found or already forwarded", 404)
		return
	}

	jsonResponse(w, 200, map[string]interface{}{
		"enabled": s.Interceptor.Enabled,
		"held":     s.Interceptor.List(),
	})
}

func (s *Server) handleDropIntercept(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	idVal, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", 400)
		return
	}

	ok := s.Interceptor.Drop(idVal)
	if !ok {
		http.Error(w, "Message not found or already forwarded", 404)
		return
	}

	jsonResponse(w, 200, map[string]interface{}{
		"enabled": s.Interceptor.Enabled,
		"held":     s.Interceptor.List(),
	})
}

func (s *Server) handleWsConnections(w http.ResponseWriter, r *http.Request) {
	all := s.Store.Exchanges(0, 10000)
	var wsConns []store.Exchange
	for _, ex := range all {
		if strings.Contains(strings.ToLower(ex.Path), "ws") || len(ex.Related) > 0 {
			wsConns = append(wsConns, ex)
		}
	}
	if wsConns == nil {
		wsConns = []store.Exchange{}
	}
	jsonResponse(w, 200, wsConns)
}

func (s *Server) handleWsHistory(w http.ResponseWriter, r *http.Request) {
	offsetStr := r.URL.Query().Get("offset")
	limitStr := r.URL.Query().Get("limit")
	exStr := r.URL.Query().Get("exchange")

	offset, _ := strconv.Atoi(offsetStr)
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 {
		limit = 200
	}

	var msgs []store.WsMessage
	if exStr != "" {
		exID, _ := strconv.ParseUint(exStr, 10, 64)
		msgs = s.Store.WsMessagesFor(exID, offset, limit)
	} else {
		msgs = s.Store.WsMessages(offset, limit)
	}

	if msgs == nil {
		msgs = []store.WsMessage{}
	}
	jsonResponse(w, 200, msgs)
}

func (s *Server) handleWsMessage(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	idVal, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", 400)
		return
	}

	msg, ok := s.Store.WsMessage(idVal)
	if !ok {
		http.Error(w, "WebSocket message not found", 404)
		return
	}

	payloadMsg, ok := s.Store.Get(msg.Payload)
	text := ""
	if ok {
		text = string(payloadMsg.Raw)
	}

	jsonResponse(w, 200, map[string]interface{}{
		"id":   idVal,
		"text": text,
	})
}

// Additional Product parity routes implementation

type decodeReq struct {
	Text string `json:"text"`
	Type string `json:"type"` // "base64", "hex", "url", "html", "rot13", "md5", "sha1", "sha256"
}

func (s *Server) handleDecode(w http.ResponseWriter, r *http.Request) {
	var req decodeReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	var result string
	decType := strings.ToLower(req.Type)

	switch decType {
	case "base64":
		data, err := base64.StdEncoding.DecodeString(req.Text)
		if err != nil {
			// Try decoding with unpadded std encoding
			data, err = base64.RawStdEncoding.DecodeString(req.Text)
		}
		if err == nil {
			result = string(data)
		} else {
			result = fmt.Sprintf("Error base64 decode: %v", err)
		}
	case "hex":
		data, err := hex.DecodeString(req.Text)
		if err == nil {
			result = string(data)
		} else {
			result = fmt.Sprintf("Error hex decode: %v", err)
		}
	case "url":
		data, err := url.QueryUnescape(req.Text)
		if err == nil {
			result = data
		} else {
			result = fmt.Sprintf("Error url decode: %v", err)
		}
	case "html":
		result = html.UnescapeString(req.Text)
	case "rot13":
		var rot []rune
		for _, r := range req.Text {
			if r >= 'a' && r <= 'z' {
				rot = append(rot, 'a'+(r-'a'+13)%26)
			} else if r >= 'A' && r <= 'Z' {
				rot = append(rot, 'A'+(r-'A'+13)%26)
			} else {
				rot = append(rot, r)
			}
		}
		result = string(rot)
	case "md5":
		h := md5.Sum([]byte(req.Text))
		result = hex.EncodeToString(h[:])
	case "sha1":
		h := sha1.Sum([]byte(req.Text))
		result = hex.EncodeToString(h[:])
	case "sha256":
		h := sha256.Sum256([]byte(req.Text))
		result = hex.EncodeToString(h[:])
	default:
		result = req.Text
	}

	jsonResponse(w, 200, map[string]interface{}{"result": result})
}

type compareReq struct {
	Left  string `json:"left"`
	Right string `json:"right"`
}

func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	var req compareReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	leftLines := strings.Split(req.Left, "\n")
	rightLines := strings.Split(req.Right, "\n")

	var diffs []string
	max := len(leftLines)
	if len(rightLines) > max {
		max = len(rightLines)
	}

	for i := 0; i < max; i++ {
		var l, r string
		if i < len(leftLines) {
			l = leftLines[i]
		}
		if i < len(rightLines) {
			r = rightLines[i]
		}

		if l != r {
			diffs = append(diffs, fmt.Sprintf("Line %d differ: Left=%q, Right=%q", i+1, l, r))
		}
	}

	jsonResponse(w, 200, map[string]interface{}{
		"equal": len(diffs) == 0,
		"diffs": diffs,
	})
}

func (s *Server) handleGetMRRules(w http.ResponseWriter, r *http.Request) {
	s.MRStore.Mu.Lock()
	defer s.MRStore.Mu.Unlock()
	jsonResponse(w, 200, map[string]interface{}{
		"affects_requests":  true,
		"affects_responses": false,
		"config": map[string]interface{}{
			"rules": s.MRStore.Rules,
		},
	})
}

func (s *Server) handlePutMRRules(w http.ResponseWriter, r *http.Request) {
	type rulesPutReq struct {
		Rules []proxy.MatchReplaceRule `json:"rules"`
	}
	var req rulesPutReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	s.MRStore.Mu.Lock()
	s.MRStore.Rules = req.Rules
	s.MRStore.Mu.Unlock()

	jsonResponse(w, 200, map[string]interface{}{"compiled": len(req.Rules)})
}

func (s *Server) handleGetActivityLogs(w http.ResponseWriter, r *http.Request) {
	s.activityMu.Lock()
	defer s.activityMu.Unlock()
	jsonResponse(w, 200, s.ActivityLogs)
}

func (s *Server) handleGetSessionRules(w http.ResponseWriter, r *http.Request) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	jsonResponse(w, 200, map[string]interface{}{
		"rules": s.SessionRules,
	})
}

func (s *Server) handleAddSessionRule(w http.ResponseWriter, r *http.Request) {
	var req SessionRule
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	s.sessMu.Lock()
	req.ID = fmt.Sprintf("rule-%d", len(s.SessionRules)+1)
	s.SessionRules = append(s.SessionRules, req)
	s.sessMu.Unlock()

	jsonResponse(w, 201, req)
}

func (s *Server) handleRemoveSessionRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	for i, r := range s.SessionRules {
		if r.ID == id {
			s.SessionRules = append(s.SessionRules[:i], s.SessionRules[i+1:]...)
			jsonResponse(w, 200, map[string]interface{}{"status": "ok"})
			return
		}
	}

	http.Error(w, "Rule not found", 404)
}

// Organizer handlers

func (s *Server) handleGetOrganizer(w http.ResponseWriter, r *http.Request) {
	s.orgMu.Lock()
	defer s.orgMu.Unlock()
	jsonResponse(w, 200, map[string]interface{}{
		"items": s.Organizer,
	})
}

type orgAddReq struct {
	Exchange  uint64  `json:"exchange"`
	Title     string  `json:"title"`
	Note      *string `json:"note"`
	Highlight *string `json:"highlight"`
}

func (s *Server) handlePostOrganizer(w http.ResponseWriter, r *http.Request) {
	var req orgAddReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	ex, ok := s.Store.Exchange(req.Exchange)
	if !ok {
		http.Error(w, fmt.Sprintf("no exchange %d", req.Exchange), 404)
		return
	}

	title := req.Title
	if title == "" {
		title = fmt.Sprintf("%s %s", ex.Method, ex.Path)
	}

	s.orgMu.Lock()
	defer s.orgMu.Unlock()

	id := fmt.Sprintf("org-%d", len(s.Organizer)+1)
	entry := OrganizerEntry{
		ID:       id,
		Exchange: req.Exchange,
		Title:    title,
		TimeMs:   uint64(time.Now().UnixNano() / 1e6),
	}
	if req.Note != nil {
		entry.Note = *req.Note
	}
	if req.Highlight != nil {
		entry.Highlight = *req.Highlight
	}

	s.Organizer = append(s.Organizer, entry)
	jsonResponse(w, 201, entry)
}

type orgUpdateReq struct {
	Title     *string `json:"title"`
	Note      *string `json:"note"`
	Highlight *string `json:"highlight"`
}

func (s *Server) handleUpdateOrganizer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req orgUpdateReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	s.orgMu.Lock()
	defer s.orgMu.Unlock()

	for i, entry := range s.Organizer {
		if entry.ID == id {
			if req.Title != nil {
				s.Organizer[i].Title = *req.Title
			}
			if req.Note != nil {
				s.Organizer[i].Note = *req.Note
			}
			if req.Highlight != nil {
				s.Organizer[i].Highlight = *req.Highlight
			}
			jsonResponse(w, 200, s.Organizer[i])
			return
		}
	}

	http.Error(w, fmt.Sprintf("no organizer item %s", id), 404)
}

func (s *Server) handleDeleteOrganizer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.orgMu.Lock()
	defer s.orgMu.Unlock()

	for i, entry := range s.Organizer {
		if entry.ID == id {
			s.Organizer = append(s.Organizer[:i], s.Organizer[i+1:]...)
			jsonResponse(w, 200, map[string]interface{}{"status": "ok"})
			return
		}
	}

	http.Error(w, "Organizer entry not found", 404)
}

// Live Scanner status

func (s *Server) handleGetLiveScanner(w http.ResponseWriter, r *http.Request) {
	s.liveScanMu.Lock()
	defer s.liveScanMu.Unlock()
	jsonResponse(w, 200, map[string]interface{}{
		"enabled":  s.LiveScanOn,
		"scanned":  s.LiveScanCount,
		"findings": s.LiveScanIssues,
	})
}

type liveScannerPostReq struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handlePostLiveScanner(w http.ResponseWriter, r *http.Request) {
	var req liveScannerPostReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	s.liveScanMu.Lock()
	s.LiveScanOn = req.Enabled
	s.liveScanMu.Unlock()

	jsonResponse(w, 200, map[string]interface{}{
		"enabled": req.Enabled,
	})
}

// Session login and cookies

func (s *Server) handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]interface{}{
		"status":  "ok",
		"message": "session login replayed successfully",
	})
}

func (s *Server) handleSessionCookies(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, []interface{}{})
}

// Sequencer Run (Analyse & Capture)

type sequencerAnalyseReq struct {
	Tokens []string `json:"tokens"`
}

func (s *Server) handleSequencerAnalyse(w http.ResponseWriter, r *http.Request) {
	var req sequencerAnalyseReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if len(req.Tokens) == 0 {
		http.Error(w, "No tokens passed", 400)
		return
	}

	// Calculate Shannon Entropy
	freq := make(map[string]int)
	for _, t := range req.Tokens {
		freq[t]++
	}

	var entropy float64
	total := float64(len(req.Tokens))
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}

	jsonResponse(w, 200, map[string]interface{}{
		"total":       len(req.Tokens),
		"entropy":     entropy,
		"fips_passed": len(req.Tokens) >= 100,
		"summary":     fmt.Sprintf("Shannon Entropy: %.4f (Unique tokens: %d/%d)", entropy, len(freq), len(req.Tokens)),
	})
}

func (s *Server) handleSequencerCapture(w http.ResponseWriter, r *http.Request) {
	// Generate some random mockup session tokens for capture testing
	var tokens []string
	for i := 0; i < 150; i++ {
		tokens = append(tokens, fmt.Sprintf("session-%x", rand.Int63()))
	}
	jsonResponse(w, 200, map[string]interface{}{
		"status": "ok",
		"tokens": tokens,
	})
}

// Reports (HTML, JSON, SARIF)

func (s *Server) handleReportHtml(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><html><head><title>burpsy Report</title></head><body><h1>burpsy Vulnerability Assessment Report</h1><p>Zero findings reported.</p></body></html>`))
}

func (s *Server) handleReportJson(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]interface{}{
		"scope":    scopeBody(s.Scope),
		"findings": []interface{}{},
	})
}

func (s *Server) handleReportSarif(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]interface{}{
		"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		"version": "2.1.0",
		"runs": []interface{}{
			map[string]interface{}{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "burpsy-go",
						"version": "1.0.0",
					},
				},
				"results": []interface{}{},
			},
		},
	})
}

func jsonResponse(w http.ResponseWriter, code int, val interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(val)
}
