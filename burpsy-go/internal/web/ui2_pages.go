package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- shared ui2 page rendering helpers -------------------------------------------------------

// ui2RenderPage renders the shell with the given view and fragment body.
func ui2RenderPage(w http.ResponseWriter, title, view string, body templateHTML) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui2Templates.ExecuteTemplate(w, "layout.html", ui2Page{Title: title, View: view, Body: body}); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ui2Fragment answers an htmx request with just the fragment, or renders the full shell.
func ui2Fragment(w http.ResponseWriter, r *http.Request, title, view string, body templateHTML) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
		return
	}
	ui2RenderPage(w, title, view, body)
}

// ui2Exec renders one named template into a string.
func ui2Exec(name string, model any) templateHTML {
	var sb strings.Builder
	_ = ui2Templates.ExecuteTemplate(&sb, name, model)
	return templateHTML(sb.String())
}

// ---- Dashboard -------------------------------------------------------------------------------

// handleUI2Dashboard serves GET /ui2/dashboard: summaries, running tasks, recent activity
// and events, and the suite-wide pause state — one page, no client computation.
func (s *Server) handleUI2Dashboard(w http.ResponseWriter, r *http.Request) {
	body := s.renderUI2Dashboard()
	ui2Fragment(w, r, "burpsy /ui2/ — Dashboard", "dashboard", body)
}

func (s *Server) renderUI2Dashboard() templateHTML {
	messages, exchanges := s.store.Count()
	resp := dashboardResp{
		Summaries:       s.dashboardSummaries(),
		Tasks:           s.tasks.Snapshot(),
		TasksRunning:    s.tasks.Running(),
		TasksDropped:    s.tasks.Dropped(),
		Activity:        nil,
		ActivityShown:   0,
		ActivityTotal:   0,
		ActivityDropped: s.toolLog.Dropped(),
		Events:          s.events.Recent(dashboardActivityLimit),
		EventsShown:     0,
		EventsTotal:     s.events.Count(),
		EventsDropped:   s.events.Dropped(),
		Exchanges:       exchanges,
		Messages:        messages,
		StoredBytes:     s.store.Bytes(),
		Sources:         s.sourceCounts(),
		Paused:          s.tasks.Paused(),
	}
	entries := s.toolLog.All()
	for i := len(entries) - 1; i >= 0 && len(resp.Activity) < dashboardActivityLimit; i-- {
		resp.Activity = append(resp.Activity, toolLogEntryView(entries[i]))
	}
	resp.ActivityShown = len(resp.Activity)
	resp.ActivityTotal = len(entries)
	resp.EventsShown = len(resp.Events)
	return ui2Exec("dashboard.html", resp)
}

// ---- Site map --------------------------------------------------------------------------------

// handleUI2Sitemap serves GET /ui2/sitemap: the host → path tree with per-node counts,
// in-scope dimming and issue markers, rendered flat (depth 2) with links into history.
func (s *Server) handleUI2Sitemap(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		_, _ = w.Write([]byte(s.renderUI2Sitemap(q.Get("host"), q.Get("path"))))
		return
	}
	ui2RenderPage(w, "burpsy /ui2/ — Site map", "sitemap", s.renderUI2Sitemap(q.Get("host"), q.Get("path")))
}

func (s *Server) renderUI2Sitemap(hostFilter, pathFilter string) templateHTML {
	// Reuse the JSON handler's own view builder so the two surfaces cannot drift.
	rec := newRecorder()
	req := newReq(http.MethodGet, "/api/sitemap?host="+hostFilter+"&path="+pathFilter)
	s.sitemapGet(rec, req)
	var tree sitemapTreeResp
	if err := ui2DecodeJSON(rec.Body.Bytes(), &tree); err != nil {
		return ui2Exec("error.html", ui2Error{Message: "site map unavailable: " + err.Error()})
	}
	flat := flattenSitemap(tree.Tree, 0, nil)
	return ui2Exec("sitemap.html", ui2SitemapModel{Tree: tree, Flat: flat})
}

type ui2SitemapNode struct {
	Depth         int
	Segment       string
	Path          string
	Key           string
	Host          string
	Exchanges     int
	Subtree       int
	Methods       string
	Statuses      string
	Mimes         string
	Params        string
	Issues        int
	SubtreeIssues int
	Worst         string
	InScope       bool
	Requested     bool
	Children      int
	Recent        []uint64
}

type ui2SitemapModel struct {
	Tree sitemapTreeResp
	Flat []ui2SitemapNode
}

func flattenSitemap(nodes []sitemapNodeView, depth int, out *[]ui2SitemapNode) []ui2SitemapNode {
	if out == nil {
		out = &[]ui2SitemapNode{}
	}
	for _, n := range nodes {
		*out = append(*out, ui2SitemapNode{
			Depth: depth, Segment: n.Segment, Path: n.Path, Key: n.Key, Host: n.HostName,
			Exchanges: n.Exchanges, Subtree: n.SubtreeCount, Methods: strings.Join(n.Methods, ","),
			Statuses: intSliceString(n.Statuses), Mimes: strings.Join(n.Mimes, ","), Params: strings.Join(n.Params, ","),
			Issues: n.Issues, SubtreeIssues: n.SubtreeIssues, Worst: n.WorstSeverity,
			InScope: n.InScope, Requested: n.Requested, Children: n.ChildCount,
		})
		for i := range n.Children {
			flattenSitemap([]sitemapNodeView{n.Children[i]}, depth+1, out)
		}
	}
	return *out
}

func intSliceString(vs []int) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

// ---- Scope -----------------------------------------------------------------------------------

// handleUI2Scope serves GET /ui2/scope: the include/exclude rules, drop switches and libraries.
func (s *Server) handleUI2Scope(w http.ResponseWriter, r *http.Request) {
	rec := newRecorder()
	s.getScope(rec, newReq(http.MethodGet, "/api/scope"))
	var view map[string]any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	ui2Fragment(w, r, "burpsy /ui2/ — Scope", "scope", ui2Exec("scope.html", view))
}

// ---- Intercept -------------------------------------------------------------------------------

// handleUI2Intercept serves GET /ui2/intercept: the interception state and the held queue.
func (s *Server) handleUI2Intercept(w http.ResponseWriter, r *http.Request) {
	rec := newRecorder()
	s.handleIntercept(rec, newReq(http.MethodGet, "/api/intercept"))
	var view map[string]any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	ui2Fragment(w, r, "burpsy /ui2/ — Intercept", "intercept", ui2Exec("intercept.html", view))
}

// handleUI2InterceptAction serves POST /ui2/intercept/{action}: enable/disable, forward-all,
// drop-all — local state changes that then refresh the queue fragment.
func (s *Server) handleUI2InterceptAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	var target string
	switch action {
	case "enable", "disable":
		target = "/api/intercept/enable"
	case "forward-all":
		target = "/api/intercept/forward-all"
	case "drop-all":
		target = "/api/intercept/drop-all"
	default:
		http.Error(w, "unknown intercept action", http.StatusBadRequest)
		return
	}
	body := `{"enabled":true}`
	if action == "disable" {
		body = `{"enabled":false}`
	}
	req := newReq(http.MethodPost, target)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(body))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code >= 400 {
		http.Error(w, rec.Body.String(), rec.Code)
		return
	}
	// Refresh the queue fragment.
	rec2 := newRecorder()
	s.handleIntercept(rec2, newReq(http.MethodGet, "/api/intercept"))
	var view map[string]any
	_ = ui2DecodeJSON(rec2.Body.Bytes(), &view)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("intercept.html", view)))
}

// ---- Logger ----------------------------------------------------------------------------------

// handleUI2Logger serves GET /ui2/logger: requests burpsy itself sent (the tool log),
// server-paged like history.
func (s *Server) handleUI2Logger(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	offset := 0
	if n, err := strconv.Atoi(q.Get("offset")); err == nil && n > 0 {
		offset = n
	}
	search := strings.TrimSpace(q.Get("search"))
	rec := newRecorder()
	req := newReq(http.MethodGet, fmt.Sprintf("/api/tools/log?limit=%d", 100000))
	s.toolLogGet(rec, req)
	var resp toolLogResp
	_ = ui2DecodeJSON(rec.Body.Bytes(), &resp)
	// Newest first already; apply search + page server-side.
	entries := resp.Entries
	if search != "" {
		needle := strings.ToLower(search)
		filtered := entries[:0]
		for _, e := range entries {
			hay := strings.ToLower(e.Tool + " " + e.Method + " " + e.Host + e.Path + " " + ui2StatusString2(e.Status))
			if strings.Contains(hay, needle) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}
	total := len(entries)
	end := offset + limit
	if end > total {
		end = total
	}
	page := entries
	if offset < total {
		page = entries[offset:end]
	} else {
		page = nil
	}
	next := -1
	if end < total {
		next = end
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Logger", "logger", ui2Exec("logger.html", ui2LoggerModel{
		Entries: page, Total: resp.Total, Matched: total, Offset: offset, Limit: limit,
		NextOffset: next, Search: search, HasMore: next >= 0, Counts: resp.Counts, Capturing: resp.Capturing,
	}))
}

type ui2LoggerModel struct {
	Entries    []toolLogEntry
	Total      int
	Matched    int
	Offset     int
	Limit      int
	NextOffset int
	Search     string
	HasMore    bool
	Counts     map[string]int
	Capturing  map[string]bool
}

// ---- WS history ------------------------------------------------------------------------------

// handleUI2WS serves GET /ui2/ws: connections and frames.
func (s *Server) handleUI2WS(w http.ResponseWriter, r *http.Request) {
	connsRec := newRecorder()
	s.handleWSConnections(connsRec, newReq(http.MethodGet, "/api/ws/connections"))
	var conns []any
	_ = ui2DecodeJSON(connsRec.Body.Bytes(), &conns)
	histRec := newRecorder()
	s.handleWSHistory(histRec, newReq(http.MethodGet, "/api/ws/history?limit=200"))
	var hist map[string]any
	_ = ui2DecodeJSON(histRec.Body.Bytes(), &hist)
	ui2Fragment(w, r, "burpsy /ui2/ — WebSockets", "ws", ui2Exec("ws.html", map[string]any{"connections": conns, "history": hist}))
}

// ---- Proxy settings: listeners + options -----------------------------------------------------

// handleUI2Proxy serves GET /ui2/proxy: listeners, response-modification options with counters,
// and match & replace rules.
func (s *Server) handleUI2Proxy(w http.ResponseWriter, r *http.Request) {
	model := map[string]any{}
	get := func(path string, target any) {
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
		_ = ui2DecodeJSON(rec.Body.Bytes(), target)
	}
	var listeners any
	get("/api/proxy/listener", &listeners)
	model["listeners"] = listeners
	var opts any
	get("/api/proxy/options", &opts)
	model["options"] = opts
	var mr any
	get("/api/tools/rules", &mr)
	model["rules"] = mr
	var passthrough any
	get("/api/proxy/passthrough", &passthrough)
	model["passthrough"] = passthrough
	ui2Fragment(w, r, "burpsy /ui2/ — Proxy settings", "proxy", ui2Exec("proxy.html", model))
}

// ---- Extensions ------------------------------------------------------------------------------

// handleUI2Extensions serves GET /ui2/extensions: the plugin list, state breakdown and allowlist.
func (s *Server) handleUI2Extensions(w http.ResponseWriter, r *http.Request) {
	rec := newRecorder()
	s.handleExtensions(rec, newReq(http.MethodGet, "/api/extensions"))
	var view any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	apisRec := newRecorder()
	s.handleExtensionAPIs(apisRec, newReq(http.MethodGet, "/api/extensions/apis"))
	var apis any
	_ = ui2DecodeJSON(apisRec.Body.Bytes(), &apis)
	ui2Fragment(w, r, "burpsy /ui2/ — Extensions", "extensions", ui2Exec("extensions.html", map[string]any{"extensions": view, "apis": apis}))
}

// ---- Scanner: launch configs, checks, coverage, live ----------------------------------------

// handleUI2Scanner serves GET /ui2/scanner: saved configurations, the corpus inventory and
// the live-audit state — the read side of the Scanner tool.
func (s *Server) handleUI2Scanner(w http.ResponseWriter, r *http.Request) {
	model := map[string]any{}
	get := func(path string, target any) {
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
		_ = ui2DecodeJSON(rec.Body.Bytes(), target)
	}
	var configs, issueTypes, checks, coverage, live, auditItems, config any
	get("/api/scanner/configs", &configs)
	get("/api/scanner/issue-types", &issueTypes)
	get("/api/scanner/checks", &checks)
	get("/api/scanner/coverage", &coverage)
	get("/api/scanner/live", &live)
	get("/api/scanner/audit-items", &auditItems)
	get("/api/scanner/config", &config)
	model["configs"] = configs
	model["issue_types"] = issueTypes
	model["checks"] = checks
	model["coverage"] = coverage
	model["live"] = live
	model["audit_items"] = auditItems
	model["config"] = config
	ui2Fragment(w, r, "burpsy /ui2/ — Scanner", "scanner", ui2Exec("scanner.html", model))
}

// ---- Advisories (issue definitions) ----------------------------------------------------------

// handleUI2Advisories serves GET /ui2/advisories: the issue-definition catalogue.
func (s *Server) handleUI2Advisories(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/advisories?q="+q.Get("q")+"&severity="+q.Get("severity")))
	var view any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	ui2Fragment(w, r, "burpsy /ui2/ — Issue definitions", "advisories", ui2Exec("advisories.html", view))
}

// ---- Organizer -------------------------------------------------------------------------------

// handleUI2Organizer serves GET /ui2/organizer: saved items and collections.
func (s *Server) handleUI2Organizer(w http.ResponseWriter, r *http.Request) {
	rec := newRecorder()
	s.handleOrganizer(rec, newReq(http.MethodGet, "/api/tools/organizer"))
	var view any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	ui2Fragment(w, r, "burpsy /ui2/ — Organizer", "organizer", ui2Exec("organizer.html", view))
}

// ---- Session ---------------------------------------------------------------------------------

// handleUI2Session serves GET /ui2/session: rules, cookie jar, trace, prompts.
func (s *Server) handleUI2Session(w http.ResponseWriter, r *http.Request) {
	model := map[string]any{}
	get := func(path string, target any) {
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
		_ = ui2DecodeJSON(rec.Body.Bytes(), target)
	}
	var rules, cookies, trace, prompts any
	get("/api/session/rules", &rules)
	get("/api/session/cookies", &cookies)
	get("/api/session/trace", &trace)
	get("/api/session/prompts", &prompts)
	model["rules"], model["cookies"], model["trace"], model["prompts"] = rules, cookies, trace, prompts
	ui2Fragment(w, r, "burpsy /ui2/ — Session", "session", ui2Exec("session.html", model))
}

// ---- Tools: decoder / comparer ---------------------------------------------------------------

// handleUI2Decoder serves GET /ui2/decoder (form) and POST /ui2/decoder/run (the transform),
// posting to /api/tools/decode|encode|hash server-side and rendering the result.
func (s *Server) handleUI2Decoder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleUI2DecoderRun(w, r)
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Decoder", "decoder", ui2Exec("decoder.html", map[string]any{"result": nil}))
}

func (s *Server) handleUI2DecoderRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	op := r.PostFormValue("op")
	input := r.PostFormValue("input")
	arg := r.PostFormValue("arg")
	var path string
	body := map[string]string{"input": input}
	switch op {
	case "decode":
		path = "/api/tools/decode"
		body["encoding"] = arg // toolsDecodeReq reads "encoding"; "op" would fall into the guesser
	case "encode":
		path = "/api/tools/encode"
		body["encoding"] = arg // toolsEncodeReq reads "encoding"
	case "hash":
		path = "/api/tools/hash"
		body["algorithm"] = arg
	default:
		http.Error(w, "unknown decoder op", http.StatusBadRequest)
		return
	}
	payload, _ := ui2Marshal(body)
	result, errText := s.ui2APIResult(http.MethodPost, path, body)
	_ = payload
	ui2Fragment(w, r, "burpsy /ui2/ — Decoder", "decoder", ui2Exec("decoder.html", map[string]any{"result": result, "error": errText, "op": op, "arg": arg, "input": input}))
}

// handleUI2Comparer serves GET /ui2/comparer (form) and POST /ui2/comparer/run.
func (s *Server) handleUI2Comparer(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleUI2ComparerRun(w, r)
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Comparer", "comparer", ui2Exec("comparer.html", map[string]any{"result": nil}))
}

func (s *Server) handleUI2ComparerRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	a := r.PostFormValue("a")
	b := r.PostFormValue("b")
	result, errText := s.ui2APIResult(http.MethodPost, "/api/tools/compare", map[string]string{"a": a, "b": b})
	ui2Fragment(w, r, "burpsy /ui2/ — Comparer", "comparer", ui2Exec("comparer.html", map[string]any{"result": result, "error": errText, "a": a, "b": b}))
}

// ---- Repeater --------------------------------------------------------------------------------

// handleUI2Repeater serves GET /ui2/repeater: the editor with the last captured request as
// the draft, and POST /ui2/repeater/send forwards through /api/repeater/send.
func (s *Server) handleUI2Repeater(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleUI2RepeaterSend(w, r)
		return
	}
	draft := ""
	if exs := s.store.Exchanges(); len(exs) > 0 {
		ex := exs[len(exs)-1]
		if ex.Request != nil {
			if msg, err := s.store.Get(*ex.Request); err == nil {
				draft = string(msg.Raw())
			}
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", ui2Exec("repeater.html", map[string]any{"draft": draft, "result": nil}))
}

func (s *Server) handleUI2RepeaterSend(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	raw := r.PostFormValue("raw")
	target := r.PostFormValue("target")
	if target == "" {
		// /api/repeater/send requires a target; the ui2 form's field is optional, so derive it
		// from the request's own Host header (absolute-form request lines also work).
		target = ui2HostFromRequest(raw)
	}
	if target == "" {
		ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", ui2Exec("repeater.html", map[string]any{
			"draft": raw, "result": nil,
			"error": "no target: the request carries no Host header and no target was given",
		}))
		return
	}
	result, errText := s.ui2APIResult(http.MethodPost, "/api/repeater/send", map[string]string{"target": target, "request": raw})
	ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", ui2Exec("repeater.html", map[string]any{
		"draft": raw, "result": result, "error": errText, "target": target,
	}))
}

// ui2HostFromRequest extracts the target authority from a raw request: an absolute-form
// request line wins, else the Host header.
func ui2HostFromRequest(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) >= 2 && strings.Contains(fields[1], "://") {
		rest := fields[1][strings.Index(fields[1], "://")+3:]
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	for _, line := range strings.Split(raw, "\r\n") {
		if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

// ui2APIResult calls one internal JSON API through the mux and returns either the decoded
// body or a plain-text error string. Returning a string (not map[string]any{"error":…}) is
// what keeps templates from printing Go map syntax like "map[error:empty target]".
func (s *Server) ui2APIResult(method, path string, payload any) (any, string) {
	var body ioReadCloser
	if payload != nil {
		b, _ := ui2Marshal(payload)
		body = ioNopCloser(strings.NewReader(string(b)))
	}
	req := newReq(method, path)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = body
	}
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return nil, strings.TrimSpace(rec.Body.String())
	}
	var result any
	if err := ui2DecodeJSON(rec.Body.Bytes(), &result); err != nil {
		return nil, "unreadable response: " + err.Error()
	}
	return result, ""
}

// ---- Settings overview -----------------------------------------------------------------------

// handleUI2Settings serves GET /ui2/settings: project, stats, CA, protocols, pools,
// schedules, skills, wordlists — the read-only diagnostics surface.
func (s *Server) handleUI2Settings(w http.ResponseWriter, r *http.Request) {
	model := map[string]any{}
	get := func(path string, key string) {
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
		var v any
		_ = ui2DecodeJSON(rec.Body.Bytes(), &v)
		model[key] = v
	}
	get("/api/project", "project")
	get("/api/stats", "stats")
	get("/api/proxy/ca", "ca")
	get("/api/protocols", "protocols")
	get("/api/pools", "pools")
	get("/api/schedules", "schedules")
	get("/api/skills", "skills")
	get("/api/wordlists", "wordlists")
	get("/api/settings/triage", "triage")
	get("/api/network/auth", "netauth")
	get("/api/network/server-certificates", "certs")
	get("/api/browser/settings", "browser")
	get("/api/events/stats", "events")
	ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings.html", model))
}

// ---- small io/json helpers (kept here so the ui2 file set stays self-contained) ---------------

type templateHTML = templateHTMLAlias

func newReq(method, path string) *http.Request {
	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		panic(err)
	}
	return req
}
func ui2DecodeJSON(b []byte, v any) error        { return ui2JSONUnmarshal(b, v) }
func ui2Marshal(v any) ([]byte, error)           { return ui2JSONMarshal(v) }
func ioNopCloser(r *strings.Reader) ioReadCloser { return ioReadCloser{r} }

var _ = core.ExchangeID(0)
