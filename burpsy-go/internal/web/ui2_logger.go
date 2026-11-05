package web

import (
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ---- Logger ----------------------------------------------------------------------------------
//
// The /ui2/logger page: requests burpsy itself sent or relayed (the tool log). Everything is read
// through GET /api/tools/log; the view axes the API owns (scope, has-response, parameterized, MIME,
// extension) are passed through to it, and the cheap display axes (tool, method, status class,
// annotated, search) are applied here over the rows it returns. Writes go through the API too:
// annotation directly (PATCH /api/tools/log/{id} is riskLocal), capture settings, clear and
// add-to-scope through a one-time review whose token binds the full body.

// ui2LoggerParams is the view state the page round-trips through its filter form and URL. The form
// names (v_*, plus search) are distinct from the capture forms' (tool, status, mime, scope_only),
// because review forms carry both sets at once.
type ui2LoggerParams struct {
	Search        string
	Tool          string
	Method        string
	StatusClass   string // "" | "0" (no response) | "2".."5"
	Annotated     bool
	ScopeOnly     bool
	HasResponse   bool
	Parameterized bool
	Mime          string
	Ext           string
	Offset        int
	Limit         int
	Sel           uint64 // the row whose detail pane is open, 0 for none
}

// parseUI2LoggerParams reads the view state from a parsed form (query and/or post body).
func parseUI2LoggerParams(v url.Values) ui2LoggerParams {
	p := ui2LoggerParams{
		Search:        strings.TrimSpace(v.Get("search")),
		Method:        strings.TrimSpace(v.Get("v_method")),
		Annotated:     ui2Truthy(v.Get("v_annotated")),
		ScopeOnly:     ui2Truthy(v.Get("v_scope")),
		HasResponse:   ui2Truthy(v.Get("v_has_response")),
		Parameterized: ui2Truthy(v.Get("v_parameterized")),
		Mime:          strings.TrimSpace(v.Get("v_mime")),
		Ext:           strings.TrimSpace(v.Get("v_ext")),
		Limit:         100,
	}
	if t := v.Get("v_tool"); t != "" {
		if _, ok := toollog.ToolFromName(t); ok {
			p.Tool = t
		}
	}
	switch sc := v.Get("v_status"); sc {
	case "0", "2", "3", "4", "5":
		p.StatusClass = sc
	}
	if n, err := strconv.Atoi(v.Get("limit")); err == nil && n > 0 && n <= 500 {
		p.Limit = n
	}
	if n, err := strconv.Atoi(v.Get("offset")); err == nil && n > 0 {
		p.Offset = n
	}
	if n, err := strconv.ParseUint(v.Get("sel"), 10, 64); err == nil {
		p.Sel = n
	}
	return p
}

// values is the view state as form values (no offset, no selection): what a sentinel, an export
// link and a review sheet carry so the page comes back the way the operator left it.
func (p ui2LoggerParams) values() url.Values {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	flag := func(k string, on bool) {
		if on {
			v.Set(k, "1")
		}
	}
	set("search", p.Search)
	set("v_tool", p.Tool)
	set("v_method", p.Method)
	set("v_status", p.StatusClass)
	flag("v_annotated", p.Annotated)
	flag("v_scope", p.ScopeOnly)
	flag("v_has_response", p.HasResponse)
	flag("v_parameterized", p.Parameterized)
	set("v_mime", p.Mime)
	set("v_ext", p.Ext)
	return v
}

// ui2LoggerFetch reads the tool log through the API with the view axes the API judges (scope is
// re-judged against the scope as it is now; parameterized may read the linked exchange). The
// path is fixed; only the encoded query carries operator input.
func (s *Server) ui2LoggerFetch(p ui2LoggerParams) (toolLogResp, string) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(math.MaxInt32))
	if p.ScopeOnly {
		q.Set("scope_only", "1")
	}
	if p.HasResponse {
		q.Set("has_response", "1")
	}
	if p.Parameterized {
		q.Set("parameterized", "1")
	}
	if p.Mime != "" {
		q.Set("mime", p.Mime)
	}
	if p.Ext != "" {
		q.Set("ext", p.Ext)
	}
	rec := newRecorder()
	s.toolLogGet(rec, newReq(http.MethodGet, "/api/tools/log?"+q.Encode()))
	var resp toolLogResp
	if rec.Code != http.StatusOK {
		return resp, strings.TrimSpace(rec.Body.String())
	}
	if err := ui2DecodeJSON(rec.Body.Bytes(), &resp); err != nil {
		return resp, "unreadable tool log: " + err.Error()
	}
	return resp, ""
}

// ui2LoggerKeep applies the display axes the page owns. Entries arrive newest first.
func ui2LoggerKeep(entries []toolLogEntry, p ui2LoggerParams) []toolLogEntry {
	needle := strings.ToLower(p.Search)
	out := make([]toolLogEntry, 0, len(entries))
	for _, e := range entries {
		if p.Tool != "" && e.Tool != p.Tool {
			continue
		}
		if p.Method != "" && e.Method != p.Method {
			continue
		}
		switch p.StatusClass {
		case "":
		case "0":
			if e.Status != nil {
				continue
			}
		default:
			if e.Status == nil || strconv.Itoa(*e.Status/100) != p.StatusClass {
				continue
			}
		}
		if p.Annotated && e.Comment == "" && e.Highlight == "" {
			continue
		}
		if needle != "" {
			hay := strings.ToLower(e.Tool + " " + e.Method + " " + e.Host + e.Path + " " + ui2StatusString2(e.Status))
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

type ui2LoggerCaptureRow struct {
	Tool       string
	On         bool
	Uncaptured uint64
}

type ui2LoggerToolOpt struct {
	Name  string
	Count int
}

// ui2LoggerRow is one table row: the API's entry plus the selection mark.
type ui2LoggerRow struct {
	toolLogEntry
	Selected bool
	Age      string
}

type ui2LoggerModel struct {
	Entries    []ui2LoggerRow
	Total      int
	Matched    int
	Offset     int
	Limit      int
	NextOffset int
	Search     string
	HasMore    bool
	// HxVals is the sentinel row's hx-vals attribute, precomputed as JSON: quoting operator text
	// inline broke the attribute's JSON whenever it contained a double quote.
	HxVals          string
	P               ui2LoggerParams
	ExportQuery     string
	Tools           []ui2LoggerToolOpt
	Methods         []string
	Counts          map[string]int
	Capturing       map[string]bool
	CaptureRows     []ui2LoggerCaptureRow
	Dropped         uint64
	UncapturedTotal uint64
	Capacity        int
	ScopeAttached   bool
	Filter          ui2LoggerFilterView
	FilterNote      string
	// Note is a capture-toggle refusal ("capture unchanged: ...") rendered next to the toggles;
	// kept apart from FilterNote so the page never blames the filter for a capture refusal.
	Note string
	// ActionNote is the outcome of an annotate / clear / scope action: Done on success, Error on
	// refusal.
	ActionDone  string
	ActionError string
	ViewError   string
	Detail      *ui2LoggerDetail
}

// ui2LoggerFilterView is the capture filter prepared for the template: the echo of what the
// server enforces plus per-class booleans the checkbox markup needs.
type ui2LoggerFilterView struct {
	Active         bool
	Summary        string
	S2, S3, S4, S5 bool
	Term           string
	Regex          bool
	Case           bool
	Negate         bool
	ScopeOnly      bool
	MimeJoined     string
	FilteredTotal  uint64
}

// ui2Age renders an epoch-millis time as a compact age ("12s", "4m", "3h", "2d").
func ui2Age(ms uint64) string {
	if ms == 0 {
		return "—"
	}
	d := time.Since(time.UnixMilli(int64(ms))) //nolint:gosec // G115: a millisecond timestamp is far below 2^63
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d"
}

// handleUI2Logger serves GET /ui2/logger: the page (shell, or #rows on an HX request), or only the
// next rows plus sentinel when the infinite-scroll sentinel asks for a later offset.
func (s *Server) handleUI2Logger(w http.ResponseWriter, r *http.Request) {
	p := parseUI2LoggerParams(r.URL.Query())
	if p.Offset > 0 {
		// Infinite-scroll append: only the <tr> rows plus the next sentinel, so the beforeend
		// swap grows the tbody without re-appending the capture panel, filter and table head.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("logger_rows_append.html", s.ui2LoggerView(p, ""))))
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Logger", "logger", ui2Exec("logger_page.html", s.ui2LoggerView(p, "")))
}

// ui2LoggerView builds the Logger page model: one page of entries plus the capture axis, the
// capture filter and, when a row is selected, its detail pane.
func (s *Server) ui2LoggerView(p ui2LoggerParams, filterNote string) ui2LoggerModel {
	resp, viewErr := s.ui2LoggerFetch(p)
	all := resp.Entries
	methodSet := map[string]bool{}
	for _, e := range all {
		methodSet[e.Method] = true
	}
	entries := ui2LoggerKeep(all, p)
	total := len(entries)
	end := min(p.Offset+p.Limit, total)
	rows := []ui2LoggerRow{}
	if p.Offset < total {
		for _, e := range entries[p.Offset:end] {
			rows = append(rows, ui2LoggerRow{toolLogEntry: e, Selected: p.Sel != 0 && e.ID == p.Sel, Age: ui2Age(e.StartedMs)})
		}
	}
	next := -1
	if end < total {
		next = end
	}
	m := ui2LoggerModel{
		Entries: rows, Total: resp.Total, Matched: total, Offset: p.Offset, Limit: p.Limit,
		NextOffset: next, Search: p.Search, HasMore: next >= 0, P: p,
		ExportQuery: p.values().Encode(),
		Counts:      resp.Counts, Capturing: resp.Capturing, Dropped: resp.Dropped,
		UncapturedTotal: resp.UncapturedTotal, Capacity: resp.Capacity, ScopeAttached: resp.ScopeAttached,
		Filter: ui2LoggerFilterViewOf(resp), FilterNote: filterNote, ViewError: viewErr,
		HxVals: ui2LoggerHxVals(next, p),
	}
	for _, t := range toollog.ToolAll {
		name := t.String()
		m.Tools = append(m.Tools, ui2LoggerToolOpt{Name: name, Count: resp.Counts[name]})
		m.CaptureRows = append(m.CaptureRows, ui2LoggerCaptureRow{
			Tool: name, On: resp.Capturing[name], Uncaptured: resp.Uncaptured[name],
		})
	}
	for k := range methodSet {
		m.Methods = append(m.Methods, k)
	}
	if p.Method != "" && !methodSet[p.Method] {
		m.Methods = append(m.Methods, p.Method)
	}
	sort.Strings(m.Methods)
	if p.Sel != 0 {
		m.Detail = s.ui2LoggerDetailFor(p.Sel, p, true, true)
	}
	return m
}

// ui2LoggerFilterViewOf prepares the capture filter echo for the template.
func ui2LoggerFilterViewOf(resp toolLogResp) ui2LoggerFilterView {
	fv := ui2LoggerFilterView{
		Term: resp.Filter.Term, Regex: resp.Filter.Regex, Case: resp.Filter.Case,
		Negate: resp.Filter.Negate, ScopeOnly: resp.Filter.ScopeOnly,
		MimeJoined: strings.Join(resp.Filter.MIME, ", "), FilteredTotal: resp.FilteredTotal,
	}
	var parts []string
	for _, class := range resp.Filter.Status {
		switch class {
		case 2:
			fv.S2 = true
		case 3:
			fv.S3 = true
		case 4:
			fv.S4 = true
		case 5:
			fv.S5 = true
		default:
			continue
		}
		parts = append(parts, strconv.Itoa(class)+"xx")
	}
	if fv.Term != "" {
		t := strconv.Quote(fv.Term)
		var mods []string
		if fv.Regex {
			mods = append(mods, "regex")
		}
		if fv.Case {
			mods = append(mods, "case-sensitive")
		}
		if fv.Negate {
			mods = append(mods, "negated")
		}
		if len(mods) > 0 {
			t += " (" + strings.Join(mods, ", ") + ")"
		}
		parts = append(parts, "term "+t)
	}
	if fv.ScopeOnly {
		parts = append(parts, "in scope only")
	}
	if len(resp.Filter.MIME) > 0 {
		parts = append(parts, "excluding MIME "+fv.MimeJoined)
	}
	fv.Active = len(parts) > 0
	fv.Summary = strings.Join(parts, " · ")
	return fv
}

// ui2LoggerHxVals is the sentinel row's hx-vals payload: JSON carrying the whole view state, so
// any operator text round-trips into the next page request.
func ui2LoggerHxVals(next int, p ui2LoggerParams) string {
	m := map[string]any{"offset": next, "limit": p.Limit}
	for k, v := range p.values() {
		m[k] = v[0]
	}
	if _, ok := m["search"]; !ok {
		m["search"] = ""
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// ---- detail pane ----

// ui2LoggerDetail is the selected row's pane: the log's own fields, the annotation editor, the
// row actions, and the request/response bytes when the send produced a stored exchange.
type ui2LoggerDetail struct {
	E            toolLogEntry
	Missing      uint64 // set when the id is not (or no longer) in the log
	URL          string
	Curl         string
	Sent         string
	HistHost     string
	HistHostPath string
	Highlights   []string
	ViewQuery    string // the page's view state, for links that keep it
	View         url.Values
	Panes        *ui2ExchangePanes
	ReqPretty    bool
	RespPretty   bool
}

// ui2ExchangePanes is one exchange's request/response, read through /api/exchange/{id} and
// /api/message/{id} and rendered by renderMessagePane. Shared by the Logger detail and the WS
// handshake view.
type ui2ExchangePanes struct {
	ID         uint64
	Error      string
	Request    string
	Response   string
	NoResponse bool
	ReqPane    ui2PaneView
	RespPane   ui2PaneView
	Host       string
	Path       string
}

func (s *Server) ui2ExchangePanesFor(id uint64, reqPretty, respPretty bool) *ui2ExchangePanes {
	out := &ui2ExchangePanes{ID: id}
	var ex struct {
		Host     string  `json:"host"`
		Path     string  `json:"path"`
		Request  *uint64 `json:"request"`
		Response *uint64 `json:"response"`
	}
	if errText := s.ui2APIGet("/api/exchange/"+strconv.FormatUint(id, 10), &ex); errText != "" {
		out.Error = "exchange #" + strconv.FormatUint(id, 10) + " is no longer in the traffic store (" + errText + ")"
		return out
	}
	out.Host, out.Path = ex.Host, ex.Path
	var msg struct {
		Text string `json:"text"`
	}
	if ex.Request != nil && s.ui2APIGet("/api/message/"+strconv.FormatUint(*ex.Request, 10), &msg) == "" {
		out.Request = msg.Text
	}
	if ex.Response == nil {
		out.NoResponse = true
	} else {
		msg.Text = ""
		if s.ui2APIGet("/api/message/"+strconv.FormatUint(*ex.Response, 10), &msg) == "" {
			out.Response = msg.Text
		}
	}
	out.ReqPane = renderMessagePane(out.Request, true, reqPretty)
	out.RespPane = renderMessagePane(out.Response, false, respPretty)
	return out
}

// ui2APIGet reads one internal JSON GET route into v, or returns the refusal text.
func (s *Server) ui2APIGet(path string, v any) string {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
	if rec.Code != http.StatusOK {
		return strings.TrimSpace(rec.Body.String())
	}
	if err := ui2DecodeJSON(rec.Body.Bytes(), v); err != nil {
		return "unreadable response: " + err.Error()
	}
	return ""
}

// ui2HistoryQueryHref is a /ui2/history link filtered by a burpsy-query expression.
func ui2HistoryQueryHref(q string) string { return "/ui2/history?q=" + url.QueryEscape(q) }

// ui2QueryQuote quotes a value for the burpsy-query DSL (its escapes: \" \\ \n \t \r).
func ui2QueryQuote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(v) + `"`
}

func (s *Server) ui2LoggerDetailFor(id uint64, p ui2LoggerParams, reqPretty, respPretty bool) *ui2LoggerDetail {
	d := &ui2LoggerDetail{ViewQuery: p.values().Encode(), View: p.values(), ReqPretty: reqPretty, RespPretty: respPretty}
	e, ok := s.ui2LoggerEntry(id)
	if !ok {
		d.Missing = id
		return d
	}
	d.E = e
	// The scheme comes from the row's TLS flag; exchangeURL owns the default-port rule.
	d.URL = exchangeURL(&core.Exchange{Host: e.Host, Port: e.Port, TLS: e.TLS, Path: e.Path})
	method := e.Method
	if method == "" {
		method = "GET"
	}
	if strings.Trim(method, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		method = ui2ShellQuote(method)
	}
	d.Curl = "curl -i -X " + method + " " + ui2ShellQuote(d.URL)
	if e.StartedMs > 0 {
		d.Sent = time.UnixMilli(int64(e.StartedMs)).Format("2006-01-02 15:04:05") + " (" + ui2Age(e.StartedMs) + " ago)" //nolint:gosec // G115: a millisecond timestamp is far below 2^63
	}
	d.HistHost = ui2HistoryQueryHref("host = " + ui2QueryQuote(e.Host))
	d.HistHostPath = ui2HistoryQueryHref("host = " + ui2QueryQuote(e.Host) + " AND path ~ " + ui2QueryQuote(e.Path))
	for _, h := range []string{"red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"} {
		if core.ValidHighlights[h] {
			d.Highlights = append(d.Highlights, h)
		}
	}
	if e.Exchange != nil {
		d.Panes = s.ui2ExchangePanesFor(*e.Exchange, reqPretty, respPretty)
	}
	return d
}

// ui2LoggerEntry finds one row by id in the whole log (not the filtered view).
func (s *Server) ui2LoggerEntry(id uint64) (toolLogEntry, bool) {
	resp, _ := s.ui2LoggerFetch(ui2LoggerParams{})
	for _, e := range resp.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return toolLogEntry{}, false
}

// handleUI2LoggerEntry serves GET /ui2/logger/entry/{id}: the detail pane fragment for one row.
func (s *Server) handleUI2LoggerEntry(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid log entry id", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	p := parseUI2LoggerParams(q)
	d := s.ui2LoggerDetailFor(id, p, q.Get("view_req") != "raw", q.Get("view_resp") != "raw")
	if r.Header.Get("HX-Request") != "true" {
		// A plain navigation (new tab, reload) gets the whole page with this row open.
		p.Sel = id
		ui2RenderPage(w, "burpsy /ui2/ — Logger", "logger", ui2Exec("logger_page.html", s.ui2LoggerView(p, "")))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("logger_detail.html", d)))
}

// ---- CSV export ----

// ui2LoggerCSVCell quotes one CSV cell and defuses spreadsheet formulas: a cell a spreadsheet would
// evaluate (leading = + - @, or a tab/CR that some readers strip first) is prefixed with a quote.
// Same guard as the React console's csvCell.
func ui2LoggerCSVCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		v = "'" + v
	}
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

// handleUI2LoggerExport serves GET /ui2/logger/export: the filtered view as CSV, every matching
// row (not one page), in the columns of the React console's toolLogToCSV.
func (s *Server) handleUI2LoggerExport(w http.ResponseWriter, r *http.Request) {
	p := parseUI2LoggerParams(r.URL.Query())
	resp, errText := s.ui2LoggerFetch(p)
	if errText != "" {
		http.Error(w, errText, http.StatusBadRequest)
		return
	}
	var b strings.Builder
	header := []string{"ID", "Timestamp", "Tool", "Host", "Port", "Method", "Path", "Status", "Length", "Duration", "Comment"}
	for i, h := range header {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(ui2LoggerCSVCell(h))
	}
	for _, e := range ui2LoggerKeep(resp.Entries, p) {
		status, length := "", ""
		if e.Status != nil {
			status = strconv.Itoa(*e.Status)
		}
		if e.ResponseLen != nil {
			length = strconv.Itoa(*e.ResponseLen)
		}
		cells := []string{
			strconv.FormatUint(e.ID, 10),
			time.UnixMilli(int64(e.StartedMs)).UTC().Format("2006-01-02T15:04:05.000Z"), //nolint:gosec // G115: a millisecond timestamp is far below 2^63
			e.Tool, e.Host, strconv.Itoa(int(e.Port)), e.Method, e.Path, status, length,
			strconv.FormatUint(e.DurationMs, 10), e.Comment,
		}
		b.WriteByte('\n')
		for i, c := range cells {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(ui2LoggerCSVCell(c))
		}
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="toollog.csv"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(b.String()))
}

// ---- actions ----

// handleUI2LoggerAction serves POST /ui2/logger/{action}.
//
// Gated mutations are a two-step review whose one-time token binds the full body: capture-<tool>-
// on/off, filter-set/filter-clear (capture filter + row limit), clear-review and scope-review MINT
// and render a review sheet; capture-run, filter-run, clear-run and scope-run SPEND it through the
// guarded path. The first click never dispatches. annotate PATCHes /api/tools/log/{id}, whose risk
// class needs no confirmation, so it applies directly; if that class ever becomes gated it gets
// the same review (annotate-run spends it).
func (s *Server) handleUI2LoggerAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	_ = r.ParseForm()
	p := parseUI2LoggerParams(r.Form)
	p.Offset = 0
	writeModel := func(m ui2LoggerModel) {
		ui2Fragment(w, r, "burpsy /ui2/ — Logger", "logger", ui2Exec("logger_page.html", m))
	}
	writeView := func(note string) { writeModel(s.ui2LoggerView(p, note)) }
	writeReview := func(model map[string]any) {
		model["search"] = p.Search
		model["view"] = p.values()
		ui2Fragment(w, r, "burpsy /ui2/ — Logger", "logger", ui2Exec("logger_confirm.html", model))
	}
	writeOutcome := func(sel uint64, done, errText string) {
		p.Sel = sel
		m := s.ui2LoggerView(p, "")
		if errText != "" {
			m.ActionError = ui2APIErrorText(errText)
		} else {
			m.ActionDone = done
		}
		writeModel(m)
	}
	token := r.PostFormValue("token")
	switch action {
	case "capture-run":
		// No dispatch at all without a token: toggling capture on a body the operator never
		// reviewed is the bypass this review exists to close.
		var errText string
		if token == "" {
			errText = "no confirmation token, review the change first"
		} else {
			payload := map[string]any{"tool": r.PostFormValue("tool"), "on": r.PostFormValue("on") == "true"}
			_, errText = s.ui2DispatchConfirmed(http.MethodPost, "/api/tools/log", payload, token)
		}
		m := s.ui2LoggerView(p, "")
		m.Note = errText
		writeModel(m)
		return
	case "filter-run":
		if token == "" {
			writeView("filter unchanged: no confirmation token, review the change first")
			return
		}
		body, errText := ui2LoggerCaptureBody(r, r.PostFormValue("clear") == "1")
		if errText != "" {
			writeView(errText)
			return
		}
		_, errText = s.ui2DispatchConfirmed(http.MethodPost, "/api/tools/log", body, token)
		writeView(errText)
		return
	case "filter-set", "filter-clear":
		clear := action == "filter-clear"
		payload, errText := ui2LoggerCaptureBody(r, clear)
		if errText != "" {
			writeView(errText)
			return
		}
		body, _ := ui2Marshal(payload)
		token, preview, errText := s.ui2MintConfirm("/api/tools/log", http.MethodPost, "/api/tools/log", body)
		writeReview(map[string]any{
			"kind": "filter", "clear": clear, "token": token, "preview": preview, "error": errText,
			"full_body": string(body),
			"status":    r.PostForm["status"], "term": r.PostFormValue("term"),
			"regex": r.PostFormValue("regex"), "case": r.PostFormValue("case"),
			"negate": r.PostFormValue("negate"), "scope_only": r.PostFormValue("scope_only"),
			"mime": r.PostFormValue("mime"), "capacity": strings.TrimSpace(r.PostFormValue("capacity")),
			"cur_capacity": s.toolLog.Capacity(),
		})
		return
	case "clear-review":
		token, preview, errText := s.ui2MintConfirm("/api/tools/log", http.MethodDelete, "/api/tools/log", nil)
		writeReview(map[string]any{
			"kind": "clear", "token": token, "preview": preview, "error": errText,
			"full_body": "(no body)", "count": len(s.toolLog.All()),
		})
		return
	case "clear-run":
		if token == "" {
			writeOutcome(0, "", "log not cleared: no confirmation token, review the change first")
			return
		}
		_, errText := s.ui2DispatchConfirmed(http.MethodDelete, "/api/tools/log", nil, token)
		writeOutcome(0, "tool log cleared; proxy history is untouched", errText)
		return
	case "scope-review", "scope-run":
		id, _ := strconv.ParseUint(r.PostFormValue("id"), 10, 64)
		e, ok := s.ui2LoggerEntry(id)
		if !ok || e.Host == "" {
			writeOutcome(0, "", "scope unchanged: log entry no longer exists")
			return
		}
		// The rule is derived from the row on the server at both steps, never from a form field.
		payload := map[string]any{"action": "include", "pattern": e.Host}
		if action == "scope-run" {
			if token == "" {
				writeOutcome(id, "", "scope unchanged: no confirmation token, review the change first")
				return
			}
			_, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/scope", payload, token)
			writeOutcome(id, e.Host+" added to scope", errText)
			return
		}
		body, _ := ui2Marshal(payload)
		token, preview, errText := s.ui2MintConfirm("/api/scope", http.MethodPost, "/api/scope", body)
		writeReview(map[string]any{
			"kind": "scope", "token": token, "preview": preview, "error": errText,
			"full_body": string(body), "id": id, "host": e.Host,
		})
		return
	case "annotate", "annotate-run":
		id, err := strconv.ParseUint(r.PostFormValue("id"), 10, 64)
		if err != nil {
			writeOutcome(0, "", "annotation not saved: invalid log entry id")
			return
		}
		payload := map[string]any{"comment": r.PostFormValue("comment"), "highlight": r.PostFormValue("highlight")}
		path := "/api/tools/log/" + strconv.FormatUint(id, 10)
		_, risk, _ := routeRiskFor(path)
		var errText string
		switch {
		case !needsConfirmation(risk):
			_, errText = s.ui2APIResult(http.MethodPatch, path, payload)
		case action == "annotate":
			body, _ := ui2Marshal(payload)
			token, preview, errText := s.ui2MintConfirm(path, http.MethodPatch, path, body)
			writeReview(map[string]any{
				"kind": "annotate", "token": token, "preview": preview, "error": errText,
				"full_body": string(body), "id": id, "comment": payload["comment"], "highlight": payload["highlight"],
			})
			return
		case token == "":
			errText = "annotation not saved: no confirmation token, review the change first"
		default:
			_, errText = s.ui2DispatchConfirmed(http.MethodPatch, path, payload, token)
		}
		writeOutcome(id, "annotation saved for #"+strconv.FormatUint(id, 10), errText)
		return
	}
	tool, state, ok := strings.Cut(strings.TrimPrefix(action, "capture-"), "-")
	if !strings.HasPrefix(action, "capture-") || !ok || (state != "on" && state != "off") {
		http.Error(w, "unknown logger action", http.StatusBadRequest)
		return
	}
	if _, ok := toollog.ToolFromName(tool); !ok {
		http.Error(w, "unknown logger action", http.StatusBadRequest)
		return
	}
	// First click: mint the one-time review for the exact toggle call. Nothing is dispatched.
	body, _ := ui2Marshal(map[string]any{"tool": tool, "on": state == "on"})
	token, preview, errText := s.ui2MintConfirm("/api/tools/log", http.MethodPost, "/api/tools/log", body)
	writeReview(map[string]any{
		"kind": "capture", "token": token, "preview": preview, "error": errText,
		"full_body": string(body), "tool": tool, "on": state == "on",
	})
}

// ui2LoggerCaptureBody builds the exact POST /api/tools/log body for the capture settings form:
// the capture filter plus, when given, the row limit. The mint and the spend both call it, so the
// body the operator reviews is byte-for-byte the body the token spends.
func ui2LoggerCaptureBody(r *http.Request, clear bool) (map[string]any, string) {
	fv, errText := ui2LoggerFilterForm(r, clear)
	if errText != "" {
		return nil, errText
	}
	body := map[string]any{"filter": fv}
	if raw := strings.TrimSpace(r.PostFormValue("capacity")); raw != "" && !clear {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return nil, "row limit must be a positive whole number"
		}
		body["capacity"] = n
	}
	return body, ""
}

// ui2LoggerFilterForm parses the capture-filter form into the exact filter value the API binds.
// An invalid class is refused with its reason before anything is minted.
func ui2LoggerFilterForm(r *http.Request, clear bool) (map[string]any, string) {
	if clear {
		return map[string]any{}, ""
	}
	var status []int
	for _, v := range r.PostForm["status"] {
		n, err := strconv.Atoi(v)
		if err != nil || n < 2 || n > 5 {
			return nil, "status classes are 2, 3, 4 and 5"
		}
		status = append(status, n)
	}
	if status == nil {
		status = []int{}
	}
	var mime []string
	for _, piece := range strings.Split(r.PostFormValue("mime"), ",") {
		if p := strings.TrimSpace(piece); p != "" {
			mime = append(mime, p)
		}
	}
	return map[string]any{
		"status":         status,
		"term":           strings.TrimSpace(r.PostFormValue("term")),
		"regex":          r.PostFormValue("regex") != "",
		"case_sensitive": r.PostFormValue("case") != "",
		"negate":         r.PostFormValue("negate") != "",
		"scope_only":     r.PostFormValue("scope_only") != "",
		"mime":           mime,
	}, ""
}
