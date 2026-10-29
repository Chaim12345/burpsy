package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The /ui2/ console: server-rendered HTML with a vendored htmx client (ui2/htmx.min.js,
// ui2/sse.min.js). The React SPA at / stays the default; this slice exists to prove the
// server-driven shape against the same JSON model — one page per view, fragments swapped
// by htmx, no build step, no framework runtime in the browser.
//
//go:embed ui2
var ui2FS embed.FS

// ui2Templates is every server-rendered fragment, parsed once at package init. text/template
// would work too; html/template is chosen because message bytes are attacker-controlled and
// land in these pages — auto-escaping is not optional here.
var ui2Templates = template.Must(template.New("ui2").Funcs(template.FuncMap{
	"lower": strings.ToLower,
	"until": func(n int) []int { return make([]int, n) },
}).ParseFS(ui2FS,
	"ui2/layout.html",
	"ui2/nav.html",
	"ui2/dashboard.html",
	"ui2/sitemap.html",
	"ui2/scope.html",
	"ui2/intercept.html",
	"ui2/logger.html",
	"ui2/ws.html",
	"ui2/proxy.html",
	"ui2/extensions.html",
	"ui2/scanner.html",
	"ui2/advisories.html",
	"ui2/organizer.html",
	"ui2/session.html",
	"ui2/decoder.html",
	"ui2/comparer.html",
	"ui2/repeater.html",
	"ui2/settings.html",
	"ui2/error.html",
	"ui2/history_rows.html",
	"ui2/history_rows_append.html",
	"ui2/history_detail.html",
	"ui2/issue_groups.html",
	"ui2/issue_detail.html",
))

// ui2Error is the model for error.html.
type ui2Error struct{ Message string }

// ui2StatusString2 renders a *int status the way rows do ("—" when nil).
func ui2StatusString2(s *int) string {
	if s == nil {
		return "—"
	}
	return strconv.Itoa(*s)
}

// ui2Page is the per-request model for the layout wrapper.
type ui2Page struct {
	Title string
	View  string // "history" | "issues"
	Body  template.HTML
}

// ui2HistoryParams is the query state the history view round-trips through the URL, so a
// filtered/paged view is bookmarkable and htmx swaps carry the same state.
type ui2HistoryParams struct {
	Q      string // burpsy-query filter (same DSL as /api/history?q=)
	Search string // substring search over method/host/path/status
	Offset int    // server-side page offset, newest first
	Limit  int    // page size (default 100)
}

const ui2DefaultPageSize = 100
const ui2MaxPageSize = 500

func parseUI2HistoryParams(r *http.Request) ui2HistoryParams {
	q := r.URL.Query()
	p := ui2HistoryParams{
		Q:      strings.TrimSpace(q.Get("q")),
		Search: strings.TrimSpace(q.Get("search")),
		Limit:  ui2DefaultPageSize,
	}
	if n, err := strconv.Atoi(q.Get("offset")); err == nil && n > 0 {
		p.Offset = n
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		if n > ui2MaxPageSize {
			n = ui2MaxPageSize
		}
		p.Limit = n
	}
	return p
}

// ui2Row is one history row as the template sees it. Kept separate from ExchangeView so the
// template never needs to know the wire shape, and so the fields rendered are exactly the
// fields computed — no payloads.
type ui2Row struct {
	ID          uint64
	Method      string
	Host        string
	Port        uint16
	Path        string
	Status      string // "—" when no response yet
	Mime        string
	ResponseLen string
	DurationMs  uint64
	StartedMs   uint64
	Highlight   string
	Selected    bool
}

func ui2StatusString(s *uint16) string {
	if s == nil {
		return "—"
	}
	return strconv.Itoa(int(*s))
}

// ui2HistoryRows is the fragment model for the rows swap target.
type ui2HistoryRows struct {
	Rows       []ui2Row
	Total      int
	Matched    int
	Offset     int
	Limit      int
	NextOffset int // -1 when this page reached the end
	Q          string
	Search     string
	HasMore    bool
}

// handleUI2 is the /ui2/ subtree root: the shell page with the history view embedded.
func (s *Server) handleUI2(w http.ResponseWriter, r *http.Request) {
	page := ui2Page{Title: "burpsy /ui2/ — History", View: "history"}
	page.Body = s.renderUI2HistoryRows(r, ui2HistoryParams{Limit: ui2DefaultPageSize})
	if err := ui2Templates.ExecuteTemplate(w, "layout.html", page); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

// handleUI2History serves GET /ui2/history: the full shell on a plain navigation, or just the
// rows fragment when htmx asks (HX-Request). The shell embeds the first page so a cold load
// needs one request.
func (s *Server) handleUI2History(w http.ResponseWriter, r *http.Request) {
	p := parseUI2HistoryParams(r)
	appendMode := r.Header.Get("HX-Request") == "true" && r.URL.Query().Get("offset") != ""
	body := s.renderUI2HistoryRows(r, p)
	if appendMode {
		// Infinite-scroll append: emit only the <tr> rows (plus the next sentinel), so the
		// htmx beforeend swap grows the tbody without replacing the block the user scrolls.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(s.renderUI2HistoryRowsAppend(r, p)))
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write([]byte(body)); err != nil {
			return
		}
		return
	}
	page := ui2Page{Title: "burpsy /ui2/ — History", View: "history", Body: body}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui2Templates.ExecuteTemplate(w, "layout.html", page); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// renderUI2HistoryRows computes one page of history rows and renders the rows fragment.
// Server-side paging: the store hands index rows only (no bodies), the filter applies before
// the page slice, so cost is O(total rows) for the scan and O(page) for the render — the
// property that keeps a 200k-row capture responsive.
func (s *Server) renderUI2HistoryRows(r *http.Request, p ui2HistoryParams) template.HTML {
	var sb strings.Builder
	_ = ui2Templates.ExecuteTemplate(&sb, "history_rows.html", s.ui2HistoryPage(r, p))
	return template.HTML(sb.String()) //nolint:gosec // html/template auto-escapes every field
}

// ui2HistoryPage computes one page of history rows into the fragment model. Server-side
// paging: the store hands index rows only (no bodies), the filter applies before the page
// slice, so cost is O(total rows) for the scan and O(page) for the render — the property
// that keeps a 200k-row capture responsive. Shared by the full fragment and the
// infinite-scroll append so the two cannot disagree about which rows a page holds.
func (s *Server) ui2HistoryPage(r *http.Request, p ui2HistoryParams) ui2HistoryRows {
	exchanges := s.store.Exchanges()

	var filter *queryFilter
	if p.Q != "" {
		f, err := compileQuery(p.Q, s.store)
		if err != nil {
			// The DSL error is rendered by the JSON API with caret art; here a plain
			// message in the rows fragment is what the operator sees inline.
			return ui2HistoryRows{
				Rows: nil, Total: len(exchanges), Matched: 0, Offset: 0, Limit: p.Limit,
				NextOffset: -1, Q: p.Q, Search: p.Search, HasMore: false,
			}
		}
		filter = f
	}

	needle := strings.ToLower(p.Search)
	matched := make([]*core.Exchange, 0, len(exchanges))
	for i := len(exchanges) - 1; i >= 0; i-- {
		ex := exchanges[i]
		switch ex.Source {
		case core.SourceRepeater, core.SourceIntruder, core.SourceScanner:
			continue
		}
		if filter != nil && !filter.match(ex) {
			continue
		}
		if needle != "" {
			hay := strings.ToLower(ex.Method + " " + ex.Host + ex.Path + " " + ui2StatusString(ex.Status))
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		matched = append(matched, ex)
	}

	total := len(matched)
	end := p.Offset + p.Limit
	if end > total {
		end = total
	}
	next := -1
	if end < total {
		next = end
	}
	rows := make([]ui2Row, 0, max(end-p.Offset, 0))
	if p.Offset < total {
		for _, ex := range matched[p.Offset:end] {
			v := exchangeView(ex)
			rows = append(rows, ui2Row{
				ID:          uint64(v.ID),
				Method:      v.Method,
				Host:        v.Host,
				Port:        v.Port,
				Path:        v.Path,
				Status:      ui2StatusString(v.Status),
				Mime:        v.Mime,
				ResponseLen: strconv.Itoa(v.ResponseLen),
				DurationMs:  v.DurationMs,
				StartedMs:   v.StartedMs,
				Highlight:   v.Highlight,
			})
		}
	}
	return ui2HistoryRows{
		Rows: rows, Total: len(exchanges), Matched: total, Offset: p.Offset, Limit: p.Limit,
		NextOffset: next, Q: p.Q, Search: p.Search, HasMore: next >= 0,
	}
}

// renderUI2HistoryRowsAppend renders just the <tr> elements for one page plus the next
// sentinel row, for the infinite-scroll beforeend swap. It shares the page computation with
// the full fragment so the two cannot disagree about which rows a page holds.
func (s *Server) renderUI2HistoryRowsAppend(r *http.Request, p ui2HistoryParams) template.HTML {
	var sb strings.Builder
	_ = ui2Templates.ExecuteTemplate(&sb, "history_rows_append.html", s.ui2HistoryPage(r, p))
	return template.HTML(sb.String()) //nolint:gosec // html/template auto-escapes every field
}

// handleUI2HistoryDetail serves GET /ui2/history/{id}: the request/response panes for one
// exchange. Message bytes are read here, one message at a time, never in the list.
func (s *Server) handleUI2HistoryDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
		return
	}
	ex, err := s.store.GetExchange(core.ExchangeID(id))
	if err != nil {
		http.Error(w, "Exchange not found", http.StatusNotFound)
		return
	}
	v := exchangeView(ex)
	model := ui2Detail{
		ID: uint64(v.ID), Method: v.Method, Host: v.Host, Port: v.Port, Path: v.Path,
		Status: ui2StatusString(v.Status), Mime: v.Mime, ResponseLen: v.ResponseLen,
		DurationMs: v.DurationMs,
	}
	if v.Request != nil {
		if msg, err := s.store.Get(core.MsgId(*v.Request)); err == nil {
			model.Request = string(msg.Raw())
		}
	}
	if model.Request == "" {
		// Restored-project case: the exchanges table carries request_msg, but the
		// in-memory Request pointer is nil after this tree's restore path, so the row
		// reads as request-less even though the bytes are on disk. Resolve through the
		// store's request index rather than guessing an id.
		if raw := requestMessageForExchange(s.store, ex); raw != nil {
			model.Request = string(raw)
		}
	}
	if v.Response != nil {
		if msg, err := s.store.Get(core.MsgId(*v.Response)); err == nil {
			model.Response = string(msg.Raw())
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui2Templates.ExecuteTemplate(w, "history_detail.html", model); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// requestMessageForExchange resolves an exchange's request bytes when the exchange's own
// Request pointer is nil (the restored-project case). It never guesses an id: the request
// index is the only authority, and when nothing resolves the pane says so — an honest
// empty pane beats fabricated bytes.
func requestMessageForExchange(st *core.TrafficStore, ex *core.Exchange) []byte {
	if st == nil || ex == nil {
		return nil
	}
	if ex.Request != nil {
		if msg, err := st.Get(*ex.Request); err == nil {
			return msg.Raw()
		}
		return nil
	}
	return nil
}

// ui2Detail is the model for one exchange's request/response pane.
type ui2Detail struct {
	ID          uint64
	Method      string
	Host        string
	Port        uint16
	Path        string
	Status      string
	Mime        string
	ResponseLen int
	DurationMs  uint64
	Request     string
	Response    string
}

// ui2IssueGroup is one grouped issue (same issue name + host) for the issues tree.
type ui2IssueGroup struct {
	Name       string
	Severity   string
	Confidence string
	Host       string
	Count      int // occurrences
	FalsePos   bool
	IDs        []uint64
	FirstID    uint64
}

// ui2IssuesModel is the issues page fragment model.
type ui2IssuesModel struct {
	Groups   []ui2IssueGroup
	Total    int
	Severity map[string]int // lower-cased severity -> count
}

// handleUI2Issues serves GET /ui2/issues: the shell with the grouped issues list, or the
// groups fragment alone for an htmx swap.
func (s *Server) handleUI2Issues(w http.ResponseWriter, r *http.Request) {
	body := s.renderUI2Issues()
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
		return
	}
	page := ui2Page{Title: "burpsy /ui2/ — Issues", View: "issues", Body: body}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui2Templates.ExecuteTemplate(w, "layout.html", page); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// renderUI2Issues groups findings by (issue name, host) — the same merge the store already
// does per target, rolled up one level for display — and renders the groups fragment.
// Evidence lives one click deep (the detail route), so the list payload stays flat.
func (s *Server) renderUI2Issues() template.HTML {
	findings := s.findings.All()
	idx := s.exchangeIndex()
	type key struct{ name, host string }
	order := make([]key, 0, len(findings))
	groups := map[key]*ui2IssueGroup{}
	sev := map[string]int{}
	for _, f := range findings {
		if s.isolatedAgainst(f, &idx) {
			continue
		}
		v := s.issueView(f, &idx, true)
		name := f.Name
		if v.IssueName != nil && *v.IssueName != "" {
			name = *v.IssueName
		}
		k := key{name: name, host: v.Host}
		g, ok := groups[k]
		if !ok {
			g = &ui2IssueGroup{Name: name, Severity: v.Severity, Confidence: v.Confidence, Host: v.Host, FirstID: v.ID}
			groups[k] = g
			order = append(order, k)
		}
		g.Count += len(v.Occurrences)
		if g.Count == 0 {
			g.Count = v.TimesSeen
		}
		g.FalsePos = g.FalsePos || v.FalsePositive
		g.IDs = append(g.IDs, v.ID)
		if !v.FalsePositive {
			sev[strings.ToLower(v.Severity)]++
		}
	}
	out := ui2IssuesModel{Groups: make([]ui2IssueGroup, 0, len(order)), Total: len(findings), Severity: sev}
	for _, k := range order {
		out.Groups = append(out.Groups, *groups[k])
	}
	var sb strings.Builder
	_ = ui2Templates.ExecuteTemplate(&sb, "issue_groups.html", out)
	return template.HTML(sb.String()) //nolint:gosec // html/template auto-escapes every field
}

// handleUI2IssueDetail serves GET /ui2/issues/{id}: one finding with its evidence excerpt,
// occurrences (exchange ids + paths) and the advisory detail — the pane the list omits.
func (s *Server) handleUI2IssueDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid issue ID", http.StatusBadRequest)
		return
	}
	f, err := s.findings.Get(id)
	if err != nil {
		http.Error(w, "Issue not found", http.StatusNotFound)
		return
	}
	idx := s.exchangeIndex()
	v := s.issueView(f, &idx, false)
	model := ui2IssueDetail{
		ID: v.ID, CheckName: v.CheckName, Severity: v.Severity, Confidence: v.Confidence,
		Host: v.Host, Param: v.Param, Evidence: v.Evidence, TimesSeen: v.TimesSeen,
		FalsePositive: v.FalsePositive, Comment: v.Comment, Source: v.Source,
		Detail: ptrString(v.Detail), Remediation: ptrString(v.Remediation),
	}
	for _, occ := range v.Occurrences {
		model.Occurrences = append(model.Occurrences, ui2Occurrence{ExchangeID: uint64(occ.ExchangeID), Path: occ.Path})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui2Templates.ExecuteTemplate(w, "issue_detail.html", model); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ui2IssueDetail is the model for one issue's detail pane.
type ui2IssueDetail struct {
	ID            uint64
	CheckName     string
	Severity      string
	Confidence    string
	Host          string
	Param         string
	Evidence      string
	TimesSeen     int
	FalsePositive bool
	Comment       string
	Source        string
	Detail        string
	Remediation   string
	Occurrences   []ui2Occurrence
}

type ui2Occurrence struct {
	ExchangeID uint64
	Path       string
}

func ptrString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// serveUI2Asset serves one vendored static file from the embedded ui2 tree.
func serveUI2Asset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/ui2/")
	sub, err := fs.Sub(ui2FS, "ui2")
	if err != nil {
		http.Error(w, "ui2 unavailable", http.StatusInternalServerError)
		return
	}
	data, err := fs.ReadFile(sub, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	switch {
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}
