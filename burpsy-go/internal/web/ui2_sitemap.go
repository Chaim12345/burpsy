package web

// ui2 Target › Site map (unit #10): the React Target tab (pages/sitemap.tsx, engagement.tsx,
// ui/target-analyzer-view.tsx, ui/crawlpaths.tsx) as server-rendered pages.
//
//   - GET /ui2/sitemap renders the filtered tree (filters are query params, so a view is
//     bookmarkable), the selected node's detail pane, and the Engagement tools, Target
//     analyzer and Crawl paths views (view=engagement|analyzer|paths).
//   - GET /ui2/sitemap/children lazily renders a node's children (mode=kids), its whole branch
//     expanded (mode=branch) or the node collapsed (mode=node).
//   - GET /ui2/sitemap/detail renders one node's request table, issues and actions.
//   - GET /ui2/sitemap/message renders one exchange's request and response.
//   - GET /ui2/sitemap/export is the engagement results as CSV.
//   - POST /ui2/sitemap/review/{confirm,run} is the one review flow for the three writes
//     (delete host/branch/item, passive branch sweep, branch crawl): confirm builds the exact
//     call from the live node, holds its bytes server-side and mints the gate token when the
//     route needs one; run spends the held review once and dispatches those bytes verbatim.

import (
	"bytes"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- filter and page params ------------------------------------------------------------------

// ui2SitemapFilter is the tree filter bar (pages/sitemap.tsx SitemapFilter plus the text term).
type ui2SitemapFilter struct {
	Q             string
	Types         []string // MIME words: html json xml javascript css image
	Statuses      []string // status classes "2".."5"
	ScopeOnly     bool
	RequestedOnly bool
	ParamsOnly    bool
	HideNotFound  bool
}

type ui2SitemapOpt struct {
	Value, Label string
	Checked      bool
}

var ui2SitemapTypeOpts = []ui2SitemapOpt{{Value: "html", Label: "HTML"}, {Value: "json", Label: "JSON"},
	{Value: "xml", Label: "XML"}, {Value: "javascript", Label: "JS"}, {Value: "css", Label: "CSS"}, {Value: "image", Label: "Images"}}
var ui2SitemapStatusOpts = []ui2SitemapOpt{{Value: "2", Label: "2xx"}, {Value: "3", Label: "3xx"},
	{Value: "4", Label: "4xx"}, {Value: "5", Label: "5xx"}}

func ui2SitemapPick(vals []string, opts []ui2SitemapOpt) []string {
	var out []string
	for _, o := range opts {
		for _, v := range vals {
			if v == o.Value {
				out = append(out, v)
				break
			}
		}
	}
	return out
}

func parseUI2SitemapFilter(q url.Values) ui2SitemapFilter {
	on := func(k string) bool { v := q.Get(k); return v != "" && v != "0" && v != "false" }
	return ui2SitemapFilter{
		Q:             strings.TrimSpace(q.Get("q")),
		Types:         ui2SitemapPick(q["type"], ui2SitemapTypeOpts),
		Statuses:      ui2SitemapPick(q["status"], ui2SitemapStatusOpts),
		ScopeOnly:     on("scope"),
		RequestedOnly: on("requested"),
		ParamsOnly:    on("params"),
		HideNotFound:  on("hide404"),
	}
}

// Narrowed is whether anything filters the tree; a narrowed tree renders matching branches open.
func (f ui2SitemapFilter) Narrowed() bool {
	return f.Q != "" || len(f.Types) > 0 || len(f.Statuses) > 0 || f.ScopeOnly || f.RequestedOnly || f.ParamsOnly || f.HideNotFound
}

func (f ui2SitemapFilter) values() url.Values {
	v := url.Values{}
	if f.Q != "" {
		v.Set("q", f.Q)
	}
	v["type"] = append([]string(nil), f.Types...)
	v["status"] = append([]string(nil), f.Statuses...)
	for k, b := range map[string]bool{"scope": f.ScopeOnly, "requested": f.RequestedOnly, "params": f.ParamsOnly, "hide404": f.HideNotFound} {
		if b {
			v.Set(k, "1")
		}
	}
	for k, vs := range v {
		if len(vs) == 0 {
			delete(v, k)
		}
	}
	return v
}

// ui2SitemapURL builds a console URL carrying the filter plus extra params. Every URL a template
// emits is built here, whole, so a NUL-carrying node key is percent-encoded once and an href's
// own escaping never re-encodes it.
func (f ui2SitemapFilter) url(path string, extra ...string) string {
	v := f.values()
	for i := 0; i+1 < len(extra); i += 2 {
		if extra[i+1] != "" {
			v.Set(extra[i], extra[i+1])
		}
	}
	if len(v) == 0 {
		return path
	}
	return path + "?" + v.Encode()
}

// ---- node predicates (ported from pages/sitemap.tsx) -----------------------------------------

func ui2SitemapBoolAxes(n *sitemapNodeView, f ui2SitemapFilter) bool {
	if f.ScopeOnly && !n.InScope {
		return false
	}
	if f.RequestedOnly && !n.Requested {
		return false
	}
	if f.ParamsOnly && len(n.Params) == 0 {
		return false
	}
	if f.HideNotFound && len(n.Statuses) > 0 {
		all4xx := true
		for _, s := range n.Statuses {
			if s < 400 || s >= 500 {
				all4xx = false
				break
			}
		}
		if all4xx {
			return false
		}
	}
	return true
}

// ui2SitemapMimeIn matches a MIME bucket against the node's media words. Substring, so the bucket
// "javascript" matches both the word and a full "application/javascript".
func ui2SitemapMimeIn(mimes []string, buckets []string) bool {
	for _, m := range mimes {
		lm := strings.ToLower(m)
		for _, b := range buckets {
			if strings.Contains(lm, b) || b == "javascript" && strings.Contains(lm, "ecmascript") {
				return true
			}
		}
	}
	return false
}

func ui2SitemapSetAxes(n *sitemapNodeView, f ui2SitemapFilter) bool {
	if len(f.Statuses) > 0 {
		ok := false
		for _, s := range n.Statuses {
			for _, c := range f.Statuses {
				if strconv.Itoa(s)[:1] == c {
					ok = true
				}
			}
		}
		if !ok {
			return false
		}
	}
	if len(f.Types) > 0 && !ui2SitemapMimeIn(n.Mimes, f.Types) {
		return false
	}
	return true
}

// ui2SitemapMatches is subtreeMatches: boolean axes bind the node itself, set axes and the text
// term are satisfied by the node or any descendant.
func ui2SitemapMatches(n *sitemapNodeView, f ui2SitemapFilter) bool {
	if !ui2SitemapBoolAxes(n, f) {
		return false
	}
	anyKid := func() bool {
		for i := range n.Children {
			if ui2SitemapMatches(&n.Children[i], f) {
				return true
			}
		}
		return false
	}
	if !ui2SitemapSetAxes(n, f) && !anyKid() {
		return false
	}
	if term := strings.ToLower(f.Q); term != "" &&
		!strings.Contains(strings.ToLower(n.Path), term) && !strings.Contains(strings.ToLower(n.Segment), term) {
		return anyKid()
	}
	return true
}

// ---- tree rows -------------------------------------------------------------------------------

// ui2SitemapRow is one tree node as the template draws it.
type ui2SitemapRow struct {
	Key, Label, Title, Host, Path string
	IsHost, HasKids, Open, Loaded bool
	Kids                          []ui2SitemapRow
	Count                         int
	Params                        string
	Issues                        int
	Worst                         string
	InScope, Requested            bool
	Inserted, Unrequested         bool
	Selected                      bool
	// Precomputed URLs (see ui2SitemapFilter.url).
	KidsURL, BranchURL, CollapseURL, SelectURL, PageURL string
	ScopeURL, RepeaterURL, ReviewURL                    string
	CommentsURL, ScriptsURL, RefsURL, AnalyzeURL        string
}

// ui2SitemapExpandCap bounds how many rows one render expands inline; past it, rows stay lazy.
const ui2SitemapExpandCap = 1500

type ui2SitemapBuild struct {
	f        ui2SitemapFilter
	sel      string
	openKeys map[string]bool // ancestors of the selection, kept open
	all      bool            // branch mode: everything below renders open
	budget   int
}

func (b *ui2SitemapBuild) rows(nodes []sitemapNodeView, depth int, host string) []ui2SitemapRow {
	out := make([]ui2SitemapRow, 0, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		if !ui2SitemapMatches(n, b.f) {
			continue
		}
		rowHost := host
		if depth == 0 {
			rowHost = n.Path
		}
		row := b.row(n, depth, rowHost)
		b.budget--
		open := b.budget > 0 && (b.all || b.f.Narrowed() || depth == 0 || b.openKeys[n.Key])
		if row.HasKids && open {
			row.Open, row.Loaded = true, true
			row.Kids = b.rows(n.Children, depth+1, rowHost)
		}
		out = append(out, row)
	}
	return out
}

func (b *ui2SitemapBuild) row(n *sitemapNodeView, depth int, host string) ui2SitemapRow {
	f := b.f
	label := n.Segment
	if label == "" {
		label = "/"
	}
	full := host
	path := ""
	if depth > 0 {
		full, path = host+n.Path, n.Path
	}
	title := full
	if depth > 0 && !n.Requested && !n.Inserted && !n.Unrequested {
		title += " (no request to this path itself)"
	}
	if n.Unrequested {
		title += " - linked from " + n.LinkedFrom + ", never requested"
	}
	if !n.InScope {
		title += " - out of scope: the tools will not touch this"
	}
	analyze := url.Values{"view": {"analyzer"}, "host": {host}, "port": {strconv.Itoa(int(n.Port))}, "tls": {strconv.FormatBool(n.TLS)}}
	if path != "" {
		analyze.Set("path", path)
	}
	return ui2SitemapRow{
		Key: n.Key, Label: label, Title: title, Host: host, Path: path,
		IsHost: depth == 0, HasKids: len(n.Children) > 0,
		Count: n.SubtreeCount, Params: strings.Join(n.Params, ","), Issues: n.SubtreeIssues, Worst: n.WorstSeverity,
		InScope: n.InScope, Requested: n.Requested, Inserted: n.Inserted, Unrequested: n.Unrequested,
		Selected:    n.Key == b.sel,
		KidsURL:     f.url("/ui2/sitemap/children", "key", n.Key, "sel", b.sel),
		BranchURL:   f.url("/ui2/sitemap/children", "key", n.Key, "mode", "branch", "sel", b.sel),
		CollapseURL: f.url("/ui2/sitemap/children", "key", n.Key, "mode", "node", "sel", b.sel),
		SelectURL:   f.url("/ui2/sitemap/detail", "key", n.Key),
		PageURL:     f.url("/ui2/sitemap", "sel", n.Key),
		ScopeURL:    "/ui2/sitemap/scope/confirm?key=" + url.QueryEscape(n.Key),
		RepeaterURL: "/ui2/sitemap/repeater?key=" + url.QueryEscape(n.Key),
		ReviewURL:   "/ui2/sitemap/review/confirm?key=" + url.QueryEscape(n.Key) + "&op=",
		CommentsURL: "/ui2/sitemap?" + url.Values{"view": {"engagement"}, "kind": {"comments"}, "host": {host}}.Encode(),
		ScriptsURL:  "/ui2/sitemap?" + url.Values{"view": {"engagement"}, "kind": {"scripts"}, "host": {host}}.Encode(),
		RefsURL:     "/ui2/sitemap?" + url.Values{"view": {"engagement"}, "kind": {"references"}, "q": {full}}.Encode(),
		AnalyzeURL:  "/ui2/sitemap?" + analyze.Encode(),
	}
}

// ui2SitemapAncestors returns the keys on the path from a root down to key (inclusive).
func ui2SitemapAncestors(nodes []sitemapNodeView, key string) map[string]bool {
	out := map[string]bool{}
	var walk func(ns []sitemapNodeView) bool
	walk = func(ns []sitemapNodeView) bool {
		for i := range ns {
			if ns[i].Key == key || walk(ns[i].Children) {
				out[ns[i].Key] = true
				return true
			}
		}
		return false
	}
	walk(nodes)
	return out
}

func ui2SitemapCountShown(nodes []sitemapNodeView, f ui2SitemapFilter) int {
	n := 0
	for i := range nodes {
		if ui2SitemapMatches(&nodes[i], f) {
			n += 1 + ui2SitemapCountShown(nodes[i].Children, f)
		}
	}
	return n
}

// ui2SitemapModel is sitemap.html's model: the tree fragment (#rows), also re-rendered by the
// add-to-scope run step (ui2_sitemap_actions.go) with its outcome lines.
type ui2SitemapModel struct {
	Tree     sitemapTreeResp
	Rows     []ui2SitemapRow
	Narrowed bool
	Shown    int
	// Note and Done are row-action outcome lines: a refusal the operator must read, and the
	// landed fact. Both empty on the plain page render.
	Note string
	Done string
	OOB  bool // rendered as an out-of-band swap beside a review outcome
}

func (s *Server) ui2SitemapTreeModel(tree *sitemapTreeResp, f ui2SitemapFilter, sel string) ui2SitemapModel {
	b := &ui2SitemapBuild{f: f, sel: sel, openKeys: ui2SitemapAncestors(tree.Tree, sel), budget: ui2SitemapExpandCap}
	return ui2SitemapModel{
		Tree: *tree, Rows: b.rows(tree.Tree, 0, ""), Narrowed: f.Narrowed(), Shown: ui2SitemapCountShown(tree.Tree, f),
	}
}

// ui2SitemapFind returns the node with exactly this key, its host and depth.
func ui2SitemapFind(nodes []sitemapNodeView, key string) (*sitemapNodeView, string, int) {
	node, host := ui2SitemapFindNode(nodes, key)
	if node == nil {
		return nil, "", 0
	}
	depth := 0
	if strings.Contains(node.Key, "\x00") {
		depth = 1
	}
	return node, host, depth
}

// ---- GET /ui2/sitemap ------------------------------------------------------------------------

type ui2SitemapPage struct {
	View       string
	Filter     ui2SitemapFilter
	TypeOpts   []ui2SitemapOpt
	StatusOpts []ui2SitemapOpt
	Tree       ui2SitemapModel
	Detail     templateHTML
	Sub        templateHTML // the engagement / analyzer / paths view body
	URLsView   string
	PathsView  string
	EngView    string
	ClearURL   string
}

func ui2SitemapOpts(opts []ui2SitemapOpt, checked []string) []ui2SitemapOpt {
	out := make([]ui2SitemapOpt, len(opts))
	for i, o := range opts {
		o.Checked = false
		for _, c := range checked {
			if c == o.Value {
				o.Checked = true
			}
		}
		out[i] = o
	}
	return out
}

// handleUI2Sitemap serves GET /ui2/sitemap: the shell, or the page body for an htmx request.
func (s *Server) handleUI2Sitemap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	f := parseUI2SitemapFilter(q)
	page := ui2SitemapPage{
		View: q.Get("view"), Filter: f,
		TypeOpts: ui2SitemapOpts(ui2SitemapTypeOpts, f.Types), StatusOpts: ui2SitemapOpts(ui2SitemapStatusOpts, f.Statuses),
		URLsView: f.url("/ui2/sitemap"), PathsView: "/ui2/sitemap?view=paths", EngView: "/ui2/sitemap?view=engagement",
		ClearURL: "/ui2/sitemap",
	}
	switch page.View {
	case "engagement":
		page.Sub = ui2Exec("sitemap_engagement.html", s.ui2SitemapEngagement(q))
	case "analyzer":
		page.Sub = ui2Exec("sitemap_analyzer.html", s.ui2SitemapAnalyzer(q))
	case "paths":
		page.Sub = ui2Exec("sitemap_paths.html", s.ui2SitemapPaths(q.Get("run")))
	default:
		page.View = "urls"
		tree, errText := s.ui2SitemapSnapshot()
		if errText != "" {
			ui2Fragment(w, r, "burpsy /ui2/ — Site map", "sitemap", ui2Exec("error.html", ui2Error{Message: errText}))
			return
		}
		sel := q.Get("sel")
		page.Tree = s.ui2SitemapTreeModel(tree, f, sel)
		if sel != "" {
			page.Detail = ui2Exec("sitemap_detail.html", s.ui2SitemapDetail(tree, sel, q.Get("panel")))
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Site map", "sitemap", ui2Exec("sitemap_page.html", page))
}

// handleUI2SitemapChildren serves GET /ui2/sitemap/children?key=&mode=kids|branch|node.
func (s *Server) handleUI2SitemapChildren(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	key := q.Get("key")
	if key == "" {
		http.Error(w, "a site-map node key is required", http.StatusBadRequest)
		return
	}
	tree, errText := s.ui2SitemapSnapshot()
	if errText != "" {
		http.Error(w, errText, http.StatusInternalServerError)
		return
	}
	node, host, depth := ui2SitemapFind(tree.Tree, key)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if node == nil {
		_, _ = w.Write([]byte(ui2Exec("sitemap_rows.html", map[string]any{"Gone": true})))
		return
	}
	f := parseUI2SitemapFilter(q)
	b := &ui2SitemapBuild{f: f, sel: q.Get("sel"), openKeys: map[string]bool{}, budget: ui2SitemapExpandCap}
	switch q.Get("mode") {
	case "branch", "node":
		b.all = q.Get("mode") == "branch"
		row := b.row(node, depth, host)
		if row.HasKids && b.all {
			row.Open, row.Loaded = true, true
			row.Kids = b.rows(node.Children, depth+1, host)
		}
		_, _ = w.Write([]byte(ui2Exec("sitemap_rows.html", map[string]any{"Rows": []ui2SitemapRow{row}})))
	default:
		_, _ = w.Write([]byte(ui2Exec("sitemap_rows.html", map[string]any{"Rows": b.rows(node.Children, depth+1, host)})))
	}
}

// ---- node detail -----------------------------------------------------------------------------

type ui2SitemapExRow struct {
	ID                                      uint64
	Method, URL, Status, Mime, Comment, Age string
	Params                                  bool
	Length                                  int
	DurationMs                              uint64
	MsgURL                                  string
}

type ui2SitemapIssue struct {
	ID                   uint64
	Name, Severity, Host string
	TimesSeen            int
}

type ui2SitemapDetailModel struct {
	Error      string
	Key, Host  string
	Path, Kind string
	Label      string
	IsHost     bool
	Methods    []string
	Statuses   []int
	Rows       []ui2SitemapExRow
	Total      int
	Issues     []ui2SitemapIssue
	URLs       string
	URLCount   int
	Panel      string
	HistoryURL string
	ReviewURL  string
	Passive    ui2SitemapPrescan
	Eng        ui2SitemapRow
}

// ui2SitemapPrescan is the passive-sweep dialog's prediction for Burp's default filters.
type ui2SitemapPrescan struct {
	Extensions   string
	Items        int
	ExtRemoved   int
	NoParamItems int
}

// ui2SitemapNodeExchanges returns the exchanges under a node, newest first: same authority, and
// for a path node its own path or anything beneath it (pages/sitemap.tsx underNode).
func (s *Server) ui2SitemapNodeExchanges(node *sitemapNodeView, host string, isHost bool) []*core.Exchange {
	var out []*core.Exchange
	exs := s.store.Exchanges()
	for i := len(exs) - 1; i >= 0; i-- {
		ex := exs[i]
		if ex.Source.Isolated() || ex.Host != host || ex.Port != node.Port || ex.TLS != node.TLS {
			continue
		}
		if !isHost && !ui2SitemapUnder(ex.Path, node.Path) {
			continue
		}
		out = append(out, ex)
	}
	return out
}

func ui2SitemapTreePath(raw string) string {
	p, _, _ := strings.Cut(raw, "?")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

func ui2SitemapUnder(exPath, nodePath string) bool {
	p := ui2SitemapTreePath(exPath)
	np := ui2SitemapTreePath(nodePath)
	if np == "/" {
		return p == "/"
	}
	return p == np || strings.HasPrefix(p, np+"/")
}

func ui2SitemapOrigin(host string, port uint16, tls bool) string {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	if tls && port == 443 || !tls && port == 80 {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + strconv.Itoa(int(port))
}

func ui2SitemapAge(startedMs uint64) string {
	if startedMs == 0 {
		return ""
	}
	d := time.Since(time.UnixMilli(int64(startedMs)))
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s ago"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	}
	return strconv.Itoa(int(d.Hours()/24)) + "d ago"
}

// ui2SitemapDSLString quotes a value for the filter grammar's string literal.
func ui2SitemapDSLString(v string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}

const ui2SitemapTableCap = 500

// ui2SitemapIssuesFor reads /api/issues?summary=1 in-process and keeps the findings with an
// occurrence among the node's exchanges - the precise link the tree's severity dots summarise.
func (s *Server) ui2SitemapIssuesFor(ids map[core.ExchangeID]bool) []ui2SitemapIssue {
	rec := newRecorder()
	s.handleIssues(rec, newReq(http.MethodGet, "/api/issues?summary=1"))
	var resp struct {
		Findings []issueFindingView `json:"findings"`
	}
	if err := ui2DecodeJSON(rec.Body.Bytes(), &resp); err != nil {
		return nil
	}
	var out []ui2SitemapIssue
	for _, f := range resp.Findings {
		for _, o := range f.Occurrences {
			if ids[o.ExchangeID] {
				name := f.CheckName
				if f.IssueName != nil && *f.IssueName != "" {
					name = *f.IssueName
				}
				out = append(out, ui2SitemapIssue{ID: f.ID, Name: name, Severity: f.Severity, Host: f.Host, TimesSeen: f.TimesSeen})
				break
			}
		}
	}
	return out
}

func (s *Server) ui2SitemapDetail(tree *sitemapTreeResp, key, panel string) ui2SitemapDetailModel {
	node, host, depth := ui2SitemapFind(tree.Tree, key)
	if node == nil {
		return ui2SitemapDetailModel{Error: "that site-map node is gone - the map changed; choose another node"}
	}
	isHost := depth == 0
	m := ui2SitemapDetailModel{
		Key: key, Host: host, IsHost: isHost, Methods: node.Methods, Statuses: node.Statuses, Panel: panel,
		ReviewURL: "/ui2/sitemap/review/confirm?key=" + url.QueryEscape(key) + "&op=",
	}
	b := &ui2SitemapBuild{}
	m.Eng = b.row(node, depth, host)
	m.Label = host
	historyQ := "host = " + host
	switch {
	case isHost:
		m.Kind = "host"
	case node.Requested:
		m.Kind, m.Path, m.Label = "path", node.Path, host+node.Path
		historyQ += " AND path ~ " + ui2SitemapDSLString(node.Path)
	default:
		m.Kind, m.Path, m.Label = "folder (never requested directly)", node.Path, host+node.Path
		historyQ += " AND path ~ " + ui2SitemapDSLString(node.Path)
	}
	m.HistoryURL = "/ui2/history?" + url.Values{"q": {historyQ}}.Encode()
	exs := s.ui2SitemapNodeExchanges(node, host, isHost)
	m.Total = len(exs)
	ids := make(map[core.ExchangeID]bool, len(exs))
	seen := map[string]bool{}
	var urls []string
	m.Passive.Extensions = strings.Join(ui2SitemapBurpExtensions, ", ")
	hidden := map[string]bool{}
	for _, e := range ui2SitemapBurpExtensions {
		hidden[e] = true
	}
	origin := ui2SitemapOrigin(host, node.Port, node.TLS)
	for _, ex := range exs {
		ids[ex.ID] = true
		u := origin + ex.Path
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
		m.Passive.Items++
		if hidden[ui2SitemapPathExt(ex.Path)] {
			m.Passive.ExtRemoved++
		}
		if ui2SitemapParamCount(ex.Path) == 0 {
			m.Passive.NoParamItems++
		}
		if len(m.Rows) >= ui2SitemapTableCap {
			continue
		}
		m.Rows = append(m.Rows, ui2SitemapExRow{
			ID: uint64(ex.ID), Method: ex.Method, URL: ex.Path, Status: ui2StatusString(ex.Status),
			Mime: ex.Mime, Comment: ptrString(ex.Notes), Age: ui2SitemapAge(ex.StartedMs), Params: strings.Contains(ex.Path, "?"),
			Length: ex.ResponseLen, DurationMs: ex.Duration.Millis(),
			MsgURL: "/ui2/sitemap/message?id=" + strconv.FormatUint(uint64(ex.ID), 10),
		})
	}
	sort.Strings(urls)
	m.URLs, m.URLCount = strings.Join(urls, "\n"), len(urls)
	if len(ids) > 0 {
		m.Issues = s.ui2SitemapIssuesFor(ids)
	}
	return m
}

// handleUI2SitemapDetail serves GET /ui2/sitemap/detail?key=[&panel=passive|urls].
func (s *Server) handleUI2SitemapDetail(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var model ui2SitemapDetailModel
	if q.Get("key") == "" {
		model.Error = "Choose a host or path in the tree to see the requests captured under it."
	} else if tree, errText := s.ui2SitemapSnapshot(); errText != "" {
		model.Error = errText
	} else {
		model = s.ui2SitemapDetail(tree, q.Get("key"), q.Get("panel"))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("sitemap_detail.html", model)))
}

// ---- one exchange's messages ------------------------------------------------------------------

// handleUI2SitemapMessage serves GET /ui2/sitemap/message?id=N: the request/response panes.
func (s *Server) handleUI2SitemapMessage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id, err := strconv.ParseUint(q.Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "id must be an exchange id", http.StatusBadRequest)
		return
	}
	ex, err := s.store.GetExchange(core.ExchangeID(id))
	if err != nil {
		http.Error(w, "Exchange not found", http.StatusNotFound)
		return
	}
	m := ui2Detail{
		ID: uint64(ex.ID), Method: ex.Method, Host: ex.Host, Port: ex.Port, Path: ex.Path,
		Status: ui2StatusString(ex.Status), Mime: ex.Mime, ResponseLen: ex.ResponseLen, DurationMs: ex.Duration.Millis(),
	}
	if raw := requestMessageForExchange(s.store, ex); raw != nil {
		m.Request = string(raw)
	}
	if ex.Response != nil {
		if msg, err := s.store.Get(*ex.Response); err == nil {
			m.Response = string(msg.Raw())
		}
	}
	m.ReqPretty = q.Get("view_req") != "raw"
	m.RespPretty = q.Get("view_resp") != "raw"
	m.ReqPane = renderMessagePane(m.Request, true, m.ReqPretty)
	m.RespPane = renderMessagePane(m.Response, false, m.RespPretty)
	toggle := func(req, resp bool) string {
		v := url.Values{"id": {strconv.FormatUint(id, 10)}}
		if !req {
			v.Set("view_req", "raw")
		}
		if !resp {
			v.Set("view_resp", "raw")
		}
		return "/ui2/sitemap/message?" + v.Encode()
	}
	model := map[string]any{
		"D": m, "ReqToggle": toggle(!m.ReqPretty, m.RespPretty), "RespToggle": toggle(m.ReqPretty, !m.RespPretty),
		"Repeater": "/ui2/history/" + strconv.FormatUint(id, 10),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("sitemap_message.html", model)))
}

// ---- engagement tools -------------------------------------------------------------------------

var ui2SitemapEngKinds = []ui2SitemapOpt{{Value: "comments", Label: "Find comments"},
	{Value: "scripts", Label: "Find scripts"}, {Value: "references", Label: "Find references to…"}}

type ui2SitemapEngResult struct {
	Kind      string          `json:"kind"`
	Matches   int             `json:"matches"`
	Truncated bool            `json:"truncated"`
	Rows      []engagementRow `json:"rows"`
}

// ui2SitemapEngCall runs GET /api/engagement/{kind} in-process. kind is allowlisted first, and
// every value goes through url.Values, so nothing the operator types reaches the path raw.
func (s *Server) ui2SitemapEngCall(kind, term, host string) (ui2SitemapEngResult, string) {
	ok := false
	for _, k := range ui2SitemapEngKinds {
		ok = ok || k.Value == kind
	}
	if !ok {
		return ui2SitemapEngResult{}, "unknown search kind"
	}
	v := url.Values{"limit": {"200"}}
	if term != "" {
		v.Set("q", term)
	}
	if host != "" {
		v.Set("host", host)
	}
	req := newReq(http.MethodGet, "/api/engagement/"+url.PathEscape(kind)+"?"+v.Encode())
	req.SetPathValue("kind", kind)
	rec := newRecorder()
	s.handleEngagement(rec, req)
	if rec.Code != http.StatusOK {
		return ui2SitemapEngResult{}, strings.TrimSpace(rec.Body.String())
	}
	var res ui2SitemapEngResult
	if err := ui2DecodeJSON(rec.Body.Bytes(), &res); err != nil {
		return res, "unreadable search result: " + err.Error()
	}
	return res, ""
}

func (s *Server) ui2SitemapEngagement(q url.Values) map[string]any {
	kind := q.Get("kind")
	if kind == "" {
		kind = "comments"
	}
	term, host := strings.TrimSpace(q.Get("q")), strings.TrimSpace(q.Get("host"))
	model := map[string]any{"Kinds": ui2SitemapOpts(ui2SitemapEngKinds, []string{kind}), "Kind": kind, "Q": term, "Host": host}
	if kind == "references" && term == "" {
		model["Hint"] = "Type the URL to find references to, then search."
		return model
	}
	res, errText := s.ui2SitemapEngCall(kind, term, host)
	model["Error"], model["Result"] = errText, res
	v := url.Values{"kind": {kind}}
	if term != "" {
		v.Set("q", term)
	}
	if host != "" {
		v.Set("host", host)
	}
	model["CSV"] = "/ui2/sitemap/export?" + v.Encode()
	model["AllHosts"] = "/ui2/sitemap?" + url.Values{"view": {"engagement"}, "kind": {kind}, "q": {term}}.Encode()
	return model
}

// ui2SitemapCSVCell neutralises spreadsheet formula prefixes in captured text.
func ui2SitemapCSVCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// handleUI2SitemapExport serves GET /ui2/sitemap/export?kind=&q=&host=: the engagement results
// as CSV (the React view's Export CSV).
func (s *Server) handleUI2SitemapExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind := q.Get("kind")
	if kind == "" {
		kind = "comments"
	}
	res, errText := s.ui2SitemapEngCall(kind, strings.TrimSpace(q.Get("q")), strings.TrimSpace(q.Get("host")))
	if errText != "" {
		http.Error(w, errText, http.StatusBadRequest)
		return
	}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{"Exchange", "Host", "Port", "TLS", "Path", "Match"})
	for _, row := range res.Rows {
		tls := "no"
		if row.TLS {
			tls = "yes"
		}
		_ = cw.Write([]string{strconv.FormatUint(row.ExchangeID, 10), ui2SitemapCSVCell(row.Host), strconv.Itoa(int(row.Port)),
			tls, ui2SitemapCSVCell(row.Path), ui2SitemapCSVCell(row.Snippet)})
	}
	cw.Flush()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="engagement-`+kind+`.csv"`)
	_, _ = w.Write(buf.Bytes())
}

// ---- target analyzer --------------------------------------------------------------------------

func (s *Server) ui2SitemapAnalyzer(q url.Values) map[string]any {
	host := strings.TrimSpace(q.Get("host"))
	tab := q.Get("tab")
	switch tab {
	case "dynamic", "static", "parameters":
	default:
		tab = "summary"
	}
	model := map[string]any{"Host": host, "Path": q.Get("path"), "Tab": tab, "Param": q.Get("param")}
	if host == "" {
		return model
	}
	v := url.Values{"host": {host}}
	for _, k := range []string{"path", "port", "tls"} {
		if x := strings.TrimSpace(q.Get(k)); x != "" {
			v.Set(k, x)
		}
	}
	rec := newRecorder()
	s.handleTargetAnalyze(rec, newReq(http.MethodGet, "/api/target/analyze?"+v.Encode()))
	if rec.Code != http.StatusOK {
		model["Error"] = strings.TrimSpace(rec.Body.String())
		return model
	}
	var rep analyzerReport
	if err := ui2DecodeJSON(rec.Body.Bytes(), &rep); err != nil {
		model["Error"] = "unreadable analyzer report: " + err.Error()
		return model
	}
	model["Report"] = rep
	tabURL := func(t, param string) string {
		x := url.Values{"view": {"analyzer"}, "tab": {t}}
		for k, vs := range v {
			x[k] = vs
		}
		if param != "" {
			x.Set("param", param)
		}
		return "/ui2/sitemap?" + x.Encode()
	}
	tabs := []ui2SitemapOpt{
		{Value: tabURL("summary", ""), Label: "Summary", Checked: tab == "summary"},
		{Value: tabURL("dynamic", ""), Label: fmt.Sprintf("Dynamic URLs (%d)", rep.Summary.DynamicURLs), Checked: tab == "dynamic"},
		{Value: tabURL("static", ""), Label: fmt.Sprintf("Static URLs (%d)", rep.Summary.StaticURLs), Checked: tab == "static"},
		{Value: tabURL("parameters", ""), Label: fmt.Sprintf("Parameters (%d)", rep.Summary.UniqueParameterNames), Checked: tab == "parameters"},
	}
	model["Tabs"] = tabs
	params := make([]map[string]any, 0, len(rep.Parameters))
	for _, p := range rep.Parameters {
		params = append(params, map[string]any{"P": p, "URL": tabURL("parameters", p.Name), "Sel": p.Name == q.Get("param")})
		if p.Name == q.Get("param") {
			model["Selected"] = p
		}
	}
	model["Params"] = params
	v.Set("format", "html")
	model["Save"] = "/api/target/analyze?" + v.Encode()
	return model
}

// ---- crawl paths ------------------------------------------------------------------------------

type ui2SitemapFetch struct {
	URL         string `json:"url"`
	Method      string `json:"method"`
	Status      int    `json:"status"`
	Depth       int    `json:"depth"`
	DuplicateOf string `json:"duplicate_of"`
	Excluded    bool   `json:"retention_excluded"`
	FoundAt     string `json:"found_at"`
	LinkText    string `json:"link_text"`
}

type ui2SitemapPathNode struct {
	F     ui2SitemapFetch
	Label string
	Kids  []*ui2SitemapPathNode
}

type ui2SitemapRun struct {
	TaskID uint64   `json:"task_id"`
	Seeds  []string `json:"seeds"`
	State  string   `json:"state"`
	Kind   string   `json:"kind"`
	Report *struct {
		Fetches []ui2SitemapFetch `json:"fetches"`
	} `json:"report"`
}

// ui2SitemapPathTree is buildCrawlTree: seeds (no found_at), and orphans whose referrer this run
// did not retain - shown under their own heading, never re-parented. Descent is bounded by a
// visited set at render time, so a cycle in target-controlled data cannot hang the page.
func ui2SitemapPathTree(fetches []ui2SitemapFetch) (seeds, orphans []*ui2SitemapPathNode, placed int) {
	byURL := map[string]*ui2SitemapPathNode{}
	var order []*ui2SitemapPathNode
	for _, f := range fetches {
		if _, ok := byURL[f.URL]; ok {
			continue
		}
		label := f.URL
		if u, err := url.Parse(f.URL); err == nil && u.Host != "" {
			label = u.EscapedPath()
			if u.RawQuery != "" {
				label += "?" + u.RawQuery
			}
		}
		n := &ui2SitemapPathNode{F: f, Label: label}
		byURL[f.URL] = n
		order = append(order, n)
	}
	for _, n := range order {
		if n.F.FoundAt == "" {
			seeds = append(seeds, n)
			continue
		}
		if p := byURL[n.F.FoundAt]; p != nil && p != n {
			p.Kids = append(p.Kids, n)
		} else {
			orphans = append(orphans, n)
		}
	}
	return seeds, orphans, len(order)
}

func (s *Server) ui2SitemapPaths(runParam string) map[string]any {
	rec := newRecorder()
	s.handleCrawlGet(rec, newReq(http.MethodGet, "/api/crawl"))
	var resp struct {
		Crawls []ui2SitemapRun `json:"crawls"`
	}
	model := map[string]any{}
	if err := ui2DecodeJSON(rec.Body.Bytes(), &resp); err != nil {
		model["Error"] = "crawl runs unavailable: " + err.Error()
		return model
	}
	want, _ := strconv.ParseUint(runParam, 10, 64)
	var run *ui2SitemapRun
	runs := make([]map[string]any, 0, len(resp.Crawls))
	for i := range resp.Crawls {
		c := &resp.Crawls[i]
		has := c.Report != nil && len(c.Report.Fetches) > 0
		if run == nil && has && (want == 0 || c.TaskID == want) {
			run = c
		}
		runs = append(runs, map[string]any{"ID": c.TaskID, "State": c.State, "Kind": c.Kind, "Has": has,
			"URL": "/ui2/sitemap?view=paths&run=" + strconv.FormatUint(c.TaskID, 10)})
	}
	model["Runs"] = runs
	model["Any"] = len(resp.Crawls) > 0
	if run == nil {
		for _, c := range resp.Crawls {
			if c.State == "running" {
				model["Running"] = true
			}
		}
		return model
	}
	seeds, orphans, placed := ui2SitemapPathTree(run.Report.Fetches)
	seen := map[*ui2SitemapPathNode]bool{}
	var flat func(ns []*ui2SitemapPathNode, depth int, out *[]map[string]any)
	flat = func(ns []*ui2SitemapPathNode, depth int, out *[]map[string]any) {
		for _, n := range ns {
			if seen[n] {
				continue
			}
			seen[n] = true
			*out = append(*out, map[string]any{"N": n, "Indent": depth * 16, "Seed": n.F.FoundAt == ""})
			flat(n.Kids, depth+1, out)
		}
	}
	var seedRows, orphanRows []map[string]any
	flat(seeds, 0, &seedRows)
	flat(orphans, 0, &orphanRows)
	model["Run"], model["Placed"], model["SeedCount"] = run, placed, len(seeds)
	model["SeedRows"], model["OrphanRows"] = seedRows, orphanRows
	return model
}

// ---- pre-scan filters (lib/prescan-filters.ts) ------------------------------------------------

// ui2SitemapBurpExtensions is Burp's shipped hidden-extension list, verbatim from its wizard.
var ui2SitemapBurpExtensions = []string{"js", "gif", "jpg", "png", "ico", "css", "woff", "woff2", "ttf", "svg"}

var ui2SitemapExtRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)

func ui2SitemapParseExtensions(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		ext := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(part)), ".")
		if ui2SitemapExtRE.MatchString(ext) && !seen[ext] {
			seen[ext] = true
			out = append(out, ext)
		}
	}
	return out
}

// ui2SitemapPrescanExclude composes the sweep's exclude query: every clause MATCHES what to drop.
func ui2SitemapPrescanExclude(exts []string, noParams bool) string {
	var clauses []string
	if noParams {
		clauses = append(clauses, "params = 0")
	}
	if len(exts) > 0 {
		parts := make([]string, len(exts))
		for i, e := range exts {
			parts[i] = "extension = " + ui2SitemapDSLString(e)
		}
		clauses = append(clauses, "("+strings.Join(parts, " or ")+")")
	}
	switch len(clauses) {
	case 0:
		return ""
	case 1:
		return "not " + clauses[0]
	}
	return "not (" + strings.Join(clauses, " and ") + ")"
}

func ui2SitemapPathExt(p string) string {
	clean, _, _ := strings.Cut(p, "?")
	clean, _, _ = strings.Cut(clean, "#")
	last := clean[strings.LastIndex(clean, "/")+1:]
	dot := strings.LastIndex(last, ".")
	if dot <= 0 || dot == len(last)-1 {
		return ""
	}
	return strings.ToLower(last[dot+1:])
}

func ui2SitemapParamCount(p string) int {
	_, q, ok := strings.Cut(p, "?")
	if !ok || q == "" {
		return 0
	}
	n := 0
	for _, part := range strings.Split(q, "&") {
		if part != "" {
			n++
		}
	}
	return n
}

// ---- the review flow: delete / passive sweep / crawl -------------------------------------------

// ui2SitemapReviewCap bounds the held reviews, the cap the triage and session reviews use.
const ui2SitemapReviewCap = 8

type ui2SitemapReview struct {
	token     string // the review's own single-use token
	gateToken string // the confirm-gate token, when the route needs one
	method    string
	path      string
	body      []byte // the exact bytes dispatched on run
	op        string
	label     string
	expires   time.Time
}

type ui2SitemapCall struct {
	Method, Path, Op, Label, Explain string
	Body                             []byte
}

// ui2SitemapBuildCall builds the exact API call for one write against one node. Every identity
// fact comes from the live node, never from client fields; only the passive sweep's pre-scan
// filter is read from the form.
func ui2SitemapBuildCall(op string, node *sitemapNodeView, host string, isHost bool, form url.Values) (ui2SitemapCall, string) {
	marshal := func(v any) []byte { b, _ := json.Marshal(v); return b }
	scheme := "http"
	if node.TLS {
		scheme = "https"
	}
	label := host
	if !isHost {
		label = host + node.Path
	}
	switch op {
	case "delete-host", "delete-branch", "delete-item":
		kind := strings.TrimPrefix(op, "delete-")
		if (kind == "host") != isHost {
			return ui2SitemapCall{}, "delete " + kind + " does not apply to this row - a host row deletes the host, a path row its branch or item"
		}
		req := sitemapDeleteReq{Host: host, Port: node.Port, TLS: node.TLS, Kind: kind}
		if !isHost {
			req.Path = node.Path
		}
		return ui2SitemapCall{Method: http.MethodDelete, Path: "/api/sitemap", Op: op, Label: label, Body: marshal(req),
			Explain: "The " + kind + " leaves the site map and stays out, including for re-captured traffic on it. This is a view-level removal: the captured exchanges stay - HTTP history, findings and anything saved against them are untouched. A burpsy restart rebuilds the map from the store, so the rows return then."}, ""
	case "passive":
		exts := ui2SitemapParseExtensions(form.Get("extensions"))
		req := passiveBranchReq{Host: host, Port: node.Port, Exclude: ui2SitemapPrescanExclude(exts, form.Get("noparams") != "")}
		if !isHost {
			req.PathPrefix = node.Path
		}
		return ui2SitemapCall{Method: http.MethodPost, Path: "/api/scanner/passive-branch", Op: op, Label: label, Body: marshal(req),
			Explain: "Re-runs the passive checks over the exchanges already captured in this branch. Sends nothing to the target; it records findings. Out-of-scope exchanges are skipped under the current scope, and the result reports how many."}, ""
	case "crawl":
		seed := scheme + "://" + host + ":" + strconv.Itoa(int(node.Port)) + "/"
		retention := "host = " + host
		if !isHost {
			seed = scheme + "://" + host + ":" + strconv.Itoa(int(node.Port)) + node.Path
			p := node.Path
			if !strings.HasSuffix(p, "/") {
				p += "/"
			}
			retention = "path ~ " + ui2SitemapDSLString(p)
		}
		body := marshal(map[string]any{"seeds": []string{seed}, "retention_query": retention})
		return ui2SitemapCall{Method: http.MethodPost, Path: "/api/crawl", Op: op, Label: label, Body: body,
			Explain: "Starts a crawl that SENDS REQUESTS to the target from this seed, under the engagement scope and the default crawl bounds, keeping only what is still under this branch."}, ""
	}
	return ui2SitemapCall{}, "unknown site-map action"
}

// handleUI2SitemapReview routes POST /ui2/sitemap/review/{action}.
func (s *Server) handleUI2SitemapReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.PathValue("action") {
	case "confirm":
		s.ui2SitemapReviewConfirm(w, r)
	case "run":
		s.ui2SitemapReviewRun(w, r)
	default:
		s.ui2SitemapReviewSheet(w, map[string]any{"Error": "unknown site-map review action"})
	}
}

func (s *Server) ui2SitemapReviewSheet(w http.ResponseWriter, model map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("sitemap_review.html", model)))
}

func (s *Server) ui2SitemapReviewConfirm(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) { s.ui2SitemapReviewSheet(w, map[string]any{"Error": msg}) }
	q := r.URL.Query()
	if len(q["key"]) != 1 || len(q["op"]) != 1 || len(q) != 2 {
		fail("exactly one site-map node key and one action are required")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail("invalid form")
		return
	}
	for k, v := range r.PostForm {
		if q.Get("op") != "passive" || (k != "extensions" && k != "noparams") || len(v) != 1 {
			fail(k + " is not a permitted field for this action")
			return
		}
	}
	tree, errText := s.ui2SitemapSnapshot()
	if errText != "" {
		fail(errText)
		return
	}
	node, host, depth := ui2SitemapFind(tree.Tree, q.Get("key"))
	if node == nil || host == "" || node.Port == 0 {
		fail("that site-map node is gone - the map changed since the page loaded; reload and choose again")
		return
	}
	call, errText := ui2SitemapBuildCall(q.Get("op"), node, host, depth == 0, r.PostForm)
	if errText != "" {
		fail(errText)
		return
	}
	gateToken := ""
	_, risk, _ := routeRiskFor(call.Path)
	gated := needsConfirmation(risk)
	if gated {
		tok, _, mintErr := s.ui2MintConfirm(call.Path, call.Method, call.Path, call.Body)
		if mintErr != "" || tok == "" {
			fail("the confirmation gate refused to mint a review: " + mintErr)
			return
		}
		gateToken = tok
	}
	now := time.Now()
	count := 0
	s.ui2SitemapReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2SitemapReview); ok && now.After(e.expires) {
			s.ui2SitemapReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= ui2SitemapReviewCap {
		fail("too many site-map reviews are open at once - confirm or let some expire, then try again")
		return
	}
	id, err1 := randomHex(16)
	token, err2 := randomHex(16)
	if err1 != nil || err2 != nil {
		fail("could not create a review")
		return
	}
	s.ui2SitemapReviews.Store(id, ui2SitemapReview{token: token, gateToken: gateToken, method: call.Method, path: call.Path,
		body: call.Body, op: call.Op, label: call.Label, expires: now.Add(ConfirmTTL)})
	var pretty bytes.Buffer
	if json.Indent(&pretty, call.Body, "", "  ") != nil {
		pretty.Write(call.Body)
	}
	titles := map[string]string{"delete-host": "Delete host", "delete-branch": "Delete branch", "delete-item": "Delete this item only",
		"passive": "Passively scan branch", "crawl": "Actively scan branch (crawl)"}
	s.ui2SitemapReviewSheet(w, map[string]any{
		"Title": titles[call.Op], "Call": call, "BodyText": pretty.String(), "ReviewID": id, "Token": token, "Gated": gated,
		"Risk": string(risk), "Cancel": "/ui2/sitemap/detail?key=" + url.QueryEscape(q.Get("key")),
	})
}

func (s *Server) ui2SitemapReviewRun(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) { s.ui2SitemapReviewSheet(w, map[string]any{"Error": msg}) }
	if err := ui2SitemapFields(r, "review_id", "token"); err != nil {
		fail(err.Error())
		return
	}
	v, ok := s.ui2SitemapReviews.LoadAndDelete(r.PostFormValue("review_id"))
	entry, isReview := v.(ui2SitemapReview)
	if !ok || !isReview {
		fail("that review is unknown or was already used - review the action again")
		return
	}
	if time.Now().After(entry.expires) {
		fail("that review expired - review the action again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(r.PostFormValue("token"))) != 1 {
		fail("that review does not match this confirmation - review the action again")
		return
	}
	// The held bytes, verbatim: the gate token binds exactly these.
	req := newReq(entry.method, entry.path)
	req.Header.Set("Content-Type", "application/json")
	if entry.gateToken != "" {
		req.Header.Set(ConfirmHeader, entry.gateToken)
	}
	req.Body = ioNopCloser(strings.NewReader(string(entry.body)))
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := newRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		fail(fmt.Sprintf("%s %s refused (%d): %s", entry.method, entry.path, rec.Code, truncateForDisplay(strings.TrimSpace(rec.Body.String()), 400)))
		return
	}
	var result map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &result)
	var pretty bytes.Buffer
	if json.Indent(&pretty, rec.Body.Bytes(), "", "  ") != nil {
		pretty.Reset()
	}
	model := map[string]any{"Done": true, "Op": entry.op, "Label": entry.label, "ResultText": pretty.String()}
	switch entry.op {
	case "delete-host", "delete-branch", "delete-item":
		model["Message"] = fmt.Sprintf("Suppressed %s %s from the site map. The captured exchanges stay.", strings.TrimPrefix(entry.op, "delete-"), entry.label)
		if tree, errText := s.ui2SitemapSnapshot(); errText == "" {
			tm := s.ui2SitemapTreeModel(tree, ui2SitemapFilter{}, "")
			tm.OOB = true
			model["Tree"] = ui2Exec("sitemap.html", tm)
		}
	case "passive":
		model["Message"], _ = result["summary"].(string)
	case "crawl":
		if id, ok := result["task_id"].(float64); ok {
			model["Message"] = fmt.Sprintf("Crawl task #%d started from %s.", int64(id), entry.label)
			model["Watch"] = fmt.Sprintf("/ui2/scanner/crawl-watch?task=%d", int64(id))
		}
	}
	s.ui2SitemapReviewSheet(w, model)
}
