package web

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/organizer"
)

// ui2OrgFilter is the Organizer page's view state, carried in the GET query so a
// filtered view is bookmarkable, exportable and survives a live refresh. Filters follow
// the SPA (pages/organizer.tsx): an item whose exchange is gone cannot be judged, so it
// is exempt from every filter except the collection view, and the page counts it.
type ui2OrgFilter struct {
	InScope   bool
	Status    string // all|2xx|3xx|4xx|5xx|none
	Mime      string
	Tool      string
	Workflow  string
	Q         string
	Regex     bool
	Case      bool
	Negative  bool
	Ext       string
	Annotated bool
	View      string // all|0 (Inbox)|collection id
	Item      int    // selected item, 0 = none
	RawReq    bool
	RawResp   bool
}

var ui2OrgStatusClasses = []string{"all", "2xx", "3xx", "4xx", "5xx", "none"}
var ui2OrgWorkflows = []organizer.Status{organizer.StatusNew, organizer.StatusInProgress, organizer.StatusPostponed, organizer.StatusDone, organizer.StatusIgnored}
var ui2OrgHighlights = []string{"none", "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"}

const ui2OrgMaxTerm = 1000

func parseUI2OrgFilter(q url.Values) ui2OrgFilter {
	on := func(k string) bool { return q.Get(k) == "1" }
	f := ui2OrgFilter{
		InScope: on("in_scope"), Status: q.Get("status"), Mime: q.Get("mime"), Tool: q.Get("tool"),
		Workflow: q.Get("workflow"), Q: q.Get("q"), Regex: on("regex"), Case: on("case"),
		Negative: on("negative"), Ext: q.Get("ext"), Annotated: on("annotated"), View: q.Get("view"),
		RawReq: q.Get("view_req") == "raw", RawResp: q.Get("view_resp") == "raw",
	}
	if len(f.Q) > ui2OrgMaxTerm {
		f.Q = f.Q[:ui2OrgMaxTerm]
	}
	known := false
	for _, s := range ui2OrgStatusClasses {
		known = known || f.Status == s
	}
	if !known {
		f.Status = "all"
	}
	if !organizer.ValidStatus(organizer.Status(f.Workflow)) {
		f.Workflow = "all"
	}
	for _, p := range []*string{&f.Mime, &f.Tool, &f.Ext} {
		if *p == "" {
			*p = "all"
		}
	}
	if n, err := strconv.Atoi(f.View); err != nil || n < 0 {
		f.View = "all"
	}
	if n, err := strconv.Atoi(q.Get("item")); err == nil && n > 0 {
		f.Item = n
	}
	return f
}

// values encodes the non-default filter state; withItem adds the selection and pane toggles.
func (f ui2OrgFilter) values(withItem bool) url.Values {
	v := url.Values{}
	set := func(k, val, def string) {
		if val != def {
			v.Set(k, val)
		}
	}
	flag := func(k string, b bool) {
		if b {
			v.Set(k, "1")
		}
	}
	flag("in_scope", f.InScope)
	set("status", f.Status, "all")
	set("mime", f.Mime, "all")
	set("tool", f.Tool, "all")
	set("workflow", f.Workflow, "all")
	set("q", f.Q, "")
	flag("regex", f.Regex)
	flag("case", f.Case)
	flag("negative", f.Negative)
	set("ext", f.Ext, "all")
	flag("annotated", f.Annotated)
	set("view", f.View, "all")
	if withItem && f.Item > 0 {
		v.Set("item", strconv.Itoa(f.Item))
		if f.RawReq {
			v.Set("view_req", "raw")
		}
		if f.RawResp {
			v.Set("view_resp", "raw")
		}
	}
	return v
}

func (f ui2OrgFilter) href(path string, withItem bool) string {
	if e := f.values(withItem).Encode(); e != "" {
		return path + "?" + e
	}
	return path
}

func (f ui2OrgFilter) filtering() bool {
	return f.InScope || f.Status != "all" || f.Mime != "all" || f.Tool != "all" || f.Workflow != "all" ||
		strings.TrimSpace(f.Q) != "" || f.Ext != "all" || f.Annotated
}

func ui2OrgMime(it organizerItemView) string {
	if it.Mime != "" {
		return it.Mime
	}
	return "(none declared)"
}

var ui2OrgExtRe = regexp.MustCompile(`^[a-z0-9]{1,10}$`)

// ui2OrgExtension is the lowercased file extension of the last path segment, "" when none.
func ui2OrgExtension(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	last := path[strings.LastIndex(path, "/")+1:]
	dot := strings.LastIndex(last, ".")
	if dot <= 0 {
		return ""
	}
	ext := strings.ToLower(last[dot+1:])
	if !ui2OrgExtRe.MatchString(ext) {
		return ""
	}
	return ext
}

func ui2OrgWorkflow(it organizer.Item) organizer.Status {
	if it.Status == "" {
		return organizer.StatusNew
	}
	return it.Status
}

func ui2OrgAnnotated(it organizer.Item) bool {
	h := strings.ToLower(strings.TrimSpace(it.Highlight))
	return strings.TrimSpace(it.Note) != "" || (h != "" && h != "none")
}

// ui2OrgOptions derives the MIME, tool and extension choices from the saved rows, so a
// filter can only offer values something carries.
func ui2OrgOptions(items []organizerItemView) (mimes, tools, exts []string) {
	m, t, e := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, it := range items {
		if !it.Resolved {
			continue
		}
		if it.HasResponse {
			m[ui2OrgMime(it)] = true
		}
		if it.Tool != "" {
			t[it.Tool] = true
		}
		if x := ui2OrgExtension(it.Path); x != "" {
			e[x] = true
		}
	}
	keys := func(s map[string]bool) []string {
		out := make([]string, 0, len(s))
		for k := range s {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return keys(m), keys(t), keys(e)
}

// ui2OrgApply returns the visible rows and how many were kept only because they could not
// be judged. termErr is set when a regex does not compile; such a term matches nothing.
func ui2OrgApply(items []organizerItemView, f ui2OrgFilter) (visible []organizerItemView, unjudged int, termErr string) {
	var re *regexp.Regexp
	term := strings.TrimSpace(f.Q) != ""
	if term && f.Regex {
		pat := f.Q
		if !f.Case {
			pat = "(?i)" + pat
		}
		var err error
		if re, err = regexp.Compile(pat); err != nil {
			termErr = "search regex does not compile, so it matches nothing: " + err.Error()
		}
	}
	for _, it := range items {
		if f.View != "all" && strconv.Itoa(it.Collection) != f.View {
			continue
		}
		if !it.Resolved {
			visible = append(visible, it)
			unjudged++
			continue
		}
		if f.InScope && (it.InScope == nil || !*it.InScope) {
			continue
		}
		switch f.Status {
		case "all":
		case "none":
			if it.HasResponse {
				continue
			}
		default:
			if it.Status == nil || fmt.Sprintf("%dxx", *it.Status/100) != f.Status {
				continue
			}
		}
		if f.Mime != "all" && (!it.HasResponse || ui2OrgMime(it) != f.Mime) {
			continue
		}
		if f.Tool != "all" && it.Tool != f.Tool {
			continue
		}
		if f.Workflow != "all" && string(ui2OrgWorkflow(it.Item)) != f.Workflow {
			continue
		}
		if term {
			hay := strings.Join([]string{it.Title, it.Note, it.Host, it.Path, it.Method}, "\n")
			var hit bool
			switch {
			case f.Regex:
				hit = re != nil && re.MatchString(hay)
			case f.Case:
				hit = strings.Contains(hay, f.Q)
			default:
				hit = strings.Contains(strings.ToLower(hay), strings.ToLower(f.Q))
			}
			if hit == f.Negative {
				continue
			}
		}
		if f.Ext != "all" && ui2OrgExtension(it.Path) != f.Ext {
			continue
		}
		if f.Annotated && !ui2OrgAnnotated(it.Item) {
			continue
		}
		visible = append(visible, it)
	}
	return visible, unjudged, termErr
}

func ui2OrgContains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// ui2OrgCopyName suggests a free "name (copy)" for a duplicate.
func ui2OrgCopyName(name string, collections []organizer.Collection) string {
	taken := map[string]bool{}
	for _, c := range collections {
		taken[c.Name] = true
	}
	cand := name + " (copy)"
	for n := 2; taken[cand] && n <= len(collections)+2; n++ {
		cand = fmt.Sprintf("%s (copy %d)", name, n)
	}
	return cand
}

// ui2OrgHistoryQuery builds a History filter naming one exchange's method, host and path.
func ui2OrgHistoryQuery(it organizerItemView) string {
	quote := func(s string) string {
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`, "\r", `\r`)
		return `"` + r.Replace(s) + `"`
	}
	q := "host = " + quote(it.Host) + " and method = " + quote(it.Method) + " and path = " + quote(it.Path)
	return "/ui2/history?" + url.Values{"q": {q}}.Encode()
}

// ui2OrganizerView builds the whole page model for one filter state.
func (s *Server) ui2OrganizerView(note string, f ui2OrgFilter) map[string]any {
	collections := s.organizer.Collections()
	names := map[int]string{0: "Inbox"}
	for _, c := range collections {
		names[c.ID] = c.Name
	}
	all := s.organizerView()
	mimes, tools, exts := ui2OrgOptions(all)
	// A filter pinned to a value nothing carries any more falls back to all, as in the SPA.
	if f.Mime != "all" && !ui2OrgContains(mimes, f.Mime) {
		f.Mime = "all"
	}
	if f.Tool != "all" && !ui2OrgContains(tools, f.Tool) {
		f.Tool = "all"
	}
	if f.Ext != "all" && !ui2OrgContains(exts, f.Ext) {
		f.Ext = "all"
	}
	if f.View != "all" {
		if _, ok := names[atoiOr(f.View, -1)]; !ok {
			f.View = "all"
		}
	}
	counts := map[int]int{}
	for _, it := range all {
		counts[it.Collection]++
	}
	visible, unjudged, termErr := ui2OrgApply(all, f)
	collectionName := func(id int) string {
		if n, ok := names[id]; ok {
			return n
		}
		return fmt.Sprintf("Unknown collection #%d", id)
	}
	rows := make([]map[string]any, 0, len(visible))
	for _, it := range visible {
		sel := f
		sel.Item, sel.RawReq, sel.RawResp = it.ID, false, false
		rows = append(rows, map[string]any{
			"item": it, "collection_name": collectionName(it.Collection), "workflow": ui2OrgWorkflow(it.Item),
			"href": sel.href("/ui2/organizer", true), "selected": it.ID == f.Item,
		})
	}
	cards := make([]map[string]any, 0, len(collections))
	for _, c := range collections {
		v := f
		v.View, v.Item = strconv.Itoa(c.ID), 0
		cards = append(cards, map[string]any{
			"id": c.ID, "name": c.Name, "note": c.Note, "count": counts[c.ID], "base": ui2CollectionDigest(c),
			"members_base": ui2MembersDigest(s.organizer.Members(c.ID)), "copy_name": ui2OrgCopyName(c.Name, collections),
			"view_href": v.href("/ui2/organizer", false), "viewing": f.View == strconv.Itoa(c.ID),
		})
	}
	inbox, allView := f, f
	inbox.View, inbox.Item = "0", 0
	allView.View, allView.Item = "all", 0
	clear := ui2OrgFilter{Status: "all", Mime: "all", Tool: "all", Workflow: "all", Ext: "all", View: f.View}
	model := map[string]any{
		"items": rows, "collections": cards, "inbox_count": counts[0], "note": note, "total": len(all),
		"filter": f, "filtering": f.filtering(), "unjudged": unjudged, "term_error": termErr,
		"mimes": mimes, "tools": tools, "exts": exts, "status_classes": ui2OrgStatusClasses, "workflows": ui2OrgWorkflows,
		"query": f.values(true).Encode(), "filter_query": f.values(false).Encode(), "export_href": f.href("/ui2/organizer/export.csv", false),
		"inbox_href": inbox.href("/ui2/organizer", false), "all_href": allView.href("/ui2/organizer", false),
		"clear_href": clear.href("/ui2/organizer", false), "view_name": "All saved items",
	}
	if f.View != "all" {
		model["view_name"] = collectionName(atoiOr(f.View, 0))
	}
	if f.Item > 0 {
		for _, it := range all {
			if it.ID == f.Item {
				model["detail"] = s.ui2OrgDetail(it, f, collectionName(it.Collection), collections)
				break
			}
		}
		if model["detail"] == nil {
			model["detail_missing"] = f.Item
		}
	}
	return model
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// ui2OrgDetail is the selected item's pane: request/response read from the traffic store
// by the view's message ids, and the review forms bound to the item's stored snapshot.
func (s *Server) ui2OrgDetail(it organizerItemView, f ui2OrgFilter, collection string, collections []organizer.Collection) map[string]any {
	d := map[string]any{
		"item": it, "collection_name": collection, "workflow": ui2OrgWorkflow(it.Item), "base": ui2WorkflowDigest(it.Item),
		"highlights": ui2OrgHighlights, "workflows": ui2OrgWorkflows, "collections": collections,
		"req_pretty": !f.RawReq, "resp_pretty": !f.RawResp,
	}
	if !it.Resolved {
		return d
	}
	d["history_href"] = ui2OrgHistoryQuery(it)
	d["scope"] = "out of scope"
	if it.InScope != nil && *it.InScope {
		d["scope"] = "in scope"
	}
	toggle := func(raw bool, isReq bool) string {
		g := f
		if isReq {
			g.RawReq = raw
		} else {
			g.RawResp = raw
		}
		return g.href("/ui2/organizer", true)
	}
	d["req_pretty_href"], d["req_raw_href"] = toggle(false, true), toggle(true, true)
	d["resp_pretty_href"], d["resp_raw_href"] = toggle(false, false), toggle(true, false)
	if it.Request != nil {
		if msg, err := s.store.Get(core.MsgId(*it.Request)); err == nil {
			d["request"] = renderMessagePane(string(msg.Raw()), true, !f.RawReq)
		}
	}
	if it.Response != nil {
		if msg, err := s.store.Get(core.MsgId(*it.Response)); err == nil {
			d["response"] = renderMessagePane(string(msg.Raw()), false, !f.RawResp)
		}
	}
	return d
}

func (s *Server) ui2OrganizerRender(w http.ResponseWriter, r *http.Request, note string) {
	f := parseUI2OrgFilter(nil)
	if r.Method == http.MethodGet {
		f = parseUI2OrgFilter(r.URL.Query())
	}
	s.ui2OrganizerRenderFilter(w, r, note, f)
}

// ui2OrganizerRenderItem re-renders after an item write with that item still selected.
func (s *Server) ui2OrganizerRenderItem(w http.ResponseWriter, r *http.Request, note string, item int) {
	f := parseUI2OrgFilter(nil)
	f.Item = item
	s.ui2OrganizerRenderFilter(w, r, note, f)
}

func (s *Server) ui2OrganizerRenderFilter(w http.ResponseWriter, r *http.Request, note string, f ui2OrgFilter) {
	ui2Fragment(w, r, "burpsy /ui2/ - Organizer", "organizer", ui2Exec("organizer.html", s.ui2OrganizerView(note, f)))
}

// ui2OrgCSVCell quotes one cell and guards a leading formula character, as the SPA's csvCell.
func ui2OrgCSVCell(v string) string {
	if v != "" && strings.ContainsRune("+-=@", rune(v[0])) {
		v = "'" + v
	}
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

// handleUI2OrganizerExport serves GET /ui2/organizer/export.csv: the filtered view as CSV,
// with the SPA's organizerToCSV columns. Read-only.
func (s *Server) handleUI2OrganizerExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f := parseUI2OrgFilter(r.URL.Query())
	all := s.organizerView()
	mimes, tools, exts := ui2OrgOptions(all)
	if !ui2OrgContains(mimes, f.Mime) {
		f.Mime = "all"
	}
	if !ui2OrgContains(tools, f.Tool) {
		f.Tool = "all"
	}
	if !ui2OrgContains(exts, f.Ext) {
		f.Ext = "all"
	}
	visible, _, _ := ui2OrgApply(all, f)
	lines := []string{strings.Join([]string{ui2OrgCSVCell("ID"), ui2OrgCSVCell("Title"), ui2OrgCSVCell("Note"), ui2OrgCSVCell("Highlight"), ui2OrgCSVCell("Status"), ui2OrgCSVCell("Exchange")}, ",")}
	for _, it := range visible {
		lines = append(lines, strings.Join([]string{
			ui2OrgCSVCell(strconv.Itoa(it.ID)), ui2OrgCSVCell(it.Title), ui2OrgCSVCell(it.Note), ui2OrgCSVCell(it.Highlight),
			ui2OrgCSVCell(string(ui2OrgWorkflow(it.Item))), ui2OrgCSVCell(strconv.Itoa(it.Exchange)),
		}, ","))
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="organizer.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(strings.Join(lines, "\n")))
}
