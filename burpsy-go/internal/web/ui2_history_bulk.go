package web

// ui2 History toolbar, filters and bulk actions (migration unit 4).
//
// The React History page filters, exports, imports, clears and acts on a multi-row selection; the
// /ui2/ History view rendered rows only. This file adds the same surface server-side:
//
//   - Filters (status / MIME buckets, method, in-scope, hide no-response, parameterized, commented,
//     highlighted, listener ports, show-only / hide extensions, row limit) applied before the page
//     slice, so paging, CSV export and live refresh all see the same set.
//   - Toolbar: export CSV (the SPA's historyToCSV columns and formula guard), import HAR (riskLocal,
//     one click), go to entry, clear history (gated review).
//   - Bulk actions on the selected ids: compare the first two, copy URLs, add to Organizer
//     (riskLocal, one click), add hosts to scope (server-held review: one gate token per host held
//     server-side), audit selected and delete selected (gate review: the run step rebuilds the body
//     from the reviewed id list, so an edited list fails the token digest).
//   - Extractor columns: a manager page over /api/history/extractors, values via
//     /api/history/extract shown as extra row columns.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- filters ---------------------------------------------------------------------------------

// The SPA's closed filter vocabularies (history.tsx STATUS_BUCKETS / MIME_TYPES / METHODS).
var (
	ui2HistoryStatusBuckets = []ui2Opt{{"2", "2xx"}, {"3", "3xx"}, {"4", "4xx"}, {"5", "5xx"}, {"none", "no response"}}
	ui2HistoryMimeBuckets   = []ui2Opt{{"html", "HTML"}, {"json", "JSON"}, {"xml", "XML"}, {"javascript", "JavaScript"}, {"css", "CSS"}, {"image", "Images"}, {"binary", "Binary"}}
	ui2HistoryMethods       = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	ui2HistoryLimits        = []int{50, 100, 200, 500}
)

type ui2Opt struct{ Value, Label string }

// ui2Hidden is one hidden field a review sheet carries to its run step.
type ui2Hidden struct{ Name, Value string }

// ui2HistoryFilters is the row-type filter state. Every field round-trips through the URL.
type ui2HistoryFilters struct {
	Status      []string
	Mime        []string
	Method      string
	ScopeOnly   bool
	HideNoResp  bool
	Params      bool
	Commented   bool
	Highlighted bool
	Listener    string
	ShowExt     string
	HideExt     string
}

// ui2ListValues reads a multi-valued field that may arrive repeated (a form's checkboxes) or
// comma-joined (the infinite-scroll sentinel's hx-vals), keeping only allowed values.
func ui2ListValues(q url.Values, key string, allowed []ui2Opt) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range q[key] {
		for _, v := range strings.Split(raw, ",") {
			v = strings.TrimSpace(v)
			for _, a := range allowed {
				if a.Value == v && !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
			}
		}
	}
	return out
}

func ui2Truthy(v string) bool { return v == "1" || v == "on" || v == "true" }

func parseUI2HistoryFilters(q url.Values) ui2HistoryFilters {
	f := ui2HistoryFilters{
		Status:      ui2ListValues(q, "status", ui2HistoryStatusBuckets),
		Mime:        ui2ListValues(q, "mime", ui2HistoryMimeBuckets),
		ScopeOnly:   ui2Truthy(q.Get("scope_only")),
		HideNoResp:  ui2Truthy(q.Get("hide_noresp")),
		Params:      ui2Truthy(q.Get("params")),
		Commented:   ui2Truthy(q.Get("commented")),
		Highlighted: ui2Truthy(q.Get("highlighted")),
		Listener:    strings.TrimSpace(q.Get("listener")),
		ShowExt:     strings.TrimSpace(q.Get("show_ext")),
		HideExt:     strings.TrimSpace(q.Get("hide_ext")),
	}
	for _, m := range ui2HistoryMethods {
		if q.Get("method") == m {
			f.Method = m
		}
	}
	return f
}

// values is the filter state as query fields (only the non-default ones).
func (f ui2HistoryFilters) values() map[string]string {
	m := map[string]string{}
	set := func(k string, on bool) {
		if on {
			m[k] = "1"
		}
	}
	if len(f.Status) > 0 {
		m["status"] = strings.Join(f.Status, ",")
	}
	if len(f.Mime) > 0 {
		m["mime"] = strings.Join(f.Mime, ",")
	}
	if f.Method != "" {
		m["method"] = f.Method
	}
	set("scope_only", f.ScopeOnly)
	set("hide_noresp", f.HideNoResp)
	set("params", f.Params)
	set("commented", f.Commented)
	set("highlighted", f.Highlighted)
	for k, v := range map[string]string{"listener": f.Listener, "show_ext": f.ShowExt, "hide_ext": f.HideExt} {
		if v != "" {
			m[k] = v
		}
	}
	return m
}

// Active counts the filters that narrow the view (for the summary label).
func (f ui2HistoryFilters) Active() int { return len(f.values()) }

// ui2ExtList normalises an extension list the SPA's way: lower-cased, one leading dot stripped,
// blanks dropped, so "PNG", ".png" and " png " are one entry.
func ui2ExtList(raw string) map[string]bool {
	out := map[string]bool{}
	for _, e := range strings.Split(raw, ",") {
		e = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), ".")
		if e != "" {
			out[e] = true
		}
	}
	return out
}

// ui2ListenerPorts parses "8080, 8081": digits only; zero is not a listener and never matches.
func ui2ListenerPorts(raw string) map[uint16]bool {
	out := map[uint16]bool{}
	for _, v := range strings.Split(raw, ",") {
		if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 16); err == nil && n > 0 {
			out[uint16(n)] = true
		}
	}
	return out
}

// ui2PathExt is the extension of a path's last segment, lower-cased, or "" (csvExtension).
func ui2PathExt(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	seg := path[strings.LastIndexByte(path, '/')+1:]
	dot := strings.LastIndexByte(seg, '.')
	if dot > 0 && dot < len(seg)-1 {
		return strings.ToLower(seg[dot+1:])
	}
	return ""
}

// ui2PathQueryCount counts query parameters; a bare "?" is zero (csvQueryCount).
func ui2PathQueryCount(path string) int {
	i := strings.IndexByte(path, '?')
	if i < 0 {
		return 0
	}
	n := 0
	for _, pair := range strings.Split(path[i+1:], "&") {
		if pair != "" {
			n++
		}
	}
	return n
}

// ui2MimeMatches is the SPA's mimeMatches: an untyped row matches no bucket.
func ui2MimeMatches(mime, bucket string) bool {
	if mime == "" {
		return false
	}
	m := strings.ToLower(mime)
	if bucket == "binary" {
		for _, t := range []string{"text", "json", "xml", "javascript", "css", "html"} {
			if strings.Contains(m, t) {
				return false
			}
		}
		return true
	}
	return strings.Contains(m, bucket)
}

// ui2HistoryFilterFunc compiles the filter state into one row predicate.
func (s *Server) ui2HistoryFilterFunc(f ui2HistoryFilters) func(*core.Exchange) bool {
	showExt, hideExt := ui2ExtList(f.ShowExt), ui2ExtList(f.HideExt)
	ports := ui2ListenerPorts(f.Listener)
	return func(ex *core.Exchange) bool {
		if f.Method != "" && ex.Method != f.Method {
			return false
		}
		if len(f.Mime) > 0 {
			hit := false
			for _, b := range f.Mime {
				hit = hit || ui2MimeMatches(ex.Mime, b)
			}
			if !hit {
				return false
			}
		}
		if len(f.Status) > 0 {
			bucket := "none"
			if ex.Status != nil {
				bucket = strconv.Itoa(int(*ex.Status))[:1]
			}
			hit := false
			for _, b := range f.Status {
				hit = hit || b == bucket
			}
			if !hit {
				return false
			}
		}
		if f.HideNoResp && ex.Response == nil {
			return false
		}
		// The scope is server state: asked here, as the Organizer view does, never re-decided.
		if f.ScopeOnly && s.scope != nil && !s.scope.Contains(ex.Host, ex.Port, ex.Path, ex.TLS) {
			return false
		}
		if f.Params && ex.RequestParams <= 0 {
			return false
		}
		if len(ports) > 0 && !ports[ex.ListenerPort] {
			return false
		}
		if f.Commented && (ex.Notes == nil || strings.TrimSpace(*ex.Notes) == "") {
			return false
		}
		if f.Highlighted && ex.Highlight == "" {
			return false
		}
		ext := ui2PathExt(ex.Path)
		if len(showExt) > 0 && !showExt[ext] {
			return false
		}
		if len(hideExt) > 0 && hideExt[ext] {
			return false
		}
		return true
	}
}

// ui2HistoryMatched is every proxy-history row the view's state selects, newest first, plus the
// store's total. Shared by the paged rows and the CSV export so the two cannot disagree.
func (s *Server) ui2HistoryMatched(p ui2HistoryParams) ([]*core.Exchange, int, error) {
	exchanges := s.store.Exchanges()
	var filter *queryFilter
	if p.Q != "" {
		f, err := compileQuery(p.Q, s.store)
		if err != nil {
			return nil, len(exchanges), err
		}
		filter = f
	}
	keep := s.ui2HistoryFilterFunc(p.F)
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
		if !keep(ex) {
			continue
		}
		matched = append(matched, ex)
	}
	return matched, len(exchanges), nil
}

// ColSpan is the rows table's column count (13 fixed plus one per extractor).
func (h ui2HistoryRows) ColSpan() int { return 13 + len(h.Extractors) }

// ---- toolbar ---------------------------------------------------------------------------------

// ui2HistoryCol is one column the chooser can hide; Key is the cell class suffix (c-<key>).
type ui2HistoryCol struct {
	Key, Label string
	Default    bool // shown by default
}

var ui2HistoryBaseCols = []ui2HistoryCol{
	{"method", "Method", true}, {"host", "Host", true}, {"path", "Path", true}, {"status", "Status", true},
	{"mime", "MIME", true}, {"len", "Length", true}, {"time", "Time", true}, {"ext", "Extension", false},
	{"params", "Params", false}, {"listener", "Listener", false}, {"comment", "Comment", false}, {"title", "Title", false},
}

// ui2HistoryToolbar renders the toolbar (bulk bar, tools, filters, columns). It sits outside
// #rows, so its form state survives every rows swap.
func (s *Server) ui2HistoryToolbar(p ui2HistoryParams) templateHTML {
	cols := append([]ui2HistoryCol(nil), ui2HistoryBaseCols...)
	defs, _ := s.historyExtractors()
	for i, d := range defs {
		cols = append(cols, ui2HistoryCol{Key: "x" + strconv.Itoa(i), Label: d.Name, Default: true})
	}
	in := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	type check struct {
		Value, Label string
		On           bool
	}
	var status, mime []check
	for _, o := range ui2HistoryStatusBuckets {
		status = append(status, check{o.Value, o.Label, in(p.F.Status, o.Value)})
	}
	for _, o := range ui2HistoryMimeBuckets {
		mime = append(mime, check{o.Value, o.Label, in(p.F.Mime, o.Value)})
	}
	return ui2Exec("history_toolbar.html", map[string]any{
		"f": p.F, "limit": p.Limit, "limits": ui2HistoryLimits, "methods": ui2HistoryMethods,
		"status": status, "mime": mime, "cols": cols,
	})
}

// ---- export CSV --------------------------------------------------------------------------------

// ui2CSVCell is the SPA's csvCell: always quoted, quotes doubled, and a leading + - = @ prefixed
// with ' so a captured host or path cannot run as a spreadsheet formula.
func ui2CSVCell(v string) string {
	if v != "" && strings.ContainsRune("+-=@", rune(v[0])) {
		v = "'" + v
	}
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

// handleUI2HistoryExport serves GET /ui2/history/export.csv: the rows the view's current state
// selects (all of them, not one page), in historyToCSV's columns. Index data only, never bodies.
func (s *Server) handleUI2HistoryExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := parseUI2HistoryParams(r)
	matched, _, err := s.ui2HistoryMatched(p)
	if err != nil {
		http.Error(w, "the filter query does not compile: "+err.Error(), http.StatusBadRequest)
		return
	}
	lines := make([]string, 0, len(matched)+1)
	head := []string{"ID", "Timestamp", "Method", "Host", "Port", "Path", "Extension", "Query", "TLS", "Edited", "Status", "Length", "MIME", "Duration", "Comment"}
	cells := func(vs []string) string {
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = ui2CSVCell(v)
		}
		return strings.Join(out, ",")
	}
	lines = append(lines, cells(head))
	for _, ex := range matched {
		v := exchangeView(ex)
		status := ""
		if v.Status != nil {
			status = strconv.Itoa(int(*v.Status))
		}
		lines = append(lines, cells([]string{
			strconv.FormatUint(uint64(v.ID), 10),
			time.UnixMilli(int64(v.StartedMs)).UTC().Format("2006-01-02T15:04:05.000Z"),
			v.Method, v.Host, strconv.Itoa(int(v.Port)), v.Path, ui2PathExt(v.Path),
			strconv.Itoa(ui2PathQueryCount(v.Path)), ui2YesNo(v.TLS), ui2YesNo(v.Variants.Edited),
			status, strconv.Itoa(v.ResponseLen), v.Mime, strconv.FormatUint(v.DurationMs, 10), ptrString(v.Notes),
		}))
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="history.csv"`)
	_, _ = io.WriteString(w, strings.Join(lines, "\n"))
}

func ui2YesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ---- import HAR ------------------------------------------------------------------------------

// handleUI2HistoryImport serves POST /ui2/history/import: a multipart HAR upload handed verbatim
// to /api/history/import/har (riskLocal: it records, it never replays, so one click is the step).
func (s *Server) handleUI2HistoryImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := func(model map[string]any) {
		ui2Fragment(w, r, "burpsy /ui2/ — History", "history", ui2Exec("history_bulk_result.html", model))
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxHARImportBytes+1<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		result(map[string]any{"error": "choose a .har file to import (the upload was not a readable multipart form)"})
		return
	}
	file, _, err := r.FormFile("har")
	if err != nil {
		result(map[string]any{"error": "choose a .har file to import"})
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxHARImportBytes+1))
	if err != nil || len(raw) > maxHARImportBytes {
		result(map[string]any{"error": "the HAR file could not be read or exceeds the import size limit"})
		return
	}
	req := newReq(http.MethodPost, "/api/history/import/har")
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(raw)))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		result(map[string]any{"error": "the import was refused: " + truncateForDisplay(strings.TrimSpace(rec.Body.String()), 300)})
		return
	}
	var out harImportResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		result(map[string]any{"error": "unreadable import response: " + err.Error()})
		return
	}
	w.Header().Set("HX-Trigger", "burpsy-history-changed")
	result(map[string]any{
		"done":  fmt.Sprintf("Imported %d HAR entr%s into history; %d skipped. Nothing was sent to any target.", out.Imported, ui2Plural(out.Imported, "y", "ies"), out.Skipped),
		"lines": out.Errors,
	})
}

func ui2Plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ---- go to entry -------------------------------------------------------------------------------

// handleUI2HistoryGoto serves GET /ui2/history/goto?id=N: that exchange's detail pane.
func (s *Server) handleUI2HistoryGoto(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	msg := func(text string) {
		ui2Fragment(w, r, "burpsy /ui2/ — History", "history", ui2Exec("history_bulk_result.html", map[string]any{"error": text}))
	}
	raw := strings.TrimPrefix(strings.TrimSpace(r.URL.Query().Get("id")), "#")
	if raw == "" {
		msg("enter an exchange id to go to")
		return
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		msg("an exchange id is a whole number")
		return
	}
	model, ok := s.ui2HistoryDetailModel(r, id)
	if !ok {
		msg(fmt.Sprintf("no exchange #%d is stored", id))
		return
	}
	body := ui2Exec("history_goto.html", map[string]any{"id": id}) + ui2Exec("history_detail.html", model)
	ui2Fragment(w, r, "burpsy /ui2/ — History", "history", body)
}

// ---- compare -----------------------------------------------------------------------------------

// handleUI2HistoryCompare serves GET /ui2/history/compare?ids=a,b,...: the Comparer page seeded
// with the first two selected requests (A and B). Seeding sends and changes nothing.
func (s *Server) handleUI2HistoryCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fail := func(text string) {
		ui2Fragment(w, r, "burpsy /ui2/ — Comparer", "comparer", ui2Exec("history_bulk_result.html", map[string]any{"error": text}))
	}
	ids, errText := ui2ParseIDList(r.URL.Query().Get("ids"))
	if errText != "" {
		fail(errText)
		return
	}
	if len(ids) < 2 {
		fail("select two rows to compare - the first two selected load into A and B")
		return
	}
	var bufs [2]string
	for i, id := range ids[:2] {
		ex, err := s.store.GetExchange(core.ExchangeID(id))
		if err != nil {
			fail(fmt.Sprintf("no exchange #%d is stored", id))
			return
		}
		raw := requestMessageForExchange(s.store, ex)
		if raw == nil {
			fail(fmt.Sprintf("exchange #%d has no stored request to compare", id))
			return
		}
		if !ui2TextareaSafe(raw) {
			fail(fmt.Sprintf("the request of exchange #%d carries bytes a text editor cannot keep unchanged (invalid UTF-8 or NUL); nothing was loaded", id))
			return
		}
		bufs[i] = string(raw)
	}
	note := fmt.Sprintf("Request #%d loaded into A and #%d into B.", ids[0], ids[1])
	body := ui2Exec("history_bulk_result.html", map[string]any{"done": note}) +
		ui2Exec("comparer.html", map[string]any{"a": bufs[0], "b": bufs[1], "result": nil})
	ui2Fragment(w, r, "burpsy /ui2/ — Comparer", "comparer", body)
}

// ---- bulk actions ------------------------------------------------------------------------------

// ui2BulkMaxIDs bounds one selection, so a review sheet stays a list a person can read.
const ui2BulkMaxIDs = 1000

// ui2ParseIDList parses "1,2,3" into distinct ids, in order.
func ui2ParseIDList(raw string) ([]uint64, string) {
	var out []uint64
	seen := map[uint64]bool{}
	for _, f := range strings.Split(raw, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return nil, "the selection carries something that is not an exchange id"
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) > ui2BulkMaxIDs {
		return nil, fmt.Sprintf("select at most %d rows for one action", ui2BulkMaxIDs)
	}
	return out, ""
}

func ui2JoinIDs(ids []uint64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatUint(id, 10)
	}
	return strings.Join(parts, ",")
}

// ui2BulkFields is the form contract: every permitted field exactly once, nothing else, no query.
func ui2BulkFields(r *http.Request, keys ...string) string {
	if err := r.ParseForm(); err != nil {
		return "invalid form"
	}
	if len(r.URL.Query()) != 0 {
		return "query fields are not permitted here"
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
		if len(r.PostForm[k]) != 1 {
			return k + " must be a single permitted field"
		}
	}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			return k + " is not a single permitted field"
		}
	}
	return ""
}

// ui2BulkItem is one selected row as a review sheet lists it.
type ui2BulkItem struct {
	ID     uint64
	Method string
	URL    string
	Status string
}

func ui2ExchangeURL(ex *core.Exchange) string {
	scheme, def := "http", uint16(80)
	if ex.TLS {
		scheme, def = "https", 443
	}
	auth := ex.Host
	if ex.Port != def {
		auth += ":" + strconv.Itoa(int(ex.Port))
	}
	return scheme + "://" + auth + ex.Path
}

// ui2BulkResolve resolves every selected id; a missing one is a named refusal.
func (s *Server) ui2BulkResolve(ids []uint64) ([]*core.Exchange, []ui2BulkItem, string) {
	if len(ids) == 0 {
		return nil, nil, "select one or more rows first (shift- or ctrl-click, or the row checkboxes)"
	}
	exs := make([]*core.Exchange, 0, len(ids))
	items := make([]ui2BulkItem, 0, len(ids))
	for _, id := range ids {
		ex, err := s.store.GetExchange(core.ExchangeID(id))
		if err != nil {
			return nil, nil, fmt.Sprintf("exchange #%d is not stored any more - reload history and select again", id)
		}
		exs = append(exs, ex)
		items = append(items, ui2BulkItem{ID: id, Method: ex.Method, URL: ui2ExchangeURL(ex), Status: ui2StatusString(ex.Status)})
	}
	return exs, items, ""
}

// The gated bodies, built by one function each so the confirm and run steps cannot differ.
func ui2AuditSelectedBody(ids []uint64) map[string]any {
	return map[string]any{"exchange_ids": ids}
}

func ui2DeleteRowsBody(ids []uint64) map[string]any {
	return map[string]any{"ids": ids}
}

// ui2HistoryScopeReview is a held hosts-to-scope review: one minted gate token per host, kept
// server-side; the operator's form carries only the review id and the review token.
type ui2HistoryScopeReview struct {
	token   string
	hosts   []string
	bodies  [][]byte
	gates   []string
	expires time.Time
}

const ui2HistoryScopeReviewCap = 8

// handleUI2HistoryBulk serves POST /ui2/history/bulk/{action}.
func (s *Server) handleUI2HistoryBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.PathValue("action") {
	case "urls":
		s.ui2BulkURLs(w, r)
	case "organizer":
		s.ui2BulkOrganizer(w, r)
	case "scope-confirm":
		s.ui2BulkScopeConfirm(w, r)
	case "scope-run":
		s.ui2BulkScopeRun(w, r)
	case "audit-confirm", "delete-confirm":
		s.ui2BulkGatedConfirm(w, r, strings.TrimSuffix(r.PathValue("action"), "-confirm"))
	case "audit-run", "delete-run":
		s.ui2BulkGatedRun(w, r, strings.TrimSuffix(r.PathValue("action"), "-run"))
	case "clear-confirm":
		s.ui2BulkClearConfirm(w, r)
	case "clear-run":
		s.ui2BulkClearRun(w, r)
	default:
		s.ui2BulkResult(w, r, map[string]any{"error": "unknown history action"})
	}
}

func (s *Server) ui2BulkResult(w http.ResponseWriter, r *http.Request, model map[string]any) {
	ui2Fragment(w, r, "burpsy /ui2/ — History", "history", ui2Exec("history_bulk_result.html", model))
}

func (s *Server) ui2BulkReview(w http.ResponseWriter, r *http.Request, model map[string]any) {
	ui2Fragment(w, r, "burpsy /ui2/ — History", "history", ui2Exec("history_bulk_confirm.html", model))
}

// ui2BulkSelection reads and resolves the "ids" field of a selection-taking action.
func (s *Server) ui2BulkSelection(r *http.Request, extra ...string) ([]uint64, []*core.Exchange, []ui2BulkItem, string) {
	if e := ui2BulkFields(r, append([]string{"ids"}, extra...)...); e != "" {
		return nil, nil, nil, e
	}
	ids, e := ui2ParseIDList(r.PostFormValue("ids"))
	if e != "" {
		return nil, nil, nil, e
	}
	exs, items, e := s.ui2BulkResolve(ids)
	return ids, exs, items, e
}

func (s *Server) ui2BulkURLs(w http.ResponseWriter, r *http.Request) {
	_, exs, _, e := s.ui2BulkSelection(r)
	if e != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": e})
		return
	}
	urls := make([]string, len(exs))
	for i, ex := range exs {
		urls[i] = ui2ExchangeURL(ex)
	}
	s.ui2BulkResult(w, r, map[string]any{
		"done": fmt.Sprintf("%d URL%s from the selection:", len(urls), ui2Plural(len(urls), "", "s")),
		"copy": strings.Join(urls, "\n"),
	})
}

func (s *Server) ui2BulkOrganizer(w http.ResponseWriter, r *http.Request) {
	ids, _, _, e := s.ui2BulkSelection(r)
	if e != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": e})
		return
	}
	var added []string
	var failed []string
	for _, id := range ids {
		res, errText := s.ui2APIResult(http.MethodPost, "/api/tools/organizer", map[string]any{"exchange": id})
		if errText != "" {
			failed = append(failed, fmt.Sprintf("#%d: %s", id, ui2APIErrorText(errText)))
			continue
		}
		item, _ := res.(map[string]any)
		added = append(added, fmt.Sprintf("exchange #%d saved as item #%v", id, item["id"]))
	}
	model := map[string]any{"lines": append(added, failed...)}
	if len(failed) == 0 {
		model["done"] = fmt.Sprintf("Added %d exchange%s to Organizer. No request was sent.", len(added), ui2Plural(len(added), "", "s"))
	} else {
		model["error"] = fmt.Sprintf("%d of %d added to Organizer; %d refused.", len(added), len(ids), len(failed))
	}
	s.ui2BulkResult(w, r, model)
}

func (s *Server) ui2BulkScopeConfirm(w http.ResponseWriter, r *http.Request) {
	_, exs, _, e := s.ui2BulkSelection(r)
	if e != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": e})
		return
	}
	var hosts []string
	seen := map[string]bool{}
	for _, ex := range exs {
		if ex.Host != "" && !seen[ex.Host] {
			seen[ex.Host] = true
			hosts = append(hosts, ex.Host)
		}
	}
	if len(hosts) == 0 {
		s.ui2BulkResult(w, r, map[string]any{"error": "the selected rows carry no host to scope"})
		return
	}
	now := time.Now()
	open := 0
	s.ui2HistoryScopeReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2HistoryScopeReview); ok && now.After(e.expires) {
			s.ui2HistoryScopeReviews.Delete(k)
		} else {
			open++
		}
		return true
	})
	if open >= ui2HistoryScopeReviewCap {
		s.ui2BulkResult(w, r, map[string]any{"error": "too many scope reviews are open - confirm or let some expire, then try again"})
		return
	}
	review := ui2HistoryScopeReview{hosts: hosts, expires: now.Add(ConfirmTTL)}
	var shown []string
	for _, h := range hosts {
		body, _ := ui2Marshal(map[string]any{"action": "include", "pattern": h})
		gate, _, mintErr := s.ui2MintConfirm("/api/scope", http.MethodPost, "/api/scope", body)
		if mintErr != "" || gate == "" {
			s.ui2BulkResult(w, r, map[string]any{"error": "could not mint the confirmation: " + mintErr})
			return
		}
		review.bodies = append(review.bodies, body)
		review.gates = append(review.gates, gate)
		shown = append(shown, "POST /api/scope "+string(body))
	}
	rid, err1 := randomHex(16)
	tok, err2 := randomHex(16)
	if err1 != nil || err2 != nil {
		s.ui2BulkResult(w, r, map[string]any{"error": "could not create the review"})
		return
	}
	review.token = tok
	s.ui2HistoryScopeReviews.Store(rid, review)
	s.ui2BulkReview(w, r, map[string]any{
		"title":  fmt.Sprintf("Add %d host%s to the target scope", len(hosts), ui2Plural(len(hosts), "", "s")),
		"hosts":  hosts,
		"calls":  shown,
		"run":    "scope-run",
		"button": "Confirm and add to scope",
		"consequences": []string{
			"Each host becomes an include rule (any port, any protocol, any path). Scope decides where the proxy and every tool may send traffic, and the change persists.",
			"Adding the rules sends no traffic by itself. Exactly the calls listed run, in order; the review is one-time and expires with the confirmation window.",
		},
		"hidden": []ui2Hidden{{"review_id", rid}, {"token", tok}},
	})
}

func (s *Server) ui2BulkScopeRun(w http.ResponseWriter, r *http.Request) {
	if e := ui2BulkFields(r, "review_id", "token"); e != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": e})
		return
	}
	v, ok := s.ui2HistoryScopeReviews.LoadAndDelete(r.PostFormValue("review_id"))
	review, isReview := v.(ui2HistoryScopeReview)
	if !ok || !isReview {
		s.ui2BulkResult(w, r, map[string]any{"error": "that review is unknown or was already used - review again"})
		return
	}
	if time.Now().After(review.expires) {
		s.ui2BulkResult(w, r, map[string]any{"error": "that review expired - review again"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(review.token), []byte(r.PostFormValue("token"))) != 1 {
		s.ui2BulkResult(w, r, map[string]any{"error": "that review does not match this confirmation - review again"})
		return
	}
	var lines []string
	failed := 0
	for i, h := range review.hosts {
		if _, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/scope", json.RawMessage(review.bodies[i]), review.gates[i]); errText != "" {
			failed++
			lines = append(lines, h+": refused - "+ui2APIErrorText(errText))
		} else {
			lines = append(lines, h+": include rule added")
		}
	}
	model := map[string]any{"lines": lines}
	if failed == 0 {
		model["done"] = fmt.Sprintf("Added %d host%s to scope. No traffic was sent.", len(review.hosts), ui2Plural(len(review.hosts), "", "s"))
	} else {
		model["error"] = fmt.Sprintf("%d of %d hosts added to scope; %d refused.", len(review.hosts)-failed, len(review.hosts), failed)
	}
	s.ui2BulkResult(w, r, model)
}

// ui2BulkGated describes the two selection-bound gated calls.
func ui2BulkGated(kind string) (method, path string, body func([]uint64) map[string]any, title, button string, consequences []string) {
	if kind == "audit" {
		return http.MethodPost, "/api/audit/selected", ui2AuditSelectedBody, "Audit %d selected item%s", "Confirm and start the audit",
			[]string{
				"An active scan runs over exactly the exchanges listed: it SENDS attack requests to their targets, within the scope rules.",
				"The scan runs as a task on the dashboard, where it can be cancelled. The confirmation is one-time and binds exactly this id list; an edited list is refused.",
			}
	}
	return http.MethodDelete, "/api/history/rows", ui2DeleteRowsBody, "Delete %d selected row%s from history", "Confirm and delete",
		[]string{
			"Exactly the rows listed leave the HTTP history view (and every list built on it). Nothing is sent.",
			"This cannot be undone from the console. The confirmation is one-time and binds exactly this id list; an edited list is refused.",
		}
}

func (s *Server) ui2BulkGatedConfirm(w http.ResponseWriter, r *http.Request, kind string) {
	ids, _, items, e := s.ui2BulkSelection(r)
	if e != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": e})
		return
	}
	method, path, build, title, button, consequences := ui2BulkGated(kind)
	body, _ := ui2Marshal(build(ids))
	token, _, mintErr := s.ui2MintConfirm(path, method, path, body)
	if mintErr != "" || token == "" {
		s.ui2BulkResult(w, r, map[string]any{"error": "could not mint the confirmation: " + mintErr})
		return
	}
	s.ui2BulkReview(w, r, map[string]any{
		"title":        fmt.Sprintf(title, len(ids), ui2Plural(len(ids), "", "s")),
		"items":        items,
		"calls":        []string{method + " " + path + " " + string(body)},
		"run":          kind + "-run",
		"button":       button,
		"consequences": consequences,
		"hidden":       []ui2Hidden{{"ids", ui2JoinIDs(ids)}, {"token", token}},
	})
}

func (s *Server) ui2BulkGatedRun(w http.ResponseWriter, r *http.Request, kind string) {
	if e := ui2BulkFields(r, "ids", "token"); e != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": e})
		return
	}
	ids, e := ui2ParseIDList(r.PostFormValue("ids"))
	if e == "" && len(ids) == 0 {
		// An empty id list would read as "clear everything" to /api/history/rows: never sent.
		e = "the reviewed selection is empty - review again"
	}
	if e != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": e})
		return
	}
	method, path, build, _, _, _ := ui2BulkGated(kind)
	res, errText := s.ui2DispatchConfirmed(method, path, build(ids), r.PostFormValue("token"))
	if errText != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": "not applied: " + ui2APIErrorText(errText)})
		return
	}
	m, _ := res.(map[string]any)
	if kind == "audit" {
		s.ui2BulkResult(w, r, map[string]any{"done": fmt.Sprintf("Audit started as task #%v over %v exchange(s) (%v duplicate(s) dropped). Follow it on the dashboard.", m["task_id"], m["count"], m["duplicates_dropped"])})
		return
	}
	w.Header().Set("HX-Trigger", "burpsy-history-changed")
	s.ui2BulkResult(w, r, map[string]any{"done": fmt.Sprintf("Deleted %v of %v selected row(s) from history. Nothing was sent.", m["removed"], m["requested"])})
}

func (s *Server) ui2BulkClearConfirm(w http.ResponseWriter, r *http.Request) {
	if e := ui2BulkFields(r); e != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": e})
		return
	}
	token, _, mintErr := s.ui2MintConfirm("/api/history/rows", http.MethodDelete, "/api/history/rows", nil)
	if mintErr != "" || token == "" {
		s.ui2BulkResult(w, r, map[string]any{"error": "could not mint the confirmation: " + mintErr})
		return
	}
	n := len(s.store.Exchanges())
	s.ui2BulkReview(w, r, map[string]any{
		"title":  fmt.Sprintf("Clear the whole capture (%d stored exchange%s)", n, ui2Plural(n, "", "s")),
		"calls":  []string{"DELETE /api/history/rows (no body: every row)"},
		"run":    "clear-run",
		"button": "Confirm and clear history",
		"consequences": []string{
			"Every row leaves history - proxy traffic and the tool rows other views list. Nothing is sent.",
			"This cannot be undone from the console. The confirmation is one-time.",
		},
		"hidden": []ui2Hidden{{"token", token}},
	})
}

func (s *Server) ui2BulkClearRun(w http.ResponseWriter, r *http.Request) {
	if e := ui2BulkFields(r, "token"); e != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": e})
		return
	}
	res, errText := s.ui2DispatchConfirmed(http.MethodDelete, "/api/history/rows", nil, r.PostFormValue("token"))
	if errText != "" {
		s.ui2BulkResult(w, r, map[string]any{"error": "not applied: " + ui2APIErrorText(errText)})
		return
	}
	m, _ := res.(map[string]any)
	w.Header().Set("HX-Trigger", "burpsy-history-changed")
	s.ui2BulkResult(w, r, map[string]any{"done": fmt.Sprintf("History cleared: %v row(s) removed. Nothing was sent.", m["removed"])})
}

// ---- extractor columns -------------------------------------------------------------------------

// ui2ExtractCell is one extractor value on one row; Null is "the response yielded nothing".
type ui2ExtractCell struct {
	Value string
	Null  bool
}

// ui2HistoryExtractColumns fills each row's extractor cells from /api/history/extract (for the
// page's rows only) and returns the column names. No extractors means no call.
func (s *Server) ui2HistoryExtractColumns(rows []ui2Row) []string {
	defs, _ := s.historyExtractors()
	if len(defs) == 0 || len(rows) == 0 {
		return ui2ExtractorNames(defs)
	}
	ids := make([]uint64, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	res, errText := s.ui2APIResult(http.MethodPost, "/api/history/extract", map[string]any{"ids": ids})
	values := map[string]any{}
	if errText == "" {
		if m, ok := res.(map[string]any); ok {
			values, _ = m["values"].(map[string]any)
		}
	}
	for i := range rows {
		row, _ := values[strconv.FormatUint(rows[i].ID, 10)].(map[string]any)
		cells := make([]ui2ExtractCell, len(defs))
		for j, d := range defs {
			if row == nil {
				continue
			}
			if v, ok := row[d.Name].(string); ok {
				cells[j] = ui2ExtractCell{Value: v}
			} else {
				cells[j] = ui2ExtractCell{Null: true}
			}
		}
		rows[i].Extract = cells
	}
	return ui2ExtractorNames(defs)
}

func ui2ExtractorNames(defs []sessionExtractDto) []string {
	names := make([]string, len(defs))
	for i, d := range defs {
		names[i] = d.Name
	}
	return names
}

// ui2ExtractorRow is one saved extractor as the manager lists it.
type ui2ExtractorRow struct {
	Name, From, How string
}

func ui2DescribeExtractor(d sessionExtractDto) ui2ExtractorRow {
	row := ui2ExtractorRow{Name: d.Name, From: "response body"}
	if from, header, err := d.extractFrom(); err == nil && from == "header" {
		row.From = "header " + header
	}
	how, err := d.extractHow()
	switch {
	case err != nil:
		row.How = "unreadable: " + err.Error()
	case how.JSONPath != "":
		row.How = "JSON path " + how.JSONPath
	case how.Pattern == wholeValuePattern:
		row.How = "whole value"
	default:
		row.How = fmt.Sprintf("regex %s (group %d)", how.Pattern, how.Group)
	}
	return row
}

// ui2ExtractorsState reads the saved definitions through the API with a digest of their
// canonical form, so an edit made from a stale page is refused instead of overwriting.
func (s *Server) ui2ExtractorsState() ([]json.RawMessage, string, error) {
	canon, err := s.ui2CanonicalGet("/api/history/extractors")
	if err != nil {
		return nil, "", err
	}
	var doc struct {
		Extractors []json.RawMessage `json:"extractors"`
	}
	if err := json.Unmarshal([]byte(canon), &doc); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256([]byte(canon))
	return doc.Extractors, hex.EncodeToString(sum[:]), nil
}

func (s *Server) ui2ExtractorsPage(w http.ResponseWriter, r *http.Request, note, done string) {
	raw, base, err := s.ui2ExtractorsState()
	if err != nil {
		note = "could not read the extractors: " + err.Error()
	}
	rows := make([]ui2ExtractorRow, 0, len(raw))
	for _, b := range raw {
		var d sessionExtractDto
		if json.Unmarshal(b, &d) == nil {
			rows = append(rows, ui2DescribeExtractor(d))
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — History extractors", "extractors", ui2Exec("history_extractors.html", map[string]any{
		"rows": rows, "base": base, "note": note, "done": done, "max": maxHistoryExtractors,
	}))
}

// handleUI2HistoryExtractors serves GET /ui2/history/extractors: the extractor-column manager.
func (s *Server) handleUI2HistoryExtractors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.ui2ExtractorsPage(w, r, "", "")
}

// handleUI2HistoryExtractorsAction serves POST /ui2/history/extractors/{action} (add|remove):
// a riskLocal PUT of the whole definition list, refused when the list changed since the page
// was rendered (the base digest), and refused by the API when a definition does not compile.
func (s *Server) handleUI2HistoryExtractorsAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fail := func(msg string) { s.ui2ExtractorsPage(w, r, "Not saved: "+msg, "") }
	action := r.PathValue("action")
	var keys []string
	switch action {
	case "add":
		keys = []string{"base", "name", "from", "header", "how", "pattern", "group", "json_path"}
	case "remove":
		keys = []string{"base", "name"}
	default:
		fail("unknown extractor action")
		return
	}
	if e := ui2BulkFields(r, keys...); e != "" {
		fail(e)
		return
	}
	current, base, err := s.ui2ExtractorsState()
	if err != nil {
		fail(err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(base), []byte(r.PostFormValue("base"))) != 1 {
		fail("the extractor list changed since this page loaded - reload and try again")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	next := make([]json.RawMessage, 0, len(current)+1)
	done := ""
	if action == "remove" {
		found := false
		for _, b := range current {
			var d sessionExtractDto
			if json.Unmarshal(b, &d) == nil && d.Name == name {
				found = true
				continue
			}
			next = append(next, b)
		}
		if !found {
			fail("no extractor is named " + name)
			return
		}
		done = "Removed the " + name + " column."
	} else {
		def, msg := ui2ExtractorFromForm(r, name)
		if msg != "" {
			fail(msg)
			return
		}
		b, _ := json.Marshal(def)
		next = append(append(next, current...), b)
		done = "Added the " + name + " column; history rows now show its value for each stored response."
	}
	payload, _ := json.Marshal(map[string]any{"extractors": next})
	req := newReq(http.MethodPut, "/api/history/extractors")
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(payload)))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		fail(truncateForDisplay(strings.TrimSpace(rec.Body.String()), 300))
		return
	}
	s.ui2ExtractorsPage(w, r, "", done)
}

// ui2ExtractorFromForm builds one definition in the API's own shape (sessionExtractDto).
func ui2ExtractorFromForm(r *http.Request, name string) (map[string]any, string) {
	if name == "" {
		return nil, "an extractor needs a name to be a column"
	}
	def := map[string]any{"name": name}
	switch r.PostFormValue("from") {
	case "body":
	case "header":
		h := strings.TrimSpace(r.PostFormValue("header"))
		if h == "" {
			return nil, "name the header to read from"
		}
		def["from"] = map[string]any{"header": h}
	default:
		return nil, "read from the body or a header"
	}
	switch r.PostFormValue("how") {
	case "whole":
		def["how"] = "whole"
	case "regex":
		pattern := r.PostFormValue("pattern")
		if pattern == "" {
			return nil, "a regex extractor needs a pattern"
		}
		group := 1
		if g := strings.TrimSpace(r.PostFormValue("group")); g != "" {
			n, err := strconv.Atoi(g)
			if err != nil || n < 0 {
				return nil, "the capture group is a whole number"
			}
			group = n
		}
		def["how"] = map[string]any{"regex": map[string]any{"pattern": pattern, "group": group}}
	case "json_path":
		p := strings.TrimSpace(r.PostFormValue("json_path"))
		if p == "" {
			return nil, "a JSON-path extractor needs a path"
		}
		def["how"] = map[string]any{"json_path": p}
	default:
		return nil, "choose regex, JSON path or whole value"
	}
	return def, ""
}
