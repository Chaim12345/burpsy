package web

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---- Search across tools (/ui2/search) -------------------------------------------------------
//
// The console rendering of GET /api/search: the form round-trips the API's options through the
// URL, the scan itself is the API handler's (called in-process), and a row's preview reads the
// matched message through GET /api/message/{id}. Nothing here matches bytes on its own.

// ui2SearchMaxPreviewOffsets bounds the match offsets a row's preview link carries (and so the
// URL length); the preview still states the true match count.
const ui2SearchMaxPreviewOffsets = 50

// ui2SearchExcerpts bounds the in-context excerpts a preview renders above the message.
const ui2SearchExcerpts = 10

// ui2SearchExcerptRadius is how many bytes of context each excerpt shows around its match.
const ui2SearchExcerptRadius = 80

// ui2SearchForm is the operator's search as the form round-trips it.
type ui2SearchForm struct {
	Q        string
	Case     bool
	Regex    bool
	Negate   bool
	InScope  bool
	Location string // both | request | response
	Within   string // both | headers | body (the API's "area")
	Tools    map[string]bool
	Limit    int // result rows; 0 means the API default
}

// ui2SearchLimits are the row limits the form offers; the API's default is 200, its cap 1000.
var ui2SearchLimits = []int{suiteSearchDefaultLimit, 500, suiteSearchMaxLimit}

// ui2SearchTool is one checkbox in the tool list, served by the API.
type ui2SearchTool struct {
	ID      string
	Label   string
	Checked bool
}

// ui2SearchRow is one matched exchange as the results table shows it.
type ui2SearchRow struct {
	ID          uint64
	Source      string
	Organizer   bool
	Method      string
	Host        string
	Path        string
	Status      string
	ResponseLen int
	Started     string
	Matches     string
	PreviewURL  string
}

type ui2SearchModel struct {
	Form       ui2SearchForm
	Tools      []ui2SearchTool
	ToolsError string
	Searched   bool
	Error      string
	Scope      string
	Scanned    int
	Returned   int
	Truncated  bool
	Rows       []ui2SearchRow
	Limits     []int
	Limit      int
}

func parseUI2SearchForm(q url.Values) ui2SearchForm {
	f := ui2SearchForm{
		Q:        q.Get("q"),
		Case:     truthy(q.Get("case")),
		Regex:    truthy(q.Get("regex")),
		Negate:   truthy(q.Get("negate")),
		InScope:  truthy(q.Get("in_scope")),
		Location: q.Get("location"),
		Within:   q.Get("within"),
		Tools:    map[string]bool{},
	}
	if f.Location == "" {
		f.Location = "both"
	}
	if f.Within == "" {
		f.Within = "both"
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n != suiteSearchDefaultLimit {
		f.Limit = min(n, suiteSearchMaxLimit)
	}
	for _, t := range q["tool"] {
		if t = strings.TrimSpace(t); t != "" {
			f.Tools[t] = true
		}
	}
	return f
}

// apiQuery is the /api/search query string for this form, mirroring the SPA's buildSearchQuery.
func (f ui2SearchForm) apiQuery() string {
	v := url.Values{}
	if f.Q != "" {
		v.Set("q", f.Q)
	}
	if f.Case {
		v.Set("case", "1")
	}
	if f.Regex {
		v.Set("regex", "1")
	}
	if f.Negate {
		v.Set("negate", "1")
	}
	if f.InScope {
		v.Set("in_scope", "1")
	}
	if f.Location != "both" {
		v.Set("location", f.Location)
	}
	if f.Within != "both" {
		v.Set("area", f.Within)
	}
	if tools := f.toolList(); len(tools) > 0 {
		v.Set("tools", strings.Join(tools, ","))
	}
	if f.Limit > 0 {
		v.Set("limit", strconv.Itoa(f.Limit))
	}
	return v.Encode()
}

func (f ui2SearchForm) toolList() []string {
	out := make([]string, 0, len(f.Tools))
	for t := range f.Tools {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// describe states what was searched, the way the SPA's describeSearch does.
func (f ui2SearchForm) describe() string {
	modes := []string{"literal text"}
	if f.Regex {
		modes[0] = "regular expression"
	}
	if f.Case {
		modes = append(modes, "case sensitive")
	} else {
		modes = append(modes, "case insensitive")
	}
	if f.Negate {
		modes = append(modes, "negative matches")
	}
	if f.InScope {
		modes = append(modes, "in scope only")
	}
	where := "requests and responses"
	if f.Location != "both" {
		where = f.Location + "s"
	}
	area := "headers and bodies"
	if f.Within != "both" {
		area = f.Within
	}
	tools := "every tool"
	if t := f.toolList(); len(t) > 0 {
		tools = strings.Join(t, ", ")
	}
	return strings.Join(modes, ", ") + " — " + where + ", " + area + ", across " + tools
}

// ui2SearchAPI runs one /api/search call in-process and decodes the typed answer.
func (s *Server) ui2SearchAPI(query string) (suiteSearchResponse, string) {
	rec := newRecorder()
	// The path is the fixed in-process /api/search route; query is url.Values-encoded form input
	// and only ever reaches that handler's parser.
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/search?"+query))
	var out suiteSearchResponse
	if rec.Code != http.StatusOK {
		return out, ui2APIErrorText(strings.TrimSpace(rec.Body.String()))
	}
	if err := ui2DecodeJSON(rec.Body.Bytes(), &out); err != nil {
		return out, "unreadable search response: " + err.Error()
	}
	return out, ""
}

func (s *Server) ui2SearchModel(f ui2SearchForm) ui2SearchModel {
	m := ui2SearchModel{Form: f, Scope: f.describe(), Searched: f.Q != "", Limits: ui2SearchLimits, Limit: f.Limit}
	if m.Limit == 0 {
		m.Limit = suiteSearchDefaultLimit
	}
	resp, errText := s.ui2SearchAPI(f.apiQuery())
	if errText != "" {
		m.Error = errText
		// A refused search still owes the operator the tool list; a blank query is the
		// API's vocabulary answer.
		resp, errText = s.ui2SearchAPI("")
		if errText != "" {
			m.ToolsError = errText
		}
	}
	for _, t := range resp.ToolOptions {
		m.Tools = append(m.Tools, ui2SearchTool{ID: t.ID, Label: t.Label, Checked: f.Tools[t.ID]})
	}
	if m.Error != "" || !m.Searched {
		return m
	}
	m.Scanned, m.Returned, m.Truncated = resp.Scanned, resp.Returned, resp.Truncated
	for _, r := range resp.Results {
		if r.ExchangeView == nil {
			continue
		}
		v := r.ExchangeView
		row := ui2SearchRow{
			ID: uint64(v.ID), Source: v.Source, Organizer: r.Organizer, Method: v.Method,
			Host: v.Host, Path: v.Path, Status: ui2StatusString(v.Status), ResponseLen: v.ResponseLen,
			Matches: strconv.Itoa(r.MatchCount),
		}
		if row.Source == "" {
			row.Source = "unattributed"
		}
		if v.StartedMs > 0 {
			row.Started = time.UnixMilli(int64(v.StartedMs)).Format("2006-01-02 15:04:05")
		}
		if r.MatchesTruncated {
			row.Matches = fmt.Sprintf("%d of %d", len(r.Matches), r.MatchCount)
		}
		row.PreviewURL = ui2SearchPreviewURL(v, r, f.Location)
		m.Rows = append(m.Rows, row)
	}
	return m
}

// ui2SearchPreviewURL links a row to the message holding its first match (the request for a
// negative-match row, or its response when only responses were searched), carrying that message's match offsets so the preview marks exactly the
// bytes the server matched rather than re-running a matcher of its own.
func ui2SearchPreviewURL(v *ExchangeView, r suiteSearchResultView, location string) string {
	q := url.Values{}
	q.Set("ex", strconv.FormatUint(uint64(v.ID), 10))
	var msgID uint64
	switch {
	case len(r.Matches) > 0:
		first := r.Matches[0]
		msgID = first.MessageID
		q.Set("dir", first.Direction)
		var offs []string
		for _, mt := range r.Matches {
			if mt.MessageID != msgID || len(offs) == ui2SearchMaxPreviewOffsets {
				continue
			}
			offs = append(offs, strconv.Itoa(mt.Offset)+":"+strconv.Itoa(mt.Len))
		}
		q.Set("m", strings.Join(offs, ","))
		q.Set("count", strconv.Itoa(r.MatchCount))
	case location == "response" && v.Response != nil:
		msgID = *v.Response
		q.Set("dir", "response")
	case v.Request != nil:
		msgID = *v.Request
		q.Set("dir", "request")
	case v.Response != nil:
		msgID = *v.Response
		q.Set("dir", "response")
	default:
		return ""
	}
	return "/ui2/search/message/" + strconv.FormatUint(msgID, 10) + "?" + q.Encode()
}

// handleUI2Search serves GET /ui2/search: the form, and the results when q is set.
func (s *Server) handleUI2Search(w http.ResponseWriter, r *http.Request) {
	m := s.ui2SearchModel(parseUI2SearchForm(r.URL.Query()))
	ui2Fragment(w, r, "burpsy /ui2/ — Search", "search", ui2Exec("search_page.html", m))
}

// ui2SearchSegment is one run of an excerpt: matched (Hit) or context.
type ui2SearchSegment struct {
	Text string
	Hit  bool
}

type ui2SearchExcerpt struct {
	Offset   int
	Leading  bool
	Trailing bool
	Segments []ui2SearchSegment
}

type ui2SearchPreview struct {
	MessageID  uint64
	ExchangeID uint64
	Direction  string
	Count      int
	Shown      int
	Dropped    int
	Excerpts   []ui2SearchExcerpt
	Pane       ui2PaneView
	Empty      bool
}

// handleUI2SearchMessage serves GET /ui2/search/message/{id}: one matched message rendered by
// renderMessagePane, with the matched bytes shown in context.
func (s *Server) handleUI2SearchMessage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	p := ui2SearchPreview{MessageID: id, Direction: q.Get("dir")}
	if p.Direction != "response" {
		p.Direction = "request"
	}
	if n, err := strconv.ParseUint(q.Get("ex"), 10, 64); err == nil {
		p.ExchangeID = n
	}
	p.Count, _ = strconv.Atoi(q.Get("count"))

	// The stored bytes themselves, as /api/message/{id} reads them (s.message): the search's
	// offsets index these raw bytes, and the JSON text field would shift them wherever the
	// message holds invalid UTF-8 (each such byte becomes a 3-byte U+FFFD).
	stored, err := s.message(id)
	if err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}
	text := string(stored.Raw())
	p.Empty = text == ""
	p.Pane = renderMessagePane(text, p.Direction == "request", false)
	for _, part := range strings.Split(q.Get("m"), ",") {
		off, ln, ok := ui2ParseSearchOffset(part, len(text))
		if !ok {
			if part != "" {
				p.Dropped++
			}
			continue
		}
		p.Shown++
		if len(p.Excerpts) < ui2SearchExcerpts {
			p.Excerpts = append(p.Excerpts, ui2SearchExcerptAt(text, off, ln))
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui2Templates.ExecuteTemplate(w, "search_preview.html", p); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ui2ParseSearchOffset reads one "offset:len" pair and refuses one outside the message.
func ui2ParseSearchOffset(part string, total int) (int, int, bool) {
	a, b, ok := strings.Cut(part, ":")
	if !ok {
		return 0, 0, false
	}
	off, err1 := strconv.Atoi(a)
	ln, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || off < 0 || ln < 0 || off > total || ln > total-off {
		return 0, 0, false
	}
	return off, ln, true
}

// ui2SearchExcerptAt cuts the bytes around one match, widened to rune boundaries so the excerpt
// never splits a UTF-8 sequence.
func ui2SearchExcerptAt(text string, off, ln int) ui2SearchExcerpt {
	start := max(0, off-ui2SearchExcerptRadius)
	for start > 0 && !utf8.RuneStart(text[start]) {
		start--
	}
	end := min(len(text), off+ln+ui2SearchExcerptRadius)
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	return ui2SearchExcerpt{
		Offset:   off,
		Leading:  start > 0,
		Trailing: end < len(text),
		Segments: []ui2SearchSegment{
			{Text: text[start:off]},
			{Text: text[off : off+ln], Hit: true},
			{Text: text[off+ln : end]},
		},
	}
}
