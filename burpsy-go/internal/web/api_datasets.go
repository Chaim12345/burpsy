package web

// GET /api/datasets/{source}: a table view over burpsy's lists — regex, columns, sort, offset, facets
// and long-poll (burpsy-react-ui-co88).
//
// Burp's agent surface has search_dataset and summarize_dataset: any list (proxy history, site map,
// scan results, attack results) can be filtered by a regex over chosen columns, sorted, paged by
// offset, and broken down into per-column counts. burpsy's list routes each take their own handful of
// parameters — /api/history has limit/q/search and no offset — and an MCP result is cut at 1 MiB, so a
// long history could not be paged to its end at all.
//
// This is ONE envelope over several sources, and it is a new route, so no existing list's shape (which
// the console reads) changes. Each source's rows are its own route's view type, flattened to scalar
// columns: the dataset of /api/history rows IS what /api/history serves, column for column, so the two
// cannot disagree about what a row says.
//
// Sources (all riskRead; a credential-class list is deliberately not offered here):
//
//	history          proxy history, with exactly /api/history's source filter (no tool-sent rows)
//	issues           scanner issues, /api/issues' view
//	sitemap          one row per observed host+path node
//	tool-log         every request burpsy itself sent, /api/tools/log's view
//	ws-history       captured WebSocket frames, /api/ws/history's view
//	intruder/{task}  the requests one Intruder attack sent (stored exchanges carrying that task id)
//
// GET /api/datasets/ (no source) lists the sources and their columns.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

const (
	defaultDatasetLimit = 25
	maxDatasetLimit     = 500
	maxDatasetWait      = 60
	maxFacetValues      = 20
)

// datasetPollInterval is how often a long-poll re-reads its source.
var datasetPollInterval = 250 * time.Millisecond

type datasetRow = map[string]any

// datasetSource produces a source's rows, in the source's natural order, and names the columns to
// facet on when the caller asks for facets without naming any.
type datasetSource struct {
	name          string
	desc          string
	defaultFacets []string
	defaultSort   string
	// rows returns the source's rows lazily: a row is flattened (a JSON round trip of its view) only
	// when something reads it, so a page of an unfiltered list costs its own rows, not the whole list.
	rows     func(s *Server, arg string) ([]lazyRow, error)
	needsArg bool
	// idOrdered: the natural order is ascending "id", so an unfiltered id-sorted page can be cut
	// before any row is flattened.
	idOrdered bool
}

// lazyRow flattens one row on demand.
type lazyRow func() datasetRow

// datasetSources is the table. Ordered for the listing.
var datasetSources = []datasetSource{
	{
		name: "history", idOrdered: true, desc: "proxy history rows (proxied and crawled traffic; tool-sent requests are in tool-log)",
		defaultFacets: []string{"host", "method", "status", "mime"}, defaultSort: "id",
		rows: func(s *Server, _ string) ([]lazyRow, error) {
			var out []lazyRow
			for _, ex := range s.store.Exchanges() {
				switch ex.Source {
				case core.SourceRepeater, core.SourceIntruder, core.SourceScanner:
					continue
				}
				out = append(out, func() datasetRow { return flattenRow(exchangeView(ex)) })
			}
			return out, nil
		},
	},
	{
		name: "issues", desc: "scanner issues",
		defaultFacets: []string{"severity", "confidence", "name", "host"}, defaultSort: "id",
		rows: func(s *Server, _ string) ([]lazyRow, error) {
			var out []lazyRow
			for _, f := range s.findings.All() {
				out = append(out, func() datasetRow { return flattenRow(s.findingToIssueView(f)) })
			}
			return out, nil
		},
	},
	{
		name: "sitemap", desc: "one row per observed host and path node of the site map",
		defaultFacets: []string{"host", "methods", "statuses"}, defaultSort: "url",
		rows: func(s *Server, _ string) ([]lazyRow, error) {
			var out []lazyRow
			for _, h := range s.sitemap.Hosts() {
				for _, p := range h.PathsSorted() {
					out = append(out, func() datasetRow {
						return flattenRow(datasetRow{
							"url":       nodeURL(h.Host, h.Port, h.TLS, p.Path),
							"host":      h.Host,
							"port":      h.Port,
							"tls":       h.TLS,
							"path":      p.Path,
							"methods":   toAnySlice(p.MethodsSorted()),
							"statuses":  intsToAny(p.StatusesSorted()),
							"exchanges": len(p.ExchangeIDs),
							"in_scope":  s.scope.Contains(h.Host, h.Port, p.Path, h.TLS),
						})
					})
				}
			}
			return out, nil
		},
	},
	{
		name: "tool-log", idOrdered: true, desc: "every request burpsy itself sent (Repeater, Intruder, Scanner, …)",
		defaultFacets: []string{"tool", "host", "status"}, defaultSort: "id",
		rows: func(s *Server, _ string) ([]lazyRow, error) {
			var out []lazyRow
			for _, e := range s.toolLog.All() {
				out = append(out, func() datasetRow { return flattenRow(toolLogEntryView(e)) })
			}
			return out, nil
		},
	},
	{
		name: "ws-history", idOrdered: true, desc: "captured WebSocket frames",
		defaultFacets: []string{"direction", "opcode", "host"}, defaultSort: "id",
		rows: func(s *Server, _ string) ([]lazyRow, error) {
			msgs := s.store.WsMessages(0, s.store.WsCount())
			out := make([]lazyRow, 0, len(msgs))
			// WsMessages answers newest first; a dataset's natural order is oldest first.
			for i := len(msgs) - 1; i >= 0; i-- {
				m := msgs[i]
				out = append(out, func() datasetRow {
					handshake, _ := s.store.GetExchange(m.Exchange)
					return flattenRow(wsRowFromMessage(m, handshake))
				})
			}
			return out, nil
		},
	},
	{
		name: "intruder", idOrdered: true, desc: "the requests one Intruder attack sent: intruder/{task_id}", needsArg: true,
		defaultFacets: []string{"status", "response_len"}, defaultSort: "id",
		rows: func(s *Server, arg string) ([]lazyRow, error) {
			task, err := strconv.ParseUint(arg, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("intruder/{task_id}: %q is not a task id", arg)
			}
			var out []lazyRow
			for _, ex := range s.store.Exchanges() {
				if ex.Source == core.SourceIntruder && ex.TaskID == task {
					out = append(out, func() datasetRow { return flattenRow(exchangeView(ex)) })
				}
			}
			return out, nil
		},
	},
}

func nodeURL(host string, port uint16, tls bool, path string) string {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func intsToAny(ns []int) []any {
	out := make([]any, len(ns))
	for i, n := range ns {
		out[i] = n
	}
	return out
}

// flattenRow turns a view struct into a row of its scalar columns, keyed by the view's own JSON names.
// Nested objects are dropped (a dataset row is a table row); arrays of scalars stay arrays.
func flattenRow(v any) datasetRow {
	raw, err := json.Marshal(v)
	if err != nil {
		return datasetRow{}
	}
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return datasetRow{}
	}
	out := make(datasetRow, len(m))
	for k, val := range m {
		switch x := val.(type) {
		case map[string]any:
			continue
		case []any:
			scalar := true
			for _, e := range x {
				switch e.(type) {
				case map[string]any, []any:
					scalar = false
				}
			}
			if scalar {
				out[k] = x
			}
		default:
			out[k] = x
		}
	}
	return out
}

// cellText is a cell as the regex and the facets see it.
func cellText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = cellText(e)
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(x)
	}
}

// cellLess orders two cells: numbers numerically, everything else as text, nulls last.
func cellLess(a, b any) bool {
	if a == nil || b == nil {
		return a != nil && b == nil
	}
	na, aok := a.(json.Number)
	nb, bok := b.(json.Number)
	if aok && bok {
		fa, _ := na.Float64()
		fb, _ := nb.Float64()
		return fa < fb
	}
	return cellText(a) < cellText(b)
}

type datasetFacetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type datasetFacet struct {
	Column   string              `json:"column"`
	Distinct int                 `json:"distinct"`
	Values   []datasetFacetValue `json:"values"`
	// Other counts the rows whose value is not among the listed top values.
	Other int `json:"other"`
}

// datasetView is the envelope.
type datasetView struct {
	Source  string   `json:"source"`
	Columns []string `json:"columns"`
	// ColumnsSampled: the page was cut without reading every row (an unfiltered id-ordered page), so
	// Columns lists the returned rows' columns rather than every row's.
	ColumnsSampled bool `json:"columns_sampled,omitempty"`
	TotalRows      int  `json:"total_rows"`
	Matched        int  `json:"matched"`
	Offset         int  `json:"offset"`
	Limit          int  `json:"limit"`
	Returned       int  `json:"returned"`
	// NextOffset is where the next page starts, or null when this page reached the last matched row.
	NextOffset *int         `json:"next_offset"`
	SortBy     string       `json:"sort_by"`
	SortOrder  string       `json:"sort_order"`
	Pattern    string       `json:"pattern,omitempty"`
	Rows       []datasetRow `json:"rows"`
	// Facets is null unless facets were asked for.
	Facets []datasetFacet `json:"facets"`
	// Status is set for a long-poll only: complete (min_rows reached) or timeout.
	Status   string `json:"status,omitempty"`
	WaitedMs int64  `json:"waited_ms,omitempty"`
}

type datasetQuery struct {
	pattern  *regexp.Regexp
	columns  []string
	sortBy   string
	desc     bool
	offset   int
	limit    int
	ret      []string
	facets   []string
	wantFace bool
	since    *float64
	wait     int
	minRows  int
}

func splitList(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseDatasetQuery(r *http.Request, src datasetSource) (datasetQuery, error) {
	q := r.URL.Query()
	dq := datasetQuery{sortBy: src.defaultSort, limit: defaultDatasetLimit, minRows: 1}
	if p := q.Get("pattern"); p != "" {
		expr := p
		if truthy(q.Get("case_insensitive")) {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return dq, fmt.Errorf("pattern is not a valid regular expression (RE2 syntax): %v", err)
		}
		dq.pattern = re
	}
	dq.columns = splitList(q.Get("columns"))
	if v := q.Get("sort_by"); v != "" {
		dq.sortBy = v
	}
	switch strings.ToLower(q.Get("sort_order")) {
	case "", "asc":
	case "desc":
		dq.desc = true
	default:
		return dq, fmt.Errorf("sort_order must be asc or desc")
	}
	ints := []struct {
		name     string
		into     *int
		min, max int
	}{
		{"offset", &dq.offset, 0, 1 << 30},
		{"limit", &dq.limit, 1, maxDatasetLimit},
		{"wait_seconds", &dq.wait, 0, maxDatasetWait},
		{"min_rows", &dq.minRows, 1, 1 << 30},
	}
	for _, p := range ints {
		raw := q.Get(p.name)
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < p.min || n > p.max {
			return dq, fmt.Errorf("%s must be an integer in %d..%d; got %q", p.name, p.min, p.max, raw)
		}
		*p.into = n
	}
	dq.ret = splitList(q.Get("return_columns"))
	if f := q.Get("facets"); f != "" {
		dq.wantFace = true
		if !truthy(f) && f != "default" {
			dq.facets = splitList(f)
		} else {
			dq.facets = src.defaultFacets
		}
	}
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return dq, fmt.Errorf("since must be a row id; got %q", v)
		}
		dq.since = &n
	}
	return dq, nil
}

func rowMatches(row datasetRow, dq datasetQuery) bool {
	if dq.since != nil {
		id, ok := row["id"].(json.Number)
		if !ok {
			return false
		}
		if f, _ := id.Float64(); f <= *dq.since {
			return false
		}
	}
	if dq.pattern == nil {
		return true
	}
	if len(dq.columns) > 0 {
		for _, c := range dq.columns {
			if dq.pattern.MatchString(cellText(row[c])) {
				return true
			}
		}
		return false
	}
	for _, v := range row {
		if dq.pattern.MatchString(cellText(v)) {
			return true
		}
	}
	return false
}

func facetsOf(rows []datasetRow, cols []string) []datasetFacet {
	out := make([]datasetFacet, 0, len(cols))
	for _, c := range cols {
		counts := map[string]int{}
		for _, r := range rows {
			v := r[c]
			if arr, ok := v.([]any); ok {
				for _, e := range arr {
					counts[cellText(e)]++
				}
				continue
			}
			counts[cellText(v)]++
		}
		values := make([]datasetFacetValue, 0, len(counts))
		for v, n := range counts {
			values = append(values, datasetFacetValue{Value: v, Count: n})
		}
		sort.Slice(values, func(i, j int) bool {
			if values[i].Count != values[j].Count {
				return values[i].Count > values[j].Count
			}
			return values[i].Value < values[j].Value
		})
		f := datasetFacet{Column: c, Distinct: len(values), Values: values}
		if len(values) > maxFacetValues {
			for _, v := range values[maxFacetValues:] {
				f.Other += v.Count
			}
			f.Values = values[:maxFacetValues]
		}
		out = append(out, f)
	}
	return out
}

// buildDataset evaluates the query once over a fresh read of the source.
func (s *Server) buildDataset(src datasetSource, name, arg string, dq datasetQuery) (datasetView, error) {
	lazy, err := src.rows(s, arg)
	if err != nil {
		return datasetView{}, err
	}
	if src.idOrdered && dq.pattern == nil && dq.since == nil && !dq.wantFace && dq.sortBy == "id" {
		return pageWithoutFlattening(lazy, name, dq), nil
	}
	rows := make([]datasetRow, len(lazy))
	for i, f := range lazy {
		rows[i] = f()
	}
	colSet := map[string]bool{}
	for _, r := range rows {
		for k := range r {
			colSet[k] = true
		}
	}
	columns := make([]string, 0, len(colSet))
	for k := range colSet {
		columns = append(columns, k)
	}
	sort.Strings(columns)

	matched := make([]datasetRow, 0, len(rows))
	for _, r := range rows {
		if rowMatches(r, dq) {
			matched = append(matched, r)
		}
	}
	if dq.sortBy != "" {
		sort.SliceStable(matched, func(i, j int) bool {
			if dq.desc {
				return cellLess(matched[j][dq.sortBy], matched[i][dq.sortBy])
			}
			return cellLess(matched[i][dq.sortBy], matched[j][dq.sortBy])
		})
	}
	view := datasetView{
		Source: name, Columns: columns, TotalRows: len(rows), Matched: len(matched),
		Offset: dq.offset, Limit: dq.limit, SortBy: dq.sortBy, SortOrder: "asc", Rows: []datasetRow{},
	}
	if dq.desc {
		view.SortOrder = "desc"
	}
	if dq.pattern != nil {
		view.Pattern = dq.pattern.String()
	}
	if dq.offset < len(matched) {
		end := dq.offset + dq.limit
		if end > len(matched) {
			end = len(matched)
		}
		for _, r := range matched[dq.offset:end] {
			if len(dq.ret) > 0 {
				pick := make(datasetRow, len(dq.ret))
				for _, c := range dq.ret {
					pick[c] = r[c]
				}
				r = pick
			}
			view.Rows = append(view.Rows, r)
		}
		if end < len(matched) {
			view.NextOffset = &end
		}
	}
	view.Returned = len(view.Rows)
	if dq.wantFace {
		view.Facets = facetsOf(matched, dq.facets)
	}
	return view, nil
}

// pageWithoutFlattening answers an unfiltered, id-ordered page by cutting the page out of the lazy
// rows first, so only the returned rows are flattened: paging to the end of a long history costs each
// page its own rows rather than the whole history again. The columns are then the returned rows'
// columns, and columns_sampled says so.
func pageWithoutFlattening(lazy []lazyRow, name string, dq datasetQuery) datasetView {
	view := datasetView{
		Source: name, TotalRows: len(lazy), Matched: len(lazy), Offset: dq.offset, Limit: dq.limit,
		SortBy: dq.sortBy, SortOrder: "asc", Rows: []datasetRow{}, ColumnsSampled: true,
	}
	if dq.desc {
		view.SortOrder = "desc"
	}
	if dq.offset < len(lazy) {
		end := dq.offset + dq.limit
		if end > len(lazy) {
			end = len(lazy)
		}
		for i := dq.offset; i < end; i++ {
			idx := i
			if dq.desc {
				idx = len(lazy) - 1 - i
			}
			r := lazy[idx]()
			if len(dq.ret) > 0 {
				pick := make(datasetRow, len(dq.ret))
				for _, c := range dq.ret {
					pick[c] = r[c]
				}
				r = pick
			}
			view.Rows = append(view.Rows, r)
		}
		if end < len(lazy) {
			view.NextOffset = &end
		}
	}
	view.Returned = len(view.Rows)
	colSet := map[string]bool{}
	for _, r := range view.Rows {
		for k := range r {
			colSet[k] = true
		}
	}
	view.Columns = make([]string, 0, len(colSet))
	for k := range colSet {
		view.Columns = append(view.Columns, k)
	}
	sort.Strings(view.Columns)
	return view
}

// datasetListing is GET /api/datasets/ with no source.
type datasetListing struct {
	Sources []datasetSourceInfo `json:"sources"`
}

type datasetSourceInfo struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	DefaultFacets []string `json:"default_facets"`
	DefaultSort   string   `json:"default_sort"`
}

func (s *Server) handleDatasets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/datasets/"), "/")
	if rest == "" {
		listing := datasetListing{Sources: make([]datasetSourceInfo, 0, len(datasetSources))}
		for _, src := range datasetSources {
			name := src.name
			if src.needsArg {
				name += "/{task_id}"
			}
			listing.Sources = append(listing.Sources, datasetSourceInfo{Name: name, Description: src.desc, DefaultFacets: src.defaultFacets, DefaultSort: src.defaultSort})
		}
		writeJSON(w, http.StatusOK, listing)
		return
	}
	name, arg, _ := strings.Cut(rest, "/")
	var src *datasetSource
	for i := range datasetSources {
		if datasetSources[i].name == name {
			src = &datasetSources[i]
		}
	}
	if src == nil {
		http.Error(w, fmt.Sprintf("no dataset named %q; GET /api/datasets/ lists them", name), http.StatusNotFound)
		return
	}
	if src.needsArg != (arg != "") {
		if src.needsArg {
			http.Error(w, fmt.Sprintf("the %s dataset needs an id: /api/datasets/%s/{task_id}", name, name), http.StatusBadRequest)
		} else {
			http.Error(w, fmt.Sprintf("the %s dataset takes no id", name), http.StatusNotFound)
		}
		return
	}
	dq, err := parseDatasetQuery(r, *src)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	full := name
	if arg != "" {
		full += "/" + arg
	}

	start := time.Now()
	deadline := start.Add(time.Duration(dq.wait) * time.Second)
	for {
		view, err := s.buildDataset(*src, full, arg, dq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if dq.wait == 0 {
			writeJSON(w, http.StatusOK, view)
			return
		}
		// Long-poll: wait for min_rows matched rows at or beyond offset.
		beyond := view.Matched - dq.offset
		if beyond >= dq.minRows || !time.Now().Before(deadline) || r.Context().Err() != nil {
			view.Status = "timeout"
			if beyond >= dq.minRows {
				view.Status = "complete"
			}
			view.WaitedMs = time.Since(start).Milliseconds()
			writeJSON(w, http.StatusOK, view)
			return
		}
		wait := datasetPollInterval
		if left := time.Until(deadline); left < wait {
			wait = left
		}
		select {
		case <-r.Context().Done():
		case <-time.After(wait):
		}
	}
}
